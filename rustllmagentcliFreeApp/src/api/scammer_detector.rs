//! Unified Scammer Detection Aggregator
//!
//! This module aggregates scammer detection data from multiple free, no-auth providers:
//! - Etherscan (address labels)
//! - ScamSniffer (scammer flags, rug history)
//! - MistTrack/SlowMist (risk levels)
//! - AML Bot (risk scores, category tags)
//!
//! # Architecture
//! All providers are queried in parallel with 3-second timeout per provider.
//! Results are merged into a unified `ScammerDetectionResult` with conservative
//! aggregation logic (max risk score, any scammer flag = true).

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cognitive_complexity)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    amlbot::AmlBotClient,
    etherscan::{AddressLabels, EtherscanClient},
    misttrack::{MistTrackClient, RiskLevel},
    scam_sniffer::ScamSnifferClient,
    ApiConfig, DEFAULT_TIMEOUT_SECS,
};

/// Unified scammer detection result from all providers
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScammerDetectionResult {
    /// Address checked
    pub address: String,
    /// Whether address is a known scammer (true if ANY provider flags it)
    pub is_known_scammer: bool,
    /// Number of previous rug pulls detected
    pub previous_rugs: u32,
    /// Deployer risk score (0-100, max from all providers)
    pub deployer_risk_score: u32,
    /// Number of critical alerts (severe risk levels)
    pub critical_alerts: u32,
    /// Number of high alerts
    pub high_alerts: u32,
    /// Merged labels/alerts from all providers (unique)
    pub alerts: Vec<String>,
    /// List of providers that were checked
    pub providers_checked: Vec<String>,
    /// List of providers that succeeded
    pub providers_succeeded: Vec<String>,
    /// List of providers that failed
    pub providers_failed: Vec<String>,
    /// Total time taken for all providers in milliseconds
    pub total_time_ms: u64,
    /// Individual provider timing breakdown
    pub timing_breakdown: ProviderTimingBreakdown,
}

/// Timing breakdown for individual providers
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderTimingBreakdown {
    /// Etherscan time in ms
    pub etherscan_ms: u64,
    /// ScamSniffer time in ms
    pub scam_sniffer_ms: u64,
    /// MistTrack time in ms
    pub misttrack_ms: u64,
    /// AML Bot time in ms
    pub amlbot_ms: u64,
}

/// Scammer detection aggregator
#[derive(Debug, Clone)]
pub struct ScammerDetector {
    etherscan: EtherscanClient,
    scam_sniffer: ScamSnifferClient,
    misttrack: MistTrackClient,
    amlbot: AmlBotClient,
    timeout: Duration,
}

impl ScammerDetector {
    /// Create a new ScammerDetector with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new ScammerDetector with custom configuration
    pub fn with_config(config: &ApiConfig) -> Result<Self> {
        let etherscan = EtherscanClient::with_config(config)?;
        let scam_sniffer = ScamSnifferClient::with_config(config)?;
        let misttrack = MistTrackClient::with_config(config)?;
        let amlbot = AmlBotClient::with_config(config)?;

        info!("ScammerDetector initialized with 4 free providers (no auth required)");

        Ok(Self {
            etherscan,
            scam_sniffer,
            misttrack,
            amlbot,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        })
    }

    /// Create a new ScammerDetector with custom timeout
    pub fn with_timeout(config: &ApiConfig, timeout: Duration) -> Result<Self> {
        let mut detector = Self::with_config(config)?;
        detector.timeout = timeout;
        Ok(detector)
    }

    /// Create a new ScammerDetector for testing
    #[cfg(test)]
    pub fn for_testing(
        etherscan: EtherscanClient,
        scam_sniffer: ScamSnifferClient,
        misttrack: MistTrackClient,
        amlbot: AmlBotClient,
        timeout: Duration,
    ) -> Self {
        Self {
            etherscan,
            scam_sniffer,
            misttrack,
            amlbot,
            timeout,
        }
    }

    /// Fetch scammer detection data from all providers in parallel
    ///
    /// # Arguments
    /// * `address` - The address to check
    /// * `chain` - The blockchain network (for provider-specific chain mapping)
    ///
    /// # Returns
    /// * `Ok(ScammerDetectionResult)` - Aggregated result from all providers
    /// * `Err(anyhow::Error)` - Error if all providers fail
    #[instrument(skip(self), fields(address = %address, chain = %chain))]
    pub async fn fetch_scammer_detection(
        &self,
        address: &str,
        chain: &str,
    ) -> Result<ScammerDetectionResult> {
        let start_time = Instant::now();

        info!("Fetching scammer detection from 4 providers for {}", address);

        // Map chain to MistTrack coin parameter
        let misttrack_coin = match chain.to_lowercase().as_str() {
            "ethereum" | "eth" => "ETH",
            "bsc" | "binance" | "bnb" => "BSC",
            "polygon" | "matic" => "MATIC",
            _ => "ETH", // Default to ETH
        };

        // Query all providers in parallel with individual timeouts
        let (etherscan_result, scam_sniffer_result, misttrack_result, amlbot_result) = tokio::join!(
            self.fetch_etherscan_with_timeout(address),
            self.fetch_scam_sniffer_with_timeout(address),
            self.fetch_misttrack_with_timeout(address, misttrack_coin),
            self.fetch_amlbot_with_timeout(address),
        );

        // Aggregate results
        let mut result = self.aggregate_results(
            address,
            etherscan_result,
            scam_sniffer_result,
            misttrack_result,
            amlbot_result,
        );

        result.total_time_ms = start_time.elapsed().as_millis() as u64;

        info!(
            "Scammer detection completed for {} in {}ms: is_scammer={}, risk_score={}, providers={}/4 succeeded",
            address,
            result.total_time_ms,
            result.is_known_scammer,
            result.deployer_risk_score,
            result.providers_succeeded.len()
        );

        Ok(result)
    }

    /// Fetch with timeout wrapper for Etherscan
    async fn fetch_etherscan_with_timeout(
        &self,
        address: &str,
    ) -> (String, Option<AddressLabels>, Option<String>, u64) {
        let start = Instant::now();
        let provider = "Etherscan".to_string();

        match tokio::time::timeout(self.timeout, self.etherscan.check_address_labels(address)).await {
            Ok(Ok(labels)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                (provider, Some(labels), None, elapsed)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("Etherscan address labels check failed: {}", e);
                (provider, None, Some(e.to_string()), elapsed)
            }
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("Etherscan address labels check timed out");
                (provider, None, Some("Timeout".to_string()), elapsed)
            }
        }
    }

    /// Fetch with timeout wrapper for ScamSniffer
    async fn fetch_scam_sniffer_with_timeout(
        &self,
        address: &str,
    ) -> (String, Option<crate::api::scam_sniffer::ScamSnifferRiskResponse>, Option<String>, u64) {
        let start = Instant::now();
        let provider = "ScamSniffer".to_string();

        match tokio::time::timeout(self.timeout, self.scam_sniffer.check_address_risk(address)).await {
            Ok(Ok(response)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                (provider, Some(response), None, elapsed)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("ScamSniffer check failed: {}", e);
                (provider, None, Some(e.to_string()), elapsed)
            }
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("ScamSniffer check timed out");
                (provider, None, Some("Timeout".to_string()), elapsed)
            }
        }
    }

    /// Fetch with timeout wrapper for MistTrack
    async fn fetch_misttrack_with_timeout(
        &self,
        address: &str,
        coin: &str,
    ) -> (String, Option<crate::api::misttrack::MistTrackRiskResponse>, Option<String>, u64) {
        let start = Instant::now();
        let provider = "MistTrack".to_string();

        match tokio::time::timeout(self.timeout, self.misttrack.check_address_risk(address, coin)).await {
            Ok(Ok(response)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                (provider, Some(response), None, elapsed)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("MistTrack check failed: {}", e);
                (provider, None, Some(e.to_string()), elapsed)
            }
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("MistTrack check timed out");
                (provider, None, Some("Timeout".to_string()), elapsed)
            }
        }
    }

    /// Fetch with timeout wrapper for AML Bot
    async fn fetch_amlbot_with_timeout(
        &self,
        address: &str,
    ) -> (String, Option<crate::api::amlbot::AmlBotCheckResponse>, Option<String>, u64) {
        let start = Instant::now();
        let provider = "AMLBot".to_string();

        match tokio::time::timeout(self.timeout, self.amlbot.check_address(address)).await {
            Ok(Ok(response)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                (provider, Some(response), None, elapsed)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("AML Bot check failed: {}", e);
                (provider, None, Some(e.to_string()), elapsed)
            }
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("AML Bot check timed out");
                (provider, None, Some("Timeout".to_string()), elapsed)
            }
        }
    }

    /// Aggregate results from all providers
    #[allow(clippy::too_many_lines)]
    fn aggregate_results(
        &self,
        address: &str,
        etherscan_result: (String, Option<AddressLabels>, Option<String>, u64),
        scam_sniffer_result: (String, Option<crate::api::scam_sniffer::ScamSnifferRiskResponse>, Option<String>, u64),
        misttrack_result: (String, Option<crate::api::misttrack::MistTrackRiskResponse>, Option<String>, u64),
        amlbot_result: (String, Option<crate::api::amlbot::AmlBotCheckResponse>, Option<String>, u64),
    ) -> ScammerDetectionResult {
        let mut result = ScammerDetectionResult {
            address: address.to_string(),
            ..Default::default()
        };

        // Track timing
        result.timing_breakdown.etherscan_ms = etherscan_result.3;
        result.timing_breakdown.scam_sniffer_ms = scam_sniffer_result.3;
        result.timing_breakdown.misttrack_ms = misttrack_result.3;
        result.timing_breakdown.amlbot_ms = amlbot_result.3;

        // Process Etherscan result
        if let Some(labels) = etherscan_result.1 {
            result.providers_succeeded.push(etherscan_result.0.clone());
            result.is_known_scammer |= labels.is_known_scammer;
            result.previous_rugs += labels.rugpull_count;
            result.deployer_risk_score = result.deployer_risk_score.max(labels.risk_score);
            #[allow(clippy::cast_possible_truncation)]
            let critical_from_etherscan = labels.scam_tags.len() as u32;
            result.critical_alerts += critical_from_etherscan;
            result.alerts.extend(labels.all_labels);
            debug!("Etherscan: is_scammer={}, risk={}, rugs={}", labels.is_known_scammer, labels.risk_score, labels.rugpull_count);
        } else {
            result.providers_failed.push(etherscan_result.0.clone());
            debug!("Etherscan failed: {}", etherscan_result.2.unwrap_or_default());
        }

        // Process ScamSniffer result
        if let Some(response) = scam_sniffer_result.1 {
            result.providers_succeeded.push(scam_sniffer_result.0.clone());
            let is_scammer = self.scam_sniffer.is_scammer(&response);
            result.is_known_scammer |= is_scammer;
            result.previous_rugs += self.scam_sniffer.count_rug_pulls(&response);
            result.deployer_risk_score = result.deployer_risk_score.max(self.scam_sniffer.get_risk_score(&response));
            result.critical_alerts += self.scam_sniffer.count_critical_alerts(&response);
            result.high_alerts += self.scam_sniffer.count_high_alerts(&response);
            result.alerts.extend(self.scam_sniffer.get_alerts(&response));
            debug!("ScamSniffer: is_scammer={}, risk={}, rugs={}", is_scammer, response.risk_score, response.rug_pull_history.len());
        } else {
            result.providers_failed.push(scam_sniffer_result.0.clone());
            debug!("ScamSniffer failed: {}", scam_sniffer_result.2.unwrap_or_default());
        }

        // Process MistTrack result
        if let Some(response) = misttrack_result.1 {
            result.providers_succeeded.push(misttrack_result.0.clone());
            let is_scammer = self.misttrack.is_scammer(&response);
            result.is_known_scammer |= is_scammer;
            result.previous_rugs += self.misttrack.count_rugpulls(&response);
            result.deployer_risk_score = result.deployer_risk_score.max(self.misttrack.get_risk_score(&response));
            result.critical_alerts += self.misttrack.count_critical_alerts(&response);
            result.high_alerts += self.misttrack.count_high_alerts(&response);
            result.alerts.extend(self.misttrack.get_alerts(&response));
            debug!("MistTrack: level={}, risk={}, is_scammer={}", response.risk_level, response.risk_score, is_scammer);
        } else {
            result.providers_failed.push(misttrack_result.0.clone());
            debug!("MistTrack failed: {}", misttrack_result.2.unwrap_or_default());
        }

        // Process AML Bot result
        if let Some(response) = amlbot_result.1 {
            result.providers_succeeded.push(amlbot_result.0.clone());
            let is_scammer = self.amlbot.is_scammer(&response);
            result.is_known_scammer |= is_scammer;
            result.previous_rugs += self.amlbot.count_rugpulls(&response);
            result.deployer_risk_score = result.deployer_risk_score.max(self.amlbot.get_risk_score(&response));
            result.critical_alerts += self.amlbot.count_critical_alerts(&response);
            result.high_alerts += self.amlbot.count_high_alerts(&response);
            result.alerts.extend(self.amlbot.get_alerts(&response));
            debug!("AML Bot: risk={}, category={}, is_scammer={}", response.risk_score, response.category, is_scammer);
        } else {
            result.providers_failed.push(amlbot_result.0.clone());
            debug!("AML Bot failed: {}", amlbot_result.2.unwrap_or_default());
        }

        // Add all providers to checked list
        result.providers_checked = vec![
            "Etherscan".to_string(),
            "ScamSniffer".to_string(),
            "MistTrack".to_string(),
            "AMLBot".to_string(),
        ];

        // Deduplicate alerts
        result.alerts = Self::deduplicate_alerts(&result.alerts);

        // Cap risk score at 100
        result.deployer_risk_score = result.deployer_risk_score.min(100);

        // Log final result
        info!(
            "Aggregated result: is_scammer={}, risk_score={}, rugs={}, critical={}, high={}, alerts={}",
            result.is_known_scammer,
            result.deployer_risk_score,
            result.previous_rugs,
            result.critical_alerts,
            result.high_alerts,
            result.alerts.len()
        );

        result
    }

    /// Deduplicate alert strings while preserving order
    fn deduplicate_alerts(alerts: &[String]) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();

        for alert in alerts {
            if seen.insert(alert.clone()) {
                result.push(alert.clone());
            }
        }

        result
    }
}

impl Default for ScammerDetector {
    fn default() -> Self {
        Self::new().expect("Failed to create default ScammerDetector")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplicate_alerts() {
        let alerts = vec![
            "Scam".to_string(),
            "Rugpull".to_string(),
            "Scam".to_string(),
            "Phishing".to_string(),
            "Rugpull".to_string(),
        ];

        let deduped = ScammerDetector::deduplicate_alerts(&alerts);
        assert_eq!(deduped.len(), 3);
        assert!(deduped.contains(&"Scam".to_string()));
        assert!(deduped.contains(&"Rugpull".to_string()));
        assert!(deduped.contains(&"Phishing".to_string()));
    }

    #[test]
    fn test_default_result() {
        let result = ScammerDetectionResult::default();
        assert!(!result.is_known_scammer);
        assert_eq!(result.previous_rugs, 0);
        assert_eq!(result.deployer_risk_score, 0);
        assert!(result.alerts.is_empty());
    }
}
