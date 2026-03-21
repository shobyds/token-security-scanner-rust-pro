//! MistTrack (SlowMist) API Client for Scammer Detection
//!
//! MistTrack by SlowMist provides free threat intelligence:
//! - Risk level assessment (low/medium/high/severe)
//! - Address labels and tags
//! - Scammer and fraud detection
//!
//! # API
//! - Endpoint: `https://misttrack.io/api/v1/address/risk_score?address={address}&coin=ETH`
//! - Authentication: None required for basic queries
//! - Rate limits: Free tier available

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, DEFAULT_TIMEOUT_SECS,
    create_http_client, with_retry,
};

/// MistTrack API client
#[derive(Debug, Clone)]
pub struct MistTrackClient {
    http_client: Client,
    base_url: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// Risk level enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Severe,
    Unknown,
}

impl Default for RiskLevel {
    fn default() -> Self {
        RiskLevel::Unknown
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Severe => write!(f, "severe"),
            RiskLevel::Unknown => write!(f, "unknown"),
        }
    }
}

/// MistTrack risk score response structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MistTrackRiskResponse {
    /// Address checked
    #[serde(default)]
    pub address: String,
    /// Risk level (low/medium/high/severe)
    #[serde(default)]
    pub risk_level: RiskLevel,
    /// Risk score (0-100)
    #[serde(default)]
    pub risk_score: u32,
    /// Address labels/tags
    #[serde(default)]
    pub labels: Vec<String>,
    /// Additional metadata
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl MistTrackClient {
    /// Create a new MistTrackClient with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new MistTrackClient with custom configuration
    pub fn with_config(_config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))?;

        // MistTrack doesn't require authentication for basic queries
        info!("MistTrack (SlowMist) client initialized (no authentication required)");

        Ok(Self {
            http_client,
            base_url: "https://misttrack.io".to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_count: 3,
            enabled: true,
        })
    }

    /// Create a new MistTrackClient with custom parameters
    pub fn with_params(
        base_url: &str,
        timeout: Duration,
        retry_count: u32,
    ) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: base_url.to_string(),
            timeout,
            retry_count,
            enabled: true,
        })
    }

    /// Create a new MistTrackClient for testing
    #[cfg(test)]
    pub fn for_testing(base_url: String, http_client: Client) -> Self {
        Self {
            http_client,
            base_url,
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
        }
    }

    /// Check address risk score
    ///
    /// # Arguments
    /// * `address` - The address to check
    /// * `coin` - The cryptocurrency (ETH, BSC, etc.)
    ///
    /// # Returns
    /// * `Ok(MistTrackRiskResponse)` - Risk assessment result
    /// * `Err(anyhow::Error)` - Error if the check fails
    #[instrument(skip(self), fields(address = %address, coin = %coin))]
    pub async fn check_address_risk(
        &self,
        address: &str,
        coin: &str,
    ) -> Result<MistTrackRiskResponse> {
        if !self.enabled {
            debug!("MistTrack is disabled, returning default response");
            return Ok(MistTrackRiskResponse::default());
        }

        info!("Checking MistTrack risk for {} on {}", address, coin);

        let url = format!(
            "{}/api/v1/address/risk_score?address={}&coin={}",
            self.base_url, address, coin
        );

        debug!("MistTrack API URL: {}", url);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .get(&url)
                    .header("accept", "application/json")
                    .send()
                    .await
                    .context("Failed to send request to MistTrack")?;

                let status = response.status();
                debug!("MistTrack response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    Ok(body)
                } else if status.as_u16() == 404 {
                    // Address not found - return default response
                    debug!("Address {} not found in MistTrack database", address);
                    Ok(r#"{"address": "", "risk_level": "unknown", "risk_score": 0, "labels": []}"#.to_string())
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by MistTrack"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    Err(anyhow!("MistTrack API error: {status} - {error_body}"))
                }
            },
        )
        .await?;

        let parsed: MistTrackRiskResponse =
            serde_json::from_str(&response_data).context("Failed to parse MistTrack response")?;

        info!(
            "MistTrack check completed for {}: risk_level={}, risk_score={}, labels={:?}",
            address, parsed.risk_level, parsed.risk_score, parsed.labels
        );

        Ok(parsed)
    }

    /// Map risk level to score (conservative mapping)
    ///
    /// Mapping:
    /// - low = 20
    /// - medium = 50
    /// - high = 75
    /// - severe = 100
    /// - unknown = 0
    pub fn risk_level_to_score(level: &RiskLevel) -> u32 {
        match level {
            RiskLevel::Low => 20,
            RiskLevel::Medium => 50,
            RiskLevel::High => 75,
            RiskLevel::Severe => 100,
            RiskLevel::Unknown => 0,
        }
    }

    /// Check if address is considered a scammer based on risk level
    pub fn is_scammer(&self, response: &MistTrackRiskResponse) -> bool {
        matches!(
            response.risk_level,
            RiskLevel::High | RiskLevel::Severe
        ) || response.risk_score >= 75
    }

    /// Count critical alerts (severe risk level)
    pub fn count_critical_alerts(&self, response: &MistTrackRiskResponse) -> u32 {
        u32::from(response.risk_level == RiskLevel::Severe)
    }

    /// Count high alerts (high risk level)
    pub fn count_high_alerts(&self, response: &MistTrackRiskResponse) -> u32 {
        u32::from(response.risk_level == RiskLevel::High)
    }

    /// Get risk score from response (use mapped score if risk_score is 0)
    pub fn get_risk_score(&self, response: &MistTrackRiskResponse) -> u32 {
        if response.risk_score > 0 {
            response.risk_score.min(100)
        } else {
            Self::risk_level_to_score(&response.risk_level)
        }
    }

    /// Count rugpull labels
    pub fn count_rugpulls(&self, response: &MistTrackRiskResponse) -> u32 {
        response
            .labels
            .iter()
            .filter(|label| {
                let label_lower = label.to_lowercase();
                label_lower.contains("rug") || label_lower.contains("rugpull")
            })
            .count() as u32
    }

    /// Get all labels as alerts
    pub fn get_alerts(&self, response: &MistTrackRiskResponse) -> Vec<String> {
        response.labels.clone()
    }
}

impl Default for MistTrackClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default MistTrackClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> MistTrackClient {
        let http_client = Client::builder()
            .http1_only()
            .build()
            .unwrap();

        MistTrackClient {
            http_client,
            base_url: mock_server_url.to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_check_address_risk_severe() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "address": "0x1234567890123456789012345678901234567890",
            "risk_level": "severe",
            "risk_score": 95,
            "labels": ["Scam", "Rugpull", "Mixer"]
        }"#;

        let mock = server
            .mock("GET", "/api/v1/address/risk_score?address=0x1234567890123456789012345678901234567890&coin=ETH")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_address_risk("0x1234567890123456789012345678901234567890", "ETH")
            .await;

        assert!(result.is_ok());
        let risk_response = result.unwrap();
        assert_eq!(risk_response.risk_level, RiskLevel::Severe);
        assert_eq!(risk_response.risk_score, 95);
        assert_eq!(risk_response.labels.len(), 3);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_address_risk_clean() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
            "risk_level": "low",
            "risk_score": 10,
            "labels": []
        }"#;

        let mock = server
            .mock("GET", "/api/v1/address/risk_score?address=0x1f9840a85d5af5bf1d1762f925bdaddc4201f984&coin=ETH")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_address_risk("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", "ETH")
            .await;

        assert!(result.is_ok());
        let risk_response = result.unwrap();
        assert_eq!(risk_response.risk_level, RiskLevel::Low);
        assert!(risk_response.labels.is_empty());

        mock.assert_async().await;
    }

    #[test]
    fn test_risk_level_to_score() {
        assert_eq!(MistTrackClient::risk_level_to_score(&RiskLevel::Low), 20);
        assert_eq!(MistTrackClient::risk_level_to_score(&RiskLevel::Medium), 50);
        assert_eq!(MistTrackClient::risk_level_to_score(&RiskLevel::High), 75);
        assert_eq!(MistTrackClient::risk_level_to_score(&RiskLevel::Severe), 100);
        assert_eq!(MistTrackClient::risk_level_to_score(&RiskLevel::Unknown), 0);
    }

    #[test]
    fn test_is_scammer_detection() {
        let client = MistTrackClient::default();

        let severe_response = MistTrackRiskResponse {
            address: "0x123".to_string(),
            risk_level: RiskLevel::Severe,
            risk_score: 100,
            labels: vec![],
            metadata: serde_json::Value::Null,
        };
        assert!(client.is_scammer(&severe_response));

        let high_response = MistTrackRiskResponse {
            address: "0x123".to_string(),
            risk_level: RiskLevel::High,
            risk_score: 80,
            labels: vec![],
            metadata: serde_json::Value::Null,
        };
        assert!(client.is_scammer(&high_response));

        let low_response = MistTrackRiskResponse {
            address: "0x123".to_string(),
            risk_level: RiskLevel::Low,
            risk_score: 20,
            labels: vec![],
            metadata: serde_json::Value::Null,
        };
        assert!(!client.is_scammer(&low_response));
    }
}
