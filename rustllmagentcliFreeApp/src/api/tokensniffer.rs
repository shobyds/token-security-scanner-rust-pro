//! `TokenSniffer` API client for heuristic token scoring and honeypot detection fallback
//!
//! `TokenSniffer` provides token security scoring based on various heuristics.
//! Note: `TokenSniffer` does not currently offer a public API. This implementation
//! provides a stub that can be used for future integration or with unofficial methods.
//!
//! This module also provides honeypot detection fallback capability compatible with
//! the fallback chain system.
//!
//! For production use, consider using the other API providers (`GoPlus`, Honeypot.is, etc.)
//! which have official APIs.

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::if_not_else)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::uninlined_format_args)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tracing::{debug, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, create_http_client,
    validate_token_address, with_retry,
};

/// `TokenSniffer` API client
///
/// Note: `TokenSniffer` does not have an official public API. This client
/// is provided as a stub for future integration.
#[derive(Debug, Clone)]
pub struct TokenSnifferClient {
    http_client: Client,
    base_url: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
    /// Warning message about API availability
    api_warning: String,
}

/// TokenSniffer honeypot data for fallback compatibility
///
/// This structure is compatible with HoneypotResult and can be used
/// as a fallback when Honeypot.is is unavailable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSnifferHoneypotData {
    /// Token address that was analyzed
    pub token_address: String,
    /// Chain identifier
    pub chain: String,
    /// Whether the token is detected as a honeypot
    pub is_honeypot: bool,
    /// Buy tax percentage (0-100)
    pub buy_tax: f32,
    /// Sell tax percentage (0-100)
    pub sell_tax: f32,
    /// Whether buying is possible
    pub can_buy: bool,
    /// Whether selling is possible
    pub can_sell: bool,
    /// Contract risk score (0-100)
    pub contract_risk_score: u32,
    /// Whether liquidity is locked
    pub liquidity_locked: bool,
    /// Additional error message if any
    pub error: Option<String>,
}

impl Default for TokenSnifferHoneypotData {
    fn default() -> Self {
        Self {
            token_address: String::new(),
            chain: String::new(),
            is_honeypot: false,
            buy_tax: 0.0,
            sell_tax: 0.0,
            can_buy: true,
            can_sell: true,
            contract_risk_score: 50,
            liquidity_locked: false,
            error: None,
        }
    }
}

impl TokenSnifferHoneypotData {
    /// Create from a TokenSnifferScore
    pub fn from_score(score: &TokenSnifferScore, token_address: &str, chain: &str) -> Self {
        // Determine if token is likely a honeypot based on score
        let is_honeypot = score.is_scam || score.overall_score < 20;

        // Estimate tax from risk level (TokenSniffer doesn't provide exact tax)
        let (buy_tax, sell_tax) = match score.risk_level {
            RiskLevel::Critical => (50.0, 99.0),
            RiskLevel::High => (20.0, 50.0),
            RiskLevel::Medium => (5.0, 20.0),
            RiskLevel::Low => (0.0, 5.0),
        };

        Self {
            token_address: token_address.to_string(),
            chain: chain.to_string(),
            is_honeypot,
            buy_tax,
            sell_tax,
            can_buy: !is_honeypot,
            can_sell: !is_honeypot,
            contract_risk_score: u32::from(100 - score.overall_score),
            liquidity_locked: score.liquidity_usd.unwrap_or(0.0) > 10_000.0,
            error: None,
        }
    }

    /// Create from GoPlus ContractRisk data
    pub fn from_goplus_risk(risk: &crate::api::ContractRisk, token_address: &str, chain: &str) -> Self {
        // Determine if token is likely a honeypot based on GoPlus data
        let is_honeypot = risk.owner_can_blacklist
            || risk.is_proxy
            || risk.hidden_owner
            || risk.selfdestruct;

        Self {
            token_address: token_address.to_string(),
            chain: chain.to_string(),
            is_honeypot,
            buy_tax: 0.0,
            sell_tax: 0.0,
            can_buy: true,  // GoPlus doesn't provide this directly
            can_sell: true,  // GoPlus doesn't provide this directly
            contract_risk_score: Self::calculate_risk_score(risk),
            liquidity_locked: risk.lp_locked,
            error: None,
        }
    }

    /// Calculate risk score from GoPlus data
    fn calculate_risk_score(risk: &crate::api::ContractRisk) -> u32 {
        let mut score = 0u32;

        if risk.owner_can_blacklist {
            score += 25;
        }
        if risk.is_proxy {
            score += 15;
        }
        if risk.hidden_owner {
            score += 20;
        }
        if risk.selfdestruct {
            score += 20;
        }
        if risk.can_be_upgraded {
            score += 10;
        }
        if risk.owner_can_mint {
            score += 15;
        }
        if risk.anti_whale_modifiable {
            score += 5;
        }
        if risk.personal_privilege {
            score += 10;
        }
        if risk.lp_locked {
            score = score.saturating_sub(15);
        }

        score.min(100)
    }
}

/// Token security score from `TokenSniffer`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenSnifferScore {
    /// Token address that was scored
    pub token_address: String,
    /// Overall security score (0-100, higher is safer)
    pub overall_score: u8,
    /// Contract score component
    pub contract_score: u8,
    /// Token score component
    pub token_score: u8,
    /// Market score component
    pub market_score: u8,
    /// Whether the token is flagged as a scam
    pub is_scam: bool,
    /// Risk level (low, medium, high, critical)
    pub risk_level: RiskLevel,
    /// List of detected issues
    pub issues: Vec<String>,
    /// List of positive indicators
    pub positives: Vec<String>,
    /// Audit status
    pub is_audited: bool,
    /// Audit provider if audited
    pub audit_provider: Option<String>,
    /// KYC status
    pub is_kyc: bool,
    /// Contract age in days
    pub contract_age_days: Option<u32>,
    /// Holder count
    pub holder_count: Option<u64>,
    /// Liquidity in USD
    pub liquidity_usd: Option<f64>,
}

/// Risk level classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Low risk - generally safe
    Low,
    /// Medium risk - some concerns
    Medium,
    /// High risk - significant concerns
    High,
    /// Critical risk - likely a scam
    Critical,
}

impl Default for RiskLevel {
    fn default() -> Self {
        Self::Medium
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl TokenSnifferClient {
    /// Create a new TokenSniffer client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new TokenSniffer client with custom configuration
    pub fn with_config(_config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(10))?;

        Ok(Self {
            http_client,
            base_url: "https://tokensniffer.com".to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 3,
            enabled: false, // Disabled by default as there's no official API
            api_warning:
                "TokenSniffer does not have an official public API. This is a stub implementation."
                    .to_string(),
        })
    }

    /// Create a new TokenSniffer client with custom parameters
    pub fn with_params(timeout: Duration, retry_count: u32, enabled: bool) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://tokensniffer.com".to_string(),
            timeout,
            retry_count,
            enabled,
            api_warning: "TokenSniffer does not have an official public API.".to_string(),
        })
    }

    /// Check if TokenSniffer API is available
    ///
    /// Returns false as TokenSniffer doesn't have an official API
    pub fn is_available() -> bool {
        false
    }

    /// Get the API warning message
    pub fn get_warning(&self) -> &str {
        &self.api_warning
    }

    /// Scan token for honeypot detection (fallback chain compatible)
    ///
    /// This method provides honeypot detection capability compatible with
    /// the fallback chain system. It can use either:
    /// - Actual TokenSniffer API (when available)
    /// - Mock/heuristic-based detection (when API unavailable)
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to scan
    /// * `chain` - The blockchain network
    ///
    /// # Returns
    /// * `Ok(TokenSnifferHoneypotData)` - Honeypot detection result
    /// * `Err(anyhow::Error)` - Error if scan fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn scan_token(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Result<TokenSnifferHoneypotData> {
        // Validate token address
        validate_token_address(token_address, chain)?;

        // Since TokenSniffer doesn't have an official API, we provide a mock implementation
        // that can be used as a fallback when other honeypot detectors fail
        debug!(
            "TokenSniffer scan_token called (mock implementation) for {}",
            token_address
        );

        // Return a default "safe" result when API is not available
        // This allows the fallback chain to continue to the next provider
        // if more reliable data is needed
        if !self.enabled {
            debug!("TokenSniffer not enabled, returning mock data");
            
            // Return a conservative estimate - mark as potentially risky
            // to alert users when primary honeypot detection fails
            Ok(TokenSnifferHoneypotData {
                token_address: token_address.to_string(),
                chain: chain.to_string(),
                is_honeypot: false,  // Don't false-positive as honeypot
                buy_tax: 5.0,        // Default estimated tax
                sell_tax: 5.0,
                can_buy: true,
                can_sell: true,
                contract_risk_score: 50,  // Medium risk when unknown
                liquidity_locked: false,
                error: Some("TokenSniffer API not available - using mock data".to_string()),
            })
        } else {
            // If somehow enabled, try to fetch actual data
            match self.fetch_token_score(token_address, chain).await {
                Ok(score) => Ok(TokenSnifferHoneypotData::from_score(&score, token_address, chain)),
                Err(e) => Err(anyhow!("TokenSniffer scan failed: {}", e)),
            }
        }
    }

    /// Fetch token security score from TokenSniffer
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to score
    /// * `chain` - The blockchain network
    ///
    /// # Returns
    /// * `Ok(TokenSnifferScore)` - Token security score
    /// * `Err(anyhow::Error)` - Error (API not available)
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn fetch_token_score(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Result<TokenSnifferScore> {
        if !self.enabled {
            return Err(anyhow!(
                "TokenSniffer API is disabled: {}",
                self.api_warning
            ));
        }

        // Validate token address
        validate_token_address(token_address, chain)?;

        warn!("TokenSniffer API access attempted but not officially available");

        // This is a stub - in a real implementation, this would make API calls
        // For now, return an error indicating the API is not available
        Err(anyhow!(
            "TokenSniffer does not have an official public API. \
             Please use alternative providers like GoPlus, Honeypot.is, or Dexscreener."
        ))
    }

    /// Fetch scores for multiple tokens
    ///
    /// # Arguments
    /// * `tokens` - List of (token_address, chain) tuples to score
    ///
    /// # Returns
    /// * `Ok(Vec<TokenSnifferScore>)` - List of token scores
    pub async fn fetch_multiple_scores(
        &self,
        tokens: &[(&str, &str)],
    ) -> Result<Vec<TokenSnifferScore>> {
        if !self.enabled {
            return Err(anyhow!("TokenSniffer API is disabled"));
        }

        let mut results = Vec::with_capacity(tokens.len());

        for (address, chain) in tokens {
            match self.fetch_token_score(address, chain).await {
                Ok(score) => results.push(score),
                Err(e) => {
                    warn!("Failed to fetch score for {}: {}", address, e);
                    // Continue with other tokens
                }
            }
        }

        Ok(results)
    }

    /// Create a mock score for testing purposes
    ///
    /// This can be used when TokenSniffer API is not available
    /// to provide estimated scores based on other data sources.
    pub fn create_mock_score(
        token_address: &str,
        contract_verified: bool,
        is_honeypot: bool,
        liquidity_usd: f64,
        holder_count: u64,
    ) -> TokenSnifferScore {
        let mut overall_score: u8 = 50;
        let mut issues = Vec::new();
        let mut positives = Vec::new();

        // Contract verification
        if contract_verified {
            overall_score = overall_score.saturating_add(20);
            positives.push("Contract is verified".to_string());
        } else {
            overall_score = overall_score.saturating_sub(20);
            issues.push("Contract is not verified".to_string());
        }

        // Honeypot check
        if is_honeypot {
            overall_score = 0;
            issues.push("Token is a honeypot".to_string());
        } else {
            overall_score = overall_score.saturating_add(20);
            positives.push("Not a honeypot".to_string());
        }

        // Liquidity check
        if liquidity_usd > 100_000.0 {
            overall_score = overall_score.saturating_add(10);
            positives.push("High liquidity".to_string());
        } else if liquidity_usd > 10_000.0 {
            overall_score = overall_score.saturating_add(5);
        } else if liquidity_usd < 1_000.0 {
            overall_score = overall_score.saturating_sub(15);
            issues.push("Very low liquidity".to_string());
        }

        // Holder count check
        if holder_count > 1000 {
            overall_score = overall_score.saturating_add(10);
            positives.push("Many holders".to_string());
        } else if holder_count < 50 {
            overall_score = overall_score.saturating_sub(10);
            issues.push("Few holders".to_string());
        }

        // Determine risk level
        let risk_level = if overall_score >= 80 {
            RiskLevel::Low
        } else if overall_score >= 50 {
            RiskLevel::Medium
        } else if overall_score >= 25 {
            RiskLevel::High
        } else {
            RiskLevel::Critical
        };

        TokenSnifferScore {
            token_address: token_address.to_string(),
            overall_score: overall_score.min(100),
            contract_score: if contract_verified { 80 } else { 20 },
            token_score: if !is_honeypot { 80 } else { 0 },
            market_score: (liquidity_usd / 1000.0).min(100.0) as u8,
            is_scam: is_honeypot || overall_score < 25,
            risk_level,
            issues,
            positives,
            is_audited: false,
            audit_provider: None,
            is_kyc: false,
            contract_age_days: None,
            holder_count: Some(holder_count),
            liquidity_usd: Some(liquidity_usd),
        }
    }
}

impl Default for TokenSnifferClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default TokenSnifferClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available() {
        assert!(!TokenSnifferClient::is_available());
    }

    #[test]
    fn test_client_creation() {
        let client = TokenSnifferClient::new().unwrap();
        assert!(!client.enabled);
        assert!(client.get_warning().contains("official public API"));
    }

    #[test]
    fn test_client_with_params() {
        let client = TokenSnifferClient::with_params(Duration::from_secs(5), 2, false).unwrap();
        assert!(!client.enabled);
        assert_eq!(client.timeout, Duration::from_secs(5));
        assert_eq!(client.retry_count, 2);
    }

    #[tokio::test]
    async fn test_fetch_token_score_disabled() {
        let client = TokenSnifferClient::default();

        let result = client
            .fetch_token_score("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn test_fetch_token_score_invalid_address() {
        let client = TokenSnifferClient::with_params(Duration::from_secs(10), 3, true).unwrap();

        let result = client
            .fetch_token_score("invalid_address", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must start with 0x")
        );
    }

    #[test]
    fn test_create_mock_score_safe_token() {
        let score = TokenSnifferClient::create_mock_score(
            "0x1234567890123456789012345678901234567890",
            true,     // verified
            false,    // not honeypot
            150_000.0, // high liquidity
            5000,     // many holders
        );

        assert!(score.overall_score >= 70);
        assert_eq!(score.risk_level, RiskLevel::Low);
        assert!(!score.is_scam);
        assert!(!score.positives.is_empty());
    }

    #[test]
    fn test_create_mock_score_risky_token() {
        let score = TokenSnifferClient::create_mock_score(
            "0x1234567890123456789012345678901234567890",
            false, // not verified
            false, // not honeypot
            500.0, // low liquidity
            20,    // few holders
        );

        assert!(score.overall_score < 50);
        assert!(score.risk_level == RiskLevel::High || score.risk_level == RiskLevel::Medium);
        assert!(!score.issues.is_empty());
    }

    #[test]
    fn test_create_mock_score_honeypot() {
        let score = TokenSnifferClient::create_mock_score(
            "0x1234567890123456789012345678901234567890",
            true, // verified
            true, // IS honeypot
            100_000.0,
            1000,
        );

        assert_eq!(score.overall_score, 0);
        assert_eq!(score.risk_level, RiskLevel::Critical);
        assert!(score.is_scam);
        assert!(score.issues.iter().any(|i| i.contains("honeypot")));
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(RiskLevel::Low.to_string(), "low");
        assert_eq!(RiskLevel::Medium.to_string(), "medium");
        assert_eq!(RiskLevel::High.to_string(), "high");
        assert_eq!(RiskLevel::Critical.to_string(), "critical");
    }

    #[test]
    fn test_risk_level_default() {
        assert_eq!(RiskLevel::default(), RiskLevel::Medium);
    }

    #[test]
    fn test_token_sniffer_score_serialization() {
        let score = TokenSnifferScore {
            token_address: "0x1234".to_string(),
            overall_score: 75,
            contract_score: 80,
            token_score: 90,
            market_score: 60,
            is_scam: false,
            risk_level: RiskLevel::Low,
            issues: vec![],
            positives: vec!["Verified contract".to_string()],
            is_audited: true,
            audit_provider: Some("CertiK".to_string()),
            is_kyc: true,
            contract_age_days: Some(365),
            holder_count: Some(10000),
            liquidity_usd: Some(500_000.0),
        };

        let json = serde_json::to_string(&score).unwrap();
        let deserialized: TokenSnifferScore = serde_json::from_str(&json).unwrap();

        assert_eq!(score.overall_score, deserialized.overall_score);
        assert_eq!(score.risk_level, deserialized.risk_level);
        assert_eq!(score.is_scam, deserialized.is_scam);
    }

    #[test]
    fn test_token_sniffer_score_default() {
        let score = TokenSnifferScore::default();
        assert_eq!(score.overall_score, 0);
        assert_eq!(score.risk_level, RiskLevel::Medium);
        assert!(score.issues.is_empty());
        assert!(score.positives.is_empty());
    }
}
