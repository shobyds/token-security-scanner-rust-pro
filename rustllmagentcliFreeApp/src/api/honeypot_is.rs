//! Honeypot.is API Client for Enhanced Honeypot Detection
//!
//! Honeypot.is provides free honeypot detection services including:
//! - Buy/sell simulation
//! - Tax calculation
//! - Trading limits detection
//! - Blacklist function detection
//! - Deployer risk assessment
//!
//! # API
//! - Endpoint: `https://api.honeypot.is/v2/IsHoneypot`
//! - Free tier: Unlimited, no authentication required
//!
//! # Features
//! - Enhanced honeypot detection beyond GoPlus
//! - Trading cooldown detection
//! - Anti-bot measure detection
//! - Max transaction/wallet limits
//! - Deployer fund analysis

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::float_cmp)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, DEFAULT_TIMEOUT_SECS,
    create_http_client, validate_token_address, with_retry,
};

/// Honeypot.is API client
#[derive(Debug, Clone)]
pub struct HoneypotIsClient {
    http_client: Client,
    base_url: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// Honeypot.is response structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HoneypotIsResponse {
    /// Whether the token is a honeypot
    #[serde(rename = "isHoneypot", default)]
    pub is_honeypot: bool,
    /// Whether simulation was successful
    #[serde(rename = "simulationSuccess", default)]
    pub simulation_success: bool,
    /// Buy tax percentage
    #[serde(rename = "buyTax", default)]
    pub buy_tax: f64,
    /// Sell tax percentage
    #[serde(rename = "sellTax", default)]
    pub sell_tax: f64,
    /// Maximum transaction amount in USD
    #[serde(rename = "maxTxAmount", default)]
    pub max_tx_amount: Option<f64>,
    /// Maximum wallet amount in USD
    #[serde(rename = "maxWalletAmount", default)]
    pub max_wallet_amount: Option<f64>,
    /// Deployer address
    #[serde(rename = "deployerAddress", default)]
    pub deployer_address: Option<String>,
    /// Deployer funds in USD
    #[serde(rename = "deployerFunds", default)]
    pub deployer_funds: Option<f64>,
    /// Risk flags
    #[serde(default)]
    pub flags: Vec<String>,
    /// Token information
    #[serde(default)]
    pub token: Option<HoneypotToken>,
    /// Whether buy is possible
    #[serde(rename = "canBuy", default)]
    pub can_buy: bool,
    /// Whether sell is possible
    #[serde(rename = "canSell", default)]
    pub can_sell: bool,
}

/// Token information from Honeypot.is
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HoneypotToken {
    /// Token name
    #[serde(default)]
    pub name: String,
    /// Token symbol
    #[serde(default)]
    pub symbol: String,
    /// Token decimals
    #[serde(default)]
    pub decimals: u32,
    /// Total supply
    #[serde(rename = "totalSupply", default)]
    pub total_supply: String,
    /// Holder count
    #[serde(rename = "holderCount", default)]
    pub holder_count: u64,
}

/// Enhanced honeypot detection result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HoneypotIsResult {
    /// Token address
    pub token_address: String,
    /// Whether detected as honeypot
    pub is_honeypot: bool,
    /// Buy tax
    pub buy_tax: f64,
    /// Sell tax
    pub sell_tax: f64,
    /// Can buy flag
    pub can_buy: bool,
    /// Can sell flag
    pub can_sell: bool,
    /// Has trading cooldown
    pub has_trading_cooldown: bool,
    /// Has blacklist function
    pub has_blacklist: bool,
    /// Anti-whale modifiable
    pub anti_whale_modifiable: bool,
    /// Max transaction amount
    pub max_tx_amount: Option<f64>,
    /// Max wallet amount
    pub max_wallet_amount: Option<f64>,
    /// Deployer address
    pub deployer_address: Option<String>,
    /// Deployer funds
    pub deployer_funds: Option<f64>,
    /// Risk flags
    pub flags: Vec<String>,
    /// Deployer risk score (0-100)
    pub deployer_risk_score: u32,
}

impl HoneypotIsClient {
    /// Create a new HoneypotIsClient with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new HoneypotIsClient with custom configuration
    pub fn with_config(_config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))?;

        info!("Honeypot.is client initialized successfully");

        Ok(Self {
            http_client,
            base_url: "https://api.honeypot.is".to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_count: DEFAULT_RETRY_COUNT,
            enabled: true,
        })
    }

    /// Create a new HoneypotIsClient with custom parameters
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

    /// Create a new HoneypotIsClient for testing
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

    /// Check if a token is a honeypot
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    /// * `chain_id` - Chain ID (1 for Ethereum, 56 for BSC)
    ///
    /// # Returns
    /// * `Ok(HoneypotIsResult)` - Enhanced honeypot detection result
    /// * `Err(anyhow::Error)` - Error if the check fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn check_honeypot(
        &self,
        token_address: &str,
        chain_id: u32,
    ) -> Result<HoneypotIsResult> {
        validate_token_address(token_address, "ethereum")?;

        if !self.enabled {
            return Ok(HoneypotIsResult::default());
        }

        info!("Checking honeypot status for {} on chain {}", token_address, chain_id);

        let url = format!(
            "{}/v2/IsHoneypot?address={}&chainID={}",
            self.base_url, token_address, chain_id
        );

        debug!("Fetching honeypot data from Honeypot.is: {}", url);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .get(&url)
                    .send()
                    .await
                    .context("Failed to send request to Honeypot.is")?;

                let status = response.status();
                debug!("Honeypot.is response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Token not found: {token_address}"))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Honeypot.is"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    Err(anyhow!("Honeypot.is API error: {status} - {error_body}"))
                }
            },
        )
        .await?;

        let parsed: HoneypotIsResponse =
            serde_json::from_str(&response_data).context("Failed to parse Honeypot.is response")?;

        // Extract flags for specific detections
        let has_trading_cooldown = parsed.flags.iter().any(|f| f.contains("COOLDOWN"));
        let has_blacklist = parsed.flags.iter().any(|f| f.contains("BLACKLIST"));
        let anti_whale_modifiable = parsed.max_tx_amount.is_some() || parsed.max_wallet_amount.is_some();

        // Calculate deployer risk score
        let deployer_risk_score = Self::calculate_deployer_risk(&parsed);

        let result = HoneypotIsResult {
            token_address: token_address.to_string(),
            is_honeypot: parsed.is_honeypot || !parsed.simulation_success,
            buy_tax: parsed.buy_tax,
            sell_tax: parsed.sell_tax,
            can_buy: parsed.can_buy,
            can_sell: parsed.can_sell,
            has_trading_cooldown,
            has_blacklist,
            anti_whale_modifiable,
            max_tx_amount: parsed.max_tx_amount,
            max_wallet_amount: parsed.max_wallet_amount,
            deployer_address: parsed.deployer_address,
            deployer_funds: parsed.deployer_funds,
            flags: parsed.flags,
            deployer_risk_score,
        };

        info!(
            "Honeypot.is check completed for {}: is_honeypot={}, buy_tax={}, sell_tax={}",
            token_address, result.is_honeypot, result.buy_tax, result.sell_tax
        );

        Ok(result)
    }

    /// Calculate deployer risk score based on Honeypot.is data
    fn calculate_deployer_risk(response: &HoneypotIsResponse) -> u32 {
        let mut risk = 0u32;

        // High deployer funds = higher risk
        if let Some(funds) = response.deployer_funds {
            if funds > 10000.0 {
                risk += 20;
            } else if funds > 1000.0 {
                risk += 10;
            }
        }

        // Honeypot flags increase risk
        if response.is_honeypot {
            risk += 50;
        }

        // Trading restrictions increase risk
        if response.max_tx_amount.is_some() {
            risk += 10;
        }
        if response.max_wallet_amount.is_some() {
            risk += 10;
        }

        // Dangerous flags
        for flag in &response.flags {
            if flag.contains("BLACKLIST") {
                risk += 20;
            }
            if flag.contains("COOLDOWN") {
                risk += 15;
            }
            if flag.contains("ANTI_BOT") {
                risk += 10;
            }
        }

        risk.min(100)
    }
}

impl Default for HoneypotIsClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default HoneypotIsClient")
    }
}

// Default constants
const DEFAULT_RETRY_COUNT: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> HoneypotIsClient {
        let http_client = Client::builder()
            .http1_only()
            .build()
            .unwrap();

        HoneypotIsClient {
            http_client,
            base_url: mock_server_url.to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_check_honeypot_success() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "isHoneypot": false,
            "simulationSuccess": true,
            "buyTax": 5.0,
            "sellTax": 5.0,
            "maxTxAmount": 1000.0,
            "maxWalletAmount": 5000.0,
            "deployerAddress": "0x1234567890123456789012345678901234567890",
            "deployerFunds": 500.0,
            "flags": [],
            "canBuy": true,
            "canSell": true
        }"#;

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_honeypot("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", 1)
            .await;

        assert!(result.is_ok());
        let honeypot_result = result.unwrap();
        assert!(!honeypot_result.is_honeypot);
        assert_eq!(honeypot_result.buy_tax, 5.0);
        assert_eq!(honeypot_result.sell_tax, 5.0);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_honeypot_detected() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "isHoneypot": true,
            "simulationSuccess": false,
            "buyTax": 99.0,
            "sellTax": 99.0,
            "flags": ["BLACKLIST_FUNCTION", "COOLDOWN"],
            "canBuy": true,
            "canSell": false
        }"#;

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_honeypot("0x1234567890123456789012345678901234567890", 1)
            .await;

        assert!(result.is_ok());
        let honeypot_result = result.unwrap();
        assert!(honeypot_result.is_honeypot);
        assert!(honeypot_result.has_blacklist);
        assert!(honeypot_result.has_trading_cooldown);
        assert!(honeypot_result.deployer_risk_score > 50);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_honeypot_not_found() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .with_body("Not Found")
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_honeypot("0x1234567890123456789012345678901234567890", 1)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));

        mock.assert_async().await;
    }

    #[test]
    fn test_honeypot_is_result_default() {
        let result = HoneypotIsResult::default();
        assert!(!result.is_honeypot);
        assert_eq!(result.buy_tax, 0.0);
        assert_eq!(result.sell_tax, 0.0);
        assert_eq!(result.deployer_risk_score, 0);
    }
}
