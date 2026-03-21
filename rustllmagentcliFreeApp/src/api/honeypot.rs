//! Honeypot.is API client for honeypot detection
//!
//! Honeypot.is provides honeypot detection services including:
//! - Buy/sell simulation
//! - Tax calculation
//! - Contract analysis for honeypot patterns
//!
//! Official API Documentation:
//! - https://docs.honeypot.is/quickstart
//! - https://docs.honeypot.is/ishoneypot
//!
//! API Endpoint: POST https://api.honeypot.is/v2/isHoneypot
//! Request Body: {"token": "0x...", "chainId": 1}
//! Response: {"success": true, "data": {"isHoneypot": false, "buyTax": 0, ...}}

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::float_cmp)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::too_many_lines)] // Allowed due to complex error handling logic

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, create_http_client,
    validate_token_address, with_retry,
};

/// Honeypot.is API client
#[derive(Debug, Clone)]
pub struct HoneypotClient {
    http_client: Client,
    base_url: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// Honeypot check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotResult {
    /// Token address that was checked
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
    /// Additional error message if any
    pub error: Option<String>,
    /// Simulation details
    pub simulation: Option<SimulationResult>,
}

impl Default for HoneypotResult {
    fn default() -> Self {
        Self {
            token_address: String::new(),
            chain: String::new(),
            is_honeypot: false,
            buy_tax: 0.0,
            sell_tax: 0.0,
            can_buy: true,
            can_sell: true,
            error: None,
            simulation: None,
        }
    }
}

/// Simulation result details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// Buy amount in native token
    pub buy_amount: Option<String>,
    /// Sell amount in native token
    pub sell_amount: Option<String>,
    /// Gas used for buy
    pub buy_gas: Option<u64>,
    /// Gas used for sell
    pub sell_gas: Option<u64>,
    /// Buy output amount
    pub buy_output: Option<String>,
    /// Sell output amount
    pub sell_output: Option<String>,
}

/// Raw response from Honeypot.is API (official v2 format - FLAT structure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotResponse {
    /// Whether the token is a honeypot
    #[serde(rename = "isHoneypot", default)]
    pub is_honeypot: bool,
    /// Reason why it's a honeypot (if applicable)
    #[serde(rename = "honeypotReason", default)]
    pub honeypot_reason: Option<String>,
    /// Buy tax percentage
    #[serde(rename = "buyTax", default)]
    pub buy_tax: Option<f64>,
    /// Sell tax percentage
    #[serde(rename = "sellTax", default)]
    pub sell_tax: Option<f64>,
    /// Whether buying is possible
    #[serde(rename = "canBuy", default)]
    pub can_buy: Option<bool>,
    /// Whether selling is possible
    #[serde(rename = "canSell", default)]
    pub can_sell: Option<bool>,
    /// Transfer tax
    #[serde(rename = "transferTax", default)]
    pub transfer_tax: Option<f64>,
    /// Buy gas estimate
    #[serde(rename = "buyGas", default)]
    pub buy_gas: Option<String>,
    /// Sell gas estimate
    #[serde(rename = "sellGas", default)]
    pub sell_gas: Option<String>,
    /// Creation time
    #[serde(rename = "creationTime", default)]
    pub creation_time: Option<String>,
    /// Liquidity amount
    #[serde(rename = "liquidity", default)]
    pub liquidity: Option<String>,
    /// Creator address
    #[serde(rename = "creatorAddress", default)]
    pub creator_address: Option<String>,
    /// Owner address
    #[serde(rename = "ownerAddress", default)]
    pub owner_address: Option<String>,
    /// Holder count
    #[serde(rename = "holderCount", default)]
    pub holder_count: Option<u64>,
    /// Additional error message
    #[serde(rename = "error", default)]
    pub error: Option<String>,
}

impl HoneypotClient {
    /// Create a new Honeypot client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new Honeypot client with custom configuration
    pub fn with_config(config: &ApiConfig) -> Result<Self> {
        // Use default timeout since no specific config in ApiConfig
        let http_client = create_http_client(Duration::from_secs(10))?;

        Ok(Self {
            http_client,
            base_url: "https://honeypot.is".to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 3,
            enabled: true,
        })
    }

    /// Create a new Honeypot client with custom parameters
    pub fn with_params(timeout: Duration, retry_count: u32, enabled: bool) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://honeypot.is".to_string(),
            timeout,
            retry_count,
            enabled,
        })
    }

    /// Create a new Honeypot client for testing with custom base URL
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

    /// Check if a token is a honeypot using the official Honeypot.is API v2
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to check
    /// * `chain` - The blockchain network (ethereum, bsc, etc.)
    ///
    /// # Returns
    /// * `Ok(HoneypotResult)` - Honeypot detection result
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address, chain = %chain))]
    pub async fn check_honeypot(&self, token_address: &str, chain: &str) -> Result<HoneypotResult> {
        if !self.enabled {
            warn!("Honeypot.is API is disabled");
            return Err(anyhow!("Honeypot.is API is disabled"));
        }

        // Validate token address
        validate_token_address(token_address, chain)?;

        // Use GET method with query parameters (as per cliVersionFull implementation)
        let endpoint = format!(
            "{}/v2/IsHoneypot?address={}&chain=eth",
            self.base_url, token_address
        );

        debug!("Checking honeypot status: GET {}", endpoint);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .get(&endpoint)
                    .header("accept", "application/json")
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
                    debug!("Honeypot.is response body length: {}", body.len());
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Token not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Honeypot.is"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    Err(anyhow!("Honeypot.is API error: {} - {}", status, error_body))
                }
            },
        )
        .await?;

        // Parse the response (flat structure as per cliVersionFull)
        let parsed: HoneypotResponse =
            serde_json::from_str(&response_data).context("Failed to parse Honeypot.is response")?;

        let result = HoneypotResult {
            token_address: token_address.to_string(),
            chain: chain.to_string(),
            is_honeypot: parsed.is_honeypot,
            buy_tax: parsed.buy_tax.unwrap_or(0.0) as f32,
            sell_tax: parsed.sell_tax.unwrap_or(0.0) as f32,
            can_buy: parsed.can_buy.unwrap_or(true),
            can_sell: parsed.can_sell.unwrap_or(true),
            error: None,
            simulation: parsed.buy_gas.as_ref().map(|_| SimulationResult {
                buy_amount: None,
                sell_amount: None,
                buy_gas: parsed.buy_gas.as_ref().and_then(|g| g.parse().ok()),
                sell_gas: parsed.sell_gas.as_ref().and_then(|g| g.parse().ok()),
                buy_output: None,
                sell_output: None,
            }),
        };

        if result.is_honeypot {
            warn!(
                "HONEYPOT DETECTED for {} on {}: buy_tax={}, sell_tax={}",
                token_address, chain, result.buy_tax, result.sell_tax
            );
        } else {
            info!(
                "Token {} on {} is NOT a honeypot: buy_tax={}, sell_tax={}, can_buy={}, can_sell={}",
                token_address, chain, result.buy_tax, result.sell_tax, result.can_buy, result.can_sell
            );
        }

        Ok(result)
    }

    /// Check multiple tokens for honeypot status
    ///
    /// # Arguments
    /// * `tokens` - List of (token_address, chain) tuples to check
    ///
    /// # Returns
    /// * `Ok(Vec<HoneypotResult>)` - List of honeypot results (may exclude failed lookups)
    pub async fn check_multiple(&self, tokens: &[(&str, &str)]) -> Result<Vec<HoneypotResult>> {
        let mut results = Vec::with_capacity(tokens.len());

        for (address, chain) in tokens {
            match self.check_honeypot(address, chain).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!("Failed to check honeypot for {}: {}", address, e);
                    // Continue with other tokens
                }
            }
        }

        Ok(results)
    }
}

impl Default for HoneypotClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default HoneypotClient")
    }
}

/// Map chain name to numeric chain ID for Honeypot.is API
/// See https://docs.honeypot.is/ishoneypot for supported chains
fn chain_to_numeric_id(chain: &str) -> u64 {
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" | "mainnet" => 1,
        "bsc" | "binance" | "bnb" | "binance smart chain" => 56,
        "polygon" | "matic" | "polygon pos" => 137,
        "arbitrum" | "arbitrum one" => 42161,
        "optimism" => 10,
        "base" => 8453,
        "avalanche" | "avax" => 43114,
        "fantom" | "ftm" => 250,
        "cronos" | "cro" => 25,
        "gnosis" | "xdai" => 100,
        "aurora" => 1_313_161_554,
        "harmony" => 1_666_600_000,
        "moonbeam" => 1284,
        "moonriver" => 1285,
        "celo" => 42220,
        "fuse" => 122,
        "kcc" | "kucoin" => 321,
        "heco" | "huobi" => 128,
        "okex" | "okc" => 66,
        "velas" => 106,
        "syscoin" => 57,
        "milkomeda" => 2001,
        "evmos" => 9001,
        "boba" => 288,
        "metis" => 1088,
        "iotex" => 4689,
        "kava" => 2222,
        "step" => 1234,
        _ => 1, // Default to Ethereum mainnet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> HoneypotClient {
        let http_client = Client::builder()
            .http1_only() // Use HTTP/1.1 for mockito compatibility
            .build()
            .unwrap();

        HoneypotClient {
            http_client,
            base_url: mock_server_url.to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0, // No retries in tests
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_check_honeypot_not_honeypot() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "success": true,
            "data": {
                "isHoneypot": false,
                "buyTax": 5.0,
                "sellTax": 5.0,
                "canBuy": true,
                "canSell": true,
                "buyGas": "150000",
                "sellGas": "150000"
            }
        }"#;

        let mock = server
            .mock(
                "POST",
                "/v2/isHoneypot",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .check_honeypot("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert!(!data.is_honeypot);
        assert!((data.buy_tax - 5.0).abs() < 0.01);
        assert!((data.sell_tax - 5.0).abs() < 0.01);
        assert!(data.can_buy);
        assert!(data.can_sell);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_honeypot_is_honeypot() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "success": true,
            "data": {
                "isHoneypot": true,
                "buyTax": 0.0,
                "sellTax": 99.0,
                "canBuy": true,
                "canSell": false,
                "error": "Sell simulation failed"
            }
        }"#;

        let mock = server
            .mock(
                "POST",
                "/v2/isHoneypot",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .check_honeypot("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert!(data.is_honeypot);
        assert!(!data.can_sell);
        assert!(data.error.is_some());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_honeypot_not_found() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "POST",
                "/v2/isHoneypot",
            )
            .with_status(404)
            .with_body("Not Found")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .check_honeypot("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Token not found"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_honeypot_rate_limit() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "POST",
                "/v2/isHoneypot",
            )
            .with_status(429)
            .with_body("Too Many Requests")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .check_honeypot("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limited"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_honeypot_server_error() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "POST",
                "/v2/isHoneypot",
            )
            .with_status(500)
            .with_body("Internal Server Error")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .check_honeypot("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("API error"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_honeypot_invalid_json() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "POST",
                "/v2/isHoneypot",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("not valid json")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .check_honeypot("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parse"));

        mock.assert_async().await;
    }

    #[test]
    fn test_check_honeypot_disabled() {
        let client = HoneypotClient {
            http_client: Client::new(),
            base_url: "https://honeypot.is".to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 3,
            enabled: false,
        };

        let result = futures::executor::block_on(
            client.check_honeypot("0x1234567890123456789012345678901234567890", "ethereum"),
        );

        // Now returns Err when disabled
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    #[test]
    fn test_check_honeypot_invalid_address() {
        let client = HoneypotClient::default();

        let result =
            futures::executor::block_on(client.check_honeypot("invalid_address", "ethereum"));

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must start with 0x")
        );
    }

    #[tokio::test]
    async fn test_check_honeypot_bsc_chain() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "success": true,
            "data": {
                "isHoneypot": false,
                "buyTax": 3.0,
                "sellTax": 3.0,
                "canBuy": true,
                "canSell": true
            }
        }"#;

        let mock = server
            .mock(
                "POST",
                "/v2/isHoneypot",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .check_honeypot("0x1234567890123456789012345678901234567890", "bsc")
            .await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.chain, "bsc");
        assert!(!data.is_honeypot);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_multiple_tokens() {
        let mut server = Server::new_async().await;

        let mock_response1 = r#"{
            "success": true,
            "data": {
                "isHoneypot": false,
                "buyTax": 5.0,
                "sellTax": 5.0,
                "canBuy": true,
                "canSell": true
            }
        }"#;

        let mock_response2 = r#"{
            "success": true,
            "data": {
                "isHoneypot": true,
                "buyTax": 0.0,
                "sellTax": 99.0,
                "canBuy": true,
                "canSell": false
            }
        }"#;

        let mock1 = server
            .mock(
                "POST",
                "/v2/isHoneypot",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response1)
            .create_async()
            .await;

        let mock2 = server
            .mock(
                "POST",
                "/v2/isHoneypot",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response2)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let tokens = vec![
            ("0x1111567890123456789012345678901234567890", "ethereum"),
            ("0x2222567890123456789012345678901234567890", "ethereum"),
        ];

        let results = client.check_multiple(&tokens).await.unwrap();

        assert_eq!(results.len(), 2);
        assert!(!results[0].is_honeypot);
        assert!(results[1].is_honeypot);

        mock1.assert_async().await;
        mock2.assert_async().await;
    }

    #[test]
    fn test_honeypot_result_serialization() {
        let result = HoneypotResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            is_honeypot: false,
            buy_tax: 5.0,
            sell_tax: 5.0,
            can_buy: true,
            can_sell: true,
            error: None,
            simulation: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: HoneypotResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result.token_address, deserialized.token_address);
        assert_eq!(result.is_honeypot, deserialized.is_honeypot);
        assert_eq!(result.buy_tax, deserialized.buy_tax);
    }
}
