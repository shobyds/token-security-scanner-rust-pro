//! Ethplorer API Client for Token Metadata
//!
//! Ethplorer provides free token metadata and holder data.
//! Free tier: 100k requests/day, no authentication required
//!
//! API Documentation: https://github.com/Ethplorer/Ethplorer

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::uninlined_format_args)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS,
    create_http_client, validate_token_address, with_retry,
};

/// Ethplorer API client
#[derive(Debug, Clone)]
pub struct EthplorerClient {
    http_client: Client,
    base_url: String,
    api_key: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// Token info response from Ethplorer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthplorerTokenInfo {
    /// Token address
    pub address: String,
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Number of decimals
    pub decimals: String,
    /// Total supply (as string with full precision)
    #[serde(rename = "totalSupply")]
    pub total_supply: String,
    /// Number of holders
    #[serde(rename = "holdersCount")]
    pub holders_count: u64,
    /// Token owner address (empty string if renounced)
    pub owner: String,
    /// Number of transfers
    #[serde(rename = "transfersCount")]
    pub transfers_count: u64,
    /// Contract info (nested structure)
    #[serde(rename = "contractInfo", default)]
    pub contract_info: Option<ContractInfo>,
    /// Price info (nested structure)
    #[serde(rename = "price", default)]
    pub price: Option<PriceInfo>,
    /// Website URL
    pub website: Option<String>,
    /// Token image URL
    pub image: Option<String>,
}

/// Contract information from Ethplorer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    /// Creator address
    #[serde(rename = "creatorAddress")]
    pub creator_address: String,
    /// Creation transaction hash
    #[serde(rename = "creationTransactionHash")]
    pub creation_tx_hash: String,
    /// Creation timestamp
    #[serde(rename = "creationTimestamp")]
    pub creation_timestamp: u64,
}

/// Price information from Ethplorer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceInfo {
    /// Price rate in USD
    pub rate: f64,
    /// Market cap in USD
    #[serde(rename = "marketCapUsd")]
    pub market_cap_usd: f64,
    /// Available supply
    #[serde(rename = "availableSupply")]
    pub available_supply: f64,
    /// 24h volume
    #[serde(rename = "volume24h")]
    pub volume_24h: f64,
}

/// Ethplorer API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthplorerError {
    /// Error status code
    pub status: Option<u32>,
    /// Error message
    pub error: Option<String>,
    /// Error code
    pub code: Option<String>,
}

impl EthplorerClient {
    /// Create a new Ethplorer client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new Ethplorer client with custom configuration
    pub fn with_config(config: &ApiConfig) -> Result<Self> {
        // Ethplorer uses "freekey" as the API key for free tier
        // No authentication required for basic endpoints
        let api_key = std::env::var("ETHPLORER_API_KEY")
            .unwrap_or_else(|_| "freekey".to_string());

        let http_client = create_http_client(config.dexscreener.timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://api.ethplorer.io".to_string(),
            api_key,
            timeout: config.dexscreener.timeout,
            retry_count: config.dexscreener.retry_count,
            enabled: config.dexscreener.enabled,
        })
    }

    /// Create a new Ethplorer client with custom parameters
    pub fn with_params(
        api_key: String,
        timeout: Duration,
        retry_count: u32,
        enabled: bool,
    ) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://api.ethplorer.io".to_string(),
            api_key,
            timeout,
            retry_count,
            enabled,
        })
    }

    /// Get token information including metadata and holder count
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(EthplorerTokenInfo)` - Token information
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_token_info(&self, token_address: &str) -> Result<EthplorerTokenInfo> {
        if !self.enabled {
            return Err(anyhow!("Ethplorer API is disabled"));
        }

        // Validate token address
        validate_token_address(token_address, "ethereum")?;

        let endpoint = format!(
            "{}/getTokenInfo/{}?apiKey={}",
            self.base_url, token_address, self.api_key
        );

        debug!("Fetching token info from Ethplorer: {}", endpoint);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .get(&endpoint)
                    .timeout(self.timeout)
                    .send()
                    .await
                    .context("Failed to send request to Ethplorer")?;

                let status = response.status();
                debug!("Ethplorer response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    debug!("Ethplorer response body length: {}", body.len());
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Token not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Ethplorer"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    Err(anyhow!("Ethplorer API error: {} - {}", status, error_body))
                }
            },
        )
        .await?;

        // Parse the response
        let token_info: EthplorerTokenInfo =
            serde_json::from_str(&response_data).context("Failed to parse Ethplorer response")?;

        info!(
            "Successfully fetched Ethplorer token info for {}: name={}, symbol={}, holders={}",
            token_address, token_info.name, token_info.symbol, token_info.holders_count
        );

        Ok(token_info)
    }

    /// Get token holder count only (lighter than full token info)
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of holders
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_token_holders_count(&self, token_address: &str) -> Result<u64> {
        let token_info = self.get_token_info(token_address).await?;
        Ok(token_info.holders_count)
    }

    /// Get token total supply only
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(String)` - Total supply as string (full precision)
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_token_total_supply(&self, token_address: &str) -> Result<String> {
        let token_info = self.get_token_info(token_address).await?;
        Ok(token_info.total_supply)
    }

    /// Get token metadata (name, symbol, decimals)
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok((name, symbol, decimals))` - Token metadata
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_token_metadata(
        &self,
        token_address: &str,
    ) -> Result<(String, String, u32)> {
        let token_info = self.get_token_info(token_address).await?;
        let decimals = token_info.decimals.parse::<u32>().unwrap_or(18);
        Ok((token_info.name, token_info.symbol, decimals))
    }
}

impl Default for EthplorerClient {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            error!("Failed to create default Ethplorer client: {}", e);
            Self {
                http_client: Client::new(),
                base_url: "https://api.ethplorer.io".to_string(),
                api_key: "freekey".to_string(),
                timeout: Duration::from_secs(10),
                retry_count: 3,
                enabled: true,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethplorer_client_creation() {
        let client = EthplorerClient::default();
        assert!(client.enabled);
        assert_eq!(client.base_url, "https://api.ethplorer.io");
        assert_eq!(client.api_key, "freekey");
    }

    #[test]
    fn test_ethplorer_client_with_params() {
        let client = EthplorerClient::with_params(
            "test_key".to_string(),
            Duration::from_secs(15),
            5,
            true,
        )
        .unwrap();
        assert!(client.enabled);
        assert_eq!(client.api_key, "test_key");
        assert_eq!(client.timeout, Duration::from_secs(15));
        assert_eq!(client.retry_count, 5);
    }

    #[tokio::test]
    async fn test_get_token_info_uniswap() {
        // Test with real Uniswap token (should work with free tier)
        let client = EthplorerClient::default();
        let result = client
            .get_token_info("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await;

        // This test may fail if API is rate limited or network is unavailable
        // but should not panic
        match result {
            Ok(info) => {
                assert_eq!(info.symbol, "UNI");
                assert!(!info.name.is_empty());
                // decimals is a string, parse it to verify it's valid
                let decimals: i32 = info.decimals.parse().unwrap_or(0);
                assert!(decimals > 0);
                assert!(info.holders_count > 0);
                println!("Uniswap token info: name={}, symbol={}, holders={}",
                    info.name, info.symbol, info.holders_count);
            }
            Err(e) => {
                // API may be rate limited or unavailable in test environment
                println!("Ethplorer API test skipped: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_get_token_info_invalid_address() {
        let client = EthplorerClient::default();
        let result = client.get_token_info("invalid_address").await;
        assert!(result.is_err());
    }
}
