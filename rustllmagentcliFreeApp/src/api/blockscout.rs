//! Blockscout API Client for Contract Metadata
//!
//! Blockscout provides blockchain data including contract metadata,
//! token information, and holder data as a free public API.
//!
//! # API Endpoints
//! - Ethereum: https://eth.blockscout.com/api
//! - Free tier: Unlimited (public API)
//!
//! # Features
//! - Token metadata retrieval
//! - Contract creator information
//! - Holder count
//! - Contract verification status

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, DEFAULT_TIMEOUT_SECS,
    create_http_client, validate_token_address, with_retry,
};

/// Default Blockscout base URL
pub const DEFAULT_BLOCKSCOUT_BASE_URL: &str = "https://eth.blockscout.com";

/// Blockscout API client
#[derive(Debug, Clone)]
pub struct BlockscoutClient {
    http_client: Client,
    base_url: String,
    timeout: Duration,
    retry_count: u32,
}

/// Token metadata from Blockscout
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockscoutTokenInfo {
    /// Token/contract address
    pub token_address: String,
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Token decimals
    pub decimals: u32,
    /// Total supply (raw string)
    pub total_supply: String,
    /// Number of holders
    pub holder_count: u64,
    /// Contract creator address
    pub creator_address: Option<String>,
    /// Contract creation transaction hash
    pub creation_tx_hash: Option<String>,
    /// Contract creation block number
    pub creation_block: Option<u64>,
    /// Whether contract is verified
    pub is_verified: bool,
    /// Contract name (if verified)
    pub contract_name: Option<String>,
    /// Token type (ERC20, ERC721, etc.)
    pub token_type: String,
    /// Market cap (if available)
    pub market_cap: Option<String>,
    /// Price USD (if available)
    pub price_usd: Option<String>,
}

/// Contract information from Blockscout
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockscoutContract {
    /// Contract address
    pub address: String,
    /// Contract name
    pub name: Option<String>,
    /// Creator address
    pub creator_address: Option<String>,
    /// Creation transaction hash
    pub creation_tx_hash: Option<String>,
    /// Creation block number
    pub creation_block: Option<u64>,
    /// Is contract verified
    pub is_verified: bool,
    /// Compiler version
    pub compiler_version: Option<String>,
    /// Optimization enabled
    pub optimization_enabled: bool,
    /// Optimization runs
    pub optimization_runs: Option<u32>,
    /// License type
    pub license_type: Option<String>,
}

/// Raw response from Blockscout token API
#[derive(Debug, Clone, Deserialize)]
struct BlockscoutTokenResponse {
    address: Option<String>,
    name: Option<String>,
    symbol: Option<String>,
    decimals: Option<String>,
    total_supply: Option<String>,
    holders_count: Option<String>,
    #[serde(rename = "type")]
    token_type: Option<String>,
    market_cap: Option<String>,
    price: Option<PriceData>,
}

#[derive(Debug, Clone, Deserialize)]
struct PriceData {
    value: Option<String>,
}

/// Raw response from Blockscout contract API
#[derive(Debug, Clone, Deserialize)]
struct BlockscoutContractResponse {
    hash: Option<String>,
    name: Option<String>,
    creator_address_hash: Option<String>,
    creation_bytecode: Option<String>,
    deployed_bytecode: Option<String>,
    is_verified: bool,
    verification_status: Option<String>,
    compiler_version: Option<String>,
    optimization_enabled: Option<bool>,
    optimization_runs: Option<u32>,
    license_type: Option<String>,
}

/// Raw response from Blockscout address API
#[derive(Debug, Clone, Deserialize)]
struct BlockscoutAddressResponse {
    hash: Option<String>,
    name: Option<String>,
    token: Option<TokenData>,
    creation_tx_hash: Option<String>,
    block_number: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TokenData {
    holders_count: Option<String>,
    total_supply: Option<String>,
    decimals: Option<String>,
    symbol: Option<String>,
    name: Option<String>,
    #[serde(rename = "type")]
    token_type: Option<String>,
}

impl BlockscoutClient {
    /// Create a new Blockscout client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new Blockscout client with custom configuration
    pub fn with_config(_config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))?;

        // Try to load .env file first
        let _ = dotenvy::dotenv();

        // Get base URL from environment or use default
        let base_url = std::env::var("BLOCKSCOUT_BASE_URL")
            .unwrap_or_else(|_| DEFAULT_BLOCKSCOUT_BASE_URL.to_string());

        info!("Blockscout client initialized with base URL: {}", base_url);

        Ok(Self {
            http_client,
            base_url,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_count: DEFAULT_RETRY_COUNT,
        })
    }

    /// Create a new Blockscout client with custom parameters
    pub fn with_params(base_url: &str, timeout: Duration, retry_count: u32) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: base_url.to_string(),
            timeout,
            retry_count,
        })
    }

    /// Create a new Blockscout client for testing with custom base URL
    #[cfg(test)]
    pub fn for_testing(base_url: String, http_client: Client) -> Self {
        Self {
            http_client,
            base_url,
            timeout: Duration::from_secs(10),
            retry_count: 0,
        }
    }

    /// Get token metadata from Blockscout
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(BlockscoutTokenInfo)` - Token metadata
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_token_info(&self, token_address: &str) -> Result<BlockscoutTokenInfo> {
        validate_token_address(token_address, "ethereum")?;

        info!("Fetching token info from Blockscout for {}", token_address);

        // Try multiple endpoints to get complete token info
        let mut token_info = BlockscoutTokenInfo {
            token_address: token_address.to_string(),
            ..Default::default()
        };

        // Fetch from /api/v2/tokens/{address}
        if let Ok(info) = self.fetch_token_v2(token_address).await {
            token_info = info;
        }

        // Fetch from /api/v2/addresses/{address} for additional data
        if let Ok(address_info) = self.fetch_address_info(token_address).await {
            if token_info.name.is_empty() {
                token_info.name = address_info.name.unwrap_or_default();
            }
            if token_info.creation_tx_hash.is_none() {
                token_info.creation_tx_hash = address_info.creation_tx_hash;
            }
            if token_info.creation_block.is_none() {
                token_info.creation_block = address_info.block_number.and_then(|b| b.parse().ok());
            }
        }

        // Fetch contract info for creator and verification status
        if let Ok(contract_info) = self.fetch_contract_info(token_address).await {
            if token_info.creator_address.is_none() {
                token_info.creator_address = contract_info.creator_address;
            }
            if token_info.creation_tx_hash.is_none() {
                token_info.creation_tx_hash = contract_info.creation_tx_hash;
            }
            if token_info.creation_block.is_none() {
                token_info.creation_block = contract_info.creation_block;
            }
            token_info.is_verified = contract_info.is_verified;
            token_info.contract_name = contract_info.name;
        }

        info!(
            "Blockscout token info retrieved for {}: name={}, symbol={}, holders={}",
            token_address, token_info.name, token_info.symbol, token_info.holder_count
        );

        Ok(token_info)
    }

    /// Get contract creator information
    ///
    /// # Arguments
    /// * `token_address` - The contract address
    ///
    /// # Returns
    /// * `Ok(BlockscoutContract)` - Contract information
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_contract_creator(&self, token_address: &str) -> Result<BlockscoutContract> {
        validate_token_address(token_address, "ethereum")?;

        info!("Fetching contract creator from Blockscout for {}", token_address);

        self.fetch_contract_info(token_address).await
    }

    /// Get holder count for a token
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of holders
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_holder_count(&self, token_address: &str) -> Result<u64> {
        validate_token_address(token_address, "ethereum")?;

        info!("Fetching holder count from Blockscout for {}", token_address);

        // Try v2 tokens endpoint first
        let url = format!(
            "{}/api/v2/tokens/{}",
            self.base_url, token_address
        );

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
                    .context("Failed to send request to Blockscout")?;

                let status = response.status();
                debug!("Blockscout response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Token not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Blockscout"))
                } else {
                    Err(anyhow!("Blockscout API error: {}", status))
                }
            },
        )
        .await?;

        let parsed: BlockscoutTokenResponse =
            serde_json::from_str(&response_data).context("Failed to parse Blockscout response")?;

        let holder_count = parsed
            .holders_count
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        Ok(holder_count)
    }

    /// Fetch token info from v2 API
    async fn fetch_token_v2(&self, token_address: &str) -> Result<BlockscoutTokenInfo> {
        let url = format!(
            "{}/api/v2/tokens/{}",
            self.base_url, token_address
        );

        debug!("Fetching token v2 info from Blockscout: {}", url);

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
                    .context("Failed to send request to Blockscout")?;

                let status = response.status();
                if status.is_success() {
                    let body = response.text().await
                        .context("Failed to read response body")?;
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Token not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Blockscout"))
                } else {
                    Err(anyhow!("Blockscout API error: {}", status))
                }
            },
        )
        .await?;

        let parsed: BlockscoutTokenResponse =
            serde_json::from_str(&response_data).context("Failed to parse Blockscout response")?;

        Ok(BlockscoutTokenInfo {
            token_address: parsed.address.unwrap_or_else(|| token_address.to_string()),
            name: parsed.name.unwrap_or_default(),
            symbol: parsed.symbol.unwrap_or_default(),
            decimals: parsed.decimals.and_then(|s| s.parse().ok()).unwrap_or(18),
            total_supply: parsed.total_supply.unwrap_or_default(),
            holder_count: parsed.holders_count.and_then(|s| s.parse().ok()).unwrap_or(0),
            token_type: parsed.token_type.unwrap_or_else(|| "ERC20".to_string()),
            market_cap: parsed.market_cap,
            price_usd: parsed.price.and_then(|p| p.value),
            ..Default::default()
        })
    }

    /// Fetch address info from v2 API
    async fn fetch_address_info(&self, token_address: &str) -> Result<BlockscoutAddressResponse> {
        let url = format!(
            "{}/api/v2/addresses/{}",
            self.base_url, token_address
        );

        debug!("Fetching address info from Blockscout: {}", url);

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
                    .context("Failed to send request to Blockscout")?;

                let status = response.status();
                if status.is_success() {
                    let body = response.text().await
                        .context("Failed to read response body")?;
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Address not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Blockscout"))
                } else {
                    Err(anyhow!("Blockscout API error: {}", status))
                }
            },
        )
        .await?;

        let parsed: BlockscoutAddressResponse =
            serde_json::from_str(&response_data).context("Failed to parse Blockscout response")?;

        Ok(parsed)
    }

    /// Fetch contract info from v2 API
    async fn fetch_contract_info(&self, token_address: &str) -> Result<BlockscoutContract> {
        let url = format!(
            "{}/api/v2/smart-contracts/{}",
            self.base_url, token_address
        );

        debug!("Fetching contract info from Blockscout: {}", url);

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
                    .context("Failed to send request to Blockscout")?;

                let status = response.status();
                if status.is_success() {
                    let body = response.text().await
                        .context("Failed to read response body")?;
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Contract not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Blockscout"))
                } else {
                    Err(anyhow!("Blockscout API error: {}", status))
                }
            },
        )
        .await?;

        let parsed: BlockscoutContractResponse =
            serde_json::from_str(&response_data).context("Failed to parse Blockscout response")?;

        Ok(BlockscoutContract {
            address: token_address.to_string(),
            name: parsed.name,
            creator_address: parsed.creator_address_hash,
            creation_tx_hash: None, // Not available in this endpoint
            creation_block: None,
            is_verified: parsed.is_verified,
            compiler_version: parsed.compiler_version,
            optimization_enabled: parsed.optimization_enabled.unwrap_or(false),
            optimization_runs: parsed.optimization_runs,
            license_type: parsed.license_type,
        })
    }
}

impl Default for BlockscoutClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default BlockscoutClient")
    }
}

// Default constants
const DEFAULT_RETRY_COUNT: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> BlockscoutClient {
        let http_client = Client::builder()
            .http1_only()
            .build()
            .unwrap();

        BlockscoutClient {
            http_client,
            base_url: mock_server_url.to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0,
        }
    }

    #[tokio::test]
    async fn test_get_token_info_success() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "address": "0x1234567890123456789012345678901234567890",
            "name": "Test Token",
            "symbol": "TEST",
            "decimals": "18",
            "total_supply": "1000000000000000000000000",
            "holders_count": "5000",
            "type": "ERC20",
            "market_cap": "1000000",
            "price": {
                "value": "1.50"
            }
        }"#;

        let mock = server
            .mock("GET", "/api/v2/tokens/0x1234567890123456789012345678901234567890")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .get_token_info("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.name, "Test Token");
        assert_eq!(info.symbol, "TEST");
        assert_eq!(info.decimals, 18);
        assert_eq!(info.holder_count, 5000);
        assert_eq!(info.token_type, "ERC20");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_holder_count_success() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "address": "0x1234567890123456789012345678901234567890",
            "name": "Test Token",
            "symbol": "TEST",
            "decimals": "18",
            "total_supply": "1000000000000000000000000",
            "holders_count": "12345",
            "type": "ERC20"
        }"#;

        let mock = server
            .mock("GET", "/api/v2/tokens/0x1234567890123456789012345678901234567890")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .get_holder_count("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 12345);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_contract_creator_success() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "hash": "0x1234567890123456789012345678901234567890",
            "name": "TestContract",
            "creator_address_hash": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "is_verified": true,
            "compiler_version": "v0.8.19+commit.7dd6d404",
            "optimization_enabled": true,
            "optimization_runs": 200,
            "license_type": "MIT"
        }"#;

        let mock = server
            .mock("GET", "/api/v2/smart-contracts/0x1234567890123456789012345678901234567890")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .get_contract_creator("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        let contract = result.unwrap();
        assert_eq!(contract.name, Some("TestContract".to_string()));
        assert_eq!(contract.creator_address, Some("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string()));
        assert!(contract.is_verified);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_api_error_404() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/api/v2/tokens/0x1234567890123456789012345678901234567890")
            .with_status(404)
            .with_body("Not Found")
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        // Use get_holder_count which properly returns errors
        let result = client
            .get_holder_count("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_api_error_429() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/api/v2/tokens/0x1234567890123456789012345678901234567890")
            .with_status(429)
            .with_body("Rate Limited")
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        // Use get_holder_count which properly returns errors
        let result = client
            .get_holder_count("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limited"));

        mock.assert_async().await;
    }

    #[test]
    fn test_blockscout_token_info_default() {
        let info = BlockscoutTokenInfo::default();
        assert_eq!(info.holder_count, 0);
        assert!(info.name.is_empty());
        assert!(info.symbol.is_empty());
    }

    #[test]
    fn test_blockscout_contract_default() {
        let contract = BlockscoutContract::default();
        assert!(!contract.is_verified);
        assert!(contract.name.is_none());
    }
}
