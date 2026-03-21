//! Deployer History and Wallet Analysis API
//!
//! This module provides comprehensive deployer profile analysis including:
//! - Deployer wallet age calculation
//! - Deployer history (all contracts deployed)
//! - Previous rug pull detection
//! - Known scammer identification
//! - Deployer risk scoring
//!
//! # Features
//! - Etherscan txlist API integration
//! - GoPlus scam list integration
//! - Wallet age calculation
//! - Deployer risk scoring

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::items_after_statements)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, UNIX_EPOCH};
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, DEFAULT_TIMEOUT_SECS,
    create_http_client, validate_token_address, with_retry,
};

/// Deployer profile with comprehensive wallet analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeployerProfile {
    /// Deployer wallet address
    pub address: String,
    /// First transaction block number
    pub first_tx_block: u64,
    /// Wallet age in days
    pub wallet_age_days: u32,
    /// Total contracts deployed by this address
    pub total_contracts: u32,
    /// Number of previous rug pulls
    pub previous_rugs: u32,
    /// Whether deployer is a known scammer
    pub is_known_scammer: bool,
    /// Deployer risk score (0-100, higher = riskier)
    pub deployer_risk_score: u32,
    /// List of contracts deployed by this address
    pub contracts: Vec<DeployedContract>,
    /// Deployer creation timestamp
    pub creation_timestamp: u64,
}

/// Individual deployed contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedContract {
    /// Contract address
    pub address: String,
    /// Contract name
    pub name: Option<String>,
    /// Deployment block number
    pub block_number: u64,
    /// Deployment timestamp
    pub timestamp: u64,
    /// Whether this contract was flagged as a scam
    pub is_scam: bool,
    /// Whether this contract was flagged as a rug pull
    pub is_rug: bool,
}

/// Deployer history analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeployerHistory {
    /// Deployer address
    pub deployer_address: String,
    /// All contracts deployed
    pub contracts: Vec<DeployedContract>,
    /// Number of rug pulls
    pub rug_count: u32,
    /// Total contracts deployed
    pub total_deployed: u32,
    /// Average time between deployments (days)
    pub avg_deployment_interval_days: f64,
    /// First deployment timestamp
    pub first_deployment: u64,
    /// Last deployment timestamp
    pub last_deployment: u64,
}

/// Etherscan txlist response
#[derive(Debug, Clone, Deserialize)]
struct EtherscanTxListResponse {
    status: String,
    message: String,
    result: Vec<EtherscanTransaction>,
}

/// Etherscan transaction
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EtherscanTransaction {
    block_number: String,
    time_stamp: String,
    hash: String,
    from: String,
    to: String,
    value: String,
    contract_address: Option<String>,
    input: String,
    is_error: String,
}

/// Deployer analysis client
#[derive(Debug, Clone)]
pub struct DeployerClient {
    http_client: Client,
    base_url: String,
    api_key: Option<String>,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

impl DeployerClient {
    /// Create a new DeployerClient with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new DeployerClient with custom configuration
    pub fn with_config(_config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))?;

        // Try to load .env file first
        let _ = dotenvy::dotenv();

        // Get API key from environment
        let api_key = std::env::var("ETHERSCAN_API_KEY").ok();
        let enabled = api_key.is_some() && !api_key.as_ref().unwrap().is_empty();

        if enabled {
            info!("Deployer client initialized successfully");
        } else {
            warn!("Etherscan API key not set - deployer analysis will be limited");
        }

        Ok(Self {
            http_client,
            base_url: "https://api.etherscan.io".to_string(),
            api_key,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_count: DEFAULT_RETRY_COUNT,
            enabled,
        })
    }

    /// Create a new DeployerClient with custom parameters
    pub fn with_params(
        api_key: Option<&str>,
        timeout: Duration,
        retry_count: u32,
    ) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://api.etherscan.io".to_string(),
            api_key: api_key.map(String::from),
            timeout,
            retry_count,
            enabled: api_key.is_some(),
        })
    }

    /// Create a new DeployerClient for testing
    #[cfg(test)]
    pub fn for_testing(base_url: String, http_client: Client, api_key: Option<&str>) -> Self {
        Self {
            http_client,
            base_url,
            api_key: api_key.map(String::from),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: api_key.is_some(),
        }
    }

    /// Get deployer profile for a token
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    /// * `chain` - The blockchain network
    ///
    /// # Returns
    /// * `Ok(DeployerProfile)` - Comprehensive deployer profile
    /// * `Err(anyhow::Error)` - Error if the analysis fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_deployer_profile(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Result<DeployerProfile> {
        validate_token_address(token_address, chain)?;

        if !self.enabled {
            tracing::warn!("DeployerClient is disabled for {} - returning default profile", token_address);
            return Ok(DeployerProfile::default());
        }

        tracing::info!("Getting deployer profile for {} on chain {}", token_address, chain);

        // Get contract creation info from Etherscan
        let creator_address = match self.get_contract_creator(token_address).await {
            Ok(addr) => addr,
            Err(e) => {
                tracing::error!("Failed to get contract creator for {}: {:?}", token_address, e);
                return Ok(DeployerProfile::default());
            }
        };

        if creator_address.is_empty() {
            tracing::warn!("No contract creation data found for {}", token_address);
            return Ok(DeployerProfile::default());
        }

        tracing::info!("Contract creator for {}: {}", token_address, creator_address);

        // Get deployer history
        let history = match self.get_deployer_history(&creator_address).await {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("Failed to get deployer history for creator {}: {:?}", creator_address, e);
                return Ok(DeployerProfile::default());
            }
        };

        // Calculate wallet age from first transaction timestamp to now
        let now = UNIX_EPOCH.elapsed()?.as_secs();
        let wallet_age_days = if history.first_deployment > 0 {
            ((now.saturating_sub(history.first_deployment)) / 86400).try_into().unwrap_or(u32::MAX)
        } else if history.last_deployment > 0 {
            // Fallback to last deployment if first is 0
            ((now.saturating_sub(history.last_deployment)) / 86400).try_into().unwrap_or(u32::MAX)
        } else {
            0
        };

        // Calculate risk score
        let risk_score = Self::calculate_deployer_risk(&history);

        // Check if known scammer (integrate with GoPlus scam list)
        let is_known_scammer = history.rug_count > 0;

        tracing::info!(
            "Deployer profile for {}: address={}, wallet_age={} days (first={}, last={}), risk_score={}, total_contracts={}",
            token_address,
            creator_address,
            wallet_age_days,
            history.first_deployment,
            history.last_deployment,
            risk_score,
            history.total_deployed
        );

        Ok(DeployerProfile {
            address: creator_address.clone(),
            first_tx_block: history.first_deployment,
            wallet_age_days,
            total_contracts: history.total_deployed,
            previous_rugs: history.rug_count,
            is_known_scammer,
            deployer_risk_score: risk_score,
            contracts: history.contracts,
            creation_timestamp: history.first_deployment,
        })
    }

    /// Get deployer history for an address
    ///
    /// # Arguments
    /// * `deployer_address` - The deployer wallet address
    ///
    /// # Returns
    /// * `Ok(DeployerHistory)` - Deployer history analysis
    /// * `Err(anyhow::Error)` - Error if the query fails
    #[instrument(skip(self), fields(deployer_address = %deployer_address))]
    pub async fn get_deployer_history(
        &self,
        deployer_address: &str,
    ) -> Result<DeployerHistory> {
        if !self.enabled {
            debug!("DeployerClient is disabled - returning empty history for {}", deployer_address);
            return Ok(DeployerHistory::default());
        }

        info!("Getting deployer history for {}", deployer_address);

        // Use the api_key from self, not from environment
        let api_key = self.api_key.clone().unwrap_or_default();

        if api_key.is_empty() {
            debug!("Etherscan API key not configured for deployer history");
            return Ok(DeployerHistory::default());
        }

        // Fetch txlist from Etherscan V2 API
        let url = format!(
            "{}/v2/api?chainid=1&module=account&action=txlist&address={}&startblock=0&endblock=99999999&page=1&offset=10000&sort=asc&apikey={}",
            self.base_url, deployer_address, api_key
        );

        debug!("Fetching deployer history from Etherscan V2: {}", url);
        let response_data = match self.fetch_etherscan_data(&url).await {
            Ok(data) => {
                debug!("Etherscan txlist response received: {} bytes", data.len());
                data
            }
            Err(e) => {
                error!("Failed to fetch deployer history for {}: {}", deployer_address, e);
                return Ok(DeployerHistory::default());
            }
        };

        debug!("Etherscan txlist response length: {} bytes", response_data.len());

        // Parse response using serde_json::Value for flexibility
        let parsed: serde_json::Value = match serde_json::from_str(&response_data) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to parse Etherscan txlist for {}: {}", deployer_address, e);
                return Ok(DeployerHistory::default());
            }
        };

        let status = parsed.get("status").and_then(|v| v.as_str()).unwrap_or("0");
        let result = parsed.get("result").and_then(|v| v.as_array());

        // Log detailed response info for debugging
        let message = parsed.get("message").and_then(|v| v.as_str()).unwrap_or("unknown");
        debug!("Etherscan txlist response - status: {}, message: {}, result count: {:?}",
            status, message, result.as_ref().map(|r| r.len()));

        if status != "1" || result.is_none() {
            debug!("No transaction history found for {} - status: {}, message: {}",
                deployer_address, status, message);
            return Ok(DeployerHistory::default());
        }

        let result = result.unwrap();
        debug!("Found {} transactions for {}", result.len(), deployer_address);

        // Filter for contract creation transactions
        // A contract creation has a non-empty contractAddress
        // Relaxed input validation - just check for non-empty input starting with 0x
        let contracts: Vec<DeployedContract> = result
            .iter()
            .filter(|tx| {
                // Check for contract creation - must have contract address
                let has_contract = tx.get("contractAddress")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|s| !s.is_empty() && s != "0x");

                // Relaxed check for contract creation input - just needs to start with 0x
                // This catches all contract creations including proxy deployments
                let has_creation_input = tx.get("input")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|s| s.starts_with("0x") && s.len() > 10);

                has_contract && has_creation_input
            })
            .map(|tx| DeployedContract {
                address: tx.get("contractAddress").and_then(serde_json::Value::as_str).unwrap_or("").to_string(),
                name: None,
                block_number: tx.get("blockNumber").and_then(serde_json::Value::as_str).and_then(|s| s.parse().ok()).unwrap_or(0),
                timestamp: tx.get("timeStamp").and_then(serde_json::Value::as_str).and_then(|s| s.parse().ok()).unwrap_or(0),
                is_scam: false,
                is_rug: false,
            })
            .collect();

        info!("Found {} contract creations for {}", contracts.len(), deployer_address);

        let total_deployed = contracts.len().try_into().unwrap_or(u32::MAX);
        let rug_count = contracts.iter().filter(|c| c.is_rug).count().try_into().unwrap_or(u32::MAX);

        // Calculate average deployment interval
        let avg_interval = if contracts.len() > 1 {
            let first = contracts.first().map_or(0u64, |c| c.timestamp);
            let last = contracts.last().map_or(0u64, |c| c.timestamp);
            if last > first && contracts.len() > 1 {
                (last.saturating_sub(first)) as f64 / 86400.0 / (contracts.len().saturating_sub(1)) as f64
            } else {
                0.0
            }
        } else {
            0.0
        };

        let first_deployment = result.first().and_then(|tx| tx.get("timeStamp").and_then(|v| v.as_str()).and_then(|s| s.parse().ok())).unwrap_or(0);
        let last_deployment = result.last().and_then(|tx| tx.get("timeStamp").and_then(|v| v.as_str()).and_then(|s| s.parse().ok())).unwrap_or(0);

        Ok(DeployerHistory {
            deployer_address: deployer_address.to_string(),
            contracts,
            rug_count,
            total_deployed,
            avg_deployment_interval_days: avg_interval,
            first_deployment,
            last_deployment,
        })
    }

    /// Get contract creator address
    async fn get_contract_creator(&self, token_address: &str) -> Result<String> {
        // Use the api_key from self, not from environment
        let api_key = self.api_key.clone().unwrap_or_default();

        if api_key.is_empty() {
            debug!("Etherscan API key not configured for deployer analysis");
            return Ok(String::new());
        }

        // Use Etherscan V2 API getcontractcreation endpoint
        let url = format!(
            "{}/v2/api?chainid=1&module=contract&action=getcontractcreation&contractaddresses={}&apikey={}",
            self.base_url, token_address, api_key
        );

        debug!("Fetching contract creator from Etherscan V2: {}", url);

        let response_data = match self.fetch_etherscan_data(&url).await {
            Ok(data) => {
                debug!("Etherscan creator response received: {} bytes", data.len());
                data
            }
            Err(e) => {
                // Check if this is a rate limit error
                let error_msg = e.to_string();
                if error_msg.contains("rate limit") || error_msg.contains("Max calls per sec") {
                    info!("Etherscan rate limit hit for {} - waiting before retry", token_address);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    error!("Failed to fetch contract creator for {}: {}", token_address, e);
                }
                return Ok(String::new());
            }
        };

        // Log raw response for debugging
        debug!("Etherscan creator raw response: {}", response_data);

        // Check for rate limit error in response body before parsing
        // Etherscan sometimes returns rate limit errors as a string in the result field
        if response_data.contains("Max calls per sec rate limit reached") ||
           response_data.contains("rate limit") {
            info!("Etherscan rate limit detected in response for {} - waiting 2s before retry", token_address);
            tokio::time::sleep(Duration::from_secs(2)).await;
            return Ok(String::new());
        }

        // Parse only the contract_creator field, ignoring any extra data
        // First parse as Value to handle both success and error responses
        let parsed_value: serde_json::Value = match serde_json::from_str(&response_data) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to parse creator response for {}: {}", token_address, e);
                return Ok(String::new());
            }
        };

        // Check if result is a string (error message) instead of array
        if let Some(result) = parsed_value.get("result") {
            if let Some(result_str) = result.as_str() {
                // Result is a string, likely an error message
                if result_str.contains("rate limit") {
                    info!("Etherscan rate limit in response for {} - waiting 2s", token_address);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    debug!("Etherscan returned message for {}: {}", token_address, result_str);
                }
                return Ok(String::new());
            }
        }

        // Now parse as CreatorResponse
        #[derive(Debug, Deserialize)]
        struct CreatorResponse {
            status: String,
            message: Option<String>,
            result: Vec<serde_json::Value>,
        }

        let parsed: CreatorResponse = match serde_json::from_value(parsed_value) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to parse creator response for {}: {}", token_address, e);
                return Ok(String::new());
            }
        };

        debug!("Parsed creator response - status: {}, result count: {}",
            parsed.status, parsed.result.len());

        if parsed.status != "1" {
            debug!("Etherscan API returned non-success status for {}: message={:?}",
                token_address, parsed.message);
            return Ok(String::new());
        }

        if parsed.result.is_empty() {
            debug!("No contract creation data found for {}", token_address);
            return Ok(String::new());
        }

        // Extract contract_creator from the first result
        let creator = parsed.result[0]
            .get("contractCreator")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if creator.is_empty() {
            debug!("Contract creator address is empty for {}", token_address);
        } else {
            info!("Contract creator for {}: {}", token_address, creator);
        }

        Ok(creator)
    }

    /// Calculate deployer risk score
    fn calculate_deployer_risk(history: &DeployerHistory) -> u32 {
        let mut risk = 0u32;

        // Fresh deployer wallet (< 7 days)
        if history.first_deployment > 0 {
            let now = UNIX_EPOCH.elapsed().unwrap_or_default().as_secs();
            let wallet_age_days = now.saturating_sub(history.first_deployment) / 86400;
            if wallet_age_days < 7 {
                risk += 15;
            }
        }

        // Known scammer
        if history.rug_count > 0 {
            risk += 40;
        }

        // Serial rug puller
        if history.rug_count >= 3 {
            risk += 30;
        } else if history.rug_count >= 1 {
            risk += 20 * history.rug_count;
        }

        // High deployment frequency (potential scam factory)
        if history.avg_deployment_interval_days > 0.0 && history.avg_deployment_interval_days < 1.0 {
            risk += 10;
        }

        risk.min(100)
    }

    /// Fetch data from Etherscan API
    async fn fetch_etherscan_data(&self, url: &str) -> Result<String> {
        debug!("Fetching Etherscan data: {}", url);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .get(url)
                    .send()
                    .await
                    .context("Failed to send request to Etherscan")?;

                let status = response.status();
                debug!("Etherscan response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    Ok(body)
                } else if status.as_u16() == 401 {
                    Err(anyhow!("Etherscan API key invalid"))
                } else if status.as_u16() == 403 {
                    Err(anyhow!("Etherscan access forbidden"))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Etherscan"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    Err(anyhow!("Etherscan API error: {status} - {error_body}"))
                }
            },
        )
        .await?;

        Ok(response_data)
    }
}

impl Default for DeployerClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default DeployerClient")
    }
}

// Default constants
const DEFAULT_RETRY_COUNT: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> DeployerClient {
        let http_client = Client::builder()
            .http1_only()
            .build()
            .unwrap();

        DeployerClient {
            http_client,
            base_url: mock_server_url.to_string(),
            api_key: Some("test_key".to_string()),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_get_deployer_profile_success() {
        let mut server = Server::new_async().await;

        let mock_creator = r#"{
            "status": "1",
            "message": "OK",
            "result": [{
                "contractAddress": "0x1234567890123456789012345678901234567890",
                "contractCreator": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
            }]
        }"#;

        let mock_txlist = r#"{
            "status": "1",
            "message": "OK",
            "result": [
                {
                    "blockNumber": "10000000",
                    "timeStamp": "1600000000",
                    "hash": "0x123",
                    "from": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                    "to": "0x1234567890123456789012345678901234567890",
                    "value": "0",
                    "contractAddress": "0x1234567890123456789012345678901234567890",
                    "input": "0x60806040",
                    "isError": "0"
                }
            ]
        }"#;

        let mock1 = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_creator)
            .create_async()
            .await;

        let mock2 = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_txlist)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .get_deployer_profile("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        let profile = result.unwrap();
        assert_eq!(profile.address, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
        assert!(profile.total_contracts >= 1);

        mock1.assert_async().await;
        mock2.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_deployer_profile_disabled() {
        let client = DeployerClient::with_params(None, Duration::from_secs(10), 0).unwrap();
        let result = client
            .get_deployer_profile("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().address, "");
    }

    #[test]
    fn test_deployer_profile_default() {
        let profile = DeployerProfile::default();
        assert_eq!(profile.wallet_age_days, 0);
        assert_eq!(profile.deployer_risk_score, 0);
        assert!(!profile.is_known_scammer);
    }

    #[test]
    fn test_deployer_history_default() {
        let history = DeployerHistory::default();
        assert_eq!(history.rug_count, 0);
        assert_eq!(history.total_deployed, 0);
    }
}
