//! GoPlus Security API client for contract risk analysis
//!
//! GoPlus provides comprehensive security analysis including:
//! - Contract ownership analysis
//! - Mint function detection
//! - Blacklist/honeypot detection
//! - LP lock status
//! - Proxy contract detection
//!
//! API Documentation: https://docs.gopluslabs.io/
//! Endpoint: POST https://api.gopluslabs.io/api/v1/token
//! Request Body: {"chain": "eth", "contract": "0x..."}
//!
//! # API Limitations (Free Tier)
//! The GoPlus free API has some limitations for well-established, safe tokens:
//! - `owner_address`: May be `null` for renounced ownership contracts or safe tokens
//! - `holder_count`: May be `null` for tokens not tracked by GoPlus
//! - `external_call`: May be `null` for simple ERC20 tokens without external calls
//!
//! These null values are **expected behavior** for safe, established tokens like UNI, AAVE, etc.
//! The API focuses on detecting risks in newer/lesser-known tokens where these fields are more relevant.
//! For established tokens, the absence of these fields should not be interpreted as an error.

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unused_self)]
#![allow(clippy::map_unwrap_or)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, chain_to_goplus_id,
    create_http_client, validate_token_address, with_retry,
};

/// GoPlus Security API client
#[derive(Debug, Clone)]
pub struct GoPlusClient {
    http_client: Client,
    base_url: String,
    api_key: Option<String>,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// Contract risk analysis result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractRisk {
    /// Token address that was analyzed
    pub token_address: String,
    /// Chain identifier
    pub chain: String,
    /// Whether the owner can mint new tokens
    pub owner_can_mint: bool,
    /// Whether the owner can blacklist addresses
    pub owner_can_blacklist: bool,
    /// Whether LP tokens are locked
    pub lp_locked: bool,
    /// Whether there is a hidden owner
    pub hidden_owner: bool,
    /// Whether the contract has a selfdestruct function
    pub selfdestruct: bool,
    /// Whether the contract is a proxy
    pub is_proxy: bool,
    /// Whether the contract can be upgraded
    pub can_be_upgraded: bool,
    /// Whether trading can be paused
    pub trade_cannot_be_paused: bool,
    /// Whether there are anti-whale mechanisms
    pub anti_whale_modifiable: bool,
    /// Whether personal privileges exist
    pub personal_privilege: bool,
    /// Owner address
    /// Note: May be `None` for renounced ownership or safe tokens (GoPlus API limitation)
    pub owner_address: Option<String>,
    /// Creator address
    /// Note: May be `None` for established tokens (GoPlus API limitation)
    pub creator_address: Option<String>,
    /// Deployer balance
    /// Note: May be `None` for established tokens (GoPlus API limitation)
    pub deployer_balance: Option<String>,
    /// Holder count
    /// Note: May be `None` for tokens not tracked by GoPlus (expected for safe tokens like UNI, AAVE)
    pub holder_count: Option<u64>,
    /// External call status as string from API ("0" or "1")
    /// Use external_call_detected() to get boolean value
    /// Note: May be `None` for simple ERC20 tokens without external calls (GoPlus API limitation)
    pub external_call: Option<String>,
    /// Additional risk flags
    pub risk_flags: Vec<String>,
}

impl ContractRisk {
    /// Check if the contract has external calls (convenience method)
    ///
    /// GoPlus returns external_call as "0" (no) or "1" (yes)
    pub fn external_call_detected(&self) -> bool {
        self.external_call
            .as_deref()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }
}

/// External call information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalCallInfo {
    /// Whether the contract makes external calls
    pub has_external_call: bool,
    /// External call addresses
    pub call_addresses: Vec<String>,
}

/// Raw response from GoPlus API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoPlusResponse {
    /// Error code (0 = success)
    pub error: Option<String>,
    /// Response data
    pub result: Option<HashMap<String, ContractData>>,
}

/// Contract data from GoPlus API
///
/// Note: GoPlus API returns all values as strings ("0"/"1" for booleans, numeric strings for counts).
/// Field names use snake_case in the API response.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractData {
    /// Whether the contract is open source
    #[serde(rename = "is_open_source", alias = "isOpenSource")]
    pub is_open_source: Option<String>,
    /// Whether the contract is a proxy
    #[serde(rename = "is_proxy", alias = "isProxy")]
    pub is_proxy: Option<String>,
    /// Whether the contract can be upgraded (mintable)
    #[serde(rename = "is_mintable", alias = "isMintable")]
    pub is_mintable: Option<String>,
    /// Whether owner can modify balance
    #[serde(rename = "owner_modify_balance", alias = "ownerModifyBalance")]
    pub owner_modify_balance: Option<String>,
    /// Whether owner can blacklist
    #[serde(rename = "owner_blacklist", alias = "ownerBlacklist")]
    pub owner_blacklist: Option<String>,
    /// Whether trading can be paused
    #[serde(rename = "trading_cooldown", alias = "tradingCooldown")]
    pub trading_cooldown: Option<String>,
    /// Whether personal privileges exist
    #[serde(rename = "personal_privilege", alias = "personalPrivilege")]
    pub personal_privilege: Option<String>,
    /// External call status ("0" or "1")
    #[serde(rename = "external_call", alias = "externalCall")]
    pub external_call: Option<String>,
    /// Whether owner can pause trading
    #[serde(rename = "can_take_back_ownership", alias = "canTakeBackOwnership")]
    pub can_take_back_ownership: Option<String>,
    /// Whether contract has selfdestruct
    #[serde(rename = "selfdestruct", alias = "selfDestruct")]
    pub selfdestruct: Option<String>,
    /// Whether contract is anti-whale modifiable
    #[serde(rename = "anti_whale", alias = "antiWhale")]
    pub anti_whale: Option<String>,
    /// LP holder info
    #[serde(rename = "lp_holder", alias = "lpHolder")]
    pub lp_holder: Option<String>,
    /// LP locked status
    #[serde(rename = "lp_locked", alias = "lpLocked")]
    pub lp_locked: Option<String>,
    /// Owner address (hex string, or "0x000...000" if renounced)
    #[serde(rename = "owner_address", alias = "ownerAddress")]
    pub owner_address: Option<String>,
    /// Creator address (hex string)
    #[serde(rename = "creator_address", alias = "creatorAddress")]
    pub creator_address: Option<String>,
    /// Deployer balance (numeric string)
    #[serde(rename = "deployer_balance", alias = "deployerBalance")]
    pub deployer_balance: Option<String>,
    /// Holder count (numeric string)
    #[serde(rename = "holder_count", alias = "holderCount")]
    pub holder_count: Option<String>,
    /// Hidden owner flag
    #[serde(rename = "hidden_owner", alias = "hiddenOwner")]
    pub hidden_owner: Option<String>,
    /// Slippage modifiable
    #[serde(rename = "slippage_modifiable", alias = "slippageModifiable")]
    pub slippage_modifiable: Option<String>,
    /// Cannot buy flag
    #[serde(rename = "cannot_buy", alias = "cannotBuy")]
    pub cannot_buy: Option<String>,
    /// Cannot sell flag
    #[serde(rename = "cannot_sell_all", alias = "cannotSellAll")]
    pub cannot_sell_all: Option<String>,
}

impl GoPlusClient {
    /// Create a new GoPlus client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new GoPlus client with custom configuration
    pub fn with_config(config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(10))?;

        Ok(Self {
            http_client,
            base_url: "https://api.gopluslabs.io".to_string(),
            api_key: config.goplus.api_key.clone(),
            timeout: Duration::from_secs(10),
            retry_count: 3,
            enabled: true,
        })
    }

    /// Create a new GoPlus client with custom parameters
    pub fn with_params(
        timeout: Duration,
        retry_count: u32,
        enabled: bool,
        api_key: Option<String>,
    ) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://api.gopluslabs.io".to_string(),
            api_key,
            timeout,
            retry_count,
            enabled,
        })
    }

    /// Create a new GoPlus client for testing with custom base URL
    #[cfg(test)]
    pub fn for_testing(base_url: String, http_client: Client, api_key: Option<String>) -> Self {
        Self {
            http_client,
            base_url,
            api_key,
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
        }
    }

    /// Fetch contract risk analysis
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to analyze
    /// * `chain` - The blockchain network (ethereum, bsc, polygon, etc.)
    ///
    /// # Returns
    /// * `Ok(ContractRisk)` - Contract risk analysis result
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address, chain = %chain))]
    pub async fn fetch_contract_risk(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Result<ContractRisk> {
        if !self.enabled {
            return Err(anyhow!("GoPlus API is disabled"));
        }

        // Validate token address
        validate_token_address(token_address, chain)?;

        let chain_id = chain_to_goplus_id(chain);
        let endpoint = format!("{}/api/v1/token", self.base_url);

        debug!("Fetching contract risk from GoPlus: POST {}", endpoint);

        // Build request body according to GoPlus API spec
        let request_body = serde_json::json!({
            "chain": chain_id,
            "contract": token_address
        });

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let mut request_builder = self
                    .http_client
                    .post(&endpoint)
                    .header("accept", "*/*")
                    .header("content-type", "application/json")
                    .json(&request_body);

                // Add API key if available (as query parameter or header)
                if let Some(ref api_key) = self.api_key {
                    request_builder = request_builder.header("Authorization", format!("Bearer {}", api_key));
                }

                let response = request_builder
                    .send()
                    .await
                    .context("Failed to send request to GoPlus")?;

                let status = response.status();
                debug!("GoPlus response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    debug!("GoPlus response body length: {}", body.len());
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!(
                        "Token not found on chain {}: {}",
                        chain_id,
                        token_address
                    ))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by GoPlus"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    Err(anyhow!("GoPlus API error: {} - {}", status, error_body))
                }
            },
        )
        .await?;

        // Parse the response
        debug!("GoPlus raw response JSON (first 500 chars): {}", &response_data[..response_data.len().min(500)]);
        
        let parsed: GoPlusResponse =
            serde_json::from_str(&response_data).context("Failed to parse GoPlus response")?;

        // Debug: Log the parsed result structure
        if let Some(ref result) = parsed.result {
            debug!("GoPlus response contains {} contract entries", result.len());
            for (addr, data) in result {
                debug!("  Contract {}: owner_address={:?}, holder_count={:?}",
                    addr, data.owner_address, data.holder_count);
            }
        }

        // Check for API error
        if let Some(error) = parsed.error {
            if error != "0" && !error.is_empty() {
                return Err(anyhow!("GoPlus API error: {}", error));
            }
        }

        // Extract contract data for the token
        let contract_data = parsed
            .result
            .as_ref()
            .and_then(|r| r.get(&token_address.to_lowercase()).cloned())
            .or_else(|| {
                parsed
                    .result
                    .as_ref()
                    .and_then(|r| r.values().next().cloned())
            })
            .unwrap_or_default();

        let risk = self.parse_contract_risk(&contract_data, token_address, chain);

        if risk.owner_can_mint || risk.owner_can_blacklist || risk.hidden_owner {
            warn!(
                "HIGH RISK detected for {} on {}: mint={}, blacklist={}, hidden_owner={}",
                token_address,
                chain,
                risk.owner_can_mint,
                risk.owner_can_blacklist,
                risk.hidden_owner
            );
        } else {
            info!(
                "Contract risk analysis for {} on {} completed",
                token_address, chain
            );
        }

        Ok(risk)
    }

    /// Parse contract data into ContractRisk
    fn parse_contract_risk(
        &self,
        data: &ContractData,
        token_address: &str,
        chain: &str,
    ) -> ContractRisk {
        let mut risk_flags = Vec::new();

        // Helper to parse boolean strings
        let parse_bool = |s: &Option<String>| -> bool {
            s.as_ref()
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false)
        };

        // Helper to parse u64 strings
        let parse_u64 =
            |s: &Option<String>| -> Option<u64> { s.as_ref().and_then(|v| v.parse().ok()) };

        // Check various risk flags
        if parse_bool(&data.is_mintable) {
            risk_flags.push("mintable".to_string());
        }
        if parse_bool(&data.owner_blacklist) {
            risk_flags.push("owner_blacklist".to_string());
        }
        if parse_bool(&data.hidden_owner) {
            risk_flags.push("hidden_owner".to_string());
        }
        if parse_bool(&data.selfdestruct) {
            risk_flags.push("selfdestruct".to_string());
        }
        if parse_bool(&data.is_proxy) {
            risk_flags.push("proxy_contract".to_string());
        }
        if parse_bool(&data.personal_privilege) {
            risk_flags.push("personal_privilege".to_string());
        }

        ContractRisk {
            token_address: token_address.to_string(),
            chain: chain.to_string(),
            owner_can_mint: parse_bool(&data.is_mintable),
            owner_can_blacklist: parse_bool(&data.owner_blacklist),
            lp_locked: parse_bool(&data.lp_locked),
            hidden_owner: parse_bool(&data.hidden_owner),
            selfdestruct: parse_bool(&data.selfdestruct),
            is_proxy: parse_bool(&data.is_proxy),
            can_be_upgraded: parse_bool(&data.can_take_back_ownership),
            trade_cannot_be_paused: !parse_bool(&data.trading_cooldown),
            anti_whale_modifiable: parse_bool(&data.anti_whale),
            personal_privilege: parse_bool(&data.personal_privilege),
            owner_address: data.owner_address.clone(),
            creator_address: data.creator_address.clone(),
            deployer_balance: data.deployer_balance.clone(),
            holder_count: parse_u64(&data.holder_count),
            // Keep external_call as string from API ("0" or "1")
            external_call: data.external_call.clone(),
            risk_flags,
        }
    }

    /// Fetch risk analysis for multiple tokens
    ///
    /// # Arguments
    /// * `tokens` - List of (token_address, chain) tuples to analyze
    ///
    /// # Returns
    /// * `Ok(Vec<ContractRisk>)` - List of risk analysis results
    pub async fn fetch_multiple_risks(&self, tokens: &[(&str, &str)]) -> Result<Vec<ContractRisk>> {
        let mut results = Vec::with_capacity(tokens.len());

        for (address, chain) in tokens {
            match self.fetch_contract_risk(address, chain).await {
                Ok(risk) => results.push(risk),
                Err(e) => {
                    warn!("Failed to fetch risk for {}: {}", address, e);
                    // Continue with other tokens
                }
            }
        }

        Ok(results)
    }
}

impl Default for GoPlusClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default GoPlusClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> GoPlusClient {
        let http_client = Client::builder()
            .http1_only() // Use HTTP/1.1 for mockito compatibility
            .build()
            .unwrap();

        GoPlusClient {
            http_client,
            base_url: mock_server_url.to_string(),
            api_key: Some("test_key".to_string()),
            timeout: Duration::from_secs(10),
            retry_count: 0, // No retries in tests
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_fetch_contract_risk_low_risk() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "error": "0",
            "result": {
                "0x1234567890123456789012345678901234567890": {
                    "is_open_source": "1",
                    "is_proxy": "0",
                    "is_mintable": "0",
                    "owner_modify_balance": "0",
                    "owner_blacklist": "0",
                    "trading_cooldown": "0",
                    "personal_privilege": "0",
                    "external_call": "0",
                    "selfdestruct": "0",
                    "anti_whale": "0",
                    "lp_locked": "1",
                    "hidden_owner": "0",
                    "holder_count": "1000"
                }
            }
        }"#;

        let mock = server
            .mock(
                "POST",
                "/api/v1/token",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_contract_risk("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        let risk = result.unwrap();
        assert!(!risk.owner_can_mint);
        assert!(!risk.owner_can_blacklist);
        assert!(risk.lp_locked);
        assert!(!risk.hidden_owner);
        assert!(!risk.selfdestruct);
        assert_eq!(risk.holder_count, Some(1000));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_contract_risk_high_risk() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "error": "0",
            "result": {
                "0x1234567890123456789012345678901234567890": {
                    "is_open_source": "0",
                    "is_proxy": "1",
                    "is_mintable": "1",
                    "owner_modify_balance": "1",
                    "owner_blacklist": "1",
                    "trading_cooldown": "1",
                    "personal_privilege": "1",
                    "external_call": "1",
                    "selfdestruct": "1",
                    "anti_whale": "1",
                    "lp_locked": "0",
                    "hidden_owner": "1",
                    "holder_count": "50"
                }
            }
        }"#;

        let mock = server
            .mock(
                "POST",
                "/api/v1/token",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_contract_risk("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        let risk = result.unwrap();
        assert!(risk.owner_can_mint);
        assert!(risk.owner_can_blacklist);
        assert!(!risk.lp_locked);
        assert!(risk.hidden_owner);
        assert!(risk.selfdestruct);
        assert!(risk.is_proxy);
        assert!(!risk.risk_flags.is_empty());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_contract_risk_not_found() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "POST",
                "/api/v1/token",
            )
            .with_status(404)
            .with_body("Not Found")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_contract_risk("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Token not found"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_contract_risk_rate_limit() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "POST",
                "/api/v1/token",
            )
            .with_status(429)
            .with_body("Too Many Requests")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_contract_risk("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limited"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_contract_risk_server_error() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "POST",
                "/api/v1/token",
            )
            .with_status(500)
            .with_body("Internal Server Error")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_contract_risk("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("API error"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_contract_risk_invalid_json() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "POST",
                "/api/v1/token",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("not valid json")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_contract_risk("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parse"));

        mock.assert_async().await;
    }

    #[test]
    fn test_fetch_contract_risk_disabled() {
        let client = GoPlusClient {
            http_client: Client::new(),
            base_url: "https://api.gopluslabs.io".to_string(),
            api_key: None,
            timeout: Duration::from_secs(10),
            retry_count: 3,
            enabled: false,
        };

        let result = futures::executor::block_on(
            client.fetch_contract_risk("0x1234567890123456789012345678901234567890", "ethereum"),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    #[test]
    fn test_fetch_contract_risk_invalid_address() {
        let client = GoPlusClient::default();

        let result =
            futures::executor::block_on(client.fetch_contract_risk("invalid_address", "ethereum"));

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must start with 0x")
        );
    }

    #[tokio::test]
    async fn test_fetch_contract_risk_bsc_chain() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "error": "0",
            "result": {
                "0x1234567890123456789012345678901234567890": {
                    "is_open_source": "1",
                    "is_mintable": "0",
                    "owner_blacklist": "0",
                    "lp_locked": "1",
                    "hidden_owner": "0",
                    "selfdestruct": "0"
                }
            }
        }"#;

        let mock = server
            .mock(
                "POST",
                "/api/v1/token",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_contract_risk("0x1234567890123456789012345678901234567890", "bsc")
            .await;

        assert!(result.is_ok());
        let risk = result.unwrap();
        assert_eq!(risk.chain, "bsc");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_multiple_risks() {
        let mut server = Server::new_async().await;

        let mock_response1 = r#"{
            "error": "0",
            "result": {
                "0x1111567890123456789012345678901234567890": {
                    "is_mintable": "0",
                    "owner_blacklist": "0",
                    "lp_locked": "1",
                    "hidden_owner": "0",
                    "selfdestruct": "0"
                }
            }
        }"#;

        let mock_response2 = r#"{
            "error": "0",
            "result": {
                "0x2222567890123456789012345678901234567890": {
                    "is_mintable": "1",
                    "owner_blacklist": "1",
                    "lp_locked": "0",
                    "hidden_owner": "1",
                    "selfdestruct": "0"
                }
            }
        }"#;

        let mock1 = server
            .mock(
                "POST",
                "/api/v1/token",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response1)
            .create_async()
            .await;

        let mock2 = server
            .mock(
                "POST",
                "/api/v1/token",
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

        let results = client.fetch_multiple_risks(&tokens).await.unwrap();

        assert_eq!(results.len(), 2);
        assert!(!results[0].owner_can_mint);
        assert!(results[1].owner_can_mint);

        mock1.assert_async().await;
        mock2.assert_async().await;
    }

    #[test]
    fn test_contract_risk_serialization() {
        let risk = ContractRisk {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            owner_can_mint: false,
            owner_can_blacklist: false,
            lp_locked: true,
            hidden_owner: false,
            selfdestruct: false,
            is_proxy: false,
            can_be_upgraded: false,
            trade_cannot_be_paused: true,
            anti_whale_modifiable: false,
            personal_privilege: false,
            owner_address: Some("0xowner".to_string()),
            creator_address: Some("0xcreator".to_string()),
            deployer_balance: Some("0".to_string()),
            holder_count: Some(1000),
            external_call: None,
            risk_flags: vec![],
        };

        let json = serde_json::to_string(&risk).unwrap();
        let deserialized: ContractRisk = serde_json::from_str(&json).unwrap();

        assert_eq!(risk.token_address, deserialized.token_address);
        assert_eq!(risk.lp_locked, deserialized.lp_locked);
        assert_eq!(risk.holder_count, deserialized.holder_count);
    }

    #[test]
    fn test_contract_data_owner_address_deserialization() {
        // BUG-001: Test that owner_address is correctly deserialized
        let json = r#"{
            "is_open_source": "1",
            "owner_address": "0x41653c7d61609d856f29355e404f310ec4142cfb",
            "creator_address": "0x41653c7d61609d856f29355e404f310ec4142cfb",
            "holder_count": "379551"
        }"#;

        let data: ContractData = serde_json::from_str(json).unwrap();
        assert_eq!(data.owner_address, Some("0x41653c7d61609d856f29355e404f310ec4142cfb".to_string()));
        assert_eq!(data.creator_address, Some("0x41653c7d61609d856f29355e404f310ec4142cfb".to_string()));
        assert_eq!(data.holder_count, Some("379551".to_string()));
    }

    #[test]
    fn test_contract_data_owner_address_renounced() {
        // BUG-001: Test owner_renounced detection with zero address
        let json = r#"{
            "owner_address": "0x0000000000000000000000000000000000000000"
        }"#;

        let data: ContractData = serde_json::from_str(json).unwrap();
        assert_eq!(data.owner_address, Some("0x0000000000000000000000000000000000000000".to_string()));
    }

    #[test]
    fn test_contract_data_owner_address_dead_address() {
        // BUG-001: Test owner_renounced detection with dead address
        let json = r#"{
            "owner_address": "0x000000000000000000000000000000000000dead"
        }"#;

        let data: ContractData = serde_json::from_str(json).unwrap();
        assert_eq!(data.owner_address, Some("0x000000000000000000000000000000000000dead".to_string()));
    }

    #[test]
    fn test_contract_data_holder_count_various_formats() {
        // BUG-001: Test holder_count with various numeric string formats
        let json = r#"{
            "holder_count": "1000000"
        }"#;

        let data: ContractData = serde_json::from_str(json).unwrap();
        assert_eq!(data.holder_count, Some("1000000".to_string()));
    }

    #[test]
    fn test_contract_data_external_call_string() {
        // BUG-002: Test that external_call is deserialized as string
        let json = r#"{
            "external_call": "1"
        }"#;

        let data: ContractData = serde_json::from_str(json).unwrap();
        assert_eq!(data.external_call, Some("1".to_string()));
    }

    #[test]
    fn test_contract_data_external_call_zero() {
        // BUG-002: Test external_call with "0" value
        let json = r#"{
            "external_call": "0"
        }"#;

        let data: ContractData = serde_json::from_str(json).unwrap();
        assert_eq!(data.external_call, Some("0".to_string()));
    }

    #[test]
    fn test_contract_risk_external_call_detected() {
        // BUG-002: Test external_call_detected() method
        let risk_with_call = ContractRisk {
            external_call: Some("1".to_string()),
            ..Default::default()
        };
        assert!(risk_with_call.external_call_detected());

        let risk_without_call = ContractRisk {
            external_call: Some("0".to_string()),
            ..Default::default()
        };
        assert!(!risk_without_call.external_call_detected());

        let risk_none = ContractRisk {
            external_call: None,
            ..Default::default()
        };
        assert!(!risk_none.external_call_detected());

        // Test case insensitivity
        let risk_true = ContractRisk {
            external_call: Some("true".to_string()),
            ..Default::default()
        };
        assert!(risk_true.external_call_detected());

        let risk_true_upper = ContractRisk {
            external_call: Some("TRUE".to_string()),
            ..Default::default()
        };
        assert!(risk_true_upper.external_call_detected());
    }

    #[test]
    fn test_goplus_response_with_all_fields() {
        // BUG-001 & BUG-002: Comprehensive test with realistic GoPlus API response
        let json = r#"{
            "error": "0",
            "result": {
                "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": {
                    "is_open_source": "1",
                    "is_proxy": "0",
                    "is_mintable": "0",
                    "owner_modify_balance": "0",
                    "owner_blacklist": "0",
                    "trading_cooldown": "0",
                    "personal_privilege": "0",
                    "external_call": "0",
                    "can_take_back_ownership": "0",
                    "selfdestruct": "0",
                    "anti_whale": "0",
                    "lp_locked": "1",
                    "hidden_owner": "0",
                    "owner_address": "0x41653c7d61609d856f29355e404f310ec4142cfb",
                    "creator_address": "0x41653c7d61609d856f29355e404f310ec4142cfb",
                    "deployer_balance": "0",
                    "holder_count": "379551"
                }
            }
        }"#;

        let response: GoPlusResponse = serde_json::from_str(json).unwrap();
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap(), "0");
        assert!(response.result.is_some());

        let contract = response.result.unwrap();
        let uni_contract = contract.get("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984").unwrap();

        // BUG-001: Verify owner_address and holder_count are present
        assert_eq!(uni_contract.owner_address, Some("0x41653c7d61609d856f29355e404f310ec4142cfb".to_string()));
        assert_eq!(uni_contract.creator_address, Some("0x41653c7d61609d856f29355e404f310ec4142cfb".to_string()));
        assert_eq!(uni_contract.holder_count, Some("379551".to_string()));

        // BUG-002: Verify external_call is string "0"
        assert_eq!(uni_contract.external_call, Some("0".to_string()));
    }

    #[test]
    fn test_contract_data_camelcase_aliases() {
        // Test that camelCase field names also work (alias support)
        let json = r#"{
            "ownerAddress": "0x1234567890123456789012345678901234567890",
            "creatorAddress": "0x0987654321098765432109876543210987654321",
            "holderCount": "500",
            "externalCall": "1"
        }"#;

        let data: ContractData = serde_json::from_str(json).unwrap();
        assert_eq!(data.owner_address, Some("0x1234567890123456789012345678901234567890".to_string()));
        assert_eq!(data.creator_address, Some("0x0987654321098765432109876543210987654321".to_string()));
        assert_eq!(data.holder_count, Some("500".to_string()));
        assert_eq!(data.external_call, Some("1".to_string()));
    }
}
