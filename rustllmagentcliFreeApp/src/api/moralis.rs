//! Moralis API client for fetching token holder data
//!
//! Moralis provides real-time token holder data including:
//! - Top holder addresses and balances
//! - Holder percentages relative to total supply
//! - Wallet labels (CEX, DAO, etc.)
//! - Contract vs EOA distinction

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unused_self)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::unnecessary_lazy_evaluations)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, DEFAULT_TIMEOUT_SECS,
    create_http_client, validate_token_address, with_retry,
};

/// Moralis API client
#[derive(Debug, Clone)]
pub struct MoralisClient {
    http_client: Client,
    base_url: String,
    api_key: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// Token holder from Moralis API (Phase 1 Task 1.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoralisHolder {
    /// Holder address
    pub owner_address: String,
    /// Balance as formatted string
    pub balance_formatted: String,
    /// Whether holder is a contract
    pub is_contract: bool,
    /// Wallet label (e.g., "Binance 8", "Coinbase")
    pub owner_address_label: Option<String>,
    /// Entity name if available
    pub entity: Option<String>,
    /// USD value of holdings
    pub usd_value: Option<String>,
    /// Percentage relative to total supply
    pub percentage_relative_to_total_supply: f64,
}

/// Response from Moralis holders API (Phase 1 Task 1.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoralisHoldersResponse {
    /// List of holders
    pub result: Vec<MoralisHolder>,
    /// Total supply
    pub total_supply: Option<String>,
    /// Pagination cursor
    pub cursor: Option<String>,
}

/// Holder analysis result (Phase 1 Task 1.2)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HolderAnalysis {
    /// Sum of top 10 holder percentages
    pub top10_holders_pct: f64,
    /// Deployer wallet percentage (if in top holders)
    pub dev_wallet_pct: Option<f64>,
    /// Labeled holders with metadata
    pub labeled_holders: Vec<LabeledHolder>,
    /// Count of unlabeled wallets holding > 5%
    pub unlabeled_whale_count: u32,
    /// Percentage held by smart contracts
    pub contract_holder_pct: f64,
}

/// Labeled holder with metadata (Phase 1 Task 1.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledHolder {
    /// Holder address
    pub address: String,
    /// Label from Moralis (e.g., "Binance 8")
    pub label: Option<String>,
    /// Percentage of total supply
    pub pct: f64,
    /// Whether holder is a contract
    pub is_contract: bool,
    /// Whether holder is safe (CEX/DAO/burn)
    pub is_safe: bool,
}

impl MoralisClient {
    /// Create a new Moralis client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new Moralis client with custom configuration
    pub fn with_config(config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(config.dexscreener.timeout)?;

        // Try to load .env file first (in case it hasn't been loaded)
        let _ = dotenvy::dotenv();

        // Get API key from environment or config
        let env_key = std::env::var("MORALIS_API_KEY").ok();
        debug!("MORALIS_API_KEY from env: {}", env_key.as_ref().map(|k| format!("{}...", &k[..8.min(k.len())])).unwrap_or_else(|| "NOT SET".to_string()));

        let config_key = config.goplus.api_key.clone();
        debug!("MORALIS_API_KEY from config.goplus.api_key: {}", config_key.as_ref().map(|k| format!("{}...", &k[..8.min(k.len())])).unwrap_or_else(|| "NOT SET".to_string()));

        let api_key = env_key
            .or_else(|| config_key)
            .ok_or_else(|| anyhow!("MORALIS_API_KEY not set"))?;

        info!("Moralis client initialized with API key (first 8 chars): {}", &api_key[..8.min(api_key.len())]);

        Ok(Self {
            http_client,
            base_url: "https://deep-index.moralis.io/api/v2.2".to_string(),
            api_key,
            timeout: config.dexscreener.timeout,
            retry_count: config.dexscreener.retry_count,
            enabled: config.dexscreener.enabled,
        })
    }

    /// Create a new Moralis client with custom parameters
    pub fn with_params(
        api_key: String,
        timeout: Duration,
        retry_count: u32,
        enabled: bool,
    ) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://deep-index.moralis.io/api/v2.2".to_string(),
            api_key,
            timeout,
            retry_count,
            enabled,
        })
    }

    /// Fetch top N token holders sorted by balance descending (Phase 1 Task 1.2)
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to analyze
    /// * `chain` - The blockchain network ("eth", "bsc", "base")
    /// * `limit` - Maximum number of holders to return (max 100)
    ///
    /// # Returns
    /// * `Ok(Vec<MoralisHolder>)` - List of top holders
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address, chain = %chain))]
    pub async fn get_top_holders(
        &self,
        token_address: &str,
        chain: &str,
        limit: usize,
    ) -> Result<Vec<MoralisHolder>> {
        if !self.enabled {
            return Err(anyhow!("Moralis API is disabled"));
        }

        // Validate token address
        validate_token_address(token_address, chain)?;

        // Moralis uses chain shorthand
        let chain_id = match chain.to_lowercase().as_str() {
            "ethereum" => "eth",
            "bsc" => "bsc",
            "base" => "base",
            "polygon" => "polygon",
            _ => "eth",
        };

        let url = format!(
            "{}/erc20/{}/owners?chain={}&limit={}",
            self.base_url,
            token_address,
            chain_id,
            limit.min(100)
        );

        debug!("Fetching token holders from Moralis: {}", url);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .get(&url)
                    .header("accept", "application/json")
                    .header("X-API-Key", &self.api_key)
                    .send()
                    .await
                    .context("Failed to send request to Moralis")?;

                let status = response.status();
                debug!("Moralis response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    debug!("Moralis response body length: {}", body.len());
                    Ok(body)
                } else if status.as_u16() == 401 {
                    Err(anyhow!("Moralis API key invalid"))
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Token not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Moralis"))
                } else {
                    Err(anyhow!("Moralis API error: {}", status))
                }
            },
        )
        .await?;

        // Parse the response
        let parsed: MoralisHoldersResponse =
            serde_json::from_str(&response_data).context("Failed to parse Moralis response")?;

        info!(
            "Successfully fetched {} holders for {}",
            parsed.result.len(),
            token_address
        );

        Ok(parsed.result)
    }

    /// Build holder analysis from Moralis holders (Phase 1 Task 1.2)
    ///
    /// # Arguments
    /// * `holders` - List of Moralis holders
    /// * `deployer_address` - Deployer wallet address
    ///
    /// # Returns
    /// * `HolderAnalysis` - Analyzed holder data
    pub fn build_holder_analysis(
        holders: &[MoralisHolder],
        deployer_address: &str,
    ) -> HolderAnalysis {
        // Known-safe label prefixes (Moralis includes many of these)
        let safe_label_prefixes = [
            "binance",
            "coinbase",
            "kraken",
            "okx",
            "uniswap",
            "curve",
            "compound",
            "aave",
            "makerdao",
            "dydx",
            "burn",
            "dead",
            "zero",
        ];

        let mut top10_sum = 0.0_f64;
        let mut labeled = Vec::new();
        let mut unlabeled_whale_count = 0u32;
        let mut dev_wallet_pct = None;
        let mut contract_holder_pct = 0.0;

        for holder in holders.iter().take(10) {
            let pct = holder.percentage_relative_to_total_supply;
            top10_sum += pct;

            let is_safe = holder
                .owner_address_label
                .as_deref()
                .is_some_and(|label| {
                    safe_label_prefixes.iter().any(|prefix| {
                        label.to_lowercase().contains(prefix)
                    })
                });

            // Flag unlabeled wallets holding > 5%
            if !is_safe && holder.owner_address_label.is_none() && pct > 5.0 {
                unlabeled_whale_count += 1;
            }

            // Check if this is the deployer wallet
            if holder.owner_address.to_lowercase() == deployer_address.to_lowercase() {
                dev_wallet_pct = Some(pct);
            }

            if holder.is_contract {
                contract_holder_pct += pct;
            }

            labeled.push(LabeledHolder {
                address: holder.owner_address.clone(),
                label: holder.owner_address_label.clone(),
                pct,
                is_contract: holder.is_contract,
                is_safe,
            });
        }

        HolderAnalysis {
            top10_holders_pct: top10_sum,
            dev_wallet_pct,
            labeled_holders: labeled,
            unlabeled_whale_count,
            contract_holder_pct,
        }
    }

    /// Fetch holders for multiple tokens
    pub async fn fetch_multiple_holders(
        &self,
        tokens: &[(&str, &str)],
        limit: usize,
    ) -> Vec<Result<Vec<MoralisHolder>>> {
        let mut results = Vec::with_capacity(tokens.len());

        for (address, chain) in tokens {
            match self.get_top_holders(address, chain, limit).await {
                Ok(holders) => results.push(Ok(holders)),
                Err(e) => {
                    warn!("Failed to fetch holders for {}: {}", address, e);
                    results.push(Err(e));
                }
            }
        }

        results
    }
}

impl Default for MoralisClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default MoralisClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> MoralisClient {
        let http_client = Client::builder()
            .http1_only()
            .build()
            .unwrap();

        MoralisClient {
            http_client,
            base_url: mock_server_url.to_string(),
            api_key: "test_key".to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_get_top_holders_success() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "result": [
                {
                    "owner_address": "0x1a9c8182c09f50c8318d769245bea52c32be35bc",
                    "balance_formatted": "264634857.29",
                    "is_contract": true,
                    "owner_address_label": null,
                    "entity": null,
                    "usd_value": "940428028.10",
                    "percentage_relative_to_total_supply": 26.46
                },
                {
                    "owner_address": "0xf977814e90da44bfa03b6295a0616a897441acec",
                    "balance_formatted": "51000000.0",
                    "is_contract": false,
                    "owner_address_label": "Binance 8",
                    "entity": null,
                    "usd_value": "181234567.89",
                    "percentage_relative_to_total_supply": 5.1
                }
            ],
            "total_supply": "1000000000",
            "cursor": null
        }"#;

        let mock = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/api/v2.2/erc20/0x[a-fA-F0-9]{40}/owners\?chain=eth&limit=10".to_string(),
                ),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .get_top_holders("0x1234567890123456789012345678901234567890", "eth", 10)
            .await;

        assert!(result.is_ok());
        let holders = result.unwrap();
        assert_eq!(holders.len(), 2);
        assert!(holders[0].percentage_relative_to_total_supply > 26.4);
        assert!(holders[0].percentage_relative_to_total_supply < 26.5);
        assert_eq!(holders[1].owner_address_label, Some("Binance 8".to_string()));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_top_holders_unauthorized() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/api/v2.2/erc20/0x[a-fA-F0-9]{40}/owners\?chain=eth&limit=10".to_string(),
                ),
            )
            .with_status(401)
            .with_body("Unauthorized")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .get_top_holders("0x1234567890123456789012345678901234567890", "eth", 10)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("API key invalid"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_top_holders_not_found() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/api/v2.2/erc20/0x[a-fA-F0-9]{40}/owners\?chain=eth&limit=10".to_string(),
                ),
            )
            .with_status(404)
            .with_body("Not Found")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .get_top_holders("0x1234567890123456789012345678901234567890", "eth", 10)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Token not found"));

        mock.assert_async().await;
    }

    #[test]
    fn test_build_holder_analysis() {
        let holders = vec![
            MoralisHolder {
                owner_address: "0x1a9c8182c09f50c8318d769245bea52c32be35bc".to_string(),
                balance_formatted: "264634857.29".to_string(),
                is_contract: true,
                owner_address_label: None,
                entity: None,
                usd_value: Some("940428028.10".to_string()),
                percentage_relative_to_total_supply: 26.46,
            },
            MoralisHolder {
                owner_address: "0xf977814e90da44bfa03b6295a0616a897441acec".to_string(),
                balance_formatted: "51000000.0".to_string(),
                is_contract: false,
                owner_address_label: Some("Binance 8".to_string()),
                entity: None,
                usd_value: Some("181234567.89".to_string()),
                percentage_relative_to_total_supply: 5.1,
            },
            MoralisHolder {
                owner_address: "0xdeployer123456789012345678901234567890".to_string(),
                balance_formatted: "10000000.0".to_string(),
                is_contract: false,
                owner_address_label: None,
                entity: None,
                usd_value: Some("35600000.00".to_string()),
                percentage_relative_to_total_supply: 1.0,
            },
        ];

        let analysis = MoralisClient::build_holder_analysis(
            &holders,
            "0xdeployer123456789012345678901234567890",
        );

        // Top 10 sum (all 3 holders in this case)
        assert!((analysis.top10_holders_pct - 32.56).abs() < 0.01);

        // Deployer wallet detected
        assert!(analysis.dev_wallet_pct.is_some());
        assert!((analysis.dev_wallet_pct.unwrap() - 1.0).abs() < 0.01);

        // One unlabeled whale (> 5%)
        assert_eq!(analysis.unlabeled_whale_count, 1);

        // Contract holder percentage
        assert!((analysis.contract_holder_pct - 26.46).abs() < 0.01);

        // Labeled holders
        assert_eq!(analysis.labeled_holders.len(), 3);
        assert!(analysis.labeled_holders[1].is_safe); // Binance
        assert!(!analysis.labeled_holders[0].is_safe); // Unlabeled contract
    }

    #[test]
    fn test_build_holder_analysis_safe_labels() {
        let holders = vec![
            MoralisHolder {
                owner_address: "0xbinance123456789012345678901234567890".to_string(),
                balance_formatted: "100000000.0".to_string(),
                is_contract: false,
                owner_address_label: Some("Binance 8".to_string()),
                entity: None,
                usd_value: Some("356000000.00".to_string()),
                percentage_relative_to_total_supply: 10.0,
            },
            MoralisHolder {
                owner_address: "0xcoinbase12345678901234567890123456789".to_string(),
                balance_formatted: "50000000.0".to_string(),
                is_contract: false,
                owner_address_label: Some("Coinbase".to_string()),
                entity: None,
                usd_value: Some("178000000.00".to_string()),
                percentage_relative_to_total_supply: 5.0,
            },
        ];

        let analysis = MoralisClient::build_holder_analysis(&holders, "0xdeployer");

        // Both should be safe (CEX labels)
        assert!(analysis.labeled_holders[0].is_safe);
        assert!(analysis.labeled_holders[1].is_safe);

        // No unlabeled whales (both are labeled)
        assert_eq!(analysis.unlabeled_whale_count, 0);
    }

    #[test]
    fn test_get_top_holders_disabled() {
        let client = MoralisClient {
            http_client: Client::new(),
            base_url: "https://deep-index.moralis.io/api/v2.2".to_string(),
            api_key: "test_key".to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: false,
        };

        let result = futures::executor::block_on(
            client.get_top_holders("0x1234567890123456789012345678901234567890", "eth", 10),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    #[test]
    fn test_get_top_holders_invalid_address() {
        let client = MoralisClient::default();

        let result = futures::executor::block_on(
            client.get_top_holders("invalid_address", "eth", 10),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must start with 0x"));
    }
}
