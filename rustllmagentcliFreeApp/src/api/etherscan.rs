//! Etherscan API client for contract metadata and verification data
//!
//! Etherscan provides blockchain data including:
//! - Contract source code verification
//! - Contract metadata (name, compiler version)
//! - Token holder information
//! - Transaction history

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, create_http_client,
    validate_token_address, with_retry,
};

/// Etherscan API client
#[derive(Debug, Clone)]
pub struct EtherscanClient {
    http_client: Client,
    base_url: String,
    api_key: Option<String>,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// Contract metadata from Etherscan
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractMetadata {
    /// Token/contract address
    pub token_address: String,
    /// Contract name
    pub contract_name: String,
    /// Compiler version used
    pub compiler_version: String,
    /// Whether the contract is verified
    pub is_verified: bool,
    /// Total supply (formatted string)
    pub total_supply: String,
    /// Number of holders
    pub holder_count: u64,
    /// Contract creation date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
    /// Contract creator address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator_address: Option<String>,
    /// Contract ABI (if verified)
    pub abi: Option<String>,
    /// Contract source code (if verified)
    pub source_code: Option<String>,
    /// Optimization enabled
    pub optimization_enabled: bool,
    /// Optimization runs
    pub optimization_runs: Option<u32>,
    /// License type
    pub license_type: Option<String>,
    /// Proxy contract flag
    pub is_proxy: bool,
    /// Implementation address (if proxy)
    pub implementation: Option<String>,
}

/// Raw response from Etherscan API for contract source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherscanSourceResponse {
    /// Status (1 = success, 0 = error)
    pub status: Option<String>,
    /// Message
    pub message: Option<String>,
    /// Result data
    pub result: Vec<SourceCodeResult>,
}

/// Source code result from Etherscan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceCodeResult {
    /// Source code
    #[serde(rename = "SourceCode")]
    pub source_code: Option<String>,
    /// ABI
    #[serde(rename = "ABI")]
    pub abi: Option<String>,
    /// Contract name
    #[serde(rename = "ContractName")]
    pub contract_name: Option<String>,
    /// Compiler version
    #[serde(rename = "CompilerVersion")]
    pub compiler_version: Option<String>,
    /// Optimization enabled
    #[serde(rename = "OptimizationUsed")]
    pub optimization_used: Option<String>,
    /// Optimization runs
    #[serde(rename = "Runs")]
    pub runs: Option<String>,
    /// Constructor arguments
    #[serde(rename = "ConstructorArguments")]
    pub constructor_arguments: Option<String>,
    /// EVM version
    #[serde(rename = "EVMVersion")]
    pub evm_version: Option<String>,
    /// Library information
    #[serde(rename = "Library")]
    pub library: Option<String>,
    /// License type
    #[serde(rename = "LicenseType")]
    pub license_type: Option<String>,
    /// Proxy flag
    #[serde(rename = "Proxy")]
    pub proxy: Option<String>,
    /// Implementation address
    #[serde(rename = "Implementation")]
    pub implementation: Option<String>,
    /// Swarm source
    #[serde(rename = "SwarmSource")]
    pub swarm_source: Option<String>,
}

/// Raw response from Etherscan API for token info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherscanTokenResponse {
    /// Status (1 = success, 0 = error)
    pub status: Option<String>,
    /// Message
    pub message: Option<String>,
    /// Result data
    pub result: TokenInfoResult,
}

/// Token info result from Etherscan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfoResult {
    /// Contract address
    #[serde(rename = "contractAddress")]
    pub contract_address: Option<String>,
    /// Token name
    #[serde(rename = "tokenName")]
    pub token_name: Option<String>,
    /// Token symbol
    #[serde(rename = "symbol")]
    pub symbol: Option<String>,
    /// Token decimal places
    #[serde(rename = "tokenDecimal")]
    pub token_decimal: Option<String>,
    /// Total supply
    #[serde(rename = "totalSupply")]
    pub total_supply: Option<String>,
    /// Number of holders
    #[serde(rename = "holderCount")]
    pub holder_count: Option<String>,
}

/// Raw response from Etherscan API for contract creation (Phase 4.3: Creator Fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherscanCreationResponse {
    /// Status (1 = success, 0 = error)
    pub status: Option<String>,
    /// Message
    pub message: Option<String>,
    /// Result data
    pub result: Vec<CreationResult>,
}

/// Contract creation result from Etherscan
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationResult {
    /// Contract address
    pub contract_address: String,
    /// Contract creator address
    pub contract_creator: String,
    /// Transaction hash
    pub tx_hash: String,
    /// Block number
    pub block_number: Option<String>,
    /// Timestamp (Unix epoch seconds)
    pub timestamp: Option<String>,
}

impl EtherscanClient {
    /// Create a new Etherscan client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new Etherscan client with custom configuration
    pub fn with_config(config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(10))?;

        Ok(Self {
            http_client,
            base_url: "https://api.etherscan.io".to_string(),
            api_key: config.etherscan_api_key.clone(),
            timeout: Duration::from_secs(10),
            retry_count: 3,
            enabled: config.etherscan_api_key.is_some(),
        })
    }

    /// Create a new Etherscan client with custom parameters
    pub fn with_params(
        timeout: Duration,
        retry_count: u32,
        enabled: bool,
        api_key: Option<String>,
    ) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://api.etherscan.io".to_string(),
            api_key,
            timeout,
            retry_count,
            enabled,
        })
    }

    /// Create a new Etherscan client for testing with custom base URL
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

    /// Fetch contract metadata from Etherscan
    ///
    /// # Arguments
    /// * `token_address` - The contract address to query
    ///
    /// # Returns
    /// * `Ok(ContractMetadata)` - Contract metadata
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn fetch_contract_metadata(&self, token_address: &str) -> Result<ContractMetadata> {
        if !self.enabled {
            return Err(anyhow!("Etherscan API is disabled (no API key configured)"));
        }

        // Validate token address
        validate_token_address(token_address, "ethereum")?;

        // Fetch source code info
        let source_result = self.fetch_source_code(token_address).await.ok();

        // Fetch token info
        let token_result = self.fetch_token_info(token_address).await.ok();

        // Fetch contract creation info (works for unverified contracts)
        let creation_result = self.fetch_contract_creation(token_address).await;
        match &creation_result {
            Ok(creation) => {
                info!(
                    "Fetched contract creation: deployer={}, tx={}",
                    creation.deployer_address, creation.deploy_tx_hash
                );
            }
            Err(e) => {
                debug!(
                    "Failed to fetch contract creation for {}: {}",
                    token_address, e
                );
            }
        }
        let creation_result = creation_result.ok();

        // Combine results
        let mut metadata = ContractMetadata {
            token_address: token_address.to_string(),
            ..Default::default()
        };

        // Populate from source code result
        if let Some(ref source) = source_result {
            metadata.contract_name = source.contract_name.clone().unwrap_or_default();
            metadata.compiler_version = source.compiler_version.clone().unwrap_or_default();
            metadata.is_verified = !source.contract_name.as_deref().unwrap_or("").is_empty();
            metadata.abi = source.abi.clone();
            metadata.source_code = source.source_code.clone();
            metadata.optimization_enabled = source
                .optimization_used
                .as_ref()
                .map(|v| v == "1")
                .unwrap_or(false);
            metadata.optimization_runs = source.runs.as_ref().and_then(|v| v.parse().ok());
            metadata.license_type = source.license_type.clone();
            metadata.is_proxy = source.proxy.as_ref().map(|v| v == "1").unwrap_or(false);
            metadata.implementation = source.implementation.clone();
        }

        // Populate from token info result
        if let Some(ref token) = token_result {
            if metadata.contract_name.is_empty() {
                metadata.contract_name = token.token_name.clone().unwrap_or_default();
            }
            metadata.total_supply = token.total_supply.clone().unwrap_or_default();
            metadata.holder_count = token
                .holder_count
                .as_ref()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }

        // Populate from contract creation result (Phase 4.3: Creator Fields)
        if let Some(ref creation) = creation_result {
            metadata.creator_address = Some(creation.deployer_address.clone());
            // Convert timestamp to ISO 8601 date string
            metadata.creation_date = chrono::DateTime::from_timestamp(creation.deploy_timestamp as i64, 0)
                .map(|dt| dt.to_rfc3339());
            info!(
                "Contract {} created by {} at timestamp {} ({:?})",
                token_address,
                creation.deployer_address,
                creation.deploy_timestamp,
                metadata.creation_date
            );
        } else {
            debug!("No creation data available for {} (creation_result was None)", token_address);
        }

        if metadata.is_verified {
            info!(
                "Contract {} verified as '{}' with compiler {}",
                token_address, metadata.contract_name, metadata.compiler_version
            );
        } else {
            debug!("Contract {} is NOT verified on Etherscan", token_address);
        }

        Ok(metadata)
    }

    /// Fetch source code from Etherscan
    async fn fetch_source_code(&self, token_address: &str) -> Result<SourceCodeResult> {
        let api_key = self.api_key
            .as_ref()
            .ok_or_else(|| anyhow!("No Etherscan API key configured. Set ETHERSCAN_API_KEY in .env file"))?;
        
        let endpoint = format!(
            "{}/api?module=contract&action=getsourcecode&address={}&apikey={}",
            self.base_url,
            token_address,
            api_key
        );

        debug!("Fetching source code from Etherscan: {}", endpoint);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .get(&endpoint)
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
                    debug!("Etherscan response body length: {}", body.len());
                    
                    // Check for rate limit error in response body
                    if body.contains("Max calls per sec rate limit reached") || body.contains("rate limit") {
                        info!("Etherscan rate limit detected in response for {} - waiting 2s before retry", token_address);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        return Err(anyhow!("Etherscan rate limit exceeded"));
                    }
                    
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Contract not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    info!("Etherscan rate limited (429) for {} - waiting 2s before retry", token_address);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Err(anyhow!("Rate limited by Etherscan"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    error!("Etherscan API error for {}: status={}, body={}", token_address, status, error_body);
                    Err(anyhow!("Etherscan API error: {} - {}", status, error_body))
                }
            },
        )
        .await?;

        let parsed: EtherscanSourceResponse =
            serde_json::from_str(&response_data).context("Failed to parse Etherscan response")?;

        if parsed.status.as_deref() == Some("0") {
            return Err(anyhow!(
                "Etherscan API error: {}",
                parsed.message.unwrap_or_default()
            ));
        }

        parsed
            .result
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("No source code data returned"))
    }

    /// Fetch token info from Etherscan
    async fn fetch_token_info(&self, token_address: &str) -> Result<TokenInfoResult> {
        let api_key = self.api_key
            .as_ref()
            .ok_or_else(|| anyhow!("No Etherscan API key configured. Set ETHERSCAN_API_KEY in .env file"))?;
        
        let endpoint = format!(
            "{}/api?module=token&action=tokeninfo&contractaddress={}&apikey={}",
            self.base_url,
            token_address,
            api_key
        );

        debug!("Fetching token info from Etherscan: {}", endpoint);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .get(&endpoint)
                    .send()
                    .await
                    .context("Failed to send request to Etherscan")?;

                let status = response.status();
                debug!("Etherscan token info response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    
                    // Check for rate limit error in response body
                    if body.contains("Max calls per sec rate limit reached") || body.contains("rate limit") {
                        info!("Etherscan rate limit detected in token info for {} - waiting 2s before retry", token_address);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        return Err(anyhow!("Etherscan rate limit exceeded"));
                    }
                    
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Token not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    info!("Etherscan rate limited (429) for token info {} - waiting 2s before retry", token_address);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Err(anyhow!("Rate limited by Etherscan"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    error!("Etherscan token info error for {}: status={}, body={}", token_address, status, error_body);
                    Err(anyhow!("Etherscan API error: {} - {}", status, error_body))
                }
            },
        )
        .await?;

        let parsed: EtherscanTokenResponse = serde_json::from_str(&response_data)
            .context("Failed to parse Etherscan token response")?;

        if parsed.status.as_deref() == Some("0") {
            return Err(anyhow!(
                "Etherscan API error: {}",
                parsed.message.unwrap_or_default()
            ));
        }

        Ok(parsed.result)
    }

    /// Fetch contract creation info using getcontractcreation endpoint
    /// This works for BOTH verified and unverified contracts (Phase 4.3: Creator Fields)
    ///
    /// # Arguments
    /// * `token_address` - The contract address to query
    ///
    /// # Returns
    /// * `Ok(ContractCreationInfo)` - Contract creation information
    /// * `Err(anyhow::Error)` - Error if the request fails
    async fn fetch_contract_creation(&self, token_address: &str) -> Result<ContractCreationInfo> {
        let endpoint = format!(
            "{}/v2/api?chainid=1&module=contract&action=getcontractcreation\
             &contractaddresses={}&apikey={}",
            self.base_url,
            token_address,
            self.api_key
                .as_ref()
                .ok_or_else(|| anyhow!("No API key configured"))?
        );

        debug!("Fetching contract creation from Etherscan: {}", endpoint);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .get(&endpoint)
                    .send()
                    .await
                    .context("Failed to send request to Etherscan")?;

                let status = response.status();
                debug!("Etherscan creation response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    debug!("Etherscan creation response body length: {}", body.len());
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Contract not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Etherscan"))
                } else {
                    Err(anyhow!("Etherscan API error: {}", status))
                }
            },
        )
        .await?;

        // Check for rate limit error in response body before parsing
        if response_data.contains("Max calls per sec rate limit reached") ||
           response_data.contains("rate limit") {
            info!("Etherscan rate limit detected in response for {} - waiting 2s", token_address);
            tokio::time::sleep(Duration::from_secs(2)).await;
            return Err(anyhow!("Etherscan rate limit exceeded"));
        }

        // Parse response as Value first to handle both success and error responses
        let parsed_value: serde_json::Value =
            serde_json::from_str(&response_data).context("Failed to parse Etherscan creation response")?;

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
                return Err(anyhow!("Etherscan API error: {}", result_str));
            }
        }

        // Now parse as EtherscanCreationResponse
        let parsed: EtherscanCreationResponse = serde_json::from_value(parsed_value)
            .context("Failed to parse Etherscan creation response")?;

        if parsed.status.as_deref() == Some("0") {
            return Err(anyhow!(
                "Etherscan API error: {}",
                parsed.message.unwrap_or_default()
            ));
        }

        let creation = parsed
            .result
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("No creation data returned"))?;

        // Parse timestamp
        let timestamp = creation.timestamp
            .and_then(|ts| ts.parse::<u64>().ok())
            .unwrap_or(0);

        // Convert to ContractCreationInfo (existing struct)
        Ok(ContractCreationInfo {
            deployer_address: creation.contract_creator,
            deploy_tx_hash: creation.tx_hash,
            deploy_block: creation.block_number.and_then(|b| b.parse().ok()).unwrap_or(0),
            deploy_timestamp: timestamp,
        })
    }

    /// Fetch contract metadata for multiple tokens
    ///
    /// # Arguments
    /// * `token_addresses` - List of contract addresses to query
    ///
    /// # Returns
    /// * `Ok(Vec<ContractMetadata>)` - List of contract metadata
    pub async fn fetch_multiple_metadata(
        &self,
        token_addresses: &[&str],
    ) -> Result<Vec<ContractMetadata>> {
        let mut results = Vec::with_capacity(token_addresses.len());

        for address in token_addresses {
            match self.fetch_contract_metadata(address).await {
                Ok(metadata) => results.push(metadata),
                Err(e) => {
                    debug!("Failed to fetch metadata for {}: {}", address, e);
                    // Continue with other tokens
                }
            }
        }

        Ok(results)
    }

    /// Check if a contract is verified
    pub async fn is_verified(&self, token_address: &str) -> Result<bool> {
        match self.fetch_contract_metadata(token_address).await {
            Ok(metadata) => Ok(metadata.is_verified),
            Err(_) => Ok(false),
        }
    }

    /// Get contract creation information including deployer address (Phase 1 Task 1.3)
    pub async fn get_contract_creation(
        &self,
        token_address: &str,
        chain_id: u64,
    ) -> Result<ContractCreationInfo> {
        #[derive(Deserialize)]
        struct Response {
            status: String,
            result: Vec<CreationResult>,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct CreationResult {
            contract_creator: String,
            tx_hash: String,
            block_number: String,
            timestamp: Option<String>,
        }

        if !self.enabled {
            return Err(anyhow!("Etherscan API is disabled"));
        }

        let url = format!(
            "{}/v2/api?chainid={}&module=contract&action=getcontractcreation\
             &contractaddresses={}&apikey={}",
            self.base_url, chain_id, token_address,
            self.api_key.as_deref().unwrap_or("")
        );

        debug!("Fetching contract creation from Etherscan: {}", url);

        let resp: Response = self.http_client.get(&url)
            .timeout(Duration::from_secs(15))
            .send().await?
            .json().await?;

        if resp.status != "1" || resp.result.is_empty() {
            return Err(anyhow!("Contract creation not found"));
        }

        let r = &resp.result[0];
        let timestamp = r.timestamp
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        Ok(ContractCreationInfo {
            deployer_address: r.contract_creator.clone(),
            deploy_tx_hash: r.tx_hash.clone(),
            deploy_block: r.block_number.parse().unwrap_or(0),
            deploy_timestamp: timestamp,
        })
    }

    /// Get wallet's first transaction timestamp (Phase 1 Task 1.3)
    pub async fn get_wallet_first_tx_timestamp(
        &self,
        wallet_address: &str,
        chain_id: u64,
    ) -> Result<Option<u64>> {
        #[derive(Deserialize)]
        struct Response {
            status: String,
            result: serde_json::Value,
        }

        if !self.enabled {
            return Ok(None);
        }

        let url = format!(
            "{}/v2/api?chainid={}&module=account&action=txlist\
             &address={}&startblock=0&endblock=99999999\
             &page=1&offset=1&sort=asc&apikey={}",
            self.base_url, chain_id, wallet_address,
            self.api_key.as_deref().unwrap_or("")
        );

        debug!("Fetching wallet first tx from Etherscan: {}", url);

        let resp: Response = self.http_client.get(&url)
            .timeout(Duration::from_secs(15))
            .send().await?
            .json().await?;

        if resp.status != "1" {
            return Ok(None); // No transactions found = brand new wallet
        }

        let timestamp = resp.result
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|tx| tx.get("timeStamp"))
            .and_then(|ts| ts.as_str())
            .and_then(|ts| ts.parse::<u64>().ok());

        Ok(timestamp)
    }

    /// Get full deployer profile with wallet age (Phase 1 Task 1.3)
    pub async fn get_deployer_profile(
        &self,
        token_address: &str,
        chain_id: u64,
    ) -> Result<DeployerProfile> {
        let creation = self.get_contract_creation(token_address, chain_id).await?;

        let first_tx_ts = self
            .get_wallet_first_tx_timestamp(&creation.deployer_address, chain_id)
            .await?
            .unwrap_or(creation.deploy_timestamp); // fallback: no older txns

        // Wallet age = days between first_tx and CURRENT time (not deployment time)
        // This represents how old the deployer wallet actually is
        let now = std::time::UNIX_EPOCH.elapsed()
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let age_secs = now.saturating_sub(first_tx_ts);
        #[allow(clippy::cast_possible_truncation)]
        let wallet_age_days = (age_secs / 86400) as u32;

        debug!("Wallet age calculation for {}: first_tx={}, now={}, age_days={}",
            creation.deployer_address, first_tx_ts, now, wallet_age_days);

        Ok(DeployerProfile {
            address: creation.deployer_address,
            first_tx_timestamp: first_tx_ts,
            wallet_age_days,
            deploy_timestamp: creation.deploy_timestamp,
        })
    }

    /// Get contract source code verification data (Phase 1 Task 1.4)
    pub async fn get_source_code(
        &self,
        token_address: &str,
        chain_id: u64,
    ) -> Result<SourceCodeResult> {
        if !self.enabled {
            return Err(anyhow!("Etherscan API is disabled"));
        }

        let url = format!(
            "{}/v2/api?chainid={}&module=contract&action=getsourcecode\
             &address={}&apikey={}",
            self.base_url, chain_id, token_address,
            self.api_key.as_deref().unwrap_or("")
        );

        debug!("Fetching source code from Etherscan: {}", url);

        let resp: EtherscanSourceResponse = self.http_client.get(&url)
            .timeout(Duration::from_secs(20))
            .send().await?
            .json().await?;

        if resp.status.as_deref() != Some("1") || resp.result.is_empty() {
            return Err(anyhow!("Source code not found"));
        }

        let r = &resp.result[0];
        let source = r.source_code.clone().unwrap_or_default();
        let is_verified = !source.is_empty();

        Ok(SourceCodeResult {
            source_code: if is_verified { r.source_code.clone() } else { None },
            abi: r.abi.clone(),
            contract_name: r.contract_name.clone(),
            compiler_version: r.compiler_version.clone(),
            optimization_used: r.optimization_used.clone(),
            runs: r.runs.clone(),
            constructor_arguments: r.constructor_arguments.clone(),
            evm_version: r.evm_version.clone(),
            library: r.library.clone(),
            license_type: r.license_type.clone(),
            proxy: r.proxy.clone(),
            implementation: r.implementation.clone(),
            swarm_source: r.swarm_source.clone(),
        })
    }

    /// Get token total supply from Etherscan (Phase 1 Task 1.5)
    pub async fn get_token_supply(
        &self,
        token_address: &str,
        chain_id: u64,
        decimals: u8,
    ) -> Result<f64> {
        if !self.enabled {
            return Err(anyhow!("Etherscan API is disabled"));
        }

        let url = format!(
            "{}/v2/api?chainid={}&module=stats&action=tokensupply\
             &contractaddress={}&apikey={}",
            self.base_url, chain_id, token_address,
            self.api_key.as_deref().unwrap_or("")
        );

        debug!("Fetching token supply from Etherscan: {}", url);

        let resp: serde_json::Value = self.http_client.get(&url)
            .timeout(Duration::from_secs(10))
            .send().await?
            .json().await?;

        if resp["status"].as_str() != Some("1") {
            return Err(anyhow!(
                "Etherscan error: {}",
                resp["message"].as_str().unwrap_or("Unknown error")
            ));
        }

        let raw_str = resp["result"].as_str().unwrap_or("0");

        // Parse as u128 then convert to float with decimals
        let raw: u128 = raw_str.parse().unwrap_or(0);
        #[allow(clippy::cast_precision_loss)]
        let divisor = 10_u128.pow(u32::from(decimals)) as f64;
        #[allow(clippy::cast_precision_loss)]
        let supply = raw as f64 / divisor;

        Ok(supply)
    }

    /// Get token total supply as raw string (without decimal conversion)
    /// This is useful for tokens with unknown decimals
    ///
    /// # Arguments
    /// * `token_address` - Token contract address
    /// * `chain_id` - Chain ID (1 for Ethereum)
    ///
    /// # Returns
    /// * `Ok(String)` - Total supply as raw string
    /// * `Err(anyhow::Error)` - Error if request fails
    pub async fn get_token_supply_raw(
        &self,
        token_address: &str,
        chain_id: u64,
    ) -> Result<String> {
        if !self.enabled {
            return Err(anyhow!("Etherscan API is disabled"));
        }

        let url = format!(
            "{}/v2/api?chainid={}&module=stats&action=tokensupply\
             &contractaddress={}&apikey={}",
            self.base_url, chain_id, token_address,
            self.api_key.as_deref().unwrap_or("")
        );

        debug!("Fetching raw token supply from Etherscan: {}", url);

        let resp: serde_json::Value = self.http_client.get(&url)
            .timeout(Duration::from_secs(10))
            .send().await?
            .json().await?;

        if resp["status"].as_str() != Some("1") {
            return Err(anyhow!(
                "Etherscan error: {}",
                resp["message"].as_str().unwrap_or("Unknown error")
            ));
        }

        Ok(resp["result"].as_str().unwrap_or("0").to_string())
    }

    /// Check address labels for scammer tags (Phase 4.1: Forta Replacement)
    ///
    /// This method checks Etherscan's internal address labels and contract names
    /// for known scammer tags like "Scam", "Phishing", "Fake", "Rug", etc.
    ///
    /// # Arguments
    /// * `address` - The address to check
    ///
    /// # Returns
    /// * `Ok(AddressLabels)` - Address labels result
    /// * `Err(anyhow::Error)` - Error if the check fails
    #[instrument(skip(self), fields(address = %address))]
    pub async fn check_address_labels(&self, address: &str) -> Result<AddressLabels> {
        if !self.enabled {
            debug!("Etherscan is disabled, returning default labels");
            return Ok(AddressLabels::default());
        }

        info!("Checking Etherscan address labels for {}", address);

        let mut labels = AddressLabels {
            address: address.to_string(),
            ..Default::default()
        };

        // Try to get contract source code to check ContractName for scam tags
        match self.fetch_source_code(address).await {
            Ok(source_result) => {
                let contract_name_opt = source_result.contract_name.clone();
                if let Some(contract_name) = &contract_name_opt {
                    let name_lower = contract_name.to_lowercase();

                    // Check for scam-related keywords in contract name
                    if name_lower.contains("scam") {
                        labels.scam_tags.push("ContractName:Scam".to_string());
                        labels.is_known_scammer = true;
                    }
                    if name_lower.contains("phishing") {
                        labels.scam_tags.push("ContractName:Phishing".to_string());
                        labels.is_known_scammer = true;
                    }
                    if name_lower.contains("fake") {
                        labels.scam_tags.push("ContractName:Fake".to_string());
                        labels.is_known_scammer = true;
                    }
                    if name_lower.contains("rug") {
                        labels.scam_tags.push("ContractName:Rug".to_string());
                        labels.rugpull_count += 1;
                    }

                    // Add contract name as a label if it contains suspicious patterns
                    if !labels.scam_tags.is_empty() {
                        labels.all_labels.push(format!("ContractName: {}", contract_name));
                    }
                }

                // Check if contract is verified (unverified contracts are higher risk)
                labels.is_verified = contract_name_opt.is_some()
                    && !contract_name_opt
                        .as_ref()
                        .is_some_and(String::is_empty);
            }
            Err(e) => {
                debug!("Failed to fetch source code for {}: {}", address, e);
                // Continue with other checks
            }
        }

        // Check token info for additional labels
        match self.fetch_token_info(address).await {
            Ok(token_result) => {
                if let Some(token_name) = token_result.token_name {
                    let name_lower = token_name.to_lowercase();

                    if name_lower.contains("scam") || name_lower.contains("fake") {
                        labels.scam_tags.push("TokenName:Suspicious".to_string());
                        labels.is_known_scammer = true;
                    }

                    labels.all_labels.push(format!("TokenName: {}", token_name));
                }

                if let Some(symbol) = token_result.symbol {
                    labels.all_labels.push(format!("Symbol: {}", symbol));
                }
            }
            Err(e) => {
                debug!("Failed to fetch token info for {}: {}", address, e);
            }
        }

        // Calculate risk score based on findings
        labels.risk_score = Self::calculate_label_risk_score(&labels);

        info!(
            "Etherscan labels check completed for {}: is_scammer={}, risk_score={}, tags={:?}",
            address, labels.is_known_scammer, labels.risk_score, labels.scam_tags
        );

        Ok(labels)
    }

    /// Calculate risk score from address labels
    fn calculate_label_risk_score(labels: &AddressLabels) -> u32 {
        let mut risk = 0u32;

        // Known scammer = maximum risk
        if labels.is_known_scammer {
            return 100;
        }

        // Unverified contract = moderate risk
        if !labels.is_verified {
            risk += 30;
        }

        // Each scam tag adds risk
        #[allow(clippy::cast_possible_truncation)]
        let scam_tags_risk: u32 = (labels.scam_tags.len() as u32) * 20;
        risk += scam_tags_risk;

        // Rug pull tags add significant risk
        risk += labels.rugpull_count * 25;

        risk.min(100)
    }
}

/// Address labels result from Etherscan (Phase 4.1: Forta Replacement)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AddressLabels {
    /// Address checked
    pub address: String,
    /// Whether address is flagged as known scammer
    #[serde(default)]
    pub is_known_scammer: bool,
    /// Number of rugpull-related tags
    #[serde(default)]
    pub rugpull_count: u32,
    /// Risk score (0-100)
    #[serde(default)]
    pub risk_score: u32,
    /// Whether contract is verified
    #[serde(default)]
    pub is_verified: bool,
    /// Scam-related tags found
    #[serde(default)]
    pub scam_tags: Vec<String>,
    /// All labels found
    #[serde(default)]
    pub all_labels: Vec<String>,
}

/// Contract creation information (Phase 1 Task 1.3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCreationInfo {
    /// Deployer wallet address
    pub deployer_address: String,
    /// Deployment transaction hash
    pub deploy_tx_hash: String,
    /// Block number where contract was deployed
    pub deploy_block: u64,
    /// Unix timestamp of deployment
    pub deploy_timestamp: u64,
}

/// Deployer profile with wallet age (Phase 1 Task 1.3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployerProfile {
    /// Deployer wallet address
    pub address: String,
    /// First transaction timestamp (Unix seconds)
    pub first_tx_timestamp: u64,
    /// Wallet age in days (from first tx to contract deploy)
    pub wallet_age_days: u32,
    /// Contract deployment timestamp (Unix seconds)
    pub deploy_timestamp: u64,
}

impl EtherscanClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default EtherscanClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> EtherscanClient {
        let http_client = Client::builder()
            .http1_only() // Use HTTP/1.1 for mockito compatibility
            .build()
            .unwrap();

        EtherscanClient {
            http_client,
            base_url: mock_server_url.to_string(),
            api_key: Some("test_key".to_string()),
            timeout: Duration::from_secs(10),
            retry_count: 0, // No retries in tests
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_fetch_contract_metadata_verified() {
        let mut server = Server::new_async().await;

        let source_response = r#"{
            "status": "1",
            "message": "OK",
            "result": [{
                "SourceCode": "contract TestToken {}",
                "ABI": "[{\"inputs\":[],\"name\":\"name\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
                "ContractName": "TestToken",
                "CompilerVersion": "v0.8.19+commit.7dd6d404",
                "OptimizationUsed": "1",
                "Runs": "200",
                "LicenseType": "MIT",
                "Proxy": "0",
                "Implementation": "",
                "SwarmSource": "ipfs://abc123"
            }]
        }"#;

        let token_response = r#"{
            "status": "1",
            "message": "OK",
            "result": {
                "contractAddress": "0x1234567890123456789012345678901234567890",
                "tokenName": "Test Token",
                "symbol": "TEST",
                "tokenDecimal": "18",
                "totalSupply": "1000000000000000000000000",
                "holderCount": "5000"
            }
        }"#;

        let mock_source = server
            .mock(
                "GET",
                mockito::Matcher::AllOf(vec![
                    mockito::Matcher::UrlEncoded("module".into(), "contract".into()),
                    mockito::Matcher::UrlEncoded("action".into(), "getsourcecode".into()),
                ]),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(source_response)
            .create_async()
            .await;

        let mock_token = server
            .mock(
                "GET",
                mockito::Matcher::AllOf(vec![
                    mockito::Matcher::UrlEncoded("module".into(), "token".into()),
                    mockito::Matcher::UrlEncoded("action".into(), "tokeninfo".into()),
                ]),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(token_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_contract_metadata("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert!(metadata.is_verified);
        assert_eq!(metadata.contract_name, "TestToken");
        assert!(metadata.compiler_version.contains("v0.8.19"));
        assert!(metadata.optimization_enabled);
        assert_eq!(metadata.optimization_runs, Some(200));
        assert_eq!(metadata.holder_count, 5000);
        assert_eq!(metadata.total_supply, "1000000000000000000000000");

        mock_source.assert_async().await;
        mock_token.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_contract_metadata_unverified() {
        let mut server = Server::new_async().await;

        let source_response = r#"{
            "status": "0",
            "message": "Contract source code not verified",
            "result": []
        }"#;

        let mock = server
            .mock(
                "GET",
                mockito::Matcher::AllOf(vec![
                    mockito::Matcher::UrlEncoded("module".into(), "contract".into()),
                    mockito::Matcher::UrlEncoded("action".into(), "getsourcecode".into()),
                ]),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(source_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_contract_metadata("0x1234567890123456789012345678901234567890")
            .await;

        // Should still succeed but with unverified status
        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert!(!metadata.is_verified);
        assert!(metadata.contract_name.is_empty());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_contract_metadata_rate_limit() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(429)
            .with_body("Too Many Requests")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_contract_metadata("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limited"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_contract_metadata_server_error() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body("Internal Server Error")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_contract_metadata("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("API error"));

        mock.assert_async().await;
    }

    #[test]
    fn test_fetch_contract_metadata_disabled() {
        let client = EtherscanClient {
            http_client: Client::new(),
            base_url: "https://api.etherscan.io".to_string(),
            api_key: None,
            timeout: Duration::from_secs(10),
            retry_count: 3,
            enabled: false,
        };

        let result = futures::executor::block_on(
            client.fetch_contract_metadata("0x1234567890123456789012345678901234567890"),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    #[test]
    fn test_fetch_contract_metadata_invalid_address() {
        let client = EtherscanClient {
            http_client: Client::new(),
            base_url: "https://api.etherscan.io".to_string(),
            api_key: Some("test_key".to_string()),
            timeout: Duration::from_secs(10),
            retry_count: 3,
            enabled: true,
        };

        let result = futures::executor::block_on(client.fetch_contract_metadata("invalid_address"));

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must start with 0x")
        );
    }

    #[tokio::test]
    async fn test_is_verified_true() {
        let mut server = Server::new_async().await;

        let source_response = r#"{
            "status": "1",
            "message": "OK",
            "result": [{
                "ContractName": "TestToken",
                "CompilerVersion": "v0.8.19"
            }]
        }"#;

        let token_response = r#"{
            "status": "1",
            "message": "OK",
            "result": {
                "tokenName": "Test",
                "symbol": "TST",
                "totalSupply": "1000000",
                "holderCount": "100"
            }
        }"#;

        let _mock_source = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(source_response)
            .create_async()
            .await;

        let _mock_token = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(token_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .is_verified("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_is_verified_false() {
        let mut server = Server::new_async().await;

        let source_response = r#"{
            "status": "0",
            "message": "Not verified",
            "result": []
        }"#;

        let _mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(source_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .is_verified("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_contract_metadata_serialization() {
        let metadata = ContractMetadata {
            token_address: "0x1234".to_string(),
            contract_name: "TestToken".to_string(),
            compiler_version: "v0.8.19".to_string(),
            is_verified: true,
            total_supply: "1000000000".to_string(),
            holder_count: 5000,
            creation_date: Some("2023-01-01".to_string()),
            creator_address: Some("0xcreator".to_string()),
            abi: Some("[]".to_string()),
            source_code: Some("contract Test {}".to_string()),
            optimization_enabled: true,
            optimization_runs: Some(200),
            license_type: Some("MIT".to_string()),
            is_proxy: false,
            implementation: None,
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: ContractMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(metadata.contract_name, deserialized.contract_name);
        assert_eq!(metadata.is_verified, deserialized.is_verified);
        assert_eq!(metadata.holder_count, deserialized.holder_count);
    }

    #[tokio::test]
    async fn test_get_token_supply_success() {
        let mut server = Server::new_async().await;

        let supply_response = r#"{
            "status": "1",
            "message": "OK",
            "result": "1000000000000000000000000"
        }"#;

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(supply_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        // Test with 18 decimals (standard ERC20)
        let result = client
            .get_token_supply("0x1234567890123456789012345678901234567890", 1, 18)
            .await;

        assert!(result.is_ok());
        let supply = result.unwrap();
        assert!((supply - 1_000_000.0).abs() < 0.01); // 1 million tokens

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_token_supply_with_decimals() {
        let mut server = Server::new_async().await;

        // 1000 tokens with 6 decimals (like USDC)
        let supply_response = r#"{
            "status": "1",
            "message": "OK",
            "result": "1000000000"
        }"#;

        let _mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(supply_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        // Test with 6 decimals
        let result = client
            .get_token_supply("0x1234567890123456789012345678901234567890", 1, 6)
            .await;

        assert!(result.is_ok());
        let supply = result.unwrap();
        assert!((supply - 1_000.0).abs() < 0.01); // 1000 tokens
    }

    #[tokio::test]
    async fn test_get_token_supply_error() {
        let mut server = Server::new_async().await;

        let error_response = r#"{
            "status": "0",
            "message": "Rate limit exceeded"
        }"#;

        let _mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(error_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .get_token_supply("0x1234567890123456789012345678901234567890", 1, 18)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limit"));
    }

    #[tokio::test]
    async fn test_get_token_supply_disabled() {
        let client = EtherscanClient {
            http_client: Client::new(),
            base_url: "https://api.etherscan.io".to_string(),
            api_key: None,
            timeout: Duration::from_secs(10),
            retry_count: 3,
            enabled: false,
        };

        let result = client
            .get_token_supply("0x1234567890123456789012345678901234567890", 1, 18)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }
}
