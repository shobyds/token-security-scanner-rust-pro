//! Transfer Events RPC Client for Holder Count Analysis
//!
//! This module calculates token holder count by analyzing ERC20 Transfer events
//! via direct RPC calls using eth_getLogs.
//!
//! # Method
//! 1. Query eth_getLogs for Transfer events
//! 2. Filter by Transfer event topic hash
//! 3. Extract unique 'to' addresses (recipients)
//! 4. Count = holder count
//!
//! # Transfer Event Signature
//! ```
//! Transfer(address indexed from, address indexed to, uint256 value)
//! Topic Hash: 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
//! ```
//!
//! # Features
//! - Direct RPC access (no external API required)
//! - Efficient holder counting via event logs
//! - Configurable block range
//! - Support for multiple RPC endpoints

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::similar_names)]

use anyhow::{Context, Result, anyhow};
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::{Address, Filter, H256, U256, BlockNumber};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{validate_token_address, DEFAULT_TIMEOUT_SECS};

/// Transfer event topic hash (ERC20 standard)
pub const TRANSFER_EVENT_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// Default blocks to scan back for holder analysis
pub const DEFAULT_BLOCKS_TO_SCAN: u64 = 100_000;

/// Maximum blocks per request (to avoid RPC limits)
pub const MAX_BLOCKS_PER_REQUEST: u64 = 10_000;

/// Transfer event client for analyzing ERC20 Transfer events
#[derive(Debug, Clone)]
pub struct TransferEventClient {
    provider: Arc<Provider<Http>>,
    rpc_url: String,
    timeout: Duration,
}

/// Individual transfer event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferEvent {
    /// Transaction hash
    pub tx_hash: String,
    /// Block number
    pub block_number: u64,
    /// From address (sender)
    pub from: String,
    /// To address (recipient)
    pub to: String,
    /// Transfer amount (raw)
    pub value: String,
    /// Token address
    pub token_address: String,
    /// Log index
    pub log_index: usize,
}

/// Holder analysis result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HolderAnalysis {
    /// Token address analyzed
    pub token_address: String,
    /// Total unique holders count
    pub holder_count: u64,
    /// List of unique holder addresses
    pub unique_holders: Vec<String>,
    /// Block range analyzed (from)
    pub from_block: u64,
    /// Block range analyzed (to)
    pub to_block: u64,
    /// Total transfer events processed
    pub total_transfers: u64,
    /// Analysis timestamp
    pub analysis_timestamp: u64,
}

/// Transfer events query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferEventsResult {
    /// Token address
    pub token_address: String,
    /// List of transfer events
    pub events: Vec<TransferEvent>,
    /// From block
    pub from_block: u64,
    /// To block
    pub to_block: u64,
    /// Total events found
    pub total_count: usize,
}

impl TransferEventClient {
    /// Create a new TransferEventClient with default RPC URL
    pub fn new() -> Result<Self> {
        Self::with_rpc_url("https://eth-mainnet.g.alchemy.com/v2/demo")
    }

    /// Create a new TransferEventClient with custom RPC URL
    pub fn with_rpc_url(rpc_url: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .context("Failed to create RPC provider")?;

        Ok(Self {
            provider: Arc::new(provider),
            rpc_url: rpc_url.to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        })
    }

    /// Create a new TransferEventClient with custom parameters
    pub fn with_params(rpc_url: &str, timeout: Duration) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .context("Failed to create RPC provider")?;

        Ok(Self {
            provider: Arc::new(provider),
            rpc_url: rpc_url.to_string(),
            timeout,
        })
    }

    /// Create a new TransferEventClient for testing
    #[cfg(test)]
    pub fn for_testing(provider: Arc<Provider<Http>>, rpc_url: String) -> Self {
        Self {
            provider,
            rpc_url,
            timeout: Duration::from_secs(10),
        }
    }

    /// Get holder count for a token by analyzing Transfer events
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of unique holders
    /// * `Err(anyhow::Error)` - Error if the query fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_holder_count(&self, token_address: &str) -> Result<u64> {
        validate_token_address(token_address, "ethereum")?;

        info!("Getting holder count for {} via Transfer events", token_address);

        let analysis = self.analyze_holders(token_address, None, None).await?;
        Ok(analysis.holder_count)
    }

    /// Get transfer events for a token in a block range
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    /// * `from_block` - Starting block number
    /// * `to_block` - Ending block number (None for latest)
    ///
    /// # Returns
    /// * `Ok(TransferEventsResult)` - List of transfer events
    /// * `Err(anyhow::Error)` - Error if the query fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_transfer_events(
        &self,
        token_address: &str,
        from_block: u64,
        to_block: Option<u64>,
    ) -> Result<TransferEventsResult> {
        validate_token_address(token_address, "ethereum")?;

        let token_addr = Address::from_str(token_address)
            .context("Invalid token address format")?;

        // Get latest block if not specified
        #[allow(clippy::single_match_else)]
        let end_block = match to_block {
            Some(b) => b,
            None => {
                let latest = self.provider.get_block_number().await
                    .context("Failed to get latest block number")?;
                latest.as_u64()
            }
        };

        // Calculate actual from_block
        let start_block = if from_block == 0 {
            // Default to scanning back DEFAULT_BLOCKS_TO_SCAN blocks
            end_block.saturating_sub(DEFAULT_BLOCKS_TO_SCAN)
        } else {
            from_block
        };

        debug!(
            "Fetching Transfer events for {} from block {} to {}",
            token_address, start_block, end_block
        );

        // Build filter for Transfer events
        let filter = Filter::new()
            .address(token_addr)
            .topic0(H256::from_str(TRANSFER_EVENT_TOPIC)?)
            .from_block(BlockNumber::Number(start_block.into()))
            .to_block(BlockNumber::Number(end_block.into()));

        // Fetch logs
        let logs = self.provider.get_logs(&filter).await
            .context("Failed to fetch transfer events")?;

        debug!("Found {} Transfer events", logs.len());

        // Parse events
        let events: Vec<TransferEvent> = logs
            .iter()
            .filter_map(|log| self.parse_transfer_event(log, token_address))
            .collect();

        Ok(TransferEventsResult {
            token_address: token_address.to_string(),
            events,
            from_block: start_block,
            to_block: end_block,
            total_count: logs.len(),
        })
    }

    /// Get list of unique holder addresses for a token
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(Vec<String>)` - List of unique holder addresses
    /// * `Err(anyhow::Error)` - Error if the query fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_unique_holders(&self, token_address: &str) -> Result<Vec<String>> {
        validate_token_address(token_address, "ethereum")?;

        info!("Getting unique holders for {} via Transfer events", token_address);

        let analysis = self.analyze_holders(token_address, None, None).await?;
        Ok(analysis.unique_holders)
    }

    /// Analyze holders for a token with configurable block range
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    /// * `from_block` - Optional starting block (defaults to scanning back DEFAULT_BLOCKS_TO_SCAN)
    /// * `to_block` - Optional ending block (defaults to latest)
    ///
    /// # Returns
    /// * `Ok(HolderAnalysis)` - Holder analysis result
    /// * `Err(anyhow::Error)` - Error if the analysis fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn analyze_holders(
        &self,
        token_address: &str,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<HolderAnalysis> {
        validate_token_address(token_address, "ethereum")?;

        let token_addr = Address::from_str(token_address)
            .context("Invalid token address format")?;

        // Get latest block if not specified
        #[allow(clippy::single_match_else)]
        let end_block = match to_block {
            Some(b) => b,
            None => {
                let latest = self.provider.get_block_number().await
                    .context("Failed to get latest block number")?;
                latest.as_u64()
            }
        };

        // Calculate from_block
        let start_block = match from_block {
            Some(b) => b,
            None => end_block.saturating_sub(DEFAULT_BLOCKS_TO_SCAN),
        };

        debug!(
            "Analyzing holders for {} from block {} to {}",
            token_address, start_block, end_block
        );

        // Collect all unique holders using HashSet
        let mut holders: HashSet<String> = HashSet::new();
        let mut total_transfers: u64 = 0;

        // Process in chunks to avoid RPC limits
        let mut current_block = start_block;
        while current_block <= end_block {
            let chunk_end = (current_block + MAX_BLOCKS_PER_REQUEST - 1).min(end_block);

            // Build filter for this chunk
            let filter = Filter::new()
                .address(token_addr)
                .topic0(H256::from_str(TRANSFER_EVENT_TOPIC)?)
                .from_block(BlockNumber::Number(current_block.into()))
                .to_block(BlockNumber::Number(chunk_end.into()));

            // Fetch logs
            let logs = match self.provider.get_logs(&filter).await {
                Ok(logs) => logs,
                Err(e) => {
                    warn!("Failed to fetch logs for block {}-{}: {}", current_block, chunk_end, e);
                    // Continue with next chunk
                    current_block = chunk_end + 1;
                    continue;
                }
            };

            total_transfers += logs.len() as u64;

            // Extract unique 'to' addresses (recipients = holders)
            for log in &logs {
                // Transfer event has 3 topics:
                // [0] = event signature hash
                // [1] = indexed 'from' address
                // [2] = indexed 'to' address
                if log.topics.len() >= 3 {
                    // Extract 'to' address from topic[2]
                    let to_address = log.topics[2].as_bytes()[12..32].to_vec();
                    if to_address.iter().any(|&b| b != 0) {
                        let holder_addr = format!("0x{}", hex::encode(to_address));
                        holders.insert(holder_addr.to_lowercase());
                    }
                }
            }

            debug!(
                "Processed blocks {}-{}: {} events, {} unique holders so far",
                current_block, chunk_end, logs.len(), holders.len()
            );

            current_block = chunk_end + 1;
        }

        let holders_vec: Vec<String> = holders.into_iter().collect();

        info!(
            "Holder analysis complete for {}: {} holders from {} transfers",
            token_address, holders_vec.len(), total_transfers
        );

        Ok(HolderAnalysis {
            token_address: token_address.to_string(),
            holder_count: holders_vec.len() as u64,
            unique_holders: holders_vec,
            from_block: start_block,
            to_block: end_block,
            total_transfers,
            analysis_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    /// Parse a log entry into a TransferEvent
    #[allow(clippy::unused_self, clippy::if_not_else)]
    fn parse_transfer_event(&self, log: &ethers::types::Log, token_address: &str) -> Option<TransferEvent> {
        // Transfer event has 3 topics:
        // [0] = event signature hash
        // [1] = indexed 'from' address
        // [2] = indexed 'to' address
        if log.topics.len() < 3 {
            return None;
        }

        // Extract addresses from topics
        let from_address = log.topics[1].as_bytes()[12..32].to_vec();
        let to_address = log.topics[2].as_bytes()[12..32].to_vec();

        // Skip if to_address is zero (burn events)
        if to_address.iter().all(|&b| b == 0) {
            return None;
        }

        // Extract value from data field
        let value = if log.data.is_empty() {
            "0".to_string()
        } else {
            format!("{}", U256::from_big_endian(&log.data.0))
        };

        Some(TransferEvent {
            tx_hash: format!("{:?}", log.transaction_hash?),
            block_number: log.block_number?.as_u64(),
            from: format!("0x{}", hex::encode(from_address)),
            to: format!("0x{}", hex::encode(to_address)),
            value,
            token_address: token_address.to_string(),
            log_index: log.log_index.unwrap_or_default().as_usize(),
        })
    }
}

impl Default for TransferEventClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default TransferEventClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_event_topic() {
        // Verify the Transfer event topic hash is correct
        assert_eq!(
            TRANSFER_EVENT_TOPIC,
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }

    #[test]
    fn test_holder_analysis_default() {
        let analysis = HolderAnalysis::default();
        assert_eq!(analysis.holder_count, 0);
        assert!(analysis.unique_holders.is_empty());
    }

    #[tokio::test]
    async fn test_client_creation() {
        // Test with demo RPC URL
        let client = TransferEventClient::with_rpc_url("https://eth-mainnet.g.alchemy.com/v2/demo");
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_client_creation_invalid_url() {
        // Test with invalid URL
        let client = TransferEventClient::with_rpc_url("not-a-valid-url");
        assert!(client.is_err());
    }

    #[test]
    fn test_transfer_event_serialization() {
        let event = TransferEvent {
            tx_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            block_number: 12_345_678,
            from: "0x1111111111111111111111111111111111111111".to_string(),
            to: "0x2222222222222222222222222222222222222222".to_string(),
            value: "1000000000000000000".to_string(),
            token_address: "0x3333333333333333333333333333333333333333".to_string(),
            log_index: 5,
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: TransferEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.tx_hash, event.tx_hash);
        assert_eq!(parsed.block_number, event.block_number);
        assert_eq!(parsed.from, event.from);
        assert_eq!(parsed.to, event.to);
    }

    #[test]
    fn test_holder_analysis_serialization() {
        let analysis = HolderAnalysis {
            token_address: "0x1234567890123456789012345678901234567890".to_string(),
            holder_count: 1000,
            unique_holders: vec![
                "0x1111111111111111111111111111111111111111".to_string(),
                "0x2222222222222222222222222222222222222222".to_string(),
            ],
            from_block: 10_000_000,
            to_block: 10_100_000,
            total_transfers: 50000,
            analysis_timestamp: 1_234_567_890,
        };

        let json = serde_json::to_string(&analysis).unwrap();
        let parsed: HolderAnalysis = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.holder_count, analysis.holder_count);
        assert_eq!(parsed.unique_holders.len(), analysis.unique_holders.len());
        assert_eq!(parsed.total_transfers, analysis.total_transfers);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_BLOCKS_TO_SCAN, 100_000);
        assert_eq!(MAX_BLOCKS_PER_REQUEST, 10_000);
    }
}
