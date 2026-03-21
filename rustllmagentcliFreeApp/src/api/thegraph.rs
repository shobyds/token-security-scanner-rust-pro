//! The Graph API client for DEX trade analytics (Uniswap V3 subgraph)
//!
//! The Graph provides blockchain data through GraphQL including:
//! - DEX swaps and trades
//! - Liquidity pool data
//! - Token transfer analysis
//!
//! This client serves as a fallback/alternative to Bitquery for DEX analytics.
//!
//! # Endpoints
//! - Uniswap V3: https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3
//! - Uniswap V2: https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v2
//!
//! # Example Query
//! ```graphql
//! {
//!   swaps(first: 100, where: { token0: "0xTOKEN" }) {
//!     amountUSD
//!     sender
//!     recipient
//!     timestamp
//!     amount0In
//!     amount1In
//!   }
//! }
//! ```

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::manual_clamp)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, create_http_client,
    validate_token_address, with_retry,
};

/// The Graph API client for DEX analytics
#[derive(Debug, Clone)]
pub struct TheGraphClient {
    http_client: Client,
    endpoint: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// Swap data from The Graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSwapData {
    /// USD amount of the swap
    #[serde(rename = "amountUSD")]
    pub amount_usd: String,
    /// Sender address
    pub sender: String,
    /// Recipient address
    pub recipient: String,
    /// Swap timestamp
    pub timestamp: String,
    /// Amount of token0 input
    #[serde(rename = "amount0In")]
    pub amount0_in: String,
    /// Amount of token1 input
    #[serde(rename = "amount1In")]
    pub amount1_in: String,
    /// Amount of token0 output
    #[serde(rename = "amount0Out")]
    pub amount0_out: String,
    /// Amount of token1 output
    #[serde(rename = "amount1Out")]
    pub amount1_out: String,
}

/// Trade analysis result from The Graph
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphTradeAnalysis {
    /// Total number of trades
    pub total_trades: u32,
    /// Number of unique buyers
    pub unique_buyers: u32,
    /// Number of unique sellers
    pub unique_sellers: u32,
    /// Buy volume in USD
    pub buy_volume_usd: f64,
    /// Sell volume in USD
    pub sell_volume_usd: f64,
    /// Total volume in USD (24h)
    pub volume_24h_usd: f64,
    /// Buy Pressure Index (buy_volume / total_volume)
    pub bpi: f64,
    /// Volume quality (unique_traders / total_trades)
    pub volume_quality: f64,
    /// Time window in hours
    pub time_window_hours: u32,
    /// Unique trader count
    pub unique_traders: u32,
    /// Unique traders in the last 24 hours (Phase 4.3: Holder Analytics)
    pub unique_traders_24h: Option<u32>,
    /// Holder growth rate percentage (Phase 4.3: Holder Analytics)
    pub holder_growth_rate: Option<f64>,
    /// Trading activity score 0-100 (Phase 4.3: Holder Analytics)
    pub trading_activity_score: Option<u8>,
    /// 30-day trade history for growth calculation (Phase 4.3)
    pub daily_trade_data: Vec<DailyTradeData>,
}

/// Daily trade data for holder growth analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyTradeData {
    /// Unix timestamp for the day
    pub date: u64,
    /// Number of trades on this day
    pub daily_txns: u32,
    /// Volume in USD on this day
    pub daily_volume_usd: f64,
    /// Total liquidity in USD on this day
    pub total_liquidity_usd: f64,
}

/// GraphQL query response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphResponse<T> {
    /// Data payload
    pub data: Option<T>,
    /// Errors if any
    pub errors: Option<Vec<GraphQLError>>,
}

/// GraphQL error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
    /// Error message
    pub message: String,
    /// Error locations
    pub locations: Option<Vec<ErrorLocation>>,
}

/// Error location in GraphQL query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorLocation {
    /// Line number
    pub line: u32,
    /// Column number
    pub column: u32,
}

/// Response data structure for swaps query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapsResponse {
    /// List of swaps
    pub swaps: Option<Vec<GraphSwapData>>,
}

impl TheGraphClient {
    /// Create a new TheGraph client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new TheGraph client with custom configuration
    pub fn with_config(config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(config.thegraph.timeout)?;

        // Use Uniswap V3 subgraph for better data coverage
        let endpoint = if config.thegraph.endpoint_uniswap_v3.is_empty() {
            "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3".to_string()
        } else {
            config.thegraph.endpoint_uniswap_v3.clone()
        };

        tracing::info!("TheGraph client initialized with endpoint: {}", endpoint);

        Ok(Self {
            http_client,
            endpoint,
            timeout: config.thegraph.timeout,
            retry_count: config.thegraph.retry_count,
            enabled: config.thegraph.enabled,
        })
    }

    /// Create a new TheGraph client with custom parameters
    pub fn with_params(
        endpoint: String,
        timeout: Duration,
        retry_count: u32,
        enabled: bool,
    ) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            endpoint,
            timeout,
            retry_count,
            enabled,
        })
    }

    /// Create a new TheGraph client for testing with custom endpoint
    #[cfg(test)]
    pub fn for_testing(endpoint: String, http_client: Client) -> Self {
        Self {
            http_client,
            endpoint,
            timeout: Duration::from_secs(15),
            retry_count: 0,
            enabled: true,
        }
    }

    /// Set the endpoint for a specific DEX/pool
    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = endpoint;
        self
    }

    /// Fetch DEX trade analysis for a token using The Graph
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to analyze
    /// * `chain` - The blockchain network (ethereum, bsc, base)
    /// * `hours_back` - Number of hours to look back (24 for daily)
    ///
    /// # Returns
    /// * `Ok(GraphTradeAnalysis)` - Trade analysis result
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address, chain = %chain))]
    pub async fn get_trade_analysis(
        &self,
        token_address: &str,
        chain: &str,
        hours_back: u32,
    ) -> Result<GraphTradeAnalysis> {
        if !self.enabled {
            return Err(anyhow!("The Graph API is disabled"));
        }

        // Validate token address
        validate_token_address(token_address, chain)?;

        // Calculate cutoff timestamp
        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::hours(i64::from(hours_back));
        let cutoff_timestamp = cutoff.timestamp();

        // Step 1: Find pools that contain this token
        let token_lower = token_address.to_lowercase();
        debug!("Finding pools for token {}", token_lower);

        // Use proper GraphQL query format for The Graph
        let pool_query = format!(
            r#"{{
  pools(
    first: 10,
    where: {{
      or: [
        {{ token0: "{token}" }},
        {{ token1: "{token}" }}
      ]
    }}
  ) {{
    id
    token0 {{ id symbol }}
    token1 {{ id symbol }}
    totalValueLockedUSD
    volumeUSD
  }}
}}"#,
            token = token_lower
        );

        let pool_body = serde_json::json!({
            "query": pool_query
        });

        debug!("Fetching pools from The Graph for token {}", token_lower);
        debug!("Pool query: {}", pool_query);

        let pool_response = self
            .http_client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .json(&pool_body)
            .send()
            .await
            .context("Failed to send pools request to The Graph")?;

        let pool_status = pool_response.status();
        debug!("The Graph pools response status: {}", pool_status);

        let mut pool_ids: Vec<String> = Vec::new();

        if pool_status.is_success() {
            let pool_text = pool_response
                .text()
                .await
                .context("Failed to read pools response")?;

            debug!("The Graph pools response: {}", pool_text);

            // Check for GraphQL errors first
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&pool_text) {
                // Check for errors field
                if let Some(errors) = parsed.get("errors").and_then(|v| v.as_array()) {
                    if !errors.is_empty() {
                        let error_msg = errors
                            .iter()
                            .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                            .collect::<Vec<_>>()
                            .join(", ");
                        warn!("The Graph pools query error: {}", error_msg);
                        // Continue with empty pool list - will return default analysis
                    }
                }
                
                if let Some(pools) = parsed.get("data").and_then(|d| d.get("pools")).and_then(|p| p.as_array()) {
                    for pool in pools {
                        if let Some(id) = pool.get("id").and_then(|v| v.as_str()) {
                            pool_ids.push(id.to_string());
                            let tvl = pool.get("totalValueLockedUSD").and_then(|v| v.as_str()).unwrap_or("0");
                            debug!("Found pool: {} with TVL ${}", id, tvl);
                        }
                    }
                }
            }
        } else {
            let error_body = pool_response.text().await.unwrap_or_default();
            warn!("The Graph pools request failed: status={}, body={}", pool_status, error_body);
        }

        info!("Found {} pools for token {}", pool_ids.len(), token_lower);

        // Step 2: Query swaps for the found pools
        // If no pools found, return empty analysis
        if pool_ids.is_empty() {
            debug!("No pools found for token {} - returning empty analysis", token_lower);
            return Ok(GraphTradeAnalysis::default());
        }

        // Build GraphQL query for swaps - query each pool separately for better reliability
        // The Graph has limitations on complex OR filters, so we'll query pools individually
        let mut all_swaps = Vec::new();
        
        for pool_id in &pool_ids {
            let query = format!(
                r#"{{
  swaps(
    first: 1000,
    where: {{
      pool: "{pool}",
      timestamp_gte: {cutoff}
    }}
  ) {{
    amountUSD
    sender
    recipient
    timestamp
    amount0In
    amount1In
    amount0Out
    amount1Out
  }}
}}"#,
                pool = pool_id,
                cutoff = cutoff_timestamp
            );

            let body = serde_json::json!({ "query": query });

            debug!("Fetching swaps for pool {} from The Graph", pool_id);

            let response = self
                .http_client
                .post(&self.endpoint)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let resp_text = resp.text().await.unwrap_or_default();
                        debug!("The Graph swaps response for pool {}: {}", pool_id, resp_text);
                        
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&resp_text) {
                            // Check for GraphQL errors
                            if let Some(errors) = parsed.get("errors").and_then(|v| v.as_array()) {
                                if !errors.is_empty() {
                                    let error_msg = errors
                                        .iter()
                                        .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    warn!("The Graph swaps query error for pool {}: {}", pool_id, error_msg);
                                    continue;
                                }
                            }
                            
                            // Extract swaps
                            if let Some(swaps) = parsed.get("data").and_then(|d| d.get("swaps")).and_then(|s| s.as_array()) {
                                for swap in swaps {
                                    if let Ok(swap_data) = serde_json::from_value::<GraphSwapData>(swap.clone()) {
                                        all_swaps.push(swap_data);
                                    }
                                }
                            }
                        }
                    } else {
                        warn!("The Graph swaps request failed for pool {}: status={}", pool_id, resp.status());
                    }
                }
                Err(e) => {
                    warn!("The Graph swaps request error for pool {}: {}", pool_id, e);
                }
            }
        }

        info!("Fetched {} total swaps from {} pools for token {}", all_swaps.len(), pool_ids.len(), token_lower);

        // Parse all swaps into analysis
        let analysis = Self::parse_swaps_data(&all_swaps, hours_back)?;

        info!(
            "Trade analysis from The Graph: {} trades, {} unique traders, volume: ${:.2}",
            analysis.total_trades,
            analysis.unique_traders,
            analysis.volume_24h_usd
        );

        Ok(analysis)
    }

    /// Parse swaps data into GraphTradeAnalysis
    fn parse_swaps_data(
        swaps: &[GraphSwapData],
        hours_back: u32,
    ) -> Result<GraphTradeAnalysis> {
        let mut analysis = GraphTradeAnalysis {
            time_window_hours: hours_back,
            ..Default::default()
        };

        if swaps.is_empty() {
            debug!("No swaps found in The Graph response");
            return Ok(analysis);
        }

        let mut unique_senders: HashSet<String> = HashSet::new();
        let mut unique_recipients: HashSet<String> = HashSet::new();
        let mut buy_volume = 0.0_f64;
        let mut sell_volume = 0.0_f64;

        for swap_value in swaps {
            // Parse amountUSD
            let amount_usd = swap_value
                .amount_usd
                .parse::<f64>()
                .unwrap_or(0.0);

            // Parse sender and recipient
            let sender = swap_value.sender.clone();
            let recipient = swap_value.recipient.clone();

            // Parse amounts
            let amount0_in = swap_value.amount0_in.parse::<f64>().unwrap_or(0.0);
            let amount1_in = swap_value.amount1_in.parse::<f64>().unwrap_or(0.0);
            let amount0_out = swap_value.amount0_out.parse::<f64>().unwrap_or(0.0);
            let amount1_out = swap_value.amount1_out.parse::<f64>().unwrap_or(0.0);

            // Determine if this is a buy or sell based on flow
            // Buy: token0 flows out, token1 flows in (or vice versa depending on pool orientation)
            // For simplicity, we consider it a buy if amount0Out > 0 or amount1Out > 0
            let is_buy = amount0_out > 0.0 || amount1_out > 0.0;

            if is_buy {
                buy_volume += amount_usd;
            } else {
                sell_volume += amount_usd;
            }

            // Track unique addresses
            if !sender.is_empty() {
                unique_senders.insert(sender);
            }
            if !recipient.is_empty() {
                unique_recipients.insert(recipient);
            }
        }

        let total_volume = buy_volume + sell_volume;
        let total_trades = swaps.len() as u32;
        let unique_traders = unique_senders.union(&unique_recipients).count() as u32;

        analysis.total_trades = total_trades;
        analysis.unique_buyers = unique_senders.len() as u32;
        analysis.unique_sellers = unique_recipients.len() as u32;
        analysis.unique_traders = unique_traders;
        analysis.buy_volume_usd = buy_volume;
        analysis.sell_volume_usd = sell_volume;
        analysis.volume_24h_usd = total_volume;

        // Calculate BPI (Buy Pressure Index)
        analysis.bpi = if total_volume > 0.0 {
            buy_volume / total_volume
        } else {
            0.5 // Default to neutral if no volume
        };

        // Calculate volume quality
        analysis.volume_quality = if total_trades > 0 {
            f64::from(unique_traders) / f64::from(total_trades)
        } else {
            0.0
        };

        // Clamp values to valid ranges
        analysis.bpi = analysis.bpi.min(1.0).max(0.0);
        analysis.volume_quality = analysis.volume_quality.min(1.0).max(0.0);

        Ok(analysis)
    }

    /// Fetch swaps for a specific pool
    ///
    /// # Arguments
    /// * `pool_address` - The liquidity pool address
    /// * `first` - Number of swaps to fetch (max 1000)
    ///
    /// # Returns
    /// * `Ok(Vec<GraphSwapData>)` - List of swaps
    pub async fn get_pool_swaps(&self, pool_address: &str, first: u32) -> Result<Vec<GraphSwapData>> {
        if !self.enabled {
            return Err(anyhow!("The Graph API is disabled"));
        }

        let first = first.min(1000); // The Graph max limit

        let query = format!(
            r#"
{{
  swaps(
    first: {first},
    where: {{
      pool: "{pool}"
    }}
  ) {{
    amountUSD
    sender
    recipient
    timestamp
    amount0In
    amount1In
    amount0Out
    amount1Out
  }}
}}"#,
            first = first,
            pool = pool_address.to_lowercase()
        );

        let body = serde_json::json!({
            "query": query
        });

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .post(&self.endpoint)
                    .json(&body)
                    .send()
                    .await
                    .context("Failed to send request to The Graph")?;

                let status = response.status();
                if status.is_success() {
                    response
                        .text()
                        .await
                        .context("Failed to read response body")
                } else {
                    Err(anyhow!("The Graph API error: {}", status))
                }
            },
        )
        .await?;

        let parsed: serde_json::Value =
            serde_json::from_str(&response_data).context("Failed to parse The Graph response")?;

        // Check for GraphQL errors
        if let Some(errors) = parsed.get("errors").and_then(|v| v.as_array()) {
            if !errors.is_empty() {
                let error_msg = errors
                    .iter()
                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(anyhow!("The Graph GraphQL error: {}", error_msg));
            }
        }

        // Extract swaps
        let swaps = parsed
            .get("data")
            .and_then(|d| d.get("swaps"))
            .and_then(|s| s.as_array())
            .cloned()
            .unwrap_or_default();

        let swap_list: Vec<GraphSwapData> = swaps
            .iter()
            .filter_map(|s| serde_json::from_value(s.clone()).ok())
            .collect();

        Ok(swap_list)
    }

    /// Get pool data by token address
    ///
    /// # Arguments
    /// * `token_address` - The token address to find pools for
    ///
    /// # Returns
    /// * `Ok(Vec<String>)` - List of pool addresses
    pub async fn get_pools_by_token(&self, token_address: &str) -> Result<Vec<String>> {
        if !self.enabled {
            return Err(anyhow!("The Graph API is disabled"));
        }

        let query = format!(
            r#"
{{
  pools(
    where: {{
      or: [
        {{ token0: "{token}" }},
        {{ token1: "{token}" }}
      ]
    }}
  ) {{
    id
    token0 {{ id }}
    token1 {{ id }}
    totalValueLockedUSD
    volumeUSD
  }}
}}"#,
            token = token_address.to_lowercase()
        );

        let body = serde_json::json!({
            "query": query
        });

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .post(&self.endpoint)
                    .json(&body)
                    .send()
                    .await
                    .context("Failed to send request to The Graph")?;

                let status = response.status();
                if status.is_success() {
                    response
                        .text()
                        .await
                        .context("Failed to read response body")
                } else {
                    Err(anyhow!("The Graph API error: {}", status))
                }
            },
        )
        .await?;

        let parsed: serde_json::Value =
            serde_json::from_str(&response_data).context("Failed to parse The Graph response")?;

        // Check for GraphQL errors
        if let Some(errors) = parsed.get("errors").and_then(|v| v.as_array()) {
            if !errors.is_empty() {
                let error_msg = errors
                    .iter()
                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(anyhow!("The Graph GraphQL error: {}", error_msg));
            }
        }

        // Extract pool IDs
        let pools = parsed
            .get("data")
            .and_then(|d| d.get("pools"))
            .and_then(|p| p.as_array())
            .cloned()
            .unwrap_or_default();

        let pool_ids: Vec<String> = pools
            .iter()
            .filter_map(|p| p.get("id").and_then(|v| v.as_str()).map(String::from))
            .collect();

        Ok(pool_ids)
    }

    /// Fetch enhanced holder analytics including growth rate and trading activity
    ///
    /// This method queries The Graph for 30-day historical data to calculate:
    /// - Unique traders in the last 24 hours
    /// - Holder growth rate (percentage change over 30 days)
    /// - Trading activity score (0-100)
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to analyze
    /// * `chain` - The blockchain network
    ///
    /// # Returns
    /// * `Ok(GraphTradeAnalysis)` - Enhanced trade analysis with holder metrics
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address, chain = %chain))]
    pub async fn get_holder_analytics(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Result<GraphTradeAnalysis> {
        if !self.enabled {
            return Err(anyhow!("The Graph API is disabled"));
        }

        validate_token_address(token_address, chain)?;

        // Step 1: Find pools that contain this token
        let token_lower = token_address.to_lowercase();
        debug!("Finding pools for token {} for holder analytics", token_lower);

        let pool_query = format!(
            r#"
{{
  pools(
    where: {{
      or: [
        {{ token0: "{token}" }},
        {{ token1: "{token}" }}
      ]
    }}
  ) {{
    id
    token0 {{ id }}
    token1 {{ id }}
  }}
}}"#,
            token = token_lower
        );

        let pool_body = serde_json::json!({
            "query": pool_query
        });

        let pool_response = self
            .http_client
            .post(&self.endpoint)
            .json(&pool_body)
            .send()
            .await
            .context("Failed to send pools request to The Graph")?;

        let mut pool_ids: Vec<String> = Vec::new();

        if pool_response.status().is_success() {
            let pool_text = pool_response
                .text()
                .await
                .context("Failed to read pools response")?;
            
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&pool_text) {
                if let Some(pools) = parsed.get("data").and_then(|d| d.get("pools")).and_then(|p| p.as_array()) {
                    for pool in pools {
                        if let Some(id) = pool.get("id").and_then(|v| v.as_str()) {
                            pool_ids.push(id.to_string());
                        }
                    }
                }
            }
        }

        if pool_ids.is_empty() {
            debug!("No Uniswap V3 pools found for token {} - using Dexscreener fallback", token_lower);
        } else {
            info!("Found {} Uniswap V3 pools for holder analytics of token {}", pool_ids.len(), token_lower);
        }

        // If no pools found, return empty analysis
        if pool_ids.is_empty() {
            return Ok(GraphTradeAnalysis::default());
        }

        // Calculate timestamps for 24h and 30-day analysis
        let now = chrono::Utc::now();
        let cutoff_24h = now - chrono::Duration::hours(24);
        let cutoff_30days = now - chrono::Duration::days(30);

        // Query each pool separately instead of using complex OR filter
        // This is more reliable for The Graph API
        let mut all_swaps_24h: Vec<serde_json::Value> = Vec::new();
        
        for pool_id in &pool_ids {
            let query_24h_single = format!(
                r#"
{{
  swaps(
    first: 1000,
    where: {{
      pool: "{pool}",
      timestamp_gte: {cutoff24h}
    }}
  ) {{
    amountUSD
    sender
    recipient
    timestamp
    amount0In
    amount1In
    amount0Out
    amount1Out
  }}
}}"#,
                pool = pool_id,
                cutoff24h = cutoff_24h.timestamp()
            );

            let body_24h_single = serde_json::json!({
                "query": query_24h_single
            });

            if let Ok(resp) = self.http_client.post(&self.endpoint).json(&body_24h_single).send().await {
                if resp.status().is_success() {
                    if let Ok(text) = resp.text().await {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(swaps) = parsed.get("data").and_then(|d| d.get("swaps")).and_then(|s| s.as_array()) {
                                all_swaps_24h.extend(swaps.clone());
                            }
                        }
                    }
                }
            }
        }

        // Use aggregated swaps data for parsing later
        // The actual parsing happens below in the resp_24hours section

        if !all_swaps_24h.is_empty() {
            info!("Found {} swaps in last 24h across {} pools", all_swaps_24h.len(), pool_ids.len());
        }

        // Query 30-day pool day data for growth calculation (Phase 4.3: Pool Analytics)
        // Use poolDayData instead of tokenDayDatas for more reliable data
        let pools_daydata_filter: String = pool_ids
            .iter()
            .map(|id| format!(r#"{{ pool: "{}" }}"#, id))
            .collect::<Vec<_>>()
            .join(", ");

        let query_30days = format!(
            r"
{{
  poolDayDatas(
    first: 100,
    orderBy: date,
    orderDirection: desc,
    where: {{
      date_gte: {cutoff30d},
      or: [{pools}]
    }}
  ) {{
    date
    pool {{ id }}
    txns
    volumeUSD
    totalValueLockedUSD
  }}
}}",
            cutoff30d = cutoff_30days.timestamp(),
            pools = pools_daydata_filter
        );

        debug!("Fetching holder analytics from The Graph for {} pools", pool_ids.len());
        debug!("30-day query: {}", query_30days);

        // Execute 30-day query (24h data already fetched via individual pool queries)
        let resp_30days = self.execute_graphql_query(&query_30days).await;

        let mut analysis = GraphTradeAnalysis::default();

        // Parse 24h data from aggregated pool queries
        if !all_swaps_24h.is_empty() {
            debug!("Processing {} swaps from 24h pool queries", all_swaps_24h.len());

            // Convert JSON values to GraphSwapData
            let swaps_data: Vec<GraphSwapData> = all_swaps_24h
                .iter()
                .filter_map(|s| serde_json::from_value::<GraphSwapData>(s.clone()).ok())
                .collect();

            if !swaps_data.is_empty() {
                let temp_analysis = Self::parse_swaps_data(&swaps_data, 24)?;
                analysis.unique_traders_24h = Some(temp_analysis.unique_traders);
                analysis.total_trades = temp_analysis.total_trades;
                analysis.volume_24h_usd = temp_analysis.volume_24h_usd;
                analysis.unique_buyers = temp_analysis.unique_buyers;
                analysis.unique_sellers = temp_analysis.unique_sellers;
                analysis.buy_volume_usd = temp_analysis.buy_volume_usd;
                analysis.sell_volume_usd = temp_analysis.sell_volume_usd;
                analysis.bpi = temp_analysis.bpi;
                analysis.volume_quality = temp_analysis.volume_quality;
                analysis.unique_traders = temp_analysis.unique_traders;
            }
        }

        // Parse 30-day data for growth rate (Phase 4.3: Pool Analytics)
        if let Ok(parsed_30days) = resp_30days {
            let day_data = parsed_30days
                .get("data")
                .and_then(|d| d.get("poolDayDatas"))
                .and_then(|t| t.as_array())
                .cloned()
                .unwrap_or_default();

            debug!("30-day poolDayDatas query returned {} results", day_data.len());

            #[allow(clippy::if_not_else)]
            if !day_data.is_empty() {
                let mut daily_data: Vec<DailyTradeData> = Vec::new();
                let mut first_day_txns = 0u32;
                let mut last_day_txns = 0u32;

                for (i, day) in day_data.iter().enumerate() {
                    let date = day
                        .get("date")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);

                    // poolDayDatas uses "txns" instead of "dailyTxns"
                    let daily_txns = day
                        .get("txns")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|s| s.parse::<u32>().ok())
                        .unwrap_or(0u32);

                    let daily_volume = day
                        .get("volumeUSD")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|s| s.parse::<f64>().ok())
                        .unwrap_or(0.0);

                    let total_liquidity = day
                        .get("totalValueLockedUSD")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|s| s.parse::<f64>().ok())
                        .unwrap_or(0.0);

                    if i == 0 {
                        last_day_txns = daily_txns;
                    }
                    if i == day_data.len() - 1 {
                        first_day_txns = daily_txns;
                    }

                    daily_data.push(DailyTradeData {
                        date,
                        daily_txns,
                        daily_volume_usd: daily_volume,
                        total_liquidity_usd: total_liquidity,
                    });
                }

                // Calculate holder growth rate
                if first_day_txns > 0 {
                    let growth_rate = ((f64::from(last_day_txns) - f64::from(first_day_txns))
                        / f64::from(first_day_txns))
                        * 100.0;
                    analysis.holder_growth_rate = Some(growth_rate);
                }

                // Calculate trading activity score (0-100)
                let avg_daily_txns: f64 = daily_data
                    .iter()
                    .map(|d| f64::from(d.daily_txns))
                    .sum::<f64>()
                    / daily_data.len() as f64;

                // Score based on average daily transactions
                // 0 txn = 0, 10+ txn/day = 50, 100+ txn/day = 80, 1000+ txn/day = 100
                let activity_score = if avg_daily_txns == 0.0 {
                    0
                } else if avg_daily_txns < 10.0 {
                    (avg_daily_txns * 5.0).clamp(0.0, 100.0) as u8
                } else if avg_daily_txns < 100.0 {
                    (50.0 + (avg_daily_txns - 10.0) * 0.375).clamp(0.0, 100.0) as u8
                } else if avg_daily_txns < 1000.0 {
                    (80.0 + (avg_daily_txns - 100.0) * 0.022).clamp(0.0, 100.0) as u8
                } else {
                    100
                };

                analysis.trading_activity_score = Some(activity_score.min(100));
                analysis.daily_trade_data = daily_data;
            } else {
                // Fallback: poolDayDatas returned 0 results
                // This can happen for tokens with low liquidity or new tokens
                warn!("poolDayDatas returned 0 results for token {} - using fallback values", token_lower);
                
                // Calculate fallback values based on 24h data
                if analysis.unique_traders_24h.is_some() {
                    // Use 24h traders as a baseline for unique_traders_24h
                    // (already set from swaps query)
                    
                    // Estimate holder growth rate as 0% (stable)
                    analysis.holder_growth_rate = Some(0.0);
                    
                    // Calculate trading activity score based on 24h data
                    let traders = analysis.unique_traders_24h.unwrap_or(0);
                    let volume = analysis.volume_24h_usd;
                    
                    // Score based on available 24h metrics
                    let trader_score = ((traders as f32 / 1000.0).min(1.0) * 50.0) as u8;
                    let volume_score = if volume > 0.0 {
                        let log_vol = volume.log10();
                        let normalized = (log_vol / 7.0).min(1.0);
                        (normalized * 50.0) as u8
                    } else {
                        0
                    };
                    
                    analysis.trading_activity_score = Some((trader_score + volume_score).min(100));
                    
                    // Create minimal daily trade data
                    let now = chrono::Utc::now().timestamp() as u64;
                    analysis.daily_trade_data = vec![DailyTradeData {
                        date: now,
                        daily_txns: analysis.total_trades,
                        daily_volume_usd: analysis.volume_24h_usd,
                        total_liquidity_usd: 0.0,
                    }];
                    
                    info!("Using fallback analytics: traders={}, volume=${}, score={:?}",
                        traders, volume, analysis.trading_activity_score);
                }
            }
        } else {
            // 30-day query failed entirely
            warn!("30-day poolDayDatas query failed for token {} - using fallback", token_lower);
            
            // Provide fallback values if we have 24h data
            if analysis.unique_traders_24h.is_some() {
                analysis.holder_growth_rate = Some(0.0);
                let traders = analysis.unique_traders_24h.unwrap_or(0);
                analysis.trading_activity_score = Some((traders / 20).min(100) as u8);
            }
        }

        info!(
            "Holder analytics: {} unique traders (24h), growth rate: {:?}%, activity score: {:?}",
            analysis.unique_traders_24h.unwrap_or(0),
            analysis.holder_growth_rate,
            analysis.trading_activity_score
        );

        Ok(analysis)
    }

    /// Execute a GraphQL query
    async fn execute_graphql_query(&self, query: &str) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "query": query
        });

        debug!("Executing GraphQL query on endpoint: {}", self.endpoint);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .post(&self.endpoint)
                    .json(&body)
                    .send()
                    .await
                    .context("Failed to send request to The Graph")?;

                let status = response.status();
                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    debug!("The Graph query succeeded");
                    Ok(body)
                } else if status.as_u16() == 429 {
                    warn!("Rate limited by The Graph");
                    Err(anyhow!("Rate limited by The Graph"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    error!("The Graph API error: {} - {}", status, error_body);
                    Err(anyhow!("The Graph API error: {} - {}", status, error_body))
                }
            },
        )
        .await?;

        let parsed: serde_json::Value =
            serde_json::from_str(&response_data).context("Failed to parse The Graph response")?;

        // Check for GraphQL errors
        if let Some(errors) = parsed.get("errors").and_then(|v| v.as_array()) {
            if !errors.is_empty() {
                let error_msg = errors
                    .iter()
                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                    .collect::<Vec<_>>()
                    .join(", ");
                error!("The Graph GraphQL error: {}", error_msg);
                return Err(anyhow!("The Graph GraphQL error: {}", error_msg));
            }
        }

        Ok(parsed)
    }
}

impl Default for TheGraphClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default TheGraphClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> TheGraphClient {
        let http_client = Client::builder()
            .http1_only()
            .build()
            .unwrap();

        TheGraphClient {
            http_client,
            endpoint: mock_server_url.to_string(),
            timeout: Duration::from_secs(15),
            retry_count: 0,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_get_trade_analysis_success() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "data": {
                "swaps": [
                    {
                        "amountUSD": "1000.50",
                        "sender": "0x1111111111111111111111111111111111111111",
                        "recipient": "0x2222222222222222222222222222222222222222",
                        "timestamp": "1234567890",
                        "amount0In": "1.0",
                        "amount1In": "0",
                        "amount0Out": "0",
                        "amount1Out": "1000.50"
                    },
                    {
                        "amountUSD": "500.25",
                        "sender": "0x3333333333333333333333333333333333333333",
                        "recipient": "0x4444444444444444444444444444444444444444",
                        "timestamp": "1234567891",
                        "amount0In": "0.5",
                        "amount1In": "0",
                        "amount0Out": "0",
                        "amount1Out": "500.25"
                    }
                ]
            }
        }"#;

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .get_trade_analysis("0x1234567890123456789012345678901234567890", "ethereum", 24)
            .await;

        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert!(analysis.total_trades >= 2);
        assert!(analysis.volume_24h_usd > 1500.0);

        mock.assert_async().await;
    }

    #[tokio::test]
    #[allow(clippy::float_cmp)]
    async fn test_get_trade_analysis_empty_response() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "data": {
                "swaps": []
            }
        }"#;

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .get_trade_analysis("0x1234567890123456789012345678901234567890", "ethereum", 24)
            .await;

        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.total_trades, 0);
        assert_eq!(analysis.volume_24h_usd, 0.0);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_trade_analysis_disabled() {
        let client = TheGraphClient {
            http_client: Client::new(),
            endpoint: "https://api.thegraph.com".to_string(),
            timeout: Duration::from_secs(15),
            retry_count: 3,
            enabled: false,
        };

        let result = client
            .get_trade_analysis("0x1234567890123456789012345678901234567890", "ethereum", 24)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    #[test]
    fn test_graph_swap_data_serialization() {
        let swap = GraphSwapData {
            amount_usd: "1000.50".to_string(),
            sender: "0x1111".to_string(),
            recipient: "0x2222".to_string(),
            timestamp: "1234567890".to_string(),
            amount0_in: "1.0".to_string(),
            amount1_in: "0".to_string(),
            amount0_out: "0".to_string(),
            amount1_out: "1000.50".to_string(),
        };

        let json = serde_json::to_string(&swap).unwrap();
        let deserialized: GraphSwapData = serde_json::from_str(&json).unwrap();

        assert_eq!(swap.amount_usd, deserialized.amount_usd);
        assert_eq!(swap.sender, deserialized.sender);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_graph_trade_analysis_default() {
        let analysis = GraphTradeAnalysis::default();
        assert_eq!(analysis.total_trades, 0);
        assert_eq!(analysis.buy_volume_usd, 0.0);
        assert_eq!(analysis.bpi, 0.0);
        assert_eq!(analysis.volume_quality, 0.0);
    }
}
