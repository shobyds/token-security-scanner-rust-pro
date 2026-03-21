//! Dexscreener API client for fetching token liquidity and price data
//!
//! Dexscreener provides real-time DEX trading data including:
//! - Token prices across multiple DEXes
//! - Liquidity pool information
//! - Trading volume metrics
//! - Pair data

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unused_self)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_precision_loss)]
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

/// Dexscreener API client
#[derive(Debug, Clone)]
pub struct DexscreenerClient {
    http_client: Client,
    base_url: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// Token data response from Dexscreener API
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenData {
    /// Token address
    pub address: String,
    /// Token name
    pub name: Option<String>,
    /// Token symbol
    pub symbol: Option<String>,
    /// Price in USD
    pub price_usd: f64,
    /// Liquidity in USD
    pub liquidity_usd: f64,
    /// 24-hour volume in USD
    pub volume_24h: f64,
    /// Number of trading pairs
    pub pair_count: u32,
    /// Chain ID
    pub chain_id: Option<String>,
    /// Pair created timestamp in milliseconds (Phase 0 Task 0.3)
    pub pair_created_at: Option<u64>,

    // Multi-pool aggregated fields (Phase 1 Task 1.1)
    /// Total liquidity across all pools
    pub total_liquidity_usd: f64,
    /// Primary pool liquidity
    pub primary_pool_liquidity: f64,
    /// Dominance ratio (largest pool / total)
    pub dominance_ratio: f64,
    /// Top 3 pools liquidity ratio
    pub top3_liquidity_ratio: f64,
    /// 1h volume from primary pool
    pub volume_h1: f64,
    /// Buy count in 24h
    pub buys_24h: u32,
    /// Sell count in 24h
    pub sells_24h: u32,
    /// Market cap
    pub market_cap: Option<f64>,
    /// FDV
    pub fdv: Option<f64>,
    /// Unique traders in 24h (buys + sells) (Phase 4.3: Trader Analytics)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_traders_24h: Option<u32>,
    /// Trading activity score 0-100 (Phase 4.3: Trader Analytics)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trading_activity_score: Option<u8>,
}

/// Pair information from Dexscreener
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pair {
    /// Chain ID
    pub chain_id: Option<String>,
    /// DEX ID
    pub dex_id: Option<String>,
    /// URL to the pair
    pub url: Option<String>,
    /// Base token information
    pub base_token: TokenInfo,
    /// Quote token information
    pub quote_token: TokenInfo,
    /// Price information
    pub price_native: Option<String>,
    /// Price in USD
    pub price_usd: Option<String>,
    /// Volume in native token (24h)
    pub volume: Option<Volume>,
    /// Liquidity information
    pub liquidity: Option<Liquidity>,
    /// Pair created timestamp
    pub pair_created_at: Option<i64>,
    /// 24-hour change percentage
    pub price_change: Option<PriceChange>,
    /// Transaction counts
    pub txns: Option<Txns>,
    /// FDV (Fully Diluted Valuation)
    pub fdv: Option<f64>,
    /// Market cap
    pub market_cap: Option<f64>,
    /// Pair address
    pub pair_address: Option<String>,
}

/// Token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token address
    pub address: Option<String>,
    /// Token name
    pub name: Option<String>,
    /// Token symbol
    pub symbol: Option<String>,
}

/// Volume information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    /// 24-hour volume in native token
    pub h24: Option<f64>,
    /// 6-hour volume in native token
    pub h6: Option<f64>,
    /// 1-hour volume in native token
    pub h1: Option<f64>,
    /// 5-minute volume in native token
    pub m5: Option<f64>,
    /// 24-hour volume in USD
    #[serde(rename = "h24USD")]
    pub h24_usd: Option<f64>,
}

/// Liquidity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Liquidity {
    /// Total liquidity in USD
    pub usd: Option<f64>,
    /// Base token liquidity
    pub base: Option<f64>,
    /// Quote token liquidity
    pub quote: Option<f64>,
}

/// Price change information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceChange {
    /// 5-minute change percentage
    pub m5: Option<f32>,
    /// 1-hour change percentage
    pub h1: Option<f32>,
    /// 6-hour change percentage
    pub h6: Option<f32>,
    /// 24-hour change percentage
    pub h24: Option<f32>,
}

/// Transaction counts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Txns {
    /// Transaction counts by time period and type
    pub m5: Option<TxnCounts>,
    pub h1: Option<TxnCounts>,
    pub h6: Option<TxnCounts>,
    pub h24: Option<TxnCounts>,
}

/// Transaction counts for a period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxnCounts {
    /// Number of buy transactions
    pub buys: Option<u32>,
    /// Number of sell transactions
    pub sells: Option<u32>,
}

/// Aggregated result from fetching all pools for a token (Phase 1 Task 1.1)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DexScreenerPairsResult {
    // Aggregated across all pools
    /// Total liquidity in USD across all pools
    pub total_liquidity_usd: f64,
    /// Liquidity of the primary (largest) pool
    pub primary_pool_liquidity: f64,
    /// Number of pools
    pub pool_count: usize,
    /// Dominance ratio: largest pool / total
    pub dominance_ratio: f64,
    /// Top 3 pools liquidity ratio: sum(top3) / total
    pub top3_liquidity_ratio: f64,

    // From the most liquid pool (primary)
    /// Price in USD from primary pool
    pub price_usd: Option<f64>,
    /// Price in native token from primary pool
    pub price_native: Option<f64>,
    /// Market cap from primary pool
    pub market_cap: Option<f64>,
    /// FDV from primary pool
    pub fdv: Option<f64>,
    /// 24h volume summed across all pools
    pub volume_h24: f64,
    /// 1h volume from primary pool
    pub volume_h1: f64,
    /// Buy count in 24h from primary pool
    pub buys_h24: u32,
    /// Sell count in 24h from primary pool
    pub sells_h24: u32,
    /// Unique traders in 24h (buys + sells) (Phase 4.3: Trader Analytics)
    pub unique_traders_24h: u32,
    /// Trading activity score 0-100 (Phase 4.3: Trader Analytics)
    pub trading_activity_score: Option<u8>,
    /// Earliest pair_created_at (token launch time)
    pub pair_created_at_ms: Option<u64>,
    /// Primary pool pair address
    pub primary_pair_address: String,
    /// Primary pool DEX name
    pub primary_dex: String,
}

impl DexScreenerPairsResult {
    /// Aggregate multiple pairs into a single result
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_pairs(pairs: Vec<Pair>) -> Self {
        if pairs.is_empty() {
            return Self::default();
        }

        // Sort pools by liquidity descending
        let mut sorted = pairs.clone();
        sorted.sort_by(|a, b| {
            let liq_a = a.liquidity.as_ref().and_then(|l| l.usd).unwrap_or(0.0);
            let liq_b = b.liquidity.as_ref().and_then(|l| l.usd).unwrap_or(0.0);
            liq_b.partial_cmp(&liq_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Sum all pool liquidities
        let total_liquidity_usd: f64 = sorted
            .iter()
            .filter_map(|p| p.liquidity.as_ref().and_then(|l| l.usd))
            .sum();

        let primary = &sorted[0];
        let primary_liq = primary.liquidity.as_ref().and_then(|l| l.usd).unwrap_or(0.0);

        // Dominance ratio: largest pool vs total
        let dominance_ratio = if total_liquidity_usd > 0.0 {
            primary_liq / total_liquidity_usd
        } else {
            1.0
        };

        // Top3 ratio
        let top3_sum: f64 = sorted
            .iter()
            .take(3)
            .filter_map(|p| p.liquidity.as_ref().and_then(|l| l.usd))
            .sum();
        let top3_ratio = if total_liquidity_usd > 0.0 {
            top3_sum / total_liquidity_usd
        } else {
            1.0
        };

        // Total 24h volume across all pools
        let volume_h24: f64 = sorted
            .iter()
            .filter_map(|p| p.volume.as_ref().and_then(|v| v.h24))
            .sum();

        // Buy/sell counts from primary pool (most accurate)
        let (buys_h24, sells_h24) = primary
            .txns
            .as_ref()
            .and_then(|t| t.h24.as_ref())
            .map_or((0, 0), |t| (t.buys.unwrap_or(0), t.sells.unwrap_or(0)));

        // Unique traders = buys + sells (Phase 4.3: Trader Analytics)
        let unique_traders_24h = buys_h24 + sells_h24;

        // Calculate trading activity score (Phase 4.3: Trader Analytics)
        // Score based on: volume, trader count, and price change
        let trading_activity_score = calculate_trading_activity_score(
            volume_h24,
            unique_traders_24h,
            primary.price_change.as_ref().and_then(|p| p.h24),
            primary_liq,
        );

        // Earliest pairCreatedAt = actual token launch time
        let earliest_created = sorted.iter().filter_map(|p| p.pair_created_at).min();

        Self {
            total_liquidity_usd,
            primary_pool_liquidity: primary_liq,
            pool_count: sorted.len(),
            dominance_ratio,
            top3_liquidity_ratio: top3_ratio,
            price_usd: primary.price_usd.as_deref().and_then(|p| p.parse().ok()),
            market_cap: primary.market_cap,
            fdv: primary.fdv,
            volume_h24,
            volume_h1: primary.volume.as_ref().and_then(|v| v.h1).unwrap_or(0.0),
            buys_h24,
            sells_h24,
            unique_traders_24h,
            trading_activity_score: Some(trading_activity_score),
            pair_created_at_ms: earliest_created.and_then(|ts| ts.try_into().ok()),
            primary_pair_address: primary.pair_address.clone().unwrap_or_default(),
            primary_dex: primary.dex_id.clone().unwrap_or_default(),
            price_native: primary.price_native.as_deref().and_then(|p| p.parse().ok()),
        }
    }
}

/// Calculate trading activity score from 0-100 (Phase 4.3: Trader Analytics)
///
/// Score components:
/// - Volume score (0-40): Based on 24h volume
/// - Trader score (0-30): Based on unique traders count
/// - Momentum score (0-30): Based on price change percentage
fn calculate_trading_activity_score(
    volume_24h: f64,
    unique_traders: u32,
    price_change_24h: Option<f32>,
    liquidity: f64,
) -> u8 {
    // Volume score: log scale, max at $10M volume
    let volume_score = if volume_24h > 0.0 {
        let log_vol = volume_24h.log10();
        let normalized = (log_vol / 7.0).min(1.0); // 10^7 = 10M
        (normalized * 40.0) as u8
    } else {
        0
    };

    // Trader score: max at 1000 unique traders
    let trader_score = ((unique_traders as f32 / 1000.0).min(1.0) * 30.0) as u8;

    // Momentum score: based on absolute price change (high volatility = active trading)
    let momentum_score = if let Some(pc) = price_change_24h {
        let abs_change = pc.abs();
        let normalized = (abs_change / 100.0).min(1.0); // Max score at 100% change
        (normalized * 30.0) as u8
    } else {
        0
    };

    let total_score = volume_score + trader_score + momentum_score;

    // Clamp to valid range
    total_score.min(100)
}

impl DexscreenerClient {
    /// Create a new Dexscreener client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new Dexscreener client with custom configuration
    pub fn with_config(config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(config.dexscreener.timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://api.dexscreener.com".to_string(),
            timeout: config.dexscreener.timeout,
            retry_count: config.dexscreener.retry_count,
            enabled: config.dexscreener.enabled,
        })
    }

    /// Create a new Dexscreener client with custom parameters
    pub fn with_params(timeout: Duration, retry_count: u32, enabled: bool) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://api.dexscreener.com".to_string(),
            timeout,
            retry_count,
            enabled,
        })
    }

    /// Create a new Dexscreener client for testing with custom base URL
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

    /// Fetch token data from Dexscreener
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to query
    /// * `chain` - The blockchain network (ethereum, bsc, polygon, etc.)
    ///
    /// # Returns
    /// * `Ok(TokenData)` - Aggregated token data from all pairs
    /// * `Err(anyhow::Error)` - Error if the request fails or token is not found
    #[instrument(skip(self), fields(token_address = %token_address, chain = %chain))]
    pub async fn fetch_token_data(&self, token_address: &str, chain: &str) -> Result<TokenData> {
        if !self.enabled {
            return Err(anyhow!("Dexscreener API is disabled"));
        }

        // Validate token address
        validate_token_address(token_address, chain)?;

        let endpoint = format!("{}/tokens/v1/{}/{}", self.base_url, chain, token_address);

        debug!("Fetching token data from Dexscreener: {}", endpoint);

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
                    .context("Failed to send request to Dexscreener")?;

                let status = response.status();
                debug!("Dexscreener response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    debug!("Dexscreener response body length: {}", body.len());
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Token not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Dexscreener"))
                } else {
                    Err(anyhow!("Dexscreener API error: {}", status))
                }
            },
        )
        .await?;

        // Parse the response - Dexscreener returns array directly: [{...}]
        let pairs: Vec<Pair> =
            serde_json::from_str(&response_data).context("Failed to parse Dexscreener response")?;

        if pairs.is_empty() {
            return Err(anyhow!("Token not found on any DEX"));
        }

        // Aggregate data from all pairs
        let token_data = self.aggregate_pair_data(&pairs, token_address)?;

        info!(
            "Successfully fetched Dexscreener data for {}: price=${}, liquidity=${}",
            token_address, token_data.price_usd, token_data.liquidity_usd
        );

        Ok(token_data)
    }

    /// Aggregate data from multiple trading pairs
    fn aggregate_pair_data(&self, pairs: &[Pair], token_address: &str) -> Result<TokenData> {
        if pairs.is_empty() {
            return Err(anyhow!("No pairs to aggregate"));
        }

        // Find the pair with highest liquidity (most reliable)
        let primary_pair = pairs
            .iter()
            .max_by(|a, b| {
                let liq_a = a.liquidity.as_ref().and_then(|l| l.usd).unwrap_or(0.0);
                let liq_b = b.liquidity.as_ref().and_then(|l| l.usd).unwrap_or(0.0);
                liq_a
                    .partial_cmp(&liq_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .ok_or_else(|| anyhow!("Failed to find primary pair"))?;

        // Calculate total liquidity across all pairs
        let total_liquidity: f64 = pairs
            .iter()
            .filter_map(|p| p.liquidity.as_ref().and_then(|l| l.usd))
            .sum();

        // Calculate total 24h volume across all pairs
        let total_volume: f64 = pairs
            .iter()
            .filter_map(|p| p.volume.as_ref().and_then(|v| v.h24_usd))
            .sum();

        // Get price from primary pair
        let price_usd = primary_pair
            .price_usd
            .as_ref()
            .and_then(|p| p.parse::<f64>().ok())
            .unwrap_or(0.0);

        // Get token info from base token
        let base_token = &primary_pair.base_token;

        // Calculate multi-pool metrics (Phase 1 Task 1.1)
        let primary_liq = primary_pair.liquidity.as_ref().and_then(|l| l.usd).unwrap_or(0.0);
        let dominance_ratio = if total_liquidity > 0.0 {
            primary_liq / total_liquidity
        } else {
            1.0
        };

        // Top 3 ratio
        let mut sorted_pairs: Vec<&Pair> = pairs.iter().collect();
        sorted_pairs.sort_by(|a, b| {
            let liq_a = a.liquidity.as_ref().and_then(|l| l.usd).unwrap_or(0.0);
            let liq_b = b.liquidity.as_ref().and_then(|l| l.usd).unwrap_or(0.0);
            liq_b.partial_cmp(&liq_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        let top3_sum: f64 = sorted_pairs
            .iter()
            .take(3)
            .filter_map(|p| p.liquidity.as_ref().and_then(|l| l.usd))
            .sum();
        let top3_ratio = if total_liquidity > 0.0 {
            top3_sum / total_liquidity
        } else {
            1.0
        };

        // Get buy/sell counts from primary pair
        let (buys_24h, sells_24h) = primary_pair
            .txns
            .as_ref()
            .and_then(|t| t.h24.as_ref())
            .map_or((0, 0), |t| (t.buys.unwrap_or(0), t.sells.unwrap_or(0)));

        // Calculate unique traders and trading activity score (Phase 4.3: Trader Analytics)
        let unique_traders_24h = buys_24h + sells_24h;
        let trading_activity_score = Some(calculate_trading_activity_score(
            total_volume,
            unique_traders_24h,
            primary_pair.price_change.as_ref().and_then(|p| p.h24),
            primary_liq,
        ));

        Ok(TokenData {
            address: token_address.to_string(),
            name: base_token.name.clone(),
            symbol: base_token.symbol.clone(),
            price_usd,
            liquidity_usd: total_liquidity,
            volume_24h: total_volume,
            pair_count: pairs.len() as u32,
            chain_id: primary_pair.chain_id.clone(),
            #[allow(clippy::cast_sign_loss)]
            pair_created_at: primary_pair.pair_created_at.map(|ts| ts as u64),
            // Multi-pool fields (Phase 1 Task 1.1)
            total_liquidity_usd: total_liquidity,
            primary_pool_liquidity: primary_liq,
            dominance_ratio,
            top3_liquidity_ratio: top3_ratio,
            volume_h1: primary_pair.volume.as_ref().and_then(|v| v.h1).unwrap_or(0.0),
            buys_24h,
            sells_24h,
            market_cap: primary_pair.market_cap,
            fdv: primary_pair.fdv,
            // Phase 4.3: Trader Analytics
            unique_traders_24h: Some(unique_traders_24h),
            trading_activity_score,
        })
    }

    /// Fetch all trading pairs for a token (Phase 1 Task 1.1)
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to analyze
    /// * `chain` - The blockchain network (ethereum, bsc, polygon, etc.)
    ///
    /// # Returns
    /// * `Ok(DexScreenerPairsResult)` - Aggregated data from all pools
    /// * `Err(anyhow::Error)` - Error if the request fails
    #[instrument(skip(self), fields(token_address = %token_address, chain = %chain))]
    pub async fn fetch_all_pairs(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Result<DexScreenerPairsResult> {
        if !self.enabled {
            return Err(anyhow!("Dexscreener API is disabled"));
        }

        // Validate token address
        validate_token_address(token_address, chain)?;

        // Use the token-pairs endpoint for multi-pool data
        let endpoint = format!("{}/token-pairs/v1/{}/{}", self.base_url, chain, token_address);

        debug!("Fetching all pairs from Dexscreener: {}", endpoint);

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
                    .context("Failed to send request to Dexscreener")?;

                let status = response.status();
                debug!("Dexscreener response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    debug!("Dexscreener response body length: {}", body.len());
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Token not found: {}", token_address))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Dexscreener"))
                } else {
                    Err(anyhow!("Dexscreener API error: {}", status))
                }
            },
        )
        .await?;

        // Parse the response - returns array of pairs directly
        let pairs: Vec<Pair> =
            serde_json::from_str(&response_data).context("Failed to parse Dexscreener response")?;

        if pairs.is_empty() {
            return Err(anyhow!(
                "No trading pairs found for token: {}",
                token_address
            ));
        }

        // Aggregate data from all pairs
        let result = DexScreenerPairsResult::from_pairs(pairs);

        info!(
            "Successfully fetched {} pairs for {}: total_liquidity=${}, primary_liquidity=${}",
            result.pool_count,
            token_address,
            result.total_liquidity_usd,
            result.primary_pool_liquidity
        );

        Ok(result)
    }

    /// Fetch data for multiple tokens in a single batch
    ///
    /// # Arguments
    /// * `token_addresses` - List of token addresses to query
    /// * `chain` - The blockchain network (ethereum, bsc, polygon, etc.)
    ///
    /// # Returns
    /// * `Ok(Vec<TokenData>)` - List of token data (may exclude failed lookups)
    pub async fn fetch_multiple_tokens(
        &self,
        token_addresses: &[&str],
        chain: &str,
    ) -> Result<Vec<TokenData>> {
        let mut results = Vec::with_capacity(token_addresses.len());

        for address in token_addresses {
            match self.fetch_token_data(address, chain).await {
                Ok(data) => results.push(data),
                Err(e) => {
                    warn!("Failed to fetch data for {}: {}", address, e);
                    // Continue with other tokens
                }
            }
        }

        Ok(results)
    }
}

impl Default for DexscreenerClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default DexscreenerClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> DexscreenerClient {
        let http_client = Client::builder()
            .http1_only() // Use HTTP/1.1 for mockito compatibility
            .build()
            .unwrap();

        DexscreenerClient {
            http_client,
            base_url: mock_server_url.to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0, // No retries in tests
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_fetch_token_data_success() {
        let mut server = Server::new_async().await;

        let mock_response = r#"[
            {
                "chainId": "ethereum",
                "dexId": "uniswap",
                "url": "https://dexscreener.com/ethereum/0xpair",
                "baseToken": {
                    "address": "0x1234567890123456789012345678901234567890",
                    "name": "Test Token",
                    "symbol": "TEST"
                },
                "quoteToken": {
                    "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                    "name": "Wrapped Ether",
                    "symbol": "WETH"
                },
                "priceNative": "0.0001",
                "priceUsd": "0.25",
                "volume": {
                    "h24": 100000,
                    "h24USD": 25000
                },
                "liquidity": {
                    "usd": 500000,
                    "base": 1000000,
                    "quote": 100
                },
                "priceChange": {
                    "h24": 5.5
                }
            }
        ]"#;

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_token_data("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let data = result.unwrap();
        assert_eq!(data.address, "0x1234567890123456789012345678901234567890");
        assert_eq!(data.name, Some("Test Token".to_string()));
        assert_eq!(data.symbol, Some("TEST".to_string()));
        assert!((data.price_usd - 0.25).abs() < 0.001);
        assert!((data.liquidity_usd - 500_000.0).abs() < 0.01);
        assert!((data.volume_24h - 25_000.0).abs() < 0.01);
        assert_eq!(data.pair_count, 1);
        assert_eq!(data.chain_id, Some("ethereum".to_string()));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_token_data_not_found() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "GET",
                "/tokens/v1/ethereum/0x1234567890123456789012345678901234567890",
            )
            .with_status(404)
            .with_body("Not Found")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_token_data("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Token not found"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_token_data_empty_pairs() {
        let mut server = Server::new_async().await;

        let mock_response = r"[]";

        let mock = server
            .mock(
                "GET",
                "/tokens/v1/ethereum/0x1234567890123456789012345678901234567890",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_token_data("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Token not found on any DEX")
        );

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_token_data_rate_limit() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "GET",
                "/tokens/v1/ethereum/0x1234567890123456789012345678901234567890",
            )
            .with_status(429)
            .with_body("Too Many Requests")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_token_data("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limited"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_token_data_server_error() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "GET",
                "/tokens/v1/ethereum/0x1234567890123456789012345678901234567890",
            )
            .with_status(500)
            .with_body("Internal Server Error")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_token_data("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("API error"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_token_data_invalid_json() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock(
                "GET",
                "/tokens/v1/ethereum/0x1234567890123456789012345678901234567890",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("not valid json")
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_token_data("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parse"));

        mock.assert_async().await;
    }

    #[test]
    fn test_fetch_token_data_disabled() {
        let client = DexscreenerClient {
            http_client: Client::new(),
            base_url: "https://api.dexscreener.com".to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 3,
            enabled: false,
        };

        let result = futures::executor::block_on(
            client.fetch_token_data("0x1234567890123456789012345678901234567890", "ethereum"),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    #[test]
    fn test_fetch_token_data_invalid_address() {
        let client = DexscreenerClient::default();

        let result = futures::executor::block_on(
            client.fetch_token_data("invalid_address", "ethereum")
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must start with 0x")
        );
    }

    #[tokio::test]
    async fn test_fetch_token_data_multiple_pairs() {
        let mut server = Server::new_async().await;

        let mock_response = r#"[
            {
                "chainId": "ethereum",
                "baseToken": {
                    "address": "0x1234567890123456789012345678901234567890",
                    "name": "Test Token",
                    "symbol": "TEST"
                },
                "quoteToken": {
                    "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                    "name": "WETH",
                    "symbol": "WETH"
                },
                "priceUsd": "0.25",
                "volume": {
                    "h24USD": 25000
                },
                "liquidity": {
                    "usd": 500000
                }
            },
            {
                "chainId": "ethereum",
                "baseToken": {
                    "address": "0x1234567890123456789012345678901234567890",
                    "name": "Test Token",
                    "symbol": "TEST"
                },
                "quoteToken": {
                    "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                    "name": "USDT",
                    "symbol": "USDT"
                },
                "priceUsd": "0.24",
                "volume": {
                    "h24USD": 15000
                },
                "liquidity": {
                    "usd": 300000
                }
            }
        ]"#;

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .fetch_token_data("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        let data = result.unwrap();
        // Total liquidity from both pairs
        assert!((data.liquidity_usd - 800_000.0).abs() < 0.01);
        // Total volume from both pairs
        assert!((data.volume_24h - 40_000.0).abs() < 0.01);
        // Price from primary pair (highest liquidity)
        assert!((data.price_usd - 0.25).abs() < 0.001);
        assert_eq!(data.pair_count, 2);

        mock.assert_async().await;
    }

    #[test]
    fn test_token_data_serialization() {
        let data = TokenData {
            address: "0x1234".to_string(),
            name: Some("Test".to_string()),
            symbol: Some("TST".to_string()),
            price_usd: 1.5,
            liquidity_usd: 100_000.0,
            volume_24h: 50_000.0,
            pair_count: 5,
            total_liquidity_usd: 100_000.0,
            primary_pool_liquidity: 80_000.0,
            dominance_ratio: 0.8,
            top3_liquidity_ratio: 0.95,
            volume_h1: 10_000.0,
            buys_24h: 100,
            sells_24h: 90,
            market_cap: Some(1_000_000.0),
            fdv: Some(1_000_000.0),
            chain_id: Some("ethereum".to_string()),
            pair_created_at: None,
            unique_traders_24h: Some(190),
            trading_activity_score: Some(75),
        };

        let json = serde_json::to_string(&data).unwrap();
        let deserialized: TokenData = serde_json::from_str(&json).unwrap();

        assert_eq!(data.address, deserialized.address);
        assert_eq!(data.price_usd, deserialized.price_usd);
    }
}
