//! API Fallback Chain System for Resilient Token Scanning
//!
//! This module provides a robust fallback mechanism that automatically tries
//! alternative API providers when primary providers fail, ensuring maximum
//! data availability.
//!
//! # Architecture
//!
//! ```text
//! FallbackChain<T>
//! ├── Provider 1 (Primary)
//! ├── Provider 2 (Fallback 1)
//! └── Provider 3 (Fallback 2)
//! ```
//!
//! # Example Usage
//!
//! ```rust
//! let mut chain = FallbackChain::new();
//!
//! // Add providers in priority order
//! chain.add_provider(
//!     ApiProvider::HoneypotIs,
//!     Box::new(|| async { honeypot_client.check_honeypot(token, chain).await })
//! );
//!
//! chain.add_provider(
//!     ApiProvider::TokenSniffer,
//!     Box::new(|| async { tokensniffer_client.scan_token(token).await })
//! );
//!
//! // Execute chain - returns first successful result
//! match chain.execute().await {
//!     Ok((provider, result)) => {
//!         info!("Succeeded with {:?}", provider);
//!     }
//!     Err(e) => {
//!         warn!("All providers failed: {}", e);
//!     }
//! }
//! ```
//!
//! # Pre-built Fallback Chains
//!
//! - `HoneypotFallbackChain`: Honeypot.is → TokenSniffer → GoPlus
//! - `VolumeAnalyticsFallbackChain`: Bitquery → The Graph → Dexscreener
//! - `PriceDataFallbackChain`: Dexscreener → DefiLlama → CoinGecko

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::uninlined_format_args)]

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use tracing::{debug, error, info, warn};

/// List of all supported API providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiProvider {
    /// Dexscreener - Primary price and market data
    Dexscreener,
    /// GoPlus Security - Contract risk analysis
    GoPlus,
    /// Moralis - Holder analysis
    Moralis,
    /// DefiLlama - Price data fallback
    DefiLlama,
    /// Etherscan - Contract metadata
    Etherscan,
    /// Honeypot.is - Primary honeypot detection
    HoneypotIs,
    /// TokenSniffer - Honeypot fallback
    TokenSniffer,
    /// Bitquery - Primary DEX analytics
    Bitquery,
    /// The Graph - DEX analytics fallback
    TheGraph,
    /// Ethplorer - Token metadata and holder count (Phase 1 Quick Win)
    Ethplorer,
}

impl fmt::Display for ApiProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dexscreener => write!(f, "Dexscreener"),
            Self::GoPlus => write!(f, "GoPlus"),
            Self::Moralis => write!(f, "Moralis"),
            Self::DefiLlama => write!(f, "DefiLlama"),
            Self::Etherscan => write!(f, "Etherscan"),
            Self::HoneypotIs => write!(f, "Honeypot.is"),
            Self::TokenSniffer => write!(f, "TokenSniffer"),
            Self::Bitquery => write!(f, "Bitquery"),
            Self::TheGraph => write!(f, "The Graph"),
            Self::Ethplorer => write!(f, "Ethplorer"),
        }
    }
}

/// Result from executing a fallback chain
#[derive(Debug, Clone)]
pub struct FallbackResult<T> {
    /// The provider that succeeded
    pub provider: ApiProvider,
    /// The successful result data
    pub data: T,
    /// Time taken to get the result in milliseconds
    pub elapsed_ms: u64,
    /// List of providers that failed (with their errors)
    pub failed_providers: Vec<(ApiProvider, String)>,
}

impl<T> FallbackResult<T> {
    /// Create a new successful result
    pub fn success(provider: ApiProvider, data: T, elapsed_ms: u64) -> Self {
        Self {
            provider,
            data,
            elapsed_ms,
            failed_providers: Vec::new(),
        }
    }

    /// Add a failed provider to the result
    pub fn with_failed_provider(mut self, provider: ApiProvider, error: String) -> Self {
        self.failed_providers.push((provider, error));
        self
    }
}

/// A fallback chain that tries multiple providers in order
pub struct FallbackChain<T> {
    /// Ordered list of providers with their handlers
    providers: Vec<ProviderEntry<T>>,
    /// Timeout for each provider attempt
    timeout: Duration,
    /// Whether to stop at first success (default: true)
    stop_at_first_success: bool,
}

/// Internal provider entry
struct ProviderEntry<T> {
    /// Provider identifier
    provider: ApiProvider,
    /// Async handler function that returns Result<T>
    handler: ProviderHandler<T>,
}

/// Type alias for the async handler function
type ProviderHandler<T> = Box<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<T>> + Send>> + Send + Sync,
>;

impl<T> Default for FallbackChain<T>
where
    T: Clone + Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FallbackChain<T>
where
    T: Clone + Send + 'static,
{
    /// Create a new empty fallback chain
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            timeout: Duration::from_secs(15),
            stop_at_first_success: true,
        }
    }

    /// Set whether to stop at first success
    pub fn stop_at_first_success(mut self, stop: bool) -> Self {
        self.stop_at_first_success = stop;
        self
    }

    /// Set the timeout for provider attempts
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Add a provider to the chain
    ///
    /// # Arguments
    /// * `provider` - The API provider identifier
    /// * `handler` - Async function that fetches data from this provider
    pub fn add_provider<F, Fut>(&mut self, provider: ApiProvider, handler: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        let boxed_handler: ProviderHandler<T> = Box::new(move || {
            Box::pin(handler())
        });

        self.providers.push(ProviderEntry {
            provider,
            handler: boxed_handler,
        });

        debug!("Added provider {:?} to fallback chain", provider);
    }

    /// Execute the fallback chain, trying each provider in order
    ///
    /// # Returns
    /// * `Ok(FallbackResult<T>)` - First successful result with metadata
    /// * `Err(anyhow::Error)` - All providers failed
    pub async fn execute(&self) -> Result<FallbackResult<T>> {
        if self.providers.is_empty() {
            return Err(anyhow!("Fallback chain has no providers configured"));
        }

        let start_time = Instant::now();
        let mut failed_providers: Vec<(ApiProvider, String)> = Vec::new();

        for (index, entry) in self.providers.iter().enumerate() {
            let provider = entry.provider;
            let provider_start = Instant::now();

            debug!("Trying provider {:?} ({} of {})", provider, index + 1, self.providers.len());

            // Execute with timeout
            let result = tokio::time::timeout(self.timeout, (entry.handler)()).await;

            match result {
                Ok(Ok(data)) => {
                    let elapsed = provider_start.elapsed().as_millis() as u64;
                    info!(
                        "Provider {:?} succeeded in {}ms",
                        provider, elapsed
                    );

                    let mut fallback_result = FallbackResult::success(provider, data, elapsed);
                    fallback_result.failed_providers = failed_providers;

                    return Ok(fallback_result);
                }
                Ok(Err(e)) => {
                    let elapsed = provider_start.elapsed().as_millis() as u64;
                    warn!(
                        "Provider {:?} failed after {}ms: {}",
                        provider, elapsed, e
                    );
                    failed_providers.push((provider, e.to_string()));
                }
                Err(_) => {
                    let elapsed = provider_start.elapsed().as_millis() as u64;
                    warn!(
                        "Provider {:?} timed out after {}ms",
                        provider, elapsed
                    );
                    failed_providers.push((
                        provider,
                        format!("Timeout after {}ms", elapsed),
                    ));
                }
            }

            // Stop at first success if configured
            if self.stop_at_first_success && index < self.providers.len() - 1 {
                // Continue to next provider only if this one failed
                // (already handled above)
            }
        }

        // All providers failed
        let total_elapsed = start_time.elapsed().as_millis() as u64;
        let error_messages: Vec<String> = failed_providers
            .iter()
            .map(|(p, e)| format!("{}: {}", p, e))
            .collect();

        error!(
            "All {} providers failed after {}ms: {}",
            failed_providers.len(),
            total_elapsed,
            error_messages.join("; ")
        );

        Err(anyhow!(
            "All API providers failed. Errors: {}",
            error_messages.join("; ")
        ))
    }

    /// Execute the chain and return just the data (without metadata)
    ///
    /// # Returns
    /// * `Ok(T)` - Successful result data
    /// * `Err(anyhow::Error)` - All providers failed
    pub async fn execute_data(&self) -> Result<T> {
        self.execute().await.map(|r| r.data)
    }

    /// Get the number of providers in the chain
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Clear all providers from the chain
    pub fn clear(&mut self) {
        self.providers.clear();
    }
}

/// Builder for creating fallback chains with a fluent API
pub struct FallbackChainBuilder<T> {
    chain: FallbackChain<T>,
}

impl<T> Default for FallbackChainBuilder<T>
where
    T: Clone + Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FallbackChainBuilder<T>
where
    T: Clone + Send + 'static,
{
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            chain: FallbackChain::new(),
        }
    }

    /// Set the timeout for provider attempts
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.chain.timeout = timeout;
        self
    }

    /// Set whether to stop at first success
    pub fn stop_at_first_success(mut self, stop: bool) -> Self {
        self.chain.stop_at_first_success = stop;
        self
    }

    /// Add a provider to the chain
    pub fn with_provider<F, Fut>(mut self, provider: ApiProvider, handler: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        self.chain.add_provider(provider, handler);
        self
    }

    /// Build the fallback chain
    pub fn build(self) -> FallbackChain<T> {
        self.chain
    }
}

// ============================================================================
// Pre-built Fallback Chains
// ============================================================================

/// Honeypot detection fallback chain
///
/// Priority:
/// 1. TokenSniffer (primary) - Free tier, reliable
/// 2. GoPlus contract risk (fallback) - Contract risk data
///
/// Note: Honeypot.is removed due to persistent parsing errors
pub struct HoneypotFallbackChain {
    chain: FallbackChain<HoneypotData>,
}

/// Unified honeypot data structure
#[derive(Debug, Clone)]
pub struct HoneypotData {
    pub token_address: String,
    pub chain: String,
    pub is_honeypot: bool,
    pub buy_tax: f32,
    pub sell_tax: f32,
    pub can_buy: bool,
    pub can_sell: bool,
    pub contract_risk_score: u32,
    pub liquidity_locked: bool,
    pub provider: ApiProvider,
}

impl HoneypotFallbackChain {
    /// Create a new honeypot fallback chain
    pub fn new() -> Self {
        Self {
            chain: FallbackChain::new(),
        }
    }

    /// Configure with actual API clients
    pub fn configure<T, G>(
        mut self,
        tokensniffer_client: &T,
        goplus_client: &G,
        token_address: &str,
        chain_id: &str,
    ) -> Self
    where
        T: crate::api::TokenSnifferClientTrait + Send + Sync + 'static,
        G: crate::api::GoPlusClientTrait + Send + Sync + 'static,
    {
        let token = token_address.to_string();
        let chain_str = chain_id.to_string();

        // Skip Honeypot.is - always fails with parse error
        // Start directly with TokenSniffer as primary

        // Add TokenSniffer as primary
        {
            let ts_client = tokensniffer_client.clone();
            let t = token.clone();
            let c = chain_str.clone();
            self.chain.add_provider(ApiProvider::TokenSniffer, move || {
                let t = t.clone();
                let c = c.clone();
                let client = ts_client.clone();
                async move {
                    let result = client.scan_token(&t, &c).await?;
                    Ok(HoneypotData {
                        token_address: result.token_address.clone(),
                        chain: result.chain.clone(),
                        is_honeypot: result.is_honeypot,
                        buy_tax: result.buy_tax,
                        sell_tax: result.sell_tax,
                        can_buy: result.can_buy,
                        can_sell: result.can_sell,
                        contract_risk_score: result.contract_risk_score,
                        liquidity_locked: result.liquidity_locked,
                        provider: ApiProvider::TokenSniffer,
                    })
                }
            });
        }

        // Add GoPlus as fallback
        {
            let gp_client = goplus_client.clone();
            let t = token;
            let c = chain_str;
            self.chain.add_provider(ApiProvider::GoPlus, move || {
                let t = t.clone();
                let c = c.clone();
                let client = gp_client.clone();
                async move {
                    let result = client.fetch_contract_risk(&t, &c).await?;
                    // Convert GoPlus data to HoneypotData
                    Ok(HoneypotData {
                        token_address: t.clone(),
                        chain: c.clone(),
                        is_honeypot: Self::goplus_to_honeypot(&result),
                        buy_tax: 0.0,
                        sell_tax: 0.0,
                        can_buy: true,
                        can_sell: true,
                        contract_risk_score: Self::calculate_risk_score(&result),
                        liquidity_locked: Self::is_liquidity_locked(&result),
                        provider: ApiProvider::GoPlus,
                    })
                }
            });
        }

        self
    }

    /// Execute the fallback chain
    pub async fn execute(&self) -> Result<HoneypotData> {
        self.chain.execute_data().await
    }

    /// Convert GoPlus contract risk to honeypot detection
    fn goplus_to_honeypot(risk: &crate::api::ContractRisk) -> bool {
        // Consider it a potential honeypot if:
        // - Owner can blacklist
        // - Has proxy contract
        // - Has hidden owner
        // - Can be upgraded
        risk.owner_can_blacklist
            || risk.is_proxy
            || risk.hidden_owner
            || risk.can_be_upgraded
            || risk.selfdestruct
    }

    /// Calculate risk score from GoPlus data
    fn calculate_risk_score(risk: &crate::api::ContractRisk) -> u32 {
        let mut score = 0u32;

        if risk.owner_can_blacklist {
            score += 25;
        }
        if risk.is_proxy {
            score += 15;
        }
        if risk.hidden_owner {
            score += 20;
        }
        if risk.can_be_upgraded {
            score += 10;
        }
        if risk.selfdestruct {
            score += 20;
        }
        if risk.owner_can_mint {
            score += 15;
        }
        if risk.anti_whale_modifiable {
            score += 5;
        }
        if risk.personal_privilege {
            score += 10;
        }
        if risk.lp_locked {
            score = score.saturating_sub(15);
        }

        score.min(100)
    }

    /// Check if liquidity is locked from GoPlus data
    fn is_liquidity_locked(risk: &crate::api::ContractRisk) -> bool {
        risk.lp_locked
    }
}

impl Default for HoneypotFallbackChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Volume analytics fallback chain
///
/// Priority:
/// 1. Dexscreener (primary) - Basic volume data
///
/// Note: Bitquery removed (402 Payment Required - token expired)
/// Note: The Graph removed (endpoint removed)
pub struct VolumeAnalyticsFallbackChain {
    chain: FallbackChain<VolumeData>,
}

/// Unified volume data structure
#[derive(Debug, Clone)]
pub struct VolumeData {
    pub total_trades: u32,
    pub unique_traders: u32,
    pub buy_volume_usd: f64,
    pub sell_volume_usd: f64,
    pub volume_24h_usd: f64,
    pub bpi: f64,
    pub volume_quality: f64,
    pub provider: ApiProvider,
}

impl VolumeAnalyticsFallbackChain {
    /// Create a new volume analytics fallback chain
    pub fn new() -> Self {
        Self {
            chain: FallbackChain::new(),
        }
    }

    /// Configure with actual API clients
    pub fn configure<D>(
        mut self,
        dexscreener_client: &D,
        token_address: &str,
        chain_id: &str,
        hours_back: u32,
    ) -> Self
    where
        D: crate::api::DexscreenerClientTrait + Send + Sync + 'static,
    {
        let token = token_address.to_string();
        let chain_str = chain_id.to_string();

        // Skip Bitquery - always 402 Payment Required
        // Skip The Graph - endpoint removed
        // Start directly with Dexscreener as primary

        // Add Dexscreener as primary
        {
            let dx_client = dexscreener_client.clone();
            let t = token;
            let c = chain_str;
            self.chain.add_provider(ApiProvider::Dexscreener, move || {
                let t = t.clone();
                let c = c.clone();
                let client = dx_client.clone();
                async move {
                    let result = client.fetch_token_data(&t, &c).await?;
                    // Convert Dexscreener data to VolumeData
                    Ok(VolumeData {
                        total_trades: 0,
                        unique_traders: 0,
                        buy_volume_usd: 0.0,
                        sell_volume_usd: 0.0,
                        volume_24h_usd: result.volume_24h,
                        bpi: 0.5,
                        volume_quality: 0.0,
                        provider: ApiProvider::Dexscreener,
                    })
                }
            });
        }

        self
    }

    /// Execute the fallback chain
    pub async fn execute(&self) -> Result<VolumeData> {
        self.chain.execute_data().await
    }
}

impl Default for VolumeAnalyticsFallbackChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Price data fallback chain
///
/// Priority:
/// 1. Dexscreener (primary)
/// 2. DefiLlama (fallback 1)
/// 3. CoinGecko (fallback 2 - if available)
pub struct PriceDataFallbackChain {
    chain: FallbackChain<PriceData>,
}

/// Unified price data structure
#[derive(Debug, Clone)]
pub struct PriceData {
    pub price_usd: f64,
    pub price_change_24h: f64,
    pub volume_24h: f64,
    pub liquidity_usd: f64,
    pub market_cap: Option<f64>,
    pub provider: ApiProvider,
}

impl PriceDataFallbackChain {
    /// Create a new price data fallback chain
    pub fn new() -> Self {
        Self {
            chain: FallbackChain::new(),
        }
    }

    /// Configure with actual API clients
    pub fn configure<D, L>(
        mut self,
        dexscreener_client: &D,
        defillama_client: &L,
        token_address: &str,
        chain_id: &str,
    ) -> Self
    where
        D: crate::api::DexscreenerClientTrait + Send + Sync + 'static,
        L: crate::api::DefiLlamaClientTrait + Send + Sync + 'static,
    {
        let token = token_address.to_string();
        let chain_str = chain_id.to_string();

        // Add Dexscreener as primary
        {
            let dx_client = dexscreener_client.clone();
            let t = token.clone();
            let c = chain_str.clone();
            self.chain.add_provider(ApiProvider::Dexscreener, move || {
                let t = t.clone();
                let c = c.clone();
                let client = dx_client.clone();
                async move {
                    let result = client.fetch_token_data(&t, &c).await?;
                    Ok(PriceData {
                        price_usd: result.price_usd,
                        price_change_24h: 0.0,  // Dexscreener doesn't provide this directly
                        volume_24h: result.volume_24h,
                        liquidity_usd: result.liquidity_usd,
                        market_cap: result.market_cap,
                        provider: ApiProvider::Dexscreener,
                    })
                }
            });
        }

        // Add DefiLlama as fallback 1
        {
            let ll_client = defillama_client.clone();
            let t = token;
            let c = chain_str;
            self.chain.add_provider(ApiProvider::DefiLlama, move || {
                let t = t.clone();
                let c = c.clone();
                let client = ll_client.clone();
                async move {
                    let result = client.get_price(&t, &c).await?;
                    Ok(PriceData {
                        price_usd: result.price,
                        price_change_24h: 0.0,
                        volume_24h: 0.0,
                        liquidity_usd: 0.0,
                        market_cap: None,
                        provider: ApiProvider::DefiLlama,
                    })
                }
            });
        }

        self
    }

    /// Execute the fallback chain
    pub async fn execute(&self) -> Result<PriceData> {
        self.chain.execute_data().await
    }
}

impl Default for PriceDataFallbackChain {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Client Traits for Fallback Chain Integration
// ============================================================================

/// Trait for HoneypotClient to enable fallback chain usage
pub trait HoneypotClientTrait: Clone + Send + Sync {
    fn check_honeypot(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::api::HoneypotResult>> + Send>>;
}

/// Trait for TokenSnifferClient to enable fallback chain usage
pub trait TokenSnifferClientTrait: Clone + Send + Sync {
    fn scan_token(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<TokenSnifferHoneypotData>> + Send>>;
}

/// TokenSniffer honeypot data for fallback compatibility
#[derive(Debug, Clone)]
pub struct TokenSnifferHoneypotData {
    pub token_address: String,
    pub chain: String,
    pub is_honeypot: bool,
    pub buy_tax: f32,
    pub sell_tax: f32,
    pub can_buy: bool,
    pub can_sell: bool,
    pub contract_risk_score: u32,
    pub liquidity_locked: bool,
    pub error: Option<String>,
}

/// Trait for GoPlusClient to enable fallback chain usage
pub trait GoPlusClientTrait: Clone + Send + Sync {
    fn fetch_contract_risk(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::api::ContractRisk>> + Send>>;
}

/// Trait for TheGraphClient to enable fallback chain usage
pub trait TheGraphClientTrait: Clone + Send + Sync {
    fn get_trade_analysis(
        &self,
        token_address: &str,
        chain: &str,
        hours_back: u32,
    ) -> Pin<Box<dyn Future<Output = Result<crate::api::GraphTradeAnalysis>> + Send>>;
}

/// Trait for DexscreenerClient to enable fallback chain usage
pub trait DexscreenerClientTrait: Clone + Send + Sync {
    fn fetch_token_data(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::api::DexTokenData>> + Send>>;
}

/// Trait for DefiLlamaClient to enable fallback chain usage
pub trait DefiLlamaClientTrait: Clone + Send + Sync {
    fn get_price(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::api::DefiLlamaPrice>> + Send>>;
}

// ============================================================================
// Trait Implementations for API Clients
// ============================================================================

impl HoneypotClientTrait for crate::api::HoneypotClient {
    fn check_honeypot(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::api::HoneypotResult>> + Send>> {
        let client = self.clone();
        let token = token_address.to_string();
        let chain_str = chain.to_string();
        Box::pin(async move {
            client.check_honeypot(&token, &chain_str).await
        })
    }
}

impl TokenSnifferClientTrait for crate::api::TokenSnifferClient {
    fn scan_token(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<TokenSnifferHoneypotData>> + Send>> {
        let client = self.clone();
        let token = token_address.to_string();
        let chain_str = chain.to_string();
        Box::pin(async move {
            let result = client.scan_token(&token, &chain_str).await?;
            Ok(TokenSnifferHoneypotData {
                token_address: result.token_address.clone(),
                chain: result.chain.clone(),
                is_honeypot: result.is_honeypot,
                buy_tax: result.buy_tax,
                sell_tax: result.sell_tax,
                can_buy: result.can_buy,
                can_sell: result.can_sell,
                contract_risk_score: result.contract_risk_score,
                liquidity_locked: result.liquidity_locked,
                error: result.error,
            })
        })
    }
}

impl GoPlusClientTrait for crate::api::GoPlusClient {
    fn fetch_contract_risk(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::api::ContractRisk>> + Send>> {
        let client = self.clone();
        let token = token_address.to_string();
        let chain_str = chain.to_string();
        Box::pin(async move {
            client.fetch_contract_risk(&token, &chain_str).await
        })
    }
}

impl TheGraphClientTrait for crate::api::TheGraphClient {
    fn get_trade_analysis(
        &self,
        token_address: &str,
        chain: &str,
        hours_back: u32,
    ) -> Pin<Box<dyn Future<Output = Result<crate::api::GraphTradeAnalysis>> + Send>> {
        let client = self.clone();
        let token = token_address.to_string();
        let chain_str = chain.to_string();
        Box::pin(async move {
            client.get_trade_analysis(&token, &chain_str, hours_back).await
        })
    }
}

impl DexscreenerClientTrait for crate::api::DexscreenerClient {
    fn fetch_token_data(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::api::DexTokenData>> + Send>> {
        let client = self.clone();
        let token = token_address.to_string();
        let chain_str = chain.to_string();
        Box::pin(async move {
            client.fetch_token_data(&token, &chain_str).await
        })
    }
}

impl DefiLlamaClientTrait for crate::api::DefiLlamaClient {
    fn get_price(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<crate::api::DefiLlamaPrice>> + Send>> {
        let client = self.clone();
        let token = token_address.to_string();
        let chain_str = chain.to_string();
        Box::pin(async move {
            client.get_price(&token, &chain_str).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fallback_chain_success_first() {
        let mut chain: FallbackChain<String> = FallbackChain::new();

        chain.add_provider(ApiProvider::Dexscreener, || {
            async move { Ok("success".to_string()) }
        });

        let result = chain.execute().await.unwrap();
        assert_eq!(result.provider, ApiProvider::Dexscreener);
        assert_eq!(result.data, "success");
        assert!(result.failed_providers.is_empty());
    }

    #[tokio::test]
    async fn test_fallback_chain_with_fallback() {
        let mut chain: FallbackChain<String> = FallbackChain::new();

        // First provider fails
        chain.add_provider(ApiProvider::Bitquery, || {
            async move { Err(anyhow!("Bitquery failed")) }
        });

        // Second provider succeeds
        chain.add_provider(ApiProvider::TheGraph, || {
            async move { Ok("fallback_success".to_string()) }
        });

        let result = chain.execute().await.unwrap();
        assert_eq!(result.provider, ApiProvider::TheGraph);
        assert_eq!(result.data, "fallback_success");
        assert_eq!(result.failed_providers.len(), 1);
        assert_eq!(result.failed_providers[0].0, ApiProvider::Bitquery);
    }

    #[tokio::test]
    async fn test_fallback_chain_all_fail() {
        let mut chain: FallbackChain<String> = FallbackChain::new();

        chain.add_provider(ApiProvider::Dexscreener, || {
            async move { Err(anyhow!("Dexscreener failed")) }
        });

        chain.add_provider(ApiProvider::DefiLlama, || {
            async move { Err(anyhow!("DefiLlama failed")) }
        });

        let result = chain.execute().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("All API providers failed"));
    }

    #[tokio::test]
    async fn test_fallback_chain_timeout() {
        let mut chain: FallbackChain<String> = FallbackChain::new().with_timeout(Duration::from_millis(100));

        // Provider that takes too long
        chain.add_provider(ApiProvider::Bitquery, || {
            async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok("too_slow".to_string())
            }
        });

        let result = chain.execute().await;
        assert!(result.is_err());
    }

    #[test]
    fn test_api_provider_display() {
        assert_eq!(ApiProvider::Dexscreener.to_string(), "Dexscreener");
        assert_eq!(ApiProvider::HoneypotIs.to_string(), "Honeypot.is");
        assert_eq!(ApiProvider::TheGraph.to_string(), "The Graph");
    }

    #[test]
    fn test_fallback_result_builder() {
        let result = FallbackResult::success(ApiProvider::Dexscreener, 42u32, 100);
        assert_eq!(result.provider, ApiProvider::Dexscreener);
        assert_eq!(result.data, 42);
        assert_eq!(result.elapsed_ms, 100);
    }

    #[tokio::test]
    async fn test_fallback_chain_builder() {
        let chain = FallbackChainBuilder::new()
            .timeout(Duration::from_secs(10))
            .stop_at_first_success(true)
            .with_provider(ApiProvider::Dexscreener, || async move {
                Ok("builder_test".to_string())
            })
            .build();

        let result = chain.execute().await.unwrap();
        assert_eq!(result.data, "builder_test");
    }
}
