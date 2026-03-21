//! Feature Extraction Module for Token Risk Analysis
//!
//! This module extracts structured features from raw scan results,
//! transforming API responses into the `TokenMetrics` format used by
//! both the TRI engine and the Phi-3 LLM analyzer.

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]

use serde::{Deserialize, Serialize};

use crate::api::{ContractRisk, DeployerProfile, DexTokenData, HoneypotResult, HolderAnalysis, ScanResult};

/// Comprehensive token metrics extracted from scan results
///
/// This struct contains all features needed for TRI scoring and LLM analysis.
/// Fields are populated from multiple API sources with graceful degradation
/// when data is unavailable.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenMetrics {
    // Basic identification
    /// Token contract address
    pub token_address: String,
    /// Blockchain network
    pub chain: String,
    /// Token name (if available)
    pub token_name: Option<String>,
    /// Token symbol (if available)
    pub token_symbol: Option<String>,

    // Liquidity metrics
    /// Total liquidity in USD
    pub liquidity_usd: f64,
    /// Whether LP tokens are locked
    pub lp_locked: bool,
    /// Number of days LP is locked
    pub lp_lock_days: u32,
    /// Percentage of LP that is locked (0.0-1.0)
    pub lp_locked_percent: f32,

    // Contract security metrics
    /// Whether token is detected as honeypot
    pub is_honeypot: bool,
    /// Whether owner can mint new tokens
    pub owner_can_mint: bool,
    /// Whether owner can blacklist addresses
    pub owner_can_blacklist: bool,
    /// Whether there is a hidden owner
    pub hidden_owner: bool,
    /// Whether contract is a proxy
    pub is_proxy: bool,
    /// Whether contract has selfdestruct function
    pub selfdestruct: bool,
    /// Whether trading can be paused
    pub trade_can_be_paused: bool,
    /// Whether owner can take back ownership (Phase 0 Task 0.2)
    pub can_take_back_ownership: bool,
    /// Whether owner has personal privileges (Phase 0 Task 0.2)
    pub personal_privilege: bool,
    /// Whether contract makes external calls (Phase 0 Task 0.2)
    pub external_call: bool,
    /// Whether ownership is renounced (Phase 0 Task 0.2)
    pub owner_renounced: bool,
    /// Whether token is an airdrop scam (Phase 0 Task 0.2)
    pub is_airdrop_scam: bool,

    // Tax metrics
    /// Buy tax percentage (0-100)
    pub buy_tax: f32,
    /// Sell tax percentage (0-100)
    pub sell_tax: f32,

    // Holder metrics
    /// Number of token holders
    pub holder_count: u64,
    /// Percentage held by top 10 holders (0-100)
    pub top10_holders_percent: f32,
    /// Percentage held by dev wallet (0-100)
    pub dev_wallet_percent: f32,
    /// Whether ownership is renounced
    pub ownership_renounced: bool,
    /// Deployer wallet address (Phase 1 Task 1.3)
    pub deployer_address: Option<String>,
    /// Deployer wallet age in days (Phase 1 Task 1.3)
    pub deployer_wallet_age_days: Option<u32>,
    /// Contract deployment timestamp (Phase 1 Task 1.3)
    pub deploy_timestamp: Option<u64>,

    // Total supply (Phase 1 Task 1.5)
    /// Total token supply (human-readable, divided by 10^decimals)
    pub total_supply: Option<f64>,

    // Source code metrics (Phase 1 Task 1.4)
    /// Whether source code is verified
    pub source_verified: bool,
    /// Whether contract is a proxy
    pub source_is_proxy: bool,
    /// Implementation address (if proxy)
    pub source_implementation: Option<String>,
    /// Source code risk score (0-100)
    pub source_risk_score: u32,
    /// Source code risk flags
    pub source_risk_flags: Vec<String>,
    /// Contract name from source
    pub contract_name: Option<String>,
    /// Compiler version
    pub compiler_version: Option<String>,

    // Volume metrics
    /// 24-hour trading volume in USD
    pub volume_24h_usd: f64,
    /// Volume to liquidity ratio
    pub volume_to_lp_ratio: f32,
    /// Number of buy transactions in 24h
    pub buy_count_24h: u32,
    /// Number of sell transactions in 24h
    pub sell_count_24h: u32,

    // Age metrics
    /// Token age in minutes (None = unknown age, treat as high risk)
    pub token_age_minutes: Option<f64>,

    // Simulation metrics
    /// Effective sell tax from simulation (0.0-1.0)
    pub effective_sell_tax: f32,
    /// Whether selling is possible
    pub can_sell: bool,

    // Gas asymmetry metrics (Phase 1 Task 1.8)
    /// Gas used for buy transaction (from honeypot simulation)
    pub buy_gas: Option<u64>,
    /// Gas used for sell transaction (from honeypot simulation)
    pub sell_gas: Option<u64>,
    /// Gas asymmetry ratio (`sell_gas` / `buy_gas`). Values > 2.0 indicate potential honeypot
    pub gas_asymmetry_ratio: Option<f64>,
    /// Whether gas asymmetry is detected (ratio > threshold)
    pub gas_asymmetry_detected: bool,

    // Developer behavior metrics
    /// Ratio of tokens dumped by dev (0.0-1.0)
    pub dev_dump_ratio: f32,
    /// Number of snipers detected
    pub sniper_count: u32,
    /// Ratio of snipers in first block (0.0-1.0)
    pub sniper_ratio: f32,

    // Market metrics
    /// Market cap in USD (if available)
    pub market_cap_usd: Option<f64>,
    /// Current price in USD (if available)
    pub price_usd: Option<f64>,
    /// Price confidence score from `DefiLlama` (0.0-1.0) - Phase 1 Task 1.6 Sprint 3 INT-001
    pub price_confidence: Option<f64>,

    // Multi-pool metrics (Phase 1 Task 1.1)
    /// Total liquidity across all pools in USD
    pub total_liquidity_usd: f64,
    /// Primary (largest) pool liquidity in USD
    pub primary_pool_liquidity: f64,
    /// Number of trading pools
    pub pool_count: u32,
    /// Dominance ratio: largest pool / total (1.0 = all liq in one pool)
    pub dominance_ratio: f64,
    /// Top 3 pools liquidity ratio: sum(top3) / total
    pub top3_liquidity_ratio: f64,
    /// Liquidity to market cap ratio (rug risk signal)
    pub liquidity_ratio: f64,
    /// 24h volume in USD
    pub volume_24h: f64,
    /// 1h volume in USD
    pub volume_1h: f64,
    /// Buy count in 24h
    pub buys_24h: u32,
    /// Sell count in 24h
    pub sells_24h: u32,
    /// Buy Pressure Index (`buys` / `total_txns`)
    pub bpi: f64,
    /// Volume quality (`unique_traders` / `total_trades`) - Phase 1 Task 1.7
    pub volume_quality: f64,
    /// Number of unique traders - Phase 1 Task 1.7
    pub unique_traders: u32,
    /// Buy volume in USD - Phase 1 Task 1.7
    pub buy_volume_usd: f64,
    /// Sell volume in USD - Phase 1 Task 1.7
    pub sell_volume_usd: f64,
    /// Whether LP was removed by dev (approximation)
    pub lp_removed_by_dev: bool,
}

impl TokenMetrics {
    /// Create a new `TokenMetrics` instance with the given address and chain
    #[must_use]
    pub fn new(token_address: impl Into<String>, chain: impl Into<String>) -> Self {
        Self {
            token_address: token_address.into(),
            chain: chain.into(),
            ..Default::default()
        }
    }

    /// Convert to JSON Value for LLM analysis
    #[must_use]
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "token_address": self.token_address,
            "chain": self.chain,
            "token_name": self.token_name,
            "token_symbol": self.token_symbol,
            "liquidity_usd": self.liquidity_usd,
            "lp_locked": self.lp_locked,
            "lp_lock_days": self.lp_lock_days,
            "lp_locked_percent": self.lp_locked_percent,
            "is_honeypot": self.is_honeypot,
            "owner_can_mint": self.owner_can_mint,
            "owner_can_blacklist": self.owner_can_blacklist,
            "hidden_owner": self.hidden_owner,
            "is_proxy": self.is_proxy,
            "selfdestruct": self.selfdestruct,
            "trade_can_be_paused": self.trade_can_be_paused,
            "can_take_back_ownership": self.can_take_back_ownership,
            "personal_privilege": self.personal_privilege,
            "external_call": self.external_call,
            "owner_renounced": self.owner_renounced,
            "is_airdrop_scam": self.is_airdrop_scam,
            "buy_tax": self.buy_tax,
            "sell_tax": self.sell_tax,
            "holder_count": self.holder_count,
            "top10_holders_percent": self.top10_holders_percent,
            "dev_wallet_percent": self.dev_wallet_percent,
            "ownership_renounced": self.ownership_renounced,
            "deployer_address": self.deployer_address,
            "deployer_wallet_age_days": self.deployer_wallet_age_days,
            "deploy_timestamp": self.deploy_timestamp,
            "total_supply": self.total_supply,
            "source_verified": self.source_verified,
            "source_is_proxy": self.source_is_proxy,
            "source_implementation": self.source_implementation,
            "source_risk_score": self.source_risk_score,
            "source_risk_flags": self.source_risk_flags,
            "contract_name": self.contract_name,
            "compiler_version": self.compiler_version,
            "volume_24h_usd": self.volume_24h_usd,
            "volume_to_lp_ratio": self.volume_to_lp_ratio,
            "buy_count_24h": self.buy_count_24h,
            "sell_count_24h": self.sell_count_24h,
            "token_age_minutes": self.token_age_minutes,
            "effective_sell_tax": self.effective_sell_tax,
            "can_sell": self.can_sell,
            "buy_gas": self.buy_gas,
            "sell_gas": self.sell_gas,
            "gas_asymmetry_ratio": self.gas_asymmetry_ratio,
            "gas_asymmetry_detected": self.gas_asymmetry_detected,
            "dev_dump_ratio": self.dev_dump_ratio,
            "sniper_count": self.sniper_count,
            "sniper_ratio": self.sniper_ratio,
            "market_cap_usd": self.market_cap_usd,
            "price_usd": self.price_usd,
            "total_liquidity_usd": self.total_liquidity_usd,
            "primary_pool_liquidity": self.primary_pool_liquidity,
            "pool_count": self.pool_count,
            "dominance_ratio": self.dominance_ratio,
            "top3_liquidity_ratio": self.top3_liquidity_ratio,
            "liquidity_ratio": self.liquidity_ratio,
            "volume_24h": self.volume_24h,
            "volume_1h": self.volume_1h,
            "buys_24h": self.buys_24h,
            "sells_24h": self.sells_24h,
            "bpi": self.bpi,
            "volume_quality": self.volume_quality,
            "unique_traders": self.unique_traders,
            "buy_volume_usd": self.buy_volume_usd,
            "sell_volume_usd": self.sell_volume_usd,
            "lp_removed_by_dev": self.lp_removed_by_dev,
        })
    }
}

/// Extract features from a scan result
///
/// This function transforms raw API responses into structured `TokenMetrics`.
/// It gracefully handles missing data by using defaults and computing
/// derived fields where possible.
///
/// # Arguments
/// * `scan_result` - The comprehensive scan result from all API providers
///
/// # Returns
/// * `TokenMetrics` - Extracted features ready for TRI scoring and LLM analysis
#[must_use]
pub fn extract_features(scan_result: &ScanResult) -> TokenMetrics {
    let mut metrics = TokenMetrics::new(&scan_result.token_address, &scan_result.chain);

    // Extract from Dexscreener
    if let Some(ref dex) = scan_result.dexscreener {
        extract_dexscreener_features(dex, &mut metrics);
    }

    // Extract from Honeypot.is
    if let Some(ref hp) = scan_result.honeypot {
        extract_honeypot_features(hp, &mut metrics);
    }

    // Extract from GoPlus
    if let Some(ref gp) = scan_result.goplus {
        extract_goplus_features(gp, &mut metrics);
    }

    // Extract from Etherscan
    if let Some(ref es) = scan_result.etherscan {
        extract_etherscan_features(es, &mut metrics);
    }

    // Bitquery removed (402 Payment Required) - no longer extracting features

    // Extract from Moralis (Phase 1 Task 1.2)
    if let Some(ref holders) = scan_result.moralis_holders {
        extract_moralis_features(holders, &mut metrics);
    }

    // Extract from Deployer Profile (Phase 1 Task 1.3)
    // Primary source: deployer_profile from Etherscan/DeployerClient
    // Fallback: Ethplorer contractInfo (creatorAddress and creationTimestamp)
    if let Some(ref profile) = scan_result.deployer_profile {
        extract_deployer_features(profile, &mut metrics);
    } else if let Some(ref eth) = scan_result.ethplorer {
        // Fallback to Ethplorer contractInfo when deployer fetch fails
        if let Some(ref contract_info) = eth.contract_info {
            tracing::warn!(
                "Deployer profile fetch failed, using Ethplorer fallback for {}",
                scan_result.token_address
            );
            metrics.deployer_address = Some(contract_info.creator_address.clone());
            metrics.deploy_timestamp = Some(contract_info.creation_timestamp);
            // Note: wallet_age_days cannot be calculated from Ethplorer alone
            // It only provides creation timestamp, not first transaction
        }
    }

    // Extract from Source Code (Phase 1 Task 1.4)
    if let Some(ref source) = scan_result.source_code {
        extract_source_features(source, &mut metrics);
    }

    // Extract total supply (Phase 1 Task 1.5)
    // Priority order: Etherscan → Ethplorer → Blockscout
    // Etherscan provides f64 directly
    if let Some(supply) = scan_result.total_supply {
        metrics.total_supply = Some(supply);
    }
    // Fallback to Ethplorer (total_supply is a string that needs parsing)
    else if let Some(ref eth) = scan_result.ethplorer
        && !eth.total_supply.is_empty()
        && let Ok(supply_val) = eth.total_supply.parse::<f64>()
    {
        metrics.total_supply = Some(supply_val);
    }
    // Fallback to Blockscout (total_supply is a string that needs parsing)
    else if let Some(ref block) = scan_result.blockscout
        && !block.total_supply.is_empty()
        && let Ok(supply_val) = block.total_supply.parse::<f64>()
    {
        metrics.total_supply = Some(supply_val);
    }

    // Extract DefiLlama price with confidence score (Phase 1 Task 1.6 - Sprint 3 INT-001)
    // DefiLlama provides price confidence (0.0-1.0) which is valuable for TRI scoring
    if let Some(ref price) = scan_result.defillama_price {
        metrics.price_usd = Some(price.price);
        metrics.price_confidence = Some(price.confidence);
    }

    // Extract The Graph analytics (Sprint 3 INT-002)
    // The Graph provides volume_quality and unique_traders data
    if let Some(ref graph) = scan_result.graph_analytics {
        // Map volume_quality from The Graph (more accurate than Dexscreener fallback)
        if graph.volume_quality > 0.0 {
            metrics.volume_quality = graph.volume_quality;
        }
        // Map unique traders
        if let Some(traders) = graph.unique_traders_24h {
            metrics.unique_traders = traders;
        }
        // Map buy/sell volume
        if graph.buy_volume_usd > 0.0 {
            metrics.buy_volume_usd = graph.buy_volume_usd;
        }
        if graph.sell_volume_usd > 0.0 {
            metrics.sell_volume_usd = graph.sell_volume_usd;
        }
        // Map BPI (Buy Pressure Index)
        if graph.bpi > 0.0 {
            metrics.bpi = graph.bpi;
        }
    }

    // Compute derived fields
    compute_derived_fields(&mut metrics);

    metrics
}

/// Extract features from Dexscreener data
fn extract_dexscreener_features(dex: &DexTokenData, metrics: &mut TokenMetrics) {
    use std::time::{SystemTime, UNIX_EPOCH};

    metrics.token_name.clone_from(&dex.name);
    metrics.token_symbol.clone_from(&dex.symbol);
    metrics.liquidity_usd = dex.liquidity_usd;
    metrics.price_usd = Some(dex.price_usd);
    metrics.volume_24h_usd = dex.volume_24h;

    // Phase 0 Task 0.3: Calculate token age from pair_created_at (milliseconds)
    if let Some(created_at_ms) = dex.pair_created_at {
        #[allow(clippy::cast_possible_truncation)]
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if now_ms > created_at_ms {
            let age_ms = now_ms - created_at_ms;
            #[allow(clippy::cast_precision_loss)]
            {
                metrics.token_age_minutes = Some(age_ms as f64 / 60_000.0);
            }
        }
    }
    // If pair_created_at is None, leave token_age_minutes as None
    // The AgeRisk formula will handle None as a high-risk signal (unknown age)

    // Phase 1 Task 1.1: Multi-pool aggregated data
    metrics.total_liquidity_usd = dex.total_liquidity_usd;
    metrics.primary_pool_liquidity = dex.primary_pool_liquidity;
    metrics.pool_count = dex.pair_count;
    metrics.dominance_ratio = dex.dominance_ratio;
    metrics.top3_liquidity_ratio = dex.top3_liquidity_ratio;
    metrics.volume_24h = dex.volume_24h;
    metrics.volume_1h = dex.volume_h1;
    metrics.buys_24h = dex.buys_24h;
    metrics.sells_24h = dex.sells_24h;
    metrics.market_cap_usd = dex.market_cap;

    // Extract transaction counts if available
    // Note: DexTokenData doesn't have txns field directly, would need Pair data
}

/// Extract features from Honeypot.is data
fn extract_honeypot_features(hp: &HoneypotResult, metrics: &mut TokenMetrics) {
    metrics.is_honeypot = hp.is_honeypot;
    metrics.buy_tax = hp.buy_tax;
    metrics.sell_tax = hp.sell_tax;
    metrics.can_sell = hp.can_sell;

    // Extract effective sell tax from simulation
    if let Some(ref sim) = hp.simulation
        && let (Some(buy), Some(sell)) = (&sim.buy_output, &sim.sell_output)
    {
        // Parse and compute effective tax
        #[allow(clippy::cast_possible_truncation)]
        if let (Ok(buy_amt), Ok(sell_amt)) = (buy.parse::<f64>(), sell.parse::<f64>())
            && buy_amt > 0.0
        {
            metrics.effective_sell_tax = ((buy_amt - sell_amt) / buy_amt) as f32;
        }
    }

    // Phase 1 Task 1.8: Extract gas asymmetry data from simulation
    if let Some(ref sim) = hp.simulation {
        metrics.buy_gas = sim.buy_gas;
        metrics.sell_gas = sim.sell_gas;

        // Compute gas asymmetry ratio if both gas values are available
        if let (Some(buy_gas), Some(sell_gas)) = (sim.buy_gas, sim.sell_gas)
            && buy_gas > 0
        {
            #[allow(clippy::cast_precision_loss)]
            {
                let ratio = sell_gas as f64 / buy_gas as f64;
                metrics.gas_asymmetry_ratio = Some(ratio);
                // Phase 1 Task 1.8: Threshold is 2.0 (not 1.12 to avoid false positives)
                metrics.gas_asymmetry_detected = ratio > 2.0;
            }
        }
    }
}

/// Extract features from `GoPlus` data
fn extract_goplus_features(gp: &ContractRisk, metrics: &mut TokenMetrics) {
    metrics.owner_can_mint = gp.owner_can_mint;
    metrics.owner_can_blacklist = gp.owner_can_blacklist;
    metrics.hidden_owner = gp.hidden_owner;
    metrics.is_proxy = gp.is_proxy;
    metrics.selfdestruct = gp.selfdestruct;
    metrics.trade_can_be_paused = !gp.trade_cannot_be_paused;
    metrics.lp_locked = gp.lp_locked;

    // Phase 0 Task 0.2: Map additional GoPlus fields that were previously hardcoded as false
    metrics.personal_privilege = gp.personal_privilege;
    // external_call is now a string "0" or "1" from GoPlus API
    metrics.external_call = gp.external_call_detected();
    metrics.can_take_back_ownership = gp.can_be_upgraded;
    metrics.is_airdrop_scam = false; // GoPlus doesn't provide this field directly

    // Check for ownership renounced (owner_address being zero address or dead address)
    // Phase 0 Task 0.2: owner_renounced mapped from GoPlus owner_address
    if let Some(ref owner) = gp.owner_address {
        let owner_lower = owner.to_lowercase();
        metrics.owner_renounced = owner_lower == "0x000000000000000000000000000000000000dead"
            || owner_lower == "0x0000000000000000000000000000000000000000"
            || owner_lower.is_empty();
        // Also set ownership_renounced for backward compatibility
        metrics.ownership_renounced = metrics.owner_renounced;
    }

    if let Some(count) = gp.holder_count {
        metrics.holder_count = count;
    }

    // Estimate dev wallet percent from deployer balance
    // This is a rough estimate - would need total supply for accurate calculation
    #[allow(clippy::cast_possible_truncation)]
    if let Some(ref deployer_balance) = gp.deployer_balance
        && let Ok(balance) = deployer_balance.parse::<f64>()
    {
        // Rough estimate: assume deployer holds significant portion
        metrics.dev_wallet_percent = (balance / 1_000_000_000.0 * 100.0).min(100.0) as f32;
    }
}

/// Extract features from Etherscan data
fn extract_etherscan_features(es: &crate::api::ContractMetadata, metrics: &mut TokenMetrics) {
    // Etherscan provides contract verification and metadata
    // Holder count if available
    if es.holder_count > 0 && metrics.holder_count == 0 {
        metrics.holder_count = es.holder_count;
    }

    // Token name from contract
    if metrics.token_name.is_none() && !es.contract_name.is_empty() {
        metrics.token_name = Some(es.contract_name.clone());
    }
}



/// Extract features from Moralis holder data (Phase 1 Task 1.2)
fn extract_moralis_features(holders: &HolderAnalysis, metrics: &mut TokenMetrics) {
    // Set top10_holders_percent from real Moralis data (convert f64 to f32)
    #[allow(clippy::cast_possible_truncation)]
    {
        metrics.top10_holders_percent = holders.top10_holders_pct as f32;
    }

    // Set dev_wallet_percent if deployer detected in top holders (convert f64 to f32)
    if let Some(dev_pct) = holders.dev_wallet_pct {
        #[allow(clippy::cast_possible_truncation)]
        {
            metrics.dev_wallet_percent = dev_pct as f32;
        }
    }

    // Note: labeled_holders, unlabeled_whale_count, and contract_holder_pct
    // are available in holders but not yet mapped to TokenMetrics fields
    // They can be used for future risk analysis enhancements
}

/// Extract features from deployer profile (Phase 1 Task 1.3)
fn extract_deployer_features(profile: &crate::api::EtherscanDeployerProfile, metrics: &mut TokenMetrics) {
    metrics.deployer_address = Some(profile.address.clone());
    metrics.deployer_wallet_age_days = Some(profile.wallet_age_days);
    metrics.deploy_timestamp = Some(profile.deploy_timestamp);
}

/// Extract features from source code verification (Phase 1 Task 1.4)
fn extract_source_features(source: &crate::api::SourceCodeResult, metrics: &mut TokenMetrics) {
    use crate::scanner::source_analyzer::analyze_source;

    metrics.source_verified = source.source_code.is_some() && !source.source_code.as_ref().unwrap().is_empty();
    metrics.source_is_proxy = source.proxy.as_deref().unwrap_or("0") == "1";
    metrics.source_implementation = source.implementation.clone().filter(|s| !s.is_empty());
    metrics.contract_name.clone_from(&source.contract_name);
    metrics.compiler_version.clone_from(&source.compiler_version);

    // Analyze source code for dangerous patterns
    let source_risk = analyze_source(source.source_code.as_deref());
    metrics.source_risk_score = source_risk.risk_score;
    metrics.source_risk_flags = source_risk.flags.iter().map(|f| f.as_str().to_string()).collect();
}

/// Compute derived fields from extracted data
fn compute_derived_fields(metrics: &mut TokenMetrics) {
    // LP locked percent (simplified - assumes fully locked or not)
    metrics.lp_locked_percent = if metrics.lp_locked { 1.0 } else { 0.0 };

    // Volume to LP ratio
    #[allow(clippy::cast_possible_truncation)]
    if metrics.liquidity_usd > 0.0 {
        metrics.volume_to_lp_ratio = (metrics.volume_24h_usd / metrics.liquidity_usd) as f32;
    }

    // Phase 1 Task 1.1: Liquidity / Market Cap ratio — rug risk signal
    if let Some(market_cap) = metrics.market_cap_usd
        && market_cap > 0.0
    {
        metrics.liquidity_ratio = metrics.total_liquidity_usd / market_cap;
    }
    // < 2%: extreme rug risk | < 5%: elevated | 5–20%: healthy

    // Phase 1 Task 1.1: Buy Pressure Index from Dexscreener txn counts
    // Only use Dexscreener fallback if Bitquery didn't provide BPI (Phase 1 Task 1.7)
    #[allow(clippy::cast_lossless)]
    if metrics.bpi <= 0.0 {
        // Bitquery not configured or failed - use Dexscreener estimate
        let total_txns = (metrics.buys_24h + metrics.sells_24h) as f64;
        if total_txns > 0.0 {
            metrics.bpi = metrics.buys_24h as f64 / total_txns;
        }
    }

    // Phase 1 Task 1.7: Volume quality fallback
    // VolumeQuality cannot be estimated from Dexscreener alone
    // If Bitquery didn't provide it, use neutral value
    if metrics.volume_quality <= 0.0 {
        metrics.volume_quality = 0.5; // neutral — unknown
    }

    // Phase 1 Task 1.1: LP removed by dev approximation
    // If primary pool dominates (>95%) AND total liq is low (<$10k) AND sells >> buys, flag it
    metrics.lp_removed_by_dev = metrics.dominance_ratio > 0.95
        && metrics.total_liquidity_usd < 10_000.0
        && metrics.sells_24h > metrics.buys_24h * 3;

    // Top 10 holders percent (placeholder - would need detailed holder data)
    // For now, estimate based on holder count (fewer holders = higher concentration)
    if metrics.holder_count > 0 {
        if metrics.holder_count < 100 {
            metrics.top10_holders_percent = 80.0;
        } else if metrics.holder_count < 500 {
            metrics.top10_holders_percent = 60.0;
        } else if metrics.holder_count < 1000 {
            metrics.top10_holders_percent = 40.0;
        } else {
            metrics.top10_holders_percent = 25.0;
        }
    } else {
        // Default for 0 holders (unknown holder count)
        metrics.top10_holders_percent = 25.0;
    }

    // Token age is now populated from Dexscreener pair_created_at (Phase 0 Task 0.3)
    // No default needed - None indicates unknown age (handled by AgeRisk formula)
}

/// Extract features directly from individual API responses
///
/// This is a convenience function for when you have individual API responses
/// rather than a unified `ScanResult`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn extract_features_from_parts(
    token_address: &str,
    chain: &str,
    dex: Option<&DexTokenData>,
    honeypot: Option<&HoneypotResult>,
    goplus: Option<&ContractRisk>,
    etherscan: Option<&crate::api::ContractMetadata>,
) -> TokenMetrics {
    let mut metrics = TokenMetrics::new(token_address, chain);

    if let Some(d) = dex {
        extract_dexscreener_features(d, &mut metrics);
    }

    if let Some(h) = honeypot {
        extract_honeypot_features(h, &mut metrics);
    }

    if let Some(g) = goplus {
        extract_goplus_features(g, &mut metrics);
    }

    if let Some(e) = etherscan {
        extract_etherscan_features(e, &mut metrics);
    }

    compute_derived_fields(&mut metrics);

    metrics
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ApiResult, ScanResult, TimingBreakdown};
    use crate::models::TokenData;

    fn create_test_scan_result() -> ScanResult {
        ScanResult {
            token_address: "0x1234567890123456789012345678901234567890".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 1000,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: Some(DexTokenData {
                address: "0x1234567890123456789012345678901234567890".to_string(),
                name: Some("TestToken".to_string()),
                symbol: Some("TST".to_string()),
                price_usd: 0.001,
                liquidity_usd: 100_000.0,
                volume_24h: 50_000.0,
                pair_count: 2,
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
                pair_created_at: None, // Test without age data
                unique_traders_24h: Some(190),
                trading_activity_score: Some(75),
            }),
            honeypot: Some(HoneypotResult {
                token_address: "0x1234567890123456789012345678901234567890".to_string(),
                chain: "ethereum".to_string(),
                is_honeypot: false,
                buy_tax: 3.0,
                sell_tax: 3.0,
                can_buy: true,
                can_sell: true,
                error: None,
                simulation: None,
            }),
            goplus: Some(ContractRisk {
                token_address: "0x1234567890123456789012345678901234567890".to_string(),
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
                owner_address: None,
                creator_address: None,
                deployer_balance: None,
                holder_count: Some(1000),
                external_call: None,
                risk_flags: Vec::new(),
            }),
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        }
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_token_metrics_default() {
        let metrics = TokenMetrics::default();
        assert_eq!(metrics.token_address, "");
        assert_eq!(metrics.chain, "");
        assert!(!metrics.is_honeypot);
        assert_eq!(metrics.liquidity_usd, 0.0);
    }

    #[test]
    fn test_token_metrics_new() {
        let metrics = TokenMetrics::new("0x1234", "ethereum");
        assert_eq!(metrics.token_address, "0x1234");
        assert_eq!(metrics.chain, "ethereum");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_extract_features_basic() {
        let scan_result = create_test_scan_result();
        let metrics = extract_features(&scan_result);

        assert_eq!(metrics.token_address, "0x1234567890123456789012345678901234567890");
        assert_eq!(metrics.chain, "ethereum");
        assert_eq!(metrics.token_name, Some("TestToken".to_string()));
        assert_eq!(metrics.token_symbol, Some("TST".to_string()));
        assert_eq!(metrics.liquidity_usd, 100_000.0);
        assert_eq!(metrics.buy_tax, 3.0);
        assert_eq!(metrics.sell_tax, 3.0);
        assert!(!metrics.is_honeypot);
        assert!(!metrics.owner_can_mint);
        assert!(metrics.lp_locked);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_extract_features_with_honeypot() {
        let mut scan_result = create_test_scan_result();
        if let Some(ref mut hp) = scan_result.honeypot {
            hp.is_honeypot = true;
            hp.can_sell = false;
            hp.sell_tax = 99.0;
        }
        let metrics = extract_features(&scan_result);

        assert!(metrics.is_honeypot);
        assert!(!metrics.can_sell);
        assert_eq!(metrics.sell_tax, 99.0);
    }

    #[test]
    fn test_extract_features_with_risky_contract() {
        let mut scan_result = create_test_scan_result();
        if let Some(ref mut gp) = scan_result.goplus {
            gp.owner_can_mint = true;
            gp.hidden_owner = true;
            gp.selfdestruct = true;
        }
        let metrics = extract_features(&scan_result);

        assert!(metrics.owner_can_mint);
        assert!(metrics.hidden_owner);
        assert!(metrics.selfdestruct);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_derived_fields() {
        let mut metrics = TokenMetrics::new("0x1234", "ethereum");
        metrics.liquidity_usd = 100_000.0;
        metrics.volume_24h_usd = 50_000.0;
        metrics.lp_locked = true;
        metrics.holder_count = 500;

        compute_derived_fields(&mut metrics);

        assert_eq!(metrics.lp_locked_percent, 1.0);
        assert!((metrics.volume_to_lp_ratio - 0.5).abs() < 0.01);
        // holder_count = 500 falls in 500-1000 range -> 40%
        assert_eq!(metrics.top10_holders_percent, 40.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_extract_features_from_parts() {
        let dex = DexTokenData {
            address: "0x1234".to_string(),
            name: Some("Test".to_string()),
            symbol: Some("TST".to_string()),
            price_usd: 0.01,
            liquidity_usd: 50_000.0,
            volume_24h: 25_000.0,
            pair_count: 1,
            total_liquidity_usd: 50_000.0,
            primary_pool_liquidity: 50_000.0,
            dominance_ratio: 1.0,
            top3_liquidity_ratio: 1.0,
            volume_h1: 5_000.0,
            buys_24h: 50,
            sells_24h: 45,
            market_cap: Some(500_000.0),
            fdv: Some(500_000.0),
            chain_id: Some("ethereum".to_string()),
            pair_created_at: None,
            unique_traders_24h: Some(95),
            trading_activity_score: Some(60),
        };

        let metrics = extract_features_from_parts(
            "0x1234",
            "ethereum",
            Some(&dex),
            None,
            None,
            None,
        );

        assert_eq!(metrics.token_name, Some("Test".to_string()));
        assert_eq!(metrics.liquidity_usd, 50_000.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_to_json_value() {
        let metrics = TokenMetrics {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            liquidity_usd: 100_000.0,
            is_honeypot: false,
            buy_tax: 3.0,
            sell_tax: 3.0,
            ..Default::default()
        };

        let json = metrics.to_json_value();
        assert_eq!(json["token_address"], "0x1234");
        assert_eq!(json["chain"], "ethereum");
        assert_eq!(json["liquidity_usd"], 100_000.0);
        assert_eq!(json["is_honeypot"], false);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_extract_features_empty_result() {
        let scan_result = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };

        let metrics = extract_features(&scan_result);

        // Should have defaults
        assert_eq!(metrics.token_address, "0x1234");
        assert_eq!(metrics.chain, "ethereum");
        assert_eq!(metrics.liquidity_usd, 0.0);
        assert_eq!(metrics.token_age_minutes, None); // No default - unknown age is None
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_holder_count_to_top10_estimate() {
        // Test different holder count scenarios
        let test_cases = vec![
            (50, 80.0),
            (300, 60.0),
            (750, 40.0),
            (2000, 25.0),
        ];

        for (holder_count, expected_top10) in test_cases {
            let mut metrics = TokenMetrics::default();
            metrics.holder_count = holder_count;
            compute_derived_fields(&mut metrics);
            assert_eq!(metrics.top10_holders_percent, expected_top10);
        }
    }

    // =========================================================================
    // Phase 6: Integration Testing - Feature Extraction Completeness
    // =========================================================================

    // =========================================================================
    // Phase 0 Task 0.2: GoPlus Fields Mapping Tests
    // =========================================================================

    #[test]
    fn test_extract_goplus_features_personal_privilege() {
        // Test that personal_privilege is correctly mapped from GoPlus
        let mut gp = ContractRisk {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            personal_privilege: true,
            ..Default::default()
        };
        let mut metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(metrics.personal_privilege);

        // Test false case
        gp.personal_privilege = false;
        metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(!metrics.personal_privilege);
    }

    #[test]
    fn test_extract_goplus_features_external_call() {
        // Test that external_call is correctly mapped from GoPlus
        // GoPlus returns external_call as string "0" (no) or "1" (yes)

        // Test "1" case (has external call)
        let mut gp = ContractRisk {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            external_call: Some("1".to_string()),
            ..Default::default()
        };
        let mut metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(metrics.external_call);

        // Test "0" case (no external call)
        gp.external_call = Some("0".to_string());
        metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(!metrics.external_call);

        // Test "true" case (case insensitive)
        gp.external_call = Some("true".to_string());
        metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(metrics.external_call);

        // Test "TRUE" case (case insensitive)
        gp.external_call = Some("TRUE".to_string());
        metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(metrics.external_call);

        // Test None case
        gp.external_call = None;
        metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(!metrics.external_call);
    }

    #[test]
    fn test_extract_goplus_features_owner_renounced() {
        // Test that owner_renounced is correctly mapped from GoPlus owner_address
        let mut gp = ContractRisk {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            owner_address: Some("0x0000000000000000000000000000000000000000".to_string()),
            ..Default::default()
        };
        let mut metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(metrics.owner_renounced);
        assert!(metrics.ownership_renounced);

        // Test dead address
        gp.owner_address = Some("0x000000000000000000000000000000000000dead".to_string());
        metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(metrics.owner_renounced);
        assert!(metrics.ownership_renounced);

        // Test empty address
        gp.owner_address = Some(String::new());
        metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(metrics.owner_renounced);

        // Test non-renounced (valid owner address)
        gp.owner_address = Some("0x1234567890123456789012345678901234567890".to_string());
        metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(!metrics.owner_renounced);
        assert!(!metrics.ownership_renounced);

        // Test None (no owner address info)
        gp.owner_address = None;
        metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(!metrics.owner_renounced);
        assert!(!metrics.ownership_renounced);
    }

    #[test]
    fn test_extract_goplus_features_can_take_back_ownership() {
        // Test that can_take_back_ownership is correctly mapped from GoPlus can_be_upgraded
        let mut gp = ContractRisk {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            can_be_upgraded: true,
            ..Default::default()
        };
        let mut metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(metrics.can_take_back_ownership);

        // Test false case
        gp.can_be_upgraded = false;
        metrics = TokenMetrics::default();
        extract_goplus_features(&gp, &mut metrics);
        assert!(!metrics.can_take_back_ownership);
    }

    #[test]
    fn test_extract_goplus_features_comprehensive() {
        // Test comprehensive GoPlus feature extraction with all fields
        // GoPlus returns external_call as string "0" or "1"

        let gp = ContractRisk {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            owner_can_mint: true,
            owner_can_blacklist: true,
            hidden_owner: true,
            is_proxy: true,
            selfdestruct: true,
            trade_cannot_be_paused: true, // trade_can_be_paused = !trade_cannot_be_paused, so this means false
            lp_locked: true,
            personal_privilege: true,
            external_call: Some("1".to_string()), // "1" means has external call
            can_be_upgraded: true,
            owner_address: Some("0x0000000000000000000000000000000000000000".to_string()),
            creator_address: Some("0xcreator".to_string()),
            deployer_balance: Some("1000000".to_string()),
            holder_count: Some(500),
            anti_whale_modifiable: false,
            risk_flags: vec!["high_risk".to_string()],
        };

        let metrics = extract_features_from_parts(
            "0x1234",
            "ethereum",
            None,
            None,
            Some(&gp),
            None,
        );

        // Verify all GoPlus fields are correctly mapped
        assert!(metrics.owner_can_mint);
        assert!(metrics.owner_can_blacklist);
        assert!(metrics.hidden_owner);
        assert!(metrics.is_proxy);
        assert!(metrics.selfdestruct);
        assert!(!metrics.trade_can_be_paused); // trade_cannot_be_paused=true means trade_can_be_paused=false
        assert!(metrics.lp_locked);
        assert!(metrics.personal_privilege);
        assert!(metrics.external_call); // "1" should map to true
        assert!(metrics.can_take_back_ownership);
        assert!(metrics.owner_renounced);
        assert!(metrics.ownership_renounced);
        assert_eq!(metrics.holder_count, 500);
    }

    #[test]
    fn test_to_json_value_includes_goplus_fields() {
        // Verify that to_json_value() includes all new GoPlus fields
        let metrics = TokenMetrics {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            personal_privilege: true,
            external_call: true,
            owner_renounced: false,
            can_take_back_ownership: true,
            is_airdrop_scam: false,
            ..Default::default()
        };

        let json = metrics.to_json_value();
        assert_eq!(json["personal_privilege"], true);
        assert_eq!(json["external_call"], true);
        assert_eq!(json["owner_renounced"], false);
        assert_eq!(json["can_take_back_ownership"], true);
        assert_eq!(json["is_airdrop_scam"], false);
    }

    // =========================================================================
    // Phase 0 Task 0.3: Token Age from Dexscreener pair_created_at Tests
    // =========================================================================

    #[test]
    fn test_extract_dexscreener_features_token_age_from_pair_created_at() {
        // Test that token age is correctly calculated from pair_created_at
        let dex = DexTokenData {
            address: "0x1234".to_string(),
            name: Some("Test".to_string()),
            symbol: Some("TST".to_string()),
            price_usd: 0.01,
            liquidity_usd: 50_000.0,
            volume_24h: 25_000.0,
            pair_count: 1,
            total_liquidity_usd: 50_000.0,
            primary_pool_liquidity: 50_000.0,
            dominance_ratio: 1.0,
            top3_liquidity_ratio: 1.0,
            volume_h1: 5_000.0,
            buys_24h: 50,
            sells_24h: 45,
            market_cap: Some(500_000.0),
            fdv: Some(500_000.0),
            chain_id: Some("ethereum".to_string()),
            // Set pair_created_at to 60 minutes ago (in milliseconds)
            #[allow(clippy::cast_possible_truncation)]
            pair_created_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64
                    - 60 * 60_000, // 60 minutes ago
            ),
            unique_traders_24h: Some(95),
            trading_activity_score: Some(60),
        };

        let mut metrics = TokenMetrics::default();
        extract_dexscreener_features(&dex, &mut metrics);

        // Token age should be approximately 60 minutes
        assert!(metrics.token_age_minutes.is_some());
        let age = metrics.token_age_minutes.unwrap();
        assert!((59.0..=61.0).contains(&age), "Expected age ~60 minutes, got {age}");
    }

    #[test]
    fn test_extract_dexscreener_features_token_age_none_when_missing() {
        // Test that token age is None when pair_created_at is not provided
        let dex = DexTokenData {
            address: "0x1234".to_string(),
            name: Some("Test".to_string()),
            symbol: Some("TST".to_string()),
            price_usd: 0.01,
            liquidity_usd: 50_000.0,
            volume_24h: 25_000.0,
            pair_count: 1,
            total_liquidity_usd: 50_000.0,
            primary_pool_liquidity: 50_000.0,
            dominance_ratio: 1.0,
            top3_liquidity_ratio: 1.0,
            volume_h1: 5_000.0,
            buys_24h: 50,
            sells_24h: 45,
            market_cap: Some(500_000.0),
            fdv: Some(500_000.0),
            chain_id: Some("ethereum".to_string()),
            pair_created_at: None,
            unique_traders_24h: Some(95),
            trading_activity_score: Some(60),
        };

        let mut metrics = TokenMetrics::default();
        extract_dexscreener_features(&dex, &mut metrics);

        // Token age should be None (unknown)
        assert!(metrics.token_age_minutes.is_none());
    }

    #[test]
    fn test_extract_dexscreener_features_token_age_very_new_token() {
        // Test token age for a very new token (1 minute old)
        let dex = DexTokenData {
            address: "0x1234".to_string(),
            name: Some("Test".to_string()),
            symbol: Some("TST".to_string()),
            price_usd: 0.01,
            liquidity_usd: 50_000.0,
            volume_24h: 25_000.0,
            pair_count: 1,
            total_liquidity_usd: 50_000.0,
            primary_pool_liquidity: 50_000.0,
            dominance_ratio: 1.0,
            top3_liquidity_ratio: 1.0,
            volume_h1: 5_000.0,
            buys_24h: 50,
            sells_24h: 45,
            market_cap: Some(500_000.0),
            fdv: Some(500_000.0),
            chain_id: Some("ethereum".to_string()),
            #[allow(clippy::cast_possible_truncation)]
            pair_created_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64
                    - 60_000, // 1 minute ago
            ),
            unique_traders_24h: Some(95),
            trading_activity_score: Some(60),
        };

        let mut metrics = TokenMetrics::default();
        extract_dexscreener_features(&dex, &mut metrics);

        // Token age should be approximately 1 minute
        assert!(metrics.token_age_minutes.is_some());
        let age = metrics.token_age_minutes.unwrap();
        assert!((0.5..=2.0).contains(&age), "Expected age ~1 minute, got {age}");
    }

    #[test]
    fn test_extract_dexscreener_features_token_age_old_token() {
        // Test token age for an old token (30 days old)
        let dex = DexTokenData {
            address: "0x1234".to_string(),
            name: Some("Test".to_string()),
            symbol: Some("TST".to_string()),
            price_usd: 0.01,
            liquidity_usd: 50_000.0,
            volume_24h: 25_000.0,
            pair_count: 1,
            total_liquidity_usd: 50_000.0,
            primary_pool_liquidity: 50_000.0,
            dominance_ratio: 1.0,
            top3_liquidity_ratio: 1.0,
            volume_h1: 5_000.0,
            buys_24h: 50,
            sells_24h: 45,
            market_cap: Some(500_000.0),
            fdv: Some(500_000.0),
            chain_id: Some("ethereum".to_string()),
            #[allow(clippy::cast_possible_truncation)]
            pair_created_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64
                    - 30 * 24 * 60 * 60_000, // 30 days ago
            ),
            unique_traders_24h: Some(95),
            trading_activity_score: Some(60),
        };

        let mut metrics = TokenMetrics::default();
        extract_dexscreener_features(&dex, &mut metrics);

        // Token age should be approximately 30 days = 43200 minutes
        assert!(metrics.token_age_minutes.is_some());
        let age = metrics.token_age_minutes.unwrap();
        assert!((43_000.0..=44_000.0).contains(&age), "Expected age ~43200 minutes, got {age}");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_extract_features_graceful_degradation_all_none() {
        // Verify that extract_features() correctly handles missing optional API responses
        let scan = ScanResult {
            token_address: "0x1234567890123456789012345678901234567890".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        // Should not panic, should return sane defaults
        assert_eq!(metrics.token_address, "0x1234567890123456789012345678901234567890");
        assert_eq!(metrics.chain, "ethereum");
        assert_eq!(metrics.liquidity_usd, 0.0);
        assert_eq!(metrics.token_age_minutes, None); // No default - unknown age is None
        assert!(!metrics.is_honeypot);
        assert!(!metrics.can_sell); // Default to false (derive Default)
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_extract_features_only_dexscreener() {
        // Test with only DexScreener data available
        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: Some(DexTokenData {
                address: "0x1234".to_string(),
                name: Some("Test".to_string()),
                symbol: Some("TST".to_string()),
                price_usd: 0.01,
                liquidity_usd: 50_000.0,
                volume_24h: 25_000.0,
                pair_count: 1,
            total_liquidity_usd: 50_000.0,
            primary_pool_liquidity: 50_000.0,
            dominance_ratio: 1.0,
            top3_liquidity_ratio: 1.0,
            volume_h1: 5_000.0,
            buys_24h: 50,
            sells_24h: 45,
            market_cap: Some(500_000.0),
            fdv: Some(500_000.0),
                chain_id: Some("ethereum".to_string()),
                pair_created_at: None,
                unique_traders_24h: Some(95),
                trading_activity_score: Some(60),
            }),
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        // Should have DexScreener data
        assert_eq!(metrics.token_name, Some("Test".to_string()));
        assert_eq!(metrics.token_symbol, Some("TST".to_string()));
        assert_eq!(metrics.liquidity_usd, 50_000.0);
        assert_eq!(metrics.price_usd, Some(0.01));
        assert_eq!(metrics.volume_24h_usd, 25_000.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_extract_features_only_honeypot() {
        // Test with only Honeypot.is data available
        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: Some(HoneypotResult {
                token_address: "0x1234".to_string(),
                chain: "ethereum".to_string(),
                is_honeypot: true,
                buy_tax: 10.0,
                sell_tax: 50.0,
                can_buy: true,
                can_sell: false,
                error: None,
                simulation: None,
            }),
            goplus: None,
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        // Should have Honeypot data
        assert!(metrics.is_honeypot);
        assert_eq!(metrics.buy_tax, 10.0);
        assert_eq!(metrics.sell_tax, 50.0);
        assert!(!metrics.can_sell);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_extract_features_only_goplus() {
        // Test with only GoPlus data available
        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: Some(ContractRisk {
                token_address: "0x1234".to_string(),
                chain: "ethereum".to_string(),
                owner_can_mint: true,
                owner_can_blacklist: false,
                lp_locked: false,
                hidden_owner: true,
                selfdestruct: false,
                is_proxy: false,
                can_be_upgraded: false,
                trade_cannot_be_paused: true,
                anti_whale_modifiable: false,
                personal_privilege: false,
                owner_address: None,
                creator_address: None,
                deployer_balance: None,
                holder_count: Some(500),
                external_call: None,
                risk_flags: Vec::new(),
            }),
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        // Should have GoPlus data
        assert!(metrics.owner_can_mint);
        assert!(!metrics.owner_can_blacklist);
        assert!(!metrics.lp_locked);
        assert!(metrics.hidden_owner);
        assert_eq!(metrics.holder_count, 500);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_extract_features_from_parts_all_none() {
        // Test extract_features_from_parts with all None inputs
        let metrics = extract_features_from_parts(
            "0x1234",
            "ethereum",
            None,
            None,
            None,
            None,
        );

        // Should not panic, should have defaults
        assert_eq!(metrics.token_address, "0x1234");
        assert_eq!(metrics.chain, "ethereum");
        assert_eq!(metrics.liquidity_usd, 0.0);
        assert_eq!(metrics.token_age_minutes, None); // No default - unknown age is None
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_derived_fields_defaults() {
        // Test that compute_derived_fields sets proper defaults
        let mut metrics = TokenMetrics::default();
        compute_derived_fields(&mut metrics);

        // Should have computed defaults
        assert_eq!(metrics.lp_locked_percent, 0.0); // Not locked by default
        assert_eq!(metrics.volume_to_lp_ratio, 0.0); // No volume, no liquidity
        assert_eq!(metrics.top10_holders_percent, 25.0); // Default for 0 holders
        assert_eq!(metrics.token_age_minutes, None); // No default - unknown age is None
    }

    // =========================================================================
    // BUG-003: Total Supply Mapping Tests
    // =========================================================================

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_total_supply_from_etherscan_priority() {
        // Test that total_supply is correctly mapped from Etherscan (highest priority)
        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: Some(1_000_000_000.0), // Etherscan provides f64
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        assert_eq!(metrics.total_supply, Some(1_000_000_000.0));
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_total_supply_from_ethplorer_fallback() {
        // Test that total_supply falls back to Ethplorer when Etherscan is None
        use crate::api::ethplorer::{ContractInfo, EthplorerTokenInfo};

        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: Some(EthplorerTokenInfo {
                address: "0x1234".to_string(),
                name: "TestToken".to_string(),
                symbol: "TST".to_string(),
                decimals: "18".to_string(),
                total_supply: "500000000000000000000000000".to_string(), // String format
                holders_count: 1000,
                owner: String::new(),
                transfers_count: 5000,
                contract_info: None,
                price: None,
                website: None,
                image: None,
            }),
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None, // Etherscan not available
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        // Should parse Ethplorer string to f64
        assert_eq!(metrics.total_supply, Some(5e26_f64));
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_total_supply_from_blockscout_fallback() {
        // Test that total_supply falls back to Blockscout when Etherscan and Ethplorer are None
        use crate::api::blockscout::BlockscoutTokenInfo;

        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: Some(BlockscoutTokenInfo {
                token_address: "0x1234".to_string(),
                name: "TestToken".to_string(),
                symbol: "TST".to_string(),
                decimals: 18,
                total_supply: "750000000000000000000000000".to_string(), // String format
                holder_count: 500,
                creator_address: None,
                creation_tx_hash: None,
                creation_block: None,
                is_verified: false,
                contract_name: None,
                token_type: "ERC20".to_string(),
                market_cap: None,
                price_usd: None,
            }),
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        // Should parse Blockscout string to f64
        assert_eq!(metrics.total_supply, Some(7.5e26_f64));
    }

    #[test]
    fn test_total_supply_priority_order() {
        // Test that Etherscan takes priority over Ethplorer and Blockscout
        use crate::api::blockscout::BlockscoutTokenInfo;
        use crate::api::ethplorer::EthplorerTokenInfo;

        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: Some(EthplorerTokenInfo {
                address: "0x1234".to_string(),
                name: "TestToken".to_string(),
                symbol: "TST".to_string(),
                decimals: "18".to_string(),
                total_supply: "200000000000000000000000000".to_string(), // Would be 2e26
                holders_count: 1000,
                owner: String::new(),
                transfers_count: 5000,
                contract_info: None,
                price: None,
                website: None,
                image: None,
            }),
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: Some(1_000_000_000.0), // Etherscan value (should win)
            dedaub: None,
            transfer_events: None,
            blockscout: Some(BlockscoutTokenInfo {
                token_address: "0x1234".to_string(),
                name: "TestToken".to_string(),
                symbol: "TST".to_string(),
                decimals: 18,
                total_supply: "300000000000000000000000000".to_string(), // Would be 3e26
                holder_count: 500,
                creator_address: None,
                creation_tx_hash: None,
                creation_block: None,
                is_verified: false,
                contract_name: None,
                token_type: "ERC20".to_string(),
                market_cap: None,
                price_usd: None,
            }),
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        // Etherscan value should win (1e9, not 2e26 or 3e26)
        assert_eq!(metrics.total_supply, Some(1_000_000_000.0));
    }

    #[test]
    fn test_total_supply_empty_string_handling() {
        // Test that empty strings are handled gracefully
        use crate::api::ethplorer::EthplorerTokenInfo;

        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: Some(EthplorerTokenInfo {
                address: "0x1234".to_string(),
                name: "TestToken".to_string(),
                symbol: "TST".to_string(),
                decimals: "18".to_string(),
                total_supply: String::new(), // Empty string
                holders_count: 1000,
                owner: String::new(),
                transfers_count: 5000,
                contract_info: None,
                price: None,
                website: None,
                image: None,
            }),
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        // Empty string should not be parsed, should remain None
        assert_eq!(metrics.total_supply, None);
    }

    // =========================================================================
    // BUG-004: Deployer Profile Fallback Tests
    // =========================================================================

    #[test]
    fn test_deployer_profile_from_etherscan_primary() {
        // Test that deployer_profile is correctly mapped from Etherscan (primary source)
        use crate::api::etherscan::DeployerProfile as EtherscanDeployerProfile;

        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: Some(EtherscanDeployerProfile {
                address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
                first_tx_timestamp: 1_600_000_000,
                wallet_age_days: 100,
                deploy_timestamp: 1_608_640_000,
            }),
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        assert_eq!(metrics.deployer_address, Some("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string()));
        assert_eq!(metrics.deployer_wallet_age_days, Some(100));
        assert_eq!(metrics.deploy_timestamp, Some(1_608_640_000));
    }

    #[test]
    fn test_deployer_profile_from_ethplorer_fallback() {
        // Test that deployer_profile falls back to Ethplorer when primary fetch fails
        use crate::api::ethplorer::{ContractInfo, EthplorerTokenInfo};

        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: Some(EthplorerTokenInfo {
                address: "0x1234".to_string(),
                name: "TestToken".to_string(),
                symbol: "TST".to_string(),
                decimals: "18".to_string(),
                total_supply: "1000000000000000000000000000".to_string(),
                holders_count: 1000,
                owner: String::new(),
                transfers_count: 5000,
                contract_info: Some(ContractInfo {
                    creator_address: "0xdeployer123456789012345678901234567890".to_string(),
                    creation_tx_hash: "0xtxhash123456789012345678901234567890".to_string(),
                    creation_timestamp: 1_609_459_200,
                }),
                price: None,
                website: None,
                image: None,
            }),
            moralis_holders: None,
            deployer_profile: None, // Primary source failed
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        // Should use Ethplorer fallback
        assert_eq!(metrics.deployer_address, Some("0xdeployer123456789012345678901234567890".to_string()));
        assert_eq!(metrics.deploy_timestamp, Some(1_609_459_200));
        // wallet_age_days should remain None (Ethplorer doesn't provide it)
        assert_eq!(metrics.deployer_wallet_age_days, None);
    }

    #[test]
    fn test_deployer_profile_primary_takes_priority() {
        // Test that primary deployer_profile takes priority over Ethplorer fallback
        use crate::api::etherscan::DeployerProfile as EtherscanDeployerProfile;
        use crate::api::ethplorer::{ContractInfo, EthplorerTokenInfo};

        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: Some(EthplorerTokenInfo {
                address: "0x1234".to_string(),
                name: "TestToken".to_string(),
                symbol: "TST".to_string(),
                decimals: "18".to_string(),
                total_supply: "1000000000000000000000000000".to_string(),
                holders_count: 1000,
                owner: String::new(),
                transfers_count: 5000,
                contract_info: Some(ContractInfo {
                    creator_address: "0xethplorer_deployer".to_string(), // Different from primary
                    creation_tx_hash: "0xtxhash123456789012345678901234567890".to_string(),
                    creation_timestamp: 1_609_459_200,
                }),
                price: None,
                website: None,
                image: None,
            }),
            moralis_holders: None,
            deployer_profile: Some(EtherscanDeployerProfile {
                address: "0xprimary_deployer".to_string(), // Primary source value
                first_tx_timestamp: 1_600_000_000,
                wallet_age_days: 100,
                deploy_timestamp: 1_608_640_000,
            }),
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        // Primary source should win
        assert_eq!(metrics.deployer_address, Some("0xprimary_deployer".to_string()));
        assert_eq!(metrics.deployer_wallet_age_days, Some(100));
        assert_eq!(metrics.deploy_timestamp, Some(1_608_640_000));
    }

    #[test]
    fn test_deployer_profile_no_contract_info_fallback() {
        // Test that missing contract_info in Ethplorer is handled gracefully
        use crate::api::ethplorer::EthplorerTokenInfo;

        let scan = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: Some(EthplorerTokenInfo {
                address: "0x1234".to_string(),
                name: "TestToken".to_string(),
                symbol: "TST".to_string(),
                decimals: "18".to_string(),
                total_supply: "1000000000000000000000000000".to_string(),
                holders_count: 1000,
                owner: String::new(),
                transfers_count: 5000,
                contract_info: None, // No contract info available
                price: None,
                website: None,
                image: None,
            }),
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: Vec::new(),
        };
        let metrics = extract_features(&scan);

        // Should remain None when both primary and fallback are unavailable
        assert_eq!(metrics.deployer_address, None);
        assert_eq!(metrics.deploy_timestamp, None);
        assert_eq!(metrics.deployer_wallet_age_days, None);
    }
}
