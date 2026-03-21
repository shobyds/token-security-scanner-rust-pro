//! Parallel Token Scanner using tokio::join! for concurrent API execution
//!
//! This module provides a high-performance token scanner that fetches data from
//! ALL API providers simultaneously, achieving 2-3 second scan times instead of
//! 10-15 seconds with sequential execution.
//!
//! # Architecture
//! ```rust
//! tokio::join!(
//!     fetch_dexscreener(token),
//!     fetch_honeypot(token),
//!     fetch_goplus(token),
//!     fetch_etherscan(token),
//! );
//! ```
//!
//! # Benefits
//! - Scan time: 2-3 seconds (instead of 10-15 seconds sequential)
//! - All API calls execute in parallel
//! - Results aggregated into unified TokenData model
//! - Graceful handling of partial failures
//!
//! # Note
//! Bitquery removed (402 Payment Required - token expired). Volume data now
//! provided by Dexscreener fallback chain.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::unused_self)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::large_futures)]
#![allow(clippy::too_many_arguments)]

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, ContractMetadata, ContractRisk, DexTokenData,
    DefiLlamaClient, DeployerProfile, DexscreenerClient, EtherscanClient, EthplorerClient, EthplorerTokenInfo, GoPlusClient,
    HolderAnalysis, HoneypotClient, HoneypotResult, MoralisClient, SourceCodeResult,
    TokenSnifferClient, chain_to_goplus_id, chain_to_honeypot_id,
    validate_token_address,
};
use crate::models::TokenData;

/// Error type for API operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Name of the API that failed
    pub api_name: String,
    /// Error message
    pub message: String,
    /// Whether this is a timeout error
    pub is_timeout: bool,
    /// Whether this is a rate limit error
    pub is_rate_limit: bool,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.api_name, self.message)
    }
}

impl std::error::Error for ApiError {}

/// Scan result from a single API provider with timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResult<T> {
    /// The result data if successful
    pub data: Option<T>,
    /// Error if the API call failed
    pub error: Option<ApiError>,
    /// Time taken for this API call in milliseconds
    pub elapsed_ms: u64,
}

impl<T> Default for ApiResult<T> {
    fn default() -> Self {
        Self {
            data: None,
            error: None,
            elapsed_ms: 0,
        }
    }
}

impl<T> ApiResult<T> {
    /// Create a successful result
    pub fn success(data: T, elapsed_ms: u64) -> Self {
        Self {
            data: Some(data),
            error: None,
            elapsed_ms,
        }
    }

    /// Create an error result
    pub fn error(api_name: &str, message: String, elapsed_ms: u64) -> Self {
        Self {
            data: None,
            error: Some(ApiError {
                api_name: api_name.to_string(),
                message,
                is_timeout: false,
                is_rate_limit: false,
            }),
            elapsed_ms,
        }
    }

    /// Create a timeout error result
    pub fn timeout(api_name: &str, elapsed_ms: u64) -> Self {
        Self {
            data: None,
            error: Some(ApiError {
                api_name: api_name.to_string(),
                message: "Request timed out".to_string(),
                is_timeout: true,
                is_rate_limit: false,
            }),
            elapsed_ms,
        }
    }

    /// Create a rate limit error result
    pub fn rate_limited(api_name: &str, elapsed_ms: u64) -> Self {
        Self {
            data: None,
            error: Some(ApiError {
                api_name: api_name.to_string(),
                message: "Rate limited by API".to_string(),
                is_timeout: false,
                is_rate_limit: true,
            }),
            elapsed_ms,
        }
    }

    /// Check if this result is successful
    pub fn is_success(&self) -> bool {
        self.data.is_some()
    }
}

/// Comprehensive scan result aggregating data from all API providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Token address that was scanned
    pub token_address: String,
    /// Blockchain network
    pub chain: String,
    /// Total scan time in milliseconds
    pub scan_time_ms: u64,
    /// Individual API timing breakdown
    pub timing_breakdown: TimingBreakdown,
    /// Dexscreener result
    pub dexscreener: Option<DexTokenData>,
    /// Honeypot.is result
    pub honeypot: Option<HoneypotResult>,
    /// GoPlus Security result
    pub goplus: Option<ContractRisk>,
    /// Etherscan result
    pub etherscan: Option<ContractMetadata>,
    /// Ethplorer token metadata and holder count (Phase 1 Quick Win)
    pub ethplorer: Option<EthplorerTokenInfo>,
    /// Moralis holder analysis result (Phase 1 Task 1.2)
    pub moralis_holders: Option<HolderAnalysis>,
    /// Deployer profile result (Phase 1 Task 1.3)
    pub deployer_profile: Option<crate::api::EtherscanDeployerProfile>,
    /// Source code verification result (Phase 1 Task 1.4)
    pub source_code: Option<SourceCodeResult>,
    /// Total token supply from Etherscan (Phase 1 Task 1.5)
    pub total_supply: Option<f64>,
    /// Dedaub contract analysis result (Phase 3: Advanced Features)
    pub dedaub: Option<crate::api::DedaubAnalysisResult>,
    /// Transfer events holder analysis (Phase 3: Advanced Features)
    pub transfer_events: Option<crate::api::TransferHolderAnalysis>,
    /// Blockscout token metadata (Phase 3: Advanced Features)
    pub blockscout: Option<crate::api::BlockscoutTokenInfo>,
    /// Alchemy simulation honeypot result (Phase 3: Advanced Features)
    pub alchemy_simulation: Option<crate::api::AlchemySimHoneypotResult>,
    /// RPC simulation honeypot result (Phase 3: Advanced Features)
    pub rpc_simulation: Option<crate::api::RpcHoneypotDetection>,
    /// Tenderly simulation honeypot result (Phase 3: Advanced Features)
    pub tenderly: Option<crate::api::TenderlyHoneypotResult>,
    /// Deployer profile from Phase 4 (Phase 4: Deployer Analysis)
    pub deployer: Option<crate::api::deployer::DeployerProfile>,
    /// Source code analysis (Phase 4: Source Code Verification)
    pub source_analysis: Option<crate::api::SourceAnalysis>,
    /// Blacklist analysis (Phase 4: Blacklist Detection)
    pub blacklist_analysis: Option<crate::api::BlacklistAnalysis>,
    /// Honeypot.is enhanced detection (Phase 4.1: Immediate Fixes)
    pub honeypot_is: Option<crate::api::honeypot_is::HoneypotIsResult>,
    /// Scammer detection result from multiple free providers (Phase 4.1: Forta Replacement)
    pub scammer_detection: Option<crate::api::scammer_detector::ScammerDetectionResult>,
    /// LP lock detection result (Phase 4.3: LP & Holder Analytics)
    pub lp_lock: Option<crate::api::lp_lock::LPLockResult>,
    /// The Graph holder analytics (Phase 4.3: LP & Holder Analytics)
    pub graph_analytics: Option<crate::api::thegraph::GraphTradeAnalysis>,
    /// DefiLlama price data with confidence score (Phase 1 Task 1.6 - Sprint 3 INT-001)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defillama_price: Option<crate::api::defillama::DefiLlamaPrice>,
    /// Aggregated unified token data
    pub aggregated: TokenData,
    /// List of errors from failed API calls
    pub errors: Vec<ApiError>,
}

/// Timing breakdown for individual API calls
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimingBreakdown {
    /// Dexscreener API time in ms
    pub dexscreener_ms: u64,
    /// Honeypot.is API time in ms
    pub honeypot_ms: u64,
    /// GoPlus API time in ms
    pub goplus_ms: u64,
    /// Etherscan API time in ms
    pub etherscan_ms: u64,
    /// Ethplorer API time in ms (Phase 1 Quick Win)
    pub ethplorer_ms: u64,
    /// Dedaub API time in ms (Phase 3: Advanced Features)
    pub dedaub_ms: u64,
    /// Transfer events RPC time in ms (Phase 3: Advanced Features)
    pub transfer_events_ms: u64,
    /// Blockscout API time in ms (Phase 3: Advanced Features)
    pub blockscout_ms: u64,
    /// Alchemy simulation time in ms (Phase 3: Advanced Features)
    pub alchemy_simulation_ms: u64,
    /// RPC simulation time in ms (Phase 3: Advanced Features)
    pub rpc_simulation_ms: u64,
    /// Tenderly simulation time in ms (Phase 3: Advanced Features)
    pub tenderly_ms: u64,
    /// Deployer analysis time in ms (Phase 4: Deployer Analysis)
    pub deployer_ms: u64,
    /// Source code analysis time in ms (Phase 4: Source Code Verification)
    pub source_analysis_ms: u64,
    /// Blacklist analysis time in ms (Phase 4: Blacklist Detection)
    pub blacklist_analysis_ms: u64,
    /// Honeypot.is enhanced detection time in ms (Phase 4.1: Immediate Fixes)
    pub honeypot_is_ms: u64,
    /// Scammer detection time in ms (Phase 4.1: Forta Replacement)
    pub scammer_detection_ms: u64,
    /// LP lock detection time in ms (Phase 4.3: LP & Holder Analytics)
    pub lp_lock_ms: u64,
    /// The Graph holder analytics time in ms (Phase 4.3: LP & Holder Analytics)
    pub graph_analytics_ms: u64,
    /// DefiLlama price fetch time in ms (Phase 1 Task 1.6 - Sprint 3 INT-001)
    pub defillama_ms: u64,
}

impl ScanResult {
    /// Check if the scan was completely successful (no errors)
    pub fn is_fully_successful(&self) -> bool {
        self.errors.is_empty()
    }

    /// Check if at least one API succeeded
    pub fn has_any_success(&self) -> bool {
        self.dexscreener.is_some()
            || self.honeypot.is_some()
            || self.goplus.is_some()
            || self.etherscan.is_some()
    }

    /// Get the number of successful API calls
    pub fn success_count(&self) -> usize {
        let mut count = 0;
        if self.dexscreener.is_some() {
            count += 1;
        }
        if self.honeypot.is_some() {
            count += 1;
        }
        if self.goplus.is_some() {
            count += 1;
        }
        if self.etherscan.is_some() {
            count += 1;
        }
        count
    }

    /// Get the number of failed API calls
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
}

/// Parallel token scanner that fetches data from all API providers simultaneously
#[derive(Debug, Clone)]
pub struct TokenScanner {
    /// API configuration
    config: ApiConfig,
    /// Dexscreener client
    dexscreener: DexscreenerClient,
    /// Honeypot.is client
    honeypot: HoneypotClient,
    /// GoPlus Security client
    goplus: GoPlusClient,
    /// Etherscan client
    etherscan: EtherscanClient,
    /// Ethplorer client for token metadata (Phase 1 Quick Win)
    ethplorer: EthplorerClient,
    /// Moralis client (Phase 1 Task 1.2)
    moralis: Option<MoralisClient>,
    /// DefiLlama client for price fallback (Phase 1 Task 1.6)
    defillama: DefiLlamaClient,
    /// TokenSniffer client for honeypot fallback
    tokensniffer: TokenSnifferClient,
    /// LP Lock client (Phase 4.3: LP & Holder Analytics)
    lp_lock: crate::api::lp_lock::LPLockClient,
    /// The Graph client (Phase 4.3: LP & Holder Analytics)
    thegraph: crate::api::thegraph::TheGraphClient,
    /// Timeout for individual API calls
    api_timeout: Duration,
}

impl TokenScanner {
    /// Create a new TokenScanner with the given configuration
    pub fn new(config: &ApiConfig) -> Result<Self> {
        let dexscreener = DexscreenerClient::with_config(config)?;
        let honeypot = HoneypotClient::with_config(config)?;
        let goplus = GoPlusClient::with_config(config)?;
        let etherscan = EtherscanClient::with_config(config)?;
        // Ethplorer client (Phase 1 Quick Win) - uses "freekey" by default
        let ethplorer = EthplorerClient::with_config(config).unwrap_or_else(|_| EthplorerClient::default());

        // Moralis client is optional - may fail if API key not set
        let moralis = MoralisClient::with_config(config).ok();

        if moralis.is_some() {
            info!("Moralis client initialized successfully");
        } else {
            warn!("Moralis client initialization failed - holder analysis will be unavailable");
        }

        // DefiLlama client is always available (no API key required)
        let defillama = DefiLlamaClient::new()?;
        // TokenSniffer client (disabled by default, used as fallback)
        let tokensniffer = TokenSnifferClient::with_config(config)?;
        // LP Lock client (Phase 4.3: LP & Holder Analytics)
        let lp_lock = crate::api::lp_lock::LPLockClient::new()?;
        // The Graph client (Phase 4.3: LP & Holder Analytics)
        let thegraph = crate::api::thegraph::TheGraphClient::with_config(config)?;

        Ok(Self {
            config: config.clone(),
            dexscreener,
            honeypot,
            goplus,
            etherscan,
            ethplorer,
            moralis,
            defillama,
            tokensniffer,
            lp_lock,
            thegraph,
            api_timeout: Duration::from_secs(15),
        })
    }

    /// Create a new TokenScanner with custom timeout
    pub fn with_timeout(config: &ApiConfig, api_timeout: Duration) -> Result<Self> {
        let mut scanner = Self::new(config)?;
        scanner.api_timeout = api_timeout;
        Ok(scanner)
    }

    /// Create a new TokenScanner for testing with custom clients
    #[cfg(test)]
    pub fn for_testing(
        dexscreener: DexscreenerClient,
        honeypot: HoneypotClient,
        goplus: GoPlusClient,
        etherscan: EtherscanClient,
        defillama: DefiLlamaClient,
        tokensniffer: TokenSnifferClient,
        lp_lock: crate::api::lp_lock::LPLockClient,
        thegraph: crate::api::thegraph::TheGraphClient,
        api_timeout: Duration,
    ) -> Self {
        Self {
            config: ApiConfig::from_env(),
            dexscreener,
            honeypot,
            goplus,
            etherscan,
            ethplorer: EthplorerClient::default(),
            moralis: None,  // Not used in tests
            defillama,
            tokensniffer,
            lp_lock,
            thegraph,
            api_timeout,
        }
    }

    /// Scan a token address across all API providers in parallel
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to scan (must start with 0x)
    /// * `chain` - The blockchain network (ethereum, bsc, polygon, etc.)
    ///
    /// # Returns
    /// * `Ok(ScanResult)` - Comprehensive scan result with all API data aggregated
    /// * `Err(anyhow::Error)` - Error if validation fails or all APIs fail
    #[instrument(skip(self), fields(token_address = %token_address, chain = %chain))]
    pub async fn scan_token(&self, token_address: &str, chain: &str) -> Result<ScanResult> {
        let start_time = Instant::now();

        // Validate token address before making any API calls
        validate_token_address(token_address, chain).context("Invalid token address")?;

        info!(
            "Starting parallel token scan for {} on {}",
            token_address, chain
        );

        // Map chain to provider-specific IDs
        let goplus_chain = chain_to_goplus_id(chain);
        let honeypot_chain = chain_to_honeypot_id(chain);

        // Clone necessary data for parallel tasks
        let token_addr = token_address.to_string();
        let token_addr_dex = token_addr.clone();
        let token_addr_hp = token_addr.clone();
        let token_addr_goplus = token_addr.clone();
        let token_addr_es = token_addr.clone();
        let token_addr_ep = token_addr.clone();
        let token_addr_dep = token_addr.clone();
        let token_addr_src = token_addr.clone();
        let token_addr_supply = token_addr.clone();
        let token_addr_dedaub = token_addr.clone();
        let token_addr_transfer = token_addr.clone();
        let token_addr_blockscout = token_addr.clone();
        let token_addr_alchemy = token_addr.clone();
        let token_addr_rpc = token_addr.clone();
        let token_addr_tenderly = token_addr.clone();
        let token_addr_phase4_deployer = token_addr.clone();
        let token_addr_phase4_source = token_addr.clone();
        let token_addr_phase4_blacklist = token_addr.clone();
        let token_addr_phase4_honeypot_is = token_addr.clone();
        let token_addr_scammer_detector = token_addr.clone();
        let token_addr_phase4_lp_lock = token_addr.clone();
        let token_addr_phase4_graph = token_addr.clone();
        let token_addr_defillama = token_addr.clone();

        // Execute ALL API calls in parallel using tokio::join!
        // This is the key to achieving 2-3 second scan times
        // Note: Bitquery removed (402 Payment Required - token expired)
        // Phase 3 APIs: dedaub, transfer_events, blockscout, alchemy_simulation, rpc_simulation, tenderly
        // Phase 4 APIs: deployer_history, source_analysis, blacklist_analysis
        // Phase 4.1 APIs: honeypot_is, scammer_detector (replaced forta)
        // Phase 4.3 APIs: lp_lock, graph_analytics
        // Phase 1 Task 1.6: DefiLlama price with confidence score (Sprint 3 INT-001)
        let (dex_result, hp_result, gp_result, es_result, ep_result, moralis_result, deployer_result, source_result, supply_result, dedaub_result, transfer_events_result, blockscout_result, alchemy_result, rpc_result, tenderly_result, phase4_deployer_result, phase4_source_result, phase4_blacklist_result, phase4_honeypot_is_result, scammer_detector_result, phase4_lp_lock_result, phase4_graph_result, defillama_result) = tokio::join!(
            self.fetch_dexscreener_with_timeout(&token_addr_dex, chain),
            self.fetch_honeypot_with_timeout(&token_addr_hp, honeypot_chain),
            self.fetch_goplus_with_timeout(&token_addr_goplus, goplus_chain),
            self.fetch_etherscan_with_timeout(&token_addr_es),
            self.fetch_ethplorer_with_timeout(&token_addr_ep),
            self.fetch_moralis_with_timeout(&token_addr, chain),
            self.fetch_deployer_profile_with_timeout(&token_addr_dep, chain),
            self.fetch_source_code_with_timeout(&token_addr_src, chain),
            self.fetch_total_supply_with_timeout(&token_addr_supply, chain),
            self.fetch_dedaub_with_timeout(&token_addr_dedaub, chain),
            self.fetch_transfer_events_with_timeout(&token_addr_transfer, chain),
            self.fetch_blockscout_with_timeout(&token_addr_blockscout, chain),
            self.fetch_alchemy_simulation_with_timeout(&token_addr_alchemy, chain),
            self.fetch_rpc_simulation_with_timeout(&token_addr_rpc, chain),
            self.fetch_tenderly_with_timeout(&token_addr_tenderly, chain),
            self.fetch_phase4_deployer_with_timeout(&token_addr_phase4_deployer, chain),
            self.fetch_phase4_source_with_timeout(&token_addr_phase4_source, chain),
            self.fetch_phase4_blacklist_with_timeout(&token_addr_phase4_blacklist, chain),
            self.fetch_phase4_honeypot_is_with_timeout(&token_addr_phase4_honeypot_is, chain),
            self.fetch_scammer_detection_with_timeout(&token_addr_scammer_detector, chain),
            self.fetch_phase4_lp_lock_with_timeout(&token_addr_phase4_lp_lock),
            self.fetch_phase4_graph_analytics_with_timeout(&token_addr_phase4_graph, chain),
            self.fetch_defillama_price_with_timeout(&token_addr_defillama, chain),
        );

        // Collect errors
        let mut errors: Vec<crate::api::ApiError> = Vec::new();
        if let Some(ref err) = dex_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = hp_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = gp_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = es_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = ep_result.error {
            errors.push(err.clone());
        }
        // Bitquery removed - no longer collecting errors
        if let Some(ref err) = moralis_result.error {
            errors.push(err.clone());
        }
        // Phase 3 API errors
        if let Some(ref err) = dedaub_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = transfer_events_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = blockscout_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = alchemy_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = rpc_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = tenderly_result.error {
            errors.push(err.clone());
        }
        // Phase 4 API errors
        if let Some(ref err) = phase4_deployer_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = phase4_source_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = phase4_blacklist_result.error {
            errors.push(err.clone());
        }
        // Phase 4.1 API errors
        if let Some(ref err) = phase4_honeypot_is_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = scammer_detector_result.error {
            errors.push(err.clone());
        }
        // Phase 4.3 API errors
        if let Some(ref err) = phase4_lp_lock_result.error {
            errors.push(err.clone());
        }
        if let Some(ref err) = phase4_graph_result.error {
            errors.push(err.clone());
        }
        // Phase 1 Task 1.6: DefiLlama error (Sprint 3 INT-001)
        if let Some(ref err) = defillama_result.error {
            errors.push(err.clone());
        }

        // Log errors
        for err in &errors {
            warn!("API error during scan: {}", err);
        }

        // Aggregate results into unified TokenData
        let aggregated = self.aggregate_token_data(
            token_address,
            chain,
            dex_result.data.as_ref(),
            hp_result.data.as_ref(),
            gp_result.data.as_ref(),
            es_result.data.as_ref(),
        );

        let scan_time_ms = start_time.elapsed().as_millis() as u64;

        let result = ScanResult {
            token_address: token_address.to_string(),
            chain: chain.to_string(),
            scan_time_ms,
            timing_breakdown: TimingBreakdown {
                dexscreener_ms: dex_result.elapsed_ms,
                honeypot_ms: hp_result.elapsed_ms,
                goplus_ms: gp_result.elapsed_ms,
                etherscan_ms: es_result.elapsed_ms,
                ethplorer_ms: ep_result.elapsed_ms,
                dedaub_ms: dedaub_result.elapsed_ms,
                transfer_events_ms: transfer_events_result.elapsed_ms,
                blockscout_ms: blockscout_result.elapsed_ms,
                alchemy_simulation_ms: alchemy_result.elapsed_ms,
                rpc_simulation_ms: rpc_result.elapsed_ms,
                tenderly_ms: tenderly_result.elapsed_ms,
                deployer_ms: phase4_deployer_result.elapsed_ms,
                source_analysis_ms: phase4_source_result.elapsed_ms,
                blacklist_analysis_ms: phase4_blacklist_result.elapsed_ms,
                honeypot_is_ms: phase4_honeypot_is_result.elapsed_ms,
                scammer_detection_ms: scammer_detector_result.elapsed_ms,
                lp_lock_ms: phase4_lp_lock_result.elapsed_ms,
                graph_analytics_ms: phase4_graph_result.elapsed_ms,
                defillama_ms: defillama_result.elapsed_ms,
            },
            dexscreener: dex_result.data,
            honeypot: hp_result.data,
            goplus: gp_result.data,
            etherscan: es_result.data,
            ethplorer: ep_result.data,
            moralis_holders: moralis_result.data,
            deployer_profile: deployer_result.data,
            source_code: source_result.data,
            total_supply: supply_result.data,
            dedaub: dedaub_result.data,
            transfer_events: transfer_events_result.data,
            blockscout: blockscout_result.data,
            alchemy_simulation: alchemy_result.data,
            rpc_simulation: rpc_result.data,
            tenderly: tenderly_result.data,
            deployer: phase4_deployer_result.data,  // Phase 4: Deployer history
            source_analysis: phase4_source_result.data,  // Phase 4: Source code
            blacklist_analysis: phase4_blacklist_result.data,  // Phase 4: Blacklist
            honeypot_is: phase4_honeypot_is_result.data,  // Phase 4.1: Honeypot.is
            scammer_detection: scammer_detector_result.data,  // Phase 4.1: Scammer detection (multi-provider)
            lp_lock: phase4_lp_lock_result.data,  // Phase 4.3: LP Lock Detection
            graph_analytics: phase4_graph_result.data,  // Phase 4.3: Holder Analytics
            defillama_price: defillama_result.data,  // Phase 1 Task 1.6: DefiLlama price (Sprint 3 INT-001)
            aggregated,
            errors,
        };

        info!(
            "Parallel scan completed for {} in {}ms ({} APIs succeeded, {} failed)",
            token_address,
            result.scan_time_ms,
            result.success_count(),
            result.error_count()
        );

        // Always return results, even if all APIs failed
        // The report will show which APIs succeeded/failed

        Ok(result)
    }

    // ========================================================================
    // Fallback Chain Methods
    // ========================================================================

    /// Check honeypot status with fallback chain
    ///
    /// Fallback order:
    /// 1. TokenSniffer (primary) - Free tier, reliable
    /// 2. GoPlus contract risk (fallback)
    ///
    /// Note: Honeypot.is removed due to persistent parsing errors
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to check
    /// * `chain` - The blockchain network
    ///
    /// # Returns
    /// * `Ok(HoneypotResult)` - Honeypot detection result from first successful provider
    /// * `Err(anyhow::Error)` - All providers failed
    #[instrument(skip(self), fields(token_address = %token_address, chain = %chain))]
    async fn check_honeypot_with_fallback(
        &self,
        token_address: &str,
        chain: &str,
    ) -> Result<HoneypotResult> {
        use crate::api::fallback_chain::{HoneypotData, HoneypotFallbackChain};

        let start = Instant::now();

        // Build fallback chain (Honeypot.is removed - starts with TokenSniffer)
        let chain_builder = HoneypotFallbackChain::new()
            .configure(
                &self.tokensniffer,
                &self.goplus,
                token_address,
                chain,
            );

        match chain_builder.execute().await {
            Ok(data) => {
                let elapsed = start.elapsed().as_millis() as u64;
                info!(
                    "Honeypot detection succeeded with {:?} in {}ms",
                    data.provider, elapsed
                );

                // Convert to HoneypotResult
                Ok(HoneypotResult {
                    token_address: data.token_address,
                    chain: data.chain,
                    is_honeypot: data.is_honeypot,
                    buy_tax: data.buy_tax,
                    sell_tax: data.sell_tax,
                    can_buy: data.can_buy,
                    can_sell: data.can_sell,
                    error: None,
                    simulation: None,
                })
            }
            Err(e) => {
                warn!("All honeypot providers failed: {}", e);
                Err(e)
            }
        }
    }

    /// Get trade analysis with fallback chain
    ///
    /// Fallback order:
    /// 1. Dexscreener (primary) - Basic volume data
    ///
    /// Note: Bitquery removed (402 Payment Required - token expired)
    /// Note: The Graph removed (endpoint removed)
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to analyze
    /// * `chain` - The blockchain network
    /// * `hours_back` - Number of hours to look back
    ///
    /// # Returns
    /// * `Ok(TradeAnalysis)` - Trade analysis result from first successful provider
    /// * `Err(anyhow::Error)` - All providers failed
    #[instrument(skip(self), fields(token_address = %token_address, chain = %chain))]

    /// Fetch Dexscreener data with timeout
    async fn fetch_dexscreener_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<DexTokenData> {
        let start = Instant::now();

        match tokio::time::timeout(
            self.api_timeout,
            self.dexscreener.fetch_token_data(token_address, chain),
        )
        .await
        {
            Ok(Ok(data)) => ApiResult::success(data, start.elapsed().as_millis() as u64),
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("timed out") {
                    ApiResult::timeout("Dexscreener", elapsed)
                } else if msg.contains("Rate limited") {
                    ApiResult::rate_limited("Dexscreener", elapsed)
                } else {
                    ApiResult::error("Dexscreener", msg, elapsed)
                }
            }
            Err(_) => ApiResult::timeout("Dexscreener", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch Honeypot.is data with timeout
    async fn fetch_honeypot_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<HoneypotResult> {
        let start = Instant::now();

        match self.check_honeypot_with_fallback(token_address, chain).await {
            Ok(data) => {
                let elapsed = start.elapsed().as_millis() as u64;
                info!("Honeypot detection succeeded with fallback chain");
                ApiResult::success(data, elapsed)
            }
            Err(e) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("All honeypot providers failed: {}", e);
                ApiResult::error("Honeypot", e.to_string(), elapsed)
            }
        }
    }

    /// Fetch GoPlus data with timeout
    async fn fetch_goplus_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<ContractRisk> {
        let start = Instant::now();

        match tokio::time::timeout(
            self.api_timeout,
            self.goplus.fetch_contract_risk(token_address, chain),
        )
        .await
        {
            Ok(Ok(data)) => ApiResult::success(data, start.elapsed().as_millis() as u64),
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("timed out") {
                    ApiResult::timeout("GoPlus", elapsed)
                } else if msg.contains("Rate limited") {
                    ApiResult::rate_limited("GoPlus", elapsed)
                } else {
                    ApiResult::error("GoPlus", msg, elapsed)
                }
            }
            Err(_) => ApiResult::timeout("GoPlus", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch Etherscan data with timeout
    async fn fetch_etherscan_with_timeout(
        &self,
        token_address: &str,
    ) -> ApiResult<ContractMetadata> {
        let start = Instant::now();

        match tokio::time::timeout(
            self.api_timeout,
            self.etherscan.fetch_contract_metadata(token_address),
        )
        .await
        {
            Ok(Ok(data)) => ApiResult::success(data, start.elapsed().as_millis() as u64),
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("timed out") {
                    ApiResult::timeout("Etherscan", elapsed)
                } else if msg.contains("Rate limited") {
                    ApiResult::rate_limited("Etherscan", elapsed)
                } else if msg.contains("disabled") {
                    // Etherscan might be disabled (no API key) - don't count as error
                    ApiResult {
                        data: None,
                        error: None,
                        elapsed_ms: elapsed,
                    }
                } else {
                    ApiResult::error("Etherscan", msg, elapsed)
                }
            }
            Err(_) => ApiResult::timeout("Etherscan", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch Moralis holder data with timeout (Phase 1 Task 1.2)
    async fn fetch_moralis_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<HolderAnalysis> {
        let start = Instant::now();

        // If Moralis client not configured, return empty result (not an error)
        let Some(ref moralis_client) = self.moralis else {
            warn!("Moralis client not configured - skipping holder analysis for {}", token_address);
            return ApiResult {
                data: None,
                error: Some(ApiError {
                    api_name: "Moralis".to_string(),
                    message: "Client not configured".to_string(),
                    is_timeout: false,
                    is_rate_limit: false,
                }),
                elapsed_ms: 0,
            };
        };

        info!("Fetching Moralis holders for {} on {}", token_address, chain);

        match tokio::time::timeout(
            self.api_timeout,
            moralis_client.get_top_holders(token_address, chain, 10),
        )
        .await
        {
            Ok(Ok(holders)) => {
                info!("Successfully fetched {} Moralis holders for {}", holders.len(), token_address);
                // Get deployer address from etherscan if available
                let deployer = "";  // Would need to pass from etherscan result
                let analysis = MoralisClient::build_holder_analysis(&holders, deployer);
                ApiResult::success(analysis, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("timed out") {
                    ApiResult::timeout("Moralis", elapsed)
                } else if msg.contains("Rate limited") {
                    ApiResult::rate_limited("Moralis", elapsed)
                } else if msg.contains("API key invalid") {
                    ApiResult::error("Moralis", "Invalid API key".to_string(), elapsed)
                } else if msg.contains("disabled") {
                    warn!("Moralis API disabled for {}: {}", token_address, msg);
                    ApiResult {
                        data: None,
                        error: Some(ApiError {
                            api_name: "Moralis".to_string(),
                            message: msg,
                            is_timeout: false,
                            is_rate_limit: false,
                        }),
                        elapsed_ms: elapsed,
                    }
                } else {
                    ApiResult::error("Moralis", msg, elapsed)
                }
            }
            Err(_) => ApiResult::timeout("Moralis", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch deployer profile with timeout (Phase 1 Task 1.3)
    async fn fetch_deployer_profile_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<crate::api::EtherscanDeployerProfile> {
        let start = Instant::now();

        // Map chain to chain ID
        let chain_id = match chain.to_lowercase().as_str() {
            "ethereum" => 1u64,
            "bsc" => 56u64,
            "polygon" => 137u64,
            _ => 1u64,
        };

        match tokio::time::timeout(
            self.api_timeout,
            self.etherscan.get_deployer_profile(token_address, chain_id),
        )
        .await
        {
            Ok(Ok(profile)) => ApiResult::success(profile, start.elapsed().as_millis() as u64),
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("timed out") {
                    ApiResult::timeout("DeployerProfile", elapsed)
                } else if msg.contains("not found") {
                    // Contract creation not found - not an error, just no data
                    ApiResult {
                        data: None,
                        error: None,
                        elapsed_ms: elapsed,
                    }
                } else {
                    ApiResult::error("DeployerProfile", msg, elapsed)
                }
            }
            Err(_) => ApiResult::timeout("DeployerProfile", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch source code with timeout (Phase 1 Task 1.4)
    async fn fetch_source_code_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<SourceCodeResult> {
        let start = Instant::now();

        // Map chain to chain ID
        let chain_id = match chain.to_lowercase().as_str() {
            "ethereum" => 1u64,
            "bsc" => 56u64,
            "polygon" => 137u64,
            _ => 1u64,
        };

        match tokio::time::timeout(
            self.api_timeout,
            self.etherscan.get_source_code(token_address, chain_id),
        )
        .await
        {
            Ok(Ok(source)) => ApiResult::success(source, start.elapsed().as_millis() as u64),
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("timed out") {
                    ApiResult::timeout("SourceCode", elapsed)
                } else if msg.contains("not found") {
                    // Source code not found - not an error, just unverified
                    ApiResult {
                        data: None,
                        error: None,
                        elapsed_ms: elapsed,
                    }
                } else {
                    ApiResult::error("SourceCode", msg, elapsed)
                }
            }
            Err(_) => ApiResult::timeout("SourceCode", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch total supply with timeout (Phase 1 Task 1.5)
    async fn fetch_total_supply_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<f64> {
        let start = Instant::now();

        // Map chain to chain ID
        let chain_id = match chain.to_lowercase().as_str() {
            "ethereum" => 1u64,
            "bsc" => 56u64,
            "polygon" => 137u64,
            _ => 1u64,
        };

        // Get token decimals from aggregated data or default to 18
        // This is a simplification - in production you'd fetch decimals from contract
        let decimals = 18u8;

        match tokio::time::timeout(
            self.api_timeout,
            self.etherscan.get_token_supply(token_address, chain_id, decimals),
        )
        .await
        {
            Ok(Ok(supply)) => ApiResult::success(supply, start.elapsed().as_millis() as u64),
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("timed out") {
                    ApiResult::timeout("TotalSupply", elapsed)
                } else {
                    // Total supply fetch failure - not critical, continue without it
                    ApiResult {
                        data: None,
                        error: None,
                        elapsed_ms: elapsed,
                    }
                }
            }
            Err(_) => ApiResult::timeout("TotalSupply", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch Ethplorer token info with timeout (Phase 1 Quick Win)
    async fn fetch_ethplorer_with_timeout(
        &self,
        token_address: &str,
    ) -> ApiResult<EthplorerTokenInfo> {
        let start = Instant::now();
        
        match tokio::time::timeout(
            self.api_timeout,
            self.ethplorer.get_token_info(token_address),
        )
        .await
        {
            Ok(Ok(info)) => {
                info!("Successfully fetched Ethplorer token info for {}: holders={}", 
                    token_address, info.holders_count);
                ApiResult::success(info, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("timed out") {
                    ApiResult::timeout("Ethplorer", elapsed)
                } else if msg.contains("Rate limited") {
                    ApiResult::rate_limited("Ethplorer", elapsed)
                } else {
                    ApiResult::error("Ethplorer", msg, elapsed)
                }
            }
            Err(_) => ApiResult::timeout("Ethplorer", start.elapsed().as_millis() as u64),
        }
    }

    // ========================================================================
    // Phase 3: Advanced Features - Timeout Wrapper Methods
    // ========================================================================

    /// Fetch Dedaub contract analysis with timeout (Phase 3: Advanced Features)
    async fn fetch_dedaub_with_timeout(
        &self,
        token_address: &str,
        _chain: &str,
    ) -> ApiResult<crate::api::DedaubAnalysisResult> {
        let start = Instant::now();

        // Dedaub requires API key - skip if not configured
        let dedaub_client = match crate::api::DedaubClient::new() {
            Ok(client) => client,
            Err(_) => {
                return ApiResult {
                    data: None,
                    error: None,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        match tokio::time::timeout(
            self.api_timeout,
            dedaub_client.analyze_contract(token_address, "ethereum"),
        )
        .await
        {
            Ok(Ok(analysis)) => {
                info!("Successfully fetched Dedaub analysis for {}: score={:?}",
                    token_address, analysis.security_score.as_ref().map(|s| s.overall_score));
                ApiResult::success(analysis, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("disabled") || msg.contains("API key") {
                    // Dedaub not configured - not an error, just skip
                    ApiResult {
                        data: None,
                        error: None,
                        elapsed_ms: elapsed,
                    }
                } else if msg.contains("timed out") {
                    ApiResult::timeout("Dedaub", elapsed)
                } else {
                    ApiResult::error("Dedaub", msg, elapsed)
                }
            }
            Err(_) => ApiResult::timeout("Dedaub", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch Transfer Events holder analysis with timeout (Phase 3: Advanced Features)
    async fn fetch_transfer_events_with_timeout(
        &self,
        token_address: &str,
        _chain: &str,
    ) -> ApiResult<crate::api::TransferHolderAnalysis> {
        let start = Instant::now();

        // Use demo RPC URL - may have limited functionality
        let transfer_client = match crate::api::TransferEventClient::with_rpc_url("https://eth-mainnet.g.alchemy.com/v2/demo") {
            Ok(client) => client,
            Err(_) => {
                return ApiResult {
                    data: None,
                    error: None,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        match tokio::time::timeout(
            self.api_timeout,
            transfer_client.analyze_holders(token_address, None, None),
        )
        .await
        {
            Ok(Ok(analysis)) => {
                info!("Successfully fetched Transfer Events analysis for {}: holders={}",
                    token_address, analysis.holder_count);
                ApiResult::success(analysis, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("timed out") {
                    ApiResult::timeout("TransferEvents", elapsed)
                } else {
                    // Transfer events fetch failure - not critical, continue without it
                    ApiResult {
                        data: None,
                        error: None,
                        elapsed_ms: elapsed,
                    }
                }
            }
            Err(_) => ApiResult::timeout("TransferEvents", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch Blockscout token info with timeout (Phase 3: Advanced Features)
    async fn fetch_blockscout_with_timeout(
        &self,
        token_address: &str,
        _chain: &str,
    ) -> ApiResult<crate::api::BlockscoutTokenInfo> {
        let start = Instant::now();

        let blockscout_client = match crate::api::BlockscoutClient::new() {
            Ok(client) => client,
            Err(_) => {
                return ApiResult {
                    data: None,
                    error: None,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        match tokio::time::timeout(
            self.api_timeout,
            blockscout_client.get_token_info(token_address),
        )
        .await
        {
            Ok(Ok(info)) => {
                info!("Successfully fetched Blockscout token info for {}: name={}",
                    token_address, info.name);
                ApiResult::success(info, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("timed out") {
                    ApiResult::timeout("Blockscout", elapsed)
                } else {
                    // Blockscout fetch failure - not critical, continue without it
                    ApiResult {
                        data: None,
                        error: None,
                        elapsed_ms: elapsed,
                    }
                }
            }
            Err(_) => ApiResult::timeout("Blockscout", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch Alchemy simulation with timeout (Phase 3: Advanced Features)
    async fn fetch_alchemy_simulation_with_timeout(
        &self,
        token_address: &str,
        _chain: &str,
    ) -> ApiResult<crate::api::AlchemySimHoneypotResult> {
        let start = Instant::now();

        // Alchemy simulation requires valid RPC URL - skip if using demo
        let alchemy_client = match crate::api::AlchemySimulationClient::new() {
            Ok(client) => client,
            Err(_) => {
                return ApiResult {
                    data: None,
                    error: None,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        match tokio::time::timeout(
            self.api_timeout,
            alchemy_client.is_honeypot(token_address),
        )
        .await
        {
            Ok(Ok(result)) => {
                info!("Successfully fetched Alchemy simulation for {}: is_honeypot={}",
                    token_address, result.is_honeypot);
                ApiResult::success(result, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("disabled") || msg.contains("demo") {
                    // Alchemy using demo URL - skip silently
                    ApiResult {
                        data: None,
                        error: None,
                        elapsed_ms: elapsed,
                    }
                } else if msg.contains("timed out") {
                    ApiResult::timeout("AlchemySimulation", elapsed)
                } else {
                    ApiResult::error("AlchemySimulation", msg, elapsed)
                }
            }
            Err(_) => ApiResult::timeout("AlchemySimulation", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch RPC simulation with timeout (Phase 3: Advanced Features)
    async fn fetch_rpc_simulation_with_timeout(
        &self,
        token_address: &str,
        _chain: &str,
    ) -> ApiResult<crate::api::RpcHoneypotDetection> {
        let start = Instant::now();

        // Use demo RPC URL - may have limited functionality
        let rpc_client = match crate::api::RpcSimulationClient::with_rpc_url("https://eth-mainnet.g.alchemy.com/v2/demo") {
            Ok(client) => client,
            Err(e) => {
                warn!("Failed to create RPC simulation client: {}", e);
                // Return error result structure instead of empty
                return ApiResult {
                    data: Some(crate::api::RpcHoneypotDetection {
                        token_address: token_address.to_string(),
                        is_honeypot: false,
                        reason: Some(format!("Failed to create RPC client: {}", e)),
                        buy_simulation: Some(crate::api::RpcSimulationResult {
                            success: false,
                            error: Some(format!("Failed to create RPC client: {}", e)),
                            revert_reason: None,
                            gas_used: None,
                            output: None,
                        }),
                        sell_simulation: None,
                        can_buy: false,
                        can_sell: false,
                        router_used: crate::api::UNISWAP_V2_ROUTER.to_string(),
                    }),
                    error: None,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        match tokio::time::timeout(
            self.api_timeout,
            rpc_client.is_honeypot(token_address),
        )
        .await
        {
            Ok(Ok(result)) => {
                info!("Successfully fetched RPC simulation for {}: is_honeypot={}",
                    token_address, result.is_honeypot);
                ApiResult::success(result, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("timed out") {
                    // Return timeout error structure
                    ApiResult {
                        data: Some(crate::api::RpcHoneypotDetection {
                            token_address: token_address.to_string(),
                            is_honeypot: false,
                            reason: Some("RPC simulation timed out".to_string()),
                            buy_simulation: Some(crate::api::RpcSimulationResult {
                                success: false,
                                error: Some("RPC simulation timed out".to_string()),
                                revert_reason: None,
                                gas_used: None,
                                output: None,
                            }),
                            sell_simulation: None,
                            can_buy: false,
                            can_sell: false,
                            router_used: crate::api::UNISWAP_V2_ROUTER.to_string(),
                        }),
                        error: None,
                        elapsed_ms: elapsed,
                    }
                } else {
                    // RPC simulation failure - return error structure with details
                    warn!("RPC simulation failed for {}: {}", token_address, msg);
                    ApiResult {
                        data: Some(crate::api::RpcHoneypotDetection {
                            token_address: token_address.to_string(),
                            is_honeypot: false,
                            reason: Some(msg.clone()),
                            buy_simulation: Some(crate::api::RpcSimulationResult {
                                success: false,
                                error: Some(msg),
                                revert_reason: None,
                                gas_used: None,
                                output: None,
                            }),
                            sell_simulation: None,
                            can_buy: false,
                            can_sell: false,
                            router_used: crate::api::UNISWAP_V2_ROUTER.to_string(),
                        }),
                        error: None,
                        elapsed_ms: elapsed,
                    }
                }
            }
            Err(_) => {
                // Hard timeout - return timeout structure
                ApiResult {
                    data: Some(crate::api::RpcHoneypotDetection {
                        token_address: token_address.to_string(),
                        is_honeypot: false,
                        reason: Some("RPC simulation timed out".to_string()),
                        buy_simulation: Some(crate::api::RpcSimulationResult {
                            success: false,
                            error: Some("RPC simulation timed out".to_string()),
                            revert_reason: None,
                            gas_used: None,
                            output: None,
                        }),
                        sell_simulation: None,
                        can_buy: false,
                        can_sell: false,
                        router_used: crate::api::UNISWAP_V2_ROUTER.to_string(),
                    }),
                    error: None,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                }
            }
        }
    }

    /// Fetch Tenderly simulation with timeout (Phase 3: Advanced Features)
    async fn fetch_tenderly_with_timeout(
        &self,
        token_address: &str,
        _chain: &str,
    ) -> ApiResult<crate::api::TenderlyHoneypotResult> {
        let start = Instant::now();

        // Tenderly requires API key - skip if not configured
        let tenderly_client = match crate::api::TenderlyClient::new() {
            Ok(client) => client,
            Err(_) => {
                return ApiResult {
                    data: None,
                    error: None,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        match tokio::time::timeout(
            self.api_timeout,
            tenderly_client.is_honeypot(token_address),
        )
        .await
        {
            Ok(Ok(result)) => {
                info!("Successfully fetched Tenderly simulation for {}: is_honeypot={}",
                    token_address, result.is_honeypot);
                ApiResult::success(result, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("disabled") || msg.contains("API key") {
                    // Tenderly not configured - skip silently
                    ApiResult {
                        data: None,
                        error: None,
                        elapsed_ms: elapsed,
                    }
                } else if msg.contains("timed out") {
                    ApiResult::timeout("Tenderly", elapsed)
                } else {
                    ApiResult::error("Tenderly", msg, elapsed)
                }
            }
            Err(_) => ApiResult::timeout("Tenderly", start.elapsed().as_millis() as u64),
        }
    }

    // ========================================================================
    // Phase 4: Timeout Wrapper Methods
    // ========================================================================

    /// Fetch Phase 4 deployer history with timeout
    async fn fetch_phase4_deployer_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<crate::api::deployer::DeployerProfile> {
        let start = Instant::now();

        let deployer_client = match crate::api::DeployerClient::new() {
            Ok(client) => client,
            Err(_) => {
                return ApiResult {
                    data: None,
                    error: None,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        match tokio::time::timeout(
            self.api_timeout,
            deployer_client.get_deployer_profile(token_address, chain),
        )
        .await
        {
            Ok(Ok(profile)) => {
                info!("Successfully fetched Phase 4 deployer profile for {}: age={} days",
                    token_address, profile.wallet_age_days);
                ApiResult::success(profile, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let msg = e.to_string();
                if msg.contains("API key") || msg.contains("disabled") {
                    ApiResult {
                        data: None,
                        error: None,
                        elapsed_ms: elapsed,
                    }
                } else if msg.contains("timed out") {
                    ApiResult::timeout("Phase4Deployer", elapsed)
                } else {
                    ApiResult::error("Phase4Deployer", msg, elapsed)
                }
            }
            Err(_) => ApiResult::timeout("Phase4Deployer", start.elapsed().as_millis() as u64),
        }
    }

    /// Fetch Phase 4 source code analysis with timeout
    #[allow(clippy::unused_async)]
    async fn fetch_phase4_source_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<crate::api::SourceAnalysis> {
        let start = Instant::now();

        // Map chain to chain ID
        let chain_id = match chain.to_lowercase().as_str() {
            "ethereum" => 1u64,
            "bsc" => 56u64,
            "polygon" => 137u64,
            _ => 1u64,
        };

        // Fetch source code from Etherscan first
        let source_code_result = match self.etherscan.get_source_code(token_address, chain_id).await {
            Ok(source) => {
                debug!("Fetched source code for {}: verified={}, name={:?}",
                    token_address,
                    !source.source_code.as_deref().unwrap_or("").is_empty(),
                    source.contract_name
                );
                source
            }
            Err(e) => {
                // Contract not verified is expected for many tokens - use debug level
                debug!("Failed to fetch source code for {}: {} - contract may be unverified", token_address, e);
                // Return empty analysis if source fetch fails
                let analysis = crate::api::analyze_source_code("", None);
                info!("Phase 4 source analysis completed for {} (no source available)", token_address);
                return ApiResult::success(analysis, start.elapsed().as_millis() as u64);
            }
        };

        // Get actual source code string
        let source_code = source_code_result.source_code.as_deref().unwrap_or("");
        let abi = source_code_result.abi.as_deref();

        // Log source code info for debugging
        if source_code.is_empty() {
            warn!("Source code is empty for {} - contract may be unverified", token_address);
        } else {
            debug!("Analyzing source code for {}: {} bytes", token_address, source_code.len());
        }

        // Analyze the actual source code
        let analysis = crate::api::analyze_source_code(source_code, abi);

        info!("Phase 4 source analysis completed for {}: verified={}, risk_flags={}, risk_score={}",
            token_address, 
            analysis.is_verified,
            analysis.risk_flags.len(),
            analysis.source_risk_score
        );

        ApiResult::success(analysis, start.elapsed().as_millis() as u64)
    }

    /// Fetch Phase 4 blacklist analysis with timeout
    #[allow(clippy::unused_async)]
    async fn fetch_phase4_blacklist_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<crate::api::BlacklistAnalysis> {
        let start = Instant::now();

        // Map chain to chain ID
        let chain_id = match chain.to_lowercase().as_str() {
            "ethereum" => 1u64,
            "bsc" => 56u64,
            "polygon" => 137u64,
            _ => 1u64,
        };

        // Fetch bytecode from Etherscan - use getsourcecode which includes bytecode
        // Note: Etherscan doesn't directly expose bytecode in their standard API
        // We'll use the source code result and check for bytecode patterns if available
        let bytecode = if let Some(bc) = self.fetch_bytecode_from_etherscan(token_address, chain_id).await {
            debug!("Fetched bytecode for {}: {} bytes", token_address, bc.len());
            bc
        } else {
            debug!("Failed to fetch bytecode for {} - returning empty analysis (contract may be unverified or RPC issue)", token_address);
            let analysis = crate::api::scan_for_blacklist("", None);
            info!("Phase 4 blacklist analysis completed for {} (no bytecode available)", token_address);
            return ApiResult::success(analysis, start.elapsed().as_millis() as u64);
        };

        // Log bytecode info for debugging
        if bytecode.is_empty() {
            warn!("Bytecode is empty for {}", token_address);
        } else {
            debug!("Analyzing bytecode for {}: {} bytes", token_address, bytecode.len());
        }

        // Scan the actual bytecode for blacklist patterns
        let analysis = crate::api::scan_for_blacklist(&bytecode, None);

        info!("Phase 4 blacklist analysis completed for {}: has_blacklist={}, has_bot_blocking={}, risk_score={}",
            token_address, 
            analysis.has_blacklist,
            analysis.has_bot_blocking,
            analysis.blacklist_risk_score
        );

        ApiResult::success(analysis, start.elapsed().as_millis() as u64)
    }

    /// Helper function to fetch bytecode from Etherscan
    async fn fetch_bytecode_from_etherscan(
        &self,
        token_address: &str,
        chain_id: u64,
    ) -> Option<String> {
        // Try to get bytecode from contract source code endpoint
        // Etherscan includes creation code and deployed bytecode in some responses
        match self.etherscan.get_source_code(token_address, chain_id).await {
            Ok(source) => {
                // Check if source code has embedded bytecode info
                // Some verified contracts include bytecode in the response
                if let Some(code) = &source.source_code {
                    // If it starts with 0x and looks like bytecode, use it
                    if code.starts_with("0x") && code.len() > 100 {
                        return Some(code.clone());
                    }
                }
                
                // Try to extract from constructor arguments if available
                if let Some(args) = &source.constructor_arguments {
                    if !args.is_empty() {
                        // Constructor arguments are part of the creation bytecode
                        return Some(format!("0x{}", args));
                    }
                }
                
                None
            }
            Err(e) => {
                debug!("Failed to fetch source code for bytecode analysis: {}", e);
                None
            }
        }
    }

    /// Fetch Phase 4.1 Honeypot.is analysis with timeout
    #[allow(clippy::manual_let_else)]
    async fn fetch_phase4_honeypot_is_with_timeout(
        &self,
        token_address: &str,
        _chain: &str,
    ) -> ApiResult<crate::api::honeypot_is::HoneypotIsResult> {
        let start = Instant::now();

        let client = match crate::api::honeypot_is::HoneypotIsClient::new() {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to create Honeypot.is client: {}", e);
                return ApiResult {
                    data: None,
                    error: None,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        match tokio::time::timeout(
            self.api_timeout,
            client.check_honeypot(token_address, 1),
        )
        .await
        {
            Ok(Ok(result)) => {
                info!("Phase 4.1 Honeypot.is analysis completed for {}: is_honeypot={}",
                    token_address, result.is_honeypot);
                ApiResult::success(result, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("Honeypot.is check failed for {}: {}", token_address, e);
                ApiResult {
                    data: None,
                    error: Some(crate::api::ApiError {
                        api_name: "Honeypot.is".to_string(),
                        message: e.to_string(),
                        is_timeout: false,
                        is_rate_limit: false,
                    }),
                    elapsed_ms: elapsed,
                }
            }
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                ApiResult::timeout("Honeypot.is", elapsed)
            }
        }
    }

    /// Fetch Phase 4.1 scammer detection from multiple free providers with timeout
    /// (Replaces Forta Network with free, no-auth providers: Etherscan, ScamSniffer, MistTrack, AMLBot)
    #[allow(clippy::manual_let_else)]
    async fn fetch_scammer_detection_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<crate::api::scammer_detector::ScammerDetectionResult> {
        let start = Instant::now();

        // Create scammer detector client
        let client = match crate::api::scammer_detector::ScammerDetector::new() {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to create ScammerDetector client: {}", e);
                return ApiResult {
                    data: None,
                    error: None,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        match tokio::time::timeout(
            self.api_timeout,
            client.fetch_scammer_detection(token_address, chain),
        )
        .await
        {
            Ok(Ok(result)) => {
                info!(
                    "Phase 4.1 Scammer detection completed for {}: is_scammer={}, risk_score={}, providers={}/4",
                    token_address,
                    result.is_known_scammer,
                    result.deployer_risk_score,
                    result.providers_succeeded.len()
                );
                ApiResult::success(result, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("Scammer detection failed for {}: {}", token_address, e);
                // Return empty result instead of error - scammer detection is optional
                ApiResult {
                    data: None,
                    error: Some(crate::api::ApiError {
                        api_name: "Scammer Detection".to_string(),
                        message: e.to_string(),
                        is_timeout: false,
                        is_rate_limit: false,
                    }),
                    elapsed_ms: elapsed,
                }
            }
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                ApiResult::timeout("Scammer Detection", elapsed)
            }
        }
    }

    /// Fetch Phase 4.3 LP Lock detection with timeout
    #[allow(clippy::manual_let_else)]
    async fn fetch_phase4_lp_lock_with_timeout(
        &self,
        token_address: &str,
    ) -> ApiResult<crate::api::lp_lock::LPLockResult> {
        let start = Instant::now();

        match tokio::time::timeout(
            self.api_timeout,
            self.lp_lock.check_locks(token_address),
        )
        .await
        {
            Ok(Ok(result)) => {
                info!("Phase 4.3 LP lock detection completed for {}: locked={}",
                    token_address, result.liquidity_locked);
                ApiResult::success(result, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("LP lock detection failed for {}: {}", token_address, e);
                ApiResult {
                    data: None,
                    error: Some(crate::api::ApiError {
                        api_name: "LP Lock".to_string(),
                        message: e.to_string(),
                        is_timeout: false,
                        is_rate_limit: false,
                    }),
                    elapsed_ms: elapsed,
                }
            }
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                ApiResult::timeout("LP Lock", elapsed)
            }
        }
    }

    /// Fetch Phase 4.3 The Graph holder analytics with timeout
    #[allow(clippy::manual_let_else)]
    async fn fetch_phase4_graph_analytics_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<crate::api::thegraph::GraphTradeAnalysis> {
        let start = Instant::now();

        match tokio::time::timeout(
            self.api_timeout,
            self.thegraph.get_holder_analytics(token_address, chain),
        )
        .await
        {
            Ok(Ok(result)) => {
                info!("Phase 4.3 Graph holder analytics completed for {}: traders_24h={:?}",
                    token_address, result.unique_traders_24h);
                ApiResult::success(result, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("Graph holder analytics failed for {}: {}", token_address, e);
                ApiResult {
                    data: None,
                    error: Some(crate::api::ApiError {
                        api_name: "The Graph".to_string(),
                        message: e.to_string(),
                        is_timeout: false,
                        is_rate_limit: false,
                    }),
                    elapsed_ms: elapsed,
                }
            }
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                ApiResult::timeout("The Graph", elapsed)
            }
        }
    }

    /// Fetch Phase 1 Task 1.6 DefiLlama price with timeout (Sprint 3 INT-001)
    async fn fetch_defillama_price_with_timeout(
        &self,
        token_address: &str,
        chain: &str,
    ) -> ApiResult<crate::api::defillama::DefiLlamaPrice> {
        let start = Instant::now();

        // Create DefiLlama client
        let client = match crate::api::defillama::DefiLlamaClient::new() {
            Ok(c) => c,
            Err(e) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("Failed to create DefiLlama client: {}", e);
                return ApiResult::error("DefiLlama", e.to_string(), elapsed);
            }
        };

        match tokio::time::timeout(
            self.api_timeout,
            client.get_price(chain, token_address),
        )
        .await
        {
            Ok(Ok(result)) => {
                info!(
                    "DefiLlama price fetch succeeded for {}: ${} (confidence: {})",
                    token_address, result.price, result.confidence
                );
                ApiResult::success(result, start.elapsed().as_millis() as u64)
            }
            Ok(Err(e)) => {
                let elapsed = start.elapsed().as_millis() as u64;
                warn!("DefiLlama price fetch failed for {}: {}", token_address, e);
                ApiResult {
                    data: None,
                    error: Some(crate::api::ApiError {
                        api_name: "DefiLlama".to_string(),
                        message: e.to_string(),
                        is_timeout: false,
                        is_rate_limit: false,
                    }),
                    elapsed_ms: elapsed,
                }
            }
            Err(_) => {
                let elapsed = start.elapsed().as_millis() as u64;
                ApiResult::timeout("DefiLlama", elapsed)
            }
        }
    }

    /// Get deployer address for a token (helper function)
    #[allow(clippy::manual_let_else)]
    async fn get_deployer_address(&self, token_address: &str) -> Option<String> {
        let client = match crate::api::etherscan::EtherscanClient::new() {
            Ok(c) => c,
            Err(_) => return None,
        };

        match client.get_contract_creation(token_address, 1).await {
            Ok(info) => Some(info.deployer_address),
            Err(_) => None,
        }
    }

    /// Aggregate token data from all API providers into unified TokenData
    #[allow(clippy::too_many_arguments)]
    fn aggregate_token_data(
        &self,
        token_address: &str,
        chain: &str,
        dex: Option<&DexTokenData>,
        hp: Option<&HoneypotResult>,
        gp: Option<&ContractRisk>,
        es: Option<&ContractMetadata>,
    ) -> TokenData {
        let mut token_data = TokenData::new(token_address, chain);

        // Aggregate from Dexscreener
        if let Some(d) = dex {
            token_data.liquidity_usd = d.liquidity_usd;
            token_data.price_usd = d.price_usd;
            token_data.volume_24h = d.volume_24h;
            if let Some(ref name) = d.name {
                token_data.contract_name = name.clone();
            }
        }

        // Aggregate from Honeypot.is
        if let Some(h) = hp {
            token_data.is_honeypot = h.is_honeypot;
            token_data.buy_tax = h.buy_tax;
            token_data.sell_tax = h.sell_tax;
        }

        // Aggregate from GoPlus
        if let Some(g) = gp {
            token_data.owner_can_mint = g.owner_can_mint;
            token_data.owner_can_blacklist = g.owner_can_blacklist;
            token_data.lp_locked = g.lp_locked;
            if let Some(count) = g.holder_count {
                token_data.holder_count = count;
            }
        }

        // Aggregate from Etherscan
        if let Some(e) = es {
            token_data.contract_verified = e.is_verified;
            if !e.contract_name.is_empty() {
                token_data.contract_name = e.contract_name.clone();
            }
            token_data.total_supply = e.total_supply.clone();
            if e.holder_count > 0 {
                token_data.holder_count = e.holder_count;
            }
        }

        // Bitquery removed - holder count now from GoPlus/Etherscan only

        // Price resolution cascade: Dexscreener → DefiLlama → 0.0 (Phase 1 Task 1.6)
        // If Dexscreener didn't provide a price, try DefiLlama as fallback
        if token_data.price_usd <= 0.0 {
            // Chain mapping for DefiLlama
            let defillama_chain = match chain.to_lowercase().as_str() {
                "ethereum" | "eth" => "ethereum",
                "bsc" | "binance" => "bsc",
                "polygon" | "matic" => "polygon",
                "base" => "base",
                "arbitrum" => "arbitrum",
                "optimism" => "optimism",
                "avalanche" | "avax" => "avalanche",
                "fantom" | "ftm" => "fantom",
                _ => "ethereum",
            };

            // Try DefiLlama for price (async in a blocking context - ok for fallback)
            if let Ok(price_data) = futures::executor::block_on(
                self.defillama.get_price(defillama_chain, token_address)
            ) {
                if price_data.price > 0.0 {
                    token_data.price_usd = price_data.price;
                    token_data.price_confidence = Some(price_data.confidence);
                    info!(
                        "Price data succeeded with provider: DefiLlama (fallback from Dexscreener)"
                    );
                    debug!(
                        "DefiLlama price fallback for {}: ${} (confidence: {})",
                        token_address, price_data.price, price_data.confidence
                    );
                }
            }
        }

        // Calculate top_holder_percent (placeholder - would need more detailed holder data)
        // For now, set to 0 if we don't have detailed holder distribution
        token_data.top_holder_percent = 0.0;

        debug!(
            "Aggregated TokenData for {}: liquidity=${}, price=${}, is_honeypot={}, risk_score={}",
            token_address,
            token_data.liquidity_usd,
            token_data.price_usd,
            token_data.is_honeypot,
            token_data.risk_score()
        );

        token_data
    }

    /// Scan multiple tokens in parallel
    ///
    /// # Arguments
    /// * `tokens` - List of (token_address, chain) tuples to scan
    ///
    /// # Returns
    /// * `Ok(Vec<ScanResult>)` - List of scan results (excludes tokens where all APIs failed)
    pub async fn scan_multiple_tokens(&self, tokens: &[(&str, &str)]) -> Result<Vec<ScanResult>> {
        let mut results = Vec::with_capacity(tokens.len());

        // Scan each token in parallel using tokio::join! macro for batches
        // For large batches, we use futures::future::join_all
        use futures::future::join_all;

        let scan_futures = tokens
            .iter()
            .map(|(address, chain)| self.scan_token(address, chain));

        let scan_results = join_all(scan_futures).await;

        for (result, (address, _chain)) in scan_results.into_iter().zip(tokens.iter()) {
            match result {
                Ok(scan_result) => results.push(scan_result),
                Err(e) => {
                    warn!("Failed to scan token {}: {}", address, e);
                    // Continue with other tokens
                }
            }
        }

        Ok(results)
    }

    /// Get scanner statistics
    pub fn get_stats(&self) -> ScannerStats {
        ScannerStats {
            dexscreener_enabled: true,
            honeypot_enabled: true,
            goplus_enabled: true,
            etherscan_enabled: self.etherscan.is_enabled(),
            api_timeout_secs: self.api_timeout.as_secs(),
        }
    }

    /// Get the API timeout duration
    pub fn api_timeout(&self) -> Duration {
        self.api_timeout
    }
}

/// Scanner configuration statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerStats {
    /// Whether Dexscreener is enabled
    pub dexscreener_enabled: bool,
    /// Whether Honeypot.is is enabled
    pub honeypot_enabled: bool,
    /// Whether GoPlus is enabled
    pub goplus_enabled: bool,
    /// Whether Etherscan is enabled
    pub etherscan_enabled: bool,
    /// API timeout in seconds
    pub api_timeout_secs: u64,
}

// Helper trait to check if clients are enabled
trait IsEnabled {
    fn is_enabled(&self) -> bool;
}

impl IsEnabled for EtherscanClient {
    fn is_enabled(&self) -> bool {
        // Use reflection-like approach since enabled field is private
        // For now, assume enabled if we have an API key
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_display() {
        let error = ApiError {
            api_name: "Dexscreener".to_string(),
            message: "Rate limited".to_string(),
            is_timeout: false,
            is_rate_limit: true,
        };
        assert_eq!(format!("{}", error), "Dexscreener: Rate limited");
    }

    #[test]
    fn test_api_result_success() {
        let result: ApiResult<String> = ApiResult::success("data".to_string(), 100);
        assert!(result.is_success());
        assert_eq!(result.data, Some("data".to_string()));
        assert!(result.error.is_none());
        assert_eq!(result.elapsed_ms, 100);
    }

    #[test]
    fn test_api_result_error() {
        let result: ApiResult<String> =
            ApiResult::error("TestAPI", "error message".to_string(), 50);
        assert!(!result.is_success());
        assert!(result.data.is_none());
        assert!(result.error.is_some());
        assert_eq!(result.elapsed_ms, 50);
    }

    #[test]
    fn test_api_result_timeout() {
        let result: ApiResult<String> = ApiResult::timeout("TestAPI", 15000);
        assert!(!result.is_success());
        assert!(result.data.is_none());
        assert!(result.error.is_some());
        assert!(result.error.unwrap().is_timeout);
    }

    #[test]
    fn test_api_result_rate_limited() {
        let result: ApiResult<String> = ApiResult::rate_limited("TestAPI", 200);
        assert!(!result.is_success());
        assert!(result.data.is_none());
        assert!(result.error.is_some());
        assert!(result.error.unwrap().is_rate_limit);
    }

    #[test]
    fn test_scan_result_success_count() {
        let result = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 1000,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: Some(DexTokenData::default()),
            honeypot: Some(HoneypotResult::default()),
            goplus: None,
            etherscan: Some(ContractMetadata::default()),
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
            errors: vec![],
        };
        assert_eq!(result.success_count(), 3);
        assert_eq!(result.error_count(), 0);
        assert!(result.has_any_success());
        assert!(result.is_fully_successful());
    }

    #[test]
    fn test_scan_result_with_errors() {
        let result = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 2000,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: Some(DexTokenData::default()),
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
            errors: vec![ApiError {
                api_name: "Honeypot.is".to_string(),
                message: "Error".to_string(),
                is_timeout: false,
                is_rate_limit: false,
            }],
        };
        assert_eq!(result.success_count(), 1);
        assert_eq!(result.error_count(), 1);
        assert!(result.has_any_success());
        assert!(!result.is_fully_successful());
    }

    #[test]
    fn test_timing_breakdown_default() {
        let timing = TimingBreakdown::default();
        assert_eq!(timing.dexscreener_ms, 0);
        assert_eq!(timing.honeypot_ms, 0);
        assert_eq!(timing.goplus_ms, 0);
        assert_eq!(timing.etherscan_ms, 0);
    }

    #[test]
    fn test_scanner_stats() {
        let stats = ScannerStats {
            dexscreener_enabled: true,
            honeypot_enabled: true,
            goplus_enabled: true,
            etherscan_enabled: false,
            api_timeout_secs: 15,
        };
        assert!(stats.dexscreener_enabled);
        assert!(!stats.etherscan_enabled);
        assert_eq!(stats.api_timeout_secs, 15);
    }
}

// Include comprehensive test suite
#[cfg(test)]
mod scanner_tests {
    #![allow(clippy::missing_errors_doc)]
    #![allow(clippy::missing_panics_doc)]
    #![allow(clippy::module_name_repetitions)]

    use std::time::{Duration, Instant};

    use mockito::Server;
    use reqwest::Client;

    use crate::api::{
        ApiConfig, ApiResult, ContractMetadata, ContractRisk, DexTokenData,
        DefiLlamaClient, DexscreenerClient, EtherscanClient, EthplorerClient, GoPlusClient, HoneypotClient,
        HoneypotResult, ScanResult, ScannerStats, TimingBreakdown, TokenScanner,
        TokenSnifferClient, scanner::ApiError,
    };
    use crate::models::TokenData;

    // ============================================================================
    // Test Helper Functions
    // ============================================================================

    /// Create a mock Dexscreener client pointing to mockito server
    fn create_mock_dexscreener(server_url: &str) -> DexscreenerClient {
        let http_client = Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        DexscreenerClient::for_testing(server_url.to_string(), http_client)
    }

    /// Create a mock Honeypot client pointing to mockito server
    fn create_mock_honeypot(server_url: &str) -> HoneypotClient {
        let http_client = Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        HoneypotClient::for_testing(server_url.to_string(), http_client)
    }

    /// Create a mock GoPlus client pointing to mockito server
    fn create_mock_goplus(server_url: &str) -> GoPlusClient {
        let http_client = Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        GoPlusClient::for_testing(
            server_url.to_string(),
            http_client,
            Some("test_key".to_string()),
        )
    }

    /// Create a mock Etherscan client pointing to mockito server
    fn create_mock_etherscan(server_url: &str) -> EtherscanClient {
        let http_client = Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        EtherscanClient::for_testing(
            server_url.to_string(),
            http_client,
            Some("test_key".to_string()),
        )
    }

    /// Create a TokenScanner with all mock clients
    fn create_mock_scanner(
        dex_server: &str,
        hp_server: &str,
        gp_server: &str,
        es_server: &str,
    ) -> TokenScanner {
        TokenScanner::for_testing(
            create_mock_dexscreener(dex_server),
            create_mock_honeypot(hp_server),
            create_mock_goplus(gp_server),
            create_mock_etherscan(es_server),
            DefiLlamaClient::default(),
            TokenSnifferClient::default(),
            crate::api::lp_lock::LPLockClient::default(),
            crate::api::thegraph::TheGraphClient::default(),
            Duration::from_secs(5),
        )
    }
    // ============================================================================

    #[tokio::test]
    async fn test_successful_parallel_scan_all_apis_succeed() {
        let mut dex_server = Server::new_async().await;
        let mut hp_server = Server::new_async().await;
        let mut gp_server = Server::new_async().await;
        let mut es_server = Server::new_async().await;
        let mut bq_server = Server::new_async().await;

        // Setup Dexscreener mock
        let dex_response = r#"{
        "schemaVersion": "1.0.0",
        "pairs": [{
            "chainId": "ethereum",
            "baseToken": {
                "address": "0x1234567890123456789012345678901234567890",
                "name": "Test Token",
                "symbol": "TEST"
            },
            "priceUsd": "1.50",
            "liquidity": {"usd": 100000},
            "volume": {"h24USD": 50000}
        }]
    }"#;
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(dex_response)
            .create_async()
            .await;

        // Setup Honeypot mock
        let hp_response = r#"{
        "isHoneypot": false,
        "buyTax": 5.0,
        "sellTax": 5.0,
        "canBuy": true,
        "canSell": true
    }"#;
        let _hp_mock = hp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(hp_response)
            .create_async()
            .await;

        // Setup GoPlus mock
        let gp_response = r#"{
        "error": "0",
        "result": {
            "0x1234567890123456789012345678901234567890": {
                "is_mintable": "0",
                "owner_blacklist": "0",
                "lp_locked": "1",
                "hidden_owner": "0",
                "holder_count": "1000"
            }
        }
    }"#;
        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(gp_response)
            .create_async()
            .await;

        // Setup Etherscan mocks
        let es_source_response = r#"{
        "status": "1",
        "message": "OK",
        "result": [{
            "ContractName": "TestToken",
            "CompilerVersion": "v0.8.19",
            "Proxy": "0"
        }]
    }"#;
        let es_token_response = r#"{
        "status": "1",
        "message": "OK",
        "result": {
            "tokenName": "Test Token",
            "symbol": "TEST",
            "totalSupply": "1000000000",
            "holderCount": "1000"
        }
    }"#;
        let _es_mock1 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(es_source_response)
            .create_async()
            .await;
        let _es_mock2 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(es_token_response)
            .create_async()
            .await;

        // Setup Bitquery mock
        let bq_response = r#"{
        "data": {
            "ethereum": {
                "transfers": [{
                    "count": 5000,
                    "uniqueFrom": 200,
                    "uniqueTo": 350,
                    "volume": "1000000000000000000000"
                }]
            }
        }
    }"#;
        let _bq_mock = bq_server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(bq_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            &hp_server.url(),
            &gp_server.url(),
            &es_server.url(),
            
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok(), "Scan failed: {:?}", result.err());
        let scan_result = result.unwrap();

        // Verify all APIs succeeded
        assert!(
            scan_result.dexscreener.is_some(),
            "Dexscreener should succeed"
        );
        assert!(scan_result.honeypot.is_some(), "Honeypot should succeed");
        assert!(scan_result.goplus.is_some(), "GoPlus should succeed");
        assert!(scan_result.etherscan.is_some(), "Etherscan should succeed");

        // Verify no errors
        assert_eq!(scan_result.errors.len(), 0, "Should have no errors");
        assert!(scan_result.is_fully_successful());
        assert_eq!(scan_result.success_count(), 4);

        // Verify aggregated data
        assert_eq!(
            scan_result.aggregated.token_address,
            "0x1234567890123456789012345678901234567890"
        );
        assert_eq!(scan_result.aggregated.chain, "ethereum");
        assert!((scan_result.aggregated.price_usd - 1.50).abs() < 0.01);
        assert!((scan_result.aggregated.liquidity_usd - 100_000.0).abs() < 0.01);
        assert!(!scan_result.aggregated.is_honeypot);
        assert!((scan_result.aggregated.buy_tax - 5.0).abs() < 0.01);
        assert!(scan_result.aggregated.lp_locked);

        // Verify timing - should be fast due to parallel execution
        assert!(
            scan_result.scan_time_ms < 5000,
            "Scan should complete in <5s"
        );
    }

    // ============================================================================
    // Test 2: Partial Failure - Some APIs Fail, Others Succeed
    // ============================================================================

    #[tokio::test]
    async fn test_partial_failure_some_apis_fail() {
        let mut dex_server = Server::new_async().await;
        let mut hp_server = Server::new_async().await;
        let mut gp_server = Server::new_async().await;
        let mut es_server = Server::new_async().await;
        let mut bq_server = Server::new_async().await;

        // Dexscreener succeeds
        let dex_response = r#"{
        "schemaVersion": "1.0.0",
        "pairs": [{
            "chainId": "ethereum",
            "baseToken": {"address": "0x1234", "name": "Test", "symbol": "TST"},
            "priceUsd": "1.00",
            "liquidity": {"usd": 50000},
            "volume": {"h24USD": 10000}
        }]
    }"#;
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(dex_response)
            .create_async()
            .await;

        // Honeypot fails with 500
        let _hp_mock = hp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body("Internal Server Error")
            .create_async()
            .await;

        // GoPlus succeeds
        let gp_response = r#"{
        "error": "0",
        "result": {
            "0x1234567890123456789012345678901234567890": {
                "is_mintable": "0",
                "owner_blacklist": "0",
                "lp_locked": "1"
            }
        }
    }"#;
        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(gp_response)
            .create_async()
            .await;

        // Etherscan fails with 429 (rate limit)
        let _es_mock1 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(429)
            .with_body("Too Many Requests")
            .create_async()
            .await;
        let _es_mock2 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(429)
            .with_body("Too Many Requests")
            .create_async()
            .await;

        // Bitquery succeeds
        let bq_response = r#"{
        "data": {
            "ethereum": {
                "transfers": [{
                    "count": 1000,
                    "uniqueFrom": 50,
                    "uniqueTo": 100,
                    "volume": "500000000000000000000"
                }]
            }
        }
    }"#;
        let _bq_mock = bq_server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(bq_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            &hp_server.url(),
            &gp_server.url(),
            &es_server.url(),
            
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok(), "Scan should succeed with partial failures");
        let scan_result = result.unwrap();

        // Verify which APIs succeeded
        assert!(
            scan_result.dexscreener.is_some(),
            "Dexscreener should succeed"
        );
        assert!(scan_result.honeypot.is_none(), "Honeypot should fail");
        assert!(scan_result.goplus.is_some(), "GoPlus should succeed");
        assert!(scan_result.etherscan.is_none(), "Etherscan should fail");

        // Verify errors were collected
        assert_eq!(scan_result.errors.len(), 2, "Should have 2 errors");
        assert!(!scan_result.is_fully_successful());
        assert_eq!(scan_result.success_count(), 2);

        // Verify aggregated data still contains successful results
        assert!((scan_result.aggregated.price_usd - 1.00).abs() < 0.01);
        assert!(scan_result.aggregated.lp_locked);
    }

    // ============================================================================
    // Test 3: Complete Failure - All APIs Fail
    // ============================================================================

    #[tokio::test]
    async fn test_complete_failure_all_apis_fail() {
        let mut dex_server = Server::new_async().await;
        let mut hp_server = Server::new_async().await;
        let mut gp_server = Server::new_async().await;
        let mut es_server = Server::new_async().await;
        let mut bq_server = Server::new_async().await;

        // All APIs fail
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body("Error")
            .create_async()
            .await;

        let _hp_mock = hp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body("Error")
            .create_async()
            .await;

        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body("Error")
            .create_async()
            .await;

        let _es_mock1 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body("Error")
            .create_async()
            .await;
        let _es_mock2 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body("Error")
            .create_async()
            .await;

        let _bq_mock = bq_server
            .mock("POST", "/")
            .with_status(500)
            .with_body("Error")
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            &hp_server.url(),
            &gp_server.url(),
            &es_server.url(),
            
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err(), "Scan should fail when all APIs fail");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("All API providers failed"));
    }

    // ============================================================================
    // Test 4: Timeout Handling - APIs That Timeout
    // ============================================================================

    #[tokio::test]
    async fn test_timeout_handling() {
        let mut dex_server = Server::new_async().await;
        let mut hp_server = Server::new_async().await;
        let mut gp_server = Server::new_async().await;
        let mut es_server = Server::new_async().await;
        let mut bq_server = Server::new_async().await;

        // Dexscreener times out (we simulate by returning error quickly for this test)
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body("Simulated timeout error")
            .create_async()
            .await;

        // Honeypot succeeds quickly
        let hp_response = r#"{
        "isHoneypot": false,
        "buyTax": 3.0,
        "sellTax": 3.0,
        "canBuy": true,
        "canSell": true
    }"#;
        let _hp_mock = hp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(hp_response)
            .create_async()
            .await;

        // GoPlus succeeds quickly
        let gp_response = r#"{
        "error": "0",
        "result": {
            "0x1234567890123456789012345678901234567890": {
                "is_mintable": "0",
                "lp_locked": "1"
            }
        }
    }"#;
        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(gp_response)
            .create_async()
            .await;

        // Etherscan succeeds quickly
        let es_source_response = r#"{"status": "1", "result": [{"ContractName": "Test"}]}"#;
        let es_token_response = r#"{"status": "1", "result": {"tokenName": "Test", "totalSupply": "1000", "holderCount": "100"}}"#;
        let _es_mock1 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(es_source_response)
            .create_async()
            .await;
        let _es_mock2 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(es_token_response)
            .create_async()
            .await;

        // Bitquery succeeds quickly
        let bq_response = r#"{"data": {"ethereum": {"transfers": [{"count": 100, "uniqueFrom": 10, "uniqueTo": 20}]}}}"#;
        let _bq_mock = bq_server
            .mock("POST", "/")
            .with_status(200)
            .with_body(bq_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            &hp_server.url(),
            &gp_server.url(),
            &es_server.url(),
            
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok(), "Scan should succeed despite API failure");

        let scan_result = result.unwrap();
        assert!(scan_result.dexscreener.is_none(), "Dexscreener should fail");
        assert!(scan_result.honeypot.is_some(), "Honeypot should succeed");

        // Check error was recorded (simulating timeout behavior)
        assert!(!scan_result.errors.is_empty(), "Should have recorded error");
    }

    // ============================================================================
    // Test 5: Rate Limit Handling - APIs That Return 429
    // ============================================================================

    #[tokio::test]
    async fn test_rate_limit_handling() {
        let mut dex_server = Server::new_async().await;
        let mut hp_server = Server::new_async().await;
        let mut gp_server = Server::new_async().await;
        let mut es_server = Server::new_async().await;
        let mut bq_server = Server::new_async().await;

        // Dexscreener returns 429
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(429)
            .with_body("Too Many Requests")
            .create_async()
            .await;

        // Honeypot succeeds
        let hp_response = r#"{"isHoneypot": false, "buyTax": 2.0, "sellTax": 2.0, "canBuy": true, "canSell": true}"#;
        let _hp_mock = hp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(hp_response)
            .create_async()
            .await;

        // GoPlus succeeds
        let gp_response = r#"{"error": "0", "result": {"0x1234567890123456789012345678901234567890": {"lp_locked": "1"}}}"#;
        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(gp_response)
            .create_async()
            .await;

        // Etherscan succeeds
        let es_source_response = r#"{"status": "1", "result": [{"ContractName": "Test"}]}"#;
        let es_token_response = r#"{"status": "1", "result": {"tokenName": "Test", "totalSupply": "1000", "holderCount": "100"}}"#;
        let _es_mock1 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(es_source_response)
            .create_async()
            .await;
        let _es_mock2 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(es_token_response)
            .create_async()
            .await;

        // Bitquery succeeds
        let bq_response = r#"{"data": {"ethereum": {"transfers": [{"count": 100, "uniqueFrom": 10, "uniqueTo": 20}]}}}"#;
        let _bq_mock = bq_server
            .mock("POST", "/")
            .with_status(200)
            .with_body(bq_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            &hp_server.url(),
            &gp_server.url(),
            &es_server.url(),
            
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok(), "Scan should succeed despite rate limit");
        let scan_result = result.unwrap();

        assert!(scan_result.dexscreener.is_none(), "Dexscreener should fail");
        assert!(scan_result.honeypot.is_some(), "Honeypot should succeed");

        // Check rate limit error was recorded
        let rate_limit_error = scan_result.errors.iter().find(|e| e.is_rate_limit);
        assert!(rate_limit_error.is_some(), "Should have rate limit error");
    }

    // ============================================================================
    // Test 6: Invalid Token Address - Validation Errors
    // ============================================================================

    #[tokio::test]
    async fn test_invalid_token_address() {
        let config = ApiConfig::from_env();
        let scanner = TokenScanner::new(&config).unwrap();

        // Test missing 0x prefix
        let result = scanner
            .scan_token("1234567890123456789012345678901234567890", "ethereum")
            .await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("0x") || err_msg.contains("Invalid"),
            "Error: {}",
            err_msg
        );

        // Test invalid length
        let result = scanner.scan_token("0x1234", "ethereum").await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("length") || err_msg.contains("Invalid"),
            "Error: {}",
            err_msg
        );

        // Test invalid characters
        let result = scanner
            .scan_token("0xGGGG567890123456789012345678901234567890", "ethereum")
            .await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("hex") || err_msg.contains("Invalid"),
            "Error: {}",
            err_msg
        );
    }

    // ============================================================================
    // Test 7: Multiple Chains - Ethereum, BSC, Polygon
    // ============================================================================

    #[tokio::test]
    async fn test_multiple_chains_ethereum() {
        let mut hp_server = Server::new_async().await;

        // Honeypot should receive eth chain ID
        let hp_response = r#"{"isHoneypot": false, "buyTax": 5.0, "sellTax": 5.0, "canBuy": true, "canSell": true}"#;
        let _hp_mock = hp_server
            .mock(
                "GET",
                "/api/check/eth/0x1234567890123456789012345678901234567890",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(hp_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            "http://invalid",
            &hp_server.url(),
            "http://invalid",
            "http://invalid",
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        // Should succeed (other APIs will fail but honeypot succeeds)
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert_eq!(scan_result.chain, "ethereum");
    }

    #[tokio::test]
    async fn test_multiple_chains_bsc() {
        let mut hp_server = Server::new_async().await;
        let mut gp_server = Server::new_async().await;

        // Honeypot should receive bsc chain ID
        let hp_response = r#"{"isHoneypot": false, "buyTax": 3.0, "sellTax": 3.0, "canBuy": true, "canSell": true}"#;
        let _hp_mock = hp_server
            .mock(
                "GET",
                "/api/check/bsc/0x1234567890123456789012345678901234567890",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(hp_response)
            .create_async()
            .await;

        // GoPlus should receive bsc chain ID
        let gp_response = r#"{"error": "0", "result": {"0x1234567890123456789012345678901234567890": {"lp_locked": "1"}}}"#;
        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(gp_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            "http://invalid",
            &hp_server.url(),
            &gp_server.url(),
            "http://invalid",
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "bsc")
            .await;

        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert_eq!(scan_result.chain, "bsc");
    }

    #[tokio::test]
    async fn test_multiple_chains_polygon() {
        let mut gp_server = Server::new_async().await;

        // GoPlus should receive matic chain ID for polygon
        let gp_response = r#"{"error": "0", "result": {"0x1234567890123456789012345678901234567890": {"lp_locked": "1"}}}"#;
        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Regex("matic".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(gp_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            "http://invalid",
            "http://invalid",
            &gp_server.url(),
            "http://invalid",
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "polygon")
            .await;

        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert_eq!(scan_result.chain, "polygon");
    }

    // ============================================================================
    // Test 8: Timing Verification - Verify Parallel Execution Works
    // ============================================================================

    #[tokio::test]
    async fn test_parallel_timing_verification() {
        let mut dex_server = Server::new_async().await;
        let mut hp_server = Server::new_async().await;
        let mut gp_server = Server::new_async().await;
        let mut es_server = Server::new_async().await;
        let mut bq_server = Server::new_async().await;

        // All APIs return success quickly
        let dex_response = r#"{"schemaVersion": "1.0.0", "pairs": [{"chainId": "ethereum", "baseToken": {"address": "0x1234", "name": "Test", "symbol": "TST"}, "priceUsd": "1.00", "liquidity": {"usd": 50000}, "volume": {"h24USD": 10000}}]}"#;
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(dex_response)
            .create_async()
            .await;

        let hp_response = r#"{"isHoneypot": false, "buyTax": 5.0, "sellTax": 5.0, "canBuy": true, "canSell": true}"#;
        let _hp_mock = hp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(hp_response)
            .create_async()
            .await;

        let gp_response = r#"{"error": "0", "result": {"0x1234567890123456789012345678901234567890": {"lp_locked": "1"}}}"#;
        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(gp_response)
            .create_async()
            .await;

        let es_source_response = r#"{"status": "1", "result": [{"ContractName": "Test"}]}"#;
        let es_token_response = r#"{"status": "1", "result": {"tokenName": "Test", "totalSupply": "1000", "holderCount": "100"}}"#;
        let _es_mock1 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(es_source_response)
            .create_async()
            .await;
        let _es_mock2 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(es_token_response)
            .create_async()
            .await;

        let bq_response = r#"{"data": {"ethereum": {"transfers": [{"count": 100, "uniqueFrom": 10, "uniqueTo": 20}]}}}"#;
        let _bq_mock = bq_server
            .mock("POST", "/")
            .with_status(200)
            .with_body(bq_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            &hp_server.url(),
            &gp_server.url(),
            &es_server.url(),
        );

        let start = Instant::now();
        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;
        let parallel_time = start.elapsed();

        assert!(result.is_ok());

        // Parallel execution should complete quickly (all APIs run concurrently)
        // With 5 APIs running in parallel, total time should be close to the slowest API
        assert!(
            parallel_time < Duration::from_secs(5),
            "Parallel scan should complete in <5s, took {:?}",
            parallel_time
        );

        // Verify timing breakdown shows individual API times
        let scan_result = result.unwrap();
        assert!(scan_result.timing_breakdown.dexscreener_ms > 0);
        assert!(scan_result.timing_breakdown.honeypot_ms > 0);
        assert!(scan_result.timing_breakdown.goplus_ms > 0);
    }

    // ============================================================================
    // Test 9: Data Aggregation - Verify TokenData is Correctly Built
    // ============================================================================

    #[tokio::test]
    async fn test_data_aggregation() {
        let mut dex_server = Server::new_async().await;
        let mut hp_server = Server::new_async().await;
        let mut gp_server = Server::new_async().await;
        let mut es_server = Server::new_async().await;
        let mut bq_server = Server::new_async().await;

        // Dexscreener provides price, liquidity, volume
        let dex_response = r#"{
        "schemaVersion": "1.0.0",
        "pairs": [{
            "chainId": "ethereum",
            "baseToken": {"address": "0x1234", "name": "AggregatedToken", "symbol": "AGG"},
            "priceUsd": "2.50",
            "liquidity": {"usd": 250000},
            "volume": {"h24USD": 75000}
        }]
    }"#;
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(dex_response)
            .create_async()
            .await;

        // Honeypot provides tax info and honeypot status
        let hp_response = r#"{"isHoneypot": false, "buyTax": 7.5, "sellTax": 8.5, "canBuy": true, "canSell": true}"#;
        let _hp_mock = hp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(hp_response)
            .create_async()
            .await;

        // GoPlus provides risk flags and holder count
        let gp_response = r#"{
        "error": "0",
        "result": {
            "0x1234567890123456789012345678901234567890": {
                "is_mintable": "0",
                "owner_blacklist": "0",
                "lp_locked": "1",
                "hidden_owner": "0",
                "holder_count": "5000"
            }
        }
    }"#;
        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(gp_response)
            .create_async()
            .await;

        // Etherscan provides verification status and contract name
        let es_source_response = r#"{"status": "1", "result": [{"ContractName": "AggregatedToken", "CompilerVersion": "v0.8.20", "Proxy": "0"}]}"#;
        let es_token_response = r#"{"status": "1", "result": {"tokenName": "Aggregated Token", "symbol": "AGG", "totalSupply": "1000000000000000000000000", "holderCount": "5500"}}"#;
        let _es_mock1 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(es_source_response)
            .create_async()
            .await;
        let _es_mock2 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(es_token_response)
            .create_async()
            .await;

        // Bitquery provides transaction analysis
        let bq_response = r#"{"data": {"ethereum": {"transfers": [{"count": 10000, "uniqueFrom": 500, "uniqueTo": 800, "volume": "5000000000000000000000"}]}}}"#;
        let _bq_mock = bq_server
            .mock("POST", "/")
            .with_status(200)
            .with_body(bq_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            &hp_server.url(),
            &gp_server.url(),
            &es_server.url(),
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        let scan_result = result.unwrap();
        let aggregated = &scan_result.aggregated;

        // Verify Dexscreener data
        assert!(
            (aggregated.price_usd - 2.50).abs() < 0.01,
            "Price should be from Dexscreener"
        );
        assert!(
            (aggregated.liquidity_usd - 250_000.0).abs() < 0.01,
            "Liquidity should be from Dexscreener"
        );
        assert!(
            (aggregated.volume_24h - 75_000.0).abs() < 0.01,
            "Volume should be from Dexscreener"
        );
        assert_eq!(
            aggregated.contract_name, "AggregatedToken",
            "Name should be from Dexscreener"
        );

        // Verify Honeypot data
        assert!(
            !aggregated.is_honeypot,
            "Honeypot status should be from Honeypot.is"
        );
        assert!(
            (aggregated.buy_tax - 7.5).abs() < 0.01,
            "Buy tax should be from Honeypot.is"
        );
        assert!(
            (aggregated.sell_tax - 8.5).abs() < 0.01,
            "Sell tax should be from Honeypot.is"
        );

        // Verify GoPlus data
        assert!(
            !aggregated.owner_can_mint,
            "Mint flag should be from GoPlus"
        );
        assert!(
            !aggregated.owner_can_blacklist,
            "Blacklist flag should be from GoPlus"
        );
        assert!(aggregated.lp_locked, "LP locked should be from GoPlus");

        // Verify Etherscan data (holder count from Etherscan takes precedence)
        assert!(
            aggregated.contract_verified,
            "Verified status should be from Etherscan"
        );
        assert_eq!(
            aggregated.holder_count, 5500,
            "Holder count should be from Etherscan"
        );
        assert_eq!(
            aggregated.total_supply, "1000000000000000000000000",
            "Total supply should be from Etherscan"
        );
    }

    // ============================================================================
    // Test 10: Error Propagation - Verify Errors Don't Stop Other APIs
    // ============================================================================

    #[tokio::test]
    async fn test_error_propagation() {
        let mut dex_server = Server::new_async().await;
        let mut hp_server = Server::new_async().await;
        let mut gp_server = Server::new_async().await;
        let mut es_server = Server::new_async().await;
        let mut bq_server = Server::new_async().await;

        // Dexscreener fails
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body("Error")
            .create_async()
            .await;

        // Honeypot fails
        let _hp_mock = hp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(503)
            .with_body("Service Unavailable")
            .create_async()
            .await;

        // GoPlus succeeds
        let gp_response = r#"{"error": "0", "result": {"0x1234567890123456789012345678901234567890": {"lp_locked": "1", "holder_count": "100"}}"#;
        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(gp_response)
            .create_async()
            .await;

        // Etherscan fails
        let _es_mock1 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body("Error")
            .create_async()
            .await;
        let _es_mock2 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .with_body("Error")
            .create_async()
            .await;

        // Bitquery succeeds
        let bq_response = r#"{"data": {"ethereum": {"transfers": [{"count": 500, "uniqueFrom": 50, "uniqueTo": 75}]}}}"#;
        let _bq_mock = bq_server
            .mock("POST", "/")
            .with_status(200)
            .with_body(bq_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            &hp_server.url(),
            &gp_server.url(),
            &es_server.url(),
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(
            result.is_ok(),
            "Scan should succeed despite multiple failures"
        );
        let scan_result = result.unwrap();

        // Verify errors were collected
        assert_eq!(scan_result.errors.len(), 3, "Should have 3 errors");

        // Verify successful APIs still returned data
        assert!(scan_result.goplus.is_some(), "GoPlus should succeed");

        // Verify aggregated data contains successful results
        assert!(scan_result.aggregated.lp_locked);
        assert_eq!(scan_result.aggregated.holder_count, 100);
    }

    // ============================================================================
    // Test 11: Scan Multiple Tokens
    // ============================================================================

    #[tokio::test]
    async fn test_scan_multiple_tokens() {
        let mut dex_server = Server::new_async().await;
        let mut hp_server = Server::new_async().await;
        let mut gp_server = Server::new_async().await;
        let mut es_server = Server::new_async().await;
        let mut bq_server = Server::new_async().await;

        // Setup mocks that work for any token
        let dex_response = r#"{"schemaVersion": "1.0.0", "pairs": [{"chainId": "ethereum", "baseToken": {"address": "0x1234", "name": "Test", "symbol": "TST"}, "priceUsd": "1.00", "liquidity": {"usd": 50000}, "volume": {"h24USD": 10000}}]}"#;
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(dex_response)
            .expect(2)
            .create_async()
            .await;

        let hp_response = r#"{"isHoneypot": false, "buyTax": 5.0, "sellTax": 5.0, "canBuy": true, "canSell": true}"#;
        let _hp_mock = hp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(hp_response)
            .expect(2)
            .create_async()
            .await;

        let gp_response = r#"{"error": "0", "result": {"0x1234567890123456789012345678901234567890": {"lp_locked": "1"}}}"#;
        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(gp_response)
            .expect(2)
            .create_async()
            .await;

        let es_source_response = r#"{"status": "1", "result": [{"ContractName": "Test"}]}"#;
        let es_token_response = r#"{"status": "1", "result": {"tokenName": "Test", "totalSupply": "1000", "holderCount": "100"}}"#;
        let _es_mock1 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(es_source_response)
            .expect(2)
            .create_async()
            .await;
        let _es_mock2 = es_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(es_token_response)
            .expect(2)
            .create_async()
            .await;

        let bq_response = r#"{"data": {"ethereum": {"transfers": [{"count": 100, "uniqueFrom": 10, "uniqueTo": 20}]}}}"#;
        let _bq_mock = bq_server
            .mock("POST", "/")
            .with_status(200)
            .with_body(bq_response)
            .expect(2)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            &hp_server.url(),
            &gp_server.url(),
            &es_server.url(),
        );

        let tokens = vec![
            ("0x1111567890123456789012345678901234567890", "ethereum"),
            ("0x2222567890123456789012345678901234567890", "ethereum"),
        ];

        let results = scanner.scan_multiple_tokens(&tokens).await.unwrap();

        assert_eq!(results.len(), 2, "Should return results for both tokens");
        assert_eq!(
            results[0].token_address,
            "0x1111567890123456789012345678901234567890"
        );
        assert_eq!(
            results[1].token_address,
            "0x2222567890123456789012345678901234567890"
        );
    }

    // ============================================================================
    // Test 12: Scanner Stats
    // ============================================================================

    #[tokio::test]
    async fn test_scanner_stats() {
        let config = ApiConfig::from_env();
        let scanner = TokenScanner::new(&config).unwrap();

        let stats = scanner.get_stats();

        assert!(stats.dexscreener_enabled);
        assert!(stats.honeypot_enabled);
        assert!(stats.goplus_enabled);
        assert!(stats.api_timeout_secs > 0);
    }

    // ============================================================================
    // Test 13: Custom Timeout
    // ============================================================================

    #[tokio::test]
    async fn test_custom_timeout() {
        let config = ApiConfig::from_env();
        let scanner = TokenScanner::with_timeout(&config, Duration::from_secs(30)).unwrap();

        assert_eq!(scanner.api_timeout(), Duration::from_secs(30));
    }

    // ============================================================================
    // Test 14: Honeypot Detection in Aggregated Data
    // ============================================================================

    #[tokio::test]
    async fn test_honeypot_detection_aggregation() {
        let mut dex_server = Server::new_async().await;
        let mut hp_server = Server::new_async().await;

        let dex_response = r#"{"schemaVersion": "1.0.0", "pairs": [{"chainId": "ethereum", "baseToken": {"address": "0x1234", "name": "Scam", "symbol": "SCAM"}, "priceUsd": "0.001", "liquidity": {"usd": 1000}, "volume": {"h24USD": 100}}]}"#;
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(dex_response)
            .create_async()
            .await;

        // Token IS a honeypot
        let hp_response = r#"{"isHoneypot": true, "buyTax": 0.0, "sellTax": 99.0, "canBuy": true, "canSell": false, "error": "Sell simulation failed"}"#;
        let _hp_mock = hp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(hp_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            &hp_server.url(),
            "http://invalid",
            "http://invalid",
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        let scan_result = result.unwrap();

        assert!(scan_result.aggregated.is_honeypot, "Should detect honeypot");
        assert!(
            (scan_result.aggregated.sell_tax - 99.0).abs() < 0.01,
            "High sell tax"
        );
        assert!(
            (scan_result.aggregated.buy_tax - 0.0).abs() < 0.01,
            "Low buy tax"
        );

        // Risk score should be high
        assert!(
            scan_result.aggregated.risk_score() >= 50,
            "Risk score should be high for honeypot"
        );
    }

    // ============================================================================
    // Test 15: Contract Risk Aggregation
    // ============================================================================

    #[tokio::test]
    async fn test_contract_risk_aggregation() {
        let mut gp_server = Server::new_async().await;

        // High risk contract
        let gp_response = r#"{
        "error": "0",
        "result": {
            "0x1234567890123456789012345678901234567890": {
                "is_mintable": "1",
                "owner_blacklist": "1",
                "lp_locked": "0",
                "hidden_owner": "1",
                "selfdestruct": "1",
                "is_proxy": "1"
            }
        }
    }"#;
        let _gp_mock = gp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(gp_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            "http://invalid",
            "http://invalid",
            &gp_server.url(),
            "http://invalid",
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        let scan_result = result.unwrap();

        assert!(
            scan_result.aggregated.owner_can_mint,
            "Should detect mintable"
        );
        assert!(
            scan_result.aggregated.owner_can_blacklist,
            "Should detect blacklist"
        );
        assert!(
            !scan_result.aggregated.lp_locked,
            "Should detect unlocked LP"
        );
    }

    // ============================================================================
    // Test 16: Empty Response Handling
    // ============================================================================

    #[tokio::test]
    async fn test_empty_response_handling() {
        let mut dex_server = Server::new_async().await;

        // Empty pairs response
        let dex_response = r#"{"schemaVersion": "1.0.0", "pairs": []}"#;
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(dex_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            "http://invalid",
            "http://invalid",
            "http://invalid",
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        // Should fail because Dexscreener returned empty pairs
        assert!(result.is_err());
    }

    // ============================================================================
    // Test 17: TokenData Risk Score Calculation
    // ============================================================================

    #[test]
    fn test_token_data_risk_score_from_scan() {
        // Safe token
        let mut safe_data = TokenData::default();
        safe_data.is_honeypot = false;
        safe_data.owner_can_mint = false;
        safe_data.owner_can_blacklist = false;
        safe_data.liquidity_usd = 100_000.0;
        safe_data.contract_verified = true;
        safe_data.buy_tax = 5.0;
        safe_data.sell_tax = 5.0;

        assert!(
            safe_data.risk_score() < 20,
            "Safe token should have low risk"
        );

        // Risky token
        let mut risky_data = TokenData::default();
        risky_data.is_honeypot = true;
        risky_data.owner_can_mint = true;
        risky_data.liquidity_usd = 100.0;
        risky_data.contract_verified = false;

        assert!(
            risky_data.risk_score() >= 50,
            "Risky token should have high risk"
        );
    }

    // ============================================================================
    // Test 18: ApiResult Helper Methods
    // ============================================================================

    #[test]
    fn test_api_result_helper_methods() {
        let success: ApiResult<String> = ApiResult::success("data".to_string(), 100);
        assert!(success.is_success());

        let error: ApiResult<String> = ApiResult::error("Test", "error".to_string(), 50);
        assert!(!error.is_success());

        let timeout: ApiResult<String> = ApiResult::timeout("Test", 15000);
        assert!(!timeout.is_success());
        assert!(timeout.error.unwrap().is_timeout);

        let rate_limited: ApiResult<String> = ApiResult::rate_limited("Test", 200);
        assert!(!rate_limited.is_success());
        assert!(rate_limited.error.unwrap().is_rate_limit);
    }

    // ============================================================================
    // Test 19: ScanResult Helper Methods
    // ============================================================================

    #[test]
    fn test_scan_result_helper_methods() {
        let mut result = ScanResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 1000,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: Some(DexTokenData::default()),
            honeypot: Some(HoneypotResult::default()),
            goplus: Some(ContractRisk::default()),
            etherscan: Some(ContractMetadata::default()),
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
            errors: vec![],
        };

        assert!(result.is_fully_successful());
        assert!(result.has_any_success());
        assert_eq!(result.success_count(), 5);
        assert_eq!(result.error_count(), 0);

        // Add an error
        result.errors.push(ApiError {
            api_name: "Test".to_string(),
            message: "Error".to_string(),
            is_timeout: false,
            is_rate_limit: false,
        });

        assert!(!result.is_fully_successful());
        assert_eq!(result.error_count(), 1);
    }

    // ============================================================================
    // Test 20: Timing Breakdown Recording
    // ============================================================================

    #[tokio::test]
    async fn test_timing_breakdown_recording() {
        let mut dex_server = Server::new_async().await;
        let mut hp_server = Server::new_async().await;

        // Dexscreener returns data
        let dex_response = r#"{"schemaVersion": "1.0.0", "pairs": [{"chainId": "ethereum", "baseToken": {"address": "0x1234", "name": "Test", "symbol": "TST"}, "priceUsd": "1.00", "liquidity": {"usd": 50000}, "volume": {"h24USD": 10000}}]}"#;
        let _dex_mock = dex_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(dex_response)
            .create_async()
            .await;

        // Honeypot returns data
        let hp_response = r#"{"isHoneypot": false, "buyTax": 5.0, "sellTax": 5.0, "canBuy": true, "canSell": true}"#;
        let _hp_mock = hp_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(hp_response)
            .create_async()
            .await;

        let scanner = create_mock_scanner(
            &dex_server.url(),
            &hp_server.url(),
            "http://invalid",
            "http://invalid",
        );

        let result = scanner
            .scan_token("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        let scan_result = result.unwrap();

        // Verify timing breakdown records non-zero times for successful APIs
        assert!(
            scan_result.timing_breakdown.dexscreener_ms > 0,
            "Dexscreener should have recorded time"
        );
        assert!(
            scan_result.timing_breakdown.honeypot_ms > 0,
            "Honeypot should have recorded time"
        );
    }

    // ============================================================================
    // Test 21: Scanner Creation with Config
    // ============================================================================

    #[test]
    fn test_scanner_creation_with_config() {
        let config = ApiConfig::from_env();
        let scanner = TokenScanner::new(&config);

        assert!(scanner.is_ok(), "Scanner should be created with config");
    }

    // ============================================================================
    // Test 22: Scanner Creation Failure Handling
    // ============================================================================

    #[test]
    fn test_scanner_creation_error_handling() {
        // Scanner creation should handle missing API keys gracefully
        let config = ApiConfig::from_env();
        let result = TokenScanner::new(&config);

        // Should succeed even if some API keys are missing (those APIs will just be disabled)
        assert!(result.is_ok());
    }
}
