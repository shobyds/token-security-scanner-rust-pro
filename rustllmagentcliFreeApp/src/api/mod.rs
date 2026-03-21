//! API Collection Layer for Token Security Scanning
//!
//! This module provides a unified interface for collecting token security data
//! from multiple API providers including Dexscreener, Honeypot.is, `GoPlus`,
//! Etherscan, and `TokenSniffer`.
//!
//! # Features
//! - Async HTTP requests with reqwest
//! - Automatic retry with exponential backoff
//! - Configurable timeouts
//! - Comprehensive error handling
//! - Structured logging with tracing
//! - Fallback chain system for resilient API access

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::match_same_arms)]

pub mod alchemy_simulation;  // Phase 3: Alchemy Simulation API (Tenderly fallback)
pub mod blacklist_scanner;  // Phase 4: Blacklist bytecode detection
pub mod blockscout;  // Phase 3: Blockscout API (fallback for metadata)
pub mod dedaub;  // Phase 3: Dedaub Contract Analysis API
pub mod defillama;  // Phase 1 Task 1.6
pub mod deployer;  // Phase 4: Deployer history analysis
pub mod dexscreener;
pub mod erc20_rpc;  // Phase 2: ERC20 RPC calls using ethers-rs
pub mod etherscan;
pub mod ethplorer;  // Phase 1 Quick Win: Token metadata + holders
pub mod fallback_chain;  // Phase 2: Fallback chain system
pub mod forta;  // Phase 4.1: Forta Network scammer detection (deprecated, use scammer_detector)
pub mod goplus;
// Phase 4.1: Free scammer detection providers (no authentication required)
pub mod scam_sniffer;  // ScamSniffer API client
pub mod misttrack;  // MistTrack (SlowMist) API client
pub mod amlbot;  // AML Bot API client
pub mod scammer_detector;  // Unified scammer detection aggregator
pub mod honeypot;
pub mod honeypot_is;  // Phase 4.1: Honeypot.is enhanced detection
pub mod lp_lock;  // Phase 4.3: LP Lock Detection
pub mod moralis;  // Phase 1 Task 1.2
pub mod rpc_simulation;  // Phase 3: Manual RPC Simulation (no external API)
pub mod scanner;
pub mod slither_analyzer;  // Phase 4.2: Slither static analysis
pub mod source_checker;  // Phase 4: Source code risk analysis
pub mod tenderly;  // Phase 2: Tenderly Simulation API for honeypot detection
pub mod thegraph;  // Phase 1: The Graph client
pub mod tokensniffer;
pub mod tokensniffer_v2;  // Phase 4.2: TokenSniffer v2 security scoring
pub mod transfer_events;  // Phase 3: Transfer Events RPC for holder count

// Re-export provider types
pub use defillama::{DefiLlamaClient, DefiLlamaPrice};  // Phase 1 Task 1.6
pub use dexscreener::{DexscreenerClient, TokenData as DexTokenData};
pub use erc20_rpc::{  // Phase 2: ERC20 RPC client
    Erc20RpcClient, Erc20Metadata,
};
pub use etherscan::{ContractCreationInfo, ContractMetadata, EtherscanClient, SourceCodeResult, AddressLabels};
pub use etherscan::DeployerProfile as EtherscanDeployerProfile;  // Phase 1 Task 1.3
pub use ethplorer::{EthplorerClient, EthplorerTokenInfo};  // Phase 1 Quick Win
pub use fallback_chain::{  // Phase 2: Fallback chain system
    ApiProvider, FallbackChain, FallbackChainBuilder, FallbackResult,
    HoneypotData, HoneypotFallbackChain, PriceData, PriceDataFallbackChain,
    VolumeData, VolumeAnalyticsFallbackChain,
    // Client traits for fallback chain
    HoneypotClientTrait, TokenSnifferClientTrait, GoPlusClientTrait,
    TheGraphClientTrait, DexscreenerClientTrait,
    DefiLlamaClientTrait, TokenSnifferHoneypotData as FallbackTokenSnifferHoneypotData,
};
pub use goplus::{ContractRisk, GoPlusClient};
pub use honeypot::{HoneypotClient, HoneypotResult};
pub use moralis::{MoralisClient, MoralisHolder, MoralisHoldersResponse, HolderAnalysis, LabeledHolder};
pub use rpc_simulation::{  // Phase 3: Manual RPC Simulation
    RpcSimulationClient, RpcSimulationResult, RpcHoneypotDetection, SwapData,
    UNISWAP_V2_ROUTER, UNISWAP_V3_ROUTER, WETH_ADDRESS as RPC_WETH_ADDRESS,
};
pub use tenderly::{  // Phase 2: Tenderly Simulation API
    TenderlyClient, TenderlySimulationRequest, TenderlySimulationResponse,
    TenderlyHoneypotResult, SimulationResult, dex_routers, WETH_ADDRESS,
};
pub use thegraph::{TheGraphClient, GraphSwapData, GraphTradeAnalysis, DailyTradeData};  // Phase 1: The Graph client
pub use tokensniffer::{TokenSnifferClient, TokenSnifferScore, TokenSnifferHoneypotData};
pub use transfer_events::{  // Phase 3: Transfer Events RPC
    TransferEventClient, TransferEvent, HolderAnalysis as TransferHolderAnalysis,
    TransferEventsResult, TRANSFER_EVENT_TOPIC,
};

// Phase 3: Additional API clients
pub use alchemy_simulation::{  // Phase 3: Alchemy Simulation API
    AlchemySimulationClient, AlchemySimulationRequest, AlchemySimulationResponse,
    AlchemyHoneypotResult as AlchemySimHoneypotResult,
};
pub use blockscout::{  // Phase 3: Blockscout API
    BlockscoutClient, BlockscoutTokenInfo, BlockscoutContract,
    DEFAULT_BLOCKSCOUT_BASE_URL,
};
pub use dedaub::{  // Phase 3: Dedaub Contract Analysis API
    DedaubClient, DedaubAnalysisResult, DedaubVulnerability, DedaubSecurityScore,
    ExternalCallPattern, ReentrancyAnalysis, AccessControlIssue, ArithmeticIssue,
};

// Phase 4: Additional API clients
pub use blacklist_scanner::{  // Phase 4: Blacklist bytecode detection
    BlacklistAnalysis, scan_for_blacklist,
};
pub use deployer::{  // Phase 4: Deployer history analysis
    DeployerClient, DeployerProfile, DeployerHistory, DeployedContract,
};
pub use forta::{  // Phase 4.1: Forta Network scammer detection
    FortaClient, FortaScammerResult, FortaAlert, FortaAlertSummary,
};
// Phase 4.1: Free scammer detection providers (no authentication required)
pub use scam_sniffer::{  // ScamSniffer API client
    ScamSnifferClient, ScamSnifferRiskResponse, RugPullEvent,
};
pub use misttrack::{  // MistTrack (SlowMist) API client
    MistTrackClient, MistTrackRiskResponse, RiskLevel,
};
pub use amlbot::{  // AML Bot API client
    AmlBotClient, AmlBotCheckResponse,
};
pub use scammer_detector::{  // Unified scammer detection aggregator
    ScammerDetector, ScammerDetectionResult, ProviderTimingBreakdown,
};
pub use honeypot_is::{  // Phase 4.1: Honeypot.is enhanced detection
    HoneypotIsClient, HoneypotIsResponse, HoneypotIsResult, HoneypotToken,
};
pub use lp_lock::{  // Phase 4.3: LP Lock Detection
    LPLockClient, LPLockResult, check_all_locks,
};
pub use slither_analyzer::{  // Phase 4.2: Slither static analysis
    SlitherAnalyzer, SlitherAnalysisResult, SlitherVulnerability,
};
pub use source_checker::{  // Phase 4: Source code risk analysis
    SourceAnalysis, SourceCodeScanner, SourceRiskFlag, analyze_source_code,
};
pub use tokensniffer_v2::{  // Phase 4.2: TokenSniffer v2 security scoring
    TokenSnifferV2Client, TokenSnifferV2Response, TokenSnifferV2Result, SnifferTest,
};

// Re-export scanner types
pub use scanner::{ApiError, ApiResult, ScanResult, ScannerStats, TimingBreakdown, TokenScanner};

use anyhow::{Context, Result, anyhow};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Default timeout for API requests in seconds
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Default number of retries for failed requests
pub const DEFAULT_RETRY_COUNT: u32 = 3;

/// Default base delay for exponential backoff in milliseconds
pub const DEFAULT_BACKOFF_BASE_MS: u64 = 100;

/// Maximum delay between retries in milliseconds
pub const DEFAULT_BACKOFF_MAX_MS: u64 = 5000;

/// API configuration loaded from environment
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Dexscreener configuration
    pub dexscreener: DexscreenerConfig,
    /// Etherscan API key
    pub etherscan_api_key: Option<String>,
    /// GoPlus configuration
    pub goplus: GoPlusConfig,
    /// The Graph configuration
    pub thegraph: TheGraphConfig,
}

/// Dexscreener-specific configuration
#[derive(Debug, Clone)]
pub struct DexscreenerConfig {
    /// Whether Dexscreener is enabled
    pub enabled: bool,
    /// Request timeout
    pub timeout: Duration,
    /// Number of retries
    pub retry_count: u32,
}

impl Default for DexscreenerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_count: DEFAULT_RETRY_COUNT,
        }
    }
}

/// GoPlus-specific configuration
#[derive(Debug, Clone)]
pub struct GoPlusConfig {
    /// API key for authentication
    pub api_key: Option<String>,
    /// API secret
    pub api_secret: Option<String>,
}

impl Default for GoPlusConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            api_secret: None,
        }
    }
}

/// The Graph-specific configuration
#[derive(Debug, Clone)]
pub struct TheGraphConfig {
    /// Whether The Graph is enabled
    pub enabled: bool,
    /// GraphQL endpoint URL for Uniswap V3
    pub endpoint_uniswap_v3: String,
    /// GraphQL endpoint URL for Uniswap V2
    pub endpoint_uniswap_v2: String,
    /// Request timeout
    pub timeout: Duration,
    /// Number of retries
    pub retry_count: u32,
}

impl Default for TheGraphConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint_uniswap_v3: "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3".to_string(),
            endpoint_uniswap_v2: "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v2".to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_count: DEFAULT_RETRY_COUNT,
        }
    }
}

impl ApiConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        // Parse Dexscreener config
        let dexscreener_enabled = std::env::var("DEXSCREENER_ENABLED")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true);

        let dexscreener_timeout_ms = std::env::var("DEXSCREENER_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS * 1000);

        let dexscreener_retry = std::env::var("DEXSCREENER_RETRY_COUNT")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(DEFAULT_RETRY_COUNT);

        // Parse GoPlus config
        // Support both API_KEY (legacy) and GOPLUS_API_KEY (new) environment variables
        let goplus_api_key = std::env::var("GOPLUS_API_KEY")
            .ok()
            .or_else(|| std::env::var("API_KEY").ok());
        let goplus_api_secret = std::env::var("API_SECRET").ok();

        // Parse The Graph config
        let thegraph_enabled = std::env::var("THEGRAPH_ENABLED")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true);
        let thegraph_timeout_ms = std::env::var("THEGRAPH_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS * 1000);
        let thegraph_retry = std::env::var("THEGRAPH_RETRY_COUNT")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(DEFAULT_RETRY_COUNT);

        Self {
            dexscreener: DexscreenerConfig {
                enabled: dexscreener_enabled,
                timeout: Duration::from_millis(dexscreener_timeout_ms),
                retry_count: dexscreener_retry,
            },
            etherscan_api_key: std::env::var("ETHERSCAN_API_KEY").ok(),
            goplus: GoPlusConfig {
                api_key: goplus_api_key,
                api_secret: goplus_api_secret,
            },
            thegraph: TheGraphConfig {
                enabled: thegraph_enabled,
                endpoint_uniswap_v3: std::env::var("THEGRAPH_ENDPOINT_UNISWAP_V3")
                    .unwrap_or_else(|_| "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3".to_string()),
                endpoint_uniswap_v2: std::env::var("THEGRAPH_ENDPOINT_UNISWAP_V2")
                    .unwrap_or_else(|_| "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v2".to_string()),
                timeout: Duration::from_millis(thegraph_timeout_ms),
                retry_count: thegraph_retry,
            },
        }
    }
}

/// Create an HTTP client with the specified timeout
pub fn create_http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("rust-token-scanner/0.1.0")
        .build()
        .context("Failed to create HTTP client")
}

/// Execute a request with retry logic and exponential backoff
///
/// # Arguments
/// * `max_retries` - Maximum number of retry attempts
/// * `base_delay_ms` - Base delay in milliseconds for exponential backoff
/// * `max_delay_ms` - Maximum delay between retries
/// * `request_fn` - Async function that performs the request
///
/// # Returns
/// * `Ok(T)` - Successful result from the request function
/// * `Err(E)` - Error after all retries exhausted
#[allow(unused_assignments)]
pub async fn with_retry<T, E, F, Fut>(
    max_retries: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
    mut request_fn: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut last_error: Option<E> = None;
    let mut attempt = 0;

    loop {
        attempt += 1;
        debug!("API request attempt {} of {}", attempt, max_retries + 1);

        match request_fn().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                if attempt > max_retries {
                    break;
                }

                // Calculate delay with exponential backoff
                let delay_ms = (base_delay_ms * 2u64.pow(attempt - 1)).min(max_delay_ms);
                warn!(
                    "API request failed (attempt {}): {}. Retrying in {}ms...",
                    attempt,
                    last_error.as_ref().unwrap(),
                    delay_ms
                );

                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }

    Err(last_error.unwrap())
}

/// Validate a token address format
///
/// # Arguments
/// * `address` - The token address to validate
/// * `chain` - The blockchain network
///
/// # Returns
/// * `Ok(())` - Address is valid
/// * `Err(anyhow::Error)` - Address is invalid
pub fn validate_token_address(address: &str, chain: &str) -> Result<()> {
    // Basic validation: must start with 0x and be 42 characters (including 0x)
    if !address.starts_with("0x") {
        return Err(anyhow!("Invalid token address: must start with 0x"));
    }

    if address.len() != 42 {
        return Err(anyhow!(
            "Invalid token address length: expected 42, got {}",
            address.len()
        ));
    }

    // Validate hex characters
    let hex_part = &address[2..];
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "Invalid token address: contains non-hex characters"
        ));
    }

    // Chain-specific validation could be added here
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" | "bsc" | "polygon" | "arbitrum" | "optimism" | "base" | "avalanche"
        | "fantom" => Ok(()),
        _ => {
            warn!(
                "Unknown chain '{}', proceeding with basic validation",
                chain
            );
            Ok(())
        }
    }
}

/// Map chain name to GoPlus chain identifier
pub fn chain_to_goplus_id(chain: &str) -> &'static str {
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" => "eth",
        "bsc" | "binance" | "bnb" => "bsc",
        "polygon" | "matic" => "matic",
        "arbitrum" => "arbitrum",
        "optimism" => "optimism",
        "base" => "base",
        "avalanche" | "avax" => "avax",
        "fantom" | "ftm" => "ftm",
        _ => "eth", // Default to Ethereum
    }
}

/// Map chain name to Honeypot.is chain identifier
pub fn chain_to_honeypot_id(chain: &str) -> &'static str {
    match chain.to_lowercase().as_str() {
        "ethereum" | "eth" => "eth",
        "bsc" | "binance" | "bnb" => "bsc",
        _ => "eth", // Default to Ethereum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_config_from_env() {
        let config = ApiConfig::from_env();
        assert!(config.dexscreener.enabled);
        // Etherscan key should be loaded from .env
        assert!(config.etherscan_api_key.is_some());
    }

    #[test]
    fn test_validate_token_address_valid() {
        assert!(
            validate_token_address("0x1234567890123456789012345678901234567890", "ethereum")
                .is_ok()
        );
        assert!(
            validate_token_address("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", "bsc").is_ok()
        );
    }

    #[test]
    fn test_validate_token_address_invalid_prefix() {
        let result = validate_token_address("1234567890123456789012345678901234567890", "ethereum");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must start with 0x")
        );
    }

    #[test]
    fn test_validate_token_address_invalid_length() {
        let result = validate_token_address("0x1234", "ethereum");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length"));
    }

    #[test]
    fn test_validate_token_address_invalid_chars() {
        let result =
            validate_token_address("0xGGGG567890123456789012345678901234567890", "ethereum");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-hex"));
    }

    #[test]
    fn test_chain_to_goplus_id() {
        assert_eq!(chain_to_goplus_id("ethereum"), "eth");
        assert_eq!(chain_to_goplus_id("ETH"), "eth");
        assert_eq!(chain_to_goplus_id("bsc"), "bsc");
        assert_eq!(chain_to_goplus_id("polygon"), "matic");
        assert_eq!(chain_to_goplus_id("unknown"), "eth");
    }

    #[test]
    fn test_chain_to_honeypot_id() {
        assert_eq!(chain_to_honeypot_id("ethereum"), "eth");
        assert_eq!(chain_to_honeypot_id("bsc"), "bsc");
        assert_eq!(chain_to_honeypot_id("unknown"), "eth");
    }

    #[tokio::test]
    async fn test_with_retry_success_first_try() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        let result = with_retry::<_, anyhow::Error, _, _>(3, 10, 100, move || {
            let count = call_count_clone.clone();
            async move {
                let mut c = count.lock().await;
                *c += 1;
                Ok::<_, anyhow::Error>("success".to_string())
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(*call_count.lock().await, 1);
    }

    #[tokio::test]
    async fn test_with_retry_success_after_failures() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        let result = with_retry::<_, anyhow::Error, _, _>(3, 10, 100, move || {
            let count = call_count_clone.clone();
            async move {
                let mut c = count.lock().await;
                *c += 1;
                let current = *c;
                if current < 3 {
                    Err(anyhow::anyhow!("temporary error"))
                } else {
                    Ok::<_, anyhow::Error>("success".to_string())
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(*call_count.lock().await, 3);
    }

    #[tokio::test]
    async fn test_with_retry_all_failures() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        let result = with_retry::<_, anyhow::Error, _, _>(2, 10, 100, move || {
            let count = call_count_clone.clone();
            async move {
                let mut c = count.lock().await;
                *c += 1;
                Err::<String, _>(anyhow::anyhow!("persistent error"))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(*call_count.lock().await, 3); // Initial + 2 retries
    }
}
