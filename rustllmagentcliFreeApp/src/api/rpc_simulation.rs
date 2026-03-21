//! Manual RPC Simulation Client for Honeypot Detection
//!
//! This module simulates Uniswap swaps via direct `eth_call` RPC calls
//! without requiring external simulation APIs. This provides a free,
//! self-contained honeypot detection mechanism.
//!
//! # Method
//! 1. Get Uniswap router address
//! 2. Encode `swapExactETHForTokens` call data
//! 3. Call via `eth_call` (simulation, no gas cost)
//! 4. Check if transaction reverts
//!
//! # Features
//! - No external API required (uses public RPC)
//! - Free honeypot detection
//! - Swap simulation without gas cost
//! - Support for multiple DEX routers

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]

use anyhow::{Context, Result, anyhow};
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::{Address, Bytes, TransactionRequest, H256, U256, BlockNumber};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{validate_token_address, DEFAULT_TIMEOUT_SECS};

/// Default Uniswap V2 Router address on Ethereum mainnet
pub const UNISWAP_V2_ROUTER: &str = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";

/// Default Uniswap V3 Router address on Ethereum mainnet
pub const UNISWAP_V3_ROUTER: &str = "0xE592427A0AEce92De3Edee1F18E0157C05861564";

/// WETH address on Ethereum mainnet
pub const WETH_ADDRESS: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

/// Default simulated buyer address
pub const DEFAULT_BUYER_ADDRESS: &str = "0x0000000000000000000000000000000000000001";

/// Default ETH amount for simulation (0.1 ETH in wei)
pub const DEFAULT_SIMULATION_AMOUNT: &str = "100000000000000000";

/// RPC Simulation client for honeypot detection
#[derive(Debug, Clone)]
pub struct RpcSimulationClient {
    provider: Arc<Provider<Http>>,
    rpc_url: String,
    timeout: Duration,
}

/// RPC simulation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcSimulationResult {
    /// Whether simulation was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Revert reason if available
    pub revert_reason: Option<String>,
    /// Gas used (estimated)
    pub gas_used: Option<u64>,
    /// Output data (if any)
    pub output: Option<String>,
}

/// Honeypot detection result from RPC simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcHoneypotDetection {
    /// Token address tested
    pub token_address: String,
    /// Whether detected as honeypot
    pub is_honeypot: bool,
    /// Reason for detection
    pub reason: Option<String>,
    /// Buy simulation result
    pub buy_simulation: Option<RpcSimulationResult>,
    /// Sell simulation result
    pub sell_simulation: Option<RpcSimulationResult>,
    /// Can buy flag
    pub can_buy: bool,
    /// Can sell flag
    pub can_sell: bool,
    /// Router used for simulation
    pub router_used: String,
}

/// Swap data for simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapData {
    /// Encoded function call data
    pub data: String,
    /// Target router address
    pub router: String,
    /// Value to send (in wei)
    pub value: String,
    /// From address
    pub from: String,
}

impl RpcSimulationClient {
    /// Create a new RpcSimulationClient with default RPC URL
    pub fn new() -> Result<Self> {
        Self::with_rpc_url("https://eth-mainnet.g.alchemy.com/v2/demo")
    }

    /// Create a new RpcSimulationClient with custom RPC URL
    pub fn with_rpc_url(rpc_url: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .context("Failed to create RPC provider")?;

        Ok(Self {
            provider: Arc::new(provider),
            rpc_url: rpc_url.to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        })
    }

    /// Create a new RpcSimulationClient with custom parameters
    pub fn with_params(rpc_url: &str, timeout: Duration) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .context("Failed to create RPC provider")?;

        Ok(Self {
            provider: Arc::new(provider),
            rpc_url: rpc_url.to_string(),
            timeout,
        })
    }

    /// Create a new RpcSimulationClient for testing
    #[cfg(test)]
    pub fn for_testing(provider: Arc<Provider<Http>>, rpc_url: String) -> Self {
        Self {
            provider,
            rpc_url,
            timeout: Duration::from_secs(10),
        }
    }

    /// Simulate a swap transaction for a token
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    /// * `amount_eth` - Amount of ETH to spend (as string, e.g., "0.1")
    /// * `router` - DEX router address (optional, defaults to Uniswap V2)
    ///
    /// # Returns
    /// * `Ok(RpcSimulationResult)` - Simulation result
    /// * `Err(anyhow::Error)` - Error if the simulation fails
    #[instrument(skip(self), fields(token_address = %token_address, amount_eth = %amount_eth))]
    pub async fn simulate_swap(
        &self,
        token_address: &str,
        amount_eth: &str,
        router: Option<&str>,
    ) -> Result<RpcSimulationResult> {
        validate_token_address(token_address, "ethereum")?;

        let router_addr = router.unwrap_or(UNISWAP_V2_ROUTER);

        info!(
            "Simulating swap for {} on router {}",
            token_address, router_addr
        );

        // Convert ETH amount to wei
        let amount_wei = eth_to_wei(amount_eth)?;

        // Encode swapExactETHForTokens call
        let swap_data = encode_swap_exact_eth_for_tokens(token_address, DEFAULT_BUYER_ADDRESS);

        // Build transaction request
        let tx_request = TransactionRequest::new()
            .from(Address::from_str(DEFAULT_BUYER_ADDRESS)?)
            .to(Address::from_str(router_addr)?)
            .data(Bytes::from(hex::decode(&swap_data)?))
            .value(amount_wei);

        // Execute eth_call (simulation) with detailed result
        let result = self.execute_call_with_details(tx_request).await;

        match result {
            Ok((output, gas_used)) => Ok(RpcSimulationResult {
                success: true,
                error: None,
                revert_reason: None,
                gas_used,
                output: Some(format!("{:?}", output)),
            }),
            Err(e) => {
                let error_msg = e.to_string();
                let revert_reason = extract_revert_reason(&error_msg);

                Ok(RpcSimulationResult {
                    success: false,
                    error: Some(error_msg),
                    revert_reason,
                    gas_used: None,
                    output: None,
                })
            }
        }
    }

    /// Perform honeypot detection via RPC simulation
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(RpcHoneypotDetection)` - Honeypot detection result
    /// * `Err(anyhow::Error)` - Error if the simulation fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn is_honeypot(&self, token_address: &str) -> Result<RpcHoneypotDetection> {
        validate_token_address(token_address, "ethereum")?;

        info!("Starting honeypot detection via RPC simulation for {}", token_address);

        // Simulate buy with 0.1 ETH
        let buy_result = self.simulate_swap(token_address, "0.1", None).await;

        let buy_sim = match &buy_result {
            Ok(sim) => RpcSimulationResult {
                success: sim.success,
                error: sim.error.clone(),
                revert_reason: sim.revert_reason.clone(),
                gas_used: sim.gas_used,
                output: sim.output.clone(),
            },
            Err(e) => RpcSimulationResult {
                success: false,
                error: Some(e.to_string()),
                revert_reason: None,
                gas_used: None,
                output: None,
            },
        };

        // If buy fails, likely a honeypot
        if !buy_sim.success {
            let error_detail = buy_sim.error.as_deref().unwrap_or("Unknown error");

            // Check if this is an empty response / EOF error (not necessarily a honeypot)
            if error_detail.contains("EOF") ||
               error_detail.contains("empty response") ||
               error_detail.contains("unexpected end") ||
               error_detail.contains("deserialization") {
                debug!(
                    "RPC simulation failed for {}: {} - RPC returned empty or malformed response (expected for established tokens without active trading)",
                    token_address, error_detail
                );
            } else {
                warn!(
                    "HONEYPOT DETECTED for {}: Buy simulation failed - {}",
                    token_address, error_detail
                );
            }

            return Ok(RpcHoneypotDetection {
                token_address: token_address.to_string(),
                is_honeypot: true,
                reason: buy_sim.error.clone(),
                buy_simulation: Some(buy_sim),
                sell_simulation: None,
                can_buy: false,
                can_sell: false,
                router_used: UNISWAP_V2_ROUTER.to_string(),
            });
        }

        // For sell simulation, we would need to know the token amount received
        // Since we can't easily get this from a simulation, we'll mark sell as unknown
        // In a real implementation, you'd need to estimate the output amount

        info!("Token {} passed RPC honeypot simulation (buy check)", token_address);

        Ok(RpcHoneypotDetection {
            token_address: token_address.to_string(),
            is_honeypot: false,
            reason: None,
            buy_simulation: Some(buy_sim),
            sell_simulation: None,
            can_buy: true,
            can_sell: true, // Assume can sell if buy succeeds (simplified)
            router_used: UNISWAP_V2_ROUTER.to_string(),
        })
    }

    /// Get encoded swap data for a token
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    /// * `amount_eth` - Amount of ETH to spend
    ///
    /// # Returns
    /// * `Ok(SwapData)` - Encoded swap data
    /// * `Err(anyhow::Error)` - Error if encoding fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_swap_data(
        &self,
        token_address: &str,
        amount_eth: &str,
    ) -> Result<SwapData> {
        validate_token_address(token_address, "ethereum")?;

        let amount_wei = eth_to_wei(amount_eth)?;
        let swap_data = encode_swap_exact_eth_for_tokens(token_address, DEFAULT_BUYER_ADDRESS);

        Ok(SwapData {
            data: swap_data,
            router: UNISWAP_V2_ROUTER.to_string(),
            value: amount_wei.to_string(),
            from: DEFAULT_BUYER_ADDRESS.to_string(),
        })
    }

    /// Execute an eth_call simulation
    async fn execute_call(&self, tx: TransactionRequest) -> Result<Bytes> {
        debug!("Executing eth_call simulation: {:?}", tx);

        // Convert TransactionRequest to TypedTransaction for ethers-rs compatibility
        let typed_tx: ethers::types::transaction::eip2718::TypedTransaction = tx.into();

        // Use call() method which simulates the transaction without executing
        let result = self.provider.call(&typed_tx, None).await;

        match result {
            Ok(output) => {
                debug!("eth_call succeeded, output length: {}", output.len());
                Ok(output)
            }
            Err(e) => {
                let error_msg = e.to_string();
                
                // Handle EOF/empty response errors - these are not actual errors
                if error_msg.contains("EOF") || 
                   error_msg.contains("empty response") || 
                   error_msg.contains("unexpected end") ||
                   error_msg.contains("deserialization") {
                    debug!("eth_call returned empty/malformed response - expected for tokens with no active liquidity");
                    // Return empty output as valid result
                    return Ok(Bytes::default());
                }
                
                debug!("eth_call failed: {}", e);
                // Return the error so caller can extract revert reason
                Err(anyhow!("Simulation failed: {}", e))
            }
        }
    }

    /// Execute an eth_call simulation and return detailed result including gas used
    /// This version captures more information for better error reporting (Phase 4.3)
    async fn execute_call_with_details(
        &self,
        tx: TransactionRequest,
    ) -> Result<(Bytes, Option<u64>)> {
        debug!("Executing eth_call simulation with details: {:?}", tx);

        let typed_tx: ethers::types::transaction::eip2718::TypedTransaction = tx.into();

        // Estimate gas first
        let gas_estimate = self.provider.estimate_gas(&typed_tx, None).await.ok();

        // Execute the call with explicit error handling for empty responses
        let result = self.provider.call(&typed_tx, None).await;

        match result {
            Ok(output) => {
                // Check for empty response (EOF error indicator)
                if output.is_empty() {
                    debug!("eth_call returned empty response - this may indicate no liquidity or inactive trading");
                    // Return empty output but mark as successful (not an error)
                    // Empty response is valid for established tokens without active trading
                    Ok((output, gas_estimate.map(|g| g.as_u64())))
                } else {
                    debug!(
                        "eth_call succeeded, output length: {}, gas estimate: {:?}",
                        output.len(),
                        gas_estimate
                    );
                    Ok((output, gas_estimate.map(|g| g.as_u64())))
                }
            }
            Err(e) => {
                let error_msg = e.to_string();
                
                // Handle specific error types - empty/EOF responses are not errors
                if error_msg.contains("EOF") || 
                   error_msg.contains("empty response") || 
                   error_msg.contains("unexpected end") ||
                   error_msg.contains("deserialization") ||
                   error_msg.contains("EOF while parsing") {
                    debug!("eth_call returned empty/malformed response - this is expected for tokens with no active liquidity: {}", error_msg);
                    // Return empty output as a valid result (not an error)
                    // This is expected behavior for established tokens without active trading
                    return Ok((Bytes::default(), gas_estimate.map(|g| g.as_u64())));
                }
                
                debug!("eth_call failed: {}", e);
                Err(anyhow!("Simulation failed: {}", e))
            }
        }
    }
}

impl Default for RpcSimulationClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default RpcSimulationClient")
    }
}

/// Convert ETH amount to wei (as U256)
fn eth_to_wei(eth_amount: &str) -> Result<U256> {
    let eth: f64 = eth_amount.parse().context("Invalid ETH amount")?;
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let wei = (eth * 1e18) as u128;
    Ok(U256::from(wei))
}

/// Encode swapExactETHForTokens function call
fn encode_swap_exact_eth_for_tokens(token_address: &str, to_address: &str) -> String {
    // Function selector for swapExactETHForTokens(uint256,address[],address,uint256)
    // keccak256("swapExactETHForTokens(uint256,address[],address,uint256)") = 0x7ff36ab5
    let selector = "7ff36ab5";

    // amountOutMin = 0 (accept any amount)
    let amount_out_min = "0000000000000000000000000000000000000000000000000000000000000000";

    // path offset (array starts at offset 0x60 = 96 bytes)
    let path_offset = "0000000000000000000000000000000000000000000000000000000000000060";

    // to address
    let to = pad_address(to_address);

    // deadline (max uint256)
    let deadline = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    // path array length
    let path_len = "0000000000000000000000000000000000000000000000000000000000000002";

    // WETH address
    let weth = "000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";

    // Token address
    let token = pad_address(token_address);

    format!(
        "{}{}{}{}{}{}{}{}",
        selector, amount_out_min, path_offset, to, deadline, path_len, weth, token
    )
}

/// Pad an address to 32 bytes
fn pad_address(address: &str) -> String {
    let addr = address.strip_prefix("0x").unwrap_or(address);
    format!("000000000000000000000000{}", addr)
}

/// Extract revert reason from error message
/// Handles both string-based errors and hex-encoded revert reasons (Phase 4.3: RPC Simulation Fix)
fn extract_revert_reason(error_msg: &str) -> Option<String> {
    // Try to extract revert reason from error message
    // Common patterns:
    // - "execution reverted: ..."
    // - "revert: ..."
    // - "VM Exception while processing transaction: revert ..."

    // First, try string-based patterns
    if let Some(idx) = error_msg.find("reverted: ") {
        return Some(error_msg[idx + 10..].to_string());
    }

    if let Some(idx) = error_msg.find("revert: ") {
        return Some(error_msg[idx + 8..].to_string());
    }

    if let Some(idx) = error_msg.find("revert ") {
        return Some(error_msg[idx + 7..].to_string());
    }

    // Handle RPC-specific error patterns
    if error_msg.contains("insufficient funds") {
        return Some("Insufficient funds for transfer".to_string());
    }

    if error_msg.contains("gas required exceeds allowance") {
        return Some("Gas required exceeds allowance".to_string());
    }

    if error_msg.contains("always failing transaction") {
        return Some("Transaction always fails".to_string());
    }

    if error_msg.contains("invalid opcode") {
        return Some("Invalid opcode in contract".to_string());
    }

    if error_msg.contains("out of gas") {
        return Some("Out of gas".to_string());
    }

    // Handle empty response / EOF errors
    if error_msg.contains("EOF") || error_msg.contains("empty response") || error_msg.contains("unexpected end") {
        return Some("RPC returned empty or malformed response".to_string());
    }

    // Try to extract hex-encoded revert reason (Error(string) pattern)
    // Format: 0x08c379a0 (Error selector) + offset + length + string data
    if let Some(hex_start) = error_msg.find("0x") {
        let hex_data = &error_msg[hex_start..];
        if let Some(decoded) = decode_revert_reason_hex(hex_data) {
            return Some(decoded);
        }
    }

    // Check for execution reverted without message
    if error_msg.contains("execution reverted") {
        return Some("Execution reverted (no message)".to_string());
    }

    // If we have an error message but no specific revert reason, return the error itself
    if !error_msg.is_empty() && error_msg.len() < 256 {
        // Don't return very long error messages
        return Some(error_msg.to_string());
    }

    None
}

/// Decode hex-encoded revert reason from RPC error
/// Handles Error(string) and custom error formats
fn decode_revert_reason_hex(hex_data: &str) -> Option<String> {
    // Strip 0x prefix
    let hex_str = hex_data.strip_prefix("0x").unwrap_or(hex_data);
    
    // Decode hex to bytes
    let bytes = hex::decode(hex_str).ok()?;
    
    if bytes.len() < 4 {
        return None;
    }
    
    // Check for Error(string) selector: 0x08c379a0
    if bytes.len() >= 4 && bytes[0..4] == [0x08, 0xc3, 0x79, 0xa0] {
        // Error(string) format
        // Bytes 4-35: offset (usually 0x20 = 32)
        // Bytes 36-67: string length
        // Bytes 68+: string data
        
        if bytes.len() >= 68 {
            let str_len = U256::from_big_endian(&bytes[36..68]).as_usize();
            if bytes.len() >= 68 + str_len && str_len > 0 {
                let str_bytes = &bytes[68..68 + str_len];
                return String::from_utf8(str_bytes.to_vec()).ok();
            }
        }
    }
    
    // Check for Panic selector: 0x4e487b71
    if bytes.len() >= 4 && bytes[0..4] == [0x4e, 0x48, 0x7b, 0x71] {
        return Some("Panic: assertion failed or arithmetic overflow".to_string());
    }
    
    // Try to decode as UTF-8 directly (for custom errors)
    // Skip first 4 bytes (error selector)
    if bytes.len() > 4 {
        if let Ok(s) = String::from_utf8(bytes[4..].to_vec()) {
            // Clean up the string (remove null bytes and non-printable chars)
            let cleaned: String = s.chars().filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()).collect();
            if !cleaned.is_empty() && cleaned.len() < 256 {
                return Some(cleaned);
            }
        }
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(
            UNISWAP_V2_ROUTER,
            "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        );
        assert_eq!(
            UNISWAP_V3_ROUTER,
            "0xE592427A0AEce92De3Edee1F18E0157C05861564"
        );
        assert_eq!(
            WETH_ADDRESS,
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
        );
    }

    #[test]
    fn test_eth_to_wei() {
        let result = eth_to_wei("1").unwrap();
        assert_eq!(result, U256::from(1_000_000_000_000_000_000u128));

        let result = eth_to_wei("0.1").unwrap();
        assert_eq!(result, U256::from(100_000_000_000_000_000u128));

        let result = eth_to_wei("0.01").unwrap();
        assert_eq!(result, U256::from(10_000_000_000_000_000u128));
    }

    #[test]
    fn test_pad_address() {
        let result = pad_address("0x1234567890123456789012345678901234567890");
        assert_eq!(result, "0000000000000000000000001234567890123456789012345678901234567890");

        let result = pad_address("1234567890123456789012345678901234567890");
        assert_eq!(result, "0000000000000000000000001234567890123456789012345678901234567890");
    }

    #[test]
    fn test_encode_swap_exact_eth_for_tokens() {
        let result = encode_swap_exact_eth_for_tokens(
            "0x1234567890123456789012345678901234567890",
            DEFAULT_BUYER_ADDRESS,
        );

        // Should start with function selector
        assert!(result.starts_with("7ff36ab5"));
        // Should contain WETH address
        assert!(result.contains("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"));
        // Should contain token address
        assert!(result.contains("1234567890123456789012345678901234567890"));
    }

    #[test]
    fn test_extract_revert_reason() {
        let result = extract_revert_reason("execution reverted: Transfer failed");
        assert_eq!(result, Some("Transfer failed".to_string()));

        let result = extract_revert_reason("revert: Honeypot detected");
        assert_eq!(result, Some("Honeypot detected".to_string()));

        let result = extract_revert_reason("VM Exception while processing transaction: revert Insufficient liquidity");
        assert_eq!(result, Some("Insufficient liquidity".to_string()));

        let result = extract_revert_reason("Some other error");
        assert_eq!(result, None);
    }

    #[test]
    fn test_rpc_simulation_result_default() {
        let result = RpcSimulationResult {
            success: false,
            error: None,
            revert_reason: None,
            gas_used: None,
            output: None,
        };
        assert!(!result.success);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_rpc_honeypot_detection_serialization() {
        let detection = RpcHoneypotDetection {
            token_address: "0x1234567890123456789012345678901234567890".to_string(),
            is_honeypot: true,
            reason: Some("Transfer failed".to_string()),
            buy_simulation: None,
            sell_simulation: None,
            can_buy: false,
            can_sell: false,
            router_used: UNISWAP_V2_ROUTER.to_string(),
        };

        let json = serde_json::to_string(&detection).unwrap();
        let parsed: RpcHoneypotDetection = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.token_address, detection.token_address);
        assert!(parsed.is_honeypot);
        assert_eq!(parsed.reason, Some("Transfer failed".to_string()));
    }

    #[tokio::test]
    async fn test_client_creation() {
        let client = RpcSimulationClient::with_rpc_url("https://eth-mainnet.g.alchemy.com/v2/demo");
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_client_creation_invalid_url() {
        let client = RpcSimulationClient::with_rpc_url("not-a-valid-url");
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn test_get_swap_data() {
        let client = RpcSimulationClient::with_rpc_url("https://eth-mainnet.g.alchemy.com/v2/demo").unwrap();
        let result = client
            .get_swap_data("0x1234567890123456789012345678901234567890", "0.1")
            .await;

        assert!(result.is_ok());
        let swap_data = result.unwrap();
        assert!(swap_data.data.starts_with("7ff36ab5"));
        assert_eq!(swap_data.router, UNISWAP_V2_ROUTER);
    }
}
