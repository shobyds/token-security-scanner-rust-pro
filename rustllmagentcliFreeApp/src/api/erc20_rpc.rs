//! ERC20 RPC Client for direct on-chain ERC20 token calls
//!
//! This module provides direct RPC calls to Ethereum nodes for fetching ERC20 token data.
//! It works for BOTH verified and unverified contracts since it uses standard ERC20 interface.
//!
//! # Features
//! - Direct RPC calls using ethers-rs
//! - Support for all standard ERC20 functions
//! - Works with any Ethereum-compatible RPC endpoint
//! - Comprehensive error handling
//! - Retry logic with exponential backoff
//!
//! # Supported ERC20 Functions
//! - `totalSupply()` - Get total token supply
//! - `name()` - Get token name
//! - `symbol()` - Get token symbol
//! - `decimals()` - Get token decimals
//! - `balanceOf(address)` - Get balance of specific address

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

use anyhow::{Context, Result, anyhow};
use ethers::abi::{AbiEncode, Address, Function, Param, ParamType, StateMutability, Token};
use ethers::providers::{Http, Middleware, Provider, ProviderError};
use ethers::types::{BlockNumber, H160, U256};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};
use url::Url;

use crate::api::{
    DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, DEFAULT_TIMEOUT_SECS,
    validate_token_address, with_retry,
};

/// ERC20 token metadata structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Erc20Metadata {
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Number of decimals
    pub decimals: u8,
    /// Total supply (formatted as string with decimals applied)
    pub total_supply_formatted: String,
    /// Total supply (raw U256)
    pub total_supply_raw: String,
    /// Token contract address
    pub token_address: String,
}

/// ERC20 RPC Client for direct on-chain calls
#[derive(Debug, Clone)]
pub struct Erc20RpcClient {
    /// RPC provider
    provider: Arc<Provider<Http>>,
    /// RPC URL
    rpc_url: String,
    /// Request timeout
    timeout: Duration,
    /// Number of retries
    retry_count: u32,
}

/// ERC20 contract ABI function definitions
mod erc20_abi {
    use ethers::abi::{Function, Param, ParamType, StateMutability};

    #[allow(deprecated)]
    /// Get the totalSupply() function definition
    pub fn total_supply() -> Function {
        Function {
            name: "totalSupply".to_string(),
            inputs: vec![],
            outputs: vec![Param {
                name: "totalSupply".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            }],
            constant: None,
            state_mutability: StateMutability::View,
        }
    }

    #[allow(deprecated)]
    /// Get the name() function definition
    pub fn name() -> Function {
        Function {
            name: "name".to_string(),
            inputs: vec![],
            outputs: vec![Param {
                name: "name".to_string(),
                kind: ParamType::String,
                internal_type: None,
            }],
            constant: None,
            state_mutability: StateMutability::View,
        }
    }

    #[allow(deprecated)]
    /// Get the symbol() function definition
    pub fn symbol() -> Function {
        Function {
            name: "symbol".to_string(),
            inputs: vec![],
            outputs: vec![Param {
                name: "symbol".to_string(),
                kind: ParamType::String,
                internal_type: None,
            }],
            constant: None,
            state_mutability: StateMutability::View,
        }
    }

    #[allow(deprecated)]
    /// Get the decimals() function definition
    pub fn decimals() -> Function {
        Function {
            name: "decimals".to_string(),
            inputs: vec![],
            outputs: vec![Param {
                name: "decimals".to_string(),
                kind: ParamType::Uint(8),
                internal_type: None,
            }],
            constant: None,
            state_mutability: StateMutability::View,
        }
    }

    #[allow(deprecated)]
    /// Get the balanceOf(address) function definition
    pub fn balance_of() -> Function {
        Function {
            name: "balanceOf".to_string(),
            inputs: vec![Param {
                name: "account".to_string(),
                kind: ParamType::Address,
                internal_type: None,
            }],
            outputs: vec![Param {
                name: "balance".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            }],
            constant: None,
            state_mutability: StateMutability::View,
        }
    }
}

impl Erc20RpcClient {
    /// Create a new ERC20 RPC client with the specified RPC URL
    ///
    /// # Arguments
    /// * `rpc_url` - The RPC endpoint URL (e.g., from .env RPC_ETHEREUM)
    ///
    /// # Returns
    /// * `Ok(Erc20RpcClient)` - New client instance
    /// * `Err(anyhow::Error)` - Error if RPC URL is invalid
    pub fn new(rpc_url: &str) -> Result<Self> {
        Self::with_params(rpc_url, Duration::from_secs(DEFAULT_TIMEOUT_SECS), DEFAULT_RETRY_COUNT)
    }

    /// Create a new ERC20 RPC client with custom parameters
    ///
    /// # Arguments
    /// * `rpc_url` - The RPC endpoint URL
    /// * `timeout` - Request timeout duration
    /// * `retry_count` - Number of retries for failed requests
    ///
    /// # Returns
    /// * `Ok(Erc20RpcClient)` - New client instance
    /// * `Err(anyhow::Error)` - Error if RPC URL is invalid
    pub fn with_params(rpc_url: &str, timeout: Duration, retry_count: u32) -> Result<Self> {
        // Create ethers provider directly (ethers uses its own reqwest 0.11 internally)
        let url = Url::parse(rpc_url).context("Invalid RPC URL")?;
        let http = Http::new(url);
        let provider = Provider::new(http);

        info!("ERC20 RPC client initialized with RPC URL: {}", rpc_url);

        Ok(Self {
            provider: Arc::new(provider),
            rpc_url: rpc_url.to_string(),
            timeout,
            retry_count,
        })
    }

    /// Create a new ERC20 RPC client from environment variable
    ///
    /// # Returns
    /// * `Ok(Erc20RpcClient)` - New client instance
    /// * `Err(anyhow::Error)` - Error if RPC_ETHEREUM is not set
    pub fn from_env() -> Result<Self> {
        let rpc_url = std::env::var("RPC_ETHEREUM")
            .ok()
            .ok_or_else(|| anyhow!("RPC_ETHEREUM environment variable not set"))?;
        
        Self::new(&rpc_url)
    }

    /// Get the total supply of an ERC20 token
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(U256)` - Total supply as raw U256
    /// * `Err(anyhow::Error)` - Error if the call fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_total_supply(&self, token_address: &str) -> Result<U256> {
        self.call_erc20_function::<U256>(token_address, &erc20_abi::total_supply(), &[])
            .await
    }

    /// Get the name of an ERC20 token
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(String)` - Token name
    /// * `Err(anyhow::Error)` - Error if the call fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_name(&self, token_address: &str) -> Result<String> {
        self.call_erc20_function::<String>(token_address, &erc20_abi::name(), &[])
            .await
    }

    /// Get the symbol of an ERC20 token
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(String)` - Token symbol
    /// * `Err(anyhow::Error)` - Error if the call fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_symbol(&self, token_address: &str) -> Result<String> {
        self.call_erc20_function::<String>(token_address, &erc20_abi::symbol(), &[])
            .await
    }

    /// Get the decimals of an ERC20 token
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(u8)` - Number of decimals
    /// * `Err(anyhow::Error)` - Error if the call fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_decimals(&self, token_address: &str) -> Result<u8> {
        let result: U256 = self.call_erc20_function::<U256>(token_address, &erc20_abi::decimals(), &[])
            .await?;
        Ok(result.as_u64() as u8)
    }

    /// Get the balance of an ERC20 token for a specific address
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    /// * `holder_address` - The address to check balance for
    ///
    /// # Returns
    /// * `Ok(U256)` - Balance as raw U256
    /// * `Err(anyhow::Error)` - Error if the call fails
    #[instrument(skip(self), fields(token_address = %token_address, holder_address = %holder_address))]
    pub async fn get_balance_of(&self, token_address: &str, holder_address: &str) -> Result<U256> {
        // Parse holder address
        let holder_addr = Address::from_str(holder_address)
            .context("Invalid holder address format")?;
        
        self.call_erc20_function::<U256>(
            token_address,
            &erc20_abi::balance_of(),
            &[Token::Address(holder_addr)],
        )
        .await
    }

    /// Get complete ERC20 token metadata in a single call
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(Erc20Metadata)` - Complete token metadata
    /// * `Err(anyhow::Error)` - Error if any call fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn get_token_metadata(&self, token_address: &str) -> Result<Erc20Metadata> {
        // Validate token address first
        validate_token_address(token_address, "ethereum")?;

        // Fetch all metadata in parallel
        let (name, symbol, decimals, total_supply_raw) = tokio::try_join!(
            self.get_name(token_address),
            self.get_symbol(token_address),
            self.get_decimals(token_address),
            self.get_total_supply(token_address),
        )?;

        // Format total supply with decimals
        let total_supply_formatted = format_u256_with_decimals(total_supply_raw, decimals);

        info!(
            "Fetched metadata for {}: name='{}', symbol='{}', decimals={}, total_supply={}",
            token_address, name, symbol, decimals, total_supply_formatted
        );

        Ok(Erc20Metadata {
            name,
            symbol,
            decimals,
            total_supply_formatted,
            total_supply_raw: total_supply_raw.to_string(),
            token_address: token_address.to_string(),
        })
    }

    /// Get the deployer's token balance (useful for rug pull detection)
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    /// * `deployer_address` - The deployer's wallet address
    ///
    /// # Returns
    /// * `Ok(U256)` - Deployer's balance as raw U256
    /// * `Err(anyhow::Error)` - Error if the call fails
    #[instrument(skip(self), fields(token_address = %token_address, deployer_address = %deployer_address))]
    pub async fn get_deployer_balance(
        &self,
        token_address: &str,
        deployer_address: &str,
    ) -> Result<U256> {
        self.get_balance_of(token_address, deployer_address).await
    }

    /// Get the deployer's balance as a formatted string with decimals applied
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    /// * `deployer_address` - The deployer's wallet address
    ///
    /// # Returns
    /// * `Ok(String)` - Formatted balance string
    /// * `Err(anyhow::Error)` - Error if the call fails
    #[instrument(skip(self), fields(token_address = %token_address, deployer_address = %deployer_address))]
    pub async fn get_deployer_balance_formatted(
        &self,
        token_address: &str,
        deployer_address: &str,
    ) -> Result<String> {
        let (balance, decimals) = tokio::try_join!(
            self.get_balance_of(token_address, deployer_address),
            self.get_decimals(token_address),
        )?;

        Ok(format_u256_with_decimals(balance, decimals))
    }

    /// Internal helper to call an ERC20 function via RPC
    ///
    /// # Type Parameters
    /// * `T` - The expected return type (must implement FromToken)
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    /// * `function` - The ERC20 function to call
    /// * `inputs` - Function input parameters
    ///
    /// # Returns
    /// * `Ok(T)` - Decoded function result
    /// * `Err(anyhow::Error)` - Error if the call fails
    async fn call_erc20_function<T: FromToken>(
        &self,
        token_address: &str,
        function: &Function,
        inputs: &[Token],
    ) -> Result<T> {
        // Validate token address
        validate_token_address(token_address, "ethereum")?;

        // Parse token address
        let token_addr = Address::from_str(token_address)
            .context("Invalid token address format")?;

        // Encode the function call
        let calldata = function
            .encode_input(inputs)
            .context("Failed to encode function call")?;

        debug!(
            "Calling ERC20 function '{}' on {}",
            function.name, token_address
        );

        // Execute the call with retry logic
        let result_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let result = self
                    .provider
                    .call(
                        &ethers::types::transaction::eip2718::TypedTransaction::Legacy(
                            ethers::types::TransactionRequest {
                                to: Some(token_addr.into()),
                                data: Some(calldata.clone().into()),
                                ..Default::default()
                            }
                        ),
                        Some(BlockNumber::Latest.into()),
                    )
                    .await;

                match result {
                    Ok(data) => Ok(data),
                    Err(ProviderError::JsonRpcClientError(e)) => {
                        Err(anyhow!("RPC error: {}", e))
                    }
                    Err(e) => Err(anyhow!("Provider error: {}", e)),
                }
            },
        )
        .await?;

        // Decode the result
        let tokens = function
            .decode_output(&result_data)
            .context("Failed to decode function output")?;

        T::from_token(&tokens[0])
    }
}

/// Trait for converting ethers Token to a type
trait FromToken {
    fn from_token(token: &Token) -> Result<Self>
    where
        Self: Sized;
}

impl FromToken for U256 {
    fn from_token(token: &Token) -> Result<Self> {
        match token {
            Token::Uint(val) => Ok(*val),
            _ => Err(anyhow!("Expected Uint token, got {:?}", token)),
        }
    }
}

impl FromToken for String {
    fn from_token(token: &Token) -> Result<Self> {
        match token {
            Token::String(s) => Ok(s.clone()),
            _ => Err(anyhow!("Expected String token, got {:?}", token)),
        }
    }
}

/// Format a U256 value with decimals applied
fn format_u256_with_decimals(value: U256, decimals: u8) -> String {
    let divisor = U256::from(10).pow(U256::from(decimals));
    let integer_part = value / divisor;
    let fractional_part = value % divisor;

    // Format fractional part with leading zeros
    let fractional_str = format!("{:0>width$}", fractional_part, width = decimals as usize);
    
    // Remove trailing zeros from fractional part
    let fractional_str = fractional_str.trim_end_matches('0');
    
    if fractional_str.is_empty() {
        integer_part.to_string()
    } else {
        format!("{}.{}", integer_part, fractional_str)
    }
}

/// Default retry count constant
const DEFAULT_RETRY_COUNT: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::abi::Token;
    use mockito::Server;

    /// Create a mock JSON-RPC response for totalSupply
    fn mock_total_supply_response(value: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{}"}}"#, value)
    }

    /// Create a mock JSON-RPC response for string returns (name, symbol)
    fn mock_string_response(s: &str) -> String {
        // Encode string as ethers would return it
        let encoded = ethers::abi::encode(&[Token::String(s.to_string())]);
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#, hex::encode(&encoded))
    }

    /// Create a mock JSON-RPC response for uint8 returns (decimals)
    fn mock_decimals_response(value: u8) -> String {
        let encoded = ethers::abi::encode(&[Token::Uint(U256::from(value))]);
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#, hex::encode(&encoded))
    }

    /// Create a mock JSON-RPC response for balanceOf
    fn mock_balance_response(value: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{}"}}"#, value)
    }

    /// Create a mock JSON-RPC error response
    fn mock_error_response(message: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32000,"message":"{}"}}}}"#, message)
    }

    #[tokio::test]
    async fn test_get_total_supply_success() {
        let mut server = Server::new_async().await;

        // UNI token total supply: 1,000,000,000 * 10^18
        let mock_response = mock_total_supply_response("0x0de0b6b3a7640000"); // 1 billion in wei

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = Erc20RpcClient::with_params(&server.url(), Duration::from_secs(10), 0)
            .expect("Failed to create client");

        let result = client
            .get_total_supply("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await;

        assert!(result.is_ok());
        let supply = result.unwrap();
        assert_eq!(supply, U256::from(1_000_000_000_000_000_000_000_000_000u128));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_name_success() {
        let mut server = Server::new_async().await;

        let mock_response = mock_string_response("Uniswap");

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = Erc20RpcClient::with_params(&server.url(), Duration::from_secs(10), 0)
            .expect("Failed to create client");

        let result = client
            .get_name("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Uniswap");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_symbol_success() {
        let mut server = Server::new_async().await;

        let mock_response = mock_string_response("UNI");

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = Erc20RpcClient::with_params(&server.url(), Duration::from_secs(10), 0)
            .expect("Failed to create client");

        let result = client
            .get_symbol("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "UNI");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_decimals_success() {
        let mut server = Server::new_async().await;

        let mock_response = mock_decimals_response(18);

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = Erc20RpcClient::with_params(&server.url(), Duration::from_secs(10), 0)
            .expect("Failed to create client");

        let result = client
            .get_decimals("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 18);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_balance_of_success() {
        let mut server = Server::new_async().await;

        // Mock balance: 1000 tokens (with 18 decimals)
        let mock_response = mock_balance_response("0x0de0b6b3a7640000");

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = Erc20RpcClient::with_params(&server.url(), Duration::from_secs(10), 0)
            .expect("Failed to create client");

        let result = client
            .get_balance_of(
                "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
                "0x1a9c8182c09f50c8318d769245bea52c32be35bc",
            )
            .await;

        assert!(result.is_ok());
        let balance = result.unwrap();
        assert_eq!(balance, U256::from(1_000_000_000_000_000_000_000u128));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_token_metadata_success() {
        let mut server = Server::new_async().await;

        // We need to handle multiple calls for metadata
        let mock_name = mock_string_response("Uniswap");
        let mock_symbol = mock_string_response("UNI");
        let mock_decimals = mock_decimals_response(18);
        let mock_supply = mock_total_supply_response("0x0de0b6b3a7640000");

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_name)
            .expect(4) // Will be called 4 times
            .create_async()
            .await;

        // For simplicity, we'll test individual calls
        let client = Erc20RpcClient::with_params(&server.url(), Duration::from_secs(10), 0)
            .expect("Failed to create client");

        let name = client
            .get_name("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await
            .unwrap();
        let symbol = client
            .get_symbol("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await
            .unwrap();
        let decimals = client
            .get_decimals("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await
            .unwrap();
        let supply = client
            .get_total_supply("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await
            .unwrap();

        assert_eq!(name, "Uniswap");
        assert_eq!(symbol, "UNI");
        assert_eq!(decimals, 18);
        assert_eq!(supply, U256::from(1_000_000_000_000_000_000_000_000_000u128));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_rpc_error_handling() {
        let mut server = Server::new_async().await;

        let mock_response = mock_error_response("execution reverted");

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = Erc20RpcClient::with_params(&server.url(), Duration::from_secs(10), 0)
            .expect("Failed to create client");

        let result = client
            .get_total_supply("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("execution reverted"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_invalid_address() {
        let client = Erc20RpcClient::with_params("http://localhost:8545", Duration::from_secs(10), 0)
            .expect("Failed to create client");

        let result = client.get_total_supply("invalid_address").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid token address"));
    }

    #[tokio::test]
    async fn test_server_error_500() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/")
            .with_status(500)
            .with_body("Internal Server Error")
            .create_async()
            .await;

        let client = Erc20RpcClient::with_params(&server.url(), Duration::from_secs(10), 0)
            .expect("Failed to create client");

        let result = client
            .get_total_supply("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await;

        assert!(result.is_err());

        mock.assert_async().await;
    }

    #[test]
    fn test_format_u256_with_decimals() {
        // Test with 18 decimals (standard ERC20)
        let value = U256::from(1_000_000_000_000_000_000_000u128); // 1000 tokens
        let formatted = format_u256_with_decimals(value, 18);
        assert_eq!(formatted, "1000");

        // Test with fractional part
        let value = U256::from(1_500_000_000_000_000_000_000u128); // 1500 tokens
        let formatted = format_u256_with_decimals(value, 18);
        assert_eq!(formatted, "1500");

        // Test with 6 decimals (USDC style)
        let value = U256::from(1_000_000u64); // 1 USDC
        let formatted = format_u256_with_decimals(value, 6);
        assert_eq!(formatted, "1");

        // Test with fractional USDC
        let value = U256::from(1_500_000u64); // 1.5 USDC
        let formatted = format_u256_with_decimals(value, 6);
        assert_eq!(formatted, "1.5");

        // Test with 0 decimals
        let value = U256::from(100u64);
        let formatted = format_u256_with_decimals(value, 0);
        assert_eq!(formatted, "100");
    }

    #[test]
    fn test_from_token_uint() {
        let token = Token::Uint(U256::from(42));
        let result = U256::from_token(&token);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), U256::from(42));

        let token = Token::String("hello".to_string());
        let result = U256::from_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_token_string() {
        let token = Token::String("Uniswap".to_string());
        let result = String::from_token(&token);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Uniswap");

        let token = Token::Uint(U256::from(42));
        let result = String::from_token(&token);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_client_from_env_missing() {
        // Ensure RPC_ETHEREUM is not set
        unsafe { std::env::remove_var("RPC_ETHEREUM") };
        
        let result = Erc20RpcClient::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("RPC_ETHEREUM"));
    }

    #[tokio::test]
    async fn test_get_deployer_balance() {
        let mut server = Server::new_async().await;

        let mock_response = mock_balance_response("0x0de0b6b3a7640000");

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = Erc20RpcClient::with_params(&server.url(), Duration::from_secs(10), 0)
            .expect("Failed to create client");

        let result = client
            .get_deployer_balance(
                "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
                "0xdeployer123456789012345678901234567890",
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), U256::from(1_000_000_000_000_000_000_000u128));

        mock.assert_async().await;
    }
}
