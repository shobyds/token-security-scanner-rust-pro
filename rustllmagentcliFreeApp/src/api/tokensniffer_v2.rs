//! TokenSniffer v2 API Client for Security Scoring
//!
//! TokenSniffer provides automated token security analysis including:
//! - Contract verification status
//! - Holder distribution analysis
//! - Trading cooldown detection
//! - Blacklist function detection
//! - Overall security score (0-100)
//!
//! # API
//! - Endpoint: `https://tokensniffer.com/api/v2/tokens/{chain_id}/{contract}`
//! - Free tier: Use `apikey=test` for public tokens
//!
//! # Features
//! - Security scoring (0-100)
//! - Test suite results
//! - Contract analysis
//! - Holder analysis

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::unused_self)]
#![allow(clippy::uninlined_format_args)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, DEFAULT_TIMEOUT_SECS,
    create_http_client, validate_token_address, with_retry,
};

/// TokenSniffer v2 API client
#[derive(Debug, Clone)]
pub struct TokenSnifferV2Client {
    http_client: Client,
    base_url: String,
    api_key: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// TokenSniffer v2 response structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenSnifferV2Response {
    /// Token address
    #[serde(default)]
    pub address: String,
    /// Chain ID
    #[serde(rename = "chainId", default)]
    pub chain_id: u32,
    /// Security score (0-100)
    #[serde(default)]
    pub score: u8,
    /// Test results
    #[serde(default)]
    pub tests: Vec<SnifferTest>,
    /// Token metadata
    #[serde(default)]
    pub token: Option<TokenMetadata>,
    /// Contract metadata
    #[serde(rename = "contract", default)]
    pub contract: Option<ContractMetadata>,
}

/// Individual test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnifferTest {
    /// Test name
    #[serde(rename = "testName")]
    pub name: String,
    /// Test description
    #[serde(rename = "description")]
    pub description: String,
    /// Whether test passed
    #[serde(rename = "status")]
    pub passed: bool,
    /// Risk level
    #[serde(rename = "riskLevel", default)]
    pub risk_level: Option<String>,
}

/// Token metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenMetadata {
    /// Token name
    #[serde(default)]
    pub name: String,
    /// Token symbol
    #[serde(default)]
    pub symbol: String,
    /// Token decimals
    #[serde(default)]
    pub decimals: u32,
    /// Total supply
    #[serde(rename = "totalSupply", default)]
    pub total_supply: String,
    /// Holder count
    #[serde(rename = "holderCount", default)]
    pub holder_count: u64,
}

/// Contract metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractMetadata {
    /// Contract name
    #[serde(default)]
    pub name: String,
    /// Compiler version
    #[serde(rename = "compilerVersion", default)]
    pub compiler_version: String,
    /// Whether verified
    #[serde(default)]
    pub verified: bool,
    /// Whether proxy
    #[serde(default)]
    pub proxy: bool,
    /// Whether mintable
    #[serde(default)]
    pub mintable: bool,
}

/// TokenSniffer analysis result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenSnifferV2Result {
    /// Token address
    pub token_address: String,
    /// Security score (0-100)
    pub security_score: u8,
    /// Source code available
    pub source_verified: bool,
    /// Can pause trading
    pub can_pause_trading: bool,
    /// Has blacklist function
    pub has_blacklist: bool,
    /// Has trading cooldown
    pub has_trading_cooldown: bool,
    /// Ownership risk
    pub ownership_risk: bool,
    /// Is honeypot
    pub is_honeypot: bool,
    /// Is mintable
    pub is_mintable: bool,
    /// Is proxy
    pub is_proxy: bool,
    /// Test results summary
    pub tests_passed: u32,
    /// Total tests
    pub total_tests: u32,
    /// Test failure details
    pub failed_tests: Vec<String>,
}

impl TokenSnifferV2Client {
    /// Create a new TokenSnifferV2Client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new TokenSnifferV2Client with custom configuration
    pub fn with_config(_config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))?;

        // Try to load .env file first
        let _ = dotenvy::dotenv();

        // Get API key from environment (use "test" for free tier)
        let api_key = std::env::var("TOKENSNIFFER_API_KEY").unwrap_or_else(|_| "test".to_string());
        let enabled = true; // Always enabled, even with test key

        info!("TokenSniffer v2 client initialized successfully");

        Ok(Self {
            http_client,
            base_url: "https://tokensniffer.com".to_string(),
            api_key,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_count: DEFAULT_RETRY_COUNT,
            enabled,
        })
    }

    /// Create a new TokenSnifferV2Client with custom parameters
    pub fn with_params(
        api_key: &str,
        timeout: Duration,
        retry_count: u32,
    ) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://tokensniffer.com".to_string(),
            api_key: api_key.to_string(),
            timeout,
            retry_count,
            enabled: true,
        })
    }

    /// Create a new TokenSnifferV2Client for testing
    #[cfg(test)]
    pub fn for_testing(base_url: String, http_client: Client, api_key: &str) -> Self {
        Self {
            http_client,
            base_url,
            api_key: api_key.to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
        }
    }

    /// Analyze a token for security risks
    ///
    /// # Arguments
    /// * `token_address` - The token contract address
    /// * `chain_id` - Chain ID (1 for Ethereum, 56 for BSC)
    ///
    /// # Returns
    /// * `Ok(TokenSnifferV2Result)` - Analysis result
    /// * `Err(anyhow::Error)` - Error if analysis fails
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn analyze_token(
        &self,
        token_address: &str,
        chain_id: u32,
    ) -> Result<TokenSnifferV2Result> {
        validate_token_address(token_address, "ethereum")?;

        if !self.enabled {
            return Ok(TokenSnifferV2Result::default());
        }

        info!("Analyzing token {} with TokenSniffer v2", token_address);

        let url = format!(
            "{}/api/v2/tokens/{}/{}?apikey={}",
            self.base_url, chain_id, token_address, self.api_key
        );

        debug!("Fetching token analysis from TokenSniffer: {}", url);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .get(&url)
                    .send()
                    .await
                    .context("Failed to send request to TokenSniffer")?;

                let status = response.status();
                debug!("TokenSniffer response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    Ok(body)
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Token not found: {}", token_address))
                } else if status.as_u16() == 401 {
                    Err(anyhow!("TokenSniffer API key invalid"))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by TokenSniffer"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    Err(anyhow!("TokenSniffer API error: {} - {}", status, error_body))
                }
            },
        )
        .await?;

        let parsed: TokenSnifferV2Response =
            serde_json::from_str(&response_data).context("Failed to parse TokenSniffer response")?;

        let result = self.parse_response(&parsed);

        info!(
            "TokenSniffer v2 analysis completed for {}: score={}/{}",
            token_address, result.security_score, 100
        );

        Ok(result)
    }

    /// Parse TokenSniffer response
    fn parse_response(&self, response: &TokenSnifferV2Response) -> TokenSnifferV2Result {
        let mut result = TokenSnifferV2Result {
            token_address: response.address.clone(),
            security_score: response.score,
            ..Default::default()
        };

        // Analyze tests
        let mut tests_passed = 0u32;
        let mut failed_tests = Vec::new();

        for test in &response.tests {
            if test.passed {
                tests_passed += 1;
            } else {
                failed_tests.push(format!("{}: {}", test.name, test.description));
            }

            // Map test names to result fields
            match test.name.to_lowercase().as_str() {
                name if name.contains("source") && name.contains("available") => {
                    result.source_verified = test.passed;
                }
                name if name.contains("transfer") && name.contains("pause") => {
                    result.can_pause_trading = !test.passed; // If test fails, can pause
                }
                name if name.contains("blacklist") => {
                    result.has_blacklist = !test.passed; // If test fails, has blacklist
                }
                name if name.contains("cooldown") => {
                    result.has_trading_cooldown = !test.passed;
                }
                name if name.contains("ownership") || name.contains("take") => {
                    result.ownership_risk = !test.passed;
                }
                name if name.contains("honeypot") => {
                    result.is_honeypot = !test.passed;
                }
                name if name.contains("mint") => {
                    result.is_mintable = !test.passed;
                }
                name if name.contains("proxy") => {
                    result.is_proxy = !test.passed;
                }
                _ => {}
            }
        }

        // Get mintable and proxy from contract metadata
        if let Some(ref contract) = response.contract {
            result.is_mintable = contract.mintable;
            result.is_proxy = contract.proxy;
        }

        result.tests_passed = tests_passed;
        result.total_tests = response.tests.len() as u32;
        result.failed_tests = failed_tests;

        result
    }
}

impl Default for TokenSnifferV2Client {
    fn default() -> Self {
        Self::new().expect("Failed to create default TokenSnifferV2Client")
    }
}

// Default constants
const DEFAULT_RETRY_COUNT: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> TokenSnifferV2Client {
        let http_client = Client::builder()
            .http1_only()
            .build()
            .unwrap();

        TokenSnifferV2Client {
            http_client,
            base_url: mock_server_url.to_string(),
            api_key: "test".to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_analyze_token_success() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
            "chainId": 1,
            "score": 85,
            "tests": [
                {
                    "testName": "Is source code available?",
                    "description": "Contract source code is verified",
                    "status": true,
                    "riskLevel": "LOW"
                },
                {
                    "testName": "Can owner pause trading?",
                    "description": "Owner cannot pause trading",
                    "status": true,
                    "riskLevel": "LOW"
                },
                {
                    "testName": "Has blacklist?",
                    "description": "No blacklist function",
                    "status": true,
                    "riskLevel": "LOW"
                },
                {
                    "testName": "Has trading cooldown?",
                    "description": "No trading cooldown",
                    "status": true,
                    "riskLevel": "LOW"
                }
            ],
            "token": {
                "name": "Uniswap",
                "symbol": "UNI",
                "decimals": 18,
                "totalSupply": "1000000000000000000000000000",
                "holderCount": 379558
            }
        }"#;

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .analyze_token("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", 1)
            .await;

        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.security_score, 85);
        assert!(analysis.source_verified);
        assert!(!analysis.can_pause_trading);
        assert!(!analysis.has_blacklist);
        assert_eq!(analysis.tests_passed, 4);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_analyze_token_with_risks() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "address": "0x1234567890123456789012345678901234567890",
            "chainId": 1,
            "score": 35,
            "tests": [
                {
                    "testName": "Is source code available?",
                    "description": "Contract source code is NOT verified",
                    "status": false,
                    "riskLevel": "HIGH"
                },
                {
                    "testName": "Can owner pause trading?",
                    "description": "Owner CAN pause trading",
                    "status": false,
                    "riskLevel": "HIGH"
                },
                {
                    "testName": "Has blacklist?",
                    "description": "Contract HAS blacklist function",
                    "status": false,
                    "riskLevel": "HIGH"
                },
                {
                    "testName": "Is honeypot?",
                    "description": "Token appears to be a honeypot",
                    "status": false,
                    "riskLevel": "CRITICAL"
                }
            ]
        }"#;

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .analyze_token("0x1234567890123456789012345678901234567890", 1)
            .await;

        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.security_score, 35);
        assert!(!analysis.source_verified);
        assert!(analysis.can_pause_trading);
        assert!(analysis.has_blacklist);
        assert!(analysis.is_honeypot);
        assert_eq!(analysis.tests_passed, 0);
        assert_eq!(analysis.total_tests, 4);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_analyze_token_not_found() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .with_body("Not Found")
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .analyze_token("0x1234567890123456789012345678901234567890", 1)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));

        mock.assert_async().await;
    }

    #[test]
    fn test_token_sniffer_v2_result_default() {
        let result = TokenSnifferV2Result::default();
        assert_eq!(result.security_score, 0);
        assert!(!result.source_verified);
        assert_eq!(result.tests_passed, 0);
    }
}
