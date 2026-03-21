//! Dedaub Contract Analysis API Client
//!
//! Dedaub provides static analysis of smart contracts to detect security vulnerabilities.
//! The API analyzes contract bytecode and source code to identify potential security issues.
//!
//! # Features
//! - External call pattern detection
//! - Reentrancy vulnerability detection
//! - Delegatecall usage analysis
//! - Access control issues detection
//! - Arithmetic vulnerability detection
//! - Overall security scoring
//!
//! # API Documentation
//! - https://api.dedaub.com/
//! - Free tier available with signup

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, DEFAULT_TIMEOUT_SECS,
    create_http_client, validate_token_address, with_retry,
};

/// Dedaub API client for contract security analysis
#[derive(Debug, Clone)]
pub struct DedaubClient {
    http_client: Client,
    base_url: String,
    api_key: Option<String>,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// Full analysis result from Dedaub
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DedaubAnalysisResult {
    /// Contract address analyzed
    pub contract_address: String,
    /// Blockchain network
    pub chain: String,
    /// Overall security score (0-100)
    pub security_score: Option<DedaubSecurityScore>,
    /// List of detected vulnerabilities
    pub vulnerabilities: Vec<DedaubVulnerability>,
    /// External call patterns detected
    pub external_calls: Vec<ExternalCallPattern>,
    /// Reentrancy analysis result
    pub reentrancy_analysis: Option<ReentrancyAnalysis>,
    /// Delegatecall usage detected
    pub has_delegatecall: bool,
    /// Access control issues detected
    pub access_control_issues: Vec<AccessControlIssue>,
    /// Arithmetic vulnerabilities detected
    pub arithmetic_issues: Vec<ArithmeticIssue>,
    /// Analysis timestamp
    pub analysis_timestamp: Option<u64>,
    /// Raw analysis data
    pub raw_data: Option<serde_json::Value>,
}

/// Individual vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedaubVulnerability {
    /// Vulnerability type/ID
    pub vuln_type: String,
    /// Severity level (critical, high, medium, low, info)
    pub severity: String,
    /// Vulnerability title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Location in contract (function name, line number)
    pub location: Option<String>,
    /// Remediation suggestions
    pub remediation: Option<String>,
    /// CWE identifier if applicable
    pub cwe_id: Option<String>,
    /// Confidence score (0-1)
    pub confidence: Option<f64>,
}

/// Security scoring structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DedaubSecurityScore {
    /// Overall score (0-100, higher is better)
    pub overall_score: u8,
    /// Security grade (A, B, C, D, F)
    pub grade: String,
    /// Breakdown by category
    pub category_scores: HashMap<String, u8>,
    /// Number of critical issues
    pub critical_count: u32,
    /// Number of high severity issues
    pub high_count: u32,
    /// Number of medium severity issues
    pub medium_count: u32,
    /// Number of low severity issues
    pub low_count: u32,
}

/// External call pattern detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalCallPattern {
    /// Target contract address
    pub target: String,
    /// Call type (call, delegatecall, staticcall)
    pub call_type: String,
    /// Function signature
    pub function_signature: Option<String>,
    /// Is the call to a known contract
    pub is_known_contract: bool,
    /// Risk level of this call
    pub risk_level: String,
}

/// Reentrancy analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReentrancyAnalysis {
    /// Is the contract vulnerable to reentrancy
    pub is_vulnerable: bool,
    /// Vulnerable functions
    pub vulnerable_functions: Vec<String>,
    /// Reentrancy guards detected
    pub has_reentrancy_guard: bool,
    /// State changes after external calls
    pub state_after_external_call: bool,
    /// Risk assessment
    pub risk_level: String,
}

/// Access control issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlIssue {
    /// Issue type
    pub issue_type: String,
    /// Description
    pub description: String,
    /// Affected functions
    pub affected_functions: Vec<String>,
    /// Severity
    pub severity: String,
}

/// Arithmetic issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArithmeticIssue {
    /// Issue type (overflow, underflow, precision loss)
    pub issue_type: String,
    /// Description
    pub description: String,
    /// Location
    pub location: Option<String>,
    /// Severity
    pub severity: String,
}

/// Chain support for Dedaub
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedaubChain {
    Ethereum,
    Bsc,
    Polygon,
    Arbitrum,
    Optimism,
    Avalanche,
    Fantom,
}

impl DedaubChain {
    /// Convert chain name to Dedaub chain ID
    pub fn to_chain_id(&self) -> &'static str {
        match self {
            DedaubChain::Ethereum => "eth",
            DedaubChain::Bsc => "bsc",
            DedaubChain::Polygon => "polygon",
            DedaubChain::Arbitrum => "arbitrum",
            DedaubChain::Optimism => "optimism",
            DedaubChain::Avalanche => "avalanche",
            DedaubChain::Fantom => "fantom",
        }
    }

    /// Parse chain name to DedaubChain
    pub fn from_chain_name(chain: &str) -> Self {
        match chain.to_lowercase().as_str() {
            "ethereum" | "eth" => DedaubChain::Ethereum,
            "bsc" | "binance" | "bnb" => DedaubChain::Bsc,
            "polygon" | "matic" => DedaubChain::Polygon,
            "arbitrum" => DedaubChain::Arbitrum,
            "optimism" | "opt" => DedaubChain::Optimism,
            "avalanche" | "avax" => DedaubChain::Avalanche,
            "fantom" | "ftm" => DedaubChain::Fantom,
            _ => DedaubChain::Ethereum,
        }
    }
}

impl DedaubClient {
    /// Create a new Dedaub client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new Dedaub client with custom configuration
    pub fn with_config(config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))?;

        // Try to load .env file first
        let _ = dotenvy::dotenv();

        // Get API key from environment
        let api_key = std::env::var("DEDAUB_API_KEY").ok();
        let enabled = api_key.is_some();

        if enabled {
            info!("Dedaub client initialized successfully");
        } else {
            debug!("Dedaub API key not configured - client disabled");
        }

        Ok(Self {
            http_client,
            base_url: "https://api.dedaub.com".to_string(),
            api_key,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_count: DEFAULT_RETRY_COUNT,
            enabled,
        })
    }

    /// Create a new Dedaub client with custom parameters
    pub fn with_params(
        api_key: Option<&str>,
        timeout: Duration,
        retry_count: u32,
    ) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: "https://api.dedaub.com".to_string(),
            api_key: api_key.map(String::from),
            timeout,
            retry_count,
            enabled: api_key.is_some(),
        })
    }

    /// Create a new Dedaub client for testing with custom base URL
    #[cfg(test)]
    pub fn for_testing(
        base_url: String,
        http_client: Client,
        api_key: Option<&str>,
    ) -> Self {
        Self {
            http_client,
            base_url,
            api_key: api_key.map(String::from),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: api_key.is_some(),
        }
    }

    /// Analyze a contract for security vulnerabilities
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to analyze
    /// * `chain` - The blockchain network
    ///
    /// # Returns
    /// * `Ok(DedaubAnalysisResult)` - Full analysis result
    /// * `Err(anyhow::Error)` - Error if the analysis fails
    #[instrument(skip(self), fields(contract_address = %contract_address, chain = %chain))]
    pub async fn analyze_contract(
        &self,
        contract_address: &str,
        chain: &str,
    ) -> Result<DedaubAnalysisResult> {
        if !self.enabled {
            return Err(anyhow!("Dedaub API is disabled (no API key configured)"));
        }

        validate_token_address(contract_address, chain)?;

        info!("Starting Dedaub analysis for {} on {}", contract_address, chain);

        let chain_id = DedaubChain::from_chain_name(chain).to_chain_id();

        // Build analysis request
        let request = DedaubAnalysisRequest {
            address: contract_address.to_string(),
            chain: chain_id.to_string(),
            include_source: true,
            include_bytecode: true,
        };

        let result = self.execute_analysis(request).await?;

        info!(
            "Dedaub analysis completed for {} - Score: {:?}",
            contract_address,
            result.security_score.as_ref().map(|s| s.overall_score)
        );

        Ok(result)
    }

    /// Check for external call patterns in a contract
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to check
    ///
    /// # Returns
    /// * `Ok(Vec<ExternalCallPattern>)` - List of external call patterns
    /// * `Err(anyhow::Error)` - Error if the check fails
    #[instrument(skip(self), fields(contract_address = %contract_address))]
    pub async fn check_external_calls(
        &self,
        contract_address: &str,
    ) -> Result<Vec<ExternalCallPattern>> {
        if !self.enabled {
            return Err(anyhow!("Dedaub API is disabled"));
        }

        let analysis = self.analyze_contract(contract_address, "ethereum").await?;
        Ok(analysis.external_calls)
    }

    /// Check for reentrancy vulnerabilities in a contract
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to check
    ///
    /// # Returns
    /// * `Ok(ReentrancyAnalysis)` - Reentrancy analysis result
    /// * `Err(anyhow::Error)` - Error if the check fails
    #[instrument(skip(self), fields(contract_address = %contract_address))]
    pub async fn check_reentrancy(
        &self,
        contract_address: &str,
    ) -> Result<ReentrancyAnalysis> {
        if !self.enabled {
            return Err(anyhow!("Dedaub API is disabled"));
        }

        let analysis = self.analyze_contract(contract_address, "ethereum").await?;
        analysis
            .reentrancy_analysis
            .ok_or_else(|| anyhow!("Reentrancy analysis not available"))
    }

    /// Get overall security score for a contract
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to analyze
    ///
    /// # Returns
    /// * `Ok(DedaubSecurityScore)` - Security score
    /// * `Err(anyhow::Error)` - Error if the analysis fails
    #[instrument(skip(self), fields(contract_address = %contract_address))]
    pub async fn get_security_score(
        &self,
        contract_address: &str,
    ) -> Result<DedaubSecurityScore> {
        if !self.enabled {
            return Err(anyhow!("Dedaub API is disabled"));
        }

        let analysis = self.analyze_contract(contract_address, "ethereum").await?;
        analysis
            .security_score
            .ok_or_else(|| anyhow!("Security score not available"))
    }

    /// Execute the analysis request
    async fn execute_analysis(
        &self,
        request: DedaubAnalysisRequest,
    ) -> Result<DedaubAnalysisResult> {
        let url = format!("{}/api/v1/analyze", self.base_url);

        debug!("Executing Dedaub analysis: {}", url);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .post(&url)
                    .header("accept", "application/json")
                    .header("content-type", "application/json")
                    .header(
                        "X-API-Key",
                        self.api_key
                            .as_ref()
                            .ok_or_else(|| anyhow!("No API key configured"))?,
                    )
                    .json(&request)
                    .send()
                    .await
                    .context("Failed to send request to Dedaub")?;

                let status = response.status();
                debug!("Dedaub response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    debug!("Dedaub response body length: {}", body.len());
                    Ok(body)
                } else if status.as_u16() == 401 {
                    Err(anyhow!("Dedaub API key invalid"))
                } else if status.as_u16() == 403 {
                    Err(anyhow!("Dedaub access forbidden"))
                } else if status.as_u16() == 404 {
                    Err(anyhow!("Contract not found: {}", request.address))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Dedaub"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    Err(anyhow!("Dedaub API error: {} - {}", status, error_body))
                }
            },
        )
        .await?;

        // Parse the response
        let parsed: DedaubApiResponse =
            serde_json::from_str(&response_data).context("Failed to parse Dedaub response")?;

        // Convert to our result structure
        let result = self.parse_analysis_response(parsed, &request.address)?;

        Ok(result)
    }

    /// Parse the API response into our result structure
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn parse_analysis_response(
        &self,
        response: DedaubApiResponse,
        contract_address: &str,
    ) -> Result<DedaubAnalysisResult> {
        // Parse security score
        let security_score = response.score.map(|score_data| DedaubSecurityScore {
            overall_score: score_data.overall.unwrap_or(50),
            grade: score_data.grade.unwrap_or_else(|| "C".to_string()),
            category_scores: score_data.categories.unwrap_or_default(),
            critical_count: score_data.critical_count.unwrap_or(0),
            high_count: score_data.high_count.unwrap_or(0),
            medium_count: score_data.medium_count.unwrap_or(0),
            low_count: score_data.low_count.unwrap_or(0),
        });

        // Parse vulnerabilities
        let vulnerabilities: Vec<DedaubVulnerability> = response
            .issues
            .unwrap_or_default()
            .into_iter()
            .map(|issue| DedaubVulnerability {
                vuln_type: issue.vuln_type,
                severity: issue.severity,
                title: issue.title,
                description: issue.description,
                location: issue.location,
                remediation: issue.remediation,
                cwe_id: issue.cwe_id,
                confidence: issue.confidence,
            })
            .collect();

        // Parse external calls
        let external_calls: Vec<ExternalCallPattern> = response
            .external_calls
            .unwrap_or_default()
            .into_iter()
            .map(|call| ExternalCallPattern {
                target: call.target,
                call_type: call.call_type,
                function_signature: call.function_signature,
                is_known_contract: call.is_known_contract.unwrap_or(false),
                risk_level: call.risk_level.unwrap_or_else(|| "medium".to_string()),
            })
            .collect();

        // Parse reentrancy analysis
        let reentrancy_analysis = response.reentrancy.map(|re| ReentrancyAnalysis {
            is_vulnerable: re.is_vulnerable,
            vulnerable_functions: re.vulnerable_functions,
            has_reentrancy_guard: re.has_reentrancy_guard,
            state_after_external_call: re.state_after_external_call,
            risk_level: re.risk_level,
        });

        // Parse access control issues
        let access_control_issues: Vec<AccessControlIssue> = response
            .access_control
            .unwrap_or_default()
            .into_iter()
            .map(|ac| AccessControlIssue {
                issue_type: ac.issue_type,
                description: ac.description,
                affected_functions: ac.affected_functions,
                severity: ac.severity,
            })
            .collect();

        // Parse arithmetic issues
        let arithmetic_issues: Vec<ArithmeticIssue> = response
            .arithmetic
            .unwrap_or_default()
            .into_iter()
            .map(|ar| ArithmeticIssue {
                issue_type: ar.issue_type,
                description: ar.description,
                location: ar.location,
                severity: ar.severity,
            })
            .collect();

        Ok(DedaubAnalysisResult {
            contract_address: contract_address.to_string(),
            chain: "ethereum".to_string(),
            security_score,
            vulnerabilities,
            external_calls,
            reentrancy_analysis,
            has_delegatecall: response.has_delegatecall.unwrap_or(false),
            access_control_issues,
            arithmetic_issues,
            analysis_timestamp: response.timestamp,
            raw_data: Some(response.raw.unwrap_or_default()),
        })
    }
}

impl Default for DedaubClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default DedaubClient")
    }
}

/// Analysis request structure
#[derive(Debug, Clone, Serialize)]
struct DedaubAnalysisRequest {
    address: String,
    chain: String,
    include_source: bool,
    include_bytecode: bool,
}

/// Raw API response structure
#[derive(Debug, Clone, Deserialize)]
struct DedaubApiResponse {
    score: Option<ScoreData>,
    issues: Option<Vec<IssueData>>,
    external_calls: Option<Vec<ExternalCallData>>,
    reentrancy: Option<ReentrancyData>,
    access_control: Option<Vec<AccessControlData>>,
    arithmetic: Option<Vec<ArithmeticData>>,
    has_delegatecall: Option<bool>,
    timestamp: Option<u64>,
    raw: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct ScoreData {
    overall: Option<u8>,
    grade: Option<String>,
    categories: Option<HashMap<String, u8>>,
    critical_count: Option<u32>,
    high_count: Option<u32>,
    medium_count: Option<u32>,
    low_count: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct IssueData {
    vuln_type: String,
    severity: String,
    title: String,
    description: String,
    location: Option<String>,
    remediation: Option<String>,
    cwe_id: Option<String>,
    confidence: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalCallData {
    target: String,
    call_type: String,
    function_signature: Option<String>,
    is_known_contract: Option<bool>,
    risk_level: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ReentrancyData {
    is_vulnerable: bool,
    vulnerable_functions: Vec<String>,
    has_reentrancy_guard: bool,
    state_after_external_call: bool,
    risk_level: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AccessControlData {
    issue_type: String,
    description: String,
    affected_functions: Vec<String>,
    severity: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ArithmeticData {
    issue_type: String,
    description: String,
    location: Option<String>,
    severity: String,
}

// Default constants
const DEFAULT_RETRY_COUNT: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> DedaubClient {
        let http_client = Client::builder()
            .http1_only()
            .build()
            .unwrap();

        DedaubClient {
            http_client,
            base_url: mock_server_url.to_string(),
            api_key: Some("test_key".to_string()),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_analyze_contract_success() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "score": {
                "overall": 75,
                "grade": "B",
                "categories": {"security": 80, "efficiency": 70},
                "critical_count": 0,
                "high_count": 1,
                "medium_count": 2,
                "low_count": 3
            },
            "issues": [
                {
                    "vuln_type": "reentrancy",
                    "severity": "high",
                    "title": "Potential Reentrancy",
                    "description": "Function may be vulnerable to reentrancy attacks",
                    "location": "withdraw()",
                    "remediation": "Use ReentrancyGuard",
                    "cwe_id": "CWE-841",
                    "confidence": 0.85
                }
            ],
            "external_calls": [
                {
                    "target": "0x1234567890123456789012345678901234567890",
                    "call_type": "call",
                    "function_signature": "transfer(address,uint256)",
                    "is_known_contract": true,
                    "risk_level": "low"
                }
            ],
            "reentrancy": {
                "is_vulnerable": false,
                "vulnerable_functions": [],
                "has_reentrancy_guard": true,
                "state_after_external_call": false,
                "risk_level": "low"
            },
            "access_control": [],
            "arithmetic": [],
            "has_delegatecall": false,
            "timestamp": 1234567890,
            "raw": {}
        }"#;

        let mock = server
            .mock("POST", "/api/v1/analyze")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .analyze_contract("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.contract_address, "0x1234567890123456789012345678901234567890");
        assert!(analysis.security_score.is_some());
        assert_eq!(analysis.security_score.unwrap().overall_score, 75);
        assert_eq!(analysis.vulnerabilities.len(), 1);
        assert_eq!(analysis.external_calls.len(), 1);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_analyze_contract_disabled() {
        let client = DedaubClient::with_params(None, Duration::from_secs(10), 0).unwrap();
        let result = client
            .analyze_contract("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn test_check_external_calls() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "score": {"overall": 80, "grade": "A"},
            "issues": [],
            "external_calls": [
                {
                    "target": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                    "call_type": "delegatecall",
                    "function_signature": null,
                    "is_known_contract": false,
                    "risk_level": "high"
                }
            ],
            "reentrancy": null,
            "access_control": [],
            "arithmetic": [],
            "has_delegatecall": true,
            "timestamp": null,
            "raw": {}
        }"#;

        let mock = server
            .mock("POST", "/api/v1/analyze")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_external_calls("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        let calls = result.unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].call_type, "delegatecall");
        assert_eq!(calls[0].risk_level, "high");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_security_score() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "score": {
                "overall": 90,
                "grade": "A",
                "categories": {"security": 95, "efficiency": 85},
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 1,
                "low_count": 2
            },
            "issues": [],
            "external_calls": [],
            "reentrancy": null,
            "access_control": [],
            "arithmetic": [],
            "has_delegatecall": false,
            "timestamp": null,
            "raw": {}
        }"#;

        let mock = server
            .mock("POST", "/api/v1/analyze")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .get_security_score("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        let score = result.unwrap();
        assert_eq!(score.overall_score, 90);
        assert_eq!(score.grade, "A");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_api_error_401() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/api/v1/analyze")
            .with_status(401)
            .with_body("Unauthorized")
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .analyze_contract("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_api_error_429() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/api/v1/analyze")
            .with_status(429)
            .with_body("Rate Limited")
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .analyze_contract("0x1234567890123456789012345678901234567890", "ethereum")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limited"));

        mock.assert_async().await;
    }

    #[test]
    fn test_dedaub_chain_conversion() {
        assert_eq!(DedaubChain::from_chain_name("ethereum"), DedaubChain::Ethereum);
        assert_eq!(DedaubChain::from_chain_name("ETH"), DedaubChain::Ethereum);
        assert_eq!(DedaubChain::from_chain_name("bsc"), DedaubChain::Bsc);
        assert_eq!(DedaubChain::from_chain_name("polygon"), DedaubChain::Polygon);
        assert_eq!(DedaubChain::from_chain_name("unknown"), DedaubChain::Ethereum);

        assert_eq!(DedaubChain::Ethereum.to_chain_id(), "eth");
        assert_eq!(DedaubChain::Bsc.to_chain_id(), "bsc");
        assert_eq!(DedaubChain::Polygon.to_chain_id(), "polygon");
    }
}
