//! Forta Network GraphQL Client for Scammer/Rug Pull Detection
//!
//! Forta Network provides decentralized threat intelligence including:
//! - Scammer address detection
//! - Rug pull alerts
//! - Honeypot bot alerts
//! - Security bot network
//!
//! # API
//! - Endpoint: `https://api.forta.network/graphql`
//! - Free tier: 100% Free, No authentication required
//!
//! # Features
//! - Query alerts by address
//! - Filter by severity (HIGH, CRITICAL)
//! - Access to 100+ security bots
//! - Real-time threat detection

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, DEFAULT_TIMEOUT_SECS,
    create_http_client, with_retry,
};

/// Forta Network GraphQL client
#[derive(Debug, Clone)]
pub struct FortaClient {
    http_client: Client,
    base_url: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
    api_key: Option<String>,
}

/// Forta GraphQL query structure
#[derive(Debug, Clone, Serialize)]
pub struct FortaQuery {
    pub query: String,
}

/// Forta GraphQL response structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FortaResponse {
    pub data: Option<FortaData>,
    pub errors: Option<Vec<FortaError>>,
}

/// Forta data structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FortaData {
    #[serde(default)]
    pub alerts: FortaAlerts,
}

/// Forta alerts structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FortaAlerts {
    #[serde(default)]
    pub alerts: Vec<FortaAlert>,
}

/// Forta alert structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortaAlert {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Forta error structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortaError {
    pub message: String,
}

/// Forta scammer detection result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FortaScammerResult {
    /// Address checked
    pub address: String,
    /// Whether address is a known scammer
    pub is_known_scammer: bool,
    /// Number of previous rug pulls
    pub previous_rugs: u32,
    /// Total alerts count
    pub total_alerts: u32,
    /// Critical alerts count
    pub critical_alerts: u32,
    /// High alerts count
    pub high_alerts: u32,
    /// Deployer risk score (0-100)
    pub deployer_risk_score: u32,
    /// Alert details
    pub alerts: Vec<FortaAlertSummary>,
}

/// Forta alert summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortaAlertSummary {
    pub name: String,
    pub severity: String,
    pub description: String,
}

impl FortaClient {
    /// Create a new FortaClient with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new FortaClient with custom configuration
    pub fn with_config(_config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))?;

        // Try to load .env file first
        let _ = dotenvy::dotenv();

        // Get API key from environment (optional - Forta works without auth but has limits)
        let api_key = std::env::var("FORTA_API_KEY").ok();
        let enabled = true; // Forta is always enabled, API key is optional

        if let Some(ref key) = api_key {
            info!("Forta Network client initialized with API key");
        } else {
            info!("Forta Network client initialized without API key (rate limits may apply)");
        }

        Ok(Self {
            http_client,
            base_url: "https://api.forta.network".to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_count: DEFAULT_RETRY_COUNT,
            enabled,
            api_key,
        })
    }

    /// Create a new FortaClient with custom parameters
    pub fn with_params(
        base_url: &str,
        timeout: Duration,
        retry_count: u32,
        api_key: Option<&str>,
    ) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: base_url.to_string(),
            timeout,
            retry_count,
            enabled: true,
            api_key: api_key.map(String::from),
        })
    }

    /// Create a new FortaClient for testing
    #[cfg(test)]
    pub fn for_testing(base_url: String, http_client: Client) -> Self {
        Self {
            http_client,
            base_url,
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
            api_key: None,
        }
    }

    /// Check if an address is a known scammer
    ///
    /// # Arguments
    /// * `address` - The address to check
    ///
    /// # Returns
    /// * `Ok(FortaScammerResult)` - Scammer detection result
    /// * `Err(anyhow::Error)` - Error if the check fails
    #[instrument(skip(self), fields(address = %address))]
    pub async fn check_scammer(&self, address: &str) -> Result<FortaScammerResult> {
        if !self.enabled {
            return Ok(FortaScammerResult::default());
        }

        info!("Checking scammer status for {}", address);

        let query = format!(
            r#"{{ 
                alerts(input: {{ 
                    addresses: ["{address}"], 
                    severity: ["HIGH","CRITICAL"], 
                    first: 20 
                }}) {{ 
                    alerts {{ 
                        name 
                        description 
                        severity 
                        metadata 
                    }} 
                }} 
            }}"#
        );

        let result = self.execute_query(&query).await?;

        // Analyze alerts for scammer detection
        let alerts = result.data.map(|d| d.alerts.alerts).unwrap_or_default();

        let critical_alerts = alerts.iter().filter(|a| a.severity == "CRITICAL").count().try_into().unwrap_or(u32::MAX);
        let high_alerts = alerts.iter().filter(|a| a.severity == "HIGH").count().try_into().unwrap_or(u32::MAX);
        let total_alerts = critical_alerts.saturating_add(high_alerts);

        // Count rug pull related alerts
        let previous_rugs = alerts.iter()
            .filter(|a| {
                let name_lower = a.name.to_lowercase();
                let desc_lower = a.description.to_lowercase();
                name_lower.contains("rug") || desc_lower.contains("rug")
            })
            .count().try_into().unwrap_or(u32::MAX);

        // Determine if known scammer
        let is_known_scammer = critical_alerts > 0 || previous_rugs > 0;

        // Calculate risk score
        let deployer_risk_score = Self::calculate_risk_score(&alerts);

        // Create alert summaries
        let alert_summaries: Vec<FortaAlertSummary> = alerts
            .iter()
            .map(|a| FortaAlertSummary {
                name: a.name.clone(),
                severity: a.severity.clone(),
                description: a.description.clone(),
            })
            .collect();

        let scammer_result = FortaScammerResult {
            address: address.to_string(),
            is_known_scammer,
            previous_rugs,
            total_alerts,
            critical_alerts,
            high_alerts,
            deployer_risk_score,
            alerts: alert_summaries,
        };

        info!(
            "Forta scammer check completed for {}: is_scammer={}, risk_score={}",
            address, scammer_result.is_known_scammer, scammer_result.deployer_risk_score
        );

        Ok(scammer_result)
    }

    /// Execute a GraphQL query
    async fn execute_query(&self, query: &str) -> Result<FortaResponse> {
        let url = format!("{}/graphql", self.base_url);

        debug!("Executing Forta GraphQL query: {}", url);

        let request_body = FortaQuery {
            query: query.to_string(),
        };

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let mut request = self
                    .http_client
                    .post(&url)
                    .header("accept", "application/json")
                    .header("content-type", "application/json")
                    .json(&request_body);

                // Add API key header if available
                if let Some(ref api_key) = self.api_key {
                    request = request.header("Authorization", format!("Bearer {api_key}"));
                    debug!("Using Forta API key for authentication");
                }

                let response = request
                    .send()
                    .await
                    .context("Failed to send request to Forta Network")?;

                let status = response.status();
                debug!("Forta Network response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    Ok(body)
                } else if status.as_u16() == 400 {
                    Err(anyhow!("Forta Network bad request"))
                } else if status.as_u16() == 401 {
                    Err(anyhow!("Forta Network authentication failed - check API key"))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by Forta Network"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    Err(anyhow!("Forta Network API error: {status} - {error_body}"))
                }
            },
        )
        .await?;

        let parsed: FortaResponse =
            serde_json::from_str(&response_data).context("Failed to parse Forta response")?;

        Ok(parsed)
    }

    /// Calculate risk score from alerts
    fn calculate_risk_score(alerts: &[FortaAlert]) -> u32 {
        let mut risk = 0u32;

        for alert in alerts {
            match alert.severity.as_str() {
                "CRITICAL" => risk += 30,
                "HIGH" => risk += 20,
                "MEDIUM" => risk += 10,
                _ => risk += 5,
            }

            // Additional risk for specific alert types
            let name_lower = alert.name.to_lowercase();
            if name_lower.contains("rug") {
                risk += 20;
            }
            if name_lower.contains("honeypot") {
                risk += 25;
            }
            if name_lower.contains("scam") {
                risk += 30;
            }
        }

        risk.min(100)
    }
}

impl Default for FortaClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default FortaClient")
    }
}

// Default constants
const DEFAULT_RETRY_COUNT: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> FortaClient {
        let http_client = Client::builder()
            .http1_only()
            .build()
            .unwrap();

        FortaClient {
            http_client,
            base_url: mock_server_url.to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
            api_key: None,
        }
    }

    #[tokio::test]
    async fn test_check_scammer_detected() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "data": {
                "alerts": {
                    "alerts": [
                        {
                            "name": "RUGPULL_DETECTED",
                            "description": "Token liquidity was removed",
                            "severity": "CRITICAL",
                            "metadata": {}
                        },
                        {
                            "name": "HONEYPOT_DETECTED",
                            "description": "Token cannot be sold",
                            "severity": "HIGH",
                            "metadata": {}
                        }
                    ]
                }
            }
        }"#;

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_scammer("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        let scammer_result = result.unwrap();
        assert!(scammer_result.is_known_scammer);
        assert!(scammer_result.previous_rugs > 0);
        assert!(scammer_result.deployer_risk_score > 50);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_scammer_clean() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "data": {
                "alerts": {
                    "alerts": []
                }
            }
        }"#;

        let mock = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_scammer("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await;

        assert!(result.is_ok());
        let scammer_result = result.unwrap();
        assert!(!scammer_result.is_known_scammer);
        assert_eq!(scammer_result.previous_rugs, 0);
        assert_eq!(scammer_result.total_alerts, 0);

        mock.assert_async().await;
    }

    #[test]
    fn test_forta_scammer_result_default() {
        let result = FortaScammerResult::default();
        assert!(!result.is_known_scammer);
        assert_eq!(result.previous_rugs, 0);
        assert_eq!(result.deployer_risk_score, 0);
    }
}
