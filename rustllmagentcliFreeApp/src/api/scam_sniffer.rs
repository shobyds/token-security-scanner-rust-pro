//! ScamSniffer API Client for Scammer Detection
//!
//! ScamSniffer provides free, no-authentication scammer detection:
//! - Scammer address flags
//! - Rug pull history
//! - Risk labels
//!
//! # API
//! - Endpoint: `https://api.scamsniffer.io/v1/address/{address}/risk`
//! - Authentication: None required
//! - Rate limits: Free tier available

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::cast_possible_truncation)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, DEFAULT_TIMEOUT_SECS,
    create_http_client, with_retry,
};

/// ScamSniffer API client
#[derive(Debug, Clone)]
pub struct ScamSnifferClient {
    http_client: Client,
    base_url: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// ScamSniffer risk response structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScamSnifferRiskResponse {
    /// Address checked
    #[serde(default)]
    pub address: String,
    /// Whether address is flagged as scammer
    #[serde(default)]
    pub is_scammer: bool,
    /// Risk score (0-100)
    #[serde(default)]
    pub risk_score: u32,
    /// Risk labels/tags
    #[serde(default)]
    pub labels: Vec<String>,
    /// Rug pull history
    #[serde(default)]
    pub rug_pull_history: Vec<RugPullEvent>,
    /// Additional metadata
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Rug pull event from ScamSniffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RugPullEvent {
    /// Token address involved
    #[serde(default)]
    pub token_address: String,
    /// Event timestamp
    #[serde(default)]
    pub timestamp: Option<String>,
    /// Event description
    #[serde(default)]
    pub description: String,
    /// Severity level
    #[serde(default)]
    pub severity: String,
}

impl ScamSnifferClient {
    /// Create a new ScamSnifferClient with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new ScamSnifferClient with custom configuration
    pub fn with_config(_config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))?;

        // ScamSniffer doesn't require authentication
        info!("ScamSniffer client initialized (no authentication required)");

        Ok(Self {
            http_client,
            base_url: "https://api.scamsniffer.io".to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_count: 3,
            enabled: true,
        })
    }

    /// Create a new ScamSnifferClient with custom parameters
    pub fn with_params(
        base_url: &str,
        timeout: Duration,
        retry_count: u32,
    ) -> Result<Self> {
        let http_client = create_http_client(timeout)?;

        Ok(Self {
            http_client,
            base_url: base_url.to_string(),
            timeout,
            retry_count,
            enabled: true,
        })
    }

    /// Create a new ScamSnifferClient for testing
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

    /// Check address risk and scammer status
    ///
    /// # Arguments
    /// * `address` - The address to check
    ///
    /// # Returns
    /// * `Ok(ScamSnifferRiskResponse)` - Risk assessment result
    /// * `Err(anyhow::Error)` - Error if the check fails
    #[instrument(skip(self), fields(address = %address))]
    pub async fn check_address_risk(&self, address: &str) -> Result<ScamSnifferRiskResponse> {
        if !self.enabled {
            debug!("ScamSniffer is disabled, returning default response");
            return Ok(ScamSnifferRiskResponse::default());
        }

        info!("Checking ScamSniffer risk for {}", address);

        let url = format!("{}/v1/address/{}/risk", self.base_url, address);

        debug!("ScamSniffer API URL: {}", url);

        let response_data = with_retry::<_, anyhow::Error, _, _>(
            self.retry_count,
            DEFAULT_BACKOFF_BASE_MS,
            DEFAULT_BACKOFF_MAX_MS,
            || async {
                let response = self
                    .http_client
                    .get(&url)
                    .header("accept", "application/json")
                    .send()
                    .await
                    .context("Failed to send request to ScamSniffer")?;

                let status = response.status();
                debug!("ScamSniffer response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    Ok(body)
                } else if status.as_u16() == 404 {
                    // Address not found in database - not necessarily an error
                    debug!("Address {} not found in ScamSniffer database", address);
                    Ok(r#"{"address": "", "is_scammer": false, "risk_score": 0, "labels": [], "rug_pull_history": []}"#.to_string())
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by ScamSniffer"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    Err(anyhow!("ScamSniffer API error: {status} - {error_body}"))
                }
            },
        )
        .await?;

        // Log raw response for debugging
        debug!("ScamSniffer raw response: {}", response_data);

        // Handle empty or malformed response
        if response_data.trim().is_empty() {
            debug!("ScamSniffer returned empty response for {} - using default", address);
            return Ok(ScamSnifferRiskResponse::default());
        }

        // Try to parse the response
        let parsed: ScamSnifferRiskResponse = match serde_json::from_str(&response_data) {
            Ok(p) => p,
            Err(e) => {
                // Log the error but return default instead of failing
                debug!("Failed to parse ScamSniffer response for {}: {} - raw: {}", address, e, response_data);
                return Ok(ScamSnifferRiskResponse::default());
            }
        };

        info!(
            "ScamSniffer check completed for {}: is_scammer={}, risk_score={}, labels={:?}",
            address, parsed.is_scammer, parsed.risk_score, parsed.labels
        );

        Ok(parsed)
    }

    /// Convert ScamSniffer response to standardized risk score (0-100)
    pub fn get_risk_score(&self, response: &ScamSnifferRiskResponse) -> u32 {
        response.risk_score.min(100)
    }

    /// Check if address is flagged as scammer
    pub fn is_scammer(&self, response: &ScamSnifferRiskResponse) -> bool {
        response.is_scammer || response.risk_score >= 75
    }

    /// Count rug pull events
    pub fn count_rug_pulls(&self, response: &ScamSnifferRiskResponse) -> u32 {
        #[allow(clippy::cast_possible_truncation)]
        let len = response.rug_pull_history.len() as u32;
        len
    }

    /// Get critical alerts count (severe risk labels)
    pub fn count_critical_alerts(&self, response: &ScamSnifferRiskResponse) -> u32 {
        #[allow(clippy::cast_possible_truncation)]
        let count = response
            .labels
            .iter()
            .filter(|label| {
                let label_lower = label.to_lowercase();
                label_lower.contains("critical")
                    || label_lower.contains("severe")
                    || label_lower.contains("scam")
                    || label_lower.contains("fraud")
            })
            .count() as u32;
        count
    }

    /// Get high alerts count
    pub fn count_high_alerts(&self, response: &ScamSnifferRiskResponse) -> u32 {
        #[allow(clippy::cast_possible_truncation)]
        let count = response
            .labels
            .iter()
            .filter(|label| {
                let label_lower = label.to_lowercase();
                label_lower.contains("high")
                    || label_lower.contains("rug")
                    || label_lower.contains("phishing")
            })
            .count() as u32;
        count
    }

    /// Get all labels/alerts as strings
    pub fn get_alerts(&self, response: &ScamSnifferRiskResponse) -> Vec<String> {
        let mut alerts = response.labels.clone();

        // Add rug pull descriptions
        for rug in &response.rug_pull_history {
            if !rug.description.is_empty() {
                alerts.push(format!("Rug Pull: {}", rug.description));
            }
        }

        alerts
    }
}

impl Default for ScamSnifferClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default ScamSnifferClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> ScamSnifferClient {
        let http_client = Client::builder()
            .http1_only()
            .build()
            .unwrap();

        ScamSnifferClient {
            http_client,
            base_url: mock_server_url.to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_check_address_risk_scammer_detected() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "address": "0x1234567890123456789012345678901234567890",
            "is_scammer": true,
            "risk_score": 95,
            "labels": ["Scam", "Phishing", "Critical"],
            "rug_pull_history": [
                {
                    "token_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                    "timestamp": "2024-01-15T10:30:00Z",
                    "description": "Liquidity removed without warning",
                    "severity": "critical"
                }
            ]
        }"#;

        let mock = server
            .mock("GET", "/v1/address/0x1234567890123456789012345678901234567890/risk")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_address_risk("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        let risk_response = result.unwrap();
        assert!(risk_response.is_scammer);
        assert_eq!(risk_response.risk_score, 95);
        assert!(!risk_response.labels.is_empty());
        assert_eq!(risk_response.rug_pull_history.len(), 1);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_address_risk_clean() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
            "is_scammer": false,
            "risk_score": 5,
            "labels": [],
            "rug_pull_history": []
        }"#;

        let mock = server
            .mock("GET", "/v1/address/0x1f9840a85d5af5bf1d1762f925bdaddc4201f984/risk")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_address_risk("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await;

        assert!(result.is_ok());
        let risk_response = result.unwrap();
        assert!(!risk_response.is_scammer);
        assert_eq!(risk_response.risk_score, 5);
        assert!(risk_response.labels.is_empty());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_address_risk_not_found() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v1/address/0x0000000000000000000000000000000000000000/risk")
            .with_status(404)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_address_risk("0x0000000000000000000000000000000000000000")
            .await;

        // Should return default response, not error
        assert!(result.is_ok());
        let risk_response = result.unwrap();
        assert!(!risk_response.is_scammer);
        assert_eq!(risk_response.risk_score, 0);

        mock.assert_async().await;
    }

    #[test]
    fn test_risk_score_helpers() {
        let client = ScamSnifferClient::default();
        let response = ScamSnifferRiskResponse {
            address: "0x123".to_string(),
            is_scammer: true,
            risk_score: 85,
            labels: vec!["Scam".to_string(), "Critical".to_string()],
            rug_pull_history: vec![RugPullEvent {
                token_address: "0x456".to_string(),
                timestamp: None,
                description: "Test rug".to_string(),
                severity: "high".to_string(),
            }],
            metadata: serde_json::Value::Null,
        };

        assert_eq!(client.get_risk_score(&response), 85);
        assert!(client.is_scammer(&response));
        assert_eq!(client.count_rug_pulls(&response), 1);
        assert_eq!(client.count_critical_alerts(&response), 2);
        assert_eq!(client.count_high_alerts(&response), 0);
    }
}
