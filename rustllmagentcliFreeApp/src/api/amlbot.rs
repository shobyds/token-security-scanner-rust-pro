//! AML Bot API Client for Scammer Detection
//!
//! AML Bot (Crystalblockchain public layer) provides free AML screening:
//! - Risk score 0-100
//! - Category tags (scam, rugpull, mixer, etc.)
//! - Address risk assessment
//!
//! # API
//! - Endpoint: `https://amlbot.com/api/v1/check/{address}`
//! - Authentication: None required for public tier
//! - Rate limits: Free tier available

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

use crate::api::{
    ApiConfig, DEFAULT_BACKOFF_BASE_MS, DEFAULT_BACKOFF_MAX_MS, DEFAULT_TIMEOUT_SECS,
    create_http_client, with_retry,
};

/// AML Bot API client
#[derive(Debug, Clone)]
pub struct AmlBotClient {
    http_client: Client,
    base_url: String,
    timeout: Duration,
    retry_count: u32,
    enabled: bool,
}

/// AML Bot check response structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AmlBotCheckResponse {
    /// Address checked
    #[serde(default)]
    pub address: String,
    /// Risk score (0-100)
    #[serde(default)]
    pub risk_score: u32,
    /// Risk category
    #[serde(default)]
    pub category: String,
    /// Category tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether address is flagged as high risk
    #[serde(default)]
    pub is_high_risk: bool,
    /// Additional metadata
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl AmlBotClient {
    /// Create a new AmlBotClient with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(&ApiConfig::from_env())
    }

    /// Create a new AmlBotClient with custom configuration
    pub fn with_config(_config: &ApiConfig) -> Result<Self> {
        let http_client = create_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))?;

        // AML Bot doesn't require authentication for public tier
        info!("AML Bot client initialized (no authentication required)");

        Ok(Self {
            http_client,
            base_url: "https://amlbot.com".to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            retry_count: 3,
            enabled: true,
        })
    }

    /// Create a new AmlBotClient with custom parameters
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

    /// Create a new AmlBotClient for testing
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

    /// Check address risk
    ///
    /// # Arguments
    /// * `address` - The address to check
    ///
    /// # Returns
    /// * `Ok(AmlBotCheckResponse)` - Risk assessment result
    /// * `Err(anyhow::Error)` - Error if the check fails
    #[instrument(skip(self), fields(address = %address))]
    pub async fn check_address(&self, address: &str) -> Result<AmlBotCheckResponse> {
        if !self.enabled {
            debug!("AML Bot is disabled, returning default response");
            return Ok(AmlBotCheckResponse::default());
        }

        info!("Checking AML Bot risk for {}", address);

        let url = format!("{}/api/v1/check/{}", self.base_url, address);

        debug!("AML Bot API URL: {}", url);

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
                    .context("Failed to send request to AML Bot")?;

                let status = response.status();
                debug!("AML Bot response status: {}", status);

                if status.is_success() {
                    let body = response
                        .text()
                        .await
                        .context("Failed to read response body")?;
                    Ok(body)
                } else if status.as_u16() == 404 {
                    // Address not found - return default response
                    debug!("Address {} not found in AML Bot database", address);
                    Ok(r#"{"address": "", "risk_score": 0, "category": "", "tags": [], "is_high_risk": false}"#.to_string())
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Rate limited by AML Bot"))
                } else {
                    let error_body = response.text().await.unwrap_or_default();
                    Err(anyhow!("AML Bot API error: {status} - {error_body}"))
                }
            },
        )
        .await?;

        let parsed: AmlBotCheckResponse =
            serde_json::from_str(&response_data).context("Failed to parse AML Bot response")?;

        info!(
            "AML Bot check completed for {}: risk_score={}, category={}, tags={:?}",
            address, parsed.risk_score, parsed.category, parsed.tags
        );

        Ok(parsed)
    }

    /// Check if address is considered a scammer based on risk score and tags
    pub fn is_scammer(&self, response: &AmlBotCheckResponse) -> bool {
        // High risk score indicates scammer
        if response.risk_score >= 75 {
            return true;
        }

        // Check for scam-related tags
        response
            .tags
            .iter()
            .any(|tag| {
                let tag_lower = tag.to_lowercase();
                tag_lower.contains("scam")
                    || tag_lower.contains("fraud")
                    || tag_lower.contains("phishing")
            })
    }

    /// Count rugpull tags
    pub fn count_rugpulls(&self, response: &AmlBotCheckResponse) -> u32 {
        #[allow(clippy::cast_possible_truncation)]
        let count = response
            .tags
            .iter()
            .filter(|tag| {
                let tag_lower = tag.to_lowercase();
                tag_lower.contains("rug") || tag_lower.contains("rugpull")
            })
            .count() as u32;
        count
    }

    /// Get risk score (0-100)
    pub fn get_risk_score(&self, response: &AmlBotCheckResponse) -> u32 {
        response.risk_score.min(100)
    }

    /// Count critical alerts (high risk + scam tags)
    pub fn count_critical_alerts(&self, response: &AmlBotCheckResponse) -> u32 {
        let mut count = 0u32;

        // High risk score is critical
        if response.risk_score >= 90 {
            count += 1;
        }

        // Count critical tags
        #[allow(clippy::cast_possible_truncation)]
        let critical_tags = response
            .tags
            .iter()
            .filter(|tag| {
                let tag_lower = tag.to_lowercase();
                tag_lower.contains("critical")
                    || tag_lower.contains("severe")
                    || tag_lower.contains("scam")
                    || tag_lower.contains("fraud")
            })
            .count() as u32;
        count += critical_tags;

        count
    }

    /// Count high alerts
    pub fn count_high_alerts(&self, response: &AmlBotCheckResponse) -> u32 {
        let mut count = 0u32;

        // Medium-high risk score
        if response.risk_score >= 50 && response.risk_score < 90 {
            count += 1;
        }

        // Count high-risk tags
        #[allow(clippy::cast_possible_truncation)]
        let high_tags = response
            .tags
            .iter()
            .filter(|tag| {
                let tag_lower = tag.to_lowercase();
                tag_lower.contains("high")
                    || tag_lower.contains("rug")
                    || tag_lower.contains("mixer")
                    || tag_lower.contains("suspicious")
            })
            .count() as u32;
        count += high_tags;

        count
    }

    /// Get all tags as alerts
    pub fn get_alerts(&self, response: &AmlBotCheckResponse) -> Vec<String> {
        let mut alerts = response.tags.clone();

        // Add category if present
        if !response.category.is_empty() {
            alerts.push(format!("Category: {}", response.category));
        }

        // Add risk score alert
        if response.risk_score >= 75 {
            alerts.push(format!("High Risk Score: {}", response.risk_score));
        }

        alerts
    }
}

impl Default for AmlBotClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default AmlBotClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> AmlBotClient {
        let http_client = Client::builder()
            .http1_only()
            .build()
            .unwrap();

        AmlBotClient {
            http_client,
            base_url: mock_server_url.to_string(),
            timeout: Duration::from_secs(10),
            retry_count: 0,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_check_address_high_risk() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "address": "0x1234567890123456789012345678901234567890",
            "risk_score": 95,
            "category": "scam",
            "tags": ["scam", "rugpull", "mixer"],
            "is_high_risk": true
        }"#;

        let mock = server
            .mock("GET", "/api/v1/check/0x1234567890123456789012345678901234567890")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_address("0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        let check_response = result.unwrap();
        assert_eq!(check_response.risk_score, 95);
        assert!(check_response.is_high_risk);
        assert_eq!(check_response.tags.len(), 3);
        assert!(client.is_scammer(&check_response));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_address_clean() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
            "risk_score": 5,
            "category": "",
            "tags": [],
            "is_high_risk": false
        }"#;

        let mock = server
            .mock("GET", "/api/v1/check/0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_address("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await;

        assert!(result.is_ok());
        let check_response = result.unwrap();
        assert_eq!(check_response.risk_score, 5);
        assert!(!check_response.is_high_risk);
        assert!(!client.is_scammer(&check_response));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_address_not_found() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/api/v1/check/0x0000000000000000000000000000000000000000")
            .with_status(404)
            .create_async()
            .await;

        let client = create_test_client(&server.url());
        let result = client
            .check_address("0x0000000000000000000000000000000000000000")
            .await;

        // Should return default response, not error
        assert!(result.is_ok());
        let check_response = result.unwrap();
        assert_eq!(check_response.risk_score, 0);
        assert!(!check_response.is_high_risk);

        mock.assert_async().await;
    }

    #[test]
    fn test_helper_functions() {
        let client = AmlBotClient::default();

        let high_risk_response = AmlBotCheckResponse {
            address: "0x123".to_string(),
            risk_score: 95,
            category: "scam".to_string(),
            tags: vec!["scam".to_string(), "rugpull".to_string()],
            is_high_risk: true,
            metadata: serde_json::Value::Null,
        };

        assert!(client.is_scammer(&high_risk_response));
        assert_eq!(client.count_rugpulls(&high_risk_response), 1);
        assert_eq!(client.get_risk_score(&high_risk_response), 95);
        assert!(client.count_critical_alerts(&high_risk_response) > 0);
    }
}
