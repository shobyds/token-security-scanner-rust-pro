//! DefiLlama API client for token price data
//!
//! DefiLlama provides free price data with confidence scores:
//! - No API key required
//! - Confidence score (0.0-1.0) for price reliability
//! - Batch price fetching for multiple tokens

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

/// DefiLlama API client (Phase 1 Task 1.6)
#[derive(Debug, Clone)]
pub struct DefiLlamaClient {
    client: Client,
    base_url: String,
    timeout: Duration,
    enabled: bool,
}

/// Price data from DefiLlama (Phase 1 Task 1.6)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefiLlamaPrice {
    /// Token symbol
    pub symbol: String,
    /// Price in USD
    pub price: f64,
    /// Token decimals
    pub decimals: u8,
    /// Price timestamp (Unix seconds)
    pub timestamp: u64,
    /// Confidence score (0.0-1.0) - price reliability
    pub confidence: f64,
}

impl DefiLlamaClient {
    /// Create a new DefiLlama client with default configuration
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("rust-token-scanner/0.1.0")
                .build()
                .context("Failed to create HTTP client")?,
            base_url: "https://coins.llama.fi".to_string(),
            timeout: Duration::from_secs(10),
            enabled: true,
        })
    }

    /// Create a new DefiLlama client with custom parameters
    pub fn with_params(timeout: Duration, enabled: bool) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(timeout)
                .user_agent("rust-token-scanner/0.1.0")
                .build()
                .context("Failed to create HTTP client")?,
            base_url: "https://coins.llama.fi".to_string(),
            timeout,
            enabled,
        })
    }

    /// Create a new DefiLlama client for testing with custom base URL
    #[cfg(test)]
    pub fn for_testing(base_url: String, client: Client) -> Self {
        Self {
            client,
            base_url,
            timeout: Duration::from_secs(10),
            enabled: true,
        }
    }

    /// Fetch current price for a token (Phase 1 Task 1.6)
    ///
    /// # Arguments
    /// * `chain` - The blockchain network ("ethereum", "bsc", "base", etc.)
    /// * `token_address` - The token contract address
    ///
    /// # Returns
    /// * `Ok(DefiLlamaPrice)` - Price data with confidence score
    /// * `Err(anyhow::Error)` - Error if price not found or request fails
    #[instrument(skip(self), fields(chain = %chain, token_address = %token_address))]
    pub async fn get_price(
        &self,
        chain: &str,
        token_address: &str,
    ) -> Result<DefiLlamaPrice> {
        if !self.enabled {
            return Err(anyhow!("DefiLlama API is disabled"));
        }

        let coin_id = format!("{}:{}", chain, token_address.to_lowercase());
        let url = format!("{}/prices/current/{}", self.base_url, coin_id);

        debug!("Fetching price from DefiLlama: {}", url);

        let resp: serde_json::Value = self.client.get(&url)
            .timeout(self.timeout)
            .send().await?
            .json().await?;

        let coin = resp["coins"][&coin_id]
            .as_object()
            .ok_or_else(|| anyhow!("Price not found in DefiLlama"))?;

        let price = DefiLlamaPrice {
            symbol: coin["symbol"].as_str().unwrap_or("?").to_string(),
            price: coin["price"].as_f64().unwrap_or(0.0),
            #[allow(clippy::cast_possible_truncation)]
            decimals: coin["decimals"].as_u64().unwrap_or(18) as u8,
            timestamp: coin["timestamp"].as_u64().unwrap_or(0),
            confidence: coin["confidence"].as_f64().unwrap_or(0.5),
        };

        info!(
            "DefiLlama price for {}: ${} (confidence: {})",
            token_address, price.price, price.confidence
        );

        Ok(price)
    }

    /// Batch fetch prices for multiple tokens (Phase 1 Task 1.6)
    ///
    /// # Arguments
    /// * `coins` - List of (chain, address) tuples
    ///
    /// # Returns
    /// * `Ok(Vec<DefiLlamaPrice>)` - List of price data
    /// * `Err(anyhow::Error)` - Error if request fails
    pub async fn get_prices_batch(
        &self,
        coins: &[(&str, &str)],
    ) -> Result<Vec<DefiLlamaPrice>> {
        if !self.enabled {
            return Err(anyhow!("DefiLlama API is disabled"));
        }

        if coins.is_empty() {
            return Ok(Vec::new());
        }

        let coins_str = coins.iter()
            .map(|(chain, addr)| format!("{}:{}", chain, addr.to_lowercase()))
            .collect::<Vec<_>>()
            .join(",");

        let url = format!("https://coins.llama.fi/prices/current/{}", coins_str);

        debug!("Fetching batch prices from DefiLlama: {}", url);

        let resp: serde_json::Value = self.client.get(&url)
            .timeout(Duration::from_secs(15))
            .send().await?
            .json().await?;

        let mut results = Vec::with_capacity(coins.len());

        if let Some(coins_map) = resp["coins"].as_object() {
            for (coin_id, coin) in coins_map {
                let price = DefiLlamaPrice {
                    symbol: coin["symbol"].as_str().unwrap_or("?").to_string(),
                    price: coin["price"].as_f64().unwrap_or(0.0),
                    #[allow(clippy::cast_possible_truncation)]
                    decimals: coin["decimals"].as_u64().unwrap_or(18) as u8,
                    timestamp: coin["timestamp"].as_u64().unwrap_or(0),
                    confidence: coin["confidence"].as_f64().unwrap_or(0.5),
                };

                debug!(
                    "DefiLlama price for {}: ${} (confidence: {})",
                    coin_id, price.price, price.confidence
                );

                results.push(price);
            }
        }

        Ok(results)
    }
}

impl Default for DefiLlamaClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default DefiLlamaClient")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_client(mock_server_url: &str) -> DefiLlamaClient {
        let http_client = Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        DefiLlamaClient::for_testing(mock_server_url.to_string(), http_client)
    }

    #[tokio::test]
    async fn test_get_price_success() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "coins": {
                "ethereum:0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": {
                    "decimals": 18,
                    "symbol": "UNI",
                    "price": 3.56,
                    "timestamp": 1770492782,
                    "confidence": 0.99
                }
            }
        }"#;

        let mock = server
            .mock("GET", "/prices/current/ethereum:0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .get_price("ethereum", "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984")
            .await;

        assert!(result.is_ok());
        let price = result.unwrap();
        assert_eq!(price.symbol, "UNI");
        assert!((price.price - 3.56).abs() < 0.01);
        assert_eq!(price.decimals, 18);
        assert!((price.confidence - 0.99).abs() < 0.01);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_price_not_found() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "coins": {}
        }"#;

        let _mock = server
            .mock("GET", "/prices/current/ethereum:0x1234567890123456789012345678901234567890")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .get_price("ethereum", "0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Price not found"));
    }

    #[tokio::test]
    async fn test_get_price_with_low_confidence() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "coins": {
                "ethereum:0x1234567890123456789012345678901234567890": {
                    "decimals": 18,
                    "symbol": "UNKNOWN",
                    "price": 0.001,
                    "timestamp": 1770492782,
                    "confidence": 0.1
                }
            }
        }"#;

        let _mock = server
            .mock("GET", "/prices/current/ethereum:0x1234567890123456789012345678901234567890")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let result = client
            .get_price("ethereum", "0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_ok());
        let price = result.unwrap();
        assert_eq!(price.symbol, "UNKNOWN");
        assert!((price.price - 0.001).abs() < 0.0001);
        assert!((price.confidence - 0.1).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_get_prices_batch_success() {
        let mut server = Server::new_async().await;

        let mock_response = r#"{
            "coins": {
                "ethereum:0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": {
                    "decimals": 18,
                    "symbol": "UNI",
                    "price": 3.56,
                    "timestamp": 1770492782,
                    "confidence": 0.99
                },
                "ethereum:0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9": {
                    "decimals": 18,
                    "symbol": "AAVE",
                    "price": 150.25,
                    "timestamp": 1770492782,
                    "confidence": 0.98
                }
            }
        }"#;

        let _mock = server
            .mock("GET", "/prices/current/ethereum:0x1f9840a85d5af5bf1d1762f925bdaddc4201f984,ethereum:0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = create_test_client(&server.url());

        let coins = vec![
            ("ethereum", "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"),
            ("ethereum", "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9"),
        ];

        let result = client.get_prices_batch(&coins).await;

        assert!(result.is_ok());
        let prices = result.unwrap();
        assert_eq!(prices.len(), 2);
    }

    #[tokio::test]
    async fn test_get_prices_batch_empty() {
        let client = DefiLlamaClient::default();

        let result = client.get_prices_batch(&[]).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_price_disabled() {
        let client = DefiLlamaClient {
            client: Client::new(),
            base_url: "https://coins.llama.fi".to_string(),
            timeout: Duration::from_secs(10),
            enabled: false,
        };

        let result = client
            .get_price("ethereum", "0x1234567890123456789012345678901234567890")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    #[test]
    fn test_defillama_price_serialization() {
        let price = DefiLlamaPrice {
            symbol: "UNI".to_string(),
            price: 3.56,
            decimals: 18,
            timestamp: 1_770_492_782,
            confidence: 0.99,
        };

        let json = serde_json::to_string(&price).unwrap();
        let deserialized: DefiLlamaPrice = serde_json::from_str(&json).unwrap();

        assert_eq!(price.symbol, deserialized.symbol);
        assert!((price.price - deserialized.price).abs() < 0.0001);
        assert_eq!(price.decimals, deserialized.decimals);
        assert_eq!(price.timestamp, deserialized.timestamp);
        assert!((price.confidence - deserialized.confidence).abs() < 0.01);
    }
}
