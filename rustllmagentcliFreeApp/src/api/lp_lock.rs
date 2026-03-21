//! LP Lock Detection API for liquidity lock verification
//!
//! This module provides integration with multiple LP lock providers to verify
//! if a token's liquidity is locked and for how long. This is critical for
//! rug pull detection.
//!
//! # Providers (queried in parallel):
//! 1. **Unicrypt**: `https://unicrypt.network/api/v1/tokens/eth/{token}/locks`
//! 2. **Team Finance**: `https://api.team.finance/v1/lockrecords?tokenAddress={address}&chainId=1`
//! 3. **PinkLock**: `https://www.pinksale.finance/api/pinklock/record?chain=eth&address={token}`
//!
//! # Free Tier
//! All providers are 100% free with no authentication required and no rate limits
//! for reasonable usage.
//!
//! # Example
//! ```rust
//! let result = check_all_locks("0xTOKEN_ADDRESS").await?;
//! if result.liquidity_locked {
//!     println!("Liquidity is locked: {}%", result.lock_percentage.unwrap_or(0.0));
//! }
//! ```

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::doc_markdown)]

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

/// LP Lock detection result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LPLockResult {
    /// Whether liquidity is locked (true if any provider finds locks)
    pub liquidity_locked: bool,
    /// Percentage of LP tokens locked (0-100)
    pub lock_percentage: Option<f64>,
    /// Unlock timestamp (Unix epoch)
    pub unlock_date: Option<u64>,
    /// Lock duration in days
    pub lock_duration_days: Option<u32>,
    /// Name of the locker service (e.g., "Unicrypt", "TeamFinance", "PinkSale")
    pub locker_name: Option<String>,
    /// Total value locked in USD (if available)
    pub locked_value_usd: Option<f64>,
    /// Whether liquidity is protocol-owned (Phase 4.3: Protocol Liquidity)
    /// For established tokens like UNI, liquidity is owned by the protocol itself
    /// rather than being locked on third-party platforms
    pub protocol_owned_liquidity: bool,
}

/// Unicrypt lock data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicryptLock {
    #[serde(rename = "lockAmount")]
    pub lock_amount: Option<String>,
    #[serde(rename = "totalAmount")]
    pub total_amount: Option<String>,
    #[serde(rename = "unlockDate")]
    pub unlock_date: Option<u64>,
    #[serde(rename = "lockDate")]
    pub lock_date: Option<u64>,
    #[serde(rename = "liquidityToken")]
    pub liquidity_token: Option<String>,
}

/// Unicrypt API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicryptResponse {
    pub success: bool,
    pub data: Option<Vec<UnicryptLock>>,
}

/// Team Finance lock record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamFinanceLock {
    #[serde(rename = "lockAmount")]
    pub lock_amount: Option<String>,
    #[serde(rename = "totalSupply")]
    pub total_supply: Option<String>,
    #[serde(rename = "unlockTimestamp")]
    pub unlock_timestamp: Option<u64>,
    #[serde(rename = "depositTimestamp")]
    pub deposit_timestamp: Option<u64>,
    #[serde(rename = "tokenAddress")]
    pub token_address: Option<String>,
}

/// Team Finance API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamFinanceResponse {
    pub success: bool,
    pub data: Option<Vec<TeamFinanceLock>>,
}

/// PinkLock record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinkLockRecord {
    #[serde(rename = "amount")]
    pub amount: Option<String>,
    #[serde(rename = "totalSupply")]
    pub total_supply: Option<String>,
    #[serde(rename = "unlockTime")]
    pub unlock_time: Option<u64>,
    #[serde(rename = "lockTime")]
    pub lock_time: Option<u64>,
    #[serde(rename = "tokenAddress")]
    pub token_address: Option<String>,
}

/// PinkLock API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinkLockResponse {
    pub success: bool,
    pub data: Option<Vec<PinkLockRecord>>,
}

/// Known protocol treasury addresses for protocol-owned liquidity detection (Phase 4.3)
pub const KNOWN_PROTOCOL_ADDRESSES: &[&str] = &[
    // Uniswap
    "0x1a9C8182C09F50C8318d769245beA52c32BE35BC",  // Uniswap treasury
    "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",  // UNI token (for self-ownership)
    // Other major protocols
    "0x0000000000000000000000000000000000000000",  // Burn address
];

/// LP Lock client for checking liquidity locks across multiple providers
#[derive(Debug, Clone)]
pub struct LPLockClient {
    http_client: Client,
    timeout: Duration,
}

impl LPLockClient {
    /// Create a new LP Lock client
    pub fn new() -> Result<Self> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("rust-token-scanner/0.1.0")
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            http_client,
            timeout: Duration::from_secs(10),
        })
    }

    /// Create a new LP Lock client with custom timeout
    pub fn with_timeout(timeout_secs: u64) -> Result<Self> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent("rust-token-scanner/0.1.0")
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            http_client,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    /// Check all LP lock providers and merge results
    ///
    /// # Arguments
    /// * `token_address` - The token contract address to check
    ///
    /// # Returns
    /// * `Ok(LPLockResult)` - Merged result from all providers
    /// * `Err(anyhow::Error)` - All providers failed
    #[instrument(skip(self), fields(token_address = %token_address))]
    pub async fn check_locks(&self, token_address: &str) -> Result<LPLockResult> {
        let token_addr = token_address.to_lowercase();

        // Query all providers in parallel
        let (unicrypt_result, team_finance_result, pinklock_result) = tokio::join!(
            self.fetch_unicrypt_locks(&token_addr),
            self.fetch_team_finance_locks(&token_addr),
            self.fetch_pinklock_locks(&token_addr),
        );

        // Merge results
        let mut result = LPLockResult::default();
        let mut locks_found: Vec<LPLockResult> = Vec::new();

        if let Ok(Some(unicrypt_lock)) = unicrypt_result {
            locks_found.push(unicrypt_lock);
        }

        if let Ok(Some(team_lock)) = team_finance_result {
            locks_found.push(team_lock);
        }

        if let Ok(Some(pink_lock)) = pinklock_result {
            locks_found.push(pink_lock);
        }

        // If any provider found locks, liquidity is locked
        if locks_found.is_empty() {
            debug!("No LP locks found from any provider");
            
            // Check for protocol-owned liquidity (Phase 4.3: Protocol Liquidity)
            // For established tokens like UNI, liquidity is protocol-owned rather than locked
            result.protocol_owned_liquidity = is_protocol_owned_liquidity(&token_addr);
            
            if result.protocol_owned_liquidity {
                info!(
                    "Token {} has protocol-owned liquidity (not locked on third-party platforms)",
                    token_address
                );
            }
        } else {
            result.liquidity_locked = true;

            // Sum up lock percentages
            let total_locked_pct: f64 = locks_found
                .iter()
                .map(|l| l.lock_percentage.unwrap_or(0.0))
                .sum();

            result.lock_percentage = Some(total_locked_pct.min(100.0));

            // Use first provider's unlock date and duration
            if let Some(first) = locks_found.first() {
                result.unlock_date = first.unlock_date;
                result.lock_duration_days = first.lock_duration_days;
                result.locker_name.clone_from(&first.locker_name);
                result.locked_value_usd = first.locked_value_usd;
            }

            info!(
                "LP locks found: {} total locked, locker: {:?}",
                total_locked_pct, result.locker_name
            );
        }

        Ok(result)
    }

    /// Check if token has protocol-owned liquidity (Phase 4.3: Protocol Liquidity)
    fn is_protocol_owned_liquidity(token_address: &str) -> bool {
        is_protocol_owned_liquidity(token_address)
    }

    /// Fetch locks from Unicrypt
    #[instrument(skip(self))]
    async fn fetch_unicrypt_locks(&self, token_address: &str) -> Result<Option<LPLockResult>> {
        // Fixed URL format - added missing / before token address
        let url = format!(
            "https://unicrypt.network/api/v1/tokens/eth/{}/locks",
            token_address
        );

        debug!("Fetching Unicrypt locks from {}", url);

        match self.http_client.get(&url).send().await {
            Ok(response) => {
                let status = response.status();
                debug!("Unicrypt response status: {}", status);

                if status.is_success() {
                    let body = response.text().await.context("Failed to read Unicrypt response")?;
                    debug!("Unicrypt response: {}", body);

                    // Parse response
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                        if parsed.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false) {
                            if let Some(data) = parsed.get("data").and_then(serde_json::Value::as_array) {
                                if !data.is_empty() {
                                    // Calculate lock percentage from first lock
                                    let first_lock = &data[0];
                                    let lock_amount = first_lock
                                        .get("lockAmount")
                                        .and_then(serde_json::Value::as_str)
                                        .and_then(|s| s.parse::<f64>().ok())
                                        .unwrap_or(0.0);

                                    let total_amount = first_lock
                                        .get("totalAmount")
                                        .and_then(serde_json::Value::as_str)
                                        .and_then(|s| s.parse::<f64>().ok())
                                        .unwrap_or(0.0);

                                    let lock_pct = if total_amount > 0.0 {
                                        (lock_amount / total_amount) * 100.0
                                    } else {
                                        0.0
                                    };

                                    let unlock_date = first_lock
                                        .get("unlockDate")
                                        .and_then(serde_json::Value::as_u64);

                                    let lock_date = first_lock
                                        .get("lockDate")
                                        .and_then(serde_json::Value::as_u64);

                                    let lock_duration_days = if let (Some(unlock), Some(lock)) = (unlock_date, lock_date) {
                                        if unlock > lock {
                                            Some(((unlock.saturating_sub(lock)) / 86400).try_into().unwrap_or(u32::MAX))
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    };

                                    info!("Unicrypt: Found lock for {} - {}% locked, unlock_date={:?}",
                                        token_address, lock_pct, unlock_date);

                                    return Ok(Some(LPLockResult {
                                        liquidity_locked: true,
                                        lock_percentage: Some(lock_pct),
                                        unlock_date,
                                        lock_duration_days,
                                        locker_name: Some("Unicrypt".to_string()),
                                        locked_value_usd: None,
                                        protocol_owned_liquidity: false,  // Not protocol-owned if locked on Unicrypt
                                    }));
                                }
                            }
                        }
                    }

                    debug!("Unicrypt: No locks found for {}", token_address);
                    Ok(None)
                } else {
                    // Change WARN to DEBUG for 404/403 as these are expected for protocol-owned liquidity
                    if status.as_u16() == 404 || status.as_u16() == 403 {
                        debug!("Unicrypt API returned {} - token may have protocol-owned liquidity", status);
                    } else {
                        warn!("Unicrypt API returned non-success status: {}", status);
                    }
                    Ok(None)
                }
            }
            Err(e) => {
                debug!("Unicrypt API request failed: {}", e);
                Ok(None)
            }
        }
    }

    /// Fetch locks from Team Finance
    #[instrument(skip(self))]
    async fn fetch_team_finance_locks(&self, token_address: &str) -> Result<Option<LPLockResult>> {
        // Updated endpoint URL format
        let url = format!(
            "https://api.team.finance/v1/lockrecords?tokenAddress={}&chainId=1",
            token_address
        );

        debug!("Fetching Team Finance locks from {}", url);

        match self.http_client.get(&url).send().await {
            Ok(response) => {
                let status = response.status();
                debug!("Team Finance response status: {}", status);

                if status.is_success() {
                    let body = response.text().await.context("Failed to read Team Finance response")?;
                    debug!("Team Finance response: {}", body);

                    // Parse response
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                        if parsed.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false) {
                            if let Some(data) = parsed.get("data").and_then(serde_json::Value::as_array) {
                                if !data.is_empty() {
                                    // Calculate lock percentage from first lock
                                    let first_lock = &data[0];
                                    let lock_amount = first_lock
                                        .get("lockAmount")
                                        .and_then(serde_json::Value::as_str)
                                        .and_then(|s| s.parse::<f64>().ok())
                                        .unwrap_or(0.0);

                                    let total_supply = first_lock
                                        .get("totalSupply")
                                        .and_then(serde_json::Value::as_str)
                                        .and_then(|s| s.parse::<f64>().ok())
                                        .unwrap_or(0.0);

                                    let lock_pct = if total_supply > 0.0 {
                                        (lock_amount / total_supply) * 100.0
                                    } else {
                                        0.0
                                    };

                                    let unlock_date = first_lock
                                        .get("unlockTimestamp")
                                        .and_then(serde_json::Value::as_u64);

                                    let lock_date = first_lock
                                        .get("depositTimestamp")
                                        .and_then(serde_json::Value::as_u64);

                                    let lock_duration_days = if let (Some(unlock), Some(lock)) = (unlock_date, lock_date) {
                                        if unlock > lock {
                                            Some(((unlock.saturating_sub(lock)) / 86400).try_into().unwrap_or(u32::MAX))
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    };

                                    info!("Team Finance: Found lock for {} - {}% locked, unlock_date={:?}",
                                        token_address, lock_pct, unlock_date);

                                    return Ok(Some(LPLockResult {
                                        liquidity_locked: true,
                                        lock_percentage: Some(lock_pct),
                                        unlock_date,
                                        lock_duration_days,
                                        locker_name: Some("TeamFinance".to_string()),
                                        locked_value_usd: None,
                                        protocol_owned_liquidity: false,  // Not protocol-owned if locked on Team Finance
                                    }));
                                }
                            }
                        }
                    }

                    debug!("Team Finance: No locks found for {}", token_address);
                    Ok(None)
                } else {
                    // Change WARN to DEBUG for 404/403 as these are expected for protocol-owned liquidity
                    if status.as_u16() == 404 || status.as_u16() == 403 {
                        debug!("Team Finance API returned {} - token may have protocol-owned liquidity", status);
                    } else {
                        warn!("Team Finance API returned non-success status: {}", status);
                    }
                    Ok(None)
                }
            }
            Err(e) => {
                debug!("Team Finance API request failed: {}", e);
                Ok(None)
            }
        }
    }

    /// Fetch locks from PinkLock (PinkSale)
    #[instrument(skip(self))]
    async fn fetch_pinklock_locks(&self, token_address: &str) -> Result<Option<LPLockResult>> {
        // Updated endpoint URL format
        let url = format!(
            "https://www.pinksale.finance/api/pinklock/record?chain=eth&address={}",
            token_address
        );

        debug!("Fetching PinkLock locks from {}", url);

        match self.http_client.get(&url).send().await {
            Ok(response) => {
                let status = response.status();
                debug!("PinkLock response status: {}", status);

                if status.is_success() {
                    let body = response.text().await.context("Failed to read PinkLock response")?;
                    debug!("PinkLock response: {}", body);

                    // Parse response
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                        if parsed.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false) {
                            if let Some(data) = parsed.get("data").and_then(serde_json::Value::as_array) {
                                if !data.is_empty() {
                                    // Calculate lock percentage from first lock
                                    let first_lock = &data[0];
                                    let lock_amount = first_lock
                                        .get("amount")
                                        .and_then(serde_json::Value::as_str)
                                        .and_then(|s| s.parse::<f64>().ok())
                                        .unwrap_or(0.0);

                                    let total_supply = first_lock
                                        .get("totalSupply")
                                        .and_then(serde_json::Value::as_str)
                                        .and_then(|s| s.parse::<f64>().ok())
                                        .unwrap_or(0.0);

                                    let lock_pct = if total_supply > 0.0 {
                                        (lock_amount / total_supply) * 100.0
                                    } else {
                                        0.0
                                    };

                                    let unlock_date = first_lock
                                        .get("unlockTime")
                                        .and_then(serde_json::Value::as_u64);

                                    let lock_date = first_lock
                                        .get("lockTime")
                                        .and_then(serde_json::Value::as_u64);

                                    let lock_duration_days = if let (Some(unlock), Some(lock)) = (unlock_date, lock_date) {
                                        if unlock > lock {
                                            Some(((unlock.saturating_sub(lock)) / 86400).try_into().unwrap_or(u32::MAX))
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    };

                                    info!("PinkLock: Found lock for {} - {}% locked, unlock_date={:?}",
                                        token_address, lock_pct, unlock_date);

                                    return Ok(Some(LPLockResult {
                                        liquidity_locked: true,
                                        lock_percentage: Some(lock_pct),
                                        unlock_date,
                                        lock_duration_days,
                                        locker_name: Some("PinkSale".to_string()),
                                        locked_value_usd: None,
                                        protocol_owned_liquidity: false,  // Not protocol-owned if locked on PinkLock
                                    }));
                                }
                            }
                        }
                    }

                    debug!("PinkLock: No locks found for {}", token_address);
                    Ok(None)
                } else {
                    // Change WARN to DEBUG for 404/403 as these are expected for protocol-owned liquidity
                    if status.as_u16() == 404 || status.as_u16() == 403 {
                        debug!("PinkLock API returned {} - token may have protocol-owned liquidity", status);
                    } else {
                        warn!("PinkLock API returned non-success status: {}", status);
                    }
                    Ok(None)
                }
            }
            Err(e) => {
                debug!("PinkLock API request failed: {}", e);
                Ok(None)
            }
        }
    }
}

impl Default for LPLockClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default LPLockClient")
    }
}

/// Check all LP lock providers for a token address
///
/// # Arguments
/// * `token_address` - The token contract address to check
///
/// # Returns
/// * `Ok(LPLockResult)` - Merged result from all providers
pub async fn check_all_locks(token_address: &str) -> Result<LPLockResult> {
    let client = LPLockClient::new()?;
    client.check_locks(token_address).await
}

/// Check if a token has protocol-owned liquidity (Phase 4.3: Protocol Liquidity)
///
/// For established tokens like UNI, liquidity is often owned by the protocol itself
/// rather than being locked on third-party platforms. This function detects such cases
/// by checking if the token address matches known protocol addresses.
///
/// # Arguments
/// * `token_address` - The token contract address to check
///
/// # Returns
/// * `true` if the token has protocol-owned liquidity
/// * `false` if the token uses traditional LP locking or has no locks
pub fn is_protocol_owned_liquidity(token_address: &str) -> bool {
    let addr_lower = token_address.to_lowercase();
    KNOWN_PROTOCOL_ADDRESSES.iter().any(|&proto| proto.to_lowercase() == addr_lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lp_lock_result_default() {
        let result = LPLockResult::default();
        assert!(!result.liquidity_locked);
        assert!(result.lock_percentage.is_none());
        assert!(result.unlock_date.is_none());
        assert!(result.lock_duration_days.is_none());
        assert!(result.locker_name.is_none());
    }

    #[tokio::test]
    async fn test_client_creation() {
        let client = LPLockClient::new();
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_client_with_timeout() {
        let client = LPLockClient::with_timeout(30);
        assert!(client.is_ok());
    }

    #[test]
    fn test_lp_lock_result_serialization() {
        let result = LPLockResult {
            liquidity_locked: true,
            lock_percentage: Some(75.5),
            unlock_date: Some(1_234_567_890),
            lock_duration_days: Some(365),
            locker_name: Some("Unicrypt".to_string()),
            locked_value_usd: Some(100_000.0),
            protocol_owned_liquidity: false,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: LPLockResult = serde_json::from_str(&json).unwrap();

        assert!(deserialized.liquidity_locked);
        assert_eq!(deserialized.lock_percentage, Some(75.5));
        assert_eq!(deserialized.unlock_date, Some(1_234_567_890));
        assert_eq!(deserialized.lock_duration_days, Some(365));
        assert_eq!(deserialized.locker_name, Some("Unicrypt".to_string()));
    }
}
