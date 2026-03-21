//! Telegram Alerting Module for Token Risk Analysis
//!
//! This module provides functionality to send Telegram alerts when
//! high-risk tokens are detected. It includes rate limiting to prevent
//! spam and tracks sent alerts for deduplication.

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::scanner::TriResult;

/// Telegram alert configuration
#[derive(Debug, Clone)]
pub struct TelegramAlertConfig {
    /// Telegram bot token
    pub bot_token: Option<String>,
    /// Chat ID to send alerts to
    pub chat_id: Option<String>,
    /// Minimum rug probability to trigger alert
    pub alert_threshold: f32,
    /// Rate limit in minutes between alerts
    pub rate_limit_minutes: u64,
}

impl Default for TelegramAlertConfig {
    fn default() -> Self {
        Self {
            bot_token: None,
            chat_id: None,
            alert_threshold: 0.45,
            rate_limit_minutes: 10,
        }
    }
}

impl TelegramAlertConfig {
    /// Check if the configuration is valid (has required credentials)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.bot_token.is_some() && self.chat_id.is_some()
    }

    /// Get the bot token or empty string
    #[must_use]
    pub fn bot_token_or_empty(&self) -> &str {
        self.bot_token.as_deref().unwrap_or("")
    }

    /// Get the chat ID or empty string
    #[must_use]
    pub fn chat_id_or_empty(&self) -> &str {
        self.chat_id.as_deref().unwrap_or("")
    }
}

/// Record of a sent Telegram alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentAlert {
    /// Token address that triggered the alert
    pub token_address: String,
    /// Chain
    pub chain: String,
    /// Timestamp when alert was sent (Unix timestamp in seconds)
    pub sent_at: u64,
    /// TRI score that triggered the alert
    pub tri_score: f32,
    /// Rug probability
    pub rug_probability: f32,
    /// Message ID of the sent alert
    pub message_id: Option<i64>,
}

impl SentAlert {
    /// Create a new sent alert record
    #[must_use]
    pub fn new(
        token_address: String,
        chain: String,
        tri_score: f32,
        rug_probability: f32,
        message_id: Option<i64>,
    ) -> Self {
        Self {
            token_address,
            chain,
            sent_at: current_timestamp(),
            tri_score,
            rug_probability,
            message_id,
        }
    }

    /// Check if this alert was sent within the rate limit window
    #[must_use]
    pub fn is_within_rate_limit(&self, rate_limit_minutes: u64) -> bool {
        let now = current_timestamp();
        let rate_limit_seconds = rate_limit_minutes * 60;
        now - self.sent_at < rate_limit_seconds
    }
}

/// Telegram alert manager with rate limiting
pub struct TelegramAlertManager {
    http_client: Client,
    config: TelegramAlertConfig,
    sent_alerts: Vec<SentAlert>,
}

impl TelegramAlertManager {
    /// Create a new alert manager with the given configuration
    #[must_use]
    pub fn new(config: TelegramAlertConfig) -> Self {
        Self {
            http_client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            config,
            sent_alerts: Vec::new(),
        }
    }

    /// Create alert manager from environment variables
    #[must_use]
    pub fn from_env() -> Self {
        let config = TelegramAlertConfig {
            bot_token: std::env::var("TELEGRAM_BOT_TOKEN").ok(),
            chat_id: std::env::var("TELEGRAM_CHAT_ID").ok(),
            alert_threshold: std::env::var("TELEGRAM_ALERT_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.45),
            rate_limit_minutes: std::env::var("TELEGRAM_RATE_LIMIT_MINUTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
        };

        Self::new(config)
    }

    /// Check if an alert should be sent for the given TRI result
    ///
    /// # Arguments
    /// * `tri_result` - The TRI result to evaluate
    /// * `rug_probability` - The ML-computed rug probability
    ///
    /// # Returns
    /// * `true` if an alert should be sent
    #[must_use]
    pub fn should_send_alert(&self, tri_result: &TriResult, rug_probability: f32) -> bool {
        // Check if configuration is valid
        if !self.config.is_valid() {
            debug!("Telegram not configured, skipping alert");
            return false;
        }

        // Check if rug probability exceeds threshold
        if rug_probability < self.config.alert_threshold {
            debug!(
                "Rug probability {:.2} below threshold {:.2}",
                rug_probability, self.config.alert_threshold
            );
            return false;
        }

        // Check rate limiting
        if self.is_rate_limited() {
            debug!("Rate limited, skipping alert");
            return false;
        }

        // Check for duplicate alerts (same token)
        if self.is_duplicate_alert(&tri_result.token_address) {
            debug!("Duplicate alert for token, skipping");
            return false;
        }

        true
    }

    /// Send a Telegram alert for a high-risk token
    ///
    /// # Arguments
    /// * `tri_result` - The TRI result containing risk analysis
    /// * `rug_probability` - The ML-computed rug probability
    ///
    /// # Returns
    /// * `Ok(Option<i64>)` - Message ID if sent successfully, None if skipped
    /// * `Err(String)` - Error message if sending failed
    pub async fn send_alert(
        &mut self,
        tri_result: &TriResult,
        rug_probability: f32,
    ) -> Result<Option<i64>, String> {
        // Check if we should send
        if !self.should_send_alert(tri_result, rug_probability) {
            return Ok(None);
        }

        // Build alert message
        let message = Self::build_alert_message(tri_result, rug_probability);

        // Send to Telegram
        match self.send_telegram_message(&message).await {
            Ok(message_id) => {
                // Record the sent alert
                let alert = SentAlert::new(
                    tri_result.token_address.clone(),
                    tri_result.chain.clone(),
                    tri_result.tri,
                    rug_probability,
                    Some(message_id),
                );
                self.sent_alerts.push(alert);

                // Clean up old alerts
                self.cleanup_old_alerts();

                info!(
                    "Telegram alert sent for {} (TRI: {:.1}, Rug: {:.2})",
                    tri_result.token_address, tri_result.tri, rug_probability
                );

                Ok(Some(message_id))
            }
            Err(e) => {
                error!("Failed to send Telegram alert: {}", e);
                Err(e)
            }
        }
    }

    /// Check if currently rate limited
    #[must_use]
    pub fn is_rate_limited(&self) -> bool {
        if let Some(last_alert) = self.sent_alerts.last() {
            return last_alert.is_within_rate_limit(self.config.rate_limit_minutes);
        }
        false
    }

    /// Check if an alert was already sent for this token
    #[must_use]
    pub fn is_duplicate_alert(&self, token_address: &str) -> bool {
        self.sent_alerts
            .iter()
            .any(|alert| alert.token_address == token_address)
    }

    /// Get the number of sent alerts
    #[must_use]
    pub fn sent_alert_count(&self) -> usize {
        self.sent_alerts.len()
    }

    /// Get recent sent alerts
    #[must_use]
    pub fn get_recent_alerts(&self, limit: usize) -> &[SentAlert] {
        let start = self.sent_alerts.len().saturating_sub(limit);
        &self.sent_alerts[start..]
    }

    /// Clear all sent alerts
    pub fn clear_alerts(&mut self) {
        self.sent_alerts.clear();
    }

    /// Build the alert message
    #[allow(clippy::too_many_lines)]
    fn build_alert_message(tri_result: &TriResult, rug_probability: f32) -> String {
        use std::fmt::Write;

        let risk_emoji = match tri_result.tri_label {
            crate::scanner::TriLabel::VerySafe => "🟢",
            crate::scanner::TriLabel::ModerateRisk => "🟡",
            crate::scanner::TriLabel::HighRisk => "🟠",
            crate::scanner::TriLabel::Avoid => "🔴",
        };

        let truncated_addr = truncate_address(&tri_result.token_address);
        let rug_pct = rug_probability * 100.0;

        let mut message = format!(
            "🚨 *TOKEN RISK ALERT* 🚨\n\n\
            *Token:* `{truncated_addr}`\n\
            *Chain:* {}\n\
            *TRI Score:* {:.1}/100 {risk_emoji}\n\
            *Rug Probability:* {rug_pct:.1}%\n\n",
            tri_result.chain,
            tri_result.tri,
        );

        // Add red flags
        if !tri_result.red_flags.is_empty() {
            message.push_str("*🔴 Red Flags:*\n");
            for (i, flag) in tri_result.red_flags.iter().take(5).enumerate() {
                let _ = writeln!(
                    message,
                    "{}. {} - {}",
                    i + 1,
                    flag.category,
                    flag.description
                );
            }
            if tri_result.red_flags.len() > 5 {
                let remaining = tri_result.red_flags.len() - 5;
                let _ = writeln!(message, "... and {remaining} more");
            } else {
                message.push('\n');
            }
        }

        // Add domain scores
        let _ = writeln!(message, "*Risk Breakdown:*");
        let _ = writeln!(message, "• Contract: {:.1}", tri_result.contract_risk);
        let _ = writeln!(message, "• Liquidity: {:.1}", tri_result.lp_score);
        let _ = writeln!(message, "• Ownership: {:.1}", tri_result.ownership_risk);
        let _ = writeln!(message, "• Tax: {:.1}", tri_result.tax_risk);
        let _ = writeln!(message, "• Honeypot: {:.1}", tri_result.honeypot_risk);
        let _ = writeln!(message, "• Volume: {:.1}", tri_result.volume_risk);
        let _ = writeln!(message, "• Dev Behavior: {:.1}", tri_result.dev_behavior);
        let _ = writeln!(message, "• Age: {:.1}", tri_result.age_risk);

        message.push_str("\n⚠️ *Always do your own research!*");

        message
    }

    /// Send a message to Telegram
    async fn send_telegram_message(&self, message: &str) -> Result<i64, String> {
        let bot_token = self.config.bot_token_or_empty();
        let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");

        let payload = serde_json::json!({
            "chat_id": self.config.chat_id_or_empty(),
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": true
        });

        let response = self
            .http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {e}"))?;

        if !response.status().is_success() {
            return Err(format!("Telegram API error: {}", response.status()));
        }

        let response_body: TelegramResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {e}"))?;

        if !response_body.ok {
            return Err(format!(
                "Telegram error: {}",
                response_body.description.unwrap_or_default()
            ));
        }

        Ok(response_body.result.message_id)
    }

    /// Clean up alerts older than 24 hours
    fn cleanup_old_alerts(&mut self) {
        let cutoff = current_timestamp() - (24 * 60 * 60);
        self.sent_alerts.retain(|alert| alert.sent_at > cutoff);
    }
}

/// Telegram API response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TelegramResponse {
    ok: bool,
    result: TelegramMessageResult,
    description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TelegramMessageResult {
    message_id: i64,
}

/// Get current Unix timestamp in seconds
#[must_use]
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Truncate an address for display
#[must_use]
fn truncate_address(address: &str) -> String {
    if address.len() <= 10 {
        return address.to_string();
    }
    format!("{}...{}", &address[..6], &address[address.len() - 4..])
}

/// Send a Telegram alert (convenience function)
///
/// This is a stateless version that doesn't track rate limiting.
/// For production use, prefer using `TelegramAlertManager`.
///
/// # Arguments
/// * `bot_token` - Telegram bot token
/// * `chat_id` - Chat ID to send to
/// * `message` - Message to send
///
/// # Returns
/// * `Ok(i64)` - Message ID if successful
/// * `Err(String)` - Error message
pub async fn send_telegram_alert(
    bot_token: &str,
    chat_id: &str,
    message: &str,
) -> Result<i64, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");

    let payload = serde_json::json!({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": true
    });

    let response = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("Telegram API error: {}", response.status()));
    }

    let response_body: TelegramResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {e}"))?;

    if !response_body.ok {
        return Err(format!(
            "Telegram error: {}",
            response_body.description.unwrap_or_default()
        ));
    }

    Ok(response_body.result.message_id)
}

/// Format a simple alert message without markdown
#[must_use]
pub fn format_simple_alert(tri_result: &TriResult, rug_probability: f32) -> String {
    format!(
        "🚨 TOKEN RISK ALERT 🚨\n\n\
         Token: {}\n\
         Chain: {}\n\
         TRI Score: {:.1}/100\n\
         Rug Probability: {:.1}%\n\n\
         Red Flags: {}\n\
         Recommendation: {}",
        truncate_address(&tri_result.token_address),
        tri_result.chain,
        tri_result.tri,
        rug_probability * 100.0,
        tri_result.red_flag_count(),
        tri_result.tri_label
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{GreenFlag, RedFlag, TriLabel};

    fn create_test_tri_result() -> TriResult {
        TriResult {
            token_address: "0x1234567890123456789012345678901234567890".to_string(),
            chain: "ethereum".to_string(),
            contract_risk: 40.0,
            lp_score: 20.0,
            ownership_risk: 30.0,
            tax_risk: 15.0,
            honeypot_risk: 10.0,
            volume_risk: 5.0,
            dev_behavior: 0.0,
            age_risk: 2.0,
            tri: 25.5,
            tri_label: TriLabel::ModerateRisk,
            red_flags: vec![
                RedFlag::new("Contract", "Owner can mint", 0.7),
                RedFlag::new("Liquidity", "LP not locked", 0.6),
            ],
            green_flags: vec![GreenFlag::new("Age", "Token is 7 days old")],
            computed_at: current_timestamp(),
        }
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_telegram_config_default() {
        let config = TelegramAlertConfig::default();
        assert!(!config.is_valid());
        assert_eq!(config.alert_threshold, 0.45);
        assert_eq!(config.rate_limit_minutes, 10);
    }

    #[test]
    fn test_telegram_config_valid() {
        let config = TelegramAlertConfig {
            bot_token: Some("test_token".to_string()),
            chat_id: Some("test_chat".to_string()),
            ..Default::default()
        };
        assert!(config.is_valid());
        assert_eq!(config.bot_token_or_empty(), "test_token");
        assert_eq!(config.chat_id_or_empty(), "test_chat");
    }

    #[test]
    fn test_sent_alert_rate_limit() {
        let alert = SentAlert {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            sent_at: current_timestamp(),
            tri_score: 50.0,
            rug_probability: 0.6,
            message_id: Some(12345),
        };

        assert!(alert.is_within_rate_limit(10));
        assert!(!alert.is_within_rate_limit(0));
    }

    #[test]
    fn test_alert_manager_should_send() {
        let config = TelegramAlertConfig {
            bot_token: Some("test".to_string()),
            chat_id: Some("test".to_string()),
            alert_threshold: 0.45,
            rate_limit_minutes: 10,
        };
        let manager = TelegramAlertManager::new(config);

        let tri_result = create_test_tri_result();

        // Should not send - rug probability below threshold
        assert!(!manager.should_send_alert(&tri_result, 0.30));

        // Should send - rug probability above threshold
        assert!(manager.should_send_alert(&tri_result, 0.50));
    }

    #[test]
    fn test_alert_manager_not_configured() {
        let manager = TelegramAlertManager::new(TelegramAlertConfig::default());
        let tri_result = create_test_tri_result();

        // Should not send - not configured
        assert!(!manager.should_send_alert(&tri_result, 0.80));
    }

    #[test]
    fn test_truncate_address() {
        assert_eq!(
            truncate_address("0x1234567890123456789012345678901234567890"),
            "0x1234...7890"
        );
        assert_eq!(truncate_address("0x1234"), "0x1234");
        assert_eq!(truncate_address("short"), "short");
    }

    #[test]
    fn test_format_simple_alert() {
        let tri_result = create_test_tri_result();
        let message = format_simple_alert(&tri_result, 0.55);

        assert!(message.contains("TOKEN RISK ALERT"));
        assert!(message.contains("0x1234...7890"));
        assert!(message.contains("25.5"));
        assert!(message.contains("55.0%"));
        assert!(message.contains("MODERATE RISK"));
    }

    #[test]
    fn test_alert_manager_rate_limiting() {
        let config = TelegramAlertConfig {
            bot_token: Some("test".to_string()),
            chat_id: Some("test".to_string()),
            rate_limit_minutes: 10,
            ..Default::default()
        };
        let mut manager = TelegramAlertManager::new(config);

        // Add a recent alert
        manager.sent_alerts.push(SentAlert::new(
            "0x1234".to_string(),
            "ethereum".to_string(),
            50.0,
            0.6,
            Some(12345),
        ));

        assert!(manager.is_rate_limited());
    }

    #[test]
    fn test_alert_manager_duplicate_detection() {
        let config = TelegramAlertConfig {
            bot_token: Some("test".to_string()),
            chat_id: Some("test".to_string()),
            rate_limit_minutes: 0, // No rate limiting for this test
            ..Default::default()
        };
        let mut manager = TelegramAlertManager::new(config);

        // Add an alert for a specific token
        manager.sent_alerts.push(SentAlert::new(
            "0x1234".to_string(),
            "ethereum".to_string(),
            50.0,
            0.6,
            Some(12345),
        ));

        assert!(manager.is_duplicate_alert("0x1234"));
        assert!(!manager.is_duplicate_alert("0x5678"));
    }

    #[test]
    fn test_alert_manager_cleanup() {
        let config = TelegramAlertConfig::default();
        let mut manager = TelegramAlertManager::new(config);

        // Add old alert (25 hours ago)
        let mut old_alert = SentAlert::new(
            "0x1234".to_string(),
            "ethereum".to_string(),
            50.0,
            0.6,
            Some(12345),
        );
        old_alert.sent_at = current_timestamp() - (25 * 60 * 60);
        manager.sent_alerts.push(old_alert);

        // Add recent alert
        manager.sent_alerts.push(SentAlert::new(
            "0x5678".to_string(),
            "ethereum".to_string(),
            60.0,
            0.7,
            Some(12346),
        ));

        manager.cleanup_old_alerts();

        // Should only have the recent alert
        assert_eq!(manager.sent_alerts.len(), 1);
        assert_eq!(manager.sent_alerts[0].token_address, "0x5678");
    }

    #[test]
    fn test_build_alert_message() {
        let tri_result = create_test_tri_result();

        let message = TelegramAlertManager::build_alert_message(&tri_result, 0.55);

        assert!(message.contains("TOKEN RISK ALERT"));
        assert!(message.contains("TRI Score"));
        assert!(message.contains("Red Flags"));
        assert!(message.contains("Risk Breakdown"));
    }
}
