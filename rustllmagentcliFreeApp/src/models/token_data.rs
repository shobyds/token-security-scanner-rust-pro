//! Unified TokenData model for aggregating security analysis results
//!
//! This model aggregates data from multiple API providers (Dexscreener, Honeypot.is,
//! GoPlus, Etherscan, Bitquery) into a single comprehensive token security profile.

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::float_cmp)]

use serde::{Deserialize, Serialize};

/// Unified token data structure aggregating results from all API providers
///
/// This struct combines liquidity data, honeypot detection, contract risk analysis,
/// metadata verification, and transaction analysis into a single security profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenData {
    /// Token contract address
    pub token_address: String,
    /// Blockchain network (ethereum, bsc, polygon, etc.)
    pub chain: String,
    /// Total liquidity in USD
    pub liquidity_usd: f64,
    /// Current price in USD
    pub price_usd: f64,
    /// Price confidence score from DefiLlama (0.0-1.0) - Phase 1 Task 1.6 Sprint 3 INT-001
    pub price_confidence: Option<f64>,
    /// Trading volume in the last 24 hours (USD)
    pub volume_24h: f64,
    /// Number of token holders
    pub holder_count: u64,
    /// Buy tax percentage (0-100)
    pub buy_tax: f32,
    /// Sell tax percentage (0-100)
    pub sell_tax: f32,
    /// Whether the contract owner can mint new tokens
    pub owner_can_mint: bool,
    /// Whether the contract owner can blacklist addresses
    pub owner_can_blacklist: bool,
    /// Whether liquidity pool tokens are locked
    pub lp_locked: bool,
    /// Percentage of tokens held by top holders
    pub top_holder_percent: f32,
    /// Whether the contract source code is verified
    pub contract_verified: bool,
    /// Whether the token is detected as a honeypot
    pub is_honeypot: bool,
    /// Contract name from verification data
    pub contract_name: String,
    /// Total token supply (formatted string for precision)
    pub total_supply: String,
}

impl Default for TokenData {
    fn default() -> Self {
        Self {
            token_address: String::new(),
            chain: String::new(),
            liquidity_usd: 0.0,
            price_usd: 0.0,
            price_confidence: None,
            volume_24h: 0.0,
            holder_count: 0,
            buy_tax: 0.0,
            sell_tax: 0.0,
            owner_can_mint: false,
            owner_can_blacklist: false,
            lp_locked: false,
            top_holder_percent: 0.0,
            contract_verified: false,
            is_honeypot: false,
            contract_name: String::new(),
            total_supply: String::new(),
        }
    }
}

impl TokenData {
    /// Create a new TokenData instance with the given address and chain
    pub fn new(token_address: impl Into<String>, chain: impl Into<String>) -> Self {
        Self {
            token_address: token_address.into(),
            chain: chain.into(),
            ..Default::default()
        }
    }

    /// Calculate a risk score based on the token data (0-100, higher is riskier)
    #[must_use]
    pub fn risk_score(&self) -> u8 {
        let mut score: u8 = 0;

        // Honeypot detection is critical
        if self.is_honeypot {
            score = score.saturating_add(50);
        }

        // Owner privileges
        if self.owner_can_mint {
            score = score.saturating_add(15);
        }
        if self.owner_can_blacklist {
            score = score.saturating_add(15);
        }

        // Liquidity concerns
        if self.liquidity_usd < 1000.0 {
            score = score.saturating_add(10);
        } else if self.liquidity_usd < 10000.0 {
            score = score.saturating_add(5);
        }

        // High holder concentration
        if self.top_holder_percent > 50.0 {
            score = score.saturating_add(15);
        } else if self.top_holder_percent > 30.0 {
            score = score.saturating_add(10);
        }

        // Contract verification
        if !self.contract_verified {
            score = score.saturating_add(10);
        }

        // High taxes
        if self.buy_tax > 10.0 || self.sell_tax > 10.0 {
            score = score.saturating_add(10);
        }

        score.min(100)
    }

    /// Check if the token is considered safe based on configurable thresholds
    #[must_use]
    pub fn is_safe(&self, max_risk_score: u8) -> bool {
        self.risk_score() <= max_risk_score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_data_default() {
        let data = TokenData::default();
        assert_eq!(data.token_address, "");
        assert_eq!(data.chain, "");
        assert_eq!(data.liquidity_usd, 0.0);
        assert_eq!(data.price_usd, 0.0);
        assert!(!data.is_honeypot);
        assert!(!data.owner_can_mint);
        assert!(!data.contract_verified);
    }

    #[test]
    fn test_token_data_new() {
        let data = TokenData::new("0x1234", "ethereum");
        assert_eq!(data.token_address, "0x1234");
        assert_eq!(data.chain, "ethereum");
    }

    #[test]
    fn test_risk_score_honeypot() {
        let mut data = TokenData::default();
        data.is_honeypot = true;
        assert!(data.risk_score() >= 50);
    }

    #[test]
    fn test_risk_score_owner_privileges() {
        let mut data = TokenData::default();
        data.owner_can_mint = true;
        data.owner_can_blacklist = true;
        assert!(data.risk_score() >= 30);
    }

    #[test]
    fn test_risk_score_low_liquidity() {
        let mut data = TokenData::default();
        data.liquidity_usd = 500.0;
        assert!(data.risk_score() >= 10);
    }

    #[test]
    fn test_risk_score_high_concentration() {
        let mut data = TokenData::default();
        data.top_holder_percent = 60.0;
        assert!(data.risk_score() >= 15);
    }

    #[test]
    fn test_risk_score_unverified() {
        let mut data = TokenData::default();
        data.contract_verified = false;
        assert!(data.risk_score() >= 10);
    }

    #[test]
    fn test_risk_score_high_taxes() {
        let mut data = TokenData::default();
        data.buy_tax = 15.0;
        data.sell_tax = 15.0;
        assert!(data.risk_score() >= 10);
    }

    #[test]
    fn test_risk_score_maximum() {
        let mut data = TokenData::default();
        data.is_honeypot = true;
        data.owner_can_mint = true;
        data.owner_can_blacklist = true;
        data.liquidity_usd = 100.0;
        data.top_holder_percent = 80.0;
        data.contract_verified = false;
        data.buy_tax = 20.0;
        data.sell_tax = 20.0;
        assert_eq!(data.risk_score(), 100);
    }

    #[test]
    fn test_is_safe() {
        let mut data = TokenData::default();
        assert!(data.is_safe(50));

        data.is_honeypot = true;
        assert!(!data.is_safe(30));
    }

    #[test]
    fn test_token_data_serialization() {
        let data = TokenData {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            liquidity_usd: 100_000.0,
            price_usd: 1.5,
            price_confidence: Some(0.95),
            volume_24h: 50_000.0,
            holder_count: 1000,
            buy_tax: 5.0,
            sell_tax: 5.0,
            owner_can_mint: false,
            owner_can_blacklist: false,
            lp_locked: true,
            top_holder_percent: 25.0,
            contract_verified: true,
            is_honeypot: false,
            contract_name: "TestToken".to_string(),
            total_supply: "1000000000".to_string(),
        };

        let json = serde_json::to_string(&data).unwrap();
        let deserialized: TokenData = serde_json::from_str(&json).unwrap();

        assert_eq!(data.token_address, deserialized.token_address);
        assert_eq!(data.chain, deserialized.chain);
        assert_eq!(data.liquidity_usd, deserialized.liquidity_usd);
        assert_eq!(data.price_usd, deserialized.price_usd);
        assert_eq!(data.price_confidence, deserialized.price_confidence);
    }
}
