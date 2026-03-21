//! ML Pre-Scoring Layer for Token Risk Analysis
//!
//! This module provides a fast, deterministic pre-filter that computes
//! a rug probability score before calling the Phi-3 LLM. If the ML score
//! is below the threshold (default 0.35), the LLM call is skipped to
//! save inference costs and reduce latency.
//!
//! # Implementation
//! This is a weighted rule-based scorer, not a neural network. It uses
//! hard rules for critical risk factors and soft rules for secondary factors.

#![allow(clippy::module_name_repetitions)]

use crate::scanner::TokenMetrics;

/// Compute rug probability score using weighted rule-based scoring
///
/// This function implements a fast, deterministic pre-filter that combines
/// multiple risk signals into a single probability score (0.0-1.0).
///
/// # Algorithm
/// 1. Hard rules: Critical risk factors that instantly increase probability
/// 2. Soft rules: Secondary factors that add incremental risk
/// 3. Final score is clamped to [0.0, 1.0]
///
/// # Arguments
/// * `metrics` - Token metrics extracted from scan results
///
/// # Returns
/// * `f32` - Rug probability score (0.0 = safe, 1.0 = definite rug)
///
/// # Thresholds
/// - < 0.35: Skip LLM analysis (low risk)
/// - >= 0.35: Call LLM for detailed analysis
/// - >= 0.70: High risk, consider immediate alert
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn compute_rug_probability(metrics: &TokenMetrics) -> f32 {
    let mut score: f32 = 0.0;

    // =========================================================================
    // HARD RULES - Critical risk factors
    // =========================================================================

    // Confirmed honeypot is the strongest signal
    if metrics.is_honeypot {
        score += 0.40;
    }

    // Cannot sell is definitive honeypot behavior
    if !metrics.can_sell {
        return 1.0; // Immediate maximum score
    }

    // Owner can mint new tokens (infinite supply risk)
    if metrics.owner_can_mint {
        score += 0.20;
    }

    // Dangerously low liquidity
    if metrics.liquidity_usd < 1000.0 {
        score += 0.15;
    } else if metrics.liquidity_usd < 5000.0 {
        score += 0.08;
    }

    // Hidden owner detected
    if metrics.hidden_owner {
        score += 0.15;
    }

    // Owner can blacklist addresses
    if metrics.owner_can_blacklist {
        score += 0.12;
    }

    // Selfdestruct function present
    if metrics.selfdestruct {
        score += 0.15;
    }

    // =========================================================================
    // SOFT RULES - Secondary risk factors
    // =========================================================================

    // High sell tax
    if metrics.sell_tax > 30.0 {
        score += 0.15;
    } else if metrics.sell_tax > 20.0 {
        score += 0.10;
    } else if metrics.sell_tax > 10.0 {
        score += 0.05;
    }

    // Asymmetric tax (sell trap)
    if metrics.sell_tax > metrics.buy_tax * 2.0 {
        score += 0.08;
    }

    // High dev wallet concentration
    if metrics.dev_wallet_percent > 20.0 {
        score += 0.12;
    } else if metrics.dev_wallet_percent > 15.0 {
        score += 0.10;
    } else if metrics.dev_wallet_percent > 10.0 {
        score += 0.05;
    }

    // High holder concentration
    if metrics.top10_holders_percent > 90.0 {
        score += 0.10;
    } else if metrics.top10_holders_percent > 80.0 {
        score += 0.08;
    } else if metrics.top10_holders_percent > 70.0 {
        score += 0.05;
    }

    // LP not locked or short lock period
    if !metrics.lp_locked {
        score += 0.10;
    } else if metrics.lp_lock_days < 30 {
        score += 0.07;
    } else if metrics.lp_lock_days < 90 {
        score += 0.03;
    }

    // Very new token (Phase 0 Task 0.3: Handle Option<f64>)
    let age = metrics.token_age_minutes.unwrap_or(0.0);
    if age < 5.0 {
        score += 0.08;
    } else if age < 10.0 {
        score += 0.05;
    } else if age < 60.0 {
        score += 0.02;
    }

    // Deployer wallet age (Phase 1 Task 1.3)
    // Fresh deployer wallet is a top rug signal
    if let Some(wallet_age_days) = metrics.deployer_wallet_age_days {
        if wallet_age_days < 1 {
            // Brand new deployer wallet (< 1 day old)
            score += 0.15;
        } else if wallet_age_days < 7 {
            // Fresh deployer wallet (< 1 week old)
            score += 0.10;
        } else if wallet_age_days < 30 {
            // Recent deployer wallet (< 1 month old)
            score += 0.05;
        }
        // > 30 days = no additional risk from wallet age
    }

    // High sniper activity
    if metrics.sniper_ratio > 0.50 {
        score += 0.08;
    } else if metrics.sniper_ratio > 0.40 {
        score += 0.05;
    } else if metrics.sniper_ratio > 0.20 {
        score += 0.03;
    }

    // Suspicious volume patterns
    if metrics.volume_to_lp_ratio > 5.0 {
        score += 0.08; // Possible wash trading
    } else if metrics.volume_to_lp_ratio > 3.0 {
        score += 0.04;
    }

    // Low unique trader ratio
    if metrics.buy_count_24h > 0 && metrics.sell_count_24h > 0 {
        let total_trades = metrics.buy_count_24h + metrics.sell_count_24h;
        // This is a rough estimate since we don't have unique traders directly
        if total_trades > 100 {
            // If many trades but low liquidity, suspicious
            if metrics.liquidity_usd < 10_000.0 {
                score += 0.05;
            }
        }
    }

    // Proxy contract (upgradeable)
    if metrics.is_proxy {
        score += 0.05;
    }

    // Trading can be paused
    if metrics.trade_can_be_paused {
        score += 0.05;
    }

    // Effective sell tax from simulation
    if metrics.effective_sell_tax > 0.50 {
        score += 0.15;
    } else if metrics.effective_sell_tax > 0.30 {
        score += 0.10;
    } else if metrics.effective_sell_tax > 0.15 {
        score += 0.05;
    }

    // Phase 1 Task 1.8: Gas asymmetry detection
    // Gas asymmetry ratio > 2.0 indicates potential honeypot
    // Tiered by severity to avoid false positives
    if let Some(gas_ratio) = metrics.gas_asymmetry_ratio {
        if gas_ratio > 3.0 {
            // Severe gas asymmetry - very likely advanced honeypot
            score += 0.20;
        } else if gas_ratio > 2.0 {
            // Moderate gas asymmetry - suspicious but not certain
            score += 0.10;
        }
    }

    // Dev dump ratio
    if metrics.dev_dump_ratio > 0.50 {
        score += 0.15;
    } else if metrics.dev_dump_ratio > 0.30 {
        score += 0.10;
    } else if metrics.dev_dump_ratio > 0.10 {
        score += 0.05;
    }

    // Clamp final score to [0.0, 1.0]
    score.clamp(0.0, 1.0)
}

/// Check if LLM analysis should be called based on rug probability
///
/// # Arguments
/// * `rug_prob` - The computed rug probability score
/// * `threshold` - The threshold for calling LLM (default 0.35)
///
/// # Returns
/// * `true` if LLM analysis should be called
#[must_use]
pub fn should_call_llm(rug_prob: f32, threshold: f32) -> bool {
    rug_prob >= threshold
}

/// Get risk level description based on rug probability
///
/// # Arguments
/// * `rug_prob` - The rug probability score
///
/// # Returns
/// * Risk level string
#[must_use]
pub fn get_risk_level(rug_prob: f32) -> &'static str {
    if rug_prob < 0.20 {
        "VERY LOW"
    } else if rug_prob < 0.35 {
        "LOW"
    } else if rug_prob < 0.50 {
        "MODERATE"
    } else if rug_prob < 0.70 {
        "HIGH"
    } else {
        "CRITICAL"
    }
}

/// Get risk level emoji based on rug probability
#[must_use]
pub fn get_risk_emoji(rug_prob: f32) -> &'static str {
    if rug_prob < 0.20 {
        "🟢"
    } else if rug_prob < 0.35 {
        "🟡"
    } else if rug_prob < 0.50 {
        "🟠"
    } else {
        "🔴"
    }
}

/// Compute detailed risk breakdown showing contribution of each factor
///
/// # Arguments
/// * `metrics` - Token metrics
///
/// # Returns
/// * Vector of (`factor_name`, contribution) tuples
#[must_use]
pub fn compute_risk_breakdown(metrics: &TokenMetrics) -> Vec<(&'static str, f32)> {
    let mut breakdown = Vec::new();

    // Hard rules contributions
    if metrics.is_honeypot {
        breakdown.push(("honeypot", 0.40));
    }

    if !metrics.can_sell {
        breakdown.push(("cannot_sell", 1.0));
        return breakdown; // Early return for definitive honeypot
    }

    if metrics.owner_can_mint {
        breakdown.push(("owner_can_mint", 0.20));
    }

    if metrics.liquidity_usd < 1000.0 {
        breakdown.push(("low_liquidity_critical", 0.15));
    } else if metrics.liquidity_usd < 5000.0 {
        breakdown.push(("low_liquidity", 0.08));
    }

    if metrics.hidden_owner {
        breakdown.push(("hidden_owner", 0.15));
    }

    if metrics.owner_can_blacklist {
        breakdown.push(("owner_blacklist", 0.12));
    }

    if metrics.selfdestruct {
        breakdown.push(("selfdestruct", 0.15));
    }

    // Soft rules contributions
    if metrics.sell_tax > 30.0 {
        breakdown.push(("high_sell_tax", 0.15));
    } else if metrics.sell_tax > 20.0 {
        breakdown.push(("sell_tax", 0.10));
    }

    if metrics.dev_wallet_percent > 15.0 {
        breakdown.push(("high_dev_holdings", 0.10));
    }

    if metrics.top10_holders_percent > 80.0 {
        breakdown.push(("holder_concentration", 0.08));
    }

    if !metrics.lp_locked {
        breakdown.push(("lp_not_locked", 0.10));
    }

    // Phase 0 Task 0.3: Handle Option<f64> for token_age_minutes
    if metrics.token_age_minutes.unwrap_or(0.0) < 10.0 {
        breakdown.push(("very_new_token", 0.05));
    }

    if metrics.sniper_ratio > 0.40 {
        breakdown.push(("high_sniper_activity", 0.05));
    }

    if metrics.volume_to_lp_ratio > 5.0 {
        breakdown.push(("wash_trading_suspect", 0.08));
    }

    // Phase 1 Task 1.8: Gas asymmetry contribution
    if let Some(gas_ratio) = metrics.gas_asymmetry_ratio {
        if gas_ratio > 3.0 {
            breakdown.push(("severe_gas_asymmetry", 0.20));
        } else if gas_ratio > 2.0 {
            breakdown.push(("gas_asymmetry", 0.10));
        }
    }

    breakdown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::TokenMetrics;

    fn create_safe_metrics() -> TokenMetrics {
        TokenMetrics {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            liquidity_usd: 100_000.0,
            lp_locked: true,
            lp_lock_days: 365,
            is_honeypot: false,
            can_sell: true,
            owner_can_mint: false,
            hidden_owner: false,
            buy_tax: 3.0,
            sell_tax: 3.0,
            dev_wallet_percent: 5.0,
            top10_holders_percent: 25.0,
            token_age_minutes: Some(1440.0), // 1 day
            sniper_ratio: 0.05,
            volume_to_lp_ratio: 0.5,
            ..Default::default()
        }
    }

    fn create_risky_metrics() -> TokenMetrics {
        TokenMetrics {
            token_address: "0x5678".to_string(),
            chain: "ethereum".to_string(),
            liquidity_usd: 500.0,
            lp_locked: false,
            lp_lock_days: 0,
            is_honeypot: false,
            can_sell: true,
            owner_can_mint: true,
            hidden_owner: true,
            buy_tax: 10.0,
            sell_tax: 35.0,
            dev_wallet_percent: 25.0,
            top10_holders_percent: 85.0,
            token_age_minutes: Some(5.0),
            sniper_ratio: 0.45,
            volume_to_lp_ratio: 8.0,
            ..Default::default()
        }
    }

    fn create_honeypot_metrics() -> TokenMetrics {
        TokenMetrics {
            token_address: "0x9999".to_string(),
            chain: "ethereum".to_string(),
            is_honeypot: true,
            can_sell: false,
            sell_tax: 99.0,
            ..Default::default()
        }
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_safe_token_low_score() {
        let metrics = create_safe_metrics();
        let score = compute_rug_probability(&metrics);
        assert!(score < 0.20, "Safe token should have low score, got {score}");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_risky_token_high_score() {
        let metrics = create_risky_metrics();
        let score = compute_rug_probability(&metrics);
        assert!(score > 0.50, "Risky token should have high score, got {score}");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_honeypot_maximum_score() {
        let metrics = create_honeypot_metrics();
        let score = compute_rug_probability(&metrics);
        assert_eq!(score, 1.0, "Honeypot should have maximum score");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_cannot_sell_maximum_score() {
        let mut metrics = create_safe_metrics();
        metrics.can_sell = false;
        let score = compute_rug_probability(&metrics);
        assert_eq!(score, 1.0, "Cannot sell should return 1.0 immediately");
    }

    #[test]
    fn test_should_call_llm() {
        assert!(!should_call_llm(0.20, 0.35));
        assert!(!should_call_llm(0.34, 0.35));
        assert!(should_call_llm(0.35, 0.35));
        assert!(should_call_llm(0.50, 0.35));
        assert!(should_call_llm(0.80, 0.35));
    }

    #[test]
    fn test_get_risk_level() {
        assert_eq!(get_risk_level(0.10), "VERY LOW");
        assert_eq!(get_risk_level(0.25), "LOW");
        assert_eq!(get_risk_level(0.40), "MODERATE");
        assert_eq!(get_risk_level(0.60), "HIGH");
        assert_eq!(get_risk_level(0.85), "CRITICAL");
    }

    #[test]
    fn test_get_risk_emoji() {
        assert_eq!(get_risk_emoji(0.10), "🟢");
        assert_eq!(get_risk_emoji(0.25), "🟡");
        assert_eq!(get_risk_emoji(0.40), "🟠");
        assert_eq!(get_risk_emoji(0.85), "🔴");
    }

    #[test]
    fn test_risk_breakdown_safe_token() {
        let metrics = create_safe_metrics();
        let breakdown = compute_risk_breakdown(&metrics);
        // Safe token should have minimal or no risk factors
        assert!(breakdown.len() <= 1);
    }

    #[test]
    fn test_risk_breakdown_risky_token() {
        let metrics = create_risky_metrics();
        let breakdown = compute_risk_breakdown(&metrics);
        // Risky token should have multiple risk factors
        assert!(breakdown.len() >= 5);

        // Check for specific expected factors
        let factor_names: Vec<_> = breakdown.iter().map(|(name, _)| *name).collect();
        assert!(factor_names.contains(&"owner_can_mint"));
        assert!(factor_names.contains(&"high_dev_holdings"));
        assert!(factor_names.contains(&"lp_not_locked"));
    }

    #[test]
    fn test_risk_breakdown_honeypot_early_return() {
        let metrics = create_honeypot_metrics();
        let breakdown = compute_risk_breakdown(&metrics);
        // Honeypot with cannot_sell should return early
        if metrics.is_honeypot {
            assert!(breakdown.iter().any(|(name, _)| *name == "honeypot"));
        }
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_score_clamping() {
        // Create a token with many risk factors
        let metrics = TokenMetrics {
            is_honeypot: true,
            owner_can_mint: true,
            hidden_owner: true,
            selfdestruct: true,
            owner_can_blacklist: true,
            liquidity_usd: 100.0,
            sell_tax: 50.0,
            dev_wallet_percent: 30.0,
            top10_holders_percent: 95.0,
            lp_locked: false,
            token_age_minutes: Some(1.0),
            sniper_ratio: 0.60,
            volume_to_lp_ratio: 10.0,
            ..Default::default()
        };

        let score = compute_rug_probability(&metrics);
        // Score should be clamped to 1.0 maximum
        assert!(score <= 1.0, "Score should be clamped to 1.0, got {score}");
    }

    #[test]
    fn test_liquidity_thresholds() {
        let base = create_safe_metrics();

        // Test critical low liquidity
        let mut metrics = base.clone();
        metrics.liquidity_usd = 500.0;
        let score = compute_rug_probability(&metrics);
        assert!(score > 0.10, "Critical low liquidity should add significant risk");

        // Test moderate low liquidity
        let mut metrics = base.clone();
        metrics.liquidity_usd = 3000.0;
        let score = compute_rug_probability(&metrics);
        assert!(score > 0.05, "Low liquidity should add some risk");

        // Test safe liquidity
        let mut metrics = base;
        metrics.liquidity_usd = 50_000.0;
        let score = compute_rug_probability(&metrics);
        assert!(score < 0.10, "Good liquidity should not add significant risk");
    }

    #[test]
    fn test_tax_thresholds() {
        let base = create_safe_metrics();

        // Test critical sell tax
        let mut metrics = base.clone();
        metrics.sell_tax = 40.0;
        let score = compute_rug_probability(&metrics);
        assert!(score > 0.15, "High sell tax should add significant risk");

        // Test moderate sell tax
        let mut metrics = base.clone();
        metrics.sell_tax = 15.0;
        let score = compute_rug_probability(&metrics);
        assert!(score > 0.03, "Moderate sell tax should add some risk");

        // Test safe tax
        let mut metrics = base;
        metrics.sell_tax = 3.0;
        let score = compute_rug_probability(&metrics);
        assert!(score < 0.05, "Low tax should not add significant risk");
    }

    #[test]
    fn test_age_thresholds() {
        let base = create_safe_metrics();

        // Test very new token
        let mut metrics = base.clone();
        metrics.token_age_minutes = Some(3.0);
        let score = compute_rug_probability(&metrics);
        assert!(score > 0.05, "Very new token should add risk");

        // Test moderately new token
        let mut metrics = base.clone();
        metrics.token_age_minutes = Some(30.0);
        let score = compute_rug_probability(&metrics);
        assert!(score > 0.0, "New token should add some risk");

        // Test old token
        let mut metrics = base;
        metrics.token_age_minutes = Some(10_000.0);
        let score = compute_rug_probability(&metrics);
        assert!(score < 0.05, "Old token should not add age-related risk");
    }

    // =========================================================================
    // Phase 1 Task 1.8: Gas Asymmetry Tests
    // =========================================================================

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_gas_asymmetry_no_asymmetry() {
        // Token with gas ratio < 2.0 should not add risk
        let mut metrics = create_safe_metrics();
        metrics.gas_asymmetry_ratio = Some(1.5); // Below threshold
        metrics.gas_asymmetry_detected = false;

        let score = compute_rug_probability(&metrics);
        // Should not add any gas-related risk
        assert!(score < 0.10, "No gas asymmetry should result in low score");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_gas_asymmetry_moderate() {
        // Token with gas ratio > 2.0 but < 3.0 should add moderate risk
        let mut metrics = create_safe_metrics();
        metrics.gas_asymmetry_ratio = Some(2.5); // Moderate asymmetry
        metrics.gas_asymmetry_detected = true;

        let score = compute_rug_probability(&metrics);
        // Should add 0.10 risk for moderate asymmetry
        assert!(score >= 0.10, "Moderate gas asymmetry should add 0.10 risk, got {score}");
        assert!(score < 0.20, "Moderate gas asymmetry should not add more than 0.20 risk");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_gas_asymmetry_severe() {
        // Token with gas ratio > 3.0 should add severe risk
        let mut metrics = create_safe_metrics();
        metrics.gas_asymmetry_ratio = Some(4.5); // Severe asymmetry
        metrics.gas_asymmetry_detected = true;

        let score = compute_rug_probability(&metrics);
        // Should add 0.20 risk for severe asymmetry
        assert!(score >= 0.20, "Severe gas asymmetry should add 0.20 risk, got {score}");
        assert!(score < 0.30, "Severe gas asymmetry should not add more than 0.30 risk");
    }

    #[test]
    fn test_gas_asymmetry_none() {
        // Token without gas data should not crash or add risk
        let mut metrics = create_safe_metrics();
        metrics.gas_asymmetry_ratio = None;
        metrics.gas_asymmetry_detected = false;

        let score = compute_rug_probability(&metrics);
        // Should handle None gracefully
        assert!(score < 0.10, "No gas data should result in low score");
    }

    #[test]
    fn test_gas_asymmetry_threshold_boundary_2_0() {
        // Test exact boundary at 2.0
        let mut metrics_below = create_safe_metrics();
        metrics_below.gas_asymmetry_ratio = Some(1.99); // Just below threshold
        let score_below = compute_rug_probability(&metrics_below);

        let mut metrics_above = create_safe_metrics();
        metrics_above.gas_asymmetry_ratio = Some(2.01); // Just above threshold
        let score_above = compute_rug_probability(&metrics_above);

        // Score should increase when crossing 2.0 threshold
        assert!(score_above > score_below, "Crossing 2.0 threshold should increase risk");
    }

    #[test]
    fn test_gas_asymmetry_threshold_boundary_3_0() {
        // Test exact boundary at 3.0
        let mut metrics_below = create_safe_metrics();
        metrics_below.gas_asymmetry_ratio = Some(2.99); // Just below severe threshold
        let score_below = compute_rug_probability(&metrics_below);

        let mut metrics_above = create_safe_metrics();
        metrics_above.gas_asymmetry_ratio = Some(3.01); // Just above severe threshold
        let score_above = compute_rug_probability(&metrics_above);

        // Score should increase when crossing 3.0 threshold
        assert!(score_above > score_below, "Crossing 3.0 threshold should increase risk");
    }

    #[test]
    fn test_gas_asymmetry_combined_with_honeypot() {
        // Gas asymmetry should stack with honeypot detection
        let mut metrics = create_honeypot_metrics();
        metrics.gas_asymmetry_ratio = Some(4.0);
        metrics.gas_asymmetry_detected = true;

        let score = compute_rug_probability(&metrics);
        // Honeypot already returns 1.0, so gas asymmetry won't increase it further
        assert!((score - 1.0).abs() < f32::EPSILON, "Honeypot with gas asymmetry should still be 1.0");
    }

    #[test]
    fn test_gas_asymmetry_risk_breakdown() {
        // Test that gas asymmetry appears in risk breakdown
        let mut metrics = create_safe_metrics();
        metrics.gas_asymmetry_ratio = Some(2.5);
        metrics.gas_asymmetry_detected = true;

        let breakdown = compute_risk_breakdown(&metrics);
        let factor_names: Vec<_> = breakdown.iter().map(|(name, _)| *name).collect();

        assert!(factor_names.contains(&"gas_asymmetry"), "Moderate asymmetry should appear in breakdown");
    }

    #[test]
    fn test_gas_asymmetry_severe_risk_breakdown() {
        // Test that severe gas asymmetry appears in risk breakdown
        let mut metrics = create_safe_metrics();
        metrics.gas_asymmetry_ratio = Some(4.5);
        metrics.gas_asymmetry_detected = true;

        let breakdown = compute_risk_breakdown(&metrics);
        let factor_names: Vec<_> = breakdown.iter().map(|(name, _)| *name).collect();

        assert!(factor_names.contains(&"severe_gas_asymmetry"), "Severe asymmetry should appear in breakdown");
    }
}
