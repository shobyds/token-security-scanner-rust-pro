//! Token Risk Index (TRI) Scoring Engine
//!
//! This module provides the core TRI scoring logic as specified in the
//! Phi-3 Mini migration implementation plan. It computes risk scores across
//! 8 domains and combines them into a final composite TRI score.
//!
//! # Sections
//! 1. Contract Security Risk
//! 2. Liquidity Safety (LP Score)
//! 3. Ownership Risk
//! 4. Tax Risk
//! 5. Honeypot/Trading Simulation Risk
//! 6. Volume Authenticity Risk
//! 7. Developer Behavior Risk
//! 8. Age & Momentum Risk

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::missing_panics_doc)]

use serde::{Deserialize, Serialize};

use crate::api::{ContractRisk, DexTokenData, HoneypotResult};

/// TRI risk label based on final score
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TriLabel {
    /// Score 0-25: Very safe token
    VerySafe,
    /// Score 25-45: Moderate risk
    ModerateRisk,
    /// Score 45-65: High risk
    HighRisk,
    /// Score 65+: Avoid
    Avoid,
}

impl TriLabel {
    /// Get display string for the label
    #[must_use]
    pub fn display(&self) -> &'static str {
        match self {
            Self::VerySafe => "VERY SAFE",
            Self::ModerateRisk => "MODERATE RISK",
            Self::HighRisk => "HIGH RISK",
            Self::Avoid => "AVOID",
        }
    }

    /// Get emoji for the label
    #[must_use]
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::VerySafe => "🟢",
            Self::ModerateRisk => "🟡",
            Self::HighRisk => "🟠",
            Self::Avoid => "🔴",
        }
    }

    /// Create label from TRI score
    #[must_use]
    pub fn from_score(score: f32) -> Self {
        if score < 25.0 {
            Self::VerySafe
        } else if score < 45.0 {
            Self::ModerateRisk
        } else if score < 65.0 {
            Self::HighRisk
        } else {
            Self::Avoid
        }
    }
}

impl std::fmt::Display for TriLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

/// Red flag identified during risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedFlag {
    /// Category of the red flag
    pub category: String,
    /// Description of the issue
    pub description: String,
    /// Weight/severity of the flag (0.0-1.0)
    pub weight: f32,
}

impl RedFlag {
    /// Create a new red flag
    #[must_use]
    pub fn new(category: impl Into<String>, description: impl Into<String>, weight: f32) -> Self {
        Self {
            category: category.into(),
            description: description.into(),
            weight: weight.clamp(0.0, 1.0),
        }
    }
}

/// Green flag identified during risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreenFlag {
    /// Category of the green flag
    pub category: String,
    /// Description of the positive attribute
    pub description: String,
}

impl GreenFlag {
    /// Create a new green flag
    #[must_use]
    pub fn new(category: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            description: description.into(),
        }
    }
}

/// TRI scoring configuration
#[derive(Debug, Clone)]
pub struct TriConfig {
    /// Weight for contract risk score
    pub weights_contract: f32,
    /// Weight for ownership risk score
    pub weights_ownership: f32,
    /// Weight for liquidity risk score
    pub weights_liquidity: f32,
    /// Weight for tax risk score
    pub weights_tax: f32,
    /// Weight for volume risk score
    pub weights_volume: f32,
    /// Weight for age risk score
    pub weights_age: f32,
}

impl Default for TriConfig {
    fn default() -> Self {
        Self {
            weights_contract: 0.30,
            weights_ownership: 0.20,
            weights_liquidity: 0.20,
            weights_tax: 0.15,
            weights_volume: 0.10,
            weights_age: 0.05,
        }
    }
}

/// Comprehensive TRI result with all domain scores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriResult {
    /// Token address that was scored
    pub token_address: String,
    /// Blockchain network
    pub chain: String,

    // Domain scores (0-100, higher = more risk)
    /// Section 1: Contract security risk
    pub contract_risk: f32,
    /// Section 2: Liquidity risk (inverted LP safety)
    pub lp_score: f32,
    /// Section 3: Ownership risk
    pub ownership_risk: f32,
    /// Section 4: Tax risk
    pub tax_risk: f32,
    /// Section 5: Honeypot risk
    pub honeypot_risk: f32,
    /// Section 6: Volume authenticity risk
    pub volume_risk: f32,
    /// Section 7: Developer behavior risk
    pub dev_behavior: f32,
    /// Section 8: Age risk
    pub age_risk: f32,

    // Composite score
    /// Final TRI composite score (0-100)
    pub tri: f32,
    /// Risk label based on TRI score
    pub tri_label: TriLabel,

    // Flags
    /// Red flags identified
    pub red_flags: Vec<RedFlag>,
    /// Green flags identified
    pub green_flags: Vec<GreenFlag>,

    // Timestamp
    /// Unix timestamp when computed
    pub computed_at: u64,
}

impl TriResult {
    /// Check if the token is considered safe
    #[must_use]
    pub fn is_safe(&self) -> bool {
        matches!(self.tri_label, TriLabel::VerySafe | TriLabel::ModerateRisk)
    }

    /// Check if the token should be avoided
    #[must_use]
    pub fn should_avoid(&self) -> bool {
        matches!(self.tri_label, TriLabel::Avoid)
    }

    /// Get the number of red flags
    #[must_use]
    pub fn red_flag_count(&self) -> usize {
        self.red_flags.len()
    }

    /// Get the number of green flags
    #[must_use]
    pub fn green_flag_count(&self) -> usize {
        self.green_flags.len()
    }
}

/// Input metrics for TRI computation
#[derive(Debug, Clone, Default)]
pub struct TriInput {
    /// Token address
    pub token_address: String,
    /// Chain
    pub chain: String,

    // Contract risk fields
    pub is_honeypot: bool,
    pub owner_can_mint: bool,
    pub owner_can_blacklist: bool,
    pub hidden_owner: bool,
    pub is_proxy: bool,
    pub selfdestruct: bool,
    pub trade_cannot_be_paused: bool,
    pub personal_privilege: bool,
    pub external_call: bool,
    pub can_be_upgraded: bool,

    // Liquidity fields
    pub liquidity_usd: f64,
    pub lp_locked: bool,
    pub lp_lock_days: u32,
    pub market_cap_usd: Option<f64>,

    // Ownership fields
    pub holder_count: u64,
    pub top10_holders_percent: f32,
    pub dev_wallet_percent: f32,
    pub ownership_renounced: bool,
    pub owner_renounced: bool,  // Phase 0 Task 0.4: For TRI reduction logic

    // Tax fields
    pub buy_tax: f32,
    pub sell_tax: f32,

    // Honeypot simulation fields
    pub can_sell: bool,
    pub effective_sell_tax: f32,

    // Gas asymmetry fields (Phase 1 Task 1.8)
    pub gas_asymmetry_ratio: Option<f64>,
    pub gas_asymmetry_detected: bool,

    // Volume fields
    pub volume_24h_usd: f64,
    pub unique_traders_24h: u32,
    pub total_trades_24h: u32,

    // Age fields
    pub token_age_minutes: Option<f64>,

    // Dev behavior fields
    pub dev_dump_ratio: f32,
    pub lp_removed_by_dev: bool,
    pub sniper_count: u32,
    pub sniper_ratio: f32,

    // Price confidence from DefiLlama (Phase 1 Task 1.6 - Sprint 3 INT-001)
    pub price_confidence: Option<f64>,
}

/// TRI Engine for computing token risk scores
pub struct TriEngine {
    config: TriConfig,
}

impl TriEngine {
    /// Create a new TRI engine with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: TriConfig::default(),
        }
    }

    /// Create a new TRI engine with custom configuration
    #[must_use]
    pub fn with_config(config: TriConfig) -> Self {
        Self { config }
    }

    /// Compute the full TRI score from input metrics
    ///
    /// # Arguments
    /// * `input` - Input metrics for scoring
    ///
    /// # Returns
    /// * `TriResult` - Complete TRI result with all domain scores
    #[must_use]
    pub fn compute_tri(&self, input: &TriInput) -> TriResult {
        let computed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute all domain scores
        let contract_risk = self.compute_contract_risk(input);
        let lp_score = self.compute_lp_score(input);
        let ownership_risk = self.compute_ownership_risk(input);
        let tax_risk = self.compute_tax_risk(input);
        let honeypot_risk = self.compute_honeypot_risk(input);
        let volume_risk = self.compute_volume_risk(input);
        let dev_behavior = self.compute_dev_behavior(input);
        let age_risk = self.compute_age_risk(input);

        // Compute composite TRI score
        let mut tri = self.compute_composite_tri(
            contract_risk,
            lp_score,
            ownership_risk,
            tax_risk,
            honeypot_risk,
            volume_risk,
            dev_behavior,
            age_risk,
        );

        // Phase 0 Task 0.4: Owner Renounce → Risk Score Reduction
        // When ownership is renounced AND no critical dangerous flags are present,
        // reduce the final TRI by 25%. This prevents a renounced token with no other
        // flags from scoring unfairly high.
        let has_critical_flags =
            input.is_honeypot
            || input.owner_can_mint
            || input.hidden_owner
            || input.can_be_upgraded
            || input.selfdestruct
            || input.personal_privilege;

        if input.owner_renounced && !has_critical_flags {
            // Owner truly renounced with no backdoors — apply 25% reduction
            #[allow(clippy::cast_possible_truncation)]
            #[allow(clippy::cast_lossless)]
            {
                tri = (tri as f64 * 0.75) as f32;
            }
            tracing::debug!("TRI reduced 25% — ownership renounced with no critical flags");
        }

        // Determine label (after potential reduction)
        let tri_label = TriLabel::from_score(tri);

        // Collect all flags
        let mut red_flags = Vec::new();
        let mut green_flags = Vec::new();

        // Add flags from each domain
        Self::collect_contract_flags(input, contract_risk, &mut red_flags, &mut green_flags);
        self.collect_lp_flags(input, lp_score, &mut red_flags, &mut green_flags);
        self.collect_ownership_flags(input, ownership_risk, &mut red_flags, &mut green_flags);
        self.collect_tax_flags(input, tax_risk, &mut red_flags, &mut green_flags);
        self.collect_honeypot_flags(input, honeypot_risk, &mut red_flags, &mut green_flags);
        self.collect_volume_flags(input, volume_risk, &mut red_flags, &mut green_flags);
        self.collect_dev_flags(input, dev_behavior, &mut red_flags, &mut green_flags);
        self.collect_age_flags(input, age_risk, &mut red_flags, &mut green_flags);

        // Phase 0 Task 0.4: Add OwnershipRenounced green flag
        if input.owner_renounced {
            green_flags.push(GreenFlag::new(
                "Ownership",
                "Ownership renounced — owner has no control",
            ));
        }

        TriResult {
            token_address: input.token_address.clone(),
            chain: input.chain.clone(),
            contract_risk,
            lp_score,
            ownership_risk,
            tax_risk,
            honeypot_risk,
            volume_risk,
            dev_behavior,
            age_risk,
            tri,
            tri_label,
            red_flags,
            green_flags,
            computed_at,
        }
    }

    /// Compute composite TRI score from domain scores
    #[allow(clippy::too_many_arguments)]
    fn compute_composite_tri(
        &self,
        contract_risk: f32,
        lp_score: f32,
        ownership_risk: f32,
        tax_risk: f32,
        honeypot_risk: f32,
        volume_risk: f32,
        dev_behavior: f32,
        age_risk: f32,
    ) -> f32 {
        let tri = contract_risk * self.config.weights_contract
            + ownership_risk * self.config.weights_ownership
            + lp_score * self.config.weights_liquidity
            + tax_risk * self.config.weights_tax
            + volume_risk * self.config.weights_volume
            + age_risk * self.config.weights_age;

        // Add honeypot risk as a bonus penalty (not in base weights)
        let tri = if honeypot_risk > 50.0 {
            tri + 10.0
        } else {
            tri
        };

        // Add dev behavior penalty
        let tri = if dev_behavior > 50.0 {
            tri + 5.0
        } else {
            tri
        };

        tri.clamp(0.0, 100.0)
    }

    /// Section 1: Compute contract security risk score
    ///
    /// Formula:
    /// ```
    /// ContractRisk = honeypot * 40 + hidden_mint * 20 + owner_blacklist * 15
    ///              + owner_privileges * 15 + proxy_upgradeable * 10
    /// ```
    #[must_use]
    pub fn compute_contract_risk(&self, input: &TriInput) -> f32 {
        let mut score: f32 = 0.0;

        // Honeypot detection is critical
        if input.is_honeypot {
            score += 40.0;
        }

        // Hidden mint function
        if input.owner_can_mint {
            score += 20.0;
        }

        // Owner blacklist capability
        if input.owner_can_blacklist {
            score += 15.0;
        }

        // Hidden owner / personal privileges
        if input.hidden_owner || input.personal_privilege {
            score += 15.0;
        }

        // Proxy/upgradeable contract
        if input.is_proxy || input.can_be_upgraded {
            score += 10.0;
        }

        // Selfdestruct function
        if input.selfdestruct {
            score += 30.0;
        }

        // Trading can be paused
        if !input.trade_cannot_be_paused {
            score += 10.0;
        }

        // External calls
        if input.external_call {
            score += 5.0;
        }

        score.clamp(0.0, 100.0)
    }

    /// Section 2: Compute liquidity safety score (inverted to risk)
    ///
    /// Formula:
    /// ```
    /// LockFactor = 1.0 if lp_lock_days > 180
    ///            = 0.8 if lp_lock_days 90-180
    ///            = 0.5 if lp_lock_days 30-90
    ///            = 0.2 if lp_lock_days < 30
    ///            = 0.0 if not locked
    ///
    /// LPSafetyScore = (lp_locked_usd / total_liquidity_usd) * LockFactor
    /// LPRisk = (1.0 - LPSafetyScore) * 100
    /// ```
    #[must_use]
    pub fn compute_lp_score(&self, input: &TriInput) -> f32 {
        // Calculate lock factor
        let lock_factor: f32 = if !input.lp_locked {
            0.0
        } else if input.lp_lock_days > 180 {
            1.0
        } else if input.lp_lock_days >= 90 {
            0.8
        } else if input.lp_lock_days >= 30 {
            0.5
        } else {
            0.2
        };

        // LP safety score (higher is safer)
        let lp_safety_score: f32 = lock_factor;

        // Invert to risk (higher is riskier)
        let mut lp_risk: f32 = (1.0 - lp_safety_score) * 100.0;

        // Additional risk for low liquidity
        if input.liquidity_usd < 5000.0 {
            lp_risk += 20.0;
        } else if input.liquidity_usd < 10_000.0 {
            lp_risk += 10.0;
        }

        // Check LP/MCap ratio if market cap is available
        if let Some(mcap) = input.market_cap_usd
            && mcap > 0.0
        {
            let lp_mcap_ratio = input.liquidity_usd / mcap;
            if lp_mcap_ratio < 0.05 {
                lp_risk += 10.0;
            } else if lp_mcap_ratio > 0.20 {
                // Unusually high LP ratio can also be suspicious
                lp_risk += 5.0;
            }
        }

        lp_risk.clamp(0.0, 100.0)
    }

    /// Section 3: Compute ownership risk score
    ///
    /// Formula:
    /// ```
    /// HolderRisk = (top10_holders_percent / 100.0) * 50.0
    /// DevRisk = dev_wallet_percent * 2.0
    /// OwnershipRisk = HolderRisk + DevRisk
    /// ```
    #[must_use]
    pub fn compute_ownership_risk(&self, input: &TriInput) -> f32 {
        let mut score = 0.0;

        // Holder concentration risk
        let holder_risk = (input.top10_holders_percent / 100.0) * 50.0;
        score += holder_risk;

        // Dev wallet risk
        let dev_risk = input.dev_wallet_percent * 2.0;
        score += dev_risk;

        // Hidden owner detection
        if input.hidden_owner {
            score += 25.0;
        }

        // Ownership renounced (reduces risk)
        if input.ownership_renounced {
            score -= 20.0;
        }

        score.clamp(0.0, 100.0)
    }

    /// Section 4: Compute tax risk score
    ///
    /// Formula:
    /// ```
    /// TaxRisk = (buy_tax + sell_tax) * 2.0
    /// ```
    #[must_use]
    pub fn compute_tax_risk(&self, input: &TriInput) -> f32 {
        let mut tax_risk = (input.buy_tax + input.sell_tax) * 2.0;

        // Asymmetric sell trap
        if input.sell_tax > input.buy_tax * 2.0 {
            tax_risk += 15.0;
        }

        // High sell tax
        if input.sell_tax > 30.0 {
            tax_risk += 20.0;
        }

        // High buy tax
        if input.buy_tax > 15.0 {
            tax_risk += 10.0;
        }

        tax_risk.clamp(0.0, 100.0)
    }

    /// Section 5: Compute honeypot/trading simulation risk
    ///
    /// Formula:
    /// ```
    /// HoneypotRisk = 100.0 if is_honeypot
    ///              = EffectiveSellTax * 100.0 * 1.3 if EffectiveSellTax > 0.30
    ///              = EffectiveSellTax * 100.0 otherwise
    /// ```
    /// 
    /// Phase 1 Task 1.8: Gas asymmetry penalty
    /// - `gas_ratio` > 3.0: +30 risk (severe asymmetry, advanced honeypot)
    /// - `gas_ratio` > 2.0: +15 risk (moderate asymmetry, suspicious)
    #[must_use]
    pub fn compute_honeypot_risk(&self, input: &TriInput) -> f32 {
        // If confirmed honeypot, maximum risk
        if input.is_honeypot {
            return 100.0;
        }

        // If cannot sell, also maximum risk
        if !input.can_sell {
            return 100.0;
        }

        // Calculate from effective sell tax
        let mut risk = input.effective_sell_tax * 100.0;

        // Amplify if effective sell tax is high
        if input.effective_sell_tax > 0.30 {
            risk *= 1.3;
        }

        // Phase 1 Task 1.8: Gas asymmetry penalty
        // Tiered by severity to avoid false positives on legitimate tokens like UNI
        if let Some(gas_ratio) = input.gas_asymmetry_ratio {
            if gas_ratio > 3.0 {
                // Severe gas asymmetry - very likely advanced honeypot
                risk += 30.0;
            } else if gas_ratio > 2.0 {
                // Moderate gas asymmetry - suspicious but not certain
                risk += 15.0;
            }
        }

        risk.clamp(0.0, 100.0)
    }

    /// Section 6: Compute volume authenticity risk
    ///
    /// Formula:
    /// ```
    /// VolumeQuality = unique_traders / total_trades_24h
    /// VolumeRisk = 0.0 if VolumeQuality > 0.6
    ///            = 50.0 if VolumeQuality 0.3-0.6
    ///            = 80.0 if VolumeQuality < 0.3
    ///            = 90.0 if volume_24h / liquidity_usd > 5.0 (wash trading)
    /// ```
    #[must_use]
    pub fn compute_volume_risk(&self, input: &TriInput) -> f32 {
        let mut risk: f32 = 0.0;

        // Calculate volume quality
        #[allow(clippy::cast_precision_loss)]
        if input.total_trades_24h > 0 {
            let volume_quality: f32 =
                input.unique_traders_24h as f32 / input.total_trades_24h as f32;

            if volume_quality > 0.6 {
                risk = 0.0;
            } else if volume_quality >= 0.3 {
                risk = 50.0;
            } else {
                risk = 80.0;
            }
        }

        // Check for wash trading (volume/liquidity ratio)
        #[allow(clippy::cast_possible_truncation)]
        if input.liquidity_usd > 0.0 {
            let volume_to_lp_ratio: f32 = input.volume_24h_usd as f32 / input.liquidity_usd as f32;
            if volume_to_lp_ratio > 5.0 {
                risk = risk.max(90.0);
            } else if volume_to_lp_ratio > 3.0 {
                risk += 20.0;
            }
        }

        risk.clamp(0.0, 100.0)
    }

    /// Section 7: Compute developer behavior risk
    #[must_use]
    pub fn compute_dev_behavior(&self, input: &TriInput) -> f32 {
        let mut risk: f32 = 0.0;

        // Dev dump ratio
        if input.dev_dump_ratio > 0.30 {
            risk += 60.0;
        } else if input.dev_dump_ratio > 0.10 {
            risk += 30.0;
        }

        // LP removed by dev
        if input.lp_removed_by_dev {
            risk += 60.0;
        }

        // Sniper activity
        if input.sniper_ratio > 0.40 {
            risk += 30.0;
        } else if input.sniper_ratio > 0.20 {
            risk += 15.0;
        }

        // High sniper count
        if input.sniper_count > 10 {
            risk += 20.0;
        } else if input.sniper_count > 5 {
            risk += 10.0;
        }

        risk.clamp(0.0, 100.0)
    }

    /// Section 8: Compute age risk
    ///
    /// Formula:
    /// ```
    /// AgeRisk = 1.0 / sqrt(minutes_since_launch) * 100
    /// ```
    /// Unknown age (None) → treat as 2 minutes (very high risk, but not 100)
    #[must_use]
    pub fn compute_age_risk(&self, input: &TriInput) -> f32 {
        // Phase 0 Task 0.3: Handle Option<f64> for token_age_minutes
        // None/unknown age → treat as 2 minutes (very high risk signal)
        let age_minutes = input.token_age_minutes.unwrap_or(2.0).max(0.1);

        #[allow(clippy::cast_possible_truncation)]
        let age_risk: f32 = 100.0 / age_minutes.sqrt() as f32;
        age_risk.clamp(0.0, 100.0)
    }

    /// Collect red and green flags from contract risk analysis
    fn collect_contract_flags(
        input: &TriInput,
        score: f32,
        red_flags: &mut Vec<RedFlag>,
        green_flags: &mut Vec<GreenFlag>,
    ) {
        if input.is_honeypot {
            red_flags.push(RedFlag::new("Contract", "Confirmed honeypot", 1.0));
        }
        if input.owner_can_mint {
            red_flags.push(RedFlag::new("Contract", "Owner can mint new tokens", 0.7));
        }
        if input.owner_can_blacklist {
            red_flags.push(RedFlag::new("Contract", "Owner can blacklist addresses", 0.6));
        }
        if input.hidden_owner {
            red_flags.push(RedFlag::new("Contract", "Hidden owner detected", 0.8));
        }
        if input.selfdestruct {
            red_flags.push(RedFlag::new("Contract", "SELFDESTRUCT function present", 0.9));
        }
        if !input.trade_cannot_be_paused {
            red_flags.push(RedFlag::new("Contract", "Trading can be paused by owner", 0.5));
        }
        if input.personal_privilege {
            red_flags.push(RedFlag::new("Contract", "Owner has personal privileges", 0.6));
        }
        if input.is_proxy {
            red_flags.push(RedFlag::new("Contract", "Proxy contract (upgradeable)", 0.4));
        }

        // Green flags
        if !input.owner_can_mint && !input.owner_can_blacklist && !input.hidden_owner {
            green_flags.push(GreenFlag::new(
                "Contract",
                "No dangerous owner privileges detected",
            ));
        }
        if !input.selfdestruct {
            green_flags.push(GreenFlag::new(
                "Contract",
                "No selfdestruct function",
            ));
        }
    }

    /// Collect flags from liquidity analysis
    #[allow(clippy::unused_self)]
    fn collect_lp_flags(
        &self,
        input: &TriInput,
        _score: f32,
        red_flags: &mut Vec<RedFlag>,
        green_flags: &mut Vec<GreenFlag>,
    ) {
        if input.liquidity_usd < 5000.0 {
            red_flags.push(RedFlag::new(
                "Liquidity",
                format!("Dangerously low liquidity (${:.2})", input.liquidity_usd),
                0.7,
            ));
        }

        if !input.lp_locked {
            red_flags.push(RedFlag::new("Liquidity", "LP tokens not locked", 0.6));
        } else if input.lp_lock_days < 30 {
            red_flags.push(RedFlag::new(
                "Liquidity",
                format!("LP unlocks in {} days", input.lp_lock_days),
                0.5,
            ));
        }

        // Green flags
        if input.lp_locked && input.lp_lock_days > 180 {
            green_flags.push(GreenFlag::new(
                "Liquidity",
                "LP locked for more than 6 months",
            ));
        }
        if input.liquidity_usd > 100_000.0 {
            green_flags.push(GreenFlag::new(
                "Liquidity",
                format!("Healthy liquidity (${:.2}k)", input.liquidity_usd / 1000.0),
            ));
        }
    }

    /// Collect flags from ownership analysis
    #[allow(clippy::unused_self)]
    fn collect_ownership_flags(
        &self,
        input: &TriInput,
        _score: f32,
        red_flags: &mut Vec<RedFlag>,
        green_flags: &mut Vec<GreenFlag>,
    ) {
        if input.top10_holders_percent > 80.0 {
            red_flags.push(RedFlag::new(
                "Ownership",
                format!(
                    "Top 10 holders control {:.1}% of supply",
                    input.top10_holders_percent
                ),
                0.7,
            ));
        }

        if input.dev_wallet_percent > 15.0 {
            red_flags.push(RedFlag::new(
                "Ownership",
                format!(
                    "Dev wallet holds {:.1}% of supply",
                    input.dev_wallet_percent
                ),
                0.5,
            ));
        }

        // Green flags
        if input.ownership_renounced {
            green_flags.push(GreenFlag::new(
                "Ownership",
                "Contract ownership renounced",
            ));
        }
        if input.top10_holders_percent < 50.0 {
            green_flags.push(GreenFlag::new(
                "Ownership",
                "Well-distributed token holdings",
            ));
        }
    }

    /// Collect flags from tax analysis
    #[allow(clippy::unused_self)]
    fn collect_tax_flags(
        &self,
        input: &TriInput,
        _score: f32,
        red_flags: &mut Vec<RedFlag>,
        green_flags: &mut Vec<GreenFlag>,
    ) {
        if input.sell_tax > 30.0 {
            red_flags.push(RedFlag::new(
                "Tax",
                format!("SELL TAX TRAP: {:.1}% > 30%", input.sell_tax),
                0.9,
            ));
        }

        if input.sell_tax > input.buy_tax * 2.0 {
            red_flags.push(RedFlag::new(
                "Tax",
                "Asymmetric sell trap (sell tax > 2x buy tax)",
                0.7,
            ));
        }

        if input.buy_tax > 15.0 {
            red_flags.push(RedFlag::new(
                "Tax",
                format!("High buy tax: {:.1}%", input.buy_tax),
                0.5,
            ));
        }

        // Green flags
        if input.buy_tax < 5.0 && input.sell_tax < 5.0 {
            green_flags.push(GreenFlag::new(
                "Tax",
                format!(
                    "Low taxes (buy: {:.1}%, sell: {:.1}%)",
                    input.buy_tax, input.sell_tax
                ),
            ));
        }
    }

    /// Collect flags from honeypot analysis
    #[allow(clippy::unused_self)]
    fn collect_honeypot_flags(
        &self,
        input: &TriInput,
        _score: f32,
        red_flags: &mut Vec<RedFlag>,
        _green_flags: &mut Vec<GreenFlag>,
    ) {
        if input.is_honeypot {
            red_flags.push(RedFlag::new("Honeypot", "Confirmed honeypot", 1.0));
        }

        if !input.can_sell {
            red_flags.push(RedFlag::new(
                "Honeypot",
                "CANNOT SELL - confirmed honeypot",
                1.0,
            ));
        }

        if input.effective_sell_tax > 0.40 {
            red_flags.push(RedFlag::new(
                "Honeypot",
                format!(
                    "Effective sell tax > 40% ({:.1}%)",
                    input.effective_sell_tax * 100.0
                ),
                0.8,
            ));
        }

        // Phase 1 Task 1.8: Gas asymmetry flags
        if let Some(ratio) = input.gas_asymmetry_ratio {
            if ratio > 3.0 {
                red_flags.push(RedFlag::new(
                    "Honeypot",
                    format!("Severe gas asymmetry detected (sell_gas/buy_gas = {ratio:.2}x, threshold 3.0x)"),
                    0.9,
                ));
            } else if ratio > 2.0 {
                red_flags.push(RedFlag::new(
                    "Honeypot",
                    format!("Gas asymmetry detected (sell_gas/buy_gas = {ratio:.2}x, threshold 2.0x)"),
                    0.6,
                ));
            }
        }
    }

    /// Collect flags from volume analysis
    #[allow(clippy::unused_self)]
    fn collect_volume_flags(
        &self,
        input: &TriInput,
        _score: f32,
        red_flags: &mut Vec<RedFlag>,
        green_flags: &mut Vec<GreenFlag>,
    ) {
        if input.liquidity_usd > 0.0 {
            let volume_to_lp_ratio = input.volume_24h_usd / input.liquidity_usd;
            if volume_to_lp_ratio > 5.0 {
                red_flags.push(RedFlag::new(
                    "Volume",
                    format!(
                        "Suspicious volume/liquidity ratio ({volume_to_lp_ratio:.1}x) - possible wash trading"
                    ),
                    0.8,
                ));
            }
        }

        #[allow(clippy::cast_precision_loss)]
        if input.total_trades_24h > 0 {
            let volume_quality = input.unique_traders_24h as f32 / input.total_trades_24h as f32;
            if volume_quality < 0.3 {
                red_flags.push(RedFlag::new(
                    "Volume",
                    format!(
                        "Low unique trader ratio ({:.1}%) - possible bot activity",
                        volume_quality * 100.0
                    ),
                    0.6,
                ));
            }
        }

        // Green flags
        if input.volume_24h_usd > input.liquidity_usd * 0.5
            && input.volume_24h_usd < input.liquidity_usd * 3.0
        {
            green_flags.push(GreenFlag::new(
                "Volume",
                "Healthy trading volume",
            ));
        }
    }

    /// Collect flags from developer behavior analysis
    #[allow(clippy::unused_self)]
    fn collect_dev_flags(
        &self,
        input: &TriInput,
        _score: f32,
        red_flags: &mut Vec<RedFlag>,
        green_flags: &mut Vec<GreenFlag>,
    ) {
        if input.lp_removed_by_dev {
            red_flags.push(RedFlag::new("Dev Behavior", "Dev removed liquidity", 1.0));
        }

        if input.dev_dump_ratio > 0.30 {
            red_flags.push(RedFlag::new(
                "Dev Behavior",
                format!(
                    "Possible dev dump (ratio: {:.1}%)",
                    input.dev_dump_ratio * 100.0
                ),
                0.8,
            ));
        }

        if input.sniper_ratio > 0.40 {
            red_flags.push(RedFlag::new(
                "Dev Behavior",
                format!(
                    "MEV sniper cluster in first block ({:.1}%)",
                    input.sniper_ratio * 100.0
                ),
                0.7,
            ));
        }

        // Green flags
        if !input.lp_removed_by_dev && input.dev_dump_ratio < 0.10 {
            green_flags.push(GreenFlag::new(
                "Dev Behavior",
                "No suspicious dev activity detected",
            ));
        }
    }

    /// Collect flags from age analysis
    #[allow(clippy::unused_self)]
    fn collect_age_flags(
        &self,
        input: &TriInput,
        _score: f32,
        red_flags: &mut Vec<RedFlag>,
        green_flags: &mut Vec<GreenFlag>,
    ) {
        // Phase 0 Task 0.3: Handle Option<f64> for token_age_minutes
        // Unknown age is treated as very high risk (launched just now)
        let age = input.token_age_minutes.unwrap_or(0.0);

        if age < 5.0 {
            red_flags.push(RedFlag::new(
                "Age",
                "Token launched less than 5 minutes ago (or age unknown)",
                0.8,
            ));
        } else if age < 30.0 {
            red_flags.push(RedFlag::new(
                "Age",
                "Very new token (less than 30 minutes old)",
                0.5,
            ));
        }

        // Green flags
        if age > 7.0 * 24.0 * 60.0 {
            green_flags.push(GreenFlag::new(
                "Age",
                "Token is more than 7 days old",
            ));
        }
    }
}

impl Default for TriEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_input() -> TriInput {
        TriInput {
            token_address: "0x1234567890123456789012345678901234567890".to_string(),
            chain: "ethereum".to_string(),
            is_honeypot: false,
            owner_can_mint: false,
            owner_can_blacklist: false,
            hidden_owner: false,
            is_proxy: false,
            selfdestruct: false,
            trade_cannot_be_paused: true,
            personal_privilege: false,
            external_call: false,
            can_be_upgraded: false,
            liquidity_usd: 100_000.0,
            lp_locked: true,
            lp_lock_days: 365,
            market_cap_usd: Some(1_000_000.0),
            holder_count: 1000,
            top10_holders_percent: 30.0,
            dev_wallet_percent: 5.0,
            ownership_renounced: false,
            owner_renounced: false,  // Phase 0 Task 0.4
            buy_tax: 3.0,
            sell_tax: 3.0,
            can_sell: true,
            effective_sell_tax: 0.03,
            // Phase 1 Task 1.8: Gas asymmetry fields
            gas_asymmetry_ratio: None,
            gas_asymmetry_detected: false,
            volume_24h_usd: 50_000.0,
            unique_traders_24h: 500,
            total_trades_24h: 1000,
            token_age_minutes: Some(1440.0), // 1 day
            dev_dump_ratio: 0.05,
            lp_removed_by_dev: false,
            sniper_count: 2,
            sniper_ratio: 0.1,
            price_confidence: None,
        }
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_tri_label_from_score() {
        assert_eq!(TriLabel::from_score(0.0), TriLabel::VerySafe);
        assert_eq!(TriLabel::from_score(24.9), TriLabel::VerySafe);
        assert_eq!(TriLabel::from_score(25.0), TriLabel::ModerateRisk);
        assert_eq!(TriLabel::from_score(44.9), TriLabel::ModerateRisk);
        assert_eq!(TriLabel::from_score(45.0), TriLabel::HighRisk);
        assert_eq!(TriLabel::from_score(64.9), TriLabel::HighRisk);
        assert_eq!(TriLabel::from_score(65.0), TriLabel::Avoid);
        assert_eq!(TriLabel::from_score(100.0), TriLabel::Avoid);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_tri_label_display() {
        assert_eq!(TriLabel::VerySafe.display(), "VERY SAFE");
        assert_eq!(TriLabel::ModerateRisk.display(), "MODERATE RISK");
        assert_eq!(TriLabel::HighRisk.display(), "HIGH RISK");
        assert_eq!(TriLabel::Avoid.display(), "AVOID");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_tri_label_emoji() {
        assert_eq!(TriLabel::VerySafe.emoji(), "🟢");
        assert_eq!(TriLabel::ModerateRisk.emoji(), "🟡");
        assert_eq!(TriLabel::HighRisk.emoji(), "🟠");
        assert_eq!(TriLabel::Avoid.emoji(), "🔴");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_red_flag_creation() {
        let flag = RedFlag::new("Test", "Test description", 0.5);
        assert_eq!(flag.category, "Test");
        assert_eq!(flag.description, "Test description");
        assert_eq!(flag.weight, 0.5);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_tri_engine_default() {
        let engine = TriEngine::default();
        assert_eq!(engine.config.weights_contract, 0.30);
        assert_eq!(engine.config.weights_ownership, 0.20);
        assert_eq!(engine.config.weights_liquidity, 0.20);
        assert_eq!(engine.config.weights_tax, 0.15);
        assert_eq!(engine.config.weights_volume, 0.10);
        assert_eq!(engine.config.weights_age, 0.05);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_contract_risk_safe() {
        let engine = TriEngine::new();
        let input = create_test_input();
        let score = engine.compute_contract_risk(&input);
        assert_eq!(score, 0.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_contract_risk_honeypot() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.is_honeypot = true;
        let score = engine.compute_contract_risk(&input);
        assert_eq!(score, 40.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_contract_risk_multiple_flags() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.owner_can_mint = true;
        input.owner_can_blacklist = true;
        input.selfdestruct = true;
        let score = engine.compute_contract_risk(&input);
        assert_eq!(score, 65.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_lp_score_locked_long() {
        let engine = TriEngine::new();
        let input = create_test_input();
        let score = engine.compute_lp_score(&input);
        assert_eq!(score, 0.0); // Fully locked, good liquidity
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_lp_score_not_locked() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.lp_locked = false;
        let score = engine.compute_lp_score(&input);
        assert_eq!(score, 100.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_lp_score_low_liquidity() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.liquidity_usd = 1000.0;
        let score = engine.compute_lp_score(&input);
        assert!(score > 20.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_ownership_risk_safe() {
        let engine = TriEngine::new();
        let input = create_test_input();
        let score = engine.compute_ownership_risk(&input);
        assert!(score < 30.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_ownership_risk_concentrated() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.top10_holders_percent = 90.0;
        input.dev_wallet_percent = 20.0;
        let score = engine.compute_ownership_risk(&input);
        assert!(score > 70.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_tax_risk_low() {
        let engine = TriEngine::new();
        let input = create_test_input();
        let score = engine.compute_tax_risk(&input);
        assert_eq!(score, 12.0); // (3 + 3) * 2 = 12
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_tax_risk_high() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.buy_tax = 10.0;
        input.sell_tax = 25.0;
        let score = engine.compute_tax_risk(&input);
        assert!(score > 50.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_honeypot_risk_safe() {
        let engine = TriEngine::new();
        let input = create_test_input();
        let score = engine.compute_honeypot_risk(&input);
        assert_eq!(score, 3.0); // 0.03 * 100
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_honeypot_risk_confirmed() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.is_honeypot = true;
        let score = engine.compute_honeypot_risk(&input);
        assert_eq!(score, 100.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_honeypot_risk_cannot_sell() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.can_sell = false;
        let score = engine.compute_honeypot_risk(&input);
        assert_eq!(score, 100.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_volume_risk_good() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        // Set volume quality > 0.6 for good score
        input.unique_traders_24h = 700;
        input.total_trades_24h = 1000;
        let score = engine.compute_volume_risk(&input);
        assert_eq!(score, 0.0); // Good volume quality (0.7)
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_volume_risk_wash_trading() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.volume_24h_usd = 1_000_000.0; // 10x liquidity
        input.unique_traders_24h = 10;
        input.total_trades_24h = 1000;
        let score = engine.compute_volume_risk(&input);
        assert_eq!(score, 90.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_dev_behavior_safe() {
        let engine = TriEngine::new();
        let input = create_test_input();
        let score = engine.compute_dev_behavior(&input);
        assert_eq!(score, 0.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_dev_behavior_risky() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.lp_removed_by_dev = true;
        input.dev_dump_ratio = 0.5;
        let score = engine.compute_dev_behavior(&input);
        assert_eq!(score, 100.0); // Clamped to maximum
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_age_risk_old() {
        let engine = TriEngine::new();
        let input = create_test_input();
        let score = engine.compute_age_risk(&input);
        assert!(score < 5.0); // 1 day old = ~2.89
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_age_risk_new() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.token_age_minutes = Some(1.0); // 1 minute old
        let score = engine.compute_age_risk(&input);
        assert_eq!(score, 100.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_compute_tri_full() {
        let engine = TriEngine::new();
        let input = create_test_input();
        let result = engine.compute_tri(&input);

        assert_eq!(result.token_address, input.token_address);
        assert_eq!(result.chain, input.chain);
        assert!(result.tri >= 0.0 && result.tri <= 100.0);
        assert!(result.contract_risk >= 0.0 && result.contract_risk <= 100.0);
        assert!(result.lp_score >= 0.0 && result.lp_score <= 100.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_tri_result_is_safe() {
        let engine = TriEngine::new();
        let input = create_test_input();
        let result = engine.compute_tri(&input);

        // Safe token should be safe
        assert!(result.is_safe());
        assert!(!result.should_avoid());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_tri_result_with_honeypot() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.is_honeypot = true;
        input.owner_can_mint = true;
        input.hidden_owner = true;
        input.sell_tax = 50.0;
        input.lp_locked = false;
        let result = engine.compute_tri(&input);

        assert!(result.should_avoid());
        assert!(!result.is_safe());
        assert!(result.red_flag_count() > 0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_tri_flags_collection() {
        let engine = TriEngine::new();
        let mut input = create_test_input();
        input.owner_can_mint = true;
        input.lp_locked = false;
        input.sell_tax = 35.0;
        let result = engine.compute_tri(&input);

        assert!(result.red_flag_count() >= 3);
    }

    // =========================================================================
    // Phase 6: Integration Testing - TRI Engine Boundary Conditions
    // =========================================================================

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_honeypot_token_scores_100() {
        // Test that confirmed honeypot with cannot_sell returns maximum TRI score
        let engine = TriEngine::default();
        let input = TriInput {
            is_honeypot: true,
            can_sell: false,
            sell_tax: 99.0,
            ..Default::default()
        };
        let result = engine.compute_tri(&input);
        
        // Honeypot with cannot sell should have maximum risk
        assert_eq!(result.honeypot_risk, 100.0);
        assert!(result.tri >= 65.0); // Should be in "Avoid" range
        assert_eq!(result.tri_label, TriLabel::Avoid);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_safe_token_scores_under_25() {
        // Test that a very safe token scores under 25 (VerySafe)
        let engine = TriEngine::default();
        let input = TriInput {
            token_address: "0xSafeToken".to_string(),
            chain: "ethereum".to_string(),
            liquidity_usd: 500_000.0,
            lp_locked: true,
            lp_lock_days: 365,
            buy_tax: 2.0,
            sell_tax: 2.0,
            can_sell: true,
            token_age_minutes: Some(10_000.0), // ~7 days old
            holder_count: 5000,
            top10_holders_percent: 20.0,
            dev_wallet_percent: 5.0,
            ownership_renounced: true,
            is_honeypot: false,
            owner_can_mint: false,
            owner_can_blacklist: false,
            hidden_owner: false,
            volume_24h_usd: 100_000.0,
            unique_traders_24h: 500,
            total_trades_24h: 1000,
            dev_dump_ratio: 0.0,
            sniper_ratio: 0.0,
            sniper_count: 0,
            ..Default::default()
        };
        let result = engine.compute_tri(&input);
        
        // Safe token should score under 25
        assert!(result.tri < 25.0, "Safe token TRI score {} should be < 25", result.tri);
        assert_eq!(result.tri_label, TriLabel::VerySafe);
        assert!(result.is_safe());
        assert!(!result.should_avoid());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_moderate_risk_token_boundary() {
        // Test token at the boundary of ModerateRisk (25-45)
        let engine = TriEngine::default();
        let input = TriInput {
            liquidity_usd: 50_000.0,
            lp_locked: true,
            lp_lock_days: 60,
            buy_tax: 5.0,
            sell_tax: 8.0,
            can_sell: true,
            token_age_minutes: Some(1440.0), // 1 day
            holder_count: 500,
            top10_holders_percent: 50.0,
            dev_wallet_percent: 15.0,
            ownership_renounced: false,
            is_honeypot: false,
            owner_can_mint: false,
            ..Default::default()
        };
        let result = engine.compute_tri(&input);
        
        // Should be in ModerateRisk range (25-45)
        assert!(result.tri >= 25.0 || result.tri < 65.0, 
            "Token should be ModerateRisk or HighRisk, got {} ({})", 
            result.tri, result.tri_label.display());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_high_risk_token_boundary() {
        // Test token at the boundary of HighRisk (45-65)
        let engine = TriEngine::default();
        let input = TriInput {
            liquidity_usd: 10_000.0,
            lp_locked: false,
            lp_lock_days: 0,
            buy_tax: 10.0,
            sell_tax: 20.0,
            can_sell: true,
            token_age_minutes: Some(120.0), // 2 hours
            holder_count: 100,
            top10_holders_percent: 70.0,
            dev_wallet_percent: 25.0,
            ownership_renounced: false,
            is_honeypot: false,
            owner_can_mint: true,
            ..Default::default()
        };
        let result = engine.compute_tri(&input);
        
        // Should be in HighRisk or Avoid range
        assert!(result.tri >= 45.0, 
            "High risk token should have TRI >= 45, got {}", result.tri);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_avoid_token_boundary() {
        // Test token that should be Avoid (65+)
        let engine = TriEngine::default();
        let input = TriInput {
            liquidity_usd: 1_000.0,
            lp_locked: false,
            lp_lock_days: 0,
            buy_tax: 15.0,
            sell_tax: 50.0,
            can_sell: true,
            token_age_minutes: Some(10.0), // 10 minutes
            holder_count: 50,
            top10_holders_percent: 90.0,
            dev_wallet_percent: 40.0,
            ownership_renounced: false,
            is_honeypot: false,
            owner_can_mint: true,
            owner_can_blacklist: true,
            hidden_owner: true,
            ..Default::default()
        };
        let result = engine.compute_tri(&input);
        
        // Should be in Avoid range (65+)
        assert!(result.tri >= 65.0, 
            "Avoid token should have TRI >= 65, got {}", result.tri);
        assert_eq!(result.tri_label, TriLabel::Avoid);
        assert!(result.should_avoid());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_tri_label_from_score_boundaries() {
        // Test TriLabel::from_score at all boundaries
        assert_eq!(TriLabel::from_score(0.0), TriLabel::VerySafe);
        assert_eq!(TriLabel::from_score(24.9), TriLabel::VerySafe);
        assert_eq!(TriLabel::from_score(25.0), TriLabel::ModerateRisk);
        assert_eq!(TriLabel::from_score(44.9), TriLabel::ModerateRisk);
        assert_eq!(TriLabel::from_score(45.0), TriLabel::HighRisk);
        assert_eq!(TriLabel::from_score(64.9), TriLabel::HighRisk);
        assert_eq!(TriLabel::from_score(65.0), TriLabel::Avoid);
        assert_eq!(TriLabel::from_score(100.0), TriLabel::Avoid);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_contract_risk_max() {
        // Test maximum contract risk (all flags set)
        let engine = TriEngine::default();
        let input = TriInput {
            is_honeypot: true,
            owner_can_mint: true,
            owner_can_blacklist: true,
            hidden_owner: true,
            is_proxy: true,
            selfdestruct: true,
            trade_cannot_be_paused: false,
            ..Default::default()
        };
        let result = engine.compute_tri(&input);
        
        // Contract risk should be very high
        assert!(result.contract_risk >= 80.0, 
            "Max contract risk should be >= 80, got {}", result.contract_risk);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_lp_score_max_risk() {
        // Test maximum LP risk (not locked, low liquidity)
        let engine = TriEngine::default();
        let input = TriInput {
            liquidity_usd: 100.0,
            lp_locked: false,
            lp_lock_days: 0,
            ..Default::default()
        };
        let result = engine.compute_tri(&input);
        
        // LP score should be very high (high risk)
        assert!(result.lp_score >= 80.0, 
            "Max LP risk should be >= 80, got {}", result.lp_score);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_tax_risk_max() {
        // Test maximum tax risk
        let engine = TriEngine::default();
        let input = TriInput {
            buy_tax: 50.0,
            sell_tax: 50.0,
            ..Default::default()
        };
        let result = engine.compute_tri(&input);
        
        // Tax risk should be very high
        assert!(result.tax_risk >= 80.0, 
            "Max tax risk should be >= 80, got {}", result.tax_risk);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_age_risk_new_token() {
        // Test maximum age risk (very new token)
        let engine = TriEngine::default();
        let input = TriInput {
            token_age_minutes: Some(1.0), // 1 minute old
            ..Default::default()
        };
        let result = engine.compute_tri(&input);
        
        // Age risk should be very high for new token
        assert!(result.age_risk >= 80.0, 
            "New token age risk should be >= 80, got {}", result.age_risk);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_age_risk_old_token() {
        // Test minimum age risk (old token)
        let engine = TriEngine::default();
        let input = TriInput {
            token_age_minutes: Some(100_000.0), // ~69 days old
            ..Default::default()
        };
        let result = engine.compute_tri(&input);
        
        // Age risk should be low for old token
        assert!(result.age_risk < 10.0,
            "Old token age risk should be < 10, got {}", result.age_risk);
    }

    // =========================================================================
    // Phase 0 Task 0.4: Owner Renounce TRI Reduction Tests
    // =========================================================================

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_owner_renounced_applies_25_percent_tri_reduction() {
        // Test that owner_renounced with no critical flags applies 25% TRI reduction
        let engine = TriEngine::default();

        // Create input with owner_renounced = true and no critical flags
        let mut input = create_test_input();
        input.owner_renounced = true;
        input.is_honeypot = false;
        input.owner_can_mint = false;
        input.hidden_owner = false;
        input.can_be_upgraded = false;
        input.selfdestruct = false;
        input.personal_privilege = false;

        let result_with_renounced = engine.compute_tri(&input);

        // Create same input but with owner_renounced = false
        input.owner_renounced = false;
        let result_without_renounced = engine.compute_tri(&input);

        // TRI with renounced should be 25% lower (75% of original)
        let expected_with_renounced = result_without_renounced.tri * 0.75;
        assert!(
            (result_with_renounced.tri - expected_with_renounced).abs() < 0.1,
            "TRI with renounced ({}) should be 75% of TRI without ({})",
            result_with_renounced.tri, result_without_renounced.tri
        );

        // Should have OwnershipRenounced green flag
        let has_renounced_flag = result_with_renounced.green_flags.iter()
            .any(|f| f.description.contains("renounced"));
        assert!(has_renounced_flag, "Should have OwnershipRenounced green flag");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_owner_renounced_no_reduction_with_critical_flags() {
        // Test that owner_renounced does NOT apply reduction when critical flags present
        let engine = TriEngine::default();

        // Create input with owner_renounced = true but with critical flag (honeypot)
        let mut input = create_test_input();
        input.owner_renounced = true;
        input.is_honeypot = true; // Critical flag

        let result = engine.compute_tri(&input);

        // Create same input but with owner_renounced = false
        input.owner_renounced = false;
        let result_without_renounced = engine.compute_tri(&input);

        // TRI should be the same (no reduction due to critical flag)
        assert!(
            (result.tri - result_without_renounced.tri).abs() < 0.1,
            "TRI should not be reduced when critical flags present"
        );
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_owner_renounced_no_reduction_with_mint_flag() {
        // Test that owner_renounced does NOT apply reduction when owner_can_mint is true
        let engine = TriEngine::default();

        let mut input = create_test_input();
        input.owner_renounced = true;
        input.owner_can_mint = true; // Critical flag

        let result = engine.compute_tri(&input);

        input.owner_renounced = false;
        let result_without_renounced = engine.compute_tri(&input);

        // TRI should be the same (no reduction due to critical flag)
        assert!(
            (result.tri - result_without_renounced.tri).abs() < 0.1,
            "TRI should not be reduced when owner_can_mint is true"
        );
    }

    #[test]
    fn test_owner_renounced_green_flag_added() {
        // Test that OwnershipRenounced green flag is added when owner_renounced is true
        let engine = TriEngine::default();

        let mut input = create_test_input();
        input.owner_renounced = true;

        let result = engine.compute_tri(&input);

        // Should have OwnershipRenounced green flag
        let has_renounced_flag = result.green_flags.iter()
            .any(|f| f.category == "Ownership" && f.description.contains("renounced"));
        assert!(has_renounced_flag, "Should have OwnershipRenounced green flag");
    }

    #[test]
    fn test_owner_not_renounced_no_green_flag() {
        // Test that OwnershipRenounced green flag is NOT added when owner_renounced is false
        let engine = TriEngine::default();

        let mut input = create_test_input();
        input.owner_renounced = false;

        let result = engine.compute_tri(&input);

        // Should NOT have OwnershipRenounced green flag
        let has_renounced_flag = result.green_flags.iter()
            .any(|f| f.category == "Ownership" && f.description.contains("renounced"));
        assert!(!has_renounced_flag, "Should NOT have OwnershipRenounced green flag");
    }

    // =========================================================================
    // Phase 1 Task 1.8: Gas Asymmetry Tests
    // =========================================================================

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_gas_asymmetry_no_asymmetry() {
        // Token with gas ratio < 2.0 should not add risk
        let engine = TriEngine::default();
        let mut input = create_test_input();
        input.gas_asymmetry_ratio = Some(1.5); // Below threshold
        input.gas_asymmetry_detected = false;

        let result = engine.compute_tri(&input);
        
        // Honeypot risk should not be affected by gas asymmetry below threshold
        assert!(result.honeypot_risk < 50.0, "No gas asymmetry should result in low honeypot risk");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_gas_asymmetry_moderate_adds_risk() {
        // Token with gas ratio > 2.0 but < 3.0 should add moderate risk (+15)
        let engine = TriEngine::default();
        let mut input = create_test_input();
        input.gas_asymmetry_ratio = Some(2.5); // Moderate asymmetry
        input.gas_asymmetry_detected = true;

        let result_with_asymmetry = engine.compute_tri(&input);

        // Compare with no asymmetry
        let mut input_no_asymmetry = create_test_input();
        input_no_asymmetry.gas_asymmetry_ratio = Some(1.0);
        let result_no_asymmetry = engine.compute_tri(&input_no_asymmetry);

        // Moderate asymmetry should add 15 to honeypot risk
        let honeypot_diff = result_with_asymmetry.honeypot_risk - result_no_asymmetry.honeypot_risk;
        assert!(
            (honeypot_diff - 15.0).abs() < 0.1,
            "Moderate gas asymmetry should add 15 to honeypot risk, got diff {honeypot_diff}"
        );
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_gas_asymmetry_severe_adds_risk() {
        // Token with gas ratio > 3.0 should add severe risk (+30)
        let engine = TriEngine::default();
        let mut input = create_test_input();
        input.gas_asymmetry_ratio = Some(4.5); // Severe asymmetry
        input.gas_asymmetry_detected = true;

        let result_with_asymmetry = engine.compute_tri(&input);

        // Compare with no asymmetry
        let mut input_no_asymmetry = create_test_input();
        input_no_asymmetry.gas_asymmetry_ratio = Some(1.0);
        let result_no_asymmetry = engine.compute_tri(&input_no_asymmetry);

        // Severe asymmetry should add 30 to honeypot risk
        let honeypot_diff = result_with_asymmetry.honeypot_risk - result_no_asymmetry.honeypot_risk;
        assert!(
            (honeypot_diff - 30.0).abs() < 0.1,
            "Severe gas asymmetry should add 30 to honeypot risk, got diff {honeypot_diff}"
        );
    }

    #[test]
    fn test_gas_asymmetry_none() {
        // Token without gas data should not crash
        let engine = TriEngine::default();
        let mut input = create_test_input();
        input.gas_asymmetry_ratio = None;
        input.gas_asymmetry_detected = false;

        let result = engine.compute_tri(&input);
        
        // Should handle None gracefully
        assert!(result.honeypot_risk < 50.0, "No gas data should result in low honeypot risk");
    }

    #[test]
    fn test_gas_asymmetry_red_flag_moderate() {
        // Test that moderate gas asymmetry creates red flag
        let engine = TriEngine::default();
        let mut input = create_test_input();
        input.gas_asymmetry_ratio = Some(2.5);
        input.gas_asymmetry_detected = true;

        let result = engine.compute_tri(&input);

        // Should have gas asymmetry red flag
        let has_gas_flag = result.red_flags.iter()
            .any(|f| f.description.contains("asymmetry"));
        assert!(has_gas_flag, "Should have gas asymmetry red flag");
    }

    #[test]
    fn test_gas_asymmetry_red_flag_severe() {
        // Test that severe gas asymmetry creates red flag
        let engine = TriEngine::default();
        let mut input = create_test_input();
        input.gas_asymmetry_ratio = Some(4.5);
        input.gas_asymmetry_detected = true;

        let result = engine.compute_tri(&input);

        // Should have severe gas asymmetry red flag
        let has_gas_flag = result.red_flags.iter()
            .any(|f| f.description.contains("Severe"));
        assert!(has_gas_flag, "Should have severe gas asymmetry red flag");
    }

    #[test]
    fn test_gas_asymmetry_threshold_boundary_2_0() {
        // Test exact boundary at 2.0
        let engine = TriEngine::default();

        let mut input_below = create_test_input();
        input_below.gas_asymmetry_ratio = Some(1.99); // Just below threshold
        let result_below = engine.compute_tri(&input_below);

        let mut input_above = create_test_input();
        input_above.gas_asymmetry_ratio = Some(2.01); // Just above threshold
        let result_above = engine.compute_tri(&input_above);

        // Honeypot risk should increase when crossing 2.0 threshold
        assert!(
            result_above.honeypot_risk > result_below.honeypot_risk,
            "Crossing 2.0 threshold should increase honeypot risk"
        );
    }

    #[test]
    fn test_gas_asymmetry_threshold_boundary_3_0() {
        // Test exact boundary at 3.0
        let engine = TriEngine::default();

        let mut input_below = create_test_input();
        input_below.gas_asymmetry_ratio = Some(2.99); // Just below severe threshold
        let result_below = engine.compute_tri(&input_below);

        let mut input_above = create_test_input();
        input_above.gas_asymmetry_ratio = Some(3.01); // Just above severe threshold
        let result_above = engine.compute_tri(&input_above);

        // Honeypot risk should increase when crossing 3.0 threshold
        assert!(
            result_above.honeypot_risk > result_below.honeypot_risk,
            "Crossing 3.0 threshold should increase honeypot risk"
        );
    }

    #[test]
    fn test_gas_asymmetry_combined_with_honeypot() {
        // Gas asymmetry should stack with confirmed honeypot
        let engine = TriEngine::default();
        let mut input = create_test_input();
        input.is_honeypot = true;
        input.gas_asymmetry_ratio = Some(4.0);
        input.gas_asymmetry_detected = true;

        let result = engine.compute_tri(&input);
        
        // Confirmed honeypot should return 100.0 honeypot risk
        assert!((result.honeypot_risk - 100.0).abs() < f32::EPSILON, "Confirmed honeypot should be 100.0");
    }
}
