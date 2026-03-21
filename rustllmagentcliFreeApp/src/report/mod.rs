//! Report Generation Module for Token Security Analysis
//!
//! This module provides report generation capabilities including:
//! - Traditional flat JSON/HTML report generation
//! - Organized directory structure for LLM analysis
//! - Scan manifest files for comprehensive data mapping

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::float_cmp)]

pub mod html_report;
pub mod json_report;
pub mod manifest;
pub mod directory_manager;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub use html_report::HtmlReportGenerator;
pub use json_report::JsonReportGenerator;
pub use manifest::{ScanManifest, ScanInfo, FileManifestEntry, FileType, ApiProvider};
pub use directory_manager::{ReportDirectoryManager, TokenScanDirectory};

use crate::api::ScanResult;
use crate::models::TokenData;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Json,
    Html,
    Both,
}

impl ReportFormat {
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "html" => Some(Self::Html),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

impl FromStr for ReportFormat {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s).ok_or(())
    }
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Html => write!(f, "html"),
            Self::Both => write!(f, "both"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub generated_at: DateTime<Utc>,
    pub token_address: String,
    pub chain: String,
    pub format: String,
    pub includes_market_data: bool,
    pub scan_duration_ms: u64,
    pub report_version: String,
}

impl Default for ReportMetadata {
    fn default() -> Self {
        Self {
            generated_at: Utc::now(),
            token_address: String::new(),
            chain: String::new(),
            format: String::new(),
            includes_market_data: false,
            scan_duration_ms: 0,
            report_version: "1.0.0".to_string(),
        }
    }
}

impl ReportMetadata {
    pub fn from_scan_result(
        scan_result: &ScanResult,
        format: &str,
        includes_market_data: bool,
    ) -> Self {
        Self {
            generated_at: Utc::now(),
            token_address: scan_result.token_address.clone(),
            chain: scan_result.chain.clone(),
            format: format.to_string(),
            includes_market_data,
            scan_duration_ms: scan_result.scan_time_ms,
            report_version: "1.0.0".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSecurityReport {
    pub metadata: ReportMetadata,
    pub token_data: TokenData,
    pub scan_result: ScanResult,
    pub risk_assessment: RiskAssessment,
    // TRI scoring fields
    pub tri_score: f32,
    pub tri_label: String,
    pub rug_probability: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_score: u8,
    pub risk_level: RiskLevel,
    pub risk_factors: Vec<RiskFactor>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl RiskLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=20 => Self::Low,
            21..=40 => Self::Medium,
            41..=70 => Self::High,
            _ => Self::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub name: String,
    pub description: String,
    pub severity: u8,
    pub detected: bool,
}

impl TokenSecurityReport {
    pub fn new(scan_result: ScanResult, includes_market_data: bool) -> Self {
        let metadata =
            ReportMetadata::from_scan_result(&scan_result, "comprehensive", includes_market_data);
        let risk_score = scan_result.aggregated.risk_score();
        let risk_level = RiskLevel::from_score(risk_score);
        let risk_factors = Self::extract_risk_factors(&scan_result.aggregated);
        let recommendation = Self::generate_recommendation(risk_level, &risk_factors);

        // Compute TRI scoring
        let metrics = crate::scanner::extract_features(&scan_result);
        let rug_probability = crate::scanner::compute_rug_probability(&metrics);
        let tri_input = crate::scanner::TriInput {
            token_address: metrics.token_address.clone(),
            chain: metrics.chain.clone(),
            is_honeypot: metrics.is_honeypot,
            owner_can_mint: metrics.owner_can_mint,
            owner_can_blacklist: metrics.owner_can_blacklist,
            hidden_owner: metrics.hidden_owner,
            is_proxy: metrics.is_proxy,
            selfdestruct: metrics.selfdestruct,
            trade_cannot_be_paused: !metrics.trade_can_be_paused,
            personal_privilege: false,
            external_call: false,
            can_be_upgraded: false,
            liquidity_usd: metrics.liquidity_usd,
            lp_locked: metrics.lp_locked,
            lp_lock_days: metrics.lp_lock_days,
            market_cap_usd: metrics.market_cap_usd,
            holder_count: metrics.holder_count,
            top10_holders_percent: metrics.top10_holders_percent,
            dev_wallet_percent: metrics.dev_wallet_percent,
            ownership_renounced: metrics.ownership_renounced,
            owner_renounced: metrics.owner_renounced,  // Phase 0 Task 0.4
            buy_tax: metrics.buy_tax,
            sell_tax: metrics.sell_tax,
            can_sell: metrics.can_sell,
            effective_sell_tax: metrics.effective_sell_tax,
            // Phase 1 Task 1.8: Gas asymmetry fields
            gas_asymmetry_ratio: metrics.gas_asymmetry_ratio,
            gas_asymmetry_detected: metrics.gas_asymmetry_detected,
            volume_24h_usd: metrics.volume_24h_usd,
            unique_traders_24h: 0,
            total_trades_24h: metrics.buy_count_24h + metrics.sell_count_24h,
            token_age_minutes: metrics.token_age_minutes,
            dev_dump_ratio: metrics.dev_dump_ratio,
            lp_removed_by_dev: false,
            sniper_count: metrics.sniper_count,
            sniper_ratio: metrics.sniper_ratio,
            price_confidence: metrics.price_confidence,  // Phase 1 Task 1.6 Sprint 3 INT-001
        };
        let tri_engine = crate::scanner::TriEngine::default();
        let tri_result = tri_engine.compute_tri(&tri_input);

        // Build token_data with price_confidence from DefiLlama
        let mut token_data = scan_result.aggregated.clone();
        token_data.price_confidence = metrics.price_confidence;

        Self {
            metadata,
            token_data,
            scan_result,
            risk_assessment: RiskAssessment {
                overall_score: risk_score,
                risk_level,
                risk_factors,
                recommendation,
            },
            tri_score: tri_result.tri,
            tri_label: tri_result.tri_label.display().to_string(),
            rug_probability,
        }
    }

    fn extract_risk_factors(token_data: &TokenData) -> Vec<RiskFactor> {
        let mut factors = Vec::new();

        factors.push(RiskFactor {
            name: "Honeypot Detection".to_string(),
            description: "Token may be a honeypot (can buy but cannot sell)".to_string(),
            severity: 10,
            detected: token_data.is_honeypot,
        });

        factors.push(RiskFactor {
            name: "Mintable Token".to_string(),
            description: "Owner can mint new tokens, potentially diluting value".to_string(),
            severity: 7,
            detected: token_data.owner_can_mint,
        });

        factors.push(RiskFactor {
            name: "Blacklist Function".to_string(),
            description: "Owner can blacklist addresses from trading".to_string(),
            severity: 7,
            detected: token_data.owner_can_blacklist,
        });

        factors.push(RiskFactor {
            name: "Unlocked Liquidity".to_string(),
            description: "Liquidity pool is not locked, rug pull risk".to_string(),
            severity: 8,
            detected: !token_data.lp_locked,
        });

        factors.push(RiskFactor {
            name: "Holder Concentration".to_string(),
            description: format!(
                "Top holder owns {:.1}% of supply",
                token_data.top_holder_percent
            ),
            severity: if token_data.top_holder_percent > 50.0 {
                9
            } else if token_data.top_holder_percent > 30.0 {
                6
            } else {
                3
            },
            detected: token_data.top_holder_percent > 30.0,
        });

        factors.push(RiskFactor {
            name: "Unverified Contract".to_string(),
            description: "Contract source code is not verified".to_string(),
            severity: 6,
            detected: !token_data.contract_verified,
        });

        factors.push(RiskFactor {
            name: "High Transaction Taxes".to_string(),
            description: format!(
                "Buy tax: {:.1}%, Sell tax: {:.1}%",
                token_data.buy_tax, token_data.sell_tax
            ),
            severity: if token_data.buy_tax > 15.0 || token_data.sell_tax > 15.0 {
                7
            } else if token_data.buy_tax > 10.0 || token_data.sell_tax > 10.0 {
                5
            } else {
                2
            },
            detected: token_data.buy_tax > 10.0 || token_data.sell_tax > 10.0,
        });

        factors.push(RiskFactor {
            name: "Low Liquidity".to_string(),
            description: format!("Liquidity: ${:.2}", token_data.liquidity_usd),
            severity: if token_data.liquidity_usd < 1000.0 {
                8
            } else if token_data.liquidity_usd < 10000.0 {
                5
            } else {
                2
            },
            detected: token_data.liquidity_usd < 10000.0,
        });

        factors
    }

    fn generate_recommendation(risk_level: RiskLevel, _risk_factors: &[RiskFactor]) -> String {
        match risk_level {
            RiskLevel::Low => "Token appears to be safe. Standard due diligence recommended.".to_string(),
            RiskLevel::Medium => "Token shows moderate risk. Proceed with caution and conduct additional research.".to_string(),
            RiskLevel::High => "Token shows high risk indicators. Investment not recommended without thorough investigation.".to_string(),
            RiskLevel::Critical => "CRITICAL WARNING: Token shows multiple severe risk factors. DO NOT INVEST.".to_string(),
        }
    }
}

pub trait ReportGenerator {
    fn generate_report(
        &self,
        report: &TokenSecurityReport,
        output_dir: &Path,
    ) -> Result<PathBuf, anyhow::Error>;
    fn file_extension(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ApiError, ScanResult, TimingBreakdown};

    fn create_test_scan_result() -> ScanResult {
        ScanResult {
            token_address: "0x1234567890123456789012345678901234567890".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 2500,
            timing_breakdown: TimingBreakdown {
                dexscreener_ms: 500,
                honeypot_ms: 450,
                goplus_ms: 600,
                etherscan_ms: 400,
                ethplorer_ms: 550,
                dedaub_ms: 0,
                transfer_events_ms: 0,
                blockscout_ms: 0,
                alchemy_simulation_ms: 0,
                rpc_simulation_ms: 0,
                tenderly_ms: 0,
                deployer_ms: 0,
                source_analysis_ms: 0,
                blacklist_analysis_ms: 0,
                honeypot_is_ms: 0,
                scammer_detection_ms: 0,
                lp_lock_ms: 0,
                graph_analytics_ms: 0,
                defillama_ms: 0,
            },
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: vec![],
        }
    }

    #[test]
    fn test_report_format_from_str() {
        assert_eq!(ReportFormat::from_str("json"), Some(ReportFormat::Json));
        assert_eq!(ReportFormat::from_str("JSON"), Some(ReportFormat::Json));
        assert_eq!(ReportFormat::from_str("html"), Some(ReportFormat::Html));
        assert_eq!(ReportFormat::from_str("both"), Some(ReportFormat::Both));
        assert_eq!(ReportFormat::from_str("invalid"), None);
    }

    #[test]
    fn test_report_format_display() {
        assert_eq!(ReportFormat::Json.to_string(), "json");
        assert_eq!(ReportFormat::Html.to_string(), "html");
        assert_eq!(ReportFormat::Both.to_string(), "both");
    }

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(20), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(21), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(40), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(41), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(70), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(71), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(100), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(255), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(RiskLevel::Low.to_string(), "LOW");
        assert_eq!(RiskLevel::Medium.to_string(), "MEDIUM");
        assert_eq!(RiskLevel::High.to_string(), "HIGH");
        assert_eq!(RiskLevel::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn test_report_metadata_default() {
        let metadata = ReportMetadata::default();
        assert_eq!(metadata.format, "");
        assert_eq!(metadata.report_version, "1.0.0");
        assert!(!metadata.includes_market_data);
        assert_eq!(metadata.scan_duration_ms, 0);
    }

    #[test]
    fn test_report_metadata_from_scan_result() {
        let scan_result = create_test_scan_result();
        let metadata = ReportMetadata::from_scan_result(&scan_result, "test", true);

        assert_eq!(
            metadata.token_address,
            "0x1234567890123456789012345678901234567890"
        );
        assert_eq!(metadata.chain, "ethereum");
        assert_eq!(metadata.format, "test");
        assert!(metadata.includes_market_data);
        assert_eq!(metadata.scan_duration_ms, 2500);
        assert_eq!(metadata.report_version, "1.0.0");
    }

    #[test]
    fn test_token_security_report_creation() {
        let scan_result = create_test_scan_result();
        let report = TokenSecurityReport::new(scan_result.clone(), false);

        assert_eq!(report.token_data.token_address, "");
        assert_eq!(
            report.scan_result.token_address,
            "0x1234567890123456789012345678901234567890"
        );
        // Note: overall_score is based on TokenData risk_score() which is 0 for default
        assert_eq!(report.risk_assessment.overall_score, 0);
        assert_eq!(report.risk_assessment.risk_level, RiskLevel::Low);
        assert!(!report.metadata.includes_market_data);
        
        // TRI scoring fields should be populated (computed from extracted features)
        // Default test data has some risk from age risk (default 60 minutes)
        assert!(report.tri_score >= 0.0 && report.tri_score <= 100.0);
        assert!(!report.tri_label.is_empty());
        assert!(report.rug_probability >= 0.0 && report.rug_probability <= 1.0);
    }

    #[test]
    fn test_risk_factors_extraction() {
        let mut scan_result = create_test_scan_result();
        scan_result.aggregated.is_honeypot = true;
        scan_result.aggregated.owner_can_mint = true;
        scan_result.aggregated.lp_locked = false;
        scan_result.aggregated.top_holder_percent = 60.0;

        let report = TokenSecurityReport::new(scan_result, false);

        // Check that risk factors were extracted
        assert!(!report.risk_assessment.risk_factors.is_empty());

        // Honeypot should be detected
        let honeypot_factor = report
            .risk_assessment
            .risk_factors
            .iter()
            .find(|f| f.name == "Honeypot Detection");
        assert!(honeypot_factor.is_some());
        assert!(honeypot_factor.unwrap().detected);
        assert_eq!(honeypot_factor.unwrap().severity, 10);

        // LP unlocked should be detected
        let lp_factor = report
            .risk_assessment
            .risk_factors
            .iter()
            .find(|f| f.name == "Unlocked Liquidity");
        assert!(lp_factor.is_some());
        assert!(lp_factor.unwrap().detected);
    }

    #[test]
    fn test_recommendation_generation() {
        // Test Low risk recommendation
        assert!(
            TokenSecurityReport::new(create_test_scan_result(), false)
                .risk_assessment
                .recommendation
                .contains("safe")
        );
    }

    #[test]
    fn test_report_generator_trait() {
        use super::{HtmlReportGenerator, JsonReportGenerator};

        let json_gen = JsonReportGenerator::new();
        assert_eq!(json_gen.file_extension(), "json");

        let html_gen = HtmlReportGenerator::new();
        assert_eq!(html_gen.file_extension(), "html");
    }

    #[test]
    fn test_section_16_token_data_fields() {
        // Verify that TokenData has all Section 16 required fields
        let token_data = TokenData::default();

        // Section 16 required fields:
        // - token_address
        assert!(token_data.token_address.is_empty());
        // - liquidity_usd
        assert_eq!(token_data.liquidity_usd, 0.0);
        // - holder_count
        assert_eq!(token_data.holder_count, 0);
        // - buy_tax
        assert_eq!(token_data.buy_tax, 0.0);
        // - sell_tax
        assert_eq!(token_data.sell_tax, 0.0);
        // - owner_can_mint
        assert!(!token_data.owner_can_mint);
        // - owner_can_blacklist
        assert!(!token_data.owner_can_blacklist);
        // - lp_locked
        assert!(!token_data.lp_locked);
        // - top_holder_percent
        assert_eq!(token_data.top_holder_percent, 0.0);
        // - contract_verified
        assert!(!token_data.contract_verified);
    }

    #[test]
    fn test_risk_score_calculation() {
        let mut token_data = TokenData::default();

        // Safe token should have low risk
        assert!(token_data.risk_score() <= 20);

        // Honeypot should increase risk significantly
        token_data.is_honeypot = true;
        assert!(token_data.risk_score() >= 50);

        // Multiple risk factors should increase score
        token_data.owner_can_mint = true;
        token_data.lp_locked = false;
        token_data.top_holder_percent = 55.0;
        assert!(token_data.risk_score() >= 50);
    }
}
