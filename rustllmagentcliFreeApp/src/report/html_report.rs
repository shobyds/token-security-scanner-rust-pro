//! HTML Report Generator

#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::format_collect)]
#![allow(clippy::unnecessary_debug_formatting)]

use anyhow::Context;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::info;

use super::{ReportGenerator, RiskLevel, TokenSecurityReport};

/// HTML report generator
pub struct HtmlReportGenerator;

impl Default for HtmlReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl HtmlReportGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate and save HTML report to organized directory structure
    ///
    /// # Arguments
    /// * `report` - The security report to save
    /// * `reports_dir` - The reports subdirectory in the organized structure
    ///
    /// # Returns
    /// * `Ok(PathBuf)` - Path to saved report
    /// * `Err(anyhow::Error)` - Error saving report
    pub fn save_to_organized_dir(
        &self,
        report: &TokenSecurityReport,
        reports_dir: &Path,
    ) -> Result<PathBuf, anyhow::Error> {
        fs::create_dir_all(reports_dir).context(format!(
            "Failed to create reports directory: {reports_dir:?}"
        ))?;

        let file_path = reports_dir.join("token_report.html");

        let html = Self::generate_html_content(report);

        let mut file = fs::File::create(&file_path)
            .context(format!("Failed to create report file: {file_path:?}"))?;

        file.write_all(html.as_bytes())
            .context("Failed to write HTML report")?;

        info!("HTML report generated (organized): {:?}", file_path);
        Ok(file_path)
    }

    fn generate_html_content(report: &TokenSecurityReport) -> String {
        let risk_color = match report.risk_assessment.risk_level {
            RiskLevel::Low => "#28a745",
            RiskLevel::Medium => "#ffc107",
            RiskLevel::High => "#fd7e14",
            RiskLevel::Critical => "#dc3545",
        };

        let risk_factors_html: String = report
            .risk_assessment
            .risk_factors
            .iter()
            .map(|f| {
                let icon = if f.detected { "⚠️" } else { "✅" };
                let style = if f.detected {
                    "color: #dc3545;"
                } else {
                    "color: #28a745; opacity: 0.6;"
                };
                format!(
                    r#"<li style="{}">{} <strong>{}</strong>: {}</li>"#,
                    style, icon, f.name, f.description
                )
            })
            .collect();

        let api_status_html: String = {
            let mut html = String::new();
            if report.scan_result.dexscreener.is_some() {
                html.push_str(r#"<span class="status-ok">✅ DexScreener</span>"#);
            } else {
                html.push_str(r#"<span class="status-error">❌ DexScreener</span>"#);
            }
            if report.scan_result.honeypot.is_some() {
                html.push_str(r#"<span class="status-ok">✅ Honeypot.is</span>"#);
            } else {
                html.push_str(r#"<span class="status-error">❌ Honeypot.is</span>"#);
            }
            if report.scan_result.goplus.is_some() {
                html.push_str(r#"<span class="status-ok">✅ GoPlus</span>"#);
            } else {
                html.push_str(r#"<span class="status-error">❌ GoPlus</span>"#);
            }
            if report.scan_result.etherscan.is_some() {
                html.push_str(r#"<span class="status-ok">✅ Etherscan</span>"#);
            } else {
                html.push_str(r#"<span class="status-error">❌ Etherscan</span>"#);
            }
            html
        };

        let rec_class = match report.risk_assessment.risk_level {
            RiskLevel::Critical => "critical",
            RiskLevel::Low => "safe",
            _ => "",
        };

        let lp_locked_str = if report.token_data.lp_locked {
            "✅ Yes"
        } else {
            "❌ No"
        };
        let contract_verified_str = if report.token_data.contract_verified {
            "✅ Yes"
        } else {
            "❌ No"
        };

        // TRI scoring section
        let tri_score = report.tri_score;
        let tri_label = &report.tri_label;
        let tri_emoji = match tri_label.as_str() {
            "VERY SAFE" => "🟢",
            "MODERATE RISK" => "🟡",
            "HIGH RISK" => "🟠",
            "AVOID" => "🔴",
            _ => "⚪",
        };
        let rug_prob_percent = report.rug_probability * 100.0;
        let owner_can_mint_str = if report.token_data.owner_can_mint {
            "⚠️ Yes"
        } else {
            "✅ No"
        };
        let owner_can_blacklist_str = if report.token_data.owner_can_blacklist {
            "⚠️ Yes"
        } else {
            "✅ No"
        };
        let is_honeypot_str = if report.token_data.is_honeypot {
            "⚠️ Yes"
        } else {
            "✅ No"
        };

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Token Security Report - {token}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: white; border-radius: 15px; padding: 30px; margin-bottom: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }}
        .header h1 {{ color: #333; font-size: 2em; margin-bottom: 10px; }}
        .header .subtitle {{ color: #666; font-size: 1.1em; }}
        .card {{ background: white; border-radius: 15px; padding: 25px; margin-bottom: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }}
        .card h2 {{ color: #333; font-size: 1.5em; margin-bottom: 20px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        .risk-score {{ text-align: center; padding: 30px; }}
        .risk-score .score {{ font-size: 4em; font-weight: bold; color: {risk_color}; }}
        .risk-score .level {{ font-size: 1.5em; color: #666; margin-top: 10px; }}
        .data-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }}
        .data-item {{ background: #f8f9fa; padding: 15px; border-radius: 10px; }}
        .data-item .label {{ color: #666; font-size: 0.9em; margin-bottom: 5px; }}
        .data-item .value {{ color: #333; font-size: 1.2em; font-weight: 600; }}
        .risk-factors {{ list-style: none; }}
        .risk-factors li {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
        .risk-factors li:last-child {{ border-bottom: none; }}
        .api-status {{ display: flex; flex-wrap: wrap; gap: 10px; }}
        .api-status span {{ padding: 8px 15px; background: #f8f9fa; border-radius: 20px; font-size: 0.9em; }}
        .status-ok {{ background: #d4edda; color: #155724; }}
        .status-error {{ background: #f8d7da; color: #721c24; }}
        .recommendation {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 20px; border-radius: 5px; white-space: pre-line; }}
        .recommendation.critical {{ background: #f8d7da; border-left-color: #dc3545; }}
        .recommendation.safe {{ background: #d4edda; border-left-color: #28a745; }}
        .timestamp {{ color: #999; font-size: 0.85em; text-align: right; margin-top: 20px; }}
        .token-address {{ font-family: monospace; background: #f8f9fa; padding: 5px 10px; border-radius: 5px; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Token Security Report</h1>
            <p class="subtitle">Token: <span class="token-address">{token}</span></p>
            <p class="subtitle">Chain: {chain} | Generated: {generated}</p>
        </div>

        <div class="card">
            <h2>📊 Risk Assessment</h2>
            <div class="risk-score">
                <div class="score" style="color: {risk_color}">{score}/100</div>
                <div class="level">Risk Level: {risk_level}</div>
            </div>
        </div>

        <div class="card">
            <h2>📈 Token Data (Section 16 Model)</h2>
            <div class="data-grid">
                <div class="data-item">
                    <div class="label">Token Address</div>
                    <div class="value token-address">{token}</div>
                </div>
                <div class="data-item">
                    <div class="label">Liquidity (USD)</div>
                    <div class="value">${liq:.2}</div>
                </div>
                <div class="data-item">
                    <div class="label">Price (USD)</div>
                    <div class="value">${price:.6}</div>
                </div>
                <div class="data-item">
                    <div class="label">Holder Count</div>
                    <div class="value">{holders}</div>
                </div>
                <div class="data-item">
                    <div class="label">Buy Tax</div>
                    <div class="value">{buy_tax}%</div>
                </div>
                <div class="data-item">
                    <div class="label">Sell Tax</div>
                    <div class="value">{sell_tax}%</div>
                </div>
                <div class="data-item">
                    <div class="label">Top Holder %</div>
                    <div class="value">{top_holder}%</div>
                </div>
                <div class="data-item">
                    <div class="label">LP Locked</div>
                    <div class="value">{lp_locked}</div>
                </div>
                <div class="data-item">
                    <div class="label">Contract Verified</div>
                    <div class="value">{contract_verified}</div>
                </div>
                <div class="data-item">
                    <div class="label">Owner Can Mint</div>
                    <div class="value">{owner_mint}</div>
                </div>
                <div class="data-item">
                    <div class="label">Owner Can Blacklist</div>
                    <div class="value">{owner_blacklist}</div>
                </div>
                <div class="data-item">
                    <div class="label">Is Honeypot</div>
                    <div class="value">{is_honeypot}</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>⚠️ Risk Factors</h2>
            <ul class="risk-factors">
                {risk_factors}
            </ul>
        </div>

        <div class="card">
            <h2>🔌 API Providers Status</h2>
            <div class="api-status">
                {api_status}
            </div>
        </div>

        <div class="card">
            <h2>📊 TRI (Token Risk Index) Analysis</h2>
            <div class="data-grid">
                <div class="data-item">
                    <div class="label">TRI Score</div>
                    <div class="value" style="color: {risk_color}; font-weight: bold;">{tri_score:.1}/100 {tri_emoji}</div>
                </div>
                <div class="data-item">
                    <div class="label">TRI Label</div>
                    <div class="value">{tri_label}</div>
                </div>
                <div class="data-item">
                    <div class="label">Rug Probability</div>
                    <div class="value">{rug_prob_percent:.1}%</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>💡 Recommendation</h2>
            <div class="recommendation {rec_class}">{recommendation}</div>
        </div>

        <div class="card">
            <h2>⏱️ Scan Performance</h2>
            <div class="data-grid">
                <div class="data-item">
                    <div class="label">Total Scan Time</div>
                    <div class="value">{scan_time}ms</div>
                </div>
                <div class="data-item">
                    <div class="label">Successful APIs</div>
                    <div class="value">{success_count}/5</div>
                </div>
            </div>
        </div>

        <p class="timestamp">Report generated by TokenGuard Security Scanner v{version}</p>
    </div>
</body>
</html>"#,
            token = report.token_data.token_address,
            chain = report.token_data.chain.to_uppercase(),
            generated = report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            risk_color = risk_color,
            score = report.risk_assessment.overall_score,
            risk_level = report.risk_assessment.risk_level,
            liq = report.token_data.liquidity_usd,
            price = report.token_data.price_usd,
            holders = report.token_data.holder_count,
            buy_tax = report.token_data.buy_tax,
            sell_tax = report.token_data.sell_tax,
            top_holder = report.token_data.top_holder_percent,
            lp_locked = lp_locked_str,
            contract_verified = contract_verified_str,
            owner_mint = owner_can_mint_str,
            owner_blacklist = owner_can_blacklist_str,
            is_honeypot = is_honeypot_str,
            risk_factors = risk_factors_html,
            api_status = api_status_html,
            rec_class = rec_class,
            recommendation = report.risk_assessment.recommendation,
            scan_time = report.scan_result.scan_time_ms,
            success_count = report.scan_result.success_count(),
            version = report.metadata.report_version,
        )
    }
}

impl ReportGenerator for HtmlReportGenerator {
    fn generate_report(
        &self,
        report: &TokenSecurityReport,
        output_dir: &Path,
    ) -> Result<PathBuf, anyhow::Error> {
        fs::create_dir_all(output_dir).context(format!(
            "Failed to create output directory: {output_dir:?}"
        ))?;

        let filename = format!(
            "token_report_{}_{}.html",
            &report.token_data.token_address[..10],
            chrono::Utc::now().format("%Y%m%d_%H%M%S")
        );

        let file_path = output_dir.join(&filename);

        let html = Self::generate_html_content(report);

        let mut file = fs::File::create(&file_path)
            .context(format!("Failed to create report file: {file_path:?}"))?;

        file.write_all(html.as_bytes())
            .context("Failed to write HTML report")?;

        info!("HTML report generated: {:?}", file_path);
        Ok(file_path)
    }

    fn file_extension(&self) -> &'static str {
        "html"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_report_generator() {
        let generator = HtmlReportGenerator::new();
        assert_eq!(generator.file_extension(), "html");
    }
}
