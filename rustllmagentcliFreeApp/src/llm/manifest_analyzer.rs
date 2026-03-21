//! Manifest Analyzer Module for LLM-based Token Analysis
//!
//! This module reads `scan_manifest.json` and all referenced API response files,
//! then calls the Groq LLM to generate a comprehensive, professional markdown analysis report.
//!
//! # Features
//! - Reads scan manifest and all referenced API response files
//! - Builds comprehensive analysis prompt with all token data
//! - Calls Groq LLM for professional analysis
//! - Generates detailed markdown report with executive summary, risk assessment, and recommendations
//! - Saves report alongside manifest in organized directory structure

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unused_self)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unnecessary_debug_formatting)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::fn_params_excessive_bools)]
#![allow(clippy::manual_midpoint)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

use crate::llm::{Phi3Client, Phi3Config, LlmAnalysis, LlmRecommendation};
use crate::report::manifest::{ScanManifest, FileType, ApiProvider};

/// Result of LLM manifest analysis
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Generated markdown content
    pub markdown_content: String,
    /// Path where report was saved
    pub output_path: PathBuf,
}

/// Analyzer for generating LLM-based token security reports from scan manifests
pub struct ManifestAnalyzer {
    llm_client: Phi3Client,
}

impl ManifestAnalyzer {
    /// Create a new ManifestAnalyzer with default Groq configuration
    pub fn new() -> Result<Self> {
        let config = Phi3Config::from_env();
        let llm_client = Phi3Client::new(&config)
            .context("Failed to initialize LLM client")?;
        
        Ok(Self { llm_client })
    }

    /// Create a new ManifestAnalyzer with custom configuration
    pub fn with_config(config: &Phi3Config) -> Result<Self> {
        let llm_client = Phi3Client::new(config)
            .context("Failed to initialize LLM client")?;
        
        Ok(Self { llm_client })
    }

    /// Analyze a scan manifest and generate comprehensive markdown report
    ///
    /// # Arguments
    /// * `manifest_path` - Path to scan_manifest.json
    ///
    /// # Returns
    /// * `AnalysisResult` - Contains markdown content and output path
    pub async fn analyze_manifest(&self, manifest_path: &Path) -> Result<AnalysisResult> {
        info!("Analyzing manifest: {:?}", manifest_path);
        
        // Load manifest
        let manifest = self.load_manifest(manifest_path)?;
        let base_dir = manifest_path.parent()
            .context("Manifest path has no parent directory")?;
        
        info!("Manifest loaded for token: {} on {}", 
              manifest.scan_info.token_address, 
              manifest.scan_info.chain);
        
        // Load all API responses
        let api_data = self.load_api_responses(&manifest, base_dir)?;
        
        // Build comprehensive analysis prompt
        let prompt = self.build_analysis_prompt(&manifest, &api_data);
        
        debug!("Sending analysis prompt to LLM ({} chars)", prompt.len());
        
        // Call Groq LLM
        let llm_response = self.call_llm(&prompt).await?;
        
        // Generate markdown report from LLM response
        let markdown_content = self.generate_markdown_report(&manifest, &api_data, &llm_response);
        
        // Determine output path (same directory as manifest)
        let output_path = base_dir.join("token_analysis.md");
        
        // Save report
        self.save_markdown_report(&markdown_content, &output_path)?;
        
        info!("LLM analysis saved to: {:?}", output_path);
        
        Ok(AnalysisResult {
            markdown_content,
            output_path,
        })
    }

    /// Load scan manifest from file
    fn load_manifest(&self, path: &Path) -> Result<ScanManifest> {
        let content = std::fs::read_to_string(path)
            .context(format!("Failed to read manifest file: {:?}", path))?;
        
        let manifest: ScanManifest = serde_json::from_str(&content)
            .context("Failed to parse manifest JSON")?;
        
        debug!("Manifest loaded: {} API responses, {} files", 
               manifest.api_responses.len(), 
               manifest.files.len());
        
        Ok(manifest)
    }

    /// Load all API response files referenced in manifest
    fn load_api_responses(&self, manifest: &ScanManifest, base_dir: &Path) -> Result<String> {
        let mut api_data = HashMap::new();
        
        for (provider, relative_path) in &manifest.api_responses {
            let full_path = base_dir.join(relative_path);
            
            match std::fs::read_to_string(&full_path) {
                Ok(content) => {
                    // Try to parse as JSON for pretty formatting
                    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&content) {
                        api_data.insert(provider.clone(), json_value);
                        debug!("Loaded API response from {}: {:?}", provider, full_path);
                    } else {
                        api_data.insert(provider.clone(), serde_json::Value::String(content));
                        debug!("Loaded raw response from {}: {:?}", provider, full_path);
                    }
                }
                Err(e) => {
                    warn!("Failed to load API response from {:?}: {}", full_path, e);
                    api_data.insert(provider.clone(), serde_json::Value::String(
                        format!("Error loading file: {}", e)
                    ));
                }
            }
        }
        
        // Serialize all API data into a single JSON string for the LLM
        let api_data_json = serde_json::to_string_pretty(&api_data)
            .context("Failed to serialize API data")?;
        
        Ok(api_data_json)
    }

    /// Build comprehensive analysis prompt for the LLM
    fn build_analysis_prompt(&self, manifest: &ScanManifest, api_data: &str) -> String {
        let token_addr = &manifest.scan_info.token_address;
        let chain = &manifest.scan_info.chain;
        let tri_score = manifest.tri_score.unwrap_or(0.0);
        let rug_prob = manifest.rug_probability.unwrap_or(0.0);
        let risk_level = manifest.risk_level.as_deref().unwrap_or("UNKNOWN");
        
        format!(
            r#"# Token Security Analysis Request

You are an expert blockchain security analyst specializing in token risk assessment. 
Analyze the provided token data and generate a comprehensive, professional security report.

## Token Information
- **Contract Address**: `{token_addr}`
- **Chain**: {chain}
- **TRI Score**: {tri_score:.1}/100
- **Rug Probability**: {rug_prob:.1}%
- **Risk Level**: {risk_level}

## API Data
The following JSON contains all available API responses from various security and market data providers:

```json
{api_data}
```

## Report Requirements

Generate a detailed markdown report with the following sections:

### 1. Executive Summary
- Overall risk assessment (1-2 sentences)
- Key findings summary (bullet points)
- Clear recommendation (Invest/Caution/Avoid)

### 2. Token Overview
- Token name and symbol (from Dexscreener data)
- Contract address and chain
- Current price and market cap
- Liquidity and volume metrics

### 3. API Data Analysis

#### 3.1 Dexscreener Market Data
- Liquidity analysis (total USD, trends)
- Volume analysis (24h volume, buy/sell ratio)
- Pool distribution (dominance ratio, top pools)
- Trading activity (buys vs sells, unique traders)

#### 3.2 GoPlus Contract Security
- Owner privileges analysis
- Mint capabilities check
- Proxy status and upgradeability
- Risk flags identified
- LP lock status

#### 3.3 Honeypot Detection
- Buy/sell simulation results
- Tax analysis (buy tax, sell tax)
- Trading restrictions check
- Honeypot confirmation

#### 3.4 Etherscan Contract Metadata
- Contract verification status
- Source code availability
- Deployer information
- Holder count and distribution

### 4. Risk Assessment

#### Green Flags (Positive Indicators)
List all positive findings with brief explanations:
- [ ] Example: "LP is locked for 1+ years"
- [ ] Example: "Contract is verified and open source"
- [ ] Example: "No owner privileges detected"

#### Red Flags (Risk Indicators)
List all risk findings with severity levels (Critical/High/Medium/Low):
- [ ] **Critical**: Example: "Owner can mint unlimited tokens"
- [ ] **High**: Example: "Extremely high sell tax (>25%)"
- [ ] **Medium**: Example: "Low liquidity (<$10k)"
- [ ] **Low**: Example: "Contract not verified"

### 5. TRI Score Analysis
- Explain the TRI score of {tri_score:.1}/100
- Compare to risk thresholds:
  - 0-20: Very Low Risk
  - 20-40: Low Risk  
  - 40-60: Medium Risk
  - 60-80: High Risk
  - 80-100: Very High Risk
- Interpret the {rug_prob:.1}% rug probability

### 6. Detailed Findings

#### Liquidity Risk
- Analyze liquidity depth and sustainability
- Check for liquidity concentration
- Evaluate trading volume vs liquidity ratio

#### Contract Security
- Review all security flags from GoPlus
- Analyze owner privileges and controls
- Check for proxy/upgrade mechanisms

#### Holder Distribution
- Analyze top holder concentration
- Check for CEX/DAO labeled holders
- Identify potential whale wallets

#### Trading Patterns
- Evaluate buy/sell pressure balance
- Check for unusual trading activity
- Analyze volume quality

#### Tax Analysis
- Review buy and sell taxes
- Compare to typical ranges (0-15% normal, >25% concerning)
- Check for dynamic tax mechanisms

### 7. Conclusion
- Final risk rating (Very Low/Low/Medium/High/Very High)
- Investment recommendation with reasoning
- Monitoring suggestions for ongoing assessment

### 8. Appendix
- Data sources used
- Analysis timestamp
- Confidence level in assessment
- Disclaimer about limitations

## Output Format

Generate the report in clean, professional markdown format with:
- Clear section headers using ## and ###
- Tables for structured data where appropriate
- Bullet points for lists
- Bold text for emphasis on key findings
- Code blocks for contract addresses
- Emoji indicators for risk levels (🟢 Green, 🟡 Caution, 🔴 Risk)

Be thorough, objective, and evidence-based. Cite specific data points from the API responses to support your findings."#
        )
    }

    /// Call Groq LLM with the analysis prompt
    async fn call_llm(&self, prompt: &str) -> Result<LlmAnalysis> {
        info!("Calling Groq LLM for token analysis...");
        
        // Create messages array for chat API
        let messages = serde_json::json!([
            {
                "role": "system",
                "content": "You are an expert blockchain security analyst specializing in DeFi token risk assessment. You provide thorough, objective, and evidence-based security analysis reports. Your reports are professional, well-structured, and actionable."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]);
        
        // Create input for the LLM client
        let input = serde_json::json!({
            "messages": messages
        });
        
        // Call the LLM (using rug_prob of 0.0 since this is a general analysis, not ML-triggered)
        let analysis = self.llm_client.analyze_token(&input, 0.0).await
            .context("LLM analysis failed")?;
        
        info!("LLM analysis completed successfully");
        
        Ok(analysis)
    }

    /// Generate markdown report from LLM response and data
    fn generate_markdown_report(
        &self,
        manifest: &ScanManifest,
        api_data: &str,
        llm_response: &LlmAnalysis,
    ) -> String {
        let token_addr = &manifest.scan_info.token_address;
        let chain = &manifest.scan_info.chain;
        let timestamp = &manifest.scan_info.scan_timestamp;
        let tri_score = manifest.tri_score.unwrap_or(0.0);
        let rug_prob = manifest.rug_probability.unwrap_or(0.0);
        let risk_level = manifest.risk_level.as_deref().unwrap_or("UNKNOWN");
        let api_success = manifest.api_success_count;
        let api_failure = manifest.api_failure_count;

        // Parse API data for specific sections
        let api_value: serde_json::Value = serde_json::from_str(api_data).unwrap_or_default();

        // Extract token info from Dexscreener data
        let dex_data = api_value.get("dexscreener").cloned().unwrap_or_default();
        let token_name = dex_data.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let token_symbol = dex_data.get("symbol").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let price_usd = dex_data.get("price_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let liquidity_usd = dex_data.get("liquidity_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let volume_24h = dex_data.get("volume_24h").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let market_cap = dex_data.get("market_cap").and_then(|v| v.as_f64()).unwrap_or(0.0);

        // Extract GoPlus data
        let goplus_data = api_value.get("goplus").cloned().unwrap_or_default();
        let is_proxy = goplus_data.get("is_proxy").and_then(|v| v.as_bool()).unwrap_or(false);
        let can_be_upgraded = goplus_data.get("can_be_upgraded").and_then(|v| v.as_bool()).unwrap_or(false);
        let owner_can_mint = goplus_data.get("owner_can_mint").and_then(|v| v.as_bool()).unwrap_or(false);
        let lp_locked = goplus_data.get("lp_locked").and_then(|v| v.as_bool()).unwrap_or(false);
        let risk_flags: Vec<&serde_json::Value> = goplus_data.get("risk_flags")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().collect())
            .unwrap_or_default();

        // Extract Honeypot data
        let honeypot_data = api_value.get("honeypot").cloned().unwrap_or_default();
        let is_honeypot = honeypot_data.get("is_honeypot").and_then(|v| v.as_bool()).unwrap_or(false);
        let buy_tax = honeypot_data.get("buy_tax").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let sell_tax = honeypot_data.get("sell_tax").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let can_buy = honeypot_data.get("can_buy").and_then(|v| v.as_bool()).unwrap_or(true);
        let can_sell = honeypot_data.get("can_sell").and_then(|v| v.as_bool()).unwrap_or(true);

        // Extract Etherscan data
        let etherscan_data = api_value.get("etherscan").cloned().unwrap_or_default();
        let is_verified = etherscan_data.get("is_verified").and_then(|v| v.as_bool()).unwrap_or(false);
        let holder_count = etherscan_data.get("holder_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let total_supply = etherscan_data.get("total_supply").and_then(|v| v.as_str()).unwrap_or("N/A");
        let compiler_version = etherscan_data.get("compiler_version").and_then(|v| v.as_str()).unwrap_or("N/A");

        // Pre-format numbers with commas
        let liquidity_fmt = format_number(liquidity_usd);
        let volume_fmt = format_number(volume_24h);
        let market_cap_fmt = format_number(market_cap);
        let tri_total = api_success + api_failure;

        // Build green flags
        let mut green_flags: Vec<String> = Vec::new();
        if !is_honeypot && can_buy && can_sell {
            green_flags.push("✅ **Not a Honeypot**: Buy and sell transactions execute normally".to_string());
        }
        if !owner_can_mint {
            green_flags.push("✅ **No Mint Function**: Owner cannot create additional tokens".to_string());
        }
        if !is_proxy && !can_be_upgraded {
            green_flags.push("✅ **Non-Upgradeable Contract**: Contract logic cannot be changed".to_string());
        }
        if risk_flags.is_empty() {
            green_flags.push("✅ **No Risk Flags**: GoPlus detected no security concerns".to_string());
        }
        if liquidity_usd > 100_000.0 {
            green_flags.push(format!("✅ **Strong Liquidity**: ${} USD locked", liquidity_fmt));
        }
        if is_verified {
            green_flags.push("✅ **Verified Contract**: Source code is publicly verified".to_string());
        }
        if buy_tax <= 10.0 && sell_tax <= 10.0 {
            green_flags.push(format!("✅ **Reasonable Taxes**: Buy {:.1}%, Sell {:.1}%", buy_tax, sell_tax));
        }

        // Build red flags
        let mut red_flags: Vec<String> = Vec::new();
        if is_honeypot || !can_buy || !can_sell {
            red_flags.push("🔴 **CRITICAL**: Token appears to be a honeypot or has trading restrictions".to_string());
        }
        if owner_can_mint {
            red_flags.push("🔴 **HIGH**: Owner can mint unlimited tokens (dilution risk)".to_string());
        }
        if is_proxy || can_be_upgraded {
            red_flags.push("🟡 **MEDIUM**: Contract is upgradeable (logic can change)".to_string());
        }
        if !risk_flags.is_empty() {
            red_flags.push("🟡 **MEDIUM**: GoPlus detected risk flags".to_string());
        }
        if liquidity_usd < 10_000.0 && liquidity_usd > 0.0 {
            red_flags.push("🟡 **MEDIUM**: Low liquidity (high slippage risk)".to_string());
        }
        if !is_verified {
            red_flags.push("🟡 **MEDIUM**: Contract source code not verified".to_string());
        }
        if buy_tax > 15.0 || sell_tax > 15.0 {
            red_flags.push(format!("🟡 **MEDIUM**: High taxes (Buy {:.1}%, Sell {:.1}%)", buy_tax, sell_tax));
        }
        if sell_tax > 25.0 {
            red_flags.push("🔴 **HIGH**: Extremely high sell tax (>25%)".to_string());
        }
        if volume_24h < 0.0 {
            red_flags.push("🟡 **MEDIUM**: Negative or zero 24h volume (data issue or no trading)".to_string());
        }

        // Calculate risk emoji
        let risk_emoji = if tri_score < 20.0 {
            "🟢"
        } else if tri_score < 40.0 {
            "🟡"
        } else if tri_score < 60.0 {
            "🟠"
        } else {
            "🔴"
        };

        // Get LLM response values
        let llm_explanation = &llm_response.explanation;
        let recommendation = llm_response.recommendation.display();
        let recommendation_emoji = get_recommendation_emoji(&llm_response.recommendation);
        let recommendation_details = get_recommendation_details(&llm_response.recommendation, tri_score, rug_prob);
        let confidence_pct = (llm_response.confidence_level * 100.0) as u32;

        // Assessments
        let liquidity_assessment = get_liquidity_assessment(liquidity_usd);
        let volume_assessment = get_volume_assessment(volume_24h);
        let market_cap_assessment = get_market_cap_assessment(market_cap);
        let liquidity_analysis = format_liquidity_analysis(liquidity_usd, volume_24h);
        let volume_analysis = format_volume_analysis(volume_24h, liquidity_usd);

        // GoPlus status
        let proxy_status = yes_no(is_proxy);
        let proxy_risk = get_risk_status(is_proxy);
        let upgrade_status = yes_no(can_be_upgraded);
        let upgrade_risk = get_risk_status(can_be_upgraded);
        let mint_status = yes_no(owner_can_mint);
        let mint_risk = get_risk_status(owner_can_mint);
        let lp_status = yes_no(!lp_locked);
        let lp_risk = get_risk_status(!lp_locked);
        let hidden_owner = goplus_data.get("hidden_owner").and_then(|v| v.as_bool()).unwrap_or(false);
        let selfdestruct = goplus_data.get("selfdestruct").and_then(|v| v.as_bool()).unwrap_or(false);
        let hidden_owner_status = yes_no(hidden_owner);
        let hidden_owner_risk = get_risk_status(hidden_owner);
        let selfdestruct_status = yes_no(selfdestruct);
        let selfdestruct_risk = get_risk_status(selfdestruct);
        let risk_flags_str = format_risk_flags(&risk_flags);

        // Honeypot results
        let honeypot_status = yes_no(is_honeypot);
        let can_buy_status = yes_no(can_buy);
        let can_sell_status = yes_no(can_sell);
        let simulation_result = format_honeypot_simulation(is_honeypot, can_buy, can_sell);

        // Etherscan results
        let verified_status = yes_no(is_verified);
        let total_supply_str = if total_supply.is_empty() { "N/A" } else { total_supply };
        let compiler_str = if compiler_version.is_empty() { "N/A" } else { compiler_version };

        // Green and red flags joined
        let green_flags_str = if green_flags.is_empty() {
            "*No significant green flags detected*".to_string()
        } else {
            green_flags.join("\n")
        };
        let red_flags_str = if red_flags.is_empty() {
            "*No significant red flags detected*".to_string()
        } else {
            red_flags.join("\n")
        };

        // Rug probability interpretation
        let rug_interpretation = get_rug_interpretation(rug_prob);

        // Detailed findings
        let liquidity_risk_str = format_liquidity_risk(liquidity_usd, volume_24h);
        let contract_security_str = format_contract_security(is_proxy, can_be_upgraded, owner_can_mint, is_verified);
        let holder_distribution_str = format_holder_distribution(holder_count);
        let trading_patterns_str = format_trading_patterns(volume_24h, buy_tax, sell_tax);
        let tax_analysis_str = format_tax_analysis(buy_tax, sell_tax);

        // Data source status
        let dex_status = get_api_status(manifest.api_responses.contains_key("dexscreener"));
        let goplus_status = get_api_status(manifest.api_responses.contains_key("goplus"));
        let honeypot_status_api = get_api_status(manifest.api_responses.contains_key("honeypot"));
        let etherscan_status = get_api_status(manifest.api_responses.contains_key("etherscan"));
        
        // Format the comprehensive report
        format!(
            r"# 🔍 Token Security Analysis Report

> **Generated**: {timestamp}  
> **Analyzer**: Groq LLM (Llama-3.1-8B-Instant) + TRI Scoring Engine

---

## 📋 Executive Summary

| Metric | Value |
|--------|-------|
| **Token** | {token_name} ({token_symbol}) |
| **Contract** | `{token_addr}` |
| **Chain** | {chain} |
| **TRI Score** | {tri_score:.1}/100 {risk_emoji} |
| **Risk Level** | {risk_level} |
| **Rug Probability** | {rug_prob:.1}% |
| **API Success Rate** | {api_success}/{tri_total} |

### Key Findings

{llm_explanation}

### Recommendation

**{recommendation_emoji} {recommendation}**

{recommendation_details}

---

## 🪙 Token Overview

| Property | Value |
|----------|-------|
| **Name** | {token_name} |
| **Symbol** | {token_symbol} |
| **Contract Address** | `{token_addr}` |
| **Chain** | {chain} |
| **Current Price** | ${price_usd:.6} |
| **Market Cap** | ${market_cap_fmt} |
| **Liquidity (USD)** | ${liquidity_fmt} |
| **Volume (24h)** | ${volume_fmt} |
| **Holder Count** | {holder_count} |

---

## 📊 API Data Analysis

### 3.1 Dexscreener Market Data

| Metric | Value | Assessment |
|--------|-------|------------|
| **Total Liquidity** | ${liquidity_fmt} | {liquidity_assessment} |
| **24h Volume** | ${volume_fmt} | {volume_assessment} |
| **Market Cap** | ${market_cap_fmt} | {market_cap_assessment} |
| **Price** | ${price_usd:.6} | - |

**Liquidity Analysis**: {liquidity_analysis}

**Volume Analysis**: {volume_analysis}

### 3.2 GoPlus Contract Security

| Security Check | Status | Risk Level |
|----------------|--------|------------|
| **Is Proxy** | {proxy_status} | {proxy_risk} |
| **Can Be Upgraded** | {upgrade_status} | {upgrade_risk} |
| **Owner Can Mint** | {mint_status} | {mint_risk} |
| **LP Locked** | {lp_status} | {lp_risk} |
| **Hidden Owner** | {hidden_owner_status} | {hidden_owner_risk} |
| **Can Self-Destruct** | {selfdestruct_status} | {selfdestruct_risk} |

**Risk Flags Detected**: {risk_flags_str}

### 3.3 Honeypot Detection

| Check | Result |
|-------|--------|
| **Is Honeypot** | {honeypot_status} |
| **Can Buy** | {can_buy_status} |
| **Can Sell** | {can_sell_status} |
| **Buy Tax** | {buy_tax:.2}% |
| **Sell Tax** | {sell_tax:.2}% |

**Simulation Result**: {simulation_result}

### 3.4 Etherscan Contract Metadata

| Property | Value |
|----------|-------|
| **Contract Verified** | {verified_status} |
| **Holder Count** | {holder_count} |
| **Total Supply** | {total_supply_str} |
| **Compiler Version** | {compiler_str} |

---

## ⚖️ Risk Assessment

### 🟢 Green Flags (Positive Indicators)

{green_flags_str}

### 🔴 Red Flags (Risk Indicators)

{red_flags_str}

---

## 📈 TRI Score Analysis

**TRI Score: {tri_score:.1}/100**

| Score Range | Risk Level | Description |
|-------------|------------|-------------|
| 0-20 | 🟢 Very Low | Minimal risk indicators |
| 20-40 | 🟡 Low | Few risk indicators |
| 40-60 | 🟠 Medium | Moderate risk, proceed with caution |
| 60-80 | 🔴 High | Significant risk indicators |
| 80-100 | 🔴 Very High | Extreme risk, likely scam |

**Current Assessment**: {risk_level}

**Rug Probability Interpretation**: {rug_prob:.1}% probability indicates {rug_interpretation}

---

## 🔬 Detailed Findings

### Liquidity Risk

{liquidity_risk_str}

### Contract Security

{contract_security_str}

### Holder Distribution

{holder_distribution_str}

### Trading Patterns

{trading_patterns_str}

### Tax Analysis

{tax_analysis_str}

---

## 📝 Conclusion

### Final Risk Rating

**{risk_level}** {risk_emoji}

### Investment Recommendation

{recommendation_details}

### Monitoring Suggestions

1. **Track Liquidity Changes**: Monitor for sudden liquidity removal
2. **Watch Holder Distribution**: Alert if top 10 holders exceed 50%
3. **Monitor Trading Volume**: Unusual spikes may indicate manipulation
4. **Check Social Channels**: Stay informed about project developments
5. **Set Price Alerts**: Be aware of significant price movements

---

## 📎 Appendix

### Data Sources

| Provider | Status | Purpose |
|----------|--------|---------|
| Dexscreener | {dex_status} | Market data, liquidity, volume |
| GoPlus | {goplus_status} | Contract security analysis |
| Honeypot.is | {honeypot_status_api} | Trading simulation, tax analysis |
| Etherscan | {etherscan_status} | Contract verification, metadata |

### Analysis Information

| Property | Value |
|----------|-------|
| **Analysis Timestamp** | {timestamp} |
| **LLM Model** | Groq Llama-3.1-8B-Instant |
| **TRI Engine Version** | 1.0.0 |
| **Confidence Level** | {confidence_pct}% |

### Limitations

- Analysis is based on available API data at scan time
- Market conditions can change rapidly
- Smart contract risks may evolve with upgrades
- This report is for informational purposes only and is not financial advice

---

*Report generated by TokenGuard Security Scanner v1.0.0*
",
            // Variables for format string
            timestamp = timestamp,
            token_name = token_name,
            token_symbol = token_symbol,
            token_addr = token_addr,
            chain = chain,
            tri_score = tri_score,
            risk_emoji = risk_emoji,
            risk_level = risk_level,
            rug_prob = rug_prob,
            api_success = api_success,
            tri_total = tri_total,
            llm_explanation = llm_explanation,
            recommendation_emoji = recommendation_emoji,
            recommendation = recommendation,
            recommendation_details = recommendation_details,
            price_usd = price_usd,
            market_cap_fmt = market_cap_fmt,
            liquidity_fmt = liquidity_fmt,
            volume_fmt = volume_fmt,
            holder_count = holder_count,
            liquidity_assessment = liquidity_assessment,
            volume_assessment = volume_assessment,
            market_cap_assessment = market_cap_assessment,
            liquidity_analysis = liquidity_analysis,
            volume_analysis = volume_analysis,
            proxy_status = proxy_status,
            proxy_risk = proxy_risk,
            upgrade_status = upgrade_status,
            upgrade_risk = upgrade_risk,
            mint_status = mint_status,
            mint_risk = mint_risk,
            lp_status = lp_status,
            lp_risk = lp_risk,
            hidden_owner_status = hidden_owner_status,
            hidden_owner_risk = hidden_owner_risk,
            selfdestruct_status = selfdestruct_status,
            selfdestruct_risk = selfdestruct_risk,
            risk_flags_str = risk_flags_str,
            honeypot_status = honeypot_status,
            can_buy_status = can_buy_status,
            can_sell_status = can_sell_status,
            buy_tax = buy_tax,
            sell_tax = sell_tax,
            simulation_result = simulation_result,
            verified_status = verified_status,
            total_supply_str = total_supply_str,
            compiler_str = compiler_str,
            green_flags_str = green_flags_str,
            red_flags_str = red_flags_str,
            rug_interpretation = rug_interpretation,
            liquidity_risk_str = liquidity_risk_str,
            contract_security_str = contract_security_str,
            holder_distribution_str = holder_distribution_str,
            trading_patterns_str = trading_patterns_str,
            tax_analysis_str = tax_analysis_str,
            dex_status = dex_status,
            goplus_status = goplus_status,
            honeypot_status_api = honeypot_status_api,
            etherscan_status = etherscan_status,
            confidence_pct = confidence_pct,
        )
    }

    /// Save markdown report to file
    fn save_markdown_report(&self, content: &str, output_path: &Path) -> Result<()> {
        std::fs::write(output_path, content)
            .context(format!("Failed to save markdown report to {:?}", output_path))?;
        
        info!("Markdown report saved: {:?}", output_path);
        Ok(())
    }
}

/// Get emoji for recommendation
fn get_recommendation_emoji(rec: &LlmRecommendation) -> &'static str {
    match rec {
        LlmRecommendation::Avoid => "🚨",
        LlmRecommendation::Caution => "⚠️",
        LlmRecommendation::Safe => "✅",
    }
}

/// Format a number with comma separators (e.g., 1000000 -> "1,000,000")
fn format_number(num: f64) -> String {
    // Convert to string with 2 decimal places
    let num_str = format!("{:.2}", num);
    let parts: Vec<&str> = num_str.split('.').collect();
    
    // Format the integer part with commas
    let int_part = parts[0];
    let mut result = String::new();
    let len = int_part.len();
    
    for (i, c) in int_part.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    
    // Add decimal part if exists
    if parts.len() > 1 {
        result.push('.');
        result.push_str(parts[1]);
    }
    
    result
}

/// Get detailed recommendation text
fn get_recommendation_details(rec: &LlmRecommendation, tri_score: f32, rug_prob: f32) -> String {
    match rec {
        LlmRecommendation::Avoid => {
            format!(
                "Based on the analysis, this token presents significant risks. \
                 With a TRI score of {:.1}/100 and {:.1}% rug probability, \
                 we recommend avoiding this investment. The identified red flags \
                 outweigh any positive indicators.",
                tri_score, rug_prob * 100.0
            )
        }
        LlmRecommendation::Caution => {
            format!(
                "This token shows mixed signals with both positive and negative indicators. \
                 With a TRI score of {:.1}/100 and {:.1}% rug probability, \
                 proceed with extreme caution. Only invest what you can afford to lose \
                 and monitor the token closely for any warning signs.",
                tri_score, rug_prob * 100.0
            )
        }
        LlmRecommendation::Safe => {
            format!(
                "This token demonstrates relatively low risk characteristics. \
                 With a TRI score of {:.1}/100 and {:.1}% rug probability, \
                 the security analysis shows favorable indicators. However, \
                 always conduct your own research and never invest more than you can afford to lose.",
                tri_score, rug_prob * 100.0
            )
        }
    }
}

/// Get liquidity assessment
fn get_liquidity_assessment(liquidity: f64) -> &'static str {
    if liquidity > 1_000_000.0 {
        "✅ Excellent"
    } else if liquidity > 100_000.0 {
        "✅ Good"
    } else if liquidity > 10_000.0 {
        "⚠️ Moderate"
    } else if liquidity > 1_000.0 {
        "🔴 Low"
    } else {
        "🔴 Critical"
    }
}

/// Get volume assessment
fn get_volume_assessment(volume: f64) -> &'static str {
    if volume > 1_000_000.0 {
        "✅ Excellent"
    } else if volume > 100_000.0 {
        "✅ Good"
    } else if volume > 10_000.0 {
        "⚠️ Moderate"
    } else if volume > 0.0 {
        "🔴 Low"
    } else {
        "🔴 No Data"
    }
}

/// Get market cap assessment
fn get_market_cap_assessment(mc: f64) -> &'static str {
    if mc > 1_000_000_000.0 {
        "✅ Large Cap"
    } else if mc > 100_000_000.0 {
        "✅ Mid Cap"
    } else if mc > 10_000_000.0 {
        "⚠️ Small Cap"
    } else if mc > 1_000_000.0 {
        "🔴 Micro Cap"
    } else if mc > 0.0 {
        "🔴 Very Small"
    } else {
        "⚠️ Unknown"
    }
}

/// Format liquidity analysis
fn format_liquidity_analysis(liquidity: f64, volume: f64) -> String {
    let liq_fmt = format_number(liquidity);
    if liquidity > 1_000_000.0 {
        format!("Strong liquidity of ${} USD provides good price stability and low slippage for trades.", liq_fmt)
    } else if liquidity > 100_000.0 {
        format!("Moderate liquidity of ${} USD is adequate for small to medium trades.", liq_fmt)
    } else if liquidity > 10_000.0 {
        format!("Low liquidity of ${} USD may result in significant slippage for larger trades.", liq_fmt)
    } else if liquidity > 0.0 {
        format!("Very low liquidity of ${} USD presents high slippage risk and potential manipulation.", liq_fmt)
    } else {
        "No liquidity data available.".to_string()
    }
}

/// Format volume analysis
fn format_volume_analysis(volume: f64, liquidity: f64) -> String {
    if volume <= 0.0 {
        "No 24h volume data available or zero trading activity.".to_string()
    } else {
        let vol_fmt = format_number(volume);
        let vol_liq_ratio = if liquidity > 0.0 { volume / liquidity } else { 0.0 };
        format!(
            "24h volume of ${} represents {:.1}% of liquidity. \
             A ratio above 100% indicates high trading activity; below 10% suggests low interest.",
            vol_fmt,
            vol_liq_ratio * 100.0
        )
    }
}

/// Get risk status string
fn get_risk_status(risky: bool) -> &'static str {
    if risky { "🔴 Risk" } else { "✅ Safe" }
}

/// Format risk flags
fn format_risk_flags(flags: &[&serde_json::Value]) -> String {
    if flags.is_empty() {
        "✅ None detected".to_string()
    } else {
        flags
            .iter()
            .map(|f| format!("🔴 {}", f))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Format honeypot simulation result
fn format_honeypot_simulation(is_honeypot: bool, can_buy: bool, can_sell: bool) -> String {
    if is_honeypot {
        "🔴 Token identified as honeypot - trading simulation failed".to_string()
    } else if !can_buy {
        "🔴 Buy transactions fail - possible honeypot".to_string()
    } else if !can_sell {
        "🔴 Sell transactions fail - confirmed honeypot behavior".to_string()
    } else {
        "✅ Buy and sell simulations passed - not a honeypot".to_string()
    }
}

/// Get API status string
fn get_api_status(available: bool) -> &'static str {
    if available { "✅ Success" } else { "❌ Failed" }
}

/// Get rug probability interpretation
fn get_rug_interpretation(prob: f32) -> String {
    let pct = prob * 100.0;
    if prob < 0.2 {
        format!("{:.1}% indicates low rug pull risk based on ML analysis of token metrics.", pct)
    } else if prob < 0.4 {
        format!("{:.1}% indicates moderate rug pull risk - exercise caution.", pct)
    } else if prob < 0.6 {
        format!("{:.1}% indicates elevated rug pull risk - significant concerns identified.", pct)
    } else {
        format!("{:.1}% indicates high rug pull risk - multiple warning signs detected.", pct)
    }
}

/// Format liquidity risk section
fn format_liquidity_risk(liquidity: f64, volume: f64) -> String {
    if liquidity > 100_000.0 {
        "Liquidity appears sufficient for normal trading activity. The liquidity-to-volume ratio \
         suggests stable trading conditions without excessive volatility from individual trades."
            .to_string()
    } else if liquidity > 10_000.0 {
        "Liquidity is moderate but may not support large trades without significant slippage. \
         Consider position sizing carefully to minimize market impact."
            .to_string()
    } else if liquidity > 0.0 {
        "Low liquidity presents significant risks including high slippage, price manipulation \
         vulnerability, and potential difficulty exiting positions. Exercise extreme caution."
            .to_string()
    } else {
        "No liquidity data available. This is a significant concern as it may indicate \
         a new token, delisted token, or data collection issues.".to_string()
    }
}

/// Format contract security section
fn format_contract_security(
    is_proxy: bool,
    can_be_upgraded: bool,
    owner_can_mint: bool,
    is_verified: bool,
) -> String {
    let mut findings = Vec::new();
    
    if is_verified {
        findings.push("✅ Contract source code is verified, allowing independent audit.");
    } else {
        findings.push("⚠️ Contract is not verified - source code cannot be audited.");
    }
    
    if is_proxy || can_be_upgraded {
        findings.push("⚠️ Contract is upgradeable - logic can be changed by owner.");
    } else {
        findings.push("✅ Contract is immutable - logic cannot be changed.");
    }
    
    if owner_can_mint {
        findings.push("🔴 Owner has minting privileges - token supply can be inflated.");
    } else {
        findings.push("✅ No minting function - supply is fixed or capped.");
    }
    
    findings.join("\n")
}

/// Format holder distribution section
fn format_holder_distribution(holder_count: u64) -> String {
    if holder_count > 10_000 {
        format!(
            "Wide distribution with {} holders suggests organic adoption and reduced \
             whale manipulation risk. However, always check top holder concentration.",
            holder_count
        )
    } else if holder_count > 1_000 {
        format!(
            "Moderate holder count of {} indicates developing adoption. Monitor for \
             concentration risks among top holders.",
            holder_count
        )
    } else if holder_count > 0 {
        format!(
            "Low holder count of {} suggests early-stage token or limited adoption. \
             High risk of whale manipulation.",
            holder_count
        )
    } else {
        "No holder data available. This may indicate a very new token or data issues.".to_string()
    }
}

/// Format trading patterns section
fn format_trading_patterns(volume: f64, buy_tax: f64, sell_tax: f64) -> String {
    if volume <= 0.0 {
        "No trading volume data available. Unable to assess trading patterns.".to_string()
    } else {
        let vol_fmt = format_number(volume);
        let tax_diff = (buy_tax - sell_tax).abs();
        let activity_level = if volume > 100_000.0 { "healthy" } else if volume > 10_000.0 { "moderate" } else { "low" };
        if tax_diff > 5.0 {
            format!(
                "Notable difference between buy ({:.1}%) and sell ({:.1}%) taxes may indicate \
                 imbalanced incentives. Monitor for potential sell pressure.",
                buy_tax, sell_tax
            )
        } else {
            format!(
                "Balanced tax structure (Buy: {:.1}%, Sell: {:.1}%) suggests neutral trading \
                 incentives. Volume of ${} indicates {} trading activity.",
                buy_tax, sell_tax, vol_fmt, activity_level
            )
        }
    }
}

/// Format tax analysis section
fn format_tax_analysis(buy_tax: f64, sell_tax: f64) -> String {
    let avg_tax = (buy_tax + sell_tax) / 2.0;
    
    if avg_tax <= 5.0 {
        format!(
            "Low tax structure (Buy: {:.1}%, Sell: {:.1}%) is favorable for traders and \
             suggests the project prioritizes trading activity.",
            buy_tax, sell_tax
        )
    } else if avg_tax <= 10.0 {
        format!(
            "Moderate tax structure (Buy: {:.1}%, Sell: {:.1}%) is within normal range for \
             DeFi tokens. Taxes may fund development or liquidity.",
            buy_tax, sell_tax
        )
    } else if avg_tax <= 15.0 {
        format!(
            "Elevated tax structure (Buy: {:.1}%, Sell: {:.1}%) may discourage frequent \
             trading. Understand where tax revenue is allocated.",
            buy_tax, sell_tax
        )
    } else {
        format!(
            "High tax structure (Buy: {:.1}%, Sell: {:.1}%) is concerning and may indicate \
             excessive project take or potential exit scam mechanics. Exercise caution.",
            buy_tax, sell_tax
        )
    }
}

/// Yes/No helper
fn yes_no(value: bool) -> &'static str {
    if value { "Yes" } else { "No" }
}

impl Default for ManifestAnalyzer {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            error!("Failed to create ManifestAnalyzer: {}", e);
            // Create with default config - will fail gracefully on API calls if not configured
            let config = Phi3Config::default();
            let llm_client = Phi3Client::new(&config).unwrap_or_else(|_| {
                // Fallback: create client with minimal config
                // This will fail on API calls but allows the struct to be created
                let mut fallback_config = Phi3Config::default();
                fallback_config.api_key = std::env::var("GROQ_API_KEY").ok();
                Phi3Client::new(&fallback_config).expect("Failed to create fallback Phi3Client")
            });
            Self { llm_client }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yes_no() {
        assert_eq!(yes_no(true), "Yes");
        assert_eq!(yes_no(false), "No");
    }

    #[test]
    fn test_get_risk_status() {
        assert_eq!(get_risk_status(true), "🔴 Risk");
        assert_eq!(get_risk_status(false), "✅ Safe");
    }

    #[test]
    fn test_get_liquidity_assessment() {
        assert_eq!(get_liquidity_assessment(2_000_000.0), "✅ Excellent");
        assert_eq!(get_liquidity_assessment(500_000.0), "✅ Good");
        assert_eq!(get_liquidity_assessment(50_000.0), "⚠️ Moderate");
        assert_eq!(get_liquidity_assessment(5_000.0), "🔴 Low");
        assert_eq!(get_liquidity_assessment(500.0), "🔴 Critical");
    }

    #[test]
    fn test_get_volume_assessment() {
        assert_eq!(get_volume_assessment(2_000_000.0), "✅ Excellent");
        assert_eq!(get_volume_assessment(500_000.0), "✅ Good");
        assert_eq!(get_volume_assessment(50_000.0), "⚠️ Moderate");
        assert_eq!(get_volume_assessment(5_000.0), "🔴 Low");
        assert_eq!(get_volume_assessment(0.0), "🔴 No Data");
    }

    #[test]
    fn test_get_recommendation_emoji() {
        assert_eq!(get_recommendation_emoji(&LlmRecommendation::Avoid), "🚨");
        assert_eq!(get_recommendation_emoji(&LlmRecommendation::Caution), "⚠️");
        assert_eq!(get_recommendation_emoji(&LlmRecommendation::Safe), "✅");
    }

    #[test]
    fn test_format_risk_flags_empty() {
        let flags: Vec<&serde_json::Value> = vec![];
        let result = format_risk_flags(&flags);
        assert_eq!(result, "✅ None detected");
    }

    #[test]
    fn test_format_honeypot_simulation_safe() {
        let result = format_honeypot_simulation(false, true, true);
        assert!(result.contains("✅"));
        assert!(result.contains("not a honeypot"));
    }

    #[test]
    fn test_format_honeypot_simulation_honeypot() {
        let result = format_honeypot_simulation(true, false, false);
        assert!(result.contains("🔴"));
        assert!(result.contains("honeypot"));
    }
}
