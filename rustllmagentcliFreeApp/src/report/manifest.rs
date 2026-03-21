//! Scan Manifest for Organized Report Structure
//!
//! This module provides structures and functions for creating comprehensive
//! scan manifests that map all API responses and reports for LLM analysis.

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::io_other_error)]
#![allow(clippy::to_string_in_format_args)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Type of file in the manifest
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    /// Raw API response
    ApiResponse,
    /// Generated report (JSON or HTML)
    Report,
    /// Manifest file itself
    Manifest,
}

/// API provider enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApiProvider {
    Dexscreener,
    Goplus,
    Honeypot,
    Etherscan,
    Bitquery,
    Moralis,
    Defillama,
    Ethplorer,
    // Phase 3: Advanced Features
    Dedaub,
    TransferEvents,
    Blockscout,
    AlchemySimulation,
    RpcSimulation,
    Tenderly,
    // Phase 4: Deployer, Source, Blacklist
    Phase4Deployer,
    Phase4Source,
    Phase4Blacklist,
    // Phase 4.1: Scammer Detection (Forta Replacement)
    ScammerDetection,
    // Phase 4.3: LP Lock & Holder Analytics
    LpLock,
    GraphAnalytics,
    Unknown,
}

impl From<&str> for ApiProvider {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "dexscreener" => Self::Dexscreener,
            "goplus" => Self::Goplus,
            "honeypot" => Self::Honeypot,
            "etherscan" => Self::Etherscan,
            "bitquery" => Self::Bitquery,
            "moralis" => Self::Moralis,
            "defillama" => Self::Defillama,
            "ethplorer" => Self::Ethplorer,
            // Phase 3: Advanced Features
            "dedaub" => Self::Dedaub,
            "transfer_events" | "transferevents" => Self::TransferEvents,
            "blockscout" => Self::Blockscout,
            "alchemy_simulation" | "alc" => Self::AlchemySimulation,
            "rpc_simulation" | "rpc" => Self::RpcSimulation,
            "tenderly" => Self::Tenderly,
            // Phase 4: Deployer, Source, Blacklist
            "phase4_deployer" | "phase4deployer" => Self::Phase4Deployer,
            "phase4_source" | "phase4source" => Self::Phase4Source,
            "phase4_blacklist" | "phase4blacklist" => Self::Phase4Blacklist,
            // Phase 4.1: Scammer Detection
            "scammer_detection" | "scammerdetection" => Self::ScammerDetection,
            // Phase 4.3: LP Lock & Holder Analytics
            "lp_lock" | "lplock" => Self::LpLock,
            "graph_analytics" | "graphanalytics" | "thegraph" => Self::GraphAnalytics,
            _ => Self::Unknown,
        }
    }
}

/// Main manifest structure for a token scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanManifest {
    /// Metadata about the scan
    pub scan_info: ScanInfo,
    /// Mapping of API provider to response file path
    pub api_responses: HashMap<String, String>,
    /// Mapping of report types to file paths
    pub reports: ReportPaths,
    /// Number of successful API calls
    pub api_success_count: u32,
    /// Number of failed API calls
    pub api_failure_count: u32,
    /// TRI score if calculated
    pub tri_score: Option<f32>,
    /// Rug probability if calculated
    pub rug_probability: Option<f32>,
    /// Risk level label
    pub risk_level: Option<String>,
    /// LLM analysis prompt
    pub llm_analysis_prompt: String,
    /// Detailed file information
    pub files: Vec<FileManifestEntry>,
}

/// Metadata about the scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanInfo {
    /// Token contract address
    pub token_address: String,
    /// Token name (e.g., "Uniswap")
    pub token_name: Option<String>,
    /// Token symbol (e.g., "UNI")
    pub token_symbol: Option<String>,
    /// Blockchain network
    pub chain: String,
    /// ISO 8601 timestamp of scan
    pub scan_timestamp: String,
    /// Scan duration in milliseconds
    pub scan_duration_ms: u64,
    /// Directory path relative to reports root
    pub scan_directory: String,
}

impl ScanInfo {
    /// Create a new ScanInfo
    #[must_use]
    pub fn new(
        token_address: String,
        token_name: Option<String>,
        token_symbol: Option<String>,
        chain: String,
        scan_duration_ms: u64,
    ) -> Self {
        Self {
            token_address,
            token_name,
            token_symbol,
            chain,
            scan_timestamp: Utc::now().to_rfc3339(),
            scan_duration_ms,
            scan_directory: String::new(),
        }
    }
}

/// Paths to generated reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPaths {
    /// Path to JSON report
    pub json: String,
    /// Path to HTML report
    pub html: String,
}

/// Individual file manifest entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifestEntry {
    /// Relative path to file
    pub path: String,
    /// Type of file (api_response, report, manifest)
    pub file_type: FileType,
    /// API provider name (for api_response types)
    pub provider: Option<ApiProvider>,
    /// Whether the API call succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Fields that were populated from this response
    pub fields_populated: Vec<String>,
    /// File size in bytes
    pub size_bytes: Option<u64>,
}

impl ScanManifest {
    /// Create a new scan manifest
    #[must_use]
    pub fn new(scan_info: ScanInfo) -> Self {
        Self {
            scan_info,
            api_responses: HashMap::new(),
            reports: ReportPaths {
                json: "reports/token_report.json".to_string(),
                html: "reports/token_report.html".to_string(),
            },
            api_success_count: 0,
            api_failure_count: 0,
            tri_score: None,
            rug_probability: None,
            risk_level: None,
            llm_analysis_prompt: String::new(),
            files: Vec::new(),
        }
    }

    /// Add an API response entry
    pub fn add_api_response(
        &mut self,
        provider: ApiProvider,
        success: bool,
        fields: Vec<String>,
        error: Option<String>,
        size_bytes: Option<u64>,
    ) {
        // Convert provider to filename (with underscores for multi-word names)
        let filename = match provider {
            ApiProvider::ScammerDetection => "scammer_detection",
            ApiProvider::Phase4Deployer => "phase4_deployer",
            ApiProvider::Phase4Source => "phase4_source",
            ApiProvider::Phase4Blacklist => "phase4_blacklist",
            ApiProvider::LpLock => "lp_lock",
            ApiProvider::GraphAnalytics => "graph_analytics",
            ApiProvider::AlchemySimulation => "alchemy_simulation",
            ApiProvider::RpcSimulation => "rpc_simulation",
            ApiProvider::TransferEvents => "transfer_events",
            _ => {
                let s = format!("{provider:?}").to_lowercase();
                return self.add_api_response_with_path(provider, success, fields, error, size_bytes, &format!("json/{s}.json"));
            }
        };
        
        let path = format!("json/{filename}.json");
        self.add_api_response_with_path(provider, success, fields, error, size_bytes, &path);
    }
    
    /// Add an API response entry with custom path
    fn add_api_response_with_path(
        &mut self,
        provider: ApiProvider,
        success: bool,
        fields: Vec<String>,
        error: Option<String>,
        size_bytes: Option<u64>,
        path: &str,
    ) {
        let provider_str = format!("{provider:?}").to_lowercase();

        if success {
            self.api_responses.insert(provider_str.clone(), path.to_string());
            self.api_success_count += 1;
        } else {
            self.api_failure_count += 1;
        }

        self.files.push(FileManifestEntry {
            path: path.to_string(),
            file_type: FileType::ApiResponse,
            provider: Some(provider),
            success,
            error,
            fields_populated: fields,
            size_bytes,
        });
    }

    /// Set report paths
    pub fn set_report_paths(&mut self, json_path: &str, html_path: &str) {
        self.reports.json = json_path.to_string();
        self.reports.html = html_path.to_string();

        self.files.push(FileManifestEntry {
            path: json_path.to_string(),
            file_type: FileType::Report,
            provider: None,
            success: true,
            error: None,
            fields_populated: vec!["comprehensive_token_data".to_string()],
            size_bytes: None,
        });

        self.files.push(FileManifestEntry {
            path: html_path.to_string(),
            file_type: FileType::Report,
            provider: None,
            success: true,
            error: None,
            fields_populated: vec!["human_readable_report".to_string()],
            size_bytes: None,
        });
    }

    /// Set TRI score and risk assessment
    pub fn set_tri_results(&mut self, tri_score: f32, rug_probability: f32, risk_level: &str) {
        self.tri_score = Some(tri_score);
        self.rug_probability = Some(rug_probability);
        self.risk_level = Some(risk_level.to_string());
    }

    /// Set scan directory
    pub fn set_scan_directory(&mut self, dir: &str) {
        self.scan_info.scan_directory = dir.to_string();
    }

    /// Set TRI score and risk assessment
    pub fn set_risk_assessment(&mut self, tri_score: f32, rug_probability: f32, risk_level: &str) {
        self.tri_score = Some(tri_score);
        self.rug_probability = Some(rug_probability);
        self.risk_level = Some(risk_level.to_string());
    }

    /// Set token metadata
    pub fn set_token_metadata(&mut self, name: Option<&str>, symbol: Option<&str>) {
        self.scan_info.token_name = name.map(String::from);
        self.scan_info.token_symbol = symbol.map(String::from);
    }

    /// Generate LLM analysis prompt based on available data
    pub fn generate_llm_prompt(&mut self) {
        let mut prompt_parts = Vec::new();

        prompt_parts.push("Analyze this token's security and risk profile based on the provided API data.\n".to_string());

        // Add sections based on which APIs succeeded
        if self.api_responses.contains_key("dexscreener") {
            prompt_parts.push("\n1. **Liquidity Analysis** (Dexscreener):\n".to_string());
            prompt_parts.push("   - Review liquidity USD and trends\n".to_string());
            prompt_parts.push("   - Check pool count and dominance ratio\n".to_string());
            prompt_parts.push("   - Analyze volume patterns\n".to_string());
        }

        if self.api_responses.contains_key("goplus") || self.api_responses.contains_key("etherscan") {
            prompt_parts.push("\n2. **Contract Security** (GoPlus/Etherscan):\n".to_string());
            prompt_parts.push("   - Check for honeypot indicators\n".to_string());
            prompt_parts.push("   - Review owner privileges\n".to_string());
            prompt_parts.push("   - Analyze source code risks\n".to_string());
        }

        if self.api_responses.contains_key("moralis") {
            prompt_parts.push("\n3. **Holder Distribution** (Moralis):\n".to_string());
            prompt_parts.push("   - Review top 10 holder concentration\n".to_string());
            prompt_parts.push("   - Check for labeled holders (CEX, DAO)\n".to_string());
            prompt_parts.push("   - Identify potential whale wallets\n".to_string());
        }

        if self.api_responses.contains_key("defillama") {
            prompt_parts.push("\n4. **Price Analysis** (DefiLlama):\n".to_string());
            prompt_parts.push("   - Review current price\n".to_string());
            prompt_parts.push("   - Check price confidence score\n".to_string());
        }

        if self.api_responses.contains_key("bitquery") {
            prompt_parts.push("\n5. **Trading Activity** (Bitquery):\n".to_string());
            prompt_parts.push("   - Analyze buy/sell pressure\n".to_string());
            prompt_parts.push("   - Review volume quality\n".to_string());
            prompt_parts.push("   - Check unique trader count\n".to_string());
        }

        prompt_parts.push("\n6. **Overall Risk Assessment**:\n".to_string());
        prompt_parts.push("   - Synthesize findings from all data sources\n".to_string());
        prompt_parts.push("   - Provide clear risk rating\n".to_string());
        prompt_parts.push("   - Highlight major red flags\n".to_string());
        prompt_parts.push("   - Note any positive indicators\n".to_string());

        self.llm_analysis_prompt = prompt_parts.join("");
    }

    /// Save manifest to file
    pub fn save_to_file(&self, directory: &PathBuf) -> std::io::Result<()> {
        let manifest_path = directory.join("scan_manifest.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(manifest_path, json)
    }
}

/// Directory structure manager for organized reports
pub struct ReportDirectoryManager {
    /// Base reports directory
    pub base_dir: PathBuf,
}

impl ReportDirectoryManager {
    /// Create a new directory manager
    #[must_use]
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Generate directory structure for a token scan
    /// Returns the full path to the scan directory
    pub fn create_scan_directory(
        &self,
        token_address: &str,
        token_name: Option<&str>,
        timestamp: &chrono::DateTime<chrono::Utc>,
    ) -> std::io::Result<PathBuf> {
        // Use token name if available, otherwise use address prefix
        let dir_name = if let Some(name) = token_name {
            format!("{}_{}", name, token_address[..10].to_string())
        } else {
            token_address[..10].to_string()
        };

        // Format timestamp as dd_mm_yyyy_hh_min
        let timestamp_str = timestamp.format("%d_%m_%Y_%H_%M").to_string();

        // Create full directory path
        let scan_dir = self.base_dir.join(dir_name).join(timestamp_str);

        // Create directories
        std::fs::create_dir_all(&scan_dir)?;
        std::fs::create_dir_all(scan_dir.join("json"))?;
        std::fs::create_dir_all(scan_dir.join("reports"))?;

        Ok(scan_dir)
    }

    /// Save API response to JSON file
    pub fn save_api_response(
        &self,
        scan_dir: &PathBuf,
        provider: &str,
        data: &str,
    ) -> std::io::Result<()> {
        let file_path = scan_dir.join("json").join(format!("{provider}.json"));
        std::fs::write(file_path, data)
    }

    /// Save API error to JSON file
    pub fn save_api_error(
        &self,
        scan_dir: &PathBuf,
        provider: &str,
        error: &str,
    ) -> std::io::Result<()> {
        let error_data = serde_json::json!({
            "error": error,
            "provider": provider,
            "timestamp": chrono::Utc::now().to_rfc3339()
        });
        let file_path = scan_dir.join("json").join(format!("{provider}.json"));
        let json = serde_json::to_string_pretty(&error_data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(file_path, json)
    }

    /// Move final reports to organized directory
    pub fn move_reports(
        &self,
        scan_dir: &PathBuf,
        json_report_path: &str,
        html_report_path: &str,
    ) -> std::io::Result<(String, String)> {
        // Read original files
        let json_content = std::fs::read(json_report_path)?;
        let html_content = std::fs::read(html_report_path)?;

        // Write to new locations
        let new_json_path = scan_dir.join("reports").join("token_report.json");
        let new_html_path = scan_dir.join("reports").join("token_report.html");

        std::fs::write(&new_json_path, json_content)?;
        std::fs::write(&new_html_path, html_content)?;

        Ok((
            new_json_path.to_string_lossy().to_string(),
            new_html_path.to_string_lossy().to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_manifest_creation() {
        let scan_info = ScanInfo::new(
            "0x1234".to_string(),
            Some("TestToken".to_string()),
            Some("TST".to_string()),
            "ethereum".to_string(),
            1000,
        );
        let manifest = ScanManifest::new(scan_info);

        assert_eq!(manifest.scan_info.token_address, "0x1234");
        assert_eq!(manifest.scan_info.chain, "ethereum");
        assert_eq!(manifest.scan_info.scan_duration_ms, 1000);
        assert!(manifest.api_responses.is_empty());
        assert_eq!(manifest.api_success_count, 0);
        assert_eq!(manifest.api_failure_count, 0);
    }

    #[test]
    fn test_add_api_response() {
        let scan_info = ScanInfo::new(
            "0x1234".to_string(),
            Some("TestToken".to_string()),
            Some("TST".to_string()),
            "ethereum".to_string(),
            1000,
        );
        let mut manifest = ScanManifest::new(scan_info);

        manifest.add_api_response(ApiProvider::Dexscreener, true, vec!["liquidity".to_string(), "price".to_string()], None, None);

        assert_eq!(manifest.api_success_count, 1);
        assert!(manifest.api_responses.contains_key("dexscreener"));
        assert_eq!(manifest.files.len(), 1);
        assert!(manifest.files[0].success);
    }

    #[test]
    fn test_generate_llm_prompt() {
        let scan_info = ScanInfo::new(
            "0x1234".to_string(),
            Some("TestToken".to_string()),
            Some("TST".to_string()),
            "ethereum".to_string(),
            1000,
        );
        let mut manifest = ScanManifest::new(scan_info);

        manifest.add_api_response(ApiProvider::Dexscreener, true, vec![], None, None);
        manifest.add_api_response(ApiProvider::Moralis, true, vec![], None, None);
        manifest.generate_llm_prompt();

        assert!(manifest.llm_analysis_prompt.contains("Liquidity Analysis"));
        assert!(manifest.llm_analysis_prompt.contains("Holder Distribution"));
    }
}
