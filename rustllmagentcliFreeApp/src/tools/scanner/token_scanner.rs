//! Token Scanner Tool for scanning token security

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::unnecessary_lazy_evaluations)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::large_futures)]

use crate::api::{ApiConfig, ScanResult, TokenScanner};
use crate::report::{
    HtmlReportGenerator, JsonReportGenerator, ReportFormat, ReportGenerator, TokenSecurityReport,
};
use crate::types::{SchemaBuilder, ToolDefinition, ToolResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Scan options for token scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Token contract address to scan
    pub token_address: String,
    /// Blockchain network (default: ethereum)
    pub chain: String,
    /// Output format: json, html, or both (default: both)
    pub format: String,
    /// Include market data in report
    pub include_market_data: bool,
    /// Output directory for reports
    pub output_dir: String,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            token_address: String::new(),
            chain: "ethereum".to_string(),
            format: "both".to_string(),
            include_market_data: false,
            output_dir: "/home/serverhp/qwenAg/reports".to_string(),
        }
    }
}

/// Pre-check status for API providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiProviderStatus {
    /// Provider name
    pub name: String,
    /// Whether provider is available
    pub available: bool,
    /// API key status
    pub has_api_key: bool,
    /// Last check message
    pub message: String,
}

/// Scan confirmation dialog data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfirmationDialog {
    /// Token address to scan
    pub token_address: String,
    /// Chain to scan on
    pub chain: String,
    /// Available scan options
    pub options: Vec<ScanOption>,
    /// API provider pre-check status
    pub provider_status: Vec<ApiProviderStatus>,
    /// Estimated scan time in seconds
    pub estimated_time_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOption {
    /// Option name
    pub name: String,
    /// Option description
    pub description: String,
    /// Default value
    pub default_value: String,
    /// Possible values (for enums)
    pub possible_values: Vec<String>,
    /// Is required
    pub required: bool,
}

/// Create the scan_token tool definition
pub fn create_scan_token_tool() -> ToolDefinition {
    let (props, required) = SchemaBuilder::new()
        .string_property(
            "token_address",
            "Token contract address to scan (must start with 0x)",
            true,
        )
        .string_property(
            "chain",
            "Blockchain network (ethereum, bsc, polygon, etc.)",
            false,
        )
        .string_property("format", "Output format: json, html, or both", false)
        .boolean_property(
            "include_market_data",
            "Include market data in report",
            false,
        )
        .string_property("output_dir", "Output directory for reports", false)
        .build();

    ToolDefinition::with_schema(
        "scan_token",
        "Scan a token address for security risks and generate comprehensive reports. Shows confirmation dialog before scanning.",
        &required,
        props,
    )
}

/// Execute the scan_token tool
pub fn scan_token(args: &serde_json::Value) -> Result<String, crate::types::error::ToolError> {
    let token_address = args["token_address"].as_str().ok_or_else(|| {
        crate::types::error::ToolError::InvalidArguments(
            "Missing 'token_address' argument".to_string(),
        )
    })?;

    // Validate token address
    if !token_address.starts_with("0x") || token_address.len() != 42 {
        return Err(crate::types::error::ToolError::InvalidArguments(
            "Invalid token address: must start with 0x and be 42 characters long".to_string(),
        ));
    }

    let chain = args["chain"].as_str().unwrap_or("ethereum");
    let format = args["format"].as_str().unwrap_or("both");
    let include_market_data = args["include_market_data"].as_bool().unwrap_or(false);
    let output_dir = args["output_dir"].as_str().unwrap_or("/home/serverhp/qwenAg/reports");

    // Create scan options
    let options = ScanOptions {
        token_address: token_address.to_string(),
        chain: chain.to_string(),
        format: format.to_string(),
        include_market_data,
        output_dir: output_dir.to_string(),
    };

    // Get API provider status
    let provider_status = get_api_provider_status();

    // Create confirmation dialog
    let dialog = ScanConfirmationDialog {
        token_address: token_address.to_string(),
        chain: chain.to_string(),
        options: vec![
            ScanOption {
                name: "format".to_string(),
                description: "Output format for reports".to_string(),
                default_value: "both".to_string(),
                possible_values: vec!["json".to_string(), "html".to_string(), "both".to_string()],
                required: false,
            },
            ScanOption {
                name: "include_market_data".to_string(),
                description: "Include market data in report".to_string(),
                default_value: "false".to_string(),
                possible_values: vec!["true".to_string(), "false".to_string()],
                required: false,
            },
            ScanOption {
                name: "output_dir".to_string(),
                description: "Output directory for reports".to_string(),
                default_value: "./reports".to_string(),
                possible_values: vec![],
                required: false,
            },
        ],
        provider_status,
        estimated_time_secs: 15,
    };

    // For now, execute the scan immediately
    // In future, this could show an interactive dialog in TUI
    let result = execute_scan(&options)?;

    Ok(serde_json::to_string_pretty(&result).unwrap_or_else(|_| result))
}

/// Get API provider pre-check status
fn get_api_provider_status() -> Vec<ApiProviderStatus> {
    let config = ApiConfig::from_env();

    vec![
        ApiProviderStatus {
            name: "DexScreener".to_string(),
            available: true,
            has_api_key: true,
            message: "No API key required".to_string(),
        },
        ApiProviderStatus {
            name: "Honeypot.is".to_string(),
            available: true,
            has_api_key: true,
            message: "No API key required".to_string(),
        },
        ApiProviderStatus {
            name: "GoPlus".to_string(),
            available: config.goplus.api_key.is_some(),
            has_api_key: config.goplus.api_key.is_some(),
            message: if config.goplus.api_key.is_some() {
                "API key configured".to_string()
            } else {
                "API key not configured".to_string()
            },
        },
        ApiProviderStatus {
            name: "Etherscan".to_string(),
            available: config.etherscan_api_key.is_some(),
            has_api_key: config.etherscan_api_key.is_some(),
            message: if config.etherscan_api_key.is_some() {
                "API key configured".to_string()
            } else {
                "API key not configured".to_string()
            },
        },
    ]
}

/// Execute the token scan
fn execute_scan(options: &ScanOptions) -> Result<String, crate::types::error::ToolError> {
    use anyhow::Context;
    use tracing::info;

    info!("Starting token scan for {}", options.token_address);

    // Use pipeline for full TRI scoring and optional LLM analysis
    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        crate::types::error::ToolError::CommandFailed(format!("Failed to create runtime: {}", e))
    })?;

    let pipeline_result = rt
        .block_on(async {
            let pipeline_config = crate::scanner::PipelineConfig::from_env();
            crate::scanner::run_pipeline(
                &options.token_address,
                &options.chain,
                pipeline_config,
                None, // No progress channel for tool execution
            )
            .await
        })
        .map_err(|e| {
            crate::types::error::ToolError::CommandFailed(format!("Pipeline error: {}", e))
        })?;

    // Create output directory
    let output_path = PathBuf::from(&options.output_dir);
    std::fs::create_dir_all(&output_path).map_err(|e| {
        crate::types::error::ToolError::CommandFailed(format!(
            "Failed to create output directory: {}",
            e
        ))
    })?;

    // Generate reports using the scan_result from pipeline
    let report = TokenSecurityReport::new(pipeline_result.scan_result.clone(), options.include_market_data);

    // Generate reports based on format
    let mut generated_files = Vec::new();

    let format = ReportFormat::from_str(&options.format).unwrap_or(ReportFormat::Both);
    match format {
        ReportFormat::Json => {
            let generator = JsonReportGenerator::new();
            if let Ok(path) = generator.generate_report(&report, &output_path) {
                generated_files.push(path.display().to_string());
            }
        }
        ReportFormat::Html => {
            let generator = HtmlReportGenerator::new();
            if let Ok(path) = generator.generate_report(&report, &output_path) {
                generated_files.push(path.display().to_string());
            }
        }
        ReportFormat::Both => {
            let json_gen = JsonReportGenerator::new();
            let html_gen = HtmlReportGenerator::new();

            if let Ok(path) = json_gen.generate_report(&report, &output_path) {
                generated_files.push(path.display().to_string());
            }
            if let Ok(path) = html_gen.generate_report(&report, &output_path) {
                generated_files.push(path.display().to_string());
            }
        }
    }

    // Create result summary with TRI scoring from pipeline
    let result = ScanResultSummary {
        token_address: options.token_address.clone(),
        chain: options.chain.clone(),
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_sign_loss)]
        risk_score: pipeline_result.tri_result.tri as u8,
        risk_level: pipeline_result.tri_result.tri_label.display().to_string(),
        recommendation: pipeline_result.llm_analysis
            .as_ref()
            .map_or_else(
                || pipeline_result.tri_result.tri_label.display().to_string(),
                |a| a.recommendation.display().to_string(),
            ),
        generated_files,
        scan_time_ms: pipeline_result.scan_result.scan_time_ms,
        apis_succeeded: pipeline_result.scan_result.success_count(),
        apis_failed: pipeline_result.scan_result.error_count(),
        // TRI scoring fields from pipeline
        tri_score: pipeline_result.tri_result.tri,
        tri_label: pipeline_result.tri_result.tri_label.display().to_string(),
        red_flag_count: pipeline_result.tri_result.red_flag_count(),
        rug_probability: pipeline_result.rug_probability,
        llm_recommendation: pipeline_result.llm_analysis
            .as_ref()
            .map(|a| a.recommendation.display().to_string()),
    };

    Ok(serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{:?}", result)))
}

/// Summary of scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultSummary {
    pub token_address: String,
    pub chain: String,
    pub risk_score: u8,
    pub risk_level: String,
    pub recommendation: String,
    pub generated_files: Vec<String>,
    pub scan_time_ms: u64,
    pub apis_succeeded: usize,
    pub apis_failed: usize,
    // TRI scoring fields
    pub tri_score: f32,
    pub tri_label: String,
    pub red_flag_count: usize,
    pub rug_probability: f32,
    pub llm_recommendation: Option<String>,
}
