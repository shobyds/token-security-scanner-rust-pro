#![allow(clippy::large_futures)]
//! `TokenGuard` CLI - Token Security Scanner

#![allow(clippy::doc_markdown)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::ignored_unit_patterns)]
#![allow(clippy::uninlined_format_args)]

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info, warn};

use rust_llm_agent::api::{ApiConfig, TokenScanner};
use rust_llm_agent::llm::ManifestAnalyzer;
use rust_llm_agent::report::{
    HtmlReportGenerator, JsonReportGenerator, ReportFormat, ReportGenerator, TokenSecurityReport,
};
use rust_llm_agent::scanner::{
    PipelineConfig, run_pipeline, save_organized_reports_with_paths,
};

#[derive(Parser, Debug)]
#[command(name = "tokenguard")]
#[command(about = "Token Security Scanner - Generate comprehensive token security reports", long_about = None)]
#[command(version = "1.0.0")]
struct Args {
    /// Blockchain network (ethereum, bsc, polygon, etc.)
    #[arg(long, default_value = "ethereum")]
    chain: String,

    /// Token contract address to scan (must start with 0x)
    #[arg(long)]
    token: String,

    /// Output format (json, html, or both)
    #[arg(long, default_value = "both")]
    format: String,

    /// Include market data in the report
    #[arg(long)]
    include_market_data: bool,

    /// Output directory for reports (default: /home/serverhp/qwenAg/reports)
    #[arg(long, default_value = "/home/serverhp/qwenAg/reports")]
    output_dir: String,

    /// Generate LLM analysis from organized reports
    #[arg(long)]
    analyze_with_llm: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file (if exists)
    // Try multiple locations: current dir, project root, home dir
    let home_env = format!("{}/.env", std::env::var("HOME").unwrap_or_default());
    let dotenv_paths = [
        ".env",
        "./.env",
        "../.env",
        "../../.env",
        home_env.as_str(),
    ];
    
    let mut loaded = false;
    for path_str in &dotenv_paths {
        if std::path::Path::new(path_str).exists() {
            match dotenvy::from_path(path_str) {
                Ok(_) => {
                    eprintln!("✅ Loaded .env file from: {}", path_str);
                    loaded = true;
                    break;
                }
                Err(e) => {
                    eprintln!("⚠️  Failed to load .env from {}: {}", path_str, e);
                }
            }
        }
    }
    
    if !loaded {
        eprintln!("⚠️  No .env file found in common locations, using environment variables");
        eprintln!("   Searched: {}", dotenv_paths.join(", "));
    }
    
    // Verify critical API keys are loaded
    if let Ok(key) = std::env::var("GROQ_API_KEY") {
        let key_preview = if key.len() > 8 {
            format!("{}...{}", &key[..4], &key[key.len() - 4..])
        } else {
            "***".to_string()
        };
        eprintln!("✅ GROQ_API_KEY loaded: {}", key_preview);
    } else {
        eprintln!("⚠️  GROQ_API_KEY not found in environment");
    }
    if let Ok(key) = std::env::var("MORALIS_API_KEY") {
        let key_preview = if key.len() > 8 {
            format!("{}...{}", &key[..4], &key[key.len() - 4..])
        } else {
            "***".to_string()
        };
        eprintln!("✅ MORALIS_API_KEY loaded: {}", key_preview);
    } else {
        eprintln!("⚠️  MORALIS_API_KEY not found in environment - holder data will be unavailable");
    }
    if let Ok(key) = std::env::var("ETHERSCAN_API_KEY") {
        let key_preview = if key.len() > 8 {
            format!("{}...{}", &key[..4], &key[key.len() - 4..])
        } else {
            "***".to_string()
        };
        eprintln!("✅ ETHERSCAN_API_KEY loaded: {}", key_preview);
    } else {
        eprintln!("⚠️  ETHERSCAN_API_KEY not found in environment");
    }
    eprintln!(); // Empty line for readability

    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_max_level(
            log_level
                .parse::<tracing::Level>()
                .unwrap_or(tracing::Level::INFO),
        )
        .init();

    info!("TokenGuard Security Scanner v1.0.0");
    info!("Scanning token: {} on chain: {}", args.token, args.chain);

    // Validate token address
    if !args.token.starts_with("0x") || args.token.len() != 42 {
        error!("Invalid token address: must start with 0x and be 42 characters long");
        std::process::exit(1);
    }

    // Parse format
    let format = ReportFormat::from_str(&args.format).context(format!(
        "Invalid format: {}. Use json, html, or both",
        args.format
    ))?;

    // Load API configuration
    let config = ApiConfig::from_env();

    // Create scanner
    let scanner = TokenScanner::new(&config).context("Failed to initialize token scanner")?;

    // Scan token
    info!("Starting token scan...");
    let scan_result = scanner
        .scan_token(&args.token, &args.chain)
        .await
        .context("Failed to scan token")?;

    info!(
        "Scan completed in {}ms ({} APIs succeeded)",
        scan_result.scan_time_ms,
        scan_result.success_count()
    );

    // Run the full pipeline (TRI scoring + optional LLM)
    info!("Running TRI scoring and LLM analysis pipeline...");
    let pipeline_config = PipelineConfig::from_env();
    
    let pipeline_result = run_pipeline(
        &args.token,
        &args.chain,
        pipeline_config.clone(),
        None, // No progress channel for CLI
    )
    .await
    .context("Pipeline execution failed")?;

    info!(
        "Pipeline completed in {}ms - TRI Score: {:.1}/100 [{}]",
        pipeline_result.total_time_ms,
        pipeline_result.tri_result.tri,
        pipeline_result.tri_result.tri_label.display()
    );

    // Create security report
    let report = TokenSecurityReport::new(scan_result.clone(), args.include_market_data);

    // Create output directory
    let output_dir = PathBuf::from(&args.output_dir);
    std::fs::create_dir_all(&output_dir).context(format!(
        "Failed to create output directory: {}",
        args.output_dir
    ))?;

    // Generate reports and capture paths
    let mut json_report_path: Option<String> = None;
    let mut html_report_path: Option<String> = None;

    match format {
        ReportFormat::Json => {
            let generator = JsonReportGenerator::new();
            let path = generator.generate_report(&report, &output_dir)?;
            json_report_path = Some(path.to_string_lossy().to_string());
            println!("JSON report generated: {}", path.display());
        }
        ReportFormat::Html => {
            let generator = HtmlReportGenerator::new();
            let path = generator.generate_report(&report, &output_dir)?;
            html_report_path = Some(path.to_string_lossy().to_string());
            println!("HTML report generated: {}", path.display());
        }
        ReportFormat::Both => {
            let json_gen = JsonReportGenerator::new();
            let html_gen = HtmlReportGenerator::new();

            let json_path = json_gen.generate_report(&report, &output_dir)?;
            let html_path = html_gen.generate_report(&report, &output_dir)?;

            json_report_path = Some(json_path.to_string_lossy().to_string());
            html_report_path = Some(html_path.to_string_lossy().to_string());

            println!("JSON report generated: {}", json_path.display());
            println!("HTML report generated: {}", html_path.display());
        }
    }

    // Save organized reports with final report paths
    if pipeline_config.organized_reports.enabled {
        info!("Saving organized reports with final JSON and HTML reports...");

        let json_path_ref = json_report_path.as_deref();
        let html_path_ref = html_report_path.as_deref();

        // Only save if we have at least one report path
        if json_path_ref.is_some() || html_path_ref.is_some() {
            match save_organized_reports_with_paths(
                &scan_result,
                &pipeline_result.tri_result,
                pipeline_result.rug_probability,
                &pipeline_config.organized_reports,
                json_path_ref.unwrap_or(""),
                html_path_ref.unwrap_or(""),
            )
            .await
            {
                Ok(manifest_path) => {
                    info!("Organized reports saved to: {:?}", manifest_path);
                    
                    // Generate LLM analysis from manifest if requested
                    if args.analyze_with_llm {
                        info!("Generating LLM analysis from manifest...");
                        match ManifestAnalyzer::new() {
                            Ok(analyzer) => {
                                match analyzer.analyze_manifest(&manifest_path).await {
                                    Ok(result) => {
                                        info!("LLM analysis saved to: {:?}", result.output_path);
                                        println!("\n✅ LLM analysis report generated: {}", result.output_path.display());
                                    }
                                    Err(e) => {
                                        error!("Failed to generate LLM analysis: {}", e);
                                        warn!("LLM analysis generation failed, but scan completed successfully");
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to initialize ManifestAnalyzer: {}", e);
                                warn!("LLM analysis skipped due to initialization error");
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to save organized reports: {}", e);
                }
            }
        }
    }

    // Print summary
    println!("\n=== Token Security Summary ===");
    println!("Token: {}", report.token_data.token_address);
    println!("Chain: {}", report.token_data.chain.to_uppercase());
    println!("Risk Score: {}/100", report.risk_assessment.overall_score);
    println!("Risk Level: {}", report.risk_assessment.risk_level);
    println!("Recommendation: {}", report.risk_assessment.recommendation);

    // Print TRI scoring summary
    println!("\n=== TRI (Token Risk Index) Analysis ===");
    println!(
        "TRI Score: {:.1}/100 [{}]",
        pipeline_result.tri_result.tri,
        pipeline_result.tri_result.tri_label.display()
    );
    println!(
        "Rug Probability: {:.1}%",
        pipeline_result.rug_probability * 100.0
    );
    println!("Red Flags: {}", pipeline_result.tri_result.red_flag_count());
    println!("Green Flags: {}", pipeline_result.tri_result.green_flag_count());

    if args.verbose {
        println!("\n--- Domain Breakdown ---");
        println!("  Contract Risk:  {:.1}", pipeline_result.tri_result.contract_risk);
        println!("  Liquidity Risk: {:.1}", pipeline_result.tri_result.lp_score);
        println!("  Ownership Risk: {:.1}", pipeline_result.tri_result.ownership_risk);
        println!("  Tax Risk:       {:.1}", pipeline_result.tri_result.tax_risk);
        println!("  Honeypot Risk:  {:.1}", pipeline_result.tri_result.honeypot_risk);
        println!("  Volume Risk:    {:.1}", pipeline_result.tri_result.volume_risk);
        println!("  Dev Behavior:   {:.1}", pipeline_result.tri_result.dev_behavior);
        println!("  Age Risk:       {:.1}", pipeline_result.tri_result.age_risk);
    }

    // Print LLM analysis if available
    if let Some(ref llm) = pipeline_result.llm_analysis {
        println!("\n=== Groq LLM Analysis ===");
        println!(
            "Recommendation: {} {}",
            llm.recommendation.emoji(),
            llm.recommendation.display()
        );
        println!("Confidence: {:.0}%", llm.confidence_level * 100.0);
        println!("Explanation: {}", llm.explanation);

        if !llm.red_flags.is_empty() {
            println!("LLM Red Flags:");
            for flag in &llm.red_flags {
                println!("  • {flag}");
            }
        }
    } else {
        println!("\n=== Groq LLM Analysis ===");
        println!(
            "LLM analysis not triggered (rug probability {:.1}% < threshold {:.1}%)",
            pipeline_result.rug_probability * 100.0,
            pipeline_config.phi3_config.rug_prob_threshold * 100.0
        );
    }

    println!("\n=== Pipeline Statistics ===");
    println!("Total Pipeline Time: {}ms", pipeline_result.total_time_ms);
    println!("Alert Sent: {}", if pipeline_result.alert_sent { "Yes" } else { "No" });

    Ok(())
}
