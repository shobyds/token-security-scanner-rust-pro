//! Token Scanner Module for Risk Analysis
//!
//! This module provides comprehensive token risk analysis including:
//! - TRI (Token Risk Index) scoring engine
//! - Feature extraction from API responses
//! - ML-based pre-scoring for LLM filtering
//! - Telegram alerting for high-risk tokens
//! - Pipeline orchestration for full analysis flow
//!
//! # Modules
//! - `tri_engine`: Core TRI scoring logic across 8 risk domains
//! - `feature_extract`: Transform API responses into structured metrics
//! - `ml_score`: Fast deterministic pre-filter before LLM calls
//! - `alerting`: Telegram notifications with rate limiting
//! - `pipeline`: Async orchestration of scan → features → ML → TRI → LLM → alert

#![allow(clippy::module_name_repetitions)]

pub mod alerting;
pub mod feature_extract;
pub mod ml_score;
pub mod pipeline;
pub mod source_analyzer;  // Phase 1 Task 1.4
pub mod tri_engine;

// Re-export commonly used types
pub use alerting::{
    SentAlert, TelegramAlertConfig, TelegramAlertManager, format_simple_alert,
    send_telegram_alert,
};
pub use feature_extract::{TokenMetrics, extract_features, extract_features_from_parts};
pub use ml_score::{
    compute_risk_breakdown, get_risk_emoji, get_risk_level, compute_rug_probability,
    should_call_llm,
};
pub use pipeline::{
    PipelineConfig, PipelineResult, ScanProgress, run_pipeline, run_pipeline_with_progress,
    save_organized_reports_with_paths, metrics_to_tri_input, OrganizedReportConfig,
};
pub use tri_engine::{GreenFlag, RedFlag, TriConfig, TriEngine, TriInput, TriLabel, TriResult};
