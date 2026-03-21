//! LLM Client Module
//!
//! This module provides integration with various LLM providers
//! for token risk analysis and natural language processing.

pub mod phi3_client;
pub mod manifest_analyzer;

// Re-export Phi-3 client types
pub use phi3_client::{
    Phi3Client,
    Phi3Config,
    LlmAnalysis,
    LlmRecommendation,
    DEFAULT_GROQ_URL,
    DEFAULT_GROQ_MODEL,
};

// Re-export manifest analyzer types
pub use manifest_analyzer::{
    ManifestAnalyzer,
    AnalysisResult,
};
