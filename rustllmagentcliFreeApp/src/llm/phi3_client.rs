//! Phi-3 Mini LLM Client for Groq API
//!
//! This module provides integration with the Llama-3.1-8B-Instruct model
//! via Groq's hosted API for token risk analysis.
//!
//! # Features
//! - Async HTTP requests to Groq API (OpenAI-compatible format)
//! - Automatic retry with exponential backoff
//! - JSON response parsing with fallback handling
//! - Bearer token authentication

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Default Groq API URL for chat completions (OpenAI-compatible)
/// Note: Model is specified in the request payload, not the URL
pub const DEFAULT_GROQ_URL: &str = "https://api.groq.com/openai/v1";

/// Default model for Groq API (Llama-3.1-8B-Instant)
pub const DEFAULT_GROQ_MODEL: &str = "llama-3.1-8b-instant";

/// Phi-3 client configuration
#[derive(Debug, Clone)]
pub struct Phi3Config {
    /// Groq API URL for chat completions
    pub base_url: String,
    /// Model to use for inference (specified in request payload)
    pub model: String,
    /// Groq API key for authentication
    pub api_key: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Number of retries for failed requests
    pub retry_count: u32,
    /// Rug probability threshold to trigger LLM analysis
    pub rug_prob_threshold: f32,
}

impl Default for Phi3Config {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_GROQ_URL.to_string(),
            model: DEFAULT_GROQ_MODEL.to_string(),
            api_key: None,
            timeout_secs: 30,
            retry_count: 3,
            rug_prob_threshold: 0.35,
        }
    }
}

impl Phi3Config {
    /// Create config from environment variables
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            base_url: std::env::var("GROQ_URL")
                .unwrap_or_else(|_| DEFAULT_GROQ_URL.to_string()),
            model: std::env::var("GROQ_MODEL")
                .unwrap_or_else(|_| DEFAULT_GROQ_MODEL.to_string()),
            api_key: std::env::var("GROQ_API_KEY").ok(),
            timeout_secs: std::env::var("GROQ_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30),
            retry_count: std::env::var("GROQ_RETRY_COUNT")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(3),
            rug_prob_threshold: std::env::var("GROQ_RUG_THRESHOLD")
                .ok()
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(0.35),
        }
    }
}

/// LLM analysis result from Phi-3 model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmAnalysis {
    /// Human-readable explanation of the risk assessment
    pub explanation: String,
    /// List of red flags identified
    pub red_flags: Vec<String>,
    /// Recommendation: "AVOID", "CAUTION", or "SAFE"
    pub recommendation: LlmRecommendation,
    /// Confidence level in the analysis (0.0-1.0)
    pub confidence_level: f32,
}

/// Risk recommendation from the LLM
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LlmRecommendation {
    /// Token should be avoided due to high risk
    Avoid,
    /// Token requires caution - moderate risk
    Caution,
    /// Token appears safe
    Safe,
}

impl LlmRecommendation {
    /// Get display string for the recommendation
    #[must_use]
    pub fn display(&self) -> &'static str {
        match self {
            LlmRecommendation::Avoid => "AVOID",
            LlmRecommendation::Caution => "CAUTION",
            LlmRecommendation::Safe => "SAFE",
        }
    }

    /// Get emoji for the recommendation
    #[must_use]
    pub fn emoji(&self) -> &'static str {
        match self {
            LlmRecommendation::Avoid => "🚨",
            LlmRecommendation::Caution => "⚠️",
            LlmRecommendation::Safe => "✅",
        }
    }
}

impl std::fmt::Display for LlmRecommendation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

/// Health status from the HF Space
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Status indicator
    pub status: String,
    /// Model name
    pub model: String,
    /// Whether GPU is available
    #[serde(default)]
    pub gpu_available: bool,
}

/// Phi-3 Client for Groq API
pub struct Phi3Client {
    http_client: Client,
    base_url: String,
    model: String,
    api_key: Option<String>,
    retry_count: u32,
}

impl Phi3Client {
    /// Create a new Phi-3 client with the given configuration
    pub fn new(config: &Phi3Config) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent("rust-token-guard/0.1.0")
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            http_client: client,
            base_url: config.base_url.clone(),
            model: config.model.clone(),
            api_key: config.api_key.clone(),
            retry_count: config.retry_count,
        })
    }

    /// Create client from environment variables
    #[must_use]
    pub fn from_env() -> Self {
        let base_url = std::env::var("GROQ_URL")
            .unwrap_or_else(|_| DEFAULT_GROQ_URL.to_string());
        let model = std::env::var("GROQ_MODEL")
            .unwrap_or_else(|_| DEFAULT_GROQ_MODEL.to_string());
        let api_key = std::env::var("GROQ_API_KEY").ok();
        let timeout_secs = std::env::var("PHI3_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);
        let retry_count = std::env::var("PHI3_RETRY_COUNT")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3);

        Self {
            http_client: Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .user_agent("rust-token-guard/0.1.0")
                .build()
                .unwrap_or_else(|_| Client::new()),
            base_url,
            model,
            api_key,
            retry_count,
        }
    }

    /// Analyze token metrics OR chat (dual purpose)
    pub async fn analyze_token(
        &self,
        input: &serde_json::Value,
        rug_prob: f32,
    ) -> Result<LlmAnalysis> {
        // Check if this is a chat request (has "messages" field)
        if let Some(messages) = input.get("messages") {
            // This is a chat request - use Groq chat endpoint directly
            debug!("Chat request detected with {} messages", messages.as_array().map_or(0, std::vec::Vec::len));
            return self.chat_with_groq(messages).await;
        }

        // Otherwise, it's a token analysis request - use the original logic
        info!(
            "Analyzing token with Groq Llama-3.1 (rug_prob: {:.2})",
            rug_prob * 100.0
        );

        // Build prompt for token risk analysis
        let prompt = format!(
            r#"Analyze this token's risk metrics and provide a structured JSON response:

Metrics: {}
Rug Probability: {:.1}%

Provide your analysis in this exact JSON format:
{{
    "explanation": "Your risk assessment explanation",
    "red_flags": ["list", "of", "red", "flags"],
    "recommendation": "AVOID" or "CAUTION" or "SAFE",
    "confidence_level": 0.0-1.0
}}"#,
            input,
            rug_prob * 100.0
        );

        // Build OpenAI-compatible payload
        let payload = serde_json::json!({
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 500
        });

        debug!("Sending payload to Groq API: {}", payload);

        // Make request with retry logic
        let response = self
            .make_chat_request_with_retry(&payload)
            .await
            .context("Failed to get analysis from Groq Llama-3.1")?;

        // Parse OpenAI-compatible response
        Self::parse_openai_response(&response)
    }

    /// Chat with Groq API (general purpose)
    async fn chat_with_groq(&self, messages: &serde_json::Value) -> Result<LlmAnalysis> {
        info!("Chatting with Groq {}", self.model);
        debug!("Chat messages: {}", messages);
        debug!("API key configured: {}", self.api_key.is_some());
        debug!("API key preview: {:?}", self.api_key.as_ref().map(|k| {
            let len = k.len();
            format!("{}...{}", &k[..4.min(len)], &k[len.saturating_sub(4)..])
        }));
        debug!("Base URL: {}", self.base_url);

        // Build OpenAI-compatible payload
        let payload = serde_json::json!({
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 500
        });

        debug!("Sending chat payload to Groq: {}", payload);

        // Make request with retry logic
        let response = self
            .make_chat_request_with_retry(&payload)
            .await
            .context("Failed to chat with Groq")?;

        // Parse Groq chat response (plain text)
        let chat_text = Self::parse_chat_response(&response)?;
        
        // Return as LlmAnalysis (reuse the structure for compatibility)
        Ok(LlmAnalysis {
            explanation: chat_text,
            red_flags: vec![],
            recommendation: LlmRecommendation::Safe,
            confidence_level: 0.9,
        })
    }

    /// Perform health check on the Groq API
    pub async fn health_check(&self) -> Result<()> {
        debug!("Performing health check on Groq API");

        // Simple ping to verify the API endpoint is accessible
        // We use a minimal POST request since the endpoint requires POST
        let payload = serde_json::json!({
            "model": self.model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1
        });

        let mut request = self
            .http_client
            .post(&self.base_url)
            .json(&payload);

        if let Some(ref api_key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {api_key}"));
        }

        let response = request
            .send()
            .await
            .context("Failed to send health check request")?;

        let status = response.status();

        // 200 OK or 429 Too Many Requests both mean the API is accessible
        if status.is_success() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            info!("Groq API health check passed (status: {})", status);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Groq API health check failed with status: {status}"))
        }
    }

    /// Make chat request with retry logic
    async fn make_chat_request_with_retry(
        &self,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let mut last_error: Option<anyhow::Error> = None;

        for attempt in 1..=self.retry_count + 1 {
            debug!("Attempt {} of {}", attempt, self.retry_count + 1);

            match self.make_chat_request(payload).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!(
                        "Attempt {} failed: {}. Retrying...",
                        attempt,
                        e
                    );
                    last_error = Some(e);

                    if attempt <= self.retry_count {
                        // Exponential backoff: 1s, 2s, 4s...
                        let delay = Duration::from_secs(2u64.pow(attempt - 1));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Unknown error")))
    }

    /// Make a single chat request to the Groq API
    async fn make_chat_request(
        &self,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // Append /chat/completions endpoint to base URL, handling trailing slashes
        let base_url = self.base_url.trim_end_matches('/');
        let endpoint = format!("{base_url}/chat/completions");
        
        let mut request = self
            .http_client
            .post(&endpoint)
            .json(payload);

        // Add Bearer token authentication (required for Groq API)
        if let Some(ref api_key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {api_key}"));
        } else {
            warn!("No Groq API key provided - request may fail if authentication is required");
        }

        let response = request
            .send()
            .await
            .context("Failed to send request to Groq API")?;

        let status = response.status();
        debug!("Groq API response status: {}", status);

        if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
            return Err(anyhow::anyhow!(
                "Groq API is unavailable (503) - service may be down"
            ));
        }

        if status == reqwest::StatusCode::UNAUTHORIZED {
            let error_body = response.text().await.unwrap_or_default();
            error!("Groq API 401 Unauthorized - Response: {}", error_body);
            return Err(anyhow::anyhow!(
                "Groq API authentication failed (401) - check your GROQ_API_KEY"
            ));
        }

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            error!("Groq API error status {}: {}", status, error_text);
            return Err(anyhow::anyhow!(
                "Groq API returned error status {status}: {error_text}"
            ));
        }

        let response_text = response
            .text()
            .await
            .context("Failed to read response text")?;

        debug!("Groq API response: {}", response_text);

        let response_json: serde_json::Value =
            serde_json::from_str(&response_text).context("Failed to parse response JSON")?;

        Ok(response_json)
    }

    /// Parse OpenAI-compatible API response into `LlmAnalysis`
    fn parse_openai_response(response: &serde_json::Value) -> Result<LlmAnalysis> {
        // Extract content from OpenAI response format:
        // { "choices": [{ "message": { "content": "..." } }] }
        let content = response
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid OpenAI response format"))?;

        debug!("LLM response content: {}", content);

        // Try to parse the analysis from the content
        match Self::parse_analysis_json(content) {
            Ok(analysis) => Ok(analysis),
            Err(e) => {
                warn!("Failed to parse LLM analysis: {}", e);
                // Return fallback analysis
                Ok(LlmAnalysis {
                    explanation: "LLM output parsing failed. Using fallback analysis.".to_string(),
                    red_flags: vec!["Unable to parse LLM response".to_string()],
                    recommendation: LlmRecommendation::Caution,
                    confidence_level: 0.3,
                })
            }
        }
    }

    /// Parse OpenAI-compatible chat response (plain text)
    fn parse_chat_response(response: &serde_json::Value) -> Result<String> {
        // Extract content from OpenAI response format
        let content = response
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid OpenAI chat response format"))?;

        debug!("Chat response: {}", content);
        Ok(content.trim().to_string())
    }

    /// Parse analysis JSON with robust error handling
    fn parse_analysis_json(json_str: &str) -> Result<LlmAnalysis> {
        let cleaned = Self::clean_json_string(json_str);

        // Try direct parsing first
        if let Ok(analysis) = serde_json::from_str::<LlmAnalysis>(&cleaned) {
            return Ok(analysis);
        }

        // Try to extract JSON object from the string
        if let Some(json_match) = Self::extract_json_object(&cleaned)
            && let Ok(analysis) = serde_json::from_str::<LlmAnalysis>(&json_match)
        {
            return Ok(analysis);
        }

        // If all parsing fails, return error
        Err(anyhow::anyhow!("Failed to parse LLM analysis JSON"))
    }

    /// Clean JSON string by removing markdown fences and whitespace
    fn clean_json_string(s: &str) -> String {
        let mut cleaned = s.trim().to_string();

        // Remove markdown code fences
        if cleaned.starts_with("```json") {
            cleaned = cleaned[7..].to_string();
        }
        if cleaned.starts_with("```") {
            cleaned = cleaned[3..].to_string();
        }
        if cleaned.ends_with("```") {
            cleaned = cleaned[..cleaned.len() - 3].to_string();
        }

        cleaned.trim().to_string()
    }

    /// Extract JSON object from string using simple bracket matching
    fn extract_json_object(s: &str) -> Option<String> {
        let start = s.find('{')?;
        let mut depth = 0;
        let mut in_string = false;
        let mut escape = false;

        for (i, c) in s[start..].char_indices() {
            if escape {
                escape = false;
                continue;
            }

            match c {
                '\\' if in_string => escape = true,
                '"' => in_string = !in_string,
                '{' if !in_string => depth += 1,
                '}' if !in_string => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(s[start..=start + i].to_string());
                    }
                }
                _ => {}
            }
        }

        None
    }

    /// Batch analyze multiple tokens (max 3)
    pub async fn batch_analyze(
        &self,
        tokens: &[(&serde_json::Value, f32)],
    ) -> Result<Vec<LlmAnalysis>> {
        if tokens.is_empty() {
            return Ok(Vec::new());
        }

        if tokens.len() > 3 {
            warn!("Batch analyze limited to 3 tokens, got {}", tokens.len());
        }

        let mut results = Vec::new();
        for (metrics, rug_prob) in tokens.iter().take(3) {
            match self.analyze_token(metrics, *rug_prob).await {
                Ok(analysis) => results.push(analysis),
                Err(e) => {
                    error!("Failed to analyze token in batch: {}", e);
                    results.push(LlmAnalysis {
                        explanation: format!("Analysis failed: {e}"),
                        red_flags: vec!["Analysis error".to_string()],
                        recommendation: LlmRecommendation::Caution,
                        confidence_level: 0.2,
                    });
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_phi3_config_default() {
        let config = Phi3Config::default();
        assert_eq!(config.base_url, DEFAULT_GROQ_URL);
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.retry_count, 3);
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(config.rug_prob_threshold, 0.35);
        }
    }

    #[test]
    fn test_llm_recommendation_display() {
        assert_eq!(LlmRecommendation::Avoid.display(), "AVOID");
        assert_eq!(LlmRecommendation::Caution.display(), "CAUTION");
        assert_eq!(LlmRecommendation::Safe.display(), "SAFE");
    }

    #[test]
    fn test_llm_recommendation_emoji() {
        assert_eq!(LlmRecommendation::Avoid.emoji(), "🚨");
        assert_eq!(LlmRecommendation::Caution.emoji(), "⚠️");
        assert_eq!(LlmRecommendation::Safe.emoji(), "✅");
    }

    #[test]
    fn test_clean_json_string() {
        // Test with markdown fences
        let input = "```json\n{\"test\": true}\n```";
        let cleaned = Phi3Client::clean_json_string(input);
        assert_eq!(cleaned, "{\"test\": true}");

        // Test with just braces
        let input = "{\"test\": true}";
        let cleaned = Phi3Client::clean_json_string(input);
        assert_eq!(cleaned, "{\"test\": true}");

        // Test with whitespace
        let input = "  \n  {\"test\": true}  \n  ";
        let cleaned = Phi3Client::clean_json_string(input);
        assert_eq!(cleaned, "{\"test\": true}");
    }

    #[test]
    fn test_extract_json_object() {
        // Test simple object
        let input = "{\"key\": \"value\"}";
        let extracted = Phi3Client::extract_json_object(input);
        assert_eq!(extracted, Some("{\"key\": \"value\"}".to_string()));

        // Test nested object
        let input = "{\"outer\": {\"inner\": true}}";
        let extracted = Phi3Client::extract_json_object(input);
        assert_eq!(
            extracted,
            Some("{\"outer\": {\"inner\": true}}".to_string())
        );

        // Test with surrounding text
        let input = "Here is the result: {\"key\": \"value\"} end";
        let extracted = Phi3Client::extract_json_object(input);
        assert_eq!(extracted, Some("{\"key\": \"value\"}".to_string()));

        // Test with no object
        let input = "no json here";
        let extracted = Phi3Client::extract_json_object(input);
        assert_eq!(extracted, None);
    }

    #[test]
    fn test_llm_analysis_serialization() {
        let analysis = LlmAnalysis {
            explanation: "Test explanation".to_string(),
            red_flags: vec!["Flag 1".to_string(), "Flag 2".to_string()],
            recommendation: LlmRecommendation::Avoid,
            confidence_level: 0.85,
        };

        let json = serde_json::to_string(&analysis).unwrap();
        let parsed: LlmAnalysis = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.explanation, "Test explanation");
        assert_eq!(parsed.red_flags.len(), 2);
        assert_eq!(parsed.recommendation, LlmRecommendation::Avoid);
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(parsed.confidence_level, 0.85);
        }
    }

    #[test]
    fn test_parse_analysis_json_valid() {
        let client = Phi3Client::from_env();

        let valid_json = r#"{
            "explanation": "This token is risky",
            "red_flags": ["High tax", "Low liquidity"],
            "recommendation": "AVOID",
            "confidence_level": 0.9
        }"#;

        let analysis = Phi3Client::parse_analysis_json(valid_json).unwrap();
        assert_eq!(analysis.explanation, "This token is risky");
        assert_eq!(analysis.red_flags.len(), 2);
        assert_eq!(analysis.recommendation, LlmRecommendation::Avoid);
    }

    #[test]
    fn test_parse_analysis_json_with_markdown() {
        let markdown_json = r#"```json
{
    "explanation": "Markdown wrapped JSON",
    "red_flags": ["Flag 1"],
    "recommendation": "CAUTION",
    "confidence_level": 0.5
}
```"#;

        let analysis = Phi3Client::parse_analysis_json(markdown_json).unwrap();
        assert_eq!(analysis.explanation, "Markdown wrapped JSON");
        assert_eq!(analysis.recommendation, LlmRecommendation::Caution);
    }

    #[test]
    fn test_parse_analysis_json_invalid() {
        let invalid = "not valid json at all";
        let result = Phi3Client::parse_analysis_json(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_health_status_serialization() {
        let status = HealthStatus {
            status: "ok".to_string(),
            model: "llama-3.1-8b-instant".to_string(),
            gpu_available: true,
        };

        let json = serde_json::to_string(&status).unwrap();
        let parsed: HealthStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.status, "ok");
        assert!(parsed.gpu_available);
    }

    #[test]
    fn test_openai_response_format() {
        // Test the expected OpenAI-compatible response format
        let openai_response = json!({
            "id": "chatcmpl-1",
            "model": "llama-3.1-8b-instant",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "{\"explanation\": \"Test\", \"red_flags\": [], \"recommendation\": \"SAFE\", \"confidence_level\": 0.8}"
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 20,
                "total_tokens": 30
            }
        });

        let analysis = Phi3Client::parse_openai_response(&openai_response).unwrap();

        assert_eq!(analysis.explanation, "Test");
        assert_eq!(analysis.recommendation, LlmRecommendation::Safe);
    }
}
