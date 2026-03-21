//! LM Studio Model Detector
//!
//! This module provides automatic detection of loaded models in LM Studio
//! by querying the `/api/v1/models` endpoint.
//!
//! Updated to try OpenAI-compatible `/v1/models` endpoint first (more reliable),
//! then fall back to native `/api/v1/models` endpoint.

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Default timeout for model detection in seconds
const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Model Detector for querying LM Studio loaded models
#[derive(Debug, Clone)]
pub struct ModelDetector {
    /// HTTP blocking client
    client: Client,
    /// Base URL for LM Studio API
    base_url: String,
    /// Timeout in seconds
    timeout_secs: u64,
}

/// Response structure for LM Studio native /api/v1/models endpoint
#[derive(Debug, Clone, Deserialize)]
struct LmStudioModelsResponse {
    models: Vec<LmStudioModelInfo>,
}

/// Individual model information from LM Studio native API
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct LmStudioModelInfo {
    /// Model key/identifier (e.g., "deepseek-coder-6.7b-instruct")
    key: String,
    /// Loaded instances of this model (non-empty array means model is loaded)
    #[serde(default)]
    loaded_instances: Vec<LmStudioLoadedInstance>,
    /// Model display name (optional)
    #[serde(default)]
    display_name: Option<String>,
    /// Model path (optional)
    #[serde(default)]
    path: Option<String>,
}

/// Loaded instance information
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct LmStudioLoadedInstance {
    /// Instance ID (e.g., "deepseek-coder-6.7b-instruct@q3_k_m")
    id: String,
    /// Instance configuration
    #[serde(default)]
    config: Option<serde_json::Value>,
}

/// Response structure for OpenAI-compatible /v1/models endpoint
#[derive(Debug, Clone, Deserialize)]
struct OpenAiModelsResponse {
    data: Vec<OpenAiModelEntry>,
}

/// Individual model entry from OpenAI-compatible API
#[derive(Debug, Clone, Deserialize)]
struct OpenAiModelEntry {
    id: String,
}

/// Model Detector error types
#[derive(Debug, thiserror::Error)]
pub enum ModelDetectorError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    /// No models loaded in LM Studio
    #[error("No models loaded in LM Studio")]
    NoModelsLoaded,

    /// Invalid response format
    #[error("Invalid response format: {0}")]
    InvalidResponse(String),

    /// Timeout exceeded
    #[error("Request timeout after {0} seconds")]
    Timeout(u64),

    /// LM Studio server not reachable
    #[error("LM Studio server not reachable at {0}")]
    ServerNotReachable(String),
}

impl ModelDetector {
    /// Create a new `ModelDetector` with default timeout (5 seconds)
    ///
    /// # Arguments
    /// * `base_url` - The base URL of the LM Studio server (e.g., `<http://localhost:1234>`)
    ///
    /// # Returns
    /// * `Self` - A new `ModelDetector` instance
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_timeout(base_url, DEFAULT_TIMEOUT_SECS)
    }

    /// Create a new `ModelDetector` with custom timeout
    ///
    /// # Arguments
    /// * `base_url` - The base URL of the LM Studio server
    /// * `timeout_secs` - Timeout in seconds for the HTTP request
    ///
    /// # Returns
    /// * `Self` - A new `ModelDetector` instance
    pub fn with_timeout(base_url: impl Into<String>, timeout_secs: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("")
            .build()
            .expect("Failed to create HTTP client for model detector");

        Self {
            client,
            base_url: base_url.into(),
            timeout_secs,
        }
    }

    /// Detect the first loaded model from LM Studio
    ///
    /// Tries OpenAI-compatible `/v1/models` endpoint first (more reliable - lists only loaded models),
    /// then falls back to native `/api/v1/models` endpoint.
    /// Returns the key of the first model that has at least one loaded instance.
    ///
    /// # Returns
    /// * `Ok(String)` - The model key of the first loaded model
    /// * `Err(ModelDetectorError)` - If detection fails
    ///
    /// # Example
    /// ```no_run
    /// use rust_llm_agent::utils::ModelDetector;
    ///
    /// let detector = ModelDetector::new("http://localhost:1234");
    /// match detector.detect_loaded_model() {
    ///     Ok(model) => println!("Using loaded model: {}", model),
    ///     Err(e) => eprintln!("Detection failed: {}", e),
    /// }
    /// ```
    pub fn detect_loaded_model(&self) -> Result<String, ModelDetectorError> {
        info!("Detecting loaded LM Studio model at {}...", self.base_url);
        println!("Detecting loaded LM Studio model...");

        // Strategy 1: Try OpenAI-compatible /v1/models endpoint first (more reliable)
        let compat_url = format!("{}/v1/models", self.base_url.trim_end_matches('/'));
        debug!("Trying OpenAI-compatible endpoint: {}", compat_url);

        match self.client.get(&compat_url).send() {
            Ok(resp) => {
                let status = resp.status();
                debug!("OpenAI endpoint response status: {}", status);

                if status.is_success() {
                    match resp.json::<OpenAiModelsResponse>() {
                        Ok(parsed) => {
                            debug!("OpenAI endpoint returned {} models", parsed.data.len());
                            if let Some(first) = parsed.data.first() {
                                info!("✓ Detected model via /v1/models: {}", first.id);
                                println!("✓ Using loaded model: {}", first.id);
                                return Ok(first.id.clone());
                            }
                            debug!("OpenAI endpoint returned empty data array");
                        }
                        Err(e) => {
                            warn!("Failed to parse OpenAI endpoint response: {}", e);
                        }
                    }
                } else {
                    debug!("OpenAI endpoint returned non-success status: {}", status);
                }
            }
            Err(e) => {
                debug!("OpenAI endpoint request failed: {}", e);
            }
        }

        debug!("OpenAI-compatible endpoint failed or returned no models, trying native endpoint");

        // Strategy 2: Fall back to native /api/v1/models endpoint
        let native_url = format!("{}/api/v1/models", self.base_url.trim_end_matches('/'));
        debug!("Falling back to native endpoint: {}", native_url);

        let response = self.client.get(&native_url).send().map_err(|e| {
            if e.is_timeout() {
                error!(
                    "Model detection timeout after {} seconds",
                    self.timeout_secs
                );
                ModelDetectorError::Timeout(self.timeout_secs)
            } else if e.is_connect() {
                error!("Cannot connect to LM Studio at {}", self.base_url);
                ModelDetectorError::ServerNotReachable(self.base_url.clone())
            } else {
                error!("Model detection request failed: {}", e);
                ModelDetectorError::RequestFailed(e)
            }
        })?;

        match self.parse_models_response(response) {
            Ok(model) => {
                info!("✓ Detected model via /api/v1/models: {}", model);
                Ok(model)
            }
            Err(e) => {
                error!("Both model detection endpoints failed: {}", e);
                Err(e)
            }
        }
    }

    /// Parse the models API response
    #[allow(clippy::unused_self)]
    fn parse_models_response(&self, response: Response) -> Result<String, ModelDetectorError> {
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().unwrap_or_default();
            error!("Models API error ({}): {}", status, error_text);

            return match status.as_u16() {
                404 => Err(ModelDetectorError::InvalidResponse(
                    "Models endpoint not found".to_string(),
                )),
                _ => Err(ModelDetectorError::InvalidResponse(format!(
                    "HTTP {status}: {error_text}"
                ))),
            };
        }

        let models_response: LmStudioModelsResponse = response.json().map_err(|e| {
            error!("Failed to parse models response: {}", e);
            ModelDetectorError::InvalidResponse(format!("Invalid JSON: {e}"))
        })?;

        Self::extract_first_loaded_model(&models_response)
    }

    /// Extract the first loaded model from the response
    fn extract_first_loaded_model(
        response: &LmStudioModelsResponse,
    ) -> Result<String, ModelDetectorError> {
        debug!("Received {} models from API", response.models.len());

        // Find the first model with non-empty loaded_instances
        for model in &response.models {
            if !model.loaded_instances.is_empty() {
                // Return the instance ID if available, otherwise the model key
                let model_identifier = model.loaded_instances[0].id.clone();

                info!("✓ Found loaded model: {}", model_identifier);
                println!("✓ Using loaded model: {model_identifier}");

                return Ok(model_identifier);
            }
        }

        // No models with loaded instances found
        warn!(
            "✗ No models loaded in LM Studio ({} models available, none loaded)",
            response.models.len()
        );
        println!("✗ No model loaded in LM Studio, using config model");

        Err(ModelDetectorError::NoModelsLoaded)
    }

    /// Check if any models are loaded in LM Studio
    ///
    /// # Returns
    /// * `Ok(bool)` - true if at least one model is loaded
    /// * `Err(ModelDetectorError)` - If the check fails
    pub fn has_loaded_models(&self) -> Result<bool, ModelDetectorError> {
        match self.detect_loaded_model() {
            Ok(_) => Ok(true),
            Err(ModelDetectorError::NoModelsLoaded) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Get the base URL
    #[allow(dead_code)]
    pub fn get_base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the timeout
    #[allow(dead_code)]
    pub fn get_timeout_secs(&self) -> u64 {
        self.timeout_secs
    }
}

/// Convenience function to detect loaded model with default settings
///
/// # Arguments
/// * `base_url` - The base URL of the LM Studio server
///
/// # Returns
/// * `Ok(String)` - The model key of the first loaded model
/// * `Err(ModelDetectorError)` - If detection fails
pub fn detect_loaded_model(base_url: impl Into<String>) -> Result<String, ModelDetectorError> {
    ModelDetector::new(base_url).detect_loaded_model()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_detector_creation() {
        let detector = ModelDetector::new("http://localhost:1234");
        assert_eq!(detector.get_base_url(), "http://localhost:1234");
        assert_eq!(detector.get_timeout_secs(), DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn test_model_detector_with_custom_timeout() {
        let detector = ModelDetector::with_timeout("http://test:1234", 10);
        assert_eq!(detector.get_base_url(), "http://test:1234");
        assert_eq!(detector.get_timeout_secs(), 10);
    }

    #[test]
    fn test_model_detector_url_trimming() {
        let detector = ModelDetector::new("http://localhost:1234/");
        // URL should be stored with trailing slash trimmed for consistent formatting
        assert!(detector.get_base_url().starts_with("http://"));
    }

    #[test]
    fn test_model_detector_error_display() {
        let err = ModelDetectorError::NoModelsLoaded;
        assert_eq!(format!("{err}"), "No models loaded in LM Studio");

        let err = ModelDetectorError::Timeout(5);
        assert_eq!(format!("{err}"), "Request timeout after 5 seconds");

        let err = ModelDetectorError::ServerNotReachable("http://localhost:1234".to_string());
        assert_eq!(
            format!("{err}"),
            "LM Studio server not reachable at http://localhost:1234"
        );
    }

    #[test]
    fn test_extract_first_loaded_model_empty() {
        let detector = ModelDetector::new("http://localhost:1234");
        let response = LmStudioModelsResponse { models: vec![] };

        let result = ModelDetector::extract_first_loaded_model(&response);
        assert!(matches!(result, Err(ModelDetectorError::NoModelsLoaded)));
    }

    #[test]
    fn test_extract_first_loaded_model_with_loaded() {
        let detector = ModelDetector::new("http://localhost:1234");
        let response = LmStudioModelsResponse {
            models: vec![
                LmStudioModelInfo {
                    key: "deepseek-coder-6.7b-instruct".to_string(),
                    loaded_instances: vec![LmStudioLoadedInstance {
                        id: "deepseek-coder-6.7b-instruct@q3_k_m".to_string(),
                        config: None,
                    }],
                    display_name: None,
                    path: None,
                },
                LmStudioModelInfo {
                    key: "phi-3.5-mini-instruct".to_string(),
                    loaded_instances: vec![],
                    display_name: None,
                    path: None,
                },
            ],
        };

        let result = ModelDetector::extract_first_loaded_model(&response);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "deepseek-coder-6.7b-instruct@q3_k_m");
    }

    #[test]
    fn test_extract_first_loaded_model_multiple_loaded() {
        let detector = ModelDetector::new("http://localhost:1234");
        let response = LmStudioModelsResponse {
            models: vec![
                LmStudioModelInfo {
                    key: "model-a".to_string(),
                    loaded_instances: vec![LmStudioLoadedInstance {
                        id: "model-a@q4".to_string(),
                        config: None,
                    }],
                    display_name: None,
                    path: None,
                },
                LmStudioModelInfo {
                    key: "model-b".to_string(),
                    loaded_instances: vec![LmStudioLoadedInstance {
                        id: "model-b@q8".to_string(),
                        config: None,
                    }],
                    display_name: None,
                    path: None,
                },
            ],
        };

        let result = ModelDetector::extract_first_loaded_model(&response);
        assert!(result.is_ok());
        // Should return the first loaded model
        assert_eq!(result.unwrap(), "model-a@q4");
    }

    #[test]
    fn test_extract_first_loaded_model_none_loaded() {
        let detector = ModelDetector::new("http://localhost:1234");
        let response = LmStudioModelsResponse {
            models: vec![
                LmStudioModelInfo {
                    key: "model-a".to_string(),
                    loaded_instances: vec![],
                    display_name: None,
                    path: None,
                },
                LmStudioModelInfo {
                    key: "model-b".to_string(),
                    loaded_instances: vec![],
                    display_name: None,
                    path: None,
                },
            ],
        };

        let result = ModelDetector::extract_first_loaded_model(&response);
        assert!(matches!(result, Err(ModelDetectorError::NoModelsLoaded)));
    }

    #[test]
    fn test_openai_models_response_parsing() {
        // Test that OpenAI-compatible response format is correctly parsed
        let json_data = r#"{
            "data": [
                {"id": "deepseek-coder-6.7b-instruct@q3_k_m"},
                {"id": "phi-3.5-mini-instruct@q4_k_m"}
            ]
        }"#;

        let parsed: Result<OpenAiModelsResponse, _> = serde_json::from_str(json_data);
        assert!(parsed.is_ok());
        let response = parsed.unwrap();
        assert_eq!(response.data.len(), 2);
        assert_eq!(response.data[0].id, "deepseek-coder-6.7b-instruct@q3_k_m");
    }

    #[test]
    fn test_openai_models_empty_response() {
        let json_data = r#"{"data": []}"#;

        let parsed: Result<OpenAiModelsResponse, _> = serde_json::from_str(json_data);
        assert!(parsed.is_ok());
        let response = parsed.unwrap();
        assert!(response.data.is_empty());
    }

    #[test]
    fn test_model_detector_error_display_all_variants() {
        // Test all error variant displays
        let err = ModelDetectorError::NoModelsLoaded;
        assert_eq!(format!("{err}"), "No models loaded in LM Studio");

        let err = ModelDetectorError::Timeout(5);
        assert_eq!(format!("{err}"), "Request timeout after 5 seconds");

        let err = ModelDetectorError::ServerNotReachable("http://localhost:1234".to_string());
        assert_eq!(
            format!("{err}"),
            "LM Studio server not reachable at http://localhost:1234"
        );

        let err = ModelDetectorError::InvalidResponse("test error".to_string());
        assert_eq!(format!("{err}"), "Invalid response format: test error");
    }
}
