//! LLM API Client for Groq API and LM Studio
//!
//! Uses global HTTP client with connection pooling for optimal performance.
//! Supports both OpenAI-compatible API (LM Studio) and Groq API.

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::too_many_lines)]

use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::time::Instant;
use tracing::{debug, error, info, warn};

use crate::http_client::HTTP_CLIENT;
use crate::llm::Phi3Client;
use crate::retry::retry_async;
use crate::types::{LlmClientError, LlmResult, Message, Role, ToolCall, ToolDefinition};

/// Request structure for OpenAI-compatible chat completions API
#[derive(Debug, Clone, Serialize)]
struct OpenAiChatRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<serde_json::Value>,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    store: Option<bool>,
}

/// Message structure for OpenAI-compatible API
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenAiMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<OpenAiToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

/// Tool call structure for OpenAI-compatible API
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenAiToolCall {
    id: String,
    #[serde(rename = "type")]
    call_type: String,
    function: OpenAiFunctionCall,
}

/// Function call structure for OpenAI-compatible API
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenAiFunctionCall {
    name: String,
    arguments: String,
}

/// Response structure for OpenAI-compatible chat completions API
#[derive(Debug, Clone, Deserialize)]
struct OpenAiChatResponse {
    choices: Vec<OpenAiChoice>,
    #[serde(default)]
    usage: Option<OpenAiUsage>,
}

/// Choice structure from OpenAI-compatible API
#[derive(Debug, Clone, Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
    finish_reason: Option<String>,
}

/// Usage statistics from OpenAI-compatible API
#[derive(Debug, Clone, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct OpenAiUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// LLM Client for API communication
///
/// Uses the global `HTTP_CLIENT` for connection pooling and HTTP/2 support
/// Supports both OpenAI-compatible API (LM Studio) and Groq API
pub struct LlmClient {
    /// Base URL for the API
    base_url: String,
    /// Model name
    model: String,
    /// Temperature for generation
    temperature: f32,
    /// Maximum tokens to generate
    max_tokens: Option<u32>,
    /// API key for authentication (used for Groq)
    api_key: Option<String>,
    /// Phi-3 client for Groq API
    phi3_client: Option<Phi3Client>,
}

impl std::fmt::Debug for LlmClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmClient")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("temperature", &self.temperature)
            .field("max_tokens", &self.max_tokens)
            .field("api_key", &self.api_key)
            .field("phi3_client", &self.phi3_client.as_ref().map(|_| "Phi3Client { .. }"))
            .finish()
    }
}

impl LlmClient {
    /// Create a new LLM client (uses global `HTTP_CLIENT`)
    pub fn new(base_url: String, model: String) -> Self {
        // Check if this is a Groq API URL
        let phi3_client = if base_url.contains("api.groq.com") {
            let config = crate::llm::Phi3Config {
                base_url: base_url.clone(),
                model: model.clone(),
                api_key: None,
                timeout_secs: 120,
                retry_count: 3,
                rug_prob_threshold: 0.35,
            };
            Phi3Client::new(&config).ok()
        } else {
            None
        };

        Self {
            base_url,
            model,
            temperature: 0.1,
            max_tokens: Some(256),
            api_key: None,
            phi3_client,
        }
    }

    /// Create LLM client with custom configuration
    #[allow(dead_code)]
    pub fn with_config(
        base_url: String,
        model: String,
        temperature: f32,
        max_tokens: Option<u32>,
        _timeout_secs: u64, // Timeout is handled by global client
        api_key: Option<String>,
    ) -> Self {
        // Check if this is a Groq API URL
        let phi3_client = if base_url.contains("api.groq.com") {
            let config = crate::llm::Phi3Config {
                base_url: base_url.clone(),
                model: model.clone(),
                api_key: api_key.clone(),
                timeout_secs: 120,
                retry_count: 3,
                rug_prob_threshold: 0.35,
            };
            Phi3Client::new(&config).ok()
        } else {
            None
        };

        Self {
            base_url,
            model,
            temperature,
            max_tokens,
            api_key,
            phi3_client,
        }
    }

    /// Create LLM client with configuration and auto-discovery
    pub fn with_config_and_discovery(config: &crate::app::config::LlmConfig) -> Self {
        #[cfg(feature = "lmstudio")]
        use crate::utils::network_scanner::NetworkScanner;

        #[cfg(feature = "lmstudio")]
        let actual_url = if config.auto_discover {
            // For Groq API, auto-discovery is disabled
            config.url.clone()
        } else {
            config.url.clone()
        };

        #[cfg(not(feature = "lmstudio"))]
        let actual_url = config.url.clone();

        #[cfg(feature = "lmstudio")]
        let actual_model = if config.auto_detect_model {
            config.model.clone()
        } else {
            config.model.clone()
        };

        #[cfg(not(feature = "lmstudio"))]
        let actual_model = config.model.clone();

        // Check if this is a Groq API URL - use Phi3Client for Groq API
        let phi3_client = if actual_url.contains("api.groq.com") {
            // Read Groq API key from env var or config
            let groq_key = std::env::var("GROQ_API_KEY")
                .unwrap_or_else(|_| config.hf_api_key.clone().unwrap_or_default());

            // Log API key status for debugging
            if groq_key.is_empty() {
                warn!("GROQ_API_KEY is empty - Groq API calls will fail");
                warn!("GROQ_API_KEY env var: {}", std::env::var("GROQ_API_KEY").unwrap_or_else(|_| "NOT SET".to_string()));
                warn!("config.hf_api_key: {:?}", config.hf_api_key.as_ref().map(|k| {
                    let len = k.len();
                    format!("{}...{}", &k[..4.min(len)], &k[len.saturating_sub(4)..])
                }));
            } else {
                let key_preview = if groq_key.len() > 8 {
                    format!("{}...{}", &groq_key[..4], &groq_key[groq_key.len() - 4..])
                } else {
                    "***".to_string()
                };
                info!("Groq API key configured: {}", key_preview);
            }

            let phi3_config = crate::llm::Phi3Config {
                base_url: actual_url.clone(),
                model: actual_model.clone(),
                api_key: if groq_key.is_empty() { None } else { Some(groq_key) },
                timeout_secs: 120,
                retry_count: 3,
                rug_prob_threshold: 0.35,
            };
            Phi3Client::new(&phi3_config).ok()
        } else {
            None
        };

        Self {
            base_url: actual_url,
            model: actual_model,
            temperature: config.temperature,
            max_tokens: Some(config.max_tokens),
            api_key: config.hf_api_key.clone(),
            phi3_client,
        }
    }

    /// Get the base URL
    pub fn get_base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the model name
    pub fn get_model(&self) -> &str {
        &self.model
    }

    /// Query the LLM with available tools
    pub async fn query_with_tools(
        &self,
        messages: &[Message],
        tools: Option<&[ToolDefinition]>,
    ) -> LlmResult<Message> {
        // If Phi3Client is configured (HF Space), use it instead
        if let Some(ref phi3) = self.phi3_client {
            return self.query_with_phi3(phi3, messages).await;
        }

        // Otherwise, use OpenAI-compatible API (LM Studio)
        self.query_with_openai(messages, tools).await
    }

    /// Query using Phi-3 client (Groq API)
    async fn query_with_phi3(
        &self,
        phi3: &Phi3Client,
        messages: &[Message],
    ) -> LlmResult<Message> {
        use crate::llm::Phi3Config;
        use serde_json::json;

        let total_start = Instant::now();
        info!("=================================================================");
        info!("STEP 1: Starting query_with_phi3 (Groq API)");
        info!("  Messages count: {}", messages.len());
        info!("  Model: {}", self.model);
        info!("  Base URL: {}", self.base_url);

        // Build conversation history as context
        let mut context = String::new();
        for msg in messages {
            match msg.role {
                Role::System => {
                    let _ = writeln!(context, "System: {}", msg.content);
                }
                Role::User => {
                    let _ = writeln!(context, "User: {}", msg.content);
                }
                Role::Assistant => {
                    let _ = writeln!(context, "Assistant: {}", msg.content);
                }
                Role::Tool => {
                    let _ = writeln!(context, "Tool: {}", msg.content);
                }
            }
        }

        info!("STEP 2: Built conversation context ({} chars)", context.len());

        // Convert internal messages to Groq/OpenAI format
        let groq_messages: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| {
                let role_str = match m.role {
                    Role::Assistant => "assistant",
                    Role::User | Role::Tool => "user", // Tool responses as user messages for Groq
                    Role::System => "system",
                };
                json!({
                    "role": role_str,
                    "content": m.content
                })
            })
            .collect();

        debug!("Groq messages count: {}", groq_messages.len());
        debug!("Groq messages: {:?}", groq_messages);

        // Use analyze_token with proper Groq format
        // Pass the conversation as a simple chat request
        let metrics = json!({
            "messages": groq_messages
        });

        debug!("Sending to phi3.analyze_token with {} messages", groq_messages.len());

        match phi3.analyze_token(&metrics, 0.0).await {
            Ok(analysis) => {
                let total_elapsed = total_start.elapsed();
                info!("STEP 10: Groq analysis complete");
                info!("  TOTAL TIME: {:?}", total_elapsed);

                Ok(Message {
                    role: Role::Assistant,
                    content: analysis.explanation,
                    tool_calls: None,
                    tool_call_id: None,
                    timestamp: Message::now(),
                    #[allow(clippy::cast_possible_truncation)]
                    duration_ms: Some(total_elapsed.as_millis() as u64),
                })
            }
            Err(e) => {
                let total_elapsed = total_start.elapsed();
                error!("STEP 9a: Groq analysis FAILED after {:?}", total_elapsed);
                error!("  Error details: {}", e);
                Err(LlmClientError::RequestFailed(format!(
                    "Groq analysis error after {total_elapsed:?}: {e}"
                )))
            }
        }
    }

    /// Query using OpenAI-compatible API (LM Studio)
    async fn query_with_openai(
        &self,
        messages: &[Message],
        tools: Option<&[ToolDefinition]>,
    ) -> LlmResult<Message> {
        use std::fmt::Write;

        let total_start = Instant::now();
        info!("=================================================================");
        info!("STEP 1: Starting query_with_openai (LM Studio API)");
        info!("  Messages count: {}", messages.len());
        info!("  Tools enabled: {}", tools.is_some());
        info!("  Model: {}", self.model);
        info!("  Base URL: {}", self.base_url);

        // Extract system prompt from messages
        let system_message = messages.iter().find(|m| m.role == Role::System);

        info!("STEP 2: Extracting system prompt");
        if let Some(sys_msg) = system_message {
            info!("  Found system message: {} chars", sys_msg.content.len());
        } else {
            info!("  No system message found");
        }

        // Convert internal Message → OpenAiMessage format
        let api_messages: Vec<OpenAiMessage> = messages
            .iter()
            .filter(|m| m.role != Role::System)
            .map(|m| {
                let content = if m.content.is_empty() && m.role == Role::Assistant {
                    None
                } else {
                    Some(m.content.clone())
                };

                let tool_calls = m.tool_calls.as_ref().map(|tcs| {
                    tcs.iter()
                        .map(|tc| OpenAiToolCall {
                            id: tc.id.clone(),
                            call_type: tc.call_type.clone(),
                            function: OpenAiFunctionCall {
                                name: tc.function.name.clone(),
                                arguments: tc.function.arguments.to_string(),
                            },
                        })
                        .collect()
                });

                OpenAiMessage {
                    role: m.role.to_string(),
                    content,
                    tool_calls,
                    tool_call_id: m.tool_call_id.clone(),
                    name: None,
                }
            })
            .collect();

        info!(
            "STEP 3: Converted {} messages to OpenAI format",
            api_messages.len()
        );

        // Build request - if we have a system message, prepend it to messages
        let request_messages = if let Some(sys_msg) = system_message {
            let mut all_messages = Vec::with_capacity(api_messages.len() + 1);
            all_messages.push(OpenAiMessage {
                role: "system".to_string(),
                content: Some(sys_msg.content.clone()),
                tool_calls: None,
                tool_call_id: None,
                name: None,
            });
            all_messages.extend(api_messages);
            all_messages
        } else {
            api_messages
        };

        // Convert ToolDefinition → OpenAI tools array
        let api_tools: Option<Vec<serde_json::Value>> =
            tools.map(|ts| ts.iter().map(ToolDefinition::to_api_format).collect());

        let tool_choice = if api_tools.is_some() {
            Some(serde_json::json!("auto"))
        } else {
            None
        };

        if let Some(ts) = &tools {
            info!("STEP 4: Tools enabled - {} tools available", ts.len());
        } else {
            info!("STEP 4: No tools provided");
        }

        let request = OpenAiChatRequest {
            model: self.model.clone(),
            messages: request_messages,
            tools: api_tools,
            tool_choice,
            temperature: self.temperature,
            max_tokens: self.max_tokens,
            stream: false,
            store: Some(false),
        };

        info!("STEP 5: Serializing OpenAI-compatible request");
        debug!("  Request struct: {:?}", request);

        let request_json = serde_json::to_string(&request).unwrap_or_default();

        info!("STEP 6: Request JSON ready");
        info!("  JSON length: {} bytes", request_json.len());

        // OpenAI-compatible endpoint: POST /v1/chat/completions
        let url = format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        );

        info!("STEP 7: Preparing HTTP POST request");
        info!("  Target URL: {}", url);
        info!("  Using: Global HTTP_CLIENT (connection pooled, HTTP/2)");

        // Use global HTTP_CLIENT directly (no retry - Groq is fast but reliable)
        let http_start = Instant::now();
        info!("STEP 8: Sending HTTP request...");

        let mut request_builder = HTTP_CLIENT
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json");

        // Add Authorization header if API key is present
        if let Some(ref key) = self.api_key {
            request_builder =
                request_builder.header(reqwest::header::AUTHORIZATION, format!("Bearer {key}"));
        }

        let response = request_builder.json(&request).send().await.map_err(|e| {
            let http_elapsed = http_start.elapsed();
            let total_elapsed = total_start.elapsed();
            error!("STEP 9a: HTTP request FAILED after {:?}", http_elapsed);
            error!("  Total elapsed: {:?}", total_elapsed);
            error!("  Error details: {}", e);
            LlmClientError::RequestFailed(format!("Connection error after {http_elapsed:?}: {e}"))
        })?;

        let http_elapsed = http_start.elapsed();
        let total_elapsed = total_start.elapsed();
        info!("STEP 9b: HTTP response received after {:?}", http_elapsed);
        info!("  Total elapsed so far: {:?}", total_elapsed);
        info!("  Status code: {}", response.status());

        // Parse response
        let result = self.parse_openai_response(response).await;

        let final_total = total_start.elapsed();
        info!("STEP 10: Response parsing complete");
        info!("  TOTAL TIME: {:?}", final_total);

        result
    }

    /// Parse the OpenAI-compatible API response
    async fn parse_openai_response(&self, response: Response) -> LlmResult<Message> {
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            error!("API error ({}): {}", status, error_text);

            return match status.as_u16() {
                401 => Err(LlmClientError::AuthenticationFailed(
                    "Invalid API key or authentication".to_string(),
                )),
                404 => Err(LlmClientError::RequestFailed(format!(
                    "Service unavailable (404): {error_text}"
                ))),
                429 => Err(LlmClientError::RateLimitExceeded),
                500 => Err(LlmClientError::RequestFailed(format!(
                    "Server error (500): {error_text}"
                ))),
                503 => Err(LlmClientError::RequestFailed(format!(
                    "Service unavailable (503): {error_text}"
                ))),
                _ => Err(LlmClientError::RequestFailed(format!(
                    "HTTP {status}: {error_text}"
                ))),
            };
        }

        let completion: OpenAiChatResponse = response.json().await.map_err(|e| {
            error!("Failed to parse response: {}", e);
            LlmClientError::InvalidResponse(format!("Invalid JSON: {e}"))
        })?;

        debug!("Received response: {} choices", completion.choices.len());

        let choice = completion
            .choices
            .into_iter()
            .next()
            .ok_or(LlmClientError::EmptyResponse)?;

        let content = choice.message.content.unwrap_or_default();

        let message = Message {
            role: Role::Assistant,
            content,
            tool_calls: None,
            tool_call_id: None,
            timestamp: Message::now(),
            duration_ms: None,
        };

        Ok(message)
    }

    /// Query the LLM (without tools)
    #[allow(dead_code)]
    pub async fn query(&self, messages: &[Message]) -> LlmResult<Message> {
        self.query_with_tools(messages, None).await
    }
}
