//! Configuration management for the application

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::doc_markdown)]

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::types::ConfigError;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// LLM configuration
    pub llm: LlmConfig,
    /// Agent configuration
    pub agent: AgentConfig,
    /// UI configuration
    pub ui: UiConfig,
    /// Tools configuration
    pub tools: ToolsConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Phi-3 Mini HF Space configuration
    #[serde(default)]
    pub phi3: Phi3Config,
    /// Token Risk Index (TRI) scoring configuration
    #[serde(default)]
    pub tri: TriConfig,
    /// Telegram alerting configuration
    #[serde(default)]
    pub telegram: TelegramConfig,
    /// Report generation configuration
    #[serde(default)]
    pub reports: ReportConfig,
}

/// LLM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Base URL for the LLM API
    pub url: String,
    /// Model name to use (fallback when `auto_detect_model` is false or detection fails)
    pub model: String,
    /// Temperature for generation (0.0 - 1.0)
    pub temperature: f32,
    /// Maximum tokens to generate
    pub max_tokens: u32,
    /// Request timeout in seconds
    pub timeout_seconds: u64,
    /// Enable auto-discovery of LM Studio server on local network (legacy, not used for Groq API)
    #[cfg(feature = "lmstudio")]
    #[serde(default = "default_auto_discover")]
    pub auto_discover: bool,
    /// Network scan range (number of IPs to scan, e.g., 40 means scan .0 to .40) (legacy, not used for Groq API)
    #[cfg(feature = "lmstudio")]
    #[serde(default = "default_network_scan_range")]
    pub network_scan_range: u32,
    /// Discovered IP address (populated after successful discovery) (legacy, not used for Groq API)
    #[cfg(feature = "lmstudio")]
    #[serde(default, skip_serializing)]
    pub discovered_ip: Option<String>,
    /// Enable automatic detection of loaded LM Studio model (legacy, not used for Groq API)
    #[cfg(feature = "lmstudio")]
    #[serde(default = "default_auto_detect_model")]
    pub auto_detect_model: bool,
    /// Detected model name (populated after successful auto-detection) (legacy, not used for Groq API)
    #[cfg(feature = "lmstudio")]
    #[serde(default, skip_serializing)]
    pub detected_model: Option<String>,
    /// Groq API key for authentication (legacy name for backward compatibility, use `GROQ_API_KEY` env var instead)
    #[serde(default)]
    pub hf_api_key: Option<String>,
}

/// Default value for `auto_detect_model`
fn default_auto_detect_model() -> bool {
    true
}

/// Default value for `auto_discover`
fn default_auto_discover() -> bool {
    true
}

/// Default value for `network_scan_range`
fn default_network_scan_range() -> u32 {
    40
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Maximum iterations for the agent loop
    pub max_iterations: usize,
    /// Tool execution timeout in seconds
    pub tool_timeout_seconds: u64,
}

/// UI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Scroll speed
    pub scroll_speed: usize,
    /// Maximum chat history messages to keep
    pub max_chat_history: usize,
    /// Maximum tool log entries to keep
    pub max_tool_log: usize,
    /// Color scheme (default, dark, light)
    pub color_scheme: String,
}

/// Tools configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsConfig {
    /// Enable system commands
    pub enable_system_commands: bool,
    /// Enable git operations
    pub enable_git: bool,
    /// Enable web fetching
    pub enable_web_fetch: bool,
    /// Maximum search results
    pub max_search_results: usize,
    /// File size limit in MB
    pub file_size_limit_mb: usize,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Log file path
    pub file: String,
}

/// Phi-3 Mini Groq API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phi3Config {
    /// Groq API base URL for chat completions (OpenAI-compatible format)
    #[serde(default = "default_phi3_base_url")]
    pub base_url: String,
    /// Model to use for inference (specified in request payload)
    #[serde(default = "default_phi3_model")]
    pub model: String,
    /// Groq API key for authentication
    #[serde(default)]
    pub api_key: Option<String>,
    /// Request timeout in seconds
    #[serde(default = "default_phi3_timeout")]
    pub timeout_secs: u64,
    /// Number of retries for failed requests
    #[serde(default = "default_phi3_retry_count")]
    pub retry_count: u32,
    /// Rug probability threshold to trigger LLM analysis
    #[serde(default = "default_phi3_rug_threshold")]
    pub rug_prob_threshold: f32,
}

fn default_phi3_base_url() -> String {
    "https://api.groq.com/openai/v1".to_string()
}

fn default_phi3_model() -> String {
    "llama-3.1-8b-instant".to_string()
}

fn default_phi3_timeout() -> u64 {
    30
}

fn default_phi3_retry_count() -> u32 {
    3
}

fn default_phi3_rug_threshold() -> f32 {
    0.35
}

impl Default for Phi3Config {
    fn default() -> Self {
        Self {
            base_url: default_phi3_base_url(),
            model: default_phi3_model(),
            api_key: None,
            timeout_secs: default_phi3_timeout(),
            retry_count: default_phi3_retry_count(),
            rug_prob_threshold: default_phi3_rug_threshold(),
        }
    }
}

/// Token Risk Index (TRI) scoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriConfig {
    /// Weight for contract risk score
    #[serde(default = "default_tri_weight_contract")]
    pub weights_contract: f32,
    /// Weight for ownership risk score
    #[serde(default = "default_tri_weight_ownership")]
    pub weights_ownership: f32,
    /// Weight for liquidity risk score
    #[serde(default = "default_tri_weight_liquidity")]
    pub weights_liquidity: f32,
    /// Weight for tax risk score
    #[serde(default = "default_tri_weight_tax")]
    pub weights_tax: f32,
    /// Weight for volume risk score
    #[serde(default = "default_tri_weight_volume")]
    pub weights_volume: f32,
    /// Weight for age risk score
    #[serde(default = "default_tri_weight_age")]
    pub weights_age: f32,
    /// TRI score threshold for alerts
    #[serde(default = "default_tri_alert_threshold")]
    pub alert_threshold: f32,
    /// TRI score threshold for danger level
    #[serde(default = "default_tri_danger_threshold")]
    pub danger_threshold: f32,
}

fn default_tri_weight_contract() -> f32 {
    0.30
}

fn default_tri_weight_ownership() -> f32 {
    0.20
}

fn default_tri_weight_liquidity() -> f32 {
    0.20
}

fn default_tri_weight_tax() -> f32 {
    0.15
}

fn default_tri_weight_volume() -> f32 {
    0.10
}

fn default_tri_weight_age() -> f32 {
    0.05
}

fn default_tri_alert_threshold() -> f32 {
    45.0
}

fn default_tri_danger_threshold() -> f32 {
    65.0
}

impl Default for TriConfig {
    fn default() -> Self {
        Self {
            weights_contract: default_tri_weight_contract(),
            weights_ownership: default_tri_weight_ownership(),
            weights_liquidity: default_tri_weight_liquidity(),
            weights_tax: default_tri_weight_tax(),
            weights_volume: default_tri_weight_volume(),
            weights_age: default_tri_weight_age(),
            alert_threshold: default_tri_alert_threshold(),
            danger_threshold: default_tri_danger_threshold(),
        }
    }
}

/// Telegram alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    /// Telegram bot token
    #[serde(default)]
    pub bot_token: Option<String>,
    /// Telegram chat ID for alerts
    #[serde(default)]
    pub chat_id: Option<String>,
    /// Rug probability threshold for sending alerts
    #[serde(default = "default_telegram_alert_threshold")]
    pub alert_threshold: f32,
    /// Rate limit in minutes between alerts
    #[serde(default = "default_telegram_rate_limit")]
    pub rate_limit_minutes: u64,
}

fn default_telegram_alert_threshold() -> f32 {
    0.45
}

fn default_telegram_rate_limit() -> u64 {
    10
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            bot_token: None,
            chat_id: None,
            alert_threshold: default_telegram_alert_threshold(),
            rate_limit_minutes: default_telegram_rate_limit(),
        }
    }
}

/// Report generation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Use organized directory structure for reports (token_name/timestamp/)
    #[serde(default = "default_organized_reports")]
    pub organized_structure: bool,
    /// Save raw API responses in organized structure
    #[serde(default = "default_save_raw_responses")]
    pub save_raw_responses: bool,
    /// Generate scan manifest files for LLM analysis
    #[serde(default = "default_generate_manifest")]
    pub generate_manifest: bool,
    /// Number of recent scans to keep per token (0 = unlimited)
    #[serde(default = "default_cleanup_keep_count")]
    pub cleanup_keep_count: usize,
    /// Base directory for reports (default: "reports")
    #[serde(default = "default_reports_base_dir")]
    pub base_dir: String,
}

fn default_organized_reports() -> bool {
    true
}

fn default_save_raw_responses() -> bool {
    true
}

fn default_generate_manifest() -> bool {
    true
}

fn default_cleanup_keep_count() -> usize {
    10
}

fn default_reports_base_dir() -> String {
    // Use absolute path to reports directory
    "/home/serverhp/qwenAg/reports".to_string()
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            organized_structure: default_organized_reports(),
            save_raw_responses: default_save_raw_responses(),
            generate_manifest: default_generate_manifest(),
            cleanup_keep_count: default_cleanup_keep_count(),
            base_dir: default_reports_base_dir(),
        }
    }
}

impl AppConfig {
    /// Load configuration from files
    pub fn load() -> Result<Self, ConfigError> {
        let config_dir = Self::get_config_dir()?;
        let default_config = config_dir.join("default.toml");
        let user_config = config_dir.join("settings.toml");

        // Load default configuration
        let mut config = if default_config.exists() {
            let content = fs::read_to_string(&default_config).map_err(|e| {
                ConfigError::IoError(std::io::Error::other(format!(
                    "Failed to read default config: {e}"
                )))
            })?;
            toml::from_str::<AppConfig>(&content)
                .map_err(|e| ConfigError::InvalidFormat(e.to_string()))?
        } else {
            // Use defaults if no config file exists
            Self::default()
        };

        // Override with user configuration if it exists
        if user_config.exists() {
            let content = fs::read_to_string(&user_config).map_err(|e| {
                ConfigError::IoError(std::io::Error::other(format!(
                    "Failed to read user config: {e}"
                )))
            })?;
            let user_config: PartialConfig =
                toml::from_str(&content).map_err(|e| ConfigError::InvalidFormat(e.to_string()))?;
            config.merge(user_config);
        }

        // Validate configuration
        config.validate()?;

        // Load GROQ_API_KEY from environment (env var takes precedence over TOML)
        if let Ok(groq_key) = std::env::var("GROQ_API_KEY")
            && !groq_key.is_empty()
        {
            config.phi3.api_key = Some(groq_key);
        }

        // Sync phi3.api_key to llm.hf_api_key for backward compatibility
        // This ensures chat functions using llm.hf_api_key will work with Groq key
        if let Some(ref key) = config.phi3.api_key {
            config.llm.hf_api_key = Some(key.clone());
        }

        Ok(config)
    }

    /// Load configuration from a specific path
    pub fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.display().to_string()));
        }

        let content = fs::read_to_string(path).map_err(|e| {
            ConfigError::IoError(std::io::Error::other(format!("Failed to read config: {e}")))
        })?;

        let config: AppConfig =
            toml::from_str(&content).map_err(|e| ConfigError::InvalidFormat(e.to_string()))?;

        config.validate()?;
        Ok(config)
    }

    /// Create configuration with default values
    pub fn default() -> Self {
        Self {
            llm: LlmConfig::default(),
            agent: AgentConfig::default(),
            ui: UiConfig::default(),
            tools: ToolsConfig::default(),
            logging: LoggingConfig::default(),
            phi3: Phi3Config::default(),
            tri: TriConfig::default(),
            telegram: TelegramConfig::default(),
            reports: ReportConfig::default(),
        }
    }

    /// Get the configuration directory
    fn get_config_dir() -> Result<PathBuf, ConfigError> {
        // Try to find config in current directory first
        let local_config = PathBuf::from("config");
        if local_config.exists() {
            return Ok(local_config);
        }

        // Fall back to user config directory
        let config_dir = dirs::config_dir()
            .ok_or_else(|| {
                ConfigError::NotFound("Could not determine user config directory".to_string())
            })?
            .join("rust_llm_agent");

        Ok(config_dir)
    }

    /// Validate configuration values
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate LLM URL
        if self.llm.url.is_empty() {
            return Err(ConfigError::InvalidValue(
                "llm.url".to_string(),
                "URL cannot be empty".to_string(),
            ));
        }

        // Validate model name
        if self.llm.model.is_empty() {
            return Err(ConfigError::InvalidValue(
                "llm.model".to_string(),
                "Model name cannot be empty".to_string(),
            ));
        }

        // Validate temperature
        if self.llm.temperature < 0.0 || self.llm.temperature > 1.0 {
            return Err(ConfigError::InvalidValue(
                "llm.temperature".to_string(),
                "Temperature must be between 0.0 and 1.0".to_string(),
            ));
        }

        // Validate max iterations
        if self.agent.max_iterations == 0 {
            return Err(ConfigError::InvalidValue(
                "agent.max_iterations".to_string(),
                "Max iterations must be greater than 0".to_string(),
            ));
        }

        // Validate file size limit
        if self.tools.file_size_limit_mb == 0 {
            return Err(ConfigError::InvalidValue(
                "tools.file_size_limit_mb".to_string(),
                "File size limit must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Merge with partial configuration
    #[allow(clippy::too_many_lines)]
    fn merge(&mut self, partial: PartialConfig) {
        if let Some(llm) = partial.llm {
            if let Some(url) = llm.url {
                self.llm.url = url;
            }
            if let Some(model) = llm.model {
                self.llm.model = model;
            }
            if let Some(temperature) = llm.temperature {
                self.llm.temperature = temperature;
            }
            if let Some(max_tokens) = llm.max_tokens {
                self.llm.max_tokens = max_tokens;
            }
            if let Some(timeout_seconds) = llm.timeout_seconds {
                self.llm.timeout_seconds = timeout_seconds;
            }
            #[cfg(feature = "lmstudio")]
            if let Some(auto_discover) = llm.auto_discover {
                self.llm.auto_discover = auto_discover;
            }
            #[cfg(feature = "lmstudio")]
            if let Some(network_scan_range) = llm.network_scan_range {
                self.llm.network_scan_range = network_scan_range;
            }
            #[cfg(feature = "lmstudio")]
            if let Some(auto_detect_model) = llm.auto_detect_model {
                self.llm.auto_detect_model = auto_detect_model;
            }
            if let Some(hf_api_key) = llm.hf_api_key {
                self.llm.hf_api_key = Some(hf_api_key);
            }
        }

        if let Some(agent) = partial.agent {
            if let Some(max_iterations) = agent.max_iterations {
                self.agent.max_iterations = max_iterations;
            }
            if let Some(tool_timeout_seconds) = agent.tool_timeout_seconds {
                self.agent.tool_timeout_seconds = tool_timeout_seconds;
            }
        }

        if let Some(ui) = partial.ui {
            if let Some(scroll_speed) = ui.scroll_speed {
                self.ui.scroll_speed = scroll_speed;
            }
            if let Some(max_chat_history) = ui.max_chat_history {
                self.ui.max_chat_history = max_chat_history;
            }
            if let Some(max_tool_log) = ui.max_tool_log {
                self.ui.max_tool_log = max_tool_log;
            }
            if let Some(color_scheme) = ui.color_scheme {
                self.ui.color_scheme = color_scheme;
            }
        }

        if let Some(tools) = partial.tools {
            if let Some(enable_system_commands) = tools.enable_system_commands {
                self.tools.enable_system_commands = enable_system_commands;
            }
            if let Some(enable_git) = tools.enable_git {
                self.tools.enable_git = enable_git;
            }
            if let Some(enable_web_fetch) = tools.enable_web_fetch {
                self.tools.enable_web_fetch = enable_web_fetch;
            }
            if let Some(max_search_results) = tools.max_search_results {
                self.tools.max_search_results = max_search_results;
            }
            if let Some(file_size_limit_mb) = tools.file_size_limit_mb {
                self.tools.file_size_limit_mb = file_size_limit_mb;
            }
        }

        if let Some(logging) = partial.logging {
            if let Some(level) = logging.level {
                self.logging.level = level;
            }
            if let Some(file) = logging.file {
                self.logging.file = file;
            }
        }

        if let Some(phi3) = partial.phi3 {
            if let Some(base_url) = phi3.base_url {
                self.phi3.base_url = base_url;
            }
            if let Some(model) = phi3.model {
                self.phi3.model = model;
            }
            if let Some(api_key) = phi3.api_key {
                self.phi3.api_key = Some(api_key);
            }
            if let Some(timeout_secs) = phi3.timeout_secs {
                self.phi3.timeout_secs = timeout_secs;
            }
            if let Some(retry_count) = phi3.retry_count {
                self.phi3.retry_count = retry_count;
            }
            if let Some(rug_prob_threshold) = phi3.rug_prob_threshold {
                self.phi3.rug_prob_threshold = rug_prob_threshold;
            }
        }

        if let Some(tri) = partial.tri {
            if let Some(weights_contract) = tri.weights_contract {
                self.tri.weights_contract = weights_contract;
            }
            if let Some(weights_ownership) = tri.weights_ownership {
                self.tri.weights_ownership = weights_ownership;
            }
            if let Some(weights_liquidity) = tri.weights_liquidity {
                self.tri.weights_liquidity = weights_liquidity;
            }
            if let Some(weights_tax) = tri.weights_tax {
                self.tri.weights_tax = weights_tax;
            }
            if let Some(weights_volume) = tri.weights_volume {
                self.tri.weights_volume = weights_volume;
            }
            if let Some(weights_age) = tri.weights_age {
                self.tri.weights_age = weights_age;
            }
            if let Some(alert_threshold) = tri.alert_threshold {
                self.tri.alert_threshold = alert_threshold;
            }
            if let Some(danger_threshold) = tri.danger_threshold {
                self.tri.danger_threshold = danger_threshold;
            }
        }

        if let Some(telegram) = partial.telegram {
            if let Some(bot_token) = telegram.bot_token {
                self.telegram.bot_token = Some(bot_token);
            }
            if let Some(chat_id) = telegram.chat_id {
                self.telegram.chat_id = Some(chat_id);
            }
            if let Some(alert_threshold) = telegram.alert_threshold {
                self.telegram.alert_threshold = alert_threshold;
            }
            if let Some(rate_limit_minutes) = telegram.rate_limit_minutes {
                self.telegram.rate_limit_minutes = rate_limit_minutes;
            }
        }

        if let Some(reports) = partial.reports {
            if let Some(organized_structure) = reports.organized_structure {
                self.reports.organized_structure = organized_structure;
            }
            if let Some(save_raw_responses) = reports.save_raw_responses {
                self.reports.save_raw_responses = save_raw_responses;
            }
            if let Some(generate_manifest) = reports.generate_manifest {
                self.reports.generate_manifest = generate_manifest;
            }
            if let Some(cleanup_keep_count) = reports.cleanup_keep_count {
                self.reports.cleanup_keep_count = cleanup_keep_count;
            }
            if let Some(base_dir) = reports.base_dir {
                self.reports.base_dir = base_dir;
            }
        }
    }
}

/// Partial configuration for merging
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PartialConfig {
    #[serde(default)]
    llm: Option<PartialLlmConfig>,
    #[serde(default)]
    agent: Option<PartialAgentConfig>,
    #[serde(default)]
    ui: Option<PartialUiConfig>,
    #[serde(default)]
    tools: Option<PartialToolsConfig>,
    #[serde(default)]
    logging: Option<PartialLoggingConfig>,
    #[serde(default)]
    phi3: Option<PartialPhi3Config>,
    #[serde(default)]
    tri: Option<PartialTriConfig>,
    #[serde(default)]
    telegram: Option<PartialTelegramConfig>,
    #[serde(default)]
    reports: Option<PartialReportConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PartialLlmConfig {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    temperature: Option<f32>,
    #[serde(default)]
    max_tokens: Option<u32>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[cfg(feature = "lmstudio")]
    #[serde(default)]
    auto_discover: Option<bool>,
    #[cfg(feature = "lmstudio")]
    #[serde(default)]
    network_scan_range: Option<u32>,
    #[cfg(feature = "lmstudio")]
    #[serde(default)]
    auto_detect_model: Option<bool>,
    #[serde(default)]
    hf_api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PartialAgentConfig {
    #[serde(default)]
    max_iterations: Option<usize>,
    #[serde(default)]
    tool_timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PartialUiConfig {
    #[serde(default)]
    scroll_speed: Option<usize>,
    #[serde(default)]
    max_chat_history: Option<usize>,
    #[serde(default)]
    max_tool_log: Option<usize>,
    #[serde(default)]
    color_scheme: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PartialToolsConfig {
    #[serde(default)]
    enable_system_commands: Option<bool>,
    #[serde(default)]
    enable_git: Option<bool>,
    #[serde(default)]
    enable_web_fetch: Option<bool>,
    #[serde(default)]
    max_search_results: Option<usize>,
    #[serde(default)]
    file_size_limit_mb: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PartialLoggingConfig {
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PartialPhi3Config {
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    retry_count: Option<u32>,
    #[serde(default)]
    rug_prob_threshold: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PartialTriConfig {
    #[serde(default)]
    weights_contract: Option<f32>,
    #[serde(default)]
    weights_ownership: Option<f32>,
    #[serde(default)]
    weights_liquidity: Option<f32>,
    #[serde(default)]
    weights_tax: Option<f32>,
    #[serde(default)]
    weights_volume: Option<f32>,
    #[serde(default)]
    weights_age: Option<f32>,
    #[serde(default)]
    alert_threshold: Option<f32>,
    #[serde(default)]
    danger_threshold: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PartialTelegramConfig {
    #[serde(default)]
    bot_token: Option<String>,
    #[serde(default)]
    chat_id: Option<String>,
    #[serde(default)]
    alert_threshold: Option<f32>,
    #[serde(default)]
    rate_limit_minutes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PartialReportConfig {
    #[serde(default)]
    organized_structure: Option<bool>,
    #[serde(default)]
    save_raw_responses: Option<bool>,
    #[serde(default)]
    generate_manifest: Option<bool>,
    #[serde(default)]
    cleanup_keep_count: Option<usize>,
    #[serde(default)]
    base_dir: Option<String>,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:1234".to_string(),
            model: "deepseek-coder-6.7b-instruct".to_string(),
            temperature: 0.2,
            max_tokens: 4096,
            timeout_seconds: 120,
            #[cfg(feature = "lmstudio")]
            auto_discover: true,
            #[cfg(feature = "lmstudio")]
            network_scan_range: 40,
            #[cfg(feature = "lmstudio")]
            discovered_ip: None,
            #[cfg(feature = "lmstudio")]
            auto_detect_model: true,
            #[cfg(feature = "lmstudio")]
            detected_model: None,
            hf_api_key: None,
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            max_iterations: 15,
            tool_timeout_seconds: 30,
        }
    }
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            scroll_speed: 3,
            max_chat_history: 100,
            max_tool_log: 50,
            color_scheme: "default".to_string(),
        }
    }
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            enable_system_commands: true,
            enable_git: true,
            enable_web_fetch: false,
            max_search_results: 100,
            file_size_limit_mb: 10,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: "agent.log".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();

        assert_eq!(config.llm.url, "http://localhost:1234");
        assert_eq!(config.llm.model, "deepseek-coder-6.7b-instruct");
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(config.llm.temperature, 0.2);
        }
        assert_eq!(config.agent.max_iterations, 15);
        assert!(config.tools.enable_system_commands);
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_config_validation_empty_url() {
        let mut config = AppConfig::default();
        config.llm.url = String::new();

        let result = config.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InvalidValue(_, _)
        ));
    }

    #[test]
    fn test_config_validation_empty_model() {
        let mut config = AppConfig::default();
        config.llm.model = String::new();

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_temperature() {
        let mut config = AppConfig::default();
        config.llm.temperature = 1.5;

        let result = config.validate();
        assert!(result.is_err());

        config.llm.temperature = -0.1;
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_max_iterations() {
        let mut config = AppConfig::default();
        config.agent.max_iterations = 0;

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_from_path() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
            [llm]
            url = "http://test:1234"
            model = "test-model"
            temperature = 0.5
            max_tokens = 2048
            timeout_seconds = 60

            [agent]
            max_iterations = 10
            tool_timeout_seconds = 20

            [ui]
            scroll_speed = 5
            max_chat_history = 50
            max_tool_log = 25
            color_scheme = "dark"

            [tools]
            enable_system_commands = false
            enable_git = false
            enable_web_fetch = true
            max_search_results = 50
            file_size_limit_mb = 5

            [logging]
            level = "debug"
            file = "test.log"
        "#;

        temp_file.write_all(config_content.as_bytes()).unwrap();

        let config = AppConfig::load_from_path(temp_file.path()).unwrap();

        assert_eq!(config.llm.url, "http://test:1234");
        assert_eq!(config.llm.model, "test-model");
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(config.llm.temperature, 0.5);
        }
        assert_eq!(config.agent.max_iterations, 10);
        assert!(!config.tools.enable_system_commands);
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn test_load_config_invalid_path() {
        let result = AppConfig::load_from_path(Path::new("/nonexistent/path/config.toml"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::NotFound(_)));
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"invalid toml {{{{").unwrap();

        let result = AppConfig::load_from_path(temp_file.path());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::InvalidFormat(_)));
    }

    #[test]
    fn test_config_merge() {
        let mut config = AppConfig::default();
        let partial = PartialConfig {
            llm: Some(PartialLlmConfig {
                url: Some("http://merged:1234".to_string()),
                model: Some("merged-model".to_string()),
                ..Default::default()
            }),
            agent: Some(PartialAgentConfig {
                max_iterations: Some(20),
                ..Default::default()
            }),
            ..Default::default()
        };

        config.merge(partial);

        assert_eq!(config.llm.url, "http://merged:1234");
        assert_eq!(config.llm.model, "merged-model");
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(config.llm.temperature, 0.2); // Unchanged
        }
        assert_eq!(config.agent.max_iterations, 20);
    }

    #[test]
    fn test_config_serialization() {
        let config = AppConfig::default();
        let json = serde_json::to_string(&config).unwrap();

        assert!(json.contains("\"llm\""));
        assert!(json.contains("\"agent\""));
        assert!(json.contains("\"tools\""));
    }

    #[test]
    fn test_config_deserialization() {
        let json = r#"{
            "llm": {
                "url": "http://test:1234",
                "model": "test",
                "temperature": 0.3,
                "max_tokens": 1024,
                "timeout_seconds": 30
            },
            "agent": {
                "max_iterations": 5,
                "tool_timeout_seconds": 10
            },
            "ui": {
                "scroll_speed": 2,
                "max_chat_history": 25,
                "max_tool_log": 10,
                "color_scheme": "light"
            },
            "tools": {
                "enable_system_commands": true,
                "enable_git": true,
                "enable_web_fetch": false,
                "max_search_results": 200,
                "file_size_limit_mb": 20
            },
            "logging": {
                "level": "trace",
                "file": "debug.log"
            }
        }"#;

        let config: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.llm.url, "http://test:1234");
        assert_eq!(config.agent.max_iterations, 5);
    }
}
