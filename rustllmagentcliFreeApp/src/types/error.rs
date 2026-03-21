//! Error types for the Rust LLM Agent

use thiserror::Error;

/// Main error type for the application
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum AgentError {
    /// LLM client errors
    #[error("LLM client error: {0}")]
    LlmClient(#[from] LlmClientError),

    /// Tool execution errors
    #[error("Tool execution error: {0}")]
    ToolExecution(#[from] ToolError),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Configuration(#[from] ConfigError),

    /// File system errors
    #[error("File system error: {0}")]
    FileSystem(#[from] std::io::Error),

    /// JSON serialization/deserialization errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// HTTP client errors
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// URL parsing errors
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Generic anyhow error wrapper
    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),

    /// Agent reached maximum iterations
    #[error("Agent exceeded maximum iteration limit: {0}")]
    MaxIterationsReached(usize),

    /// Tool not found in registry
    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    /// Invalid tool arguments
    #[error("Invalid tool arguments for '{0}': {1}")]
    InvalidToolArguments(String, String),

    /// Conversation errors
    #[error("Conversation error: {0}")]
    Conversation(String),

    /// TUI errors
    #[error("TUI error: {0}")]
    Tui(String),
}

/// LLM Client specific errors
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum LlmClientError {
    /// API request failed
    #[error("API request failed: {0}")]
    RequestFailed(String),

    /// Invalid response format
    #[error("Invalid response format: {0}")]
    InvalidResponse(String),

    /// Model not found
    #[error("Model not found: {0}")]
    ModelNotFound(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Timeout
    #[error("Request timeout after {0} seconds")]
    Timeout(u64),

    /// Empty response
    #[error("Received empty response from LLM")]
    EmptyResponse,

    /// Invalid tool call format
    #[error("Invalid tool call format: {0}")]
    InvalidToolCall(String),
}

/// Tool execution errors
#[derive(Error, Debug, Clone)]
#[allow(dead_code)]
pub enum ToolError {
    /// File not found
    #[error("File not found: {0}")]
    FileNotFound(String),

    /// Directory not found
    #[error("Directory not found: {0}")]
    DirectoryNotFound(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// File too large
    #[error("File too large: {0} bytes (limit: {1} bytes)")]
    FileTooLarge(u64, u64),

    /// Invalid path
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Search failed
    #[error("Search failed: {0}")]
    SearchFailed(String),

    /// Git operation failed
    #[error("Git operation failed: {0}")]
    GitOperation(String),

    /// Command execution failed
    #[error("Command execution failed: {0}")]
    CommandFailed(String),

    /// Tool timeout
    #[error("Tool execution timeout after {0} seconds")]
    Timeout(u64),

    /// Invalid arguments
    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),

    /// Output too large
    #[error("Output too large: {0} bytes (limit: {1} bytes)")]
    OutputTooLarge(usize, usize),
}

/// Configuration errors
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ConfigError {
    /// Configuration file not found
    #[error("Configuration file not found: {0}")]
    NotFound(String),

    /// Invalid configuration format
    #[error("Invalid configuration format: {0}")]
    InvalidFormat(String),

    /// Missing required configuration
    #[error("Missing required configuration: {0}")]
    MissingRequired(String),

    /// Invalid configuration value
    #[error("Invalid configuration value for '{0}': {1}")]
    InvalidValue(String, String),

    /// IO error reading configuration
    #[error("IO error reading configuration: {0}")]
    IoError(#[from] std::io::Error),

    /// TOML parsing error
    #[error("TOML parsing error: {0}")]
    TomlError(#[from] toml::de::Error),
}

/// Result type alias for Agent operations
#[allow(dead_code)]
pub type AgentResult<T> = Result<T, AgentError>;

/// Result type alias for LLM Client operations
pub type LlmResult<T> = Result<T, LlmClientError>;

/// Result type alias for Tool operations
#[allow(dead_code)]
pub type ToolResult<T> = Result<T, ToolError>;

/// Result type alias for Configuration operations
#[allow(dead_code)]
pub type ConfigResult<T> = Result<T, ConfigError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_error_display() {
        let err = AgentError::MaxIterationsReached(15);
        assert_eq!(
            format!("{err}"),
            "Agent exceeded maximum iteration limit: 15"
        );
    }

    #[test]
    fn test_llm_client_error_display() {
        let err = LlmClientError::RequestFailed("Connection refused".to_string());
        assert_eq!(format!("{err}"), "API request failed: Connection refused");
    }

    #[test]
    fn test_tool_error_display() {
        let err = ToolError::FileNotFound("/path/to/file.rs".to_string());
        assert_eq!(format!("{err}"), "File not found: /path/to/file.rs");
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::NotFound("config.toml".to_string());
        assert_eq!(
            format!("{err}"),
            "Configuration file not found: config.toml"
        );
    }

    #[test]
    fn test_error_from_conversions() {
        // Test From trait implementations
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let agent_err: AgentError = io_err.into();
        assert!(matches!(agent_err, AgentError::FileSystem(_)));

        let json_err = serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid json",
        ));
        let agent_err: AgentError = json_err.into();
        assert!(matches!(agent_err, AgentError::Json(_)));
    }

    #[test]
    fn test_result_type_aliases() {
        let agent_result: AgentResult<()> = Ok(());
        assert!(agent_result.is_ok());

        let llm_result: LlmResult<String> = Err(LlmClientError::EmptyResponse);
        assert!(llm_result.is_err());

        let tool_result: ToolResult<i32> = Err(ToolError::InvalidArguments("test".to_string()));
        assert!(tool_result.is_err());

        let config_result: ConfigResult<bool> =
            Err(ConfigError::MissingRequired("llm_url".to_string()));
        assert!(config_result.is_err());
    }
}
