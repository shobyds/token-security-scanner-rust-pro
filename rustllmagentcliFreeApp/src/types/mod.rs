//! Type definitions for the Rust LLM Agent

pub mod error;
pub mod message;
pub mod tool;

// Re-export error types
pub use error::{AgentError, ConfigError, LlmClientError, LlmResult};
// Re-export message types
pub use message::{FunctionCall, Message, Role, ToolCall};
// Re-export tool types
pub use tool::{SchemaBuilder, ToolDefinition, ToolResult};
