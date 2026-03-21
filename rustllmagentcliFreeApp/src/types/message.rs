//! Message types for conversation management

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use serde::{Deserialize, Serialize};

/// Role of a message in the conversation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// System message (instructions, context)
    System,
    /// User message (queries, commands)
    User,
    /// Assistant message (LLM responses)
    Assistant,
    /// Tool result message
    Tool,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::System => write!(f, "system"),
            Role::User => write!(f, "user"),
            Role::Assistant => write!(f, "assistant"),
            Role::Tool => write!(f, "tool"),
        }
    }
}

/// A message in the conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The role of the message sender
    pub role: Role,
    /// The content of the message
    pub content: String,
    /// Optional tool calls (for assistant messages)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// Optional tool call ID (for tool result messages)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Timestamp when message was created (Unix timestamp in seconds)
    #[serde(default)]
    pub timestamp: u64,
    /// Duration of the operation in milliseconds (for thinking/answer time)
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

impl Message {
    /// Get current timestamp in seconds
    pub fn now() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Create a new system message
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: content.into(),
            tool_calls: None,
            tool_call_id: None,
            timestamp: Self::now(),
            duration_ms: None,
        }
    }

    /// Create a new user message
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: content.into(),
            tool_calls: None,
            tool_call_id: None,
            timestamp: Self::now(),
            duration_ms: None,
        }
    }

    /// Create a new assistant message
    #[allow(dead_code)]
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
            tool_calls: None,
            tool_call_id: None,
            timestamp: Self::now(),
            duration_ms: None,
        }
    }

    /// Create a new assistant message with tool calls
    #[allow(dead_code)]
    pub fn assistant_with_tool_calls(
        content: impl Into<String>,
        tool_calls: Vec<ToolCall>,
    ) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
            tool_calls: Some(tool_calls),
            tool_call_id: None,
            timestamp: Self::now(),
            duration_ms: None,
        }
    }

    /// Create a new tool result message
    pub fn tool(content: impl Into<String>, tool_call_id: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: content.into(),
            tool_calls: None,
            tool_call_id: Some(tool_call_id.into()),
            timestamp: Self::now(),
            duration_ms: None,
        }
    }

    /// Check if this message has tool calls
    #[allow(dead_code)]
    pub fn has_tool_calls(&self) -> bool {
        self.tool_calls
            .as_ref()
            .is_some_and(|calls| !calls.is_empty())
    }

    /// Get the tool calls from this message
    #[allow(dead_code)]
    pub fn get_tool_calls(&self) -> Option<&Vec<ToolCall>> {
        self.tool_calls.as_ref()
    }

    /// Convert message to API format (`OpenAI` compatible)
    #[allow(dead_code)]
    pub fn to_api_format(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "role".to_string(),
            serde_json::Value::String(self.role.to_string()),
        );
        map.insert(
            "content".to_string(),
            serde_json::Value::String(self.content.clone()),
        );

        if let Some(ref tool_calls) = self.tool_calls {
            map.insert(
                "tool_calls".to_string(),
                serde_json::to_value(tool_calls).unwrap_or_default(),
            );
        }

        if let Some(ref tool_call_id) = self.tool_call_id {
            map.insert(
                "tool_call_id".to_string(),
                serde_json::Value::String(tool_call_id.clone()),
            );
        }

        serde_json::Value::Object(map)
    }
}

/// A tool call from the LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Unique identifier for the tool call
    pub id: String,
    /// The type of tool call (always "function" for now)
    #[serde(rename = "type")]
    pub call_type: String,
    /// The function to call
    pub function: FunctionCall,
}

impl ToolCall {
    /// Create a new tool call
    #[allow(dead_code)]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        arguments: serde_json::Value,
    ) -> Self {
        Self {
            id: id.into(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: name.into(),
                arguments,
            },
        }
    }

    /// Get the tool name
    pub fn name(&self) -> &str {
        &self.function.name
    }

    /// Get the tool arguments
    pub fn arguments(&self) -> &serde_json::Value {
        &self.function.arguments
    }

    /// Parse arguments as a specific type
    #[allow(dead_code)]
    pub fn arguments_as<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.function.arguments.clone())
    }
}

/// A function call within a tool call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    /// The name of the function to call
    pub name: String,
    /// The arguments to pass to the function
    pub arguments: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_display() {
        assert_eq!(Role::System.to_string(), "system");
        assert_eq!(Role::User.to_string(), "user");
        assert_eq!(Role::Assistant.to_string(), "assistant");
        assert_eq!(Role::Tool.to_string(), "tool");
    }

    #[test]
    fn test_message_constructors() {
        let system_msg = Message::system("You are a helpful assistant");
        assert_eq!(system_msg.role, Role::System);
        assert_eq!(system_msg.content, "You are a helpful assistant");
        assert!(system_msg.tool_calls.is_none());
        assert!(system_msg.tool_call_id.is_none());

        let user_msg = Message::user("Hello, world!");
        assert_eq!(user_msg.role, Role::User);
        assert_eq!(user_msg.content, "Hello, world!");

        let assistant_msg = Message::assistant("Hi there!");
        assert_eq!(assistant_msg.role, Role::Assistant);
        assert_eq!(assistant_msg.content, "Hi there!");

        let tool_msg = Message::tool("Result", "call_123");
        assert_eq!(tool_msg.role, Role::Tool);
        assert_eq!(tool_msg.content, "Result");
        assert_eq!(tool_msg.tool_call_id, Some("call_123".to_string()));
    }

    #[test]
    fn test_message_with_tool_calls() {
        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({"path": "test.rs"}),
        );
        let msg = Message::assistant_with_tool_calls("Let me read that file", vec![tool_call]);
        assert!(msg.has_tool_calls());
        assert_eq!(msg.get_tool_calls().unwrap().len(), 1);
    }

    #[test]
    fn test_message_to_api_format() {
        let msg = Message::user("Test message");
        let api_format = msg.to_api_format();

        assert!(api_format.is_object());
        let obj = api_format.as_object().unwrap();
        assert_eq!(obj.get("role").unwrap(), "user");
        assert_eq!(obj.get("content").unwrap(), "Test message");
    }

    #[test]
    fn test_tool_call_creation() {
        let tool_call = ToolCall::new(
            "call_abc",
            "search_files",
            serde_json::json!({"pattern": "*.rs", "path": "/src"}),
        );

        assert_eq!(tool_call.id, "call_abc");
        assert_eq!(tool_call.call_type, "function");
        assert_eq!(tool_call.name(), "search_files");
        assert_eq!(
            tool_call.arguments(),
            &serde_json::json!({"pattern": "*.rs", "path": "/src"})
        );
    }

    #[test]
    fn test_tool_call_arguments_parsing() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct ReadFileArgs {
            path: String,
            limit: u32,
        }

        let tool_call = ToolCall::new(
            "call_123",
            "read_file",
            serde_json::json!({"path": "src/main.rs", "limit": 100}),
        );

        let args: ReadFileArgs = tool_call.arguments_as().unwrap();
        assert_eq!(args.path, "src/main.rs");
        assert_eq!(args.limit, 100);
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message::user("Test");
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"role\":\"user\""));
        assert!(json.contains("\"content\":\"Test\""));
    }

    #[test]
    fn test_message_deserialization() {
        let json = r#"{
            "role": "user",
            "content": "Hello"
        }"#;

        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.role, Role::User);
        assert_eq!(msg.content, "Hello");
    }
}
