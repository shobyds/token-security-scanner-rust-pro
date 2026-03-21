//! Conversation state management

use crate::types::{Message, Role, ToolDefinition, ToolResult};
use serde::{Deserialize, Serialize};

/// Manages conversation history and context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    messages: Vec<Message>,
    tool_definitions: Vec<ToolDefinition>,
    max_history: usize,
}

impl Conversation {
    /// Create a new empty conversation
    #[must_use]
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            tool_definitions: Vec::new(),
            max_history: 50,
        }
    }

    /// Create a new conversation with a system prompt
    #[allow(dead_code)]
    pub fn new_with_system_prompt(
        system_prompt: impl Into<String>,
        tool_definitions: Vec<&ToolDefinition>,
    ) -> Self {
        let mut conv = Self::new();
        conv.add_system_prompt(system_prompt, tool_definitions);
        conv
    }

    /// Add a system prompt to the conversation
    pub fn add_system_prompt(
        &mut self,
        system_prompt: impl Into<String>,
        tool_definitions: Vec<&ToolDefinition>,
    ) {
        self.tool_definitions = tool_definitions.into_iter().cloned().collect();
        self.messages.push(Message::system(system_prompt));
    }

    /// Add a message to the conversation
    pub fn add_message(&mut self, message: Message) {
        self.messages.push(message);
        self.trim_history();
    }

    /// Add a tool result to the conversation
    pub fn add_tool_result(&mut self, tool_call_id: String, result: &ToolResult) {
        self.messages
            .push(Message::tool(result.to_llm_string(), tool_call_id));
        self.trim_history();
    }

    /// Get all messages in the conversation
    #[must_use]
    pub fn get_messages(&self) -> &[Message] {
        &self.messages
    }

    /// Get tool definitions
    #[allow(dead_code)]
    #[must_use]
    pub fn get_tool_definitions(&self) -> &[ToolDefinition] {
        &self.tool_definitions
    }

    /// Clear all messages (but keep tool definitions)
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Get the number of messages
    #[allow(dead_code)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Check if conversation is empty
    #[allow(dead_code)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Trim history to `max_history` limit
    fn trim_history(&mut self) {
        if self.messages.len() > self.max_history {
            // Keep system message + most recent messages
            let system_messages: Vec<_> = self
                .messages
                .iter()
                .filter(|m| matches!(m.role, Role::System))
                .cloned()
                .collect();

            let non_system_messages: Vec<_> = self
                .messages
                .iter()
                .filter(|m| !matches!(m.role, Role::System))
                .cloned()
                .collect();

            // Keep only the most recent non-system messages
            let keep_count = self.max_history.saturating_sub(system_messages.len());
            let recent_messages: Vec<_> = non_system_messages
                .iter()
                .skip(non_system_messages.len().saturating_sub(keep_count))
                .cloned()
                .collect();

            self.messages.clear();
            self.messages.extend(system_messages);
            self.messages.extend(recent_messages);
        }
    }
}

impl Default for Conversation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversation_creation() {
        let conv = Conversation::new();
        assert!(conv.is_empty());
        assert_eq!(conv.len(), 0);
        assert!(conv.get_tool_definitions().is_empty());
    }

    #[test]
    fn test_add_system_prompt() {
        let mut conv = Conversation::new();
        conv.add_system_prompt("You are helpful", vec![]);

        assert_eq!(conv.len(), 1);
        assert_eq!(conv.get_messages()[0].role, Role::System);
    }

    #[test]
    fn test_add_message() {
        let mut conv = Conversation::new();
        conv.add_message(Message::user("Hello"));
        conv.add_message(Message::assistant("Hi there!"));

        assert_eq!(conv.len(), 2);
        assert_eq!(conv.get_messages()[0].role, Role::User);
        assert_eq!(conv.get_messages()[1].role, Role::Assistant);
    }

    #[test]
    fn test_add_tool_result() {
        let mut conv = Conversation::new();
        conv.add_message(Message::user("Read the file"));

        let result = ToolResult::success("read_file", "File contents", 100);
        conv.add_tool_result("call_123".to_string(), &result);

        assert_eq!(conv.len(), 2);
        assert_eq!(conv.get_messages()[1].role, Role::Tool);
        assert_eq!(
            conv.get_messages()[1].tool_call_id,
            Some("call_123".to_string())
        );
    }

    #[test]
    fn test_clear_conversation() {
        let mut conv = Conversation::new();
        conv.add_system_prompt("System", vec![]);
        conv.add_message(Message::user("Hello"));
        conv.add_message(Message::assistant("Hi"));

        conv.clear();

        assert!(conv.is_empty());
        assert_eq!(conv.len(), 0);
    }

    #[test]
    fn test_trim_history() {
        let mut conv = Conversation::new();
        conv.max_history = 5;

        // Add system message
        conv.add_system_prompt("System", vec![]);

        // Add many messages
        for i in 0..20 {
            conv.add_message(Message::user(format!("User {i}")));
            conv.add_message(Message::assistant(format!("Assistant {i}")));
        }

        // Should have system + limited history
        assert!(conv.len() <= conv.max_history);

        // System message should still be there
        assert_eq!(conv.get_messages()[0].role, Role::System);
    }

    #[test]
    fn test_conversation_with_tool_definitions() {
        let tool_def = ToolDefinition::new("test_tool", "A test tool", serde_json::json!({}));
        let conv = Conversation::new_with_system_prompt("System", vec![&tool_def]);

        assert_eq!(conv.get_tool_definitions().len(), 1);
        assert_eq!(conv.get_tool_definitions()[0].name, "test_tool");
    }

    #[test]
    fn test_get_messages() {
        let mut conv = Conversation::new();
        conv.add_message(Message::user("Test"));
        conv.add_message(Message::assistant("Response"));

        let messages = conv.get_messages();
        assert_eq!(messages.len(), 2);
    }

    #[test]
    fn test_conversation_default() {
        let conv = Conversation::default();
        assert!(conv.is_empty());
    }

    #[test]
    fn test_multiple_tool_results() {
        let mut conv = Conversation::new();
        conv.add_message(Message::user("Do something"));

        let result1 = ToolResult::success("tool1", "Result 1", 10);
        let result2 = ToolResult::failure("tool2", "Error", 20);

        conv.add_tool_result("call_1".to_string(), &result1);
        conv.add_tool_result("call_2".to_string(), &result2);

        assert_eq!(conv.len(), 3); // User + 2 tool results

        let messages = conv.get_messages();
        assert_eq!(messages[1].role, Role::Tool);
        assert_eq!(messages[2].role, Role::Tool);
    }

    #[test]
    fn test_tool_definitions_persist_after_clear() {
        let tool_def = ToolDefinition::new("test_tool", "A test tool", serde_json::json!({}));
        let mut conv = Conversation::new_with_system_prompt("System", vec![&tool_def]);

        conv.add_message(Message::user("Test"));
        conv.clear();

        // Tool definitions should still be available
        assert_eq!(conv.get_tool_definitions().len(), 1);
    }

    #[test]
    fn test_conversation_serialization() {
        let mut conv = Conversation::new();
        conv.add_message(Message::user("Test"));

        let json = serde_json::to_string(&conv).unwrap();
        assert!(json.contains("Test"));

        let deserialized: Conversation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.len(), 1);
    }
}
