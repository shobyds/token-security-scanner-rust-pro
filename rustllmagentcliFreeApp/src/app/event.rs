//! Event handling system for the application

#![allow(clippy::must_use_candidate)]

use crate::types::ToolCall;
use crate::types::tool::ToolResult;

/// Application events for communication between components
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum AppEvent {
    /// User sent a message
    UserMessage { content: String },

    /// Assistant responded with a message
    AssistantMessage {
        content: String,
        tool_calls: Option<Vec<ToolCall>>,
    },

    /// Tool execution started
    ToolExecutionStart {
        tool_name: String,
        arguments: serde_json::Value,
    },

    /// Tool execution completed
    ToolExecutionComplete {
        tool_name: String,
        result: ToolResult,
    },

    /// Error occurred
    Error { message: String },

    /// Clear conversation history
    ClearConversation,

    /// Quit application
    Quit,

    /// Tick event for rendering updates
    Tick,

    /// Resize event
    Resize { width: u16, height: u16 },
}

/// Stream events for incremental response updates
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum StreamEvent {
    /// Text chunk received
    TextChunk(String),
    /// Tool call started
    ToolCallStart(ToolCall),
    /// Tool call result received
    ToolCallResult(ToolResult),
    /// Streaming complete
    Complete,
    /// Error occurred
    Error(String),
}

/// Event sender type
pub type EventSender = tokio::sync::mpsc::UnboundedSender<AppEvent>;

/// Event receiver type
#[allow(dead_code)]
pub type EventReceiver = tokio::sync::mpsc::UnboundedReceiver<AppEvent>;

/// Stream event sender type
#[allow(dead_code)]
pub type StreamEventSender = tokio::sync::mpsc::UnboundedSender<StreamEvent>;

/// Stream event receiver type
#[allow(dead_code)]
pub type StreamEventReceiver = tokio::sync::mpsc::UnboundedReceiver<StreamEvent>;

/// Create a new event channel
#[allow(dead_code)]
pub fn create_event_channel() -> (EventSender, EventReceiver) {
    tokio::sync::mpsc::unbounded_channel()
}

/// Create a new stream event channel
#[allow(dead_code)]
pub fn create_stream_event_channel() -> (StreamEventSender, StreamEventReceiver) {
    tokio::sync::mpsc::unbounded_channel()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_event_creation() {
        let event = AppEvent::UserMessage {
            content: "Hello".to_string(),
        };

        match event {
            AppEvent::UserMessage { content } => {
                assert_eq!(content, "Hello");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_assistant_message_event() {
        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({"path": "test.rs"}),
        );

        let event = AppEvent::AssistantMessage {
            content: "Let me read that".to_string(),
            tool_calls: Some(vec![tool_call]),
        };

        match event {
            AppEvent::AssistantMessage {
                content,
                tool_calls,
            } => {
                assert_eq!(content, "Let me read that");
                assert!(tool_calls.is_some());
                assert_eq!(tool_calls.unwrap().len(), 1);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_tool_execution_events() {
        let start_event = AppEvent::ToolExecutionStart {
            tool_name: "read_file".to_string(),
            arguments: serde_json::json!({"path": "test.rs"}),
        };

        match start_event {
            AppEvent::ToolExecutionStart {
                tool_name,
                arguments,
            } => {
                assert_eq!(tool_name, "read_file");
                assert_eq!(arguments["path"], "test.rs");
            }
            _ => panic!("Wrong event type"),
        }

        let result = ToolResult::success("read_file", "Contents", 100);
        let complete_event = AppEvent::ToolExecutionComplete {
            tool_name: "read_file".to_string(),
            result,
        };

        match complete_event {
            AppEvent::ToolExecutionComplete { tool_name, result } => {
                assert_eq!(tool_name, "read_file");
                assert!(result.success);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_event_channel() {
        let (tx, mut rx) = create_event_channel();

        tx.send(AppEvent::UserMessage {
            content: "Test".to_string(),
        })
        .unwrap();

        let event = rx.blocking_recv().unwrap();
        match event {
            AppEvent::UserMessage { content } => {
                assert_eq!(content, "Test");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_event_clone() {
        let event = AppEvent::Error {
            message: "Test error".to_string(),
        };

        let cloned = event.clone();
        match cloned {
            AppEvent::Error { message } => {
                assert_eq!(message, "Test error");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_tick_and_resize_events() {
        let tick_event = AppEvent::Tick;
        assert!(matches!(tick_event, AppEvent::Tick));

        let resize_event = AppEvent::Resize {
            width: 80,
            height: 24,
        };

        match resize_event {
            AppEvent::Resize { width, height } => {
                assert_eq!(width, 80);
                assert_eq!(height, 24);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_stream_event_text_chunk() {
        let event = StreamEvent::TextChunk("Hello ".to_string());

        match event {
            StreamEvent::TextChunk(chunk) => {
                assert_eq!(chunk, "Hello ");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_stream_event_tool_call_start() {
        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({"path": "test.rs"}),
        );

        let event = StreamEvent::ToolCallStart(tool_call.clone());

        match event {
            StreamEvent::ToolCallStart(tc) => {
                assert_eq!(tc.id, "call_1");
                assert_eq!(tc.name(), "read_file");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_stream_event_tool_call_result() {
        let result = ToolResult::success("read_file", "Contents", 100);
        let event = StreamEvent::ToolCallResult(result.clone());

        match event {
            StreamEvent::ToolCallResult(res) => {
                assert!(res.success);
                assert_eq!(res.output, "Contents");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_stream_event_complete_and_error() {
        let complete_event = StreamEvent::Complete;
        assert!(matches!(complete_event, StreamEvent::Complete));

        let error_event = StreamEvent::Error("Test error".to_string());
        match error_event {
            StreamEvent::Error(msg) => {
                assert_eq!(msg, "Test error");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_stream_event_channel() {
        let (tx, mut rx) = create_stream_event_channel();

        tx.send(StreamEvent::TextChunk("Test".to_string())).unwrap();

        let event = rx.blocking_recv().unwrap();
        match event {
            StreamEvent::TextChunk(chunk) => {
                assert_eq!(chunk, "Test");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_stream_event_clone() {
        let event = StreamEvent::Error("Test error".to_string());

        let cloned = event.clone();
        match cloned {
            StreamEvent::Error(msg) => {
                assert_eq!(msg, "Test error");
            }
            _ => panic!("Wrong event type"),
        }
    }
}
