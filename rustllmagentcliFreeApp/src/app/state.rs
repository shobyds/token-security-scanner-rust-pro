//! Global application state management

#![allow(clippy::must_use_candidate)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::module_name_repetitions)]

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::app::config::AppConfig;
use crate::app::event::{AppEvent, EventSender};
use crate::types::Message;

// Re-export scanner types for convenient access
pub use crate::scanner::{RedFlag, TriLabel, TriResult};

/// Scan state representing the current status of a token scan
#[derive(Debug, Clone, Default)]
pub enum ScanState {
    /// No scan in progress
    #[default]
    Idle,
    /// Currently scanning a token
    Scanning {
        /// Token address being scanned
        address: String,
        /// Blockchain network
        chain: String,
    },
    /// Scan completed with result
    Complete(TriResult),
    /// Scan failed with error
    Error(String),
}

/// Phi-3 LLM client status
#[derive(Debug, Clone, Default)]
pub enum Phi3Status {
    /// Status unknown (not yet checked)
    #[default]
    Unknown,
    /// Warming up the model
    WarmingUp,
    /// Model is ready for inference
    Ready,
    /// Error occurred
    Error(String),
}

impl Phi3Status {
    /// Check if the status is ready
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Check if there's an error
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }
}

/// Global application state
#[derive(Debug)]
pub struct AppState {
    /// Application configuration
    pub config: AppConfig,
    /// Working directory
    pub workdir: PathBuf,
    /// Event sender
    event_tx: Option<EventSender>,
    /// Conversation history
    conversation_history: Vec<Message>,
    /// Tool execution log
    tool_log: Vec<ToolLogEntry>,
    /// Current scan state
    pub scan_state: ScanState,
    /// Last TRI result (cached)
    pub last_tri: Option<TriResult>,
    /// Scan history (recent scans)
    pub scan_history: Vec<TriResult>,
    /// Current scan progress (0.0 - 1.0)
    pub scan_progress: f32,
    /// Telegram alerts sent (for rate limiting)
    pub telegram_alerts: Vec<TelegramAlertRecord>,
    /// Phi-3 LLM client status
    pub phi3_status: Phi3Status,
}

/// Record of a Telegram alert sent (for rate limiting)
#[derive(Debug, Clone)]
pub struct TelegramAlertRecord {
    /// Token address that triggered the alert
    pub token_address: String,
    /// Timestamp when alert was sent (Unix timestamp in seconds)
    pub sent_at: u64,
    /// Rug probability that triggered the alert
    pub rug_probability: f32,
}

/// Log entry for tool execution
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ToolLogEntry {
    /// Tool name
    pub tool_name: String,
    /// Arguments
    pub arguments: String,
    /// Result output
    pub output: String,
    /// Whether it was successful
    pub success: bool,
    /// Execution time in ms
    pub execution_time_ms: u64,
}

impl AppState {
    /// Create a new application state
    pub fn new(llm_url: String, model: String, workdir: String, config: AppConfig) -> Self {
        let mut state = Self {
            config,
            workdir: PathBuf::from(workdir),
            event_tx: None,
            conversation_history: Vec::new(),
            tool_log: Vec::new(),
            scan_state: ScanState::Idle,
            last_tri: None,
            scan_history: Vec::new(),
            scan_progress: 0.0,
            telegram_alerts: Vec::new(),
            phi3_status: Phi3Status::Unknown,
        };

        // Override config with CLI arguments
        state.config.llm.url = llm_url;
        state.config.llm.model = model;

        info!("AppState created with workdir: {:?}", state.workdir);
        state
    }

    /// Create `AppState` with default config
    #[allow(dead_code)]
    pub fn with_defaults(workdir: String) -> Self {
        let config = AppConfig::default();
        Self::new(
            config.llm.url.clone(),
            config.llm.model.clone(),
            workdir,
            config,
        )
    }

    /// Set the event sender
    #[allow(dead_code)]
    pub fn set_event_sender(&mut self, tx: EventSender) {
        self.event_tx = Some(tx);
    }

    /// Emit an event
    #[allow(dead_code)]
    pub fn emit_event(&self, event: AppEvent) {
        if let Some(ref tx) = self.event_tx {
            let _ = tx.send(event);
        }
    }

    /// Add a message to conversation history
    #[allow(dead_code)]
    pub fn add_message(&mut self, message: Message) {
        self.conversation_history.push(message);

        // Trim history if needed
        if self.conversation_history.len() > self.config.ui.max_chat_history {
            // Keep system message + recent messages
            let system_messages: Vec<_> = self
                .conversation_history
                .iter()
                .filter(|m| matches!(m.role, crate::types::Role::System))
                .cloned()
                .collect();

            let recent_messages: Vec<_> = self
                .conversation_history
                .iter()
                .filter(|m| !matches!(m.role, crate::types::Role::System))
                .skip(
                    self.conversation_history
                        .len()
                        .saturating_sub(self.config.ui.max_chat_history),
                )
                .cloned()
                .collect();

            self.conversation_history = system_messages;
            self.conversation_history.extend(recent_messages);
        }
    }

    /// Get conversation history
    #[allow(dead_code)]
    pub fn get_conversation_history(&self) -> &[Message] {
        &self.conversation_history
    }

    /// Get messages (alias for `get_conversation_history`, used by TUI)
    #[allow(dead_code)]
    pub fn get_messages(&self) -> &[Message] {
        &self.conversation_history
    }

    /// Clear conversation history
    #[allow(dead_code)]
    pub fn clear_conversation(&mut self) {
        self.conversation_history.clear();
        self.emit_event(AppEvent::ClearConversation);
    }

    /// Add a tool execution log entry
    #[allow(dead_code)]
    pub fn add_tool_log(&mut self, entry: ToolLogEntry) {
        self.tool_log.push(entry);

        // Trim log if needed
        if self.tool_log.len() > self.config.ui.max_tool_log {
            self.tool_log.remove(0);
        }
    }

    /// Get tool execution log
    #[allow(dead_code)]
    pub fn get_tool_log(&self) -> &[ToolLogEntry] {
        &self.tool_log
    }

    /// Clear tool log
    #[allow(dead_code)]
    pub fn clear_tool_log(&mut self) {
        self.tool_log.clear();
    }

    /// Get the absolute path for a relative path
    #[allow(dead_code)]
    pub fn resolve_path(&self, path: &std::path::Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.workdir.join(path)
        }
    }

    /// Get working directory
    #[allow(dead_code)]
    pub fn get_workdir(&self) -> &PathBuf {
        &self.workdir
    }
}

/// Thread-safe wrapper for `AppState`
#[allow(dead_code)]
pub type SharedAppState = Arc<Mutex<AppState>>;

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            workdir: self.workdir.clone(),
            event_tx: self.event_tx.clone(),
            conversation_history: self.conversation_history.clone(),
            tool_log: self.tool_log.clone(),
            scan_state: self.scan_state.clone(),
            last_tri: self.last_tri.clone(),
            scan_history: self.scan_history.clone(),
            scan_progress: self.scan_progress,
            telegram_alerts: self.telegram_alerts.clone(),
            phi3_status: self.phi3_status.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Role;

    #[test]
    fn test_app_state_creation() {
        let state = AppState::with_defaults(".".to_string());

        assert_eq!(state.workdir, PathBuf::from("."));
        assert!(state.event_tx.is_none());
        assert!(state.conversation_history.is_empty());
        assert!(state.tool_log.is_empty());
    }

    #[test]
    fn test_app_state_with_custom_config() {
        let mut config = AppConfig::default();
        config.llm.url = "http://custom:1234".to_string();
        config.llm.model = "custom-model".to_string();

        let state = AppState::new(
            "http://cli:1234".to_string(),
            "cli-model".to_string(),
            "/workspace".to_string(),
            config,
        );

        // CLI args should override config
        assert_eq!(state.config.llm.url, "http://cli:1234");
        assert_eq!(state.config.llm.model, "cli-model");
        assert_eq!(state.workdir, PathBuf::from("/workspace"));
    }

    #[test]
    fn test_add_message() {
        let mut state = AppState::with_defaults(".".to_string());

        state.add_message(Message::user("Hello"));
        state.add_message(Message::assistant("Hi there!"));

        assert_eq!(state.conversation_history.len(), 2);
        assert_eq!(state.conversation_history[0].role, Role::User);
        assert_eq!(state.conversation_history[1].role, Role::Assistant);
    }

    #[test]
    fn test_conversation_history_limit() {
        let mut state = AppState::with_defaults(".".to_string());
        state.config.ui.max_chat_history = 5;

        // Add system message
        state.add_message(Message::system("You are helpful"));

        // Add many messages
        for i in 0..20 {
            state.add_message(Message::user(format!("User {i}")));
            state.add_message(Message::assistant(format!("Assistant {i}")));
        }

        // Should have system + limited history
        assert!(state.conversation_history.len() <= state.config.ui.max_chat_history + 1);
    }

    #[test]
    fn test_clear_conversation() {
        let mut state = AppState::with_defaults(".".to_string());

        state.add_message(Message::user("Hello"));
        state.add_message(Message::assistant("Hi"));

        state.clear_conversation();

        assert!(state.conversation_history.is_empty());
    }

    #[test]
    fn test_tool_log() {
        let mut state = AppState::with_defaults(".".to_string());

        let entry = ToolLogEntry {
            tool_name: "read_file".to_string(),
            arguments: "{\"path\": \"test.rs\"}".to_string(),
            output: "File contents".to_string(),
            success: true,
            execution_time_ms: 100,
        };

        state.add_tool_log(entry.clone());

        assert_eq!(state.tool_log.len(), 1);
        assert_eq!(state.tool_log[0].tool_name, "read_file");
        assert!(state.tool_log[0].success);
    }

    #[test]
    fn test_tool_log_limit() {
        let mut state = AppState::with_defaults(".".to_string());
        state.config.ui.max_tool_log = 5;

        for i in 0..20 {
            state.add_tool_log(ToolLogEntry {
                tool_name: format!("tool_{i}"),
                arguments: String::new(),
                output: String::new(),
                success: true,
                execution_time_ms: 100,
            });
        }

        assert_eq!(state.tool_log.len(), 5);
        // Should have the most recent entries
        assert_eq!(state.tool_log[0].tool_name, "tool_15");
    }

    #[test]
    fn test_resolve_path() {
        let state = AppState::with_defaults("/workspace".to_string());

        let absolute = std::path::Path::new("/etc/config");
        let resolved = state.resolve_path(absolute);
        assert_eq!(resolved, PathBuf::from("/etc/config"));

        let relative = std::path::Path::new("src/main.rs");
        let resolved = state.resolve_path(relative);
        assert_eq!(resolved, PathBuf::from("/workspace/src/main.rs"));
    }

    #[test]
    fn test_get_workdir() {
        let state = AppState::with_defaults("/my/project".to_string());
        assert_eq!(state.get_workdir(), &PathBuf::from("/my/project"));
    }

    #[test]
    fn test_state_clone() {
        let mut state = AppState::with_defaults(".".to_string());
        state.add_message(Message::user("Test"));

        let cloned = state.clone();
        assert_eq!(cloned.workdir, state.workdir);
        assert_eq!(cloned.conversation_history.len(), 1);
    }
}
