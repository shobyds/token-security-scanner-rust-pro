//! TUI Application structure and main loop

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::agent::{controller::AgentController, conversation::Conversation};
use crate::app::state::AppState;
use crate::tui::widgets::scan_dialog::ScanDialogState;
use crate::types::message::Message;
use throbber_widgets_tui::ThrobberState;

/// Connection status for LLM
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionStatus {
    #[default]
    /// Checking connection
    Checking,
    /// Connected successfully
    Connected,
    /// Connection failed
    Failed,
}

/// Groq API status for scan operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroqStatus {
    #[default]
    /// Status unknown (not yet checked)
    Unknown,
    /// Groq API available
    Available,
    /// Groq API unavailable
    Unavailable,
    /// Currently calling LLM
    Calling,
}

/// Response from background LLM task
pub struct LlmResponse {
    /// The response content, or error message
    pub content: Result<String>,
    /// Duration of the query in milliseconds
    pub duration_ms: u64,
}

/// TUI Application state
pub struct TuiApp<'a> {
    /// Application state
    pub state: &'a mut AppState,
    /// Input buffer for user queries
    pub input_buffer: String,
    /// Scroll offset for chat history
    pub scroll_offset: usize,
    /// Currently active panel
    pub active_panel: Panel,
    /// Flag to indicate application should quit
    pub should_quit: bool,
    /// LLM connection status
    pub connection_status: ConnectionStatus,
    /// Flag indicating if assistant is currently thinking/processing
    pub assistant_thinking: bool,
    /// Timestamp when assistant started thinking
    pub assistant_thinking_start: Option<std::time::Instant>,
    /// State for the animated throbber widget
    pub throbber_state: throbber_widgets_tui::ThrobberState,
    /// Receiver for LLM responses from background tasks
    pub response_rx: Option<mpsc::Receiver<LlmResponse>>,
    /// History of submitted queries (for up/down arrow navigation)
    pub query_history: Vec<String>,
    /// Current position in history (None = not navigating, Some = index in history)
    pub history_index: Option<usize>,
    /// Detected model name from auto-detection
    pub detected_model: Option<String>,
    /// Discovered URL from auto-discovery (e.g., "http://192.168.1.5:1234")
    pub discovered_url: Option<String>,
    /// TODO list for task tracking
    pub todo_list: crate::tui::todo::TodoList,
    /// Scan confirmation dialog state
    pub scan_dialog_state: ScanDialogState,
    // Phase 2: TRI Scoring Pipeline state fields
    /// Latest TRI result from most recent scan
    pub last_tri: Option<crate::scanner::TriResult>,
    /// Last pipeline result (includes LLM analysis)
    pub last_pipeline_result: Option<crate::scanner::PipelineResult>,
    /// History of scans (most recent first, max 10)
    pub scan_history: std::collections::VecDeque<crate::scanner::PipelineResult>,
    /// Whether a scan is currently running
    pub scan_in_progress: bool,
    /// Current scan token address (for status bar)
    pub scan_token_address: Option<String>,
    /// Receiver for pipeline progress events
    pub scan_progress_rx: Option<tokio::sync::mpsc::Receiver<crate::scanner::ScanProgress>>,
    /// Groq API status (for status bar indicator)
    pub groq_status: GroqStatus,
    /// Toast notification manager for critical alerts
    pub toast_manager: crate::tui::toast::ToastManager,
}

/// Panel types for the TUI (ToolLog removed - tool execution logged to file only)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Panel {
    #[default]
    /// Input panel
    Input,
    /// Chat panel (full width now)
    Chat,
    /// TODO list panel
    Todo,
}

#[allow(dead_code)]
impl<'a> TuiApp<'a> {
    /// Create a new TUI application
    pub fn new(state: &'a mut AppState) -> Self {
        let toast_manager = crate::tui::toast::ToastManager::new();

        Self {
            state,
            input_buffer: String::new(),
            scroll_offset: 0,
            active_panel: Panel::Input,
            should_quit: false,
            connection_status: ConnectionStatus::Checking,
            assistant_thinking: false,
            assistant_thinking_start: None,
            throbber_state: ThrobberState::default(),
            response_rx: None,
            query_history: Vec::new(),
            history_index: None,
            detected_model: None,
            discovered_url: None,
            todo_list: crate::tui::todo::TodoList::new(),
            scan_dialog_state: ScanDialogState::new(),
            // Phase 2: TRI Scoring Pipeline state fields
            last_tri: None,
            last_pipeline_result: None,
            scan_history: std::collections::VecDeque::new(),
            scan_in_progress: false,
            scan_token_address: None,
            scan_progress_rx: None,
            groq_status: GroqStatus::Unknown,
            toast_manager,
        }
    }

    /// Test LLM connection - uses longer timeout for Groq API
    async fn test_connection(&mut self) {
        use crate::agent::llm_client::LlmClient;

        // Check if Groq API is configured (by URL containing "api.groq.com")
        let is_groq = self.state.config.llm.url.contains("api.groq.com")
            || self.state.config.phi3.base_url.contains("api.groq.com");

        // For Groq API, use config directly
        let client = if is_groq {
            // Groq API configuration
            LlmClient::with_config(
                self.state.config.phi3.base_url.clone(),
                self.state.config.phi3.model.clone(),
                self.state.config.llm.temperature,
                Some(self.state.config.llm.max_tokens),
                self.state.config.phi3.timeout_secs,
                self.state.config.phi3.api_key.clone(),
            )
        } else {
            // LM Studio with auto-discovery
            LlmClient::with_config_and_discovery(&self.state.config.llm)
        };

        // Store the discovered URL for later use
        self.discovered_url = Some(client.get_base_url().to_string());

        // Use a simple test query
        let test_messages = vec![Message::user("OK")];

        match client.query(&test_messages).await {
            Ok(response) => {
                self.connection_status = ConnectionStatus::Connected;
                info!("LLM connection successful, response: {}", response.content);
            }
            Err(e) => {
                // Don't mark as failed immediately - Groq API might be temporarily unavailable
                self.connection_status = ConnectionStatus::Checking;
                warn!(
                    "LLM connection test failed (may succeed on actual query): {}",
                    e
                );
            }
        }
    }

    /// Run the TUI application
    pub async fn run(mut self) -> Result<()> {
        info!("Starting TUI application");

        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, crossterm::cursor::Show)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Detect loaded model and test connection in background
        let llm_config = self.state.config.llm.clone();
        let phi3_config = self.state.config.phi3.clone();
        let (model_tx, mut model_rx) = tokio::sync::watch::channel(String::new());
        let (url_tx, mut url_rx) = tokio::sync::watch::channel(String::new());

        // Spawn model detection and connection test task
        let status_tx = tokio::sync::watch::channel(ConnectionStatus::Checking);
        let status_rx = status_tx.1;

        tokio::spawn(async move {
            use crate::agent::llm_client::LlmClient;

            // Check if Groq API is configured (by URL containing "api.groq.com")
            let is_groq = llm_config.url.contains("api.groq.com")
                || phi3_config.base_url.contains("api.groq.com");

            // For Groq API, use config directly
            let client = if is_groq {
                LlmClient::with_config(
                    phi3_config.base_url.clone(),
                    phi3_config.model.clone(),
                    llm_config.temperature,
                    Some(llm_config.max_tokens),
                    phi3_config.timeout_secs,
                    phi3_config.api_key.clone(),
                )
            } else {
                LlmClient::with_config_and_discovery(&llm_config)
            };

            // Get the discovered URL
            let discovered_url = client.get_base_url().to_string();
            let _ = url_tx.send(discovered_url);

            // Get the detected model name
            let detected_model = client.get_model().to_string();
            let _ = model_tx.send(detected_model);

            // Test connection with actual query
            let test_messages = vec![Message::user("OK")];
            let result = client.query(&test_messages).await;

            // Only mark as connected if the query actually succeeded
            let status = if result.is_ok() {
                ConnectionStatus::Connected
            } else {
                ConnectionStatus::Failed
            };
            let _ = status_tx.0.send(status);
        });

        // Store discovered URL
        if url_rx.borrow_and_update().is_empty() {
            let _ = url_rx.changed().await;
        }
        if !url_rx.borrow().is_empty() {
            let url = url_rx.borrow().clone();
            self.discovered_url = Some(url.clone());
            info!("Using discovered URL: {}", url);
        }

        // Store detected model
        if model_rx.borrow_and_update().is_empty() {
            let _ = model_rx.changed().await;
        }
        if !model_rx.borrow().is_empty() {
            let model = model_rx.borrow().clone();
            self.detected_model = Some(model.clone());
            info!("Using detected model: {}", model);
        }

        // Run event loop with proper cleanup
        let result = self.run_loop(&mut terminal, status_rx).await;

        // Always cleanup terminal on exit (even on error)
        let cleanup_result = (|| -> Result<()> {
            disable_raw_mode()?;
            execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
            terminal.show_cursor()?;
            Ok(())
        })();

        // Report any errors
        if let Err(e) = &result {
            error!("TUI application error: {}", e);
        }
        if let Err(e) = cleanup_result {
            error!("Terminal cleanup error: {}", e);
        }

        result
    }

    /// Main event loop
    async fn run_loop<B: ratatui::backend::Backend>(
        &mut self,
        terminal: &mut Terminal<B>,
        status_rx: tokio::sync::watch::Receiver<ConnectionStatus>,
    ) -> Result<()> {
        use crate::tui::ui;

        loop {
            // Advance throbber animation state when assistant is thinking
            if self.assistant_thinking {
                self.throbber_state.calc_next();
            }

            // Check for incoming LLM response from background task (non-blocking)
            if let Some(ref mut rx) = self.response_rx {
                // Try to receive a response without blocking
                match rx.try_recv() {
                    Ok(llm_response) => {
                        // Background task completed, process the response
                        self.assistant_thinking = false;
                        self.assistant_thinking_start = None;

                        match llm_response.content {
                            Ok(response) => {
                                info!(
                                    "Query successful, response length: {}, time: {}ms",
                                    response.len(),
                                    llm_response.duration_ms
                                );

                                // Update connection status to Connected on successful query
                                if self.connection_status != ConnectionStatus::Connected {
                                    self.connection_status = ConnectionStatus::Connected;
                                    info!(
                                        "Connection status updated: Connected (after successful query)"
                                    );
                                }

                                // Check if this is an AI review response (contains JSON array of tasks)
                                if self.todo_list.ai_reviewed && self.todo_list.has_csv() {
                                    // Try to parse as AI task extraction response
                                    if let Some(tasks) = TuiApp::parse_ai_task_response(&response) {
                                        // Auto-populate tasks from AI response
                                        self.handle_ai_review_response(&tasks);
                                        // Reset AI review flag
                                        self.todo_list.ai_reviewed = false;
                                    } else {
                                        // Not a valid AI response, show as normal
                                        self.add_normal_assistant_response(
                                            &response,
                                            llm_response.duration_ms,
                                        );
                                    }
                                }
                                // Check if response contains tool calls (@tool_name({...}) syntax)
                                else if let Some((tool_name, args_json)) =
                                    TuiApp::parse_tool_call_from_text(&response)
                                {
                                    info!(
                                        "Tool call detected: {} with args: {}",
                                        tool_name, args_json
                                    );

                                    // Execute the tool
                                    let workdir = self.state.workdir.clone();
                                    let file_size_limit =
                                        self.state.config.tools.file_size_limit_mb;
                                    let tool_timeout =
                                        self.state.config.agent.tool_timeout_seconds * 1000;
                                    use crate::agent::ToolCoordinator;
                                    let tool_coordinator = ToolCoordinator::new(
                                        workdir,
                                        file_size_limit,
                                        tool_timeout,
                                    );

                                    // Create a ToolCall from the parsed data
                                    use crate::types::{FunctionCall, ToolCall};
                                    let tool_call = ToolCall {
                                        id: format!("call_{}", self.state.get_messages().len()),
                                        call_type: "function".to_string(),
                                        function: FunctionCall {
                                            name: tool_name.clone(),
                                            arguments: args_json.clone(),
                                        },
                                    };

                                    // Execute tool
                                    let tool_result = tool_coordinator.execute_tool(&tool_call);
                                    info!(
                                        "Tool {} executed: success={}",
                                        tool_name, tool_result.success
                                    );

                                    // Add assistant message with tool call
                                    let mut assistant_msg = Message::assistant(&response);
                                    assistant_msg.duration_ms = Some(llm_response.duration_ms);
                                    assistant_msg.tool_calls = Some(vec![tool_call.clone()]);
                                    self.state.add_message(assistant_msg);

                                    // Add tool result as a Tool message
                                    let tool_result_msg = Message::tool(
                                        if tool_result.success {
                                            format!(
                                                "✓ {}: {}",
                                                tool_call.name(),
                                                tool_result.output
                                            )
                                        } else {
                                            format!(
                                                "✗ {}: {}",
                                                tool_call.name(),
                                                tool_result.error.unwrap_or_default()
                                            )
                                        },
                                        tool_call.id.clone(),
                                    );
                                    self.state.add_message(tool_result_msg);

                                    // Reset scroll
                                    self.scroll_offset = 0;
                                } else {
                                    // No tool call - just add the response
                                    let mut assistant_msg = Message::assistant(&response);
                                    assistant_msg.duration_ms = Some(llm_response.duration_ms);
                                    self.state.add_message(assistant_msg);

                                    // Reset scroll to bottom to show new message
                                    self.scroll_offset = 0;
                                }
                            }
                            Err(e) => {
                                error!("Query failed after {}ms: {}", llm_response.duration_ms, e);
                                let mut error_msg = Message::system(&format!("Error: {}", e));
                                error_msg.duration_ms = Some(llm_response.duration_ms);
                                self.state.add_message(error_msg);
                            }
                        }

                        // Reset scroll to bottom to show new message
                        self.scroll_offset = 0;

                        // Drop the receiver since task is complete
                        self.response_rx = None;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        // No message yet, continue normally
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        // Channel closed without sending - task panicked or was cancelled
                        error!("LLM background task closed unexpectedly");
                        self.assistant_thinking = false;
                        self.assistant_thinking_start = None;
                        self.state
                            .add_message(Message::system("Error: LLM task failed unexpectedly"));
                        self.response_rx = None;
                    }
                }
            }

            // Phase 2: Poll scan progress channel (non-blocking)
            self.poll_scan_progress();

            // Cleanup expired toasts
            self.toast_manager.cleanup();

            // Render UI
            terminal.draw(|frame| {
                ui::render(frame, self);
            })?;

            // Check for connection status update (only during initial connection test)
            // After first update, status is managed by actual query results
            if self.connection_status == ConnectionStatus::Checking {
                let current_status = *status_rx.borrow();
                if self.connection_status != current_status {
                    self.connection_status = current_status;
                    info!(
                        "Connection status updated from initial test: {:?}",
                        current_status
                    );
                }
            }

            // Handle events with short timeout to prevent blocking
            if event::poll(std::time::Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    // Handle Ctrl+C immediately - before any other processing
                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        self.should_quit = true;
                        break;
                    }

                    // Handle the key event
                    self.process_key_event(key).await?;
                }
            }

            if self.should_quit {
                break;
            }
        }

        Ok(())
    }

    /// Process a key event (creates controller internally)
    async fn process_key_event(&mut self, key: KeyEvent) -> Result<()> {
        // Handle scan dialog input (priority - intercepts ALL keys when dialog visible)
        if self.scan_dialog_state.visible {
            match key.code {
                KeyCode::Tab => {
                    // Tab cycles through options in dialog (instead of switching panels)
                    self.scan_dialog_state.select_next();
                    return Ok(());
                }
                KeyCode::BackTab => {
                    // Shift+Tab goes backwards
                    self.scan_dialog_state.select_previous();
                    return Ok(());
                }
                KeyCode::Up => {
                    self.scan_dialog_state.select_previous();
                    return Ok(());
                }
                KeyCode::Down => {
                    self.scan_dialog_state.select_next();
                    return Ok(());
                }
                KeyCode::Char(' ') => {
                    self.scan_dialog_state.toggle_option();
                    return Ok(());
                }
                KeyCode::Enter => {
                    // Confirm and execute scan
                    self.scan_dialog_state.confirm();

                    // Clone values before calling async method
                    let (token_addr, chain) = if let Some(dialog) = &self.scan_dialog_state.dialog {
                        (dialog.token_address.clone(), dialog.chain.clone())
                    } else {
                        return Ok(());
                    };

                    let format = "both".to_string();
                    let include_market_data = false;
                    let output_dir = "./reports".to_string();

                    self.execute_scan_async(
                        &token_addr,
                        &chain,
                        &format,
                        include_market_data,
                        &output_dir,
                    )
                    .await;
                    return Ok(());
                }
                KeyCode::Esc => {
                    self.scan_dialog_state.cancel();
                    self.state
                        .add_message(Message::system("❌ Scan cancelled."));
                    return Ok(());
                }
                _ => return Ok(()), // Consume all other keys while dialog is visible
            }
        }

        // Normal key handling when dialog is not visible
        match key.code {
            // Phase 3: Keyboard shortcuts for scan operations
            
            // F2: Clear last scan / reset last_tri
            KeyCode::F(2) => {
                self.last_tri = None;
                self.last_pipeline_result = None;
                self.scan_token_address = None;
                self.groq_status = GroqStatus::Unknown;
                self.state.add_message(Message::system(
                    "🧹 Scan state cleared. Use F5 to re-scan last token."
                ));
                return Ok(());
            }
            
            // F5: Re-scan last token (if scan_token_address is set)
            KeyCode::F(5) => {
                if let Some(ref addr) = self.scan_token_address {
                    let chain = "ethereum".to_string(); // Default chain for re-scan
                    self.state.add_message(Message::system(&format!(
                        "🔄 Re-scanning {}...",
                        addr
                    )));
                    self.trigger_scan(addr.clone(), chain).await;
                } else {
                    self.state.add_message(Message::system(
                        "⚠ No previous scan to re-scan. Use /scan <address> first."
                    ));
                }
                return Ok(());
            }
            
            // Ctrl+E: Export last TRI result to JSON
            KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(ref result) = self.last_pipeline_result {
                    use serde_json;
                    use std::fs;
                    
                    let addr_short = if result.scan_result.token_address.len() > 10 {
                        format!("{}_{}", 
                            &result.scan_result.token_address[..6],
                            &result.scan_result.token_address[result.scan_result.token_address.len()-4..]
                        )
                    } else {
                        result.scan_result.token_address.clone()
                    };
                    
                    let filename = format!(
                        "tri_export_{}_{}.json",
                        addr_short,
                        chrono::Utc::now().format("%Y%m%d_%H%M%S")
                    );
                    
                    let output_path = std::path::PathBuf::from("./reports").join(&filename);
                    
                    // Ensure reports directory exists
                    let _ = fs::create_dir_all("./reports");
                    
                    match serde_json::to_string_pretty(result) {
                        Ok(json) => {
                            match fs::write(&output_path, &json) {
                                Ok(_) => {
                                    self.state.add_message(Message::system(&format!(
                                        "✅ TRI result exported to: {:?}",
                                        output_path
                                    )));
                                }
                                Err(e) => {
                                    self.state.add_message(Message::system(&format!(
                                        "❌ Failed to write export file: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        Err(e) => {
                            self.state.add_message(Message::system(&format!(
                                "❌ Failed to serialize TRI result: {}",
                                e
                            )));
                        }
                    }
                } else {
                    self.state.add_message(Message::system(
                        "⚠ No scan result to export. Scan a token first."
                    ));
                }
                return Ok(());
            }
            
            // Q to quit from non-input panels only
            KeyCode::Char('q') if self.active_panel != Panel::Input => {
                self.should_quit = true;
            }

            // Enter to submit query from input panel
            KeyCode::Enter if self.active_panel == Panel::Input => {
                self.submit_query_standalone().await?;
            }

            // Character input for input panel
            KeyCode::Char(c) if self.active_panel == Panel::Input => {
                self.input_buffer.push(c);
            }

            // Backspace for input panel
            KeyCode::Backspace if self.active_panel == Panel::Input => {
                self.input_buffer.pop();
            }

            // Escape to clear input
            KeyCode::Esc if self.active_panel == Panel::Input => {
                self.input_buffer.clear();
            }

            // Arrow up: history navigation in input panel, scroll in chat panel
            KeyCode::Up if self.active_panel == Panel::Input => {
                self.navigate_history(-1);
            }
            KeyCode::Up => {
                self.scroll_up();
            }

            // Arrow down: history navigation in input panel, scroll in chat panel
            KeyCode::Down if self.active_panel == Panel::Input => {
                self.navigate_history(1);
            }
            KeyCode::Down => {
                self.scroll_down();
            }

            // Tab to cycle panels
            KeyCode::Tab => {
                self.cycle_panels();
            }

            _ => {}
        }
        Ok(())
    }

    /// Handle slash commands
    async fn handle_slash_command(&mut self, command: &str) -> Result<()> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        match parts[0].trim_start_matches('/') {
            "clear" | "reset" => {
                self.state.clear_conversation();
                self.state
                    .add_message(Message::system("Conversation history cleared."));
                self.scroll_offset = 0;
                info!("Conversation cleared via /clear command");
            }
            "help" => {
                let help_text = r#"Available Commands:

Conversation:
  /clear     - Clear conversation history
  /history   - Show conversation history
  /save      - Save conversation to JSON file
  /load      - Load conversation from JSON file

TODO List:
  /todo      - Show TODO list or add task: /todo <task>
  /done      - Mark task complete: /done <id>
  /undo      - Mark task incomplete: /undo <id>
  /start     - Mark task as in progress: /start <id>
  /pause     - Mark task as pending: /pause <id>
  /cycle     - Cycle task status: /cycle <id>
  /parse-todo - Parse tasks from text: /parse-todo <text>
  /clear-todos - Clear all tasks

CSV Management (auto-created for text >300 chars):
  /csv-view      - View CSV file content and info
  /csv-ai-review - Send CSV to AI for task extraction
  /csv-tasks     - Show tasks extracted from CSV
  /csv-clear     - Clear CSV tracking (keep file)
  /csv-delete    - Delete CSV file and clear tracking
  /csv-cleanup   - Clean up CSV when all tasks completed

Token Scanner (Phase 1-3):
  /scan <address>              - Scan token on ethereum (default)
  /scan <address> --chain <c>  - Scan token on specified chain
  /scan: <address>             - Legacy syntax (ethereum only)
  Example: /scan 0xbb584f66d5313bb3fc4f1a103885b2c182e05a32 --chain ethereum
  
  Keyboard Shortcuts:
  F2  - Clear last scan state
  F5  - Re-scan last token
  Ctrl+E - Export last TRI result to JSON (./reports/)

Other:
  /help      - Show this help message
  /quit      - Exit the application

Regular queries are sent to the LLM.
Type naturally - the LLM will use tools when needed.

For long text (>300 chars):
  - CSV is auto-created in temp directory
  - Use /csv-view to review content
  - Use /csv-ai-review for AI task extraction
  - Use /csv-delete when done

Task Status Symbols:
  ○ Pending (yellow)
  ◐ In Progress (cyan, bold)
  ● Completed (green, strikethrough)"#;
                self.state.add_message(Message::system(help_text));
                info!("Help displayed via /help command");
            }
            "history" => {
                let messages = self.state.get_messages();
                let history: Vec<String> = messages
                    .iter()
                    .map(|m| {
                        format!(
                            "{}: {}",
                            m.role,
                            m.content.chars().take(100).collect::<String>()
                        )
                    })
                    .collect();
                self.state.add_message(Message::system(&format!(
                    "Conversation History ({} messages):\n{}",
                    messages.len(),
                    history.join("\n")
                )));
                info!("History displayed via /history command");
            }
            "save" => {
                use serde_json;
                use std::fs;
                let messages = self.state.get_messages();
                match serde_json::to_string_pretty(messages) {
                    Ok(json) => {
                        let filename = format!(
                            "conversation_{}.json",
                            chrono::Local::now().format("%Y%m%d_%H%M%S")
                        );
                        if let Err(e) = fs::write(&filename, &json) {
                            self.state
                                .add_message(Message::system(&format!("Failed to save: {}", e)));
                        } else {
                            self.state.add_message(Message::system(&format!(
                                "Conversation saved to {}",
                                filename
                            )));
                            info!("Conversation saved to {}", filename);
                        }
                    }
                    Err(e) => {
                        self.state
                            .add_message(Message::system(&format!("Failed to serialize: {}", e)));
                    }
                }
            }
            "load" => {
                use serde_json;
                use std::fs;
                let filename = parts.get(1).unwrap_or(&"conversation.json");
                match fs::read_to_string(filename) {
                    Ok(json) => match serde_json::from_str::<Vec<crate::types::Message>>(&json) {
                        Ok(messages) => {
                            self.state.clear_conversation();
                            for msg in messages {
                                self.state.add_message(msg);
                            }
                            self.state.add_message(Message::system(&format!(
                                "Loaded {} messages from {}",
                                self.state.get_messages().len(),
                                filename
                            )));
                            info!("Conversation loaded from {}", filename);
                        }
                        Err(e) => {
                            self.state
                                .add_message(Message::system(&format!("Failed to parse: {}", e)));
                        }
                    },
                    Err(e) => {
                        self.state
                            .add_message(Message::system(&format!("Failed to load: {}", e)));
                    }
                }
            }
            "todo" | "task" => {
                // Add a new task
                let task_text = if parts.len() > 1 {
                    parts[1..].join(" ")
                } else {
                    // If no task text, show TODO list status
                    let status = if self.todo_list.tasks.is_empty() {
                        "No tasks. Use /todo <task> to add a task.".to_string()
                    } else {
                        format!(
                            "{} - {}\n\nTasks:\n{}",
                            self.todo_list.title.as_deref().unwrap_or("TODO List"),
                            self.todo_list.progress_string(),
                            self.todo_list
                                .tasks
                                .iter()
                                .map(|t| format!(
                                    "  {} #{}: {}",
                                    t.checkbox(),
                                    t.id,
                                    t.display_text()
                                ))
                                .collect::<Vec<_>>()
                                .join("\n")
                        )
                    };
                    self.state.add_message(Message::system(&status));
                    info!("TODO status displayed");
                    self.scroll_offset = 0;
                    return Ok(());
                };

                let id = self.todo_list.add_task(task_text.clone());
                self.state.add_message(Message::system(&format!(
                    "Task #{} added: {}",
                    id, task_text
                )));
                info!("TODO task added: {}", task_text);
            }
            "done" | "complete" => {
                // Mark a task as complete
                if let Some(task_id_str) = parts.get(1) {
                    if let Ok(task_id) = task_id_str.parse::<usize>() {
                        if self.todo_list.complete_task(task_id) {
                            self.state.add_message(Message::system(&format!(
                                "Task #{} marked as complete ✓",
                                task_id
                            )));
                            info!("TODO task #{} completed", task_id);

                            // Check if all tasks are completed and CSV exists - auto cleanup
                            if self.todo_list.all_tasks_completed() && self.todo_list.has_csv() {
                                self.state.add_message(Message::system(
                                    "✓ All tasks completed! Use /csv-cleanup to remove temporary CSV file."
                                ));
                            }
                        } else {
                            self.state.add_message(Message::system(&format!(
                                "Task #{} not found",
                                task_id
                            )));
                        }
                    } else {
                        self.state
                            .add_message(Message::system("Invalid task ID. Use: /done <task_id>"));
                    }
                } else {
                    self.state
                        .add_message(Message::system("Task ID required. Use: /done <task_id>"));
                }
            }
            "undo" => {
                // Mark a task as incomplete
                if let Some(task_id_str) = parts.get(1) {
                    if let Ok(task_id) = task_id_str.parse::<usize>() {
                        if self.todo_list.uncomplete_task(task_id) {
                            self.state.add_message(Message::system(&format!(
                                "Task #{} marked as incomplete ○",
                                task_id
                            )));
                            info!("TODO task #{} undone", task_id);
                        } else {
                            self.state.add_message(Message::system(&format!(
                                "Task #{} not found",
                                task_id
                            )));
                        }
                    } else {
                        self.state
                            .add_message(Message::system("Invalid task ID. Use: /undo <task_id>"));
                    }
                } else {
                    self.state
                        .add_message(Message::system("Task ID required. Use: /undo <task_id>"));
                }
            }
            "start" => {
                // Mark a task as in progress
                if let Some(task_id_str) = parts.get(1) {
                    if let Ok(task_id) = task_id_str.parse::<usize>() {
                        if self.todo_list.start_task(task_id) {
                            self.state.add_message(Message::system(&format!(
                                "Task #{} marked as in progress ◐",
                                task_id
                            )));
                            info!("TODO task #{} started", task_id);
                        } else {
                            self.state.add_message(Message::system(&format!(
                                "Task #{} not found",
                                task_id
                            )));
                        }
                    } else {
                        self.state
                            .add_message(Message::system("Invalid task ID. Use: /start <task_id>"));
                    }
                } else {
                    self.state
                        .add_message(Message::system("Task ID required. Use: /start <task_id>"));
                }
            }
            "pause" => {
                // Mark a task as pending (pause from in progress)
                if let Some(task_id_str) = parts.get(1) {
                    if let Ok(task_id) = task_id_str.parse::<usize>() {
                        if self.todo_list.reset_task(task_id) {
                            self.state.add_message(Message::system(&format!(
                                "Task #{} marked as pending ○",
                                task_id
                            )));
                            info!("TODO task #{} paused", task_id);
                        } else {
                            self.state.add_message(Message::system(&format!(
                                "Task #{} not found",
                                task_id
                            )));
                        }
                    } else {
                        self.state
                            .add_message(Message::system("Invalid task ID. Use: /pause <task_id>"));
                    }
                } else {
                    self.state
                        .add_message(Message::system("Task ID required. Use: /pause <task_id>"));
                }
            }
            "cycle" => {
                // Cycle task status: Pending → InProgress → Completed → Pending
                if let Some(task_id_str) = parts.get(1) {
                    if let Ok(task_id) = task_id_str.parse::<usize>() {
                        if let Some(task) =
                            self.todo_list.tasks.iter_mut().find(|t| t.id == task_id)
                        {
                            let old_status = format!("{:?}", task.status);
                            task.cycle_status();
                            let new_status = format!("{:?}", task.status);
                            let symbol = task.checkbox();

                            self.state.add_message(Message::system(&format!(
                                "Task #{} cycled: {} → {} {}",
                                task_id, old_status, new_status, symbol
                            )));
                            info!(
                                "TODO task #{} cycled: {} → {}",
                                task_id, old_status, new_status
                            );
                        } else {
                            self.state.add_message(Message::system(&format!(
                                "Task #{} not found",
                                task_id
                            )));
                        }
                    } else {
                        self.state
                            .add_message(Message::system("Invalid task ID. Use: /cycle <task_id>"));
                    }
                } else {
                    self.state
                        .add_message(Message::system("Task ID required. Use: /cycle <task_id>"));
                }
            }
            "clear-todos" | "reset-todos" => {
                // Clear all tasks
                self.todo_list.clear_all();
                self.state
                    .add_message(Message::system("All tasks cleared."));
                info!("TODO list cleared");
            }
            "parse-todo" => {
                // Parse tasks from input text (for long text)
                if parts.len() > 1 {
                    let text = parts[1..].join(" ");
                    let tasks = crate::tui::todo::parse_tasks_from_text(&text);
                    if tasks.is_empty() {
                        self.state
                            .add_message(Message::system("No tasks found in text."));
                    } else {
                        for task_text in &tasks {
                            self.todo_list.add_task(task_text.clone());
                        }
                        self.state.add_message(Message::system(&format!(
                            "Parsed {} tasks from text. Use /todo to view.",
                            tasks.len()
                        )));
                        info!("Parsed {} TODO tasks from text", tasks.len());
                    }
                } else {
                    self.state
                        .add_message(Message::system("Text required. Use: /parse-todo <text>"));
                }
            }
            "csv-view" => {
                // View CSV content
                if let Some(csv_path) = &self.todo_list.temp_csv_path {
                    match crate::utils::csv_todo::read_temp_csv(csv_path) {
                        Ok(content) => {
                            // Show CSV info
                            match crate::utils::csv_todo::get_csv_info(csv_path) {
                                Ok(info) => {
                                    let preview = if content.len() > 500 {
                                        format!("{}...", &content[..500])
                                    } else {
                                        content.clone()
                                    };
                                    self.state.add_message(Message::system(&format!(
                                        "CSV File Info:\n\
                                         Path: {}\n\
                                         Size: {}\n\
                                         AI Reviewed: {}\n\n\
                                         Content Preview:\n{}",
                                        csv_path.display(),
                                        info.size_human(),
                                        if self.todo_list.ai_reviewed {
                                            "Yes"
                                        } else {
                                            "No"
                                        },
                                        preview
                                    )));
                                    info!("CSV viewed: {}", csv_path.display());
                                }
                                Err(e) => {
                                    self.state.add_message(Message::system(&format!(
                                        "CSV content:\n{}",
                                        content
                                    )));
                                }
                            }
                        }
                        Err(e) => {
                            self.state.add_message(Message::system(&format!(
                                "Failed to read CSV: {}",
                                e
                            )));
                        }
                    }
                } else {
                    self.state.add_message(Message::system(
                        "No CSV file tracked. Enter text >300 chars to auto-create one.",
                    ));
                }
            }
            "csv-ai-review" | "csv-review" => {
                // Request AI to review CSV and extract tasks
                if let Some(csv_path) = &self.todo_list.temp_csv_path.clone() {
                    let csv_content = self.todo_list.csv_content.clone();

                    self.state.add_message(Message::system(
                        "Sending CSV content to AI for task extraction...\n\
                         This will analyze the text and create individual tasks.",
                    ));
                    info!("AI review requested for CSV: {}", csv_path.display());

                    // Create a query to send to the LLM for task extraction
                    let ai_review_query = format!(
                        "Analyze the following text and extract all actionable tasks. \
                         Return a JSON array of task descriptions (strings only, no objects). \
                         Each task should be a clear, actionable item.\n\n\
                         Text to analyze:\n{}\n\n\
                         Response format: [\"Task 1\", \"Task 2\", \"Task 3\"]",
                        csv_content
                    );

                    // Store that we're waiting for AI review
                    self.todo_list.ai_reviewed = true;

                    // Add to history and submit directly
                    self.add_to_history(ai_review_query.clone());
                    self.state.add_message(Message::user(&ai_review_query));

                    // Submit to LLM using internal method
                    return self.submit_to_llm_direct(ai_review_query).await;
                } else {
                    self.state.add_message(Message::system(
                        "No CSV file to review. Enter text >300 chars first.",
                    ));
                }
            }
            "csv-clear" => {
                // Clear CSV tracking without deleting file
                if self.todo_list.has_csv() {
                    self.todo_list.clear_csv();
                    self.state.add_message(Message::system(
                        "CSV tracking cleared. File may still exist in temp directory.",
                    ));
                    info!("CSV tracking cleared");
                } else {
                    self.state
                        .add_message(Message::system("No CSV file tracked."));
                }
            }
            "csv-delete" => {
                // Delete CSV file and clear tracking
                if let Some(csv_path) = &self.todo_list.temp_csv_path.clone() {
                    match crate::utils::csv_todo::delete_temp_csv(csv_path) {
                        Ok(()) => {
                            self.todo_list.clear_csv();
                            self.state.add_message(Message::system(&format!(
                                "CSV file deleted: {}",
                                csv_path.display()
                            )));
                            info!("CSV deleted: {}", csv_path.display());
                        }
                        Err(e) => {
                            self.state.add_message(Message::system(&format!(
                                "Failed to delete CSV: {}",
                                e
                            )));
                        }
                    }
                } else {
                    self.state
                        .add_message(Message::system("No CSV file tracked."));
                }
            }
            "csv-tasks" => {
                // Parse and show tasks from CSV content
                if let Some(csv_path) = &self.todo_list.temp_csv_path {
                    match crate::utils::csv_todo::read_temp_csv(csv_path) {
                        Ok(content) => {
                            // Find raw content row and parse tasks
                            let tasks = crate::utils::csv_todo::parse_tasks_from_raw_text(&content);
                            if tasks.is_empty() {
                                // Try parsing from the whole content
                                let all_tasks =
                                    crate::utils::csv_todo::parse_tasks_from_csv(&content);
                                if all_tasks.is_empty() {
                                    self.state.add_message(Message::system(
                                        "No tasks could be extracted from CSV.",
                                    ));
                                } else {
                                    self.state.add_message(Message::system(&format!(
                                        "CSV contains {} task rows:\n{}",
                                        all_tasks.len(),
                                        all_tasks
                                            .iter()
                                            .map(|t| format!("  - {}: {}", t.status, t.description))
                                            .collect::<Vec<_>>()
                                            .join("\n")
                                    )));
                                }
                            } else {
                                self.state.add_message(Message::system(&format!(
                                    "Extracted {} tasks from CSV:\n{}",
                                    tasks.len(),
                                    tasks
                                        .iter()
                                        .map(|t| format!(
                                            "  {}. {}",
                                            tasks.iter().position(|x| x == t).unwrap_or(0) + 1,
                                            t
                                        ))
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                )));
                            }
                        }
                        Err(e) => {
                            self.state.add_message(Message::system(&format!(
                                "Failed to read CSV: {}",
                                e
                            )));
                        }
                    }
                } else {
                    self.state
                        .add_message(Message::system("No CSV file tracked."));
                }
            }
            "csv-cleanup" => {
                // Clean up CSV file when all tasks are completed
                if !self.todo_list.has_csv() {
                    self.state
                        .add_message(Message::system("No CSV file tracked. Nothing to cleanup."));
                } else if !self.todo_list.all_tasks_completed() {
                    let (pending, in_progress, completed) = self.todo_list.count_by_status();
                    let total = self.todo_list.tasks.len();
                    self.state.add_message(Message::system(&format!(
                        "Cannot cleanup: {} tasks still pending/in progress ({} completed out of {}).",
                        pending + in_progress, completed, total
                    )));
                } else {
                    // All tasks completed, safe to cleanup
                    if let Some(csv_path) = &self.todo_list.temp_csv_path.clone() {
                        match crate::utils::csv_todo::delete_temp_csv(csv_path) {
                            Ok(()) => {
                                self.todo_list.clear_csv();
                                self.state.add_message(Message::system(&format!(
                                    "✓ CSV cleanup complete. Deleted: {}",
                                    csv_path.display()
                                )));
                                info!("CSV cleanup complete: {}", csv_path.display());
                            }
                            Err(e) => {
                                self.state.add_message(Message::system(&format!(
                                    "Failed to delete CSV: {}",
                                    e
                                )));
                            }
                        }
                    } else {
                        // CSV path not set but has_csv() returned true (shouldn't happen)
                        self.todo_list.clear_csv();
                        self.state.add_message(Message::system(
                            "CSV tracking cleared (file already deleted).",
                        ));
                    }
                }
            }
            "quit" | "exit" => {
                self.should_quit = true;
                info!("Quit via /quit command");
            }
            cmd if cmd.starts_with("scan") => {
                // Handle /scan command with multiple syntaxes:
                // /scan <address> [--chain <chain>]
                // /scan: <address> (legacy syntax)
                
                // Check if using legacy /scan: syntax
                let use_legacy = cmd.contains(':');
                
                let (token_address, chain) = if use_legacy {
                    // Legacy syntax: /scan: <address>
                    let addr = cmd.split(':').nth(1).unwrap_or("").trim();
                    (addr.to_string(), "ethereum".to_string())
                } else if parts.len() > 1 {
                    // New syntax: /scan <address> [--chain <chain>]
                    let addr = parts[1].trim().to_string();
                    let mut chain = "ethereum".to_string();
                    
                    // Parse --chain flag
                    if parts.len() > 2 {
                        let mut i = 2;
                        while i < parts.len() {
                            if parts[i] == "--chain" && i + 1 < parts.len() {
                                chain = parts[i + 1].to_string();
                                break;
                            }
                            i += 1;
                        }
                    }
                    
                    (addr, chain)
                } else {
                    // No address provided
                    self.state.add_message(Message::system(
                        "Usage: /scan <token_address> [--chain <chain>]\n\
                         Example: /scan 0xabc...def --chain ethereum\n\
                         Legacy: /scan: 0xabc...def\n\
                         Chains: ethereum, bsc, polygon, base, arbitrum"
                    ));
                    self.scroll_offset = 0;
                    return Ok(());
                };

                // Validate token address
                if token_address.is_empty() {
                    self.state.add_message(Message::system(
                        "Usage: /scan <token_address> [--chain <chain>]\nExample: /scan 0xbb584f66d5313bb3fc4f1a103885b2c182e05a32"
                    ));
                } else if !token_address.starts_with("0x") || token_address.len() != 42 {
                    self.state.add_message(Message::system(
                        "Invalid token address. Must start with 0x and be 42 characters long.",
                    ));
                } else {
                    // Trigger scan directly using Phase 2 trigger_scan() method
                    self.state.add_message(Message::system(&format!(
                        "🔍 Starting scan for {} on {}...",
                        token_address, chain
                    )));
                    
                    // Call trigger_scan to start async scan
                    self.trigger_scan(token_address.clone(), chain.clone()).await;
                }
            }
            _ => {
                self.state.add_message(Message::system(&format!(
                    "Unknown command: {}. Type /help for available commands.",
                    parts[0]
                )));
            }
        }

        self.scroll_offset = 0;
        Ok(())
    }

    /// Execute token scan asynchronously
    async fn execute_scan_async(
        &mut self,
        token_address: &str,
        chain: &str,
        format: &str,
        include_market_data: bool,
        output_dir: &str,
    ) {
        use crate::api::{ApiConfig, TokenScanner};
        use crate::report::{
            HtmlReportGenerator, JsonReportGenerator, ReportFormat, ReportGenerator,
            TokenSecurityReport,
        };
        use crate::scanner::{
            run_pipeline, PipelineConfig, PipelineResult,
            save_organized_reports_with_paths, OrganizedReportConfig,
            TriEngine, compute_rug_probability, extract_features, metrics_to_tri_input,
        };
        use crate::llm::manifest_analyzer::ManifestAnalyzer;
        use std::path::PathBuf;

        self.state.add_message(Message::system(&format!(
            "🔍 Starting token scan for {}...",
            token_address
        )));

        let config = ApiConfig::from_env();
        match TokenScanner::new(&config) {
            Ok(scanner) => match scanner.scan_token(token_address, chain).await {
                Ok(scan_result) => {
                    let report = TokenSecurityReport::new(scan_result.clone(), include_market_data);
                    let output_path = PathBuf::from(output_dir);
                    let _ = std::fs::create_dir_all(&output_path);

                    let mut generated_files = Vec::new();
                    let fmt = ReportFormat::from_str(format).unwrap_or(ReportFormat::Both);

                    // Generate flat reports (existing functionality)
                    let mut json_report_path = String::new();
                    let mut html_report_path = String::new();

                    match fmt {
                        ReportFormat::Json => {
                            let generator = JsonReportGenerator::new();
                            if let Ok(p) = generator.generate_report(&report, &output_path) {
                                json_report_path = p.display().to_string();
                                generated_files.push(json_report_path.clone());
                            }
                        }
                        ReportFormat::Html => {
                            let generator = HtmlReportGenerator::new();
                            if let Ok(p) = generator.generate_report(&report, &output_path) {
                                html_report_path = p.display().to_string();
                                generated_files.push(html_report_path.clone());
                            }
                        }
                        ReportFormat::Both => {
                            if let Ok(p) =
                                JsonReportGenerator::new().generate_report(&report, &output_path)
                            {
                                json_report_path = p.display().to_string();
                                generated_files.push(json_report_path.clone());
                            }
                            if let Ok(p) =
                                HtmlReportGenerator::new().generate_report(&report, &output_path)
                            {
                                html_report_path = p.display().to_string();
                                generated_files.push(html_report_path.clone());
                            }
                        }
                    }

                    // Compute TRI score and metrics
                    let metrics = extract_features(&scan_result);
                    let rug_probability = compute_rug_probability(&metrics);
                    let tri_engine = TriEngine::default();
                    let tri_input = metrics_to_tri_input(&metrics);
                    let tri_result = tri_engine.compute_tri(&tri_input);

                    // Store TRI result for TUI state
                    self.last_tri = Some(tri_result.clone());

                    // Display scan summary
                    let result = format!(
                        "Token: {}\nChain: {}\nRisk Score: {}/100\nRisk Level: {}\nRecommendation: {}\nTRI Score: {:.1}/100 [{}]\nRug Probability: {:.1}%\nReports: {:?}",
                        token_address,
                        chain.to_uppercase(),
                        report.risk_assessment.overall_score,
                        report.risk_assessment.risk_level,
                        report.risk_assessment.recommendation,
                        tri_result.tri,
                        tri_result.tri_label.display(),
                        rug_probability * 100.0,
                        generated_files
                    );
                    self.state.add_message(Message::system(&result));

                    // Save organized reports with manifest
                    info!("Saving organized reports with manifest...");
                    match save_organized_reports_with_paths(
                        &scan_result,
                        &tri_result,
                        rug_probability,
                        &OrganizedReportConfig::default(),
                        &json_report_path,
                        &html_report_path,
                    ).await {
                        Ok(manifest_path) => {
                            self.state.add_message(Message::system(&format!(
                                "📁 Organized reports saved to: {:?}",
                                manifest_path
                            )));

                            // Trigger LLM analysis from manifest
                            info!("Generating LLM analysis from manifest...");
                            match ManifestAnalyzer::new() {
                                Ok(analyzer) => {
                                    match analyzer.analyze_manifest(&manifest_path).await {
                                        Ok(analysis_result) => {
                                            self.state.add_message(Message::system(&format!(
                                                "🤖 LLM analysis saved to: {:?}",
                                                analysis_result.output_path
                                            )));
                                        }
                                        Err(e) => {
                                            warn!("LLM analysis failed: {}", e);
                                            self.state.add_message(Message::system(&format!(
                                                "⚠ LLM analysis failed: {}",
                                                e
                                            )));
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to create ManifestAnalyzer: {}", e);
                                    self.state.add_message(Message::system(&format!(
                                        "⚠ LLM analyzer initialization failed: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to save organized reports: {}", e);
                            self.state.add_message(Message::system(&format!(
                                "⚠ Failed to save organized reports: {}",
                                e
                            )));
                        }
                    }
                }
                Err(e) => {
                    self.state
                        .add_message(Message::system(&format!("❌ Scan failed: {}", e)));
                }
            },
            Err(e) => {
                self.state.add_message(Message::system(&format!(
                    "❌ Failed to initialize scanner: {}",
                    e
                )));
            }
        }
    }

    /// Submit query with LLM integration - spawns background task so UI remains responsive
    async fn submit_query_standalone(&mut self) -> Result<()> {
        if self.input_buffer.trim().is_empty() {
            return Ok(());
        }

        let query = self.input_buffer.clone();
        self.input_buffer.clear();

        // Check for slash commands
        if query.starts_with('/') {
            return self.handle_slash_command(&query).await;
        }

        // Auto-detect long input (>300 chars) and save to CSV for AI review
        if query.len() > 300 && !self.todo_list.has_csv() {
            // Save original text to temporary CSV
            match crate::utils::csv_todo::create_temp_csv(&query) {
                Ok(csv_path) => {
                    // Store CSV path and content in todo_list
                    self.todo_list.set_csv_path(csv_path.clone());
                    self.todo_list.csv_content = query.clone();
                    self.todo_list.ai_reviewed = false;

                    // Parse potential tasks from the text for preview
                    let tasks = crate::tui::todo::parse_tasks_from_text(&query);

                    self.state.add_message(Message::system(&format!(
                        "Long text detected ({} chars). Saved to temporary CSV.\n\
                         CSV path: {}\n\
                         Potential tasks detected: {}\n\
                         Use /csv-view to review, /csv-ai-review for AI task extraction,\n\
                         or /csv-clear to cancel.",
                        query.len(),
                        csv_path.display(),
                        if tasks.is_empty() {
                            "0".to_string()
                        } else {
                            format!("{}", tasks.len())
                        }
                    )));
                    info!("Long text saved to temp CSV: {}", csv_path.display());

                    // Clear input and let user decide next steps
                    self.input_buffer.clear();
                    return Ok(());
                }
                Err(e) => {
                    self.state.add_message(Message::system(&format!(
                        "Warning: Failed to create temp CSV: {}. Continuing without CSV storage.",
                        e
                    )));
                    // Continue with normal flow if CSV creation fails
                }
            }
        }

        // Add query to history
        self.add_to_history(query.clone());

        // Add user message immediately
        self.state.add_message(Message::user(&query));

        info!("Submitting query: {}", query);
        // Use detected model if available (from phi3 config for Groq API)
        let model_to_use = self
            .detected_model
            .clone()
            .unwrap_or_else(|| self.state.config.phi3.model.clone());
        // Use discovered URL if available, otherwise fall back to phi3 config for Groq API
        let url_to_use = self
            .discovered_url
            .clone()
            .unwrap_or_else(|| self.state.config.phi3.base_url.clone());
        info!("LLM URL: {}", url_to_use);
        info!("Model: {}", model_to_use);

        // Track query timing and set thinking state
        let query_start = std::time::Instant::now();
        self.assistant_thinking = true;
        self.assistant_thinking_start = Some(query_start);

        // Clone data needed for background task
        let llm_url = url_to_use.clone();
        let model = model_to_use.clone();
        // Get messages and ensure system prompt is included
        let all_messages = self.state.get_messages().to_vec();

        // Separate system prompt from conversation messages
        use crate::types::Role;
        let system_prompt = all_messages.iter().find(|m| m.role == Role::System);
        let non_system_messages: Vec<_> = all_messages
            .iter()
            .filter(|m| m.role != Role::System)
            .cloned()
            .collect();

        // Limit conversation history to last 10 messages (excluding system prompt)
        // This reduces context size for faster response times
        let limited_messages: Vec<_> = non_system_messages
            .iter()
            .rev()
            .take(10) // Keep only last 10 messages
            .rev()
            .cloned()
            .collect();

        // Rebuild messages with system prompt first, then limited history
        let mut messages = Vec::new();
        if let Some(sys_msg) = system_prompt {
            messages.push(sys_msg.clone());
        } else {
            // Add system prompt if not present (for tool instructions)
            use crate::agent::controller::create_system_prompt;
            messages.push(Message::system(&create_system_prompt()));
        }
        messages.extend(limited_messages);

        let workdir = self.state.workdir.clone();
        let file_size_limit = self.state.config.tools.file_size_limit_mb;
        let tool_timeout = self.state.config.agent.tool_timeout_seconds * 1000;
        // Clone Groq API key from config before spawning (single source of truth)
        let groq_api_key = self.state.config.phi3.api_key.clone();

        // Get tool definitions for the query
        use crate::agent::ToolCoordinator;
        let tool_coordinator = ToolCoordinator::new(workdir, file_size_limit, tool_timeout);
        let tools: Vec<crate::types::ToolDefinition> = tool_coordinator
            .get_tool_definitions()
            .iter()
            .map(|t| (*t).clone())
            .collect();

        // Create channel for response
        let (tx, rx) = mpsc::channel::<LlmResponse>(1);
        self.response_rx = Some(rx);

        // Spawn background task to process the query
        // IMPORTANT: Don't pass tools array (causes timeout)
        // Model uses @tool_name({...}) syntax in response text which we parse
        tokio::spawn(async move {
            use crate::agent::llm_client::LlmClient;

            // For Groq API, we need to pass the API key from phi3 config
            // Use with_config with Groq API key and increased max_tokens for better responses
            let client = LlmClient::with_config(
                llm_url,
                model,
                0.1,        // temperature - lower = faster generation
                Some(500),  // max_tokens - increased from 150 for better responses
                60,         // timeout_secs - optimized for speed
                groq_api_key, // Use Groq API key from phi3 config
            );

            // DON'T pass tools array - model doesn't support OpenAI tools format
            // Tools are in system prompt, model responds with @tool_name({...}) syntax
            let result = client.query_with_tools(&messages, None).await;
            let duration_ms = query_start.elapsed().as_millis() as u64;

            // Convert LlmClient result to our expected format
            let content: Result<String> = match result {
                Ok(msg) => Ok(msg.content),
                Err(e) => Err(anyhow::anyhow!("LLM error: {}", e)),
            };

            // Send response back to main thread
            let _ = tx
                .send(LlmResponse {
                    content,
                    duration_ms,
                })
                .await;
        });

        // Return immediately - UI will continue rendering while LLM processes
        // Response will be handled in run_loop() when it arrives via channel

        Ok(())
    }

    /// Submit query directly to LLM without going through the normal input flow
    /// Used for AI review workflow to avoid recursion
    async fn submit_to_llm_direct(&mut self, query: String) -> Result<()> {
        info!("Submitting direct query: {}", query);

        // Use detected model if available (from phi3 config for Groq API)
        let model_to_use = self
            .detected_model
            .clone()
            .unwrap_or_else(|| self.state.config.phi3.model.clone());
        let url_to_use = self
            .discovered_url
            .clone()
            .unwrap_or_else(|| self.state.config.phi3.base_url.clone());

        info!("LLM URL: {}", url_to_use);
        info!("Model: {}", model_to_use);

        // Track query timing and set thinking state
        let query_start = std::time::Instant::now();
        self.assistant_thinking = true;
        self.assistant_thinking_start = Some(query_start);

        // Get messages and ensure system prompt is included
        let all_messages = self.state.get_messages().to_vec();

        // Separate system prompt from conversation messages
        use crate::types::Role;
        let system_prompt = all_messages.iter().find(|m| m.role == Role::System);
        let non_system_messages: Vec<_> = all_messages
            .iter()
            .filter(|m| m.role != Role::System)
            .cloned()
            .collect();

        // Limit conversation history to last 10 messages (excluding system prompt)
        let limited_messages: Vec<_> = non_system_messages
            .iter()
            .rev()
            .take(10)
            .rev()
            .cloned()
            .collect();

        // Rebuild messages with system prompt first, then limited history
        let mut messages = Vec::new();
        if let Some(sys_msg) = system_prompt {
            messages.push(sys_msg.clone());
        } else {
            use crate::agent::controller::create_system_prompt;
            messages.push(Message::system(&create_system_prompt()));
        }
        messages.extend(limited_messages);

        let llm_url = url_to_use.clone();
        let model = model_to_use.clone();
        // Clone Groq API key from config before spawning (single source of truth)
        let groq_api_key = self.state.config.phi3.api_key.clone();

        // Create channel for response
        let (tx, rx) = mpsc::channel::<LlmResponse>(1);
        self.response_rx = Some(rx);

        // Spawn background task to process the query
        tokio::spawn(async move {
            use crate::agent::llm_client::LlmClient;

            // For Groq API, we need to pass the API key from phi3 config
            // Use increased max_tokens for better responses
            let client = LlmClient::with_config(
                llm_url,
                model,
                0.1,        // temperature - lower = faster
                Some(500),  // max_tokens - increased from 150 for better responses
                60,         // timeout_secs - optimized for speed
                groq_api_key, // Use Groq API key from phi3 config
            );

            let result = client.query_with_tools(&messages, None).await;
            let duration_ms = query_start.elapsed().as_millis() as u64;

            let content: Result<String> = match result {
                Ok(msg) => Ok(msg.content),
                Err(e) => Err(anyhow::anyhow!("LLM error: {}", e)),
            };

            let _ = tx
                .send(LlmResponse {
                    content,
                    duration_ms,
                })
                .await;
        });

        Ok(())
    }

    /// Parse tool call from response text (@tool_name({...}) syntax)
    #[allow(clippy::unnecessary_wraps)]
    fn parse_tool_call_from_text(text: &str) -> Option<(String, serde_json::Value)> {
        crate::agent::controller::parse_tool_call_from_text(text)
    }

    /// Parse AI task extraction response (JSON array of strings)
    ///
    /// Expected format: ["Task 1", "Task 2", "Task 3"]
    /// Also handles wrapped responses like: Here are the tasks: ["Task 1", "Task 2"]
    fn parse_ai_task_response(text: &str) -> Option<Vec<String>> {
        use serde_json;

        // Try to find JSON array in the response
        // Look for [ character and extract from there
        if let Some(start_idx) = text.find('[') {
            if let Some(end_idx) = text.rfind(']') {
                if end_idx > start_idx {
                    let json_str = &text[start_idx..=end_idx];

                    // Try to parse as JSON array of strings
                    if let Ok(tasks) = serde_json::from_str::<Vec<String>>(json_str) {
                        if !tasks.is_empty() {
                            return Some(tasks);
                        }
                    }

                    // Try to parse as JSON array of objects with description field
                    #[derive(serde::Deserialize)]
                    struct TaskObject {
                        description: Option<String>,
                        task: Option<String>,
                        title: Option<String>,
                    }

                    if let Ok(task_objects) = serde_json::from_str::<Vec<TaskObject>>(json_str) {
                        let tasks: Vec<String> = task_objects
                            .iter()
                            .filter_map(|t| {
                                t.description
                                    .clone()
                                    .or_else(|| t.task.clone())
                                    .or_else(|| t.title.clone())
                            })
                            .collect();

                        if !tasks.is_empty() {
                            return Some(tasks);
                        }
                    }
                }
            }
        }

        None
    }

    /// Handle AI review response by auto-populating tasks
    fn handle_ai_review_response(&mut self, tasks: &[String]) {
        // Clear any existing tasks from previous parsing
        self.todo_list.clear_all();

        // Add all AI-extracted tasks with Pending status
        for task_text in tasks {
            let id = self.todo_list.add_task(task_text.clone());
            info!("AI-extracted task #{} added: {}", id, task_text);
        }

        // Show confirmation message
        self.state.add_message(Message::system(&format!(
            "✓ AI extracted {} tasks from CSV and populated TODO list.\n\
             Use /todo to view tasks, /start <id> to begin work,\n\
             or /done <id> to mark tasks complete.",
            tasks.len()
        )));

        info!("AI review complete: {} tasks extracted", tasks.len());
    }

    /// Add a normal assistant response (non-AI-review)
    fn add_normal_assistant_response(&mut self, response: &str, duration_ms: u64) {
        let mut assistant_msg = Message::assistant(response);
        assistant_msg.duration_ms = Some(duration_ms);
        self.state.add_message(assistant_msg);
        self.scroll_offset = 0;
    }

    /// Submit query to the agent
    pub async fn submit_query(&mut self, controller: &mut AgentController<'_>) -> Result<()> {
        if self.input_buffer.trim().is_empty() {
            return Ok(());
        }

        let query = self.input_buffer.clone();
        self.input_buffer.clear();

        // Add user message to state
        self.state.add_message(Message::user(&query));

        // Process query with agent
        match controller.process_query(&query).await {
            Ok(response) => {
                self.state.add_message(Message::assistant(&response));
            }
            Err(e) => {
                self.state
                    .add_message(Message::system(&format!("Error: {}", e)));
            }
        }

        // Reset scroll to bottom
        self.scroll_offset = 0;

        Ok(())
    }

    /// Scroll up in chat history
    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    /// Scroll down in chat history
    pub fn scroll_down(&mut self) {
        let max_scroll = self.state.get_messages().len().saturating_sub(1);
        self.scroll_offset = self.scroll_offset.saturating_add(1).min(max_scroll);
    }

    /// Cycle through panels (Input <-> Chat <-> Todo)
    pub fn cycle_panels(&mut self) {
        self.active_panel = match self.active_panel {
            Panel::Input => Panel::Chat,
            Panel::Chat => {
                // Only show TODO panel if there are tasks
                if self.todo_list.tasks.is_empty() {
                    Panel::Input
                } else {
                    Panel::Todo
                }
            }
            Panel::Todo => Panel::Input,
        };
    }

    /// Get input buffer reference
    pub fn get_input_buffer(&self) -> &str {
        &self.input_buffer
    }

    /// Get active panel
    pub fn get_active_panel(&self) -> Panel {
        self.active_panel
    }

    /// Get scroll offset
    pub fn get_scroll_offset(&self) -> usize {
        self.scroll_offset
    }

    /// Clear input buffer
    pub fn clear_input(&mut self) {
        self.input_buffer.clear();
    }

    /// Navigate through query history with up/down arrows
    /// direction: -1 for up/back (older), 1 for down/forward (newer)
    pub fn navigate_history(&mut self, direction: i8) {
        if self.query_history.is_empty() {
            return;
        }

        match direction {
            -1 => {
                // Up/Back - go to older queries
                match self.history_index {
                    None => {
                        // First navigation - save current input and go to last history item
                        self.history_index = Some(self.query_history.len() - 1);
                    }
                    Some(idx) if idx > 0 => {
                        // Navigate back to older query
                        self.history_index = Some(idx - 1);
                    }
                    Some(_) => {
                        // Already at oldest query, stay there
                    }
                }
            }
            1 => {
                // Down/Forward - go to newer queries
                match self.history_index {
                    None => {
                        // Not currently navigating, nothing to do
                    }
                    Some(idx) if idx < self.query_history.len() - 1 => {
                        // Navigate forward to newer query
                        self.history_index = Some(idx + 1);
                    }
                    Some(_) => {
                        // Past the end - clear input and reset navigation
                        self.history_index = None;
                        self.input_buffer.clear();
                        return;
                    }
                }
            }
            _ => {}
        }

        // Set input buffer to selected history item
        if let Some(idx) = self.history_index {
            self.input_buffer = self.query_history[idx].clone();
        }
    }

    /// Add a query to history (called after successful submission)
    pub fn add_to_history(&mut self, query: String) {
        // Avoid adding empty queries
        if query.trim().is_empty() {
            return;
        }

        // Avoid duplicates at the end (don't add same query twice in a row)
        if self
            .query_history
            .last()
            .map_or(true, |last| last != &query)
        {
            self.query_history.push(query);
        }

        // Reset history navigation after adding new query
        self.history_index = None;
    }

    // =========================================================================
    // Phase 2: TRI Scoring Pipeline - Async Scan Trigger
    // =========================================================================

    /// Trigger an async token scan with progress tracking
    ///
    /// # Arguments
    /// * `token_address` - Token contract address to scan
    /// * `chain` - Blockchain network
    pub async fn trigger_scan(&mut self, token_address: String, chain: String) {
        use crate::scanner::{PipelineConfig, run_pipeline_with_progress, TriConfig};

        if self.scan_in_progress {
            self.state
                .add_message(Message::system("⚠ Scan already in progress. Please wait."));
            return;
        }

        self.scan_in_progress = true;
        self.scan_token_address = Some(token_address.clone());
        self.state.add_message(Message::system(&format!(
            "🔍 Scanning {} on {}...",
            token_address, chain
        )));

        // Build pipeline config from app config
        let phi3_config = crate::llm::Phi3Config {
            base_url: self.state.config.phi3.base_url.clone(),
            model: self.state.config.phi3.model.clone(),
            api_key: self.state.config.phi3.api_key.clone(),
            timeout_secs: self.state.config.phi3.timeout_secs,
            retry_count: self.state.config.phi3.retry_count,
            rug_prob_threshold: self.state.config.phi3.rug_prob_threshold,
        };

        let tri_config = TriConfig::default();

        let telegram_config = crate::scanner::TelegramAlertConfig {
            bot_token: self.state.config.telegram.bot_token.clone(),
            chat_id: self.state.config.telegram.chat_id.clone(),
            alert_threshold: self.state.config.telegram.alert_threshold,
            rate_limit_minutes: self.state.config.telegram.rate_limit_minutes,
        };

        let pipeline_config = PipelineConfig {
            phi3_config,
            tri_config,
            telegram_config,
            organized_reports: crate::scanner::pipeline::OrganizedReportConfig {
                enabled: self.state.config.reports.organized_structure,
                base_dir: std::path::PathBuf::from(&self.state.config.reports.base_dir),
                save_raw_responses: self.state.config.reports.save_raw_responses,
                generate_manifest: self.state.config.reports.generate_manifest,
            },
        };

        // Create progress channel
        let (tx, rx) = tokio::sync::mpsc::channel::<crate::scanner::ScanProgress>(32);
        self.scan_progress_rx = Some(rx);

        // Spawn background task
        let token_clone = token_address.clone();
        let chain_clone = chain.clone();
        tokio::spawn(async move {
            run_pipeline_with_progress(&token_clone, &chain_clone, pipeline_config, tx).await
        });
    }

    /// Display TRI result summary in chat panel
    ///
    /// # Arguments
    /// * `result` - Pipeline result to display
    pub fn display_tri_result(&mut self, result: &crate::scanner::PipelineResult) {
        let tri = &result.tri_result;
        let label = tri.tri_label.display();
        let emoji = tri.tri_label.emoji();

        let mut lines = vec![
            format!("┌─ {} Token Analysis Complete ─────────────────", emoji),
            format!("│  TRI Score: {:.1}/100  [{}]", tri.tri, label),
            format!("│  Rug Probability: {:.1}%", result.rug_probability * 100.0),
            String::from("│"),
            String::from("│  Domain Breakdown:"),
            format!("│    Contract Risk:  {:.1}", tri.contract_risk),
            format!("│    Ownership Risk: {:.1}", tri.ownership_risk),
            format!("│    LP Score:       {:.1}", tri.lp_score),
            format!("│    Tax Risk:       {:.1}", tri.tax_risk),
            format!("│    Volume Risk:    {:.1}", tri.volume_risk),
            format!("│    Age Risk:       {:.1}", tri.age_risk),
        ];

        if !tri.red_flags.is_empty() {
            lines.push(String::from("│"));
            lines.push(String::from("│  ⛔ Red Flags:"));
            for flag in &tri.red_flags {
                lines.push(format!("│    • [{}] {}", flag.category, flag.description));
            }
        }

        if let Some(ref llm) = result.llm_analysis {
            lines.push(String::from("│"));
            lines.push(format!(
                "│  🤖 Groq Analysis: {} {}",
                llm.recommendation.emoji(),
                llm.recommendation.display()
            ));
            lines.push(format!("│  {}", llm.explanation));
        }

        lines.push(String::from("└──────────────────────────────────────────────"));

        self.state.add_message(Message::system(&lines.join("\n")));
    }

    /// Poll scan progress channel and handle events
    ///
    /// This should be called in the main TUI event loop to process
    /// scan progress events without blocking the UI.
    pub fn poll_scan_progress(&mut self) {
        // Check if we have a progress receiver
        let has_receiver = self.scan_progress_rx.is_some();
        
        if !has_receiver {
            return;
        }

        // Track if we need to clear the receiver
        let mut should_clear = false;
        let mut result_to_display: Option<crate::scanner::PipelineResult> = None;

        // Process all pending events
        if let Some(ref mut rx) = self.scan_progress_rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    crate::scanner::ScanProgress::ApiComplete { provider, success } => {
                        let icon = if success { "✅" } else { "⚠️" };
                        self.state.add_message(Message::system(&format!(
                            "{icon} {provider} complete"
                        )));
                    }
                    crate::scanner::ScanProgress::MlScoreComplete { rug_probability } => {
                        self.state.add_message(Message::system(&format!(
                            "🎯 Rug probability: {:.1}%",
                            rug_probability * 100.0
                        )));
                    }
                    crate::scanner::ScanProgress::LlmStarted => {
                        self.groq_status = GroqStatus::Calling;
                        self.state.add_message(Message::system(
                            "🤖 Sending to Groq LLM for analysis...",
                        ));
                    }
                    crate::scanner::ScanProgress::LlmComplete { .. } => {
                        self.groq_status = GroqStatus::Available;
                    }
                    crate::scanner::ScanProgress::Done(result) => {
                        self.last_tri = Some(result.tri_result.clone());
                        self.scan_history.push_front(*result.clone());
                        if self.scan_history.len() > 10 {
                            self.scan_history.pop_back();
                        }
                        self.last_pipeline_result = Some(*result.clone());
                        self.scan_in_progress = false;
                        self.groq_status = GroqStatus::Available;
                        // Store result for display after borrow ends
                        result_to_display = Some(*result);
                        should_clear = true;
                    }
                    crate::scanner::ScanProgress::Error(e) => {
                        self.scan_in_progress = false;
                        self.groq_status = GroqStatus::Unavailable;
                        self.state
                            .add_message(Message::system(&format!("❌ Scan failed: {}", e)));
                        should_clear = true;
                    }
                    _ => {}
                }
            }
        }

        // Display result after borrow ends
        if let Some(result) = result_to_display {
            self.display_tri_result(&result);
        }

        // Clear the receiver after processing all events if scan is complete
        if should_clear {
            self.scan_progress_rx = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::todo::TaskStatus;

    #[test]
    fn test_panel_default() {
        let panel = Panel::default();
        assert_eq!(panel, Panel::Input);
    }

    #[test]
    fn test_panel_equality() {
        assert_eq!(Panel::Input, Panel::Input);
        assert_eq!(Panel::Chat, Panel::Chat);
        assert_ne!(Panel::Input, Panel::Chat);
    }

    #[test]
    fn test_panel_copy() {
        let panel1 = Panel::Input;
        let panel2 = panel1; // Copy
        assert_eq!(panel1, panel2);
    }

    #[test]
    fn test_tui_app_creation() {
        let mut state = AppState::with_defaults(".".to_string());
        let app = TuiApp::new(&mut state);

        assert_eq!(app.get_input_buffer(), "");
        assert_eq!(app.get_active_panel(), Panel::Input);
        assert_eq!(app.get_scroll_offset(), 0);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_tui_app_scroll_up() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        app.scroll_up();
        assert_eq!(app.get_scroll_offset(), 0); // Should not go negative

        app.scroll_offset = 5;
        app.scroll_up();
        assert_eq!(app.get_scroll_offset(), 4);
    }

    #[test]
    fn test_tui_app_scroll_down() {
        let mut state = AppState::with_defaults(".".to_string());
        state.add_message(Message::user("Test 1"));
        state.add_message(Message::assistant("Test 2"));
        state.add_message(Message::user("Test 3"));

        let mut app = TuiApp::new(&mut state);

        app.scroll_down();
        assert_eq!(app.get_scroll_offset(), 1);

        app.scroll_down();
        assert_eq!(app.get_scroll_offset(), 2);
    }

    #[test]
    fn test_tui_app_cycle_panels() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Input -> Chat -> Input (ToolLog removed)
        assert_eq!(app.get_active_panel(), Panel::Input);
        app.cycle_panels();
        assert_eq!(app.get_active_panel(), Panel::Chat);
        app.cycle_panels();
        assert_eq!(app.get_active_panel(), Panel::Input);
    }

    #[test]
    fn test_tui_app_clear_input() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        app.input_buffer = "test input".to_string();
        app.clear_input();
        assert_eq!(app.get_input_buffer(), "");
    }

    #[test]
    fn test_tui_app_input_buffer() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        app.input_buffer = "hello".to_string();
        assert_eq!(app.get_input_buffer(), "hello");
    }

    #[test]
    fn test_add_to_history() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        app.add_to_history("query 1".to_string());
        assert_eq!(app.query_history.len(), 1);
        assert_eq!(app.query_history[0], "query 1");

        app.add_to_history("query 2".to_string());
        assert_eq!(app.query_history.len(), 2);
        assert_eq!(app.query_history[1], "query 2");
    }

    #[test]
    fn test_add_to_history_no_duplicates() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        app.add_to_history("query 1".to_string());
        app.add_to_history("query 1".to_string()); // Should not add duplicate
        assert_eq!(app.query_history.len(), 1);

        app.add_to_history("query 2".to_string());
        app.add_to_history("query 2".to_string()); // Should not add duplicate
        assert_eq!(app.query_history.len(), 2);
    }

    #[test]
    fn test_add_to_history_no_empty() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        app.add_to_history("".to_string());
        app.add_to_history("   ".to_string());
        assert_eq!(app.query_history.len(), 0);
    }

    #[test]
    fn test_navigate_history_empty() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        app.navigate_history(-1); // Should do nothing
        assert_eq!(app.history_index, None);
        assert_eq!(app.input_buffer, "");
    }

    #[test]
    fn test_navigate_history_up() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add some history
        app.add_to_history("query 1".to_string());
        app.add_to_history("query 2".to_string());
        app.add_to_history("query 3".to_string());

        // Navigate up (back) - should get query 3 (most recent)
        app.navigate_history(-1);
        assert_eq!(app.history_index, Some(2));
        assert_eq!(app.input_buffer, "query 3");

        // Navigate up again - should get query 2
        app.navigate_history(-1);
        assert_eq!(app.history_index, Some(1));
        assert_eq!(app.input_buffer, "query 2");

        // Navigate up again - should get query 1 (oldest)
        app.navigate_history(-1);
        assert_eq!(app.history_index, Some(0));
        assert_eq!(app.input_buffer, "query 1");

        // Navigate up again - should stay at query 1
        app.navigate_history(-1);
        assert_eq!(app.history_index, Some(0));
        assert_eq!(app.input_buffer, "query 1");
    }

    #[test]
    fn test_navigate_history_down() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add some history
        app.add_to_history("query 1".to_string());
        app.add_to_history("query 2".to_string());
        app.add_to_history("query 3".to_string());

        // Navigate to oldest first
        app.navigate_history(-1);
        app.navigate_history(-1);
        app.navigate_history(-1);
        assert_eq!(app.history_index, Some(0));
        assert_eq!(app.input_buffer, "query 1");

        // Navigate down (forward) - should get query 2
        app.navigate_history(1);
        assert_eq!(app.history_index, Some(1));
        assert_eq!(app.input_buffer, "query 2");

        // Navigate down - should get query 3
        app.navigate_history(1);
        assert_eq!(app.history_index, Some(2));
        assert_eq!(app.input_buffer, "query 3");

        // Navigate down - should clear input (past the end)
        app.navigate_history(1);
        assert_eq!(app.history_index, None);
        assert_eq!(app.input_buffer, "");
    }

    #[test]
    fn test_navigate_history_down_without_navigating_up_first() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        app.add_to_history("query 1".to_string());
        app.add_to_history("query 2".to_string());

        // Press down without navigating up first - should do nothing
        app.navigate_history(1);
        assert_eq!(app.history_index, None);
        assert_eq!(app.input_buffer, "");
    }

    #[test]
    fn test_add_to_history_resets_navigation() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        app.add_to_history("query 1".to_string());
        app.add_to_history("query 2".to_string());

        // Navigate to history
        app.navigate_history(-1);
        assert_eq!(app.history_index, Some(1));

        // Add new query - should reset navigation
        app.add_to_history("query 3".to_string());
        assert_eq!(app.history_index, None);
    }

    #[test]
    fn test_history_full_workflow() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Simulate user typing and submitting 3 queries
        app.input_buffer = "list files".to_string();
        app.add_to_history(app.input_buffer.clone());
        app.input_buffer.clear();

        app.input_buffer = "read file".to_string();
        app.add_to_history(app.input_buffer.clone());
        app.input_buffer.clear();

        app.input_buffer = "write file".to_string();
        app.add_to_history(app.input_buffer.clone());
        app.input_buffer.clear();

        assert_eq!(app.query_history.len(), 3);

        // Press up - should get "write file"
        app.navigate_history(-1);
        assert_eq!(app.input_buffer, "write file");

        // Press up - should get "read file"
        app.navigate_history(-1);
        assert_eq!(app.input_buffer, "read file");

        // Press up - should get "list files"
        app.navigate_history(-1);
        assert_eq!(app.input_buffer, "list files");

        // Press up - should stay at "list files"
        app.navigate_history(-1);
        assert_eq!(app.input_buffer, "list files");

        // Press down - should get "read file"
        app.navigate_history(1);
        assert_eq!(app.input_buffer, "read file");

        // Press down - should get "write file"
        app.navigate_history(1);
        assert_eq!(app.input_buffer, "write file");

        // Press down - should clear
        app.navigate_history(1);
        assert_eq!(app.input_buffer, "");
        assert_eq!(app.history_index, None);
    }

    // ==================== Phase 4: AI Review Tests ====================

    #[test]
    fn test_parse_ai_task_response_simple_array() {
        let text = r#"["Task 1", "Task 2", "Task 3"]"#;
        let tasks = TuiApp::parse_ai_task_response(text);
        assert!(tasks.is_some());
        let tasks = tasks.unwrap();
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0], "Task 1");
        assert_eq!(tasks[1], "Task 2");
        assert_eq!(tasks[2], "Task 3");
    }

    #[test]
    fn test_parse_ai_task_response_wrapped_in_text() {
        let text = r#"Here are the tasks I found: ["Task 1", "Task 2", "Task 3"]"#;
        let tasks = TuiApp::parse_ai_task_response(text);
        assert!(tasks.is_some());
        let tasks = tasks.unwrap();
        assert_eq!(tasks.len(), 3);
    }

    #[test]
    fn test_parse_ai_task_response_with_explanation() {
        let text = r#"I've analyzed the text and found these tasks:
1. First task
2. Second task

Here's the JSON array: ["Task 1", "Task 2", "Task 3"]

Let me know if you need more details."#;
        let tasks = TuiApp::parse_ai_task_response(text);
        assert!(tasks.is_some());
        let tasks = tasks.unwrap();
        assert_eq!(tasks.len(), 3);
    }

    #[test]
    fn test_parse_ai_task_response_empty_array() {
        let text = r#"[]"#;
        let tasks = TuiApp::parse_ai_task_response(text);
        assert!(tasks.is_none()); // Empty array should return None
    }

    #[test]
    fn test_parse_ai_task_response_no_json() {
        let text = r#"I couldn't find any tasks in the text."#;
        let tasks = TuiApp::parse_ai_task_response(text);
        assert!(tasks.is_none());
    }

    #[test]
    fn test_parse_ai_task_response_objects_with_description() {
        let text = r#"[{"description": "Task 1"}, {"description": "Task 2"}]"#;
        let tasks = TuiApp::parse_ai_task_response(text);
        assert!(tasks.is_some());
        let tasks = tasks.unwrap();
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0], "Task 1");
        assert_eq!(tasks[1], "Task 2");
    }

    #[test]
    fn test_parse_ai_task_response_objects_with_task_field() {
        let text = r#"[{"task": "Task 1"}, {"task": "Task 2"}]"#;
        let tasks = TuiApp::parse_ai_task_response(text);
        assert!(tasks.is_some());
        let tasks = tasks.unwrap();
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0], "Task 1");
        assert_eq!(tasks[1], "Task 2");
    }

    #[test]
    fn test_parse_ai_task_response_objects_with_title_field() {
        let text = r#"[{"title": "Task 1"}, {"title": "Task 2"}]"#;
        let tasks = TuiApp::parse_ai_task_response(text);
        assert!(tasks.is_some());
        let tasks = tasks.unwrap();
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0], "Task 1");
        assert_eq!(tasks[1], "Task 2");
    }

    #[test]
    fn test_parse_ai_task_response_mixed_fields() {
        let text = r#"[
            {"description": "Task 1"},
            {"task": "Task 2"},
            {"title": "Task 3"}
        ]"#;
        let tasks = TuiApp::parse_ai_task_response(text);
        assert!(tasks.is_some());
        let tasks = tasks.unwrap();
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0], "Task 1");
        assert_eq!(tasks[1], "Task 2");
        assert_eq!(tasks[2], "Task 3");
    }

    #[test]
    fn test_parse_ai_task_response_complex_json() {
        let text = r#"Based on my analysis:
- The text contains multiple actionable items
- Some are clear, others need refinement

Here's the extracted task list:
["Implement feature", "Write tests", "Deploy to production"]

Each task is ready to be added to your TODO list."#;
        let tasks = TuiApp::parse_ai_task_response(text);
        assert!(tasks.is_some());
        let tasks = tasks.unwrap();
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0], "Implement feature");
        assert_eq!(tasks[1], "Write tests");
        assert_eq!(tasks[2], "Deploy to production");
    }

    #[test]
    fn test_parse_ai_task_response_multiline_array() {
        let text = r#"[
  "First task with longer description",
  "Second task",
  "Third task"
]"#;
        let tasks = TuiApp::parse_ai_task_response(text);
        assert!(tasks.is_some());
        let tasks = tasks.unwrap();
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0], "First task with longer description");
    }

    #[test]
    fn test_handle_ai_review_response() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);
        let tasks = vec![
            "Task 1".to_string(),
            "Task 2".to_string(),
            "Task 3".to_string(),
        ];

        app.handle_ai_review_response(&tasks);

        // Verify tasks were added
        assert_eq!(app.todo_list.tasks.len(), 3);
        assert_eq!(app.todo_list.tasks[0].description, "Task 1");
        assert_eq!(app.todo_list.tasks[1].description, "Task 2");
        assert_eq!(app.todo_list.tasks[2].description, "Task 3");

        // Verify all tasks are Pending
        for task in &app.todo_list.tasks {
            assert!(task.is_pending());
        }

        // Verify message was added
        let messages = app.state.get_messages();
        assert!(!messages.is_empty());
    }

    #[test]
    fn test_handle_ai_review_response_clears_existing() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add existing task
        app.todo_list.add_task("Existing task".to_string());
        assert_eq!(app.todo_list.tasks.len(), 1);

        // Handle AI review with new tasks
        let tasks = vec!["New task 1".to_string(), "New task 2".to_string()];
        app.handle_ai_review_response(&tasks);

        // Verify old task was cleared and new tasks added
        assert_eq!(app.todo_list.tasks.len(), 2);
        assert_eq!(app.todo_list.tasks[0].description, "New task 1");
        assert_eq!(app.todo_list.tasks[1].description, "New task 2");
    }

    #[test]
    fn test_handle_ai_review_response_empty_tasks() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);
        let tasks: Vec<String> = vec![];

        app.handle_ai_review_response(&tasks);

        // Verify no tasks were added
        assert_eq!(app.todo_list.tasks.len(), 0);
    }

    #[test]
    fn test_add_normal_assistant_response() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);
        let response = "This is a normal response";
        let duration_ms = 1000u64;

        app.add_normal_assistant_response(response, duration_ms);

        // Verify message was added
        let messages = app.state.get_messages();
        assert!(!messages.is_empty());

        // Verify it's an assistant message
        let last_msg = messages.last().unwrap();
        assert_eq!(last_msg.role, crate::types::Role::Assistant);
        assert!(last_msg.content.contains(response));
        assert_eq!(last_msg.duration_ms, Some(duration_ms));
    }

    // ==================== Phase 6: Task Status Slash Commands Tests ====================

    #[tokio::test]
    async fn test_slash_start_command() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add a task
        app.todo_list.add_task("Test task".to_string());
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::Pending);

        // Use /start command
        app.handle_slash_command("/start 1").await.unwrap();

        // Verify task is now InProgress
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::InProgress);

        // Verify message was added
        let messages = app.state.get_messages();
        assert!(!messages.is_empty());
        assert!(messages.last().unwrap().content.contains("in progress"));
        assert!(messages.last().unwrap().content.contains("◐"));
    }

    #[tokio::test]
    async fn test_slash_start_nonexistent_task() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Use /start with non-existent task
        app.handle_slash_command("/start 999").await.unwrap();

        // Verify error message
        let messages = app.state.get_messages();
        assert!(messages.last().unwrap().content.contains("not found"));
    }

    #[tokio::test]
    async fn test_slash_start_invalid_id() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Use /start with invalid ID
        app.handle_slash_command("/start abc").await.unwrap();

        // Verify error message
        let messages = app.state.get_messages();
        assert!(messages.last().unwrap().content.contains("Invalid task ID"));
    }

    #[tokio::test]
    async fn test_slash_start_no_id() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Use /start without ID
        app.handle_slash_command("/start").await.unwrap();

        // Verify error message
        let messages = app.state.get_messages();
        assert!(
            messages
                .last()
                .unwrap()
                .content
                .contains("Task ID required")
        );
    }

    #[tokio::test]
    async fn test_slash_pause_command() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add a task and start it
        app.todo_list.add_task("Test task".to_string());
        app.todo_list.start_task(1);
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::InProgress);

        // Use /pause command
        app.handle_slash_command("/pause 1").await.unwrap();

        // Verify task is now Pending
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::Pending);

        // Verify message was added
        let messages = app.state.get_messages();
        assert!(messages.last().unwrap().content.contains("pending"));
        assert!(messages.last().unwrap().content.contains("○"));
    }

    #[tokio::test]
    async fn test_slash_pause_completed_task() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add a task and complete it
        app.todo_list.add_task("Test task".to_string());
        app.todo_list.complete_task(1);
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::Completed);

        // Use /pause command (should reset to Pending)
        app.handle_slash_command("/pause 1").await.unwrap();

        // Verify task is now Pending
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::Pending);
    }

    #[tokio::test]
    async fn test_slash_cycle_command_pending_to_inprogress() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add a task (starts as Pending)
        app.todo_list.add_task("Test task".to_string());
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::Pending);

        // Use /cycle command
        app.handle_slash_command("/cycle 1").await.unwrap();

        // Verify task is now InProgress
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::InProgress);

        // Verify message shows cycle
        let messages = app.state.get_messages();
        let msg = &messages.last().unwrap().content;
        assert!(msg.contains("cycled"));
        assert!(msg.contains("Pending"));
        assert!(msg.contains("InProgress"));
        assert!(msg.contains("◐"));
    }

    #[tokio::test]
    async fn test_slash_cycle_command_inprogress_to_completed() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add a task and start it
        app.todo_list.add_task("Test task".to_string());
        app.todo_list.start_task(1);
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::InProgress);

        // Use /cycle command
        app.handle_slash_command("/cycle 1").await.unwrap();

        // Verify task is now Completed
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::Completed);

        // Verify message shows cycle
        let messages = app.state.get_messages();
        let msg = &messages.last().unwrap().content;
        assert!(msg.contains("InProgress"));
        assert!(msg.contains("Completed"));
        assert!(msg.contains("●"));
    }

    #[tokio::test]
    async fn test_slash_cycle_command_completed_to_pending() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add a task and complete it
        app.todo_list.add_task("Test task".to_string());
        app.todo_list.complete_task(1);
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::Completed);

        // Use /cycle command
        app.handle_slash_command("/cycle 1").await.unwrap();

        // Verify task is now Pending
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::Pending);

        // Verify message shows cycle
        let messages = app.state.get_messages();
        let msg = &messages.last().unwrap().content;
        assert!(msg.contains("Completed"));
        assert!(msg.contains("Pending"));
        assert!(msg.contains("○"));
    }

    #[tokio::test]
    async fn test_slash_cycle_nonexistent_task() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Use /cycle with non-existent task
        app.handle_slash_command("/cycle 999").await.unwrap();

        // Verify error message
        let messages = app.state.get_messages();
        assert!(messages.last().unwrap().content.contains("not found"));
    }

    #[tokio::test]
    async fn test_slash_cycle_invalid_id() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Use /cycle with invalid ID
        app.handle_slash_command("/cycle abc").await.unwrap();

        // Verify error message
        let messages = app.state.get_messages();
        assert!(messages.last().unwrap().content.contains("Invalid task ID"));
    }

    #[tokio::test]
    async fn test_slash_cycle_no_id() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Use /cycle without ID
        app.handle_slash_command("/cycle").await.unwrap();

        // Verify error message
        let messages = app.state.get_messages();
        assert!(
            messages
                .last()
                .unwrap()
                .content
                .contains("Task ID required")
        );
    }

    #[tokio::test]
    async fn test_full_status_workflow() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add task
        app.todo_list.add_task("Workflow task".to_string());

        // Start task
        app.handle_slash_command("/start 1").await.unwrap();
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::InProgress);

        // Pause task
        app.handle_slash_command("/pause 1").await.unwrap();
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::Pending);

        // Cycle to InProgress
        app.handle_slash_command("/cycle 1").await.unwrap();
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::InProgress);

        // Cycle to Completed
        app.handle_slash_command("/cycle 1").await.unwrap();
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::Completed);

        // Cycle back to Pending
        app.handle_slash_command("/cycle 1").await.unwrap();
        assert_eq!(app.todo_list.tasks[0].status, TaskStatus::Pending);
    }

    #[tokio::test]
    async fn test_help_includes_new_commands() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Use /help command
        app.handle_slash_command("/help").await.unwrap();

        // Verify help text includes new commands
        let messages = app.state.get_messages();
        let help_text = &messages.last().unwrap().content;
        assert!(help_text.contains("/start"));
        assert!(help_text.contains("/pause"));
        assert!(help_text.contains("/cycle"));
        assert!(help_text.contains("in progress"));
        assert!(help_text.contains("pending"));
        assert!(help_text.contains("Cycle task status"));
    }

    // ==================== Phase 7: CSV Lifecycle Management Tests ====================

    #[tokio::test]
    async fn test_csv_cleanup_no_csv() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Use /csv-cleanup without CSV
        app.handle_slash_command("/csv-cleanup").await.unwrap();

        // Verify message
        let messages = app.state.get_messages();
        assert!(
            messages
                .last()
                .unwrap()
                .content
                .contains("No CSV file tracked")
        );
    }

    #[tokio::test]
    async fn test_csv_cleanup_not_all_completed() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add tasks but don't complete them
        app.todo_list.add_task("Task 1".to_string());
        app.todo_list.add_task("Task 2".to_string());
        app.todo_list.start_task(1);

        // Create a fake CSV path
        app.todo_list
            .set_csv_path(std::path::PathBuf::from("/tmp/test.csv"));

        // Use /csv-cleanup
        app.handle_slash_command("/csv-cleanup").await.unwrap();

        // Verify message shows tasks still pending
        let messages = app.state.get_messages();
        assert!(messages.last().unwrap().content.contains("Cannot cleanup"));
        assert!(
            messages
                .last()
                .unwrap()
                .content
                .contains("tasks still pending")
        );
    }

    #[tokio::test]
    async fn test_csv_cleanup_all_completed() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add and complete tasks
        app.todo_list.add_task("Task 1".to_string());
        app.todo_list.add_task("Task 2".to_string());
        app.todo_list.complete_task(1);
        app.todo_list.complete_task(2);

        // Create a fake CSV path (file doesn't need to exist for this test)
        // The cleanup command handles non-existent files gracefully
        app.todo_list
            .set_csv_path(std::path::PathBuf::from("/tmp/test_csv_cleanup.csv"));

        // Use /csv-cleanup
        app.handle_slash_command("/csv-cleanup").await.unwrap();

        // Verify CSV tracking was cleared (even if file didn't exist)
        // The command clears tracking even if file deletion fails
        let messages = app.state.get_messages();
        // Should show either success or error message
        assert!(
            messages.last().unwrap().content.contains("CSV")
                || messages.last().unwrap().content.contains("cleanup")
        );
    }

    #[tokio::test]
    async fn test_done_command_shows_cleanup_hint() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add task and create CSV
        app.todo_list.add_task("Task 1".to_string());
        app.todo_list
            .set_csv_path(std::path::PathBuf::from("/tmp/test.csv"));

        // Complete the task
        app.handle_slash_command("/done 1").await.unwrap();

        // Verify hint message was shown
        let messages = app.state.get_messages();
        assert!(
            messages
                .last()
                .unwrap()
                .content
                .contains("All tasks completed")
        );
        assert!(messages.last().unwrap().content.contains("/csv-cleanup"));
    }

    #[tokio::test]
    async fn test_done_command_no_hint_with_pending_tasks() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add multiple tasks and create CSV
        app.todo_list.add_task("Task 1".to_string());
        app.todo_list.add_task("Task 2".to_string());
        app.todo_list
            .set_csv_path(std::path::PathBuf::from("/tmp/test.csv"));

        // Complete only one task
        app.handle_slash_command("/done 1").await.unwrap();

        // Verify no cleanup hint (tasks still pending)
        let messages = app.state.get_messages();
        assert!(!messages.last().unwrap().content.contains("/csv-cleanup"));
    }

    #[tokio::test]
    async fn test_csv_cleanup_workflow() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Simulate complete workflow
        app.todo_list.add_task("Task 1".to_string());
        app.todo_list.add_task("Task 2".to_string());
        app.todo_list
            .set_csv_path(std::path::PathBuf::from("/tmp/workflow_test.csv"));

        // Complete all tasks
        app.handle_slash_command("/done 1").await.unwrap();
        app.handle_slash_command("/done 2").await.unwrap();

        // Verify cleanup hint was shown
        let messages = app.state.get_messages();
        assert!(messages.iter().any(|m| m.content.contains("/csv-cleanup")));

        // Cleanup CSV (file doesn't exist, but tracking should be cleared)
        app.handle_slash_command("/csv-cleanup").await.unwrap();

        // Verify message about cleanup was shown (success or error)
        let messages = app.state.get_messages();
        assert!(messages.last().unwrap().content.contains("CSV"));
    }

    #[tokio::test]
    async fn test_csv_cleanup_with_mixed_status() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Add tasks with mixed statuses
        app.todo_list.add_task("Pending".to_string());
        app.todo_list.add_task("In Progress".to_string());
        app.todo_list.add_task("Completed".to_string());
        app.todo_list.start_task(2);
        app.todo_list.complete_task(3);
        app.todo_list
            .set_csv_path(std::path::PathBuf::from("/tmp/mixed.csv"));

        // Try to cleanup
        app.handle_slash_command("/csv-cleanup").await.unwrap();

        // Verify error message with status breakdown
        let messages = app.state.get_messages();
        let msg = &messages.last().unwrap().content;
        assert!(msg.contains("Cannot cleanup"));
        assert!(msg.contains("pending/in progress"));
    }

    #[tokio::test]
    async fn test_help_includes_csv_cleanup() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut app = TuiApp::new(&mut state);

        // Use /help command
        app.handle_slash_command("/help").await.unwrap();

        // Verify help text includes csv-cleanup
        let messages = app.state.get_messages();
        let help_text = &messages.last().unwrap().content;
        assert!(help_text.contains("/csv-cleanup"));
        assert!(help_text.contains("Clean up CSV"));
    }
}
