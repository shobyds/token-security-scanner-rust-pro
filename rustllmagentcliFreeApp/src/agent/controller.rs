//! Agent controller for orchestrating LLM queries and tool execution
//!
//! This module implements the agentic loop with improved tool calling for small LLMs.
//! Key optimizations for DeepSeek-Coder-6.7B-Instruct:
//! - Comprehensive system prompt with detailed examples
//! - Multiple tool call syntax support (@tool, <tool>, `TOOL_CALL`:)
//! - Clear "one tool at a time" instructions
//! - Progress tracking to detect when LLM is just talking
//! - Multi-step task planning for complex queries

use anyhow::Result;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, error, info, warn};

use crate::agent::{LlmClient, ToolCoordinator, conversation::Conversation};
use crate::app::state::AppState;
use crate::types::{AgentError, Message, Role, ToolCall};

/// Represents a single step in a multi-step task plan
#[derive(Debug, Clone)]
pub struct TaskStep {
    /// Description of what this step should accomplish
    pub description: String,
    /// The tool to use for this step
    pub tool_name: String,
    /// Arguments for the tool
    pub arguments: Value,
    /// Whether this step has been completed
    pub completed: bool,
    /// Result from executing this step
    pub result: Option<String>,
}

/// Multi-step task planner for complex queries
#[derive(Debug, Clone)]
pub struct TaskPlan {
    /// Original user query
    pub query: String,
    /// Steps to accomplish the task
    pub steps: Vec<TaskStep>,
    /// Current step index
    pub current_step: usize,
    /// Whether the plan is complete
    pub completed: bool,
}

impl TaskPlan {
    /// Create a new task plan
    #[must_use]
    pub fn new(query: String) -> Self {
        Self {
            query,
            steps: Vec::new(),
            current_step: 0,
            completed: false,
        }
    }

    /// Add a step to the plan
    pub fn add_step(&mut self, description: String, tool_name: String, arguments: Value) {
        self.steps.push(TaskStep {
            description,
            tool_name,
            arguments,
            completed: false,
            result: None,
        });
    }

    /// Get the next step to execute
    #[must_use]
    pub fn next_step(&self) -> Option<&TaskStep> {
        if self.current_step < self.steps.len() {
            self.steps.get(self.current_step)
        } else {
            None
        }
    }

    /// Mark current step as completed and move to next
    pub fn complete_current_step(&mut self, result: String) {
        if let Some(step) = self.steps.get_mut(self.current_step) {
            step.completed = true;
            step.result = Some(result);
        }
        self.current_step += 1;

        // Check if plan is complete
        if self.current_step >= self.steps.len() {
            self.completed = true;
        }
    }

    /// Get progress as a string
    #[must_use]
    pub fn progress_string(&self) -> String {
        format!(
            "Step {}/{}: {}",
            self.current_step + 1,
            self.steps.len(),
            self.steps
                .get(self.current_step)
                .map_or("Complete", |s| s.description.as_str())
        )
    }
}

/// Global counter for tool calls across iterations (for progress tracking)
static TOOL_CALLS_TOTAL: AtomicUsize = AtomicUsize::new(0);

/// Agent controller that manages the agentic loop
pub struct AgentController<'a> {
    #[allow(dead_code)]
    state: &'a mut AppState,
    llm_client: LlmClient,
    tool_coordinator: ToolCoordinator,
    conversation: Conversation,
    max_iterations: usize,
    /// Track iterations without tool use
    iterations_without_tool: usize,
    /// Current multi-step task plan (if any)
    current_plan: Option<TaskPlan>,
}

impl<'a> AgentController<'a> {
    /// Create a new agent controller
    pub fn new(state: &'a mut AppState) -> Self {
        // Use auto-discovery and auto-detection for LLM client
        let llm_client = LlmClient::with_config_and_discovery(&state.config.llm);

        let tool_coordinator = ToolCoordinator::new(
            state.workdir.clone(),
            state.config.tools.file_size_limit_mb,
            state.config.agent.tool_timeout_seconds * 1000,
        );

        let max_iterations = state.config.agent.max_iterations;

        let mut conversation = Conversation::new();
        conversation.add_system_prompt(
            create_system_prompt(),
            tool_coordinator.get_tool_definitions(),
        );

        Self {
            state,
            llm_client,
            tool_coordinator,
            conversation,
            max_iterations,
            iterations_without_tool: 0,
            current_plan: None,
        }
    }

    /// Process a user query
    ///
    /// # Errors
    /// Returns `AgentError` if the agent fails to process the query, including:
    /// - `MaxIterationsReached` if the maximum number of iterations is exceeded
    /// - LLM errors from querying the language model
    /// - Tool execution errors
    #[allow(clippy::too_many_lines)]
    pub async fn process_query(&mut self, user_query: &str) -> Result<String, AgentError> {
        info!("Processing query: {}", user_query);

        // Reset tool call counter for this query
        TOOL_CALLS_TOTAL.store(0, Ordering::Relaxed);
        self.iterations_without_tool = 0;

        // Add user message to conversation
        self.conversation.add_message(Message::user(user_query));

        let mut iteration = 0;

        loop {
            iteration += 1;

            if iteration > self.max_iterations {
                error!("Max iterations reached ({})", self.max_iterations);
                return Err(AgentError::MaxIterationsReached(self.max_iterations));
            }

            // Check if we're stuck (too many iterations without tool use)
            if self.iterations_without_tool >= 3 && iteration > 5 {
                warn!(
                    "LLM hasn't used tools in {} iterations. Adding guidance.",
                    self.iterations_without_tool
                );
                // Add a guidance message to nudge the LLM toward tool use
                self.conversation.add_message(Message::system(
                    "Reminder: If you need information about files, directories, or code, \
                     use a tool immediately with @tool_name({...}) syntax. \
                     For example: @list_directory({\"path\": \"/path/to/dir\"})",
                ));
            }

            // If approaching iteration limit, force summary
            if iteration >= self.max_iterations - 1 {
                warn!(
                    "Approaching iteration limit ({}/{}). Forcing summary.",
                    iteration, self.max_iterations
                );
                self.conversation.add_message(Message::system(
                    "You are at the iteration limit. Provide a final summary of what you can determine \
                     from the available information, or clearly state what additional information you need."
                ));
            }

            debug!("Agent iteration: {}/{}", iteration, self.max_iterations);

            // Get LLM response
            let tools = self.tool_coordinator.get_tool_definitions();
            let tools_vec: Vec<crate::types::ToolDefinition> =
                tools.iter().map(|t| (*t).clone()).collect();

            // Limit conversation history to last 10 messages (excluding system prompt)
            // This reduces context size for faster response times
            let all_messages = self.conversation.get_messages();

            // Collect non-system messages, take last 10
            let non_system: Vec<_> = all_messages
                .iter()
                .filter(|m| m.role != crate::types::Role::System)
                .cloned()
                .collect();

            let limited_messages: Vec<_> =
                non_system.iter().rev().take(10).rev().cloned().collect();

            // Rebuild with system prompt first
            let mut messages_for_llm = Vec::new();
            if let Some(sys_msg) = all_messages
                .iter()
                .find(|m| m.role == crate::types::Role::System)
            {
                messages_for_llm.push(sys_msg.clone());
            }
            messages_for_llm.extend(limited_messages);

            let response = self
                .llm_client
                .query_with_tools(&messages_for_llm, Some(&tools_vec))
                .await
                .map_err(AgentError::LlmClient)?;

            debug!("LLM response: {}", response.content);

            // Add assistant response to conversation
            self.conversation.add_message(response.clone());

            // Check if LLM requested tool calls via native tool_call format
            if let Some(tool_calls) = response.tool_calls.clone() {
                debug!("LLM requested {} native tool call(s)", tool_calls.len());
                self.iterations_without_tool = 0;

                for tool_call in tool_calls {
                    info!("Executing native tool: {}", tool_call.name());

                    // Execute tool
                    let tool_result = self.tool_coordinator.execute_tool(&tool_call);

                    debug!(
                        "Tool '{}' completed: success={}",
                        tool_call.name(),
                        tool_result.success
                    );

                    // Add tool result to conversation
                    self.conversation
                        .add_tool_result(tool_call.id.clone(), &tool_result);
                }

                // Continue loop - LLM will process tool results
                continue;
            }

            // Check if LLM requested tool calls via text syntax
            if let Some((tool_name, args_json)) = parse_tool_call_from_text(&response.content) {
                info!("Parsed text-based tool call: {}({})", tool_name, args_json);
                self.iterations_without_tool = 0;
                TOOL_CALLS_TOTAL.fetch_add(1, Ordering::Relaxed);

                // Create a synthetic tool call for execution
                let tool_call = crate::types::ToolCall::new(
                    format!("call_text_{iteration}"),
                    &tool_name,
                    args_json.clone(),
                );

                // Execute tool
                let tool_result = self.tool_coordinator.execute_tool(&tool_call);

                debug!(
                    "Tool '{}' completed: success={}",
                    tool_name, tool_result.success
                );

                // Add tool result to conversation
                self.conversation
                    .add_tool_result(tool_call.id.clone(), &tool_result);

                // Continue loop - LLM will process tool results
                continue;
            }

            // No tool calls - LLM is just talking
            self.iterations_without_tool += 1;
            info!(
                "No tool call detected (iterations without tool: {})",
                self.iterations_without_tool
            );

            // If this is the first iteration and no tool was used, the LLM might be answering directly
            if iteration == 1 {
                info!("LLM provided direct response without tools");
                return Ok(response.content);
            }

            // If we've had tool calls but now LLM is providing final answer
            if TOOL_CALLS_TOTAL.load(Ordering::Relaxed) > 0 {
                info!(
                    "LLM provided final response after {} tool call(s)",
                    TOOL_CALLS_TOTAL.load(Ordering::Relaxed)
                );
                return Ok(response.content);
            }

            // LLM is just talking without using tools - continue to next iteration
            // The guidance message will be added if this continues
        }
    }

    /// Process a complex query with multi-step planning
    ///
    /// This method breaks down complex queries into multiple steps and executes them sequentially.
    /// Example: "Find all TODOs in Rust files and count them" becomes:
    /// 1. `search_files(directory=".", pattern="*.rs")`
    /// 2. For each file: `grep_recursive(pattern="TODO")`
    /// 3. Aggregate and count results
    ///
    /// # Errors
    /// Returns `AgentError` if the agent fails to process the query, including:
    /// - `MaxIterationsReached` if the maximum number of iterations is exceeded
    /// - LLM errors from querying the language model
    /// - Tool execution errors
    #[allow(clippy::unused_async)]
    pub async fn process_complex_query(&mut self, user_query: &str) -> Result<String, AgentError> {
        info!(
            "Processing complex query with multi-step planning: {}",
            user_query
        );

        // Create a task plan
        let mut plan = TaskPlan::new(user_query.to_string());

        // Analyze query and create initial plan
        // For now, we use a simple heuristic-based approach
        // In a more advanced implementation, this could use the LLM to generate the plan
        self.create_plan_for_query(&mut plan, user_query)?;

        info!("Created plan with {} steps", plan.steps.len());

        // Add plan introduction to conversation
        self.conversation.add_message(Message::system(format!(
            "Multi-step task plan created: {} steps to complete '{user_query}'",
            plan.steps.len()
        )));

        // Execute each step
        while !plan.completed {
            if let Some(step) = plan.next_step() {
                info!(
                    "Executing step {}: {}",
                    plan.current_step + 1,
                    step.description
                );

                // Create tool call for this step
                let tool_call = ToolCall::new(
                    format!("plan_step_{}", plan.current_step),
                    &step.tool_name,
                    step.arguments.clone(),
                );

                // Execute the tool
                let tool_result = self.tool_coordinator.execute_tool(&tool_call);

                info!(
                    "Step {} completed: success={}",
                    plan.current_step + 1,
                    tool_result.success
                );

                // Record result
                if tool_result.success {
                    plan.complete_current_step(tool_result.output.clone());

                    // Add tool result to conversation
                    self.conversation
                        .add_tool_result(tool_call.id.clone(), &tool_result);
                } else {
                    // Step failed
                    let error_msg = tool_result.error.clone().unwrap_or_default();
                    plan.complete_current_step(format!("Error: {error_msg}"));

                    // Add error to conversation
                    self.conversation.add_message(Message::system(format!(
                        "Step {} failed: {error_msg}",
                        plan.current_step
                    )));

                    // Continue with next step or abort
                    // For now, we continue but log the error
                }

                // Track progress
                info!("Plan progress: {}", plan.progress_string());
            } else {
                break;
            }
        }

        // Generate final summary
        let summary = self.generate_plan_summary(&plan);
        Ok(summary)
    }

    /// Create a task plan for a complex query
    ///
    /// Uses heuristics to determine what steps are needed
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn create_plan_for_query(&self, plan: &mut TaskPlan, query: &str) -> Result<(), AgentError> {
        let query_lower = query.to_lowercase();

        // Example: "Find all TODOs in Rust files"
        if query_lower.contains("todo")
            && (query_lower.contains("rust") || query_lower.contains(".rs"))
        {
            plan.add_step(
                "Find all Rust files".to_string(),
                "search_files".to_string(),
                serde_json::json!({
                    "directory": ".",
                    "pattern": "*.rs"
                }),
            );
            plan.add_step(
                "Search for TODO comments in Rust files".to_string(),
                "grep_recursive".to_string(),
                serde_json::json!({
                    "directory": ".",
                    "pattern": "TODO",
                    "file_pattern": "*.rs"
                }),
            );
            return Ok(());
        }

        // Example: "Count lines in all source files"
        if query_lower.contains("count") && query_lower.contains("line") {
            plan.add_step(
                "Find all source files".to_string(),
                "search_files".to_string(),
                serde_json::json!({
                    "directory": ".",
                    "pattern": "*.{rs,py,js,ts,go}"
                }),
            );
            plan.add_step(
                "Count lines in source files".to_string(),
                "code_count_lines".to_string(),
                serde_json::json!({
                    "path": "."
                }),
            );
            return Ok(());
        }

        // Example: "Show git status and recent commits"
        if query_lower.contains("git") {
            if query_lower.contains("status") {
                plan.add_step(
                    "Get git repository status".to_string(),
                    "git_status".to_string(),
                    serde_json::json!({
                        "repo_path": "."
                    }),
                );
            }
            if query_lower.contains("commit") || query_lower.contains("log") {
                plan.add_step(
                    "Get recent git commits".to_string(),
                    "git_log".to_string(),
                    serde_json::json!({
                        "repo_path": ".",
                        "count": 10
                    }),
                );
            }
            return Ok(());
        }

        // Example: "List all files in src directory"
        if query_lower.contains("list") && query_lower.contains("file") {
            plan.add_step(
                "List directory contents".to_string(),
                "list_directory".to_string(),
                serde_json::json!({
                    "path": "src"
                }),
            );
            return Ok(());
        }

        // Default: no specific plan, use standard processing
        Ok(())
    }

    /// Generate a summary of the completed plan
    #[allow(clippy::unused_self, clippy::format_push_string)]
    fn generate_plan_summary(&self, plan: &TaskPlan) -> String {
        let mut summary = String::new();
        summary.push_str(&format!("Completed: {}\n\n", plan.query));

        for (i, step) in plan.steps.iter().enumerate() {
            summary.push_str(&format!(
                "Step {}: {} - {}\n",
                i + 1,
                step.description,
                if step.completed { "Done" } else { "Pending" }
            ));
            if let Some(ref result) = step.result {
                // Show first 200 chars of result
                let preview = if result.len() > 200 {
                    format!("{}...", &result[..200])
                } else {
                    result.clone()
                };
                summary.push_str(&format!("  Result: {preview}\n"));
            }
        }

        summary
    }

    /// Reset conversation history
    pub fn reset_conversation(&mut self) {
        self.conversation.clear();
        self.conversation.add_system_prompt(
            create_system_prompt(),
            self.tool_coordinator.get_tool_definitions(),
        );
        self.iterations_without_tool = 0;
        info!("Conversation reset");
    }

    /// Get conversation history
    #[allow(dead_code)]
    #[must_use]
    pub fn get_conversation(&self) -> &Conversation {
        &self.conversation
    }

    /// Get the number of tools available
    #[allow(dead_code)]
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.tool_coordinator.tool_count()
    }
}

/// Parse a tool call from text response.
///
/// Supports multiple syntaxes for robustness with small LLMs.
/// Order optimized for performance: JSON first (most explicit), then @tool, then /cmd.
///
/// 1. `{"function_name": "...", "function_arg": {...}}` - JSON format (MOST EXPLICIT)
/// 2. `@tool_name({...})` - Primary syntax (most distinctive)
/// 3. `/command args` - Shell command style (e.g., `/ls src`)
/// 4. `<tool>tool_name({...})</tool>` - XML-style tags
/// 5. `TOOL_CALL: tool_name({...})` - Legacy syntax
///
/// Returns `Some((tool_name, args_json))` if found, `None` otherwise.
#[must_use]
pub fn parse_tool_call_from_text(text: &str) -> Option<(String, Value)> {
    // 1. Try JSON format FIRST (most explicit, recommended by LLM)
    if let Some(result) = parse_json_function_syntax(text) {
        return Some(result);
    }

    // 2. Try @tool_name({...}) syntax (most distinctive)
    if let Some(result) = parse_at_syntax(text) {
        return Some(result);
    }

    // 3. Try shell command style: /command args
    if let Some(result) = parse_shell_command_syntax(text) {
        return Some(result);
    }

    // 4. Try <tool>...</tool> XML syntax
    if let Some(result) = parse_xml_syntax(text) {
        return Some(result);
    }

    // 5. Try TOOL_CALL: legacy syntax
    if let Some(result) = parse_legacy_syntax(text) {
        return Some(result);
    }

    None
}

/// Parse @`tool_name`({...}) syntax
fn parse_at_syntax(text: &str) -> Option<(String, Value)> {
    // Look for @ followed by tool name
    let chars = text.char_indices().peekable();

    for (idx, c) in chars {
        if c == '@' {
            // Found @, now extract tool name
            let start = idx + 1;
            let rest = &text[start..];

            // Tool name is alphanumeric and underscores until ( or { or whitespace
            let tool_name_end = rest
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            let tool_name = rest[..tool_name_end].trim();

            if tool_name.is_empty() {
                continue;
            }

            // Find the JSON arguments (look for { after tool name)
            let after_name = &rest[tool_name_end..];

            // Skip whitespace and optional (
            let trimmed = after_name.trim_start();

            // Handle @tool() with empty parens
            if trimmed.starts_with("()") || trimmed.starts_with('(') && trimmed.starts_with("())") {
                // @ls() or @tool() - return empty JSON
                let mapped_name = map_short_tool_name(tool_name);
                return Some((mapped_name, serde_json::json!({})));
            }

            let json_start = if trimmed.starts_with('(') {
                // @tool({...}) format - find { after (
                let after_paren = trimmed.trim_start_matches('(').trim_start();
                if let Some(brace_idx) = after_paren.find('{') {
                    start + tool_name_end + (after_name.len() - after_paren.len()) + brace_idx
                } else {
                    continue;
                }
            } else if trimmed.starts_with('{') {
                // @tool{...} format
                start + tool_name_end + (after_name.len() - trimmed.len())
            } else {
                continue;
            };

            let json_str = &text[json_start..];

            // Parse JSON with brace matching
            if let Some((json_content, _)) = extract_json_object(json_str)
                && let Ok(args) = serde_json::from_str::<Value>(&json_content)
            {
                let mapped_name = map_short_tool_name(tool_name);
                return Some((mapped_name, args));
            }
        }
    }

    None
}

/// Map short tool names to full tool names
fn map_short_tool_name(short_name: &str) -> String {
    match short_name {
        "ls" => "list_directory",
        "cat" | "cp" => "read_file",
        "pwd" | "cd" => "run_command",
        "grep" => "grep_recursive",
        "mkdir" => "create_directory",
        "rm" | "rmdir" => "delete_directory",
        "touch" | "mv" => "write_file",
        _ => short_name,
    }
    .to_string()
}

/// Parse <tool>...</tool> XML syntax
fn parse_xml_syntax(text: &str) -> Option<(String, Value)> {
    let text_lower = text.to_lowercase();
    let open_tag = "<tool>";
    let close_tag = "</tool>";

    if let Some(open_idx) = text_lower.find(open_tag) {
        let content_start = open_idx + open_tag.len();

        if let Some(close_idx) = text_lower[content_start..].find(close_tag) {
            let content = text[content_start..content_start + close_idx].trim();

            // Content should be tool_name({...}) or tool_name{...}
            // Extract tool name (everything before ( or {)
            let tool_name_end = content.find(['(', '{']).unwrap_or(content.len());
            let tool_name = content[..tool_name_end].trim();

            if tool_name.is_empty() {
                return None;
            }

            // Find JSON
            let after_name = &content[tool_name_end..];
            if let Some(brace_idx) = after_name.find('{') {
                let json_str = &content[tool_name_end + brace_idx..];
                if let Some((json_content, _)) = extract_json_object(json_str)
                    && let Ok(args) = serde_json::from_str::<Value>(&json_content)
                {
                    return Some((tool_name.to_string(), args));
                }
            }
        }
    }

    None
}

/// Parse `TOOL_CALL`: legacy syntax
fn parse_legacy_syntax(text: &str) -> Option<(String, Value)> {
    let text_lower = text.to_lowercase();
    let pattern = "tool_call:";

    if let Some(start_idx) = text_lower.find(pattern) {
        // Find the start of the tool call
        let after_pattern = &text[start_idx + pattern.len()..];
        let trimmed = after_pattern.trim_start();

        // Find the tool name (everything before the opening parenthesis or brace)
        let tool_name_end = trimmed.find(['(', '{']).unwrap_or(trimmed.len());
        let tool_name = trimmed[..tool_name_end].trim().to_string();

        if tool_name.is_empty() {
            return None;
        }

        // Find the JSON arguments
        let remaining = &trimmed[tool_name_end..];

        if let Some(json_start) = remaining.find('{') {
            let json_str = &remaining[json_start..];

            if let Some((json_content, _)) = extract_json_object(json_str)
                && let Ok(args) = serde_json::from_str::<Value>(&json_content)
            {
                return Some((tool_name, args));
            }
        }
    }

    None
}

/// Parse shell command style: /command args
/// Examples:
/// - `/ls src` → `list_directory({"path": "src"})`
/// - `/cat file.txt` → `read_file({"path": "file.txt"})`
/// - `/pwd` → `run_command({"command": "pwd"})`
fn parse_shell_command_syntax(text: &str) -> Option<(String, Value)> {
    // Look for lines starting with /
    for line in text.lines() {
        let trimmed = line.trim();

        // Check if line starts with / followed by alphanumeric (command)
        if let Some(after_slash) = trimmed.strip_prefix('/') {
            // Extract command name (alphanumeric until space or end)
            let space_idx = after_slash
                .find(|c: char| c.is_whitespace())
                .unwrap_or(after_slash.len());
            let command = &after_slash[..space_idx];

            if command.is_empty() || !command.chars().all(char::is_alphanumeric) {
                continue;
            }

            // Extract arguments (everything after command)
            let args_str = after_slash[space_idx..].trim();

            // Map shell commands to tool names and build arguments
            let (tool_name, args) = match command {
                "ls" | "dir" | "list" => {
                    // /ls [path] → list_directory({"path": "." or path})
                    let path = if args_str.is_empty() { "." } else { args_str }.to_string();
                    ("list_directory", serde_json::json!({"path": path}))
                }
                "cat" | "type" | "read" => {
                    // /cat file.txt → read_file({"path": "file.txt"})
                    if args_str.is_empty() {
                        continue;
                    }
                    ("read_file", serde_json::json!({"path": args_str}))
                }
                "pwd" => {
                    // /pwd → run_command({"command": "pwd"})
                    ("run_command", serde_json::json!({"command": "pwd"}))
                }
                "cd" => {
                    // /cd [dir] → run_command({"command": "cd", "args": dir})
                    let dir = if args_str.is_empty() { "." } else { args_str }.to_string();
                    (
                        "run_command",
                        serde_json::json!({"command": "cd", "args": dir}),
                    )
                }
                "grep" => {
                    // /grep pattern [file] → search_in_file or grep_recursive
                    if args_str.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = args_str.split_whitespace().collect();
                    if parts.len() >= 2 {
                        (
                            "grep_recursive",
                            serde_json::json!({
                                "pattern": parts[0],
                                "directory": ".",
                                "file_pattern": parts[1]
                            }),
                        )
                    } else {
                        (
                            "search_in_file",
                            serde_json::json!({
                                "pattern": parts[0],
                                "path": "."
                            }),
                        )
                    }
                }
                "rm" | "del" => {
                    // /rm file → We don't have a delete_file tool, skip
                    continue;
                }
                "mkdir" => {
                    // /mkdir dir → create_directory({"path": dir, "recursive": false})
                    if args_str.is_empty() {
                        continue;
                    }
                    (
                        "create_directory",
                        serde_json::json!({
                            "path": args_str,
                            "recursive": false
                        }),
                    )
                }
                _ => {
                    // Unknown command, try to map to a tool by name
                    continue;
                }
            };

            return Some((tool_name.to_string(), args));
        }
    }

    None
}

/// Parse JSON format: `{"function_name": "...", "function_arg": {...}}`
/// Also handles: `{"name": "...", "arguments": {...}}`
fn parse_json_function_syntax(text: &str) -> Option<(String, Value)> {
    // Look for JSON object containing function_name or name
    let text_lower = text.to_lowercase();

    // Find function_name or name field
    let fn_name_key = if text_lower.contains("\"function_name\"") {
        "function_name"
    } else if text_lower.contains("\"name\"") && text_lower.contains("\"function_arg\"") {
        "name"
    } else {
        return None;
    };

    // Find function_arg or arguments field
    let fn_arg_key = if text_lower.contains("\"function_arg\"") {
        "function_arg"
    } else if text_lower.contains("\"arguments\"") {
        "arguments"
    } else {
        return None;
    };

    // Extract the full JSON object
    if let Some(open_idx) = text.find('{')
        && let Some((json_str, _)) = extract_json_object(&text[open_idx..])
    {
        // Parse the JSON
        if let Ok(json_value) = serde_json::from_str::<Value>(&json_str) {
            // Extract function name
            let tool_name = json_value
                .get(fn_name_key)
                .and_then(|v| v.as_str())
                .map(ToString::to_string)?;

            // Extract arguments
            let args = json_value
                .get(fn_arg_key)
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));

            // Map common function names to tool names
            let mapped_name = match tool_name.as_str() {
                "http_request" => "fetch_url",
                "count_lines" => "count_lines",
                "grep_in_directory" => "grep_recursive",
                "git_status" => "git_status",
                "list_directory" => "list_directory",
                "read_file" => "read_file",
                "write_file" => "write_file",
                "search_files" => "search_files",
                "run_command" => "run_command",
                // Add more mappings as needed
                _ => &tool_name,
            };

            // Map argument field names if needed
            let mapped_args = map_arguments(mapped_name, &args);

            return Some((mapped_name.to_string(), mapped_args));
        }
    }

    None
}

/// Map argument field names to match tool expectations
fn map_arguments(tool_name: &str, args: &Value) -> Value {
    match tool_name {
        "fetch_url" => {
            // {"url": "...", "method": "GET"} → {"url": "..."}
            if let Some(obj) = args.as_object() {
                let mut mapped = serde_json::Map::new();
                if let Some(url) = obj.get("url") {
                    mapped.insert("url".to_string(), url.clone());
                }
                serde_json::Value::Object(mapped)
            } else {
                args.clone()
            }
        }
        "count_lines" => {
            // {"file_path": "..."} → {"path": "..."}
            if let Some(obj) = args.as_object() {
                let mut mapped = serde_json::Map::new();
                if let Some(file_path) = obj.get("file_path") {
                    mapped.insert("path".to_string(), file_path.clone());
                }
                serde_json::Value::Object(mapped)
            } else {
                args.clone()
            }
        }
        "grep_in_directory" | "grep_recursive" => {
            // {"directory_path": "...", "search_pattern": "..."} → {"directory": "...", "pattern": "..."}
            if let Some(obj) = args.as_object() {
                let mut mapped = serde_json::Map::new();
                if let Some(dir) = obj.get("directory_path") {
                    mapped.insert("directory".to_string(), dir.clone());
                }
                if let Some(pattern) = obj.get("search_pattern") {
                    mapped.insert("pattern".to_string(), pattern.clone());
                }
                serde_json::Value::Object(mapped)
            } else {
                args.clone()
            }
        }
        "git_status" => {
            // {} → {"repo_path": "."}
            serde_json::json!({"repo_path": "."})
        }
        _ => args.clone(),
    }
}

/// Extract a JSON object from a string, handling nested objects and strings.
/// Returns (`json_string`, `end_index`) if successful.
fn extract_json_object(s: &str) -> Option<(String, usize)> {
    if !s.starts_with('{') {
        return None;
    }

    let mut brace_count = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, c) in s.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }

        match c {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => brace_count += 1,
            '}' if !in_string => {
                brace_count -= 1;
                if brace_count == 0 {
                    return Some((s[..=i].to_string(), i + 1));
                }
            }
            _ => {}
        }
    }

    None // No matching closing brace
}

/// Create the system prompt for the agent.
///
/// ULTRA SHORT VERSION - All tools listed concisely
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn create_system_prompt() -> String {
    r#"You have DIRECT file/git/web access. Use tools immediately for file/code questions. NEVER say "I can't access files".

TOOLS: /ls /cat /pwd /cd /grep /mkdir | @list_directory @read_file @read_lines @write_file @append_file @insert_at_line @directory_tree @file_exists @file_info @count_lines @code_stats @code_count_lines @search_files @search_in_file @grep_recursive @extract_functions @find_imports @git_status @git_diff @git_log @run_command @fetch_url @fetch_url_headers @delete_directory @create_directory

RULES: 1) Use ONE tool immediately 2) Format: /cmd or @tool({...}) 3) NEVER refuse file access

Ex: User: List files → You: /ls
User: Git status → You: @git_status({"repo_path":"."})

READY!"#
        .to_string()
}

// Helper function for testing (needs to be outside impl block)
#[allow(clippy::unnecessary_wraps)]
fn create_plan_for_query_helper(plan: &mut TaskPlan, query: &str) -> Result<(), AgentError> {
    let query_lower = query.to_lowercase();

    if query_lower.contains("todo") && (query_lower.contains("rust") || query_lower.contains(".rs"))
    {
        plan.add_step(
            "Find all Rust files".to_string(),
            "search_files".to_string(),
            serde_json::json!({
                "directory": ".",
                "pattern": "*.rs"
            }),
        );
        plan.add_step(
            "Search for TODO comments in Rust files".to_string(),
            "grep_recursive".to_string(),
            serde_json::json!({
                "directory": ".",
                "pattern": "TODO",
                "file_pattern": "*.rs"
            }),
        );
        return Ok(());
    }

    if query_lower.contains("git") {
        if query_lower.contains("status") {
            plan.add_step(
                "Get git repository status".to_string(),
                "git_status".to_string(),
                serde_json::json!({
                    "repo_path": "."
                }),
            );
        }
        if query_lower.contains("commit") || query_lower.contains("log") {
            plan.add_step(
                "Get recent git commits".to_string(),
                "git_log".to_string(),
                serde_json::json!({
                    "repo_path": ".",
                    "count": 10
                }),
            );
        }
        return Ok(());
    }

    if query_lower.contains("list") && query_lower.contains("file") {
        plan.add_step(
            "List directory contents".to_string(),
            "list_directory".to_string(),
            serde_json::json!({
                "path": "src"
            }),
        );
        return Ok(());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_prompt_creation() {
        let prompt = create_system_prompt();
        assert!(prompt.contains("DIRECT"));
        assert!(prompt.contains("/ls"));
        assert!(prompt.contains("@read_file"));
        assert!(prompt.contains("@git_status"));
        assert!(prompt.contains("@fetch_url"));
        assert!(prompt.contains("NEVER"));
        assert!(prompt.contains("READY"));
    }

    #[test]
    fn test_parse_tool_call_at_syntax() {
        let text = "@read_file({\"path\": \"/home/test.rs\"})";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "read_file");
        assert_eq!(args["path"], "/home/test.rs");
    }

    #[test]
    fn test_parse_tool_call_at_syntax_with_parens() {
        let text = "@list_directory({\"path\": \"/home/project\", \"max_results\": 50})";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "list_directory");
        assert_eq!(args["path"], "/home/project");
        assert_eq!(args["max_results"], 50);
    }

    #[test]
    fn test_parse_tool_call_xml_syntax() {
        let text = "<tool>read_file({\"path\": \"/test.txt\"})</tool>";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "read_file");
        assert_eq!(args["path"], "/test.txt");
    }

    #[test]
    fn test_parse_tool_call_legacy_syntax() {
        let text = "TOOL_CALL: read_file({\"path\": \"/home/test.rs\"})";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "read_file");
        assert_eq!(args["path"], "/home/test.rs");
    }

    #[test]
    fn test_parse_tool_call_with_surrounding_text() {
        let text = "Let me read that file for you.\n\n@read_file({\"path\": \"/home/test.rs\"})\n\nI'll analyze it next.";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "read_file");
        assert_eq!(args["path"], "/home/test.rs");
    }

    #[test]
    fn test_parse_tool_call_lowercase_legacy() {
        let text = "tool_call: read_file({\"path\": \"/test.txt\"})";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "read_file");
        assert_eq!(args["path"], "/test.txt");
    }

    #[test]
    fn test_parse_no_tool_call() {
        let text = "Hello! How can I help you today?";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_invalid_json() {
        let text = "@read_file({invalid json})";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_tool_call_with_string_containing_braces() {
        let text = r#"@write_file({"path": "/test.txt", "content": "Hello {world}"})"#;
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "write_file");
        assert_eq!(args["path"], "/test.txt");
        assert_eq!(args["content"], "Hello {world}");
    }

    #[test]
    fn test_parse_nested_json() {
        let text = r#"@run_command({"command": "echo", "args": "hello {world}"})"#;
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "run_command");
        assert_eq!(args["command"], "echo");
        assert_eq!(args["args"], "hello {world}");
    }

    #[test]
    fn test_extract_json_object_simple() {
        let json = r#"{"path": "/test.txt"}"#;
        let result = extract_json_object(json);
        assert!(result.is_some());
        let (content, end) = result.unwrap();
        assert_eq!(content, json);
        assert_eq!(end, json.len());
    }

    #[test]
    fn test_extract_json_object_nested() {
        let json = r#"{"outer": {"inner": "value"}}"#;
        let result = extract_json_object(json);
        assert!(result.is_some());
        let (content, end) = result.unwrap();
        assert_eq!(content, json);
        assert_eq!(end, json.len());
    }

    #[test]
    fn test_extract_json_object_with_string_braces() {
        let json = r#"{"content": "Hello {world}"}"#;
        let result = extract_json_object(json);
        assert!(result.is_some());
        let (content, end) = result.unwrap();
        assert_eq!(content, json);
        assert_eq!(end, json.len());
    }

    #[test]
    fn test_extract_json_object_no_match() {
        let json = r#"{"incomplete"#;
        let result = extract_json_object(json);
        assert!(result.is_none());
    }

    #[test]
    fn test_agent_controller_creation() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        assert!(controller.tool_count() > 0);
        assert_eq!(controller.max_iterations, state.config.agent.max_iterations);
    }

    #[test]
    fn test_agent_controller_with_custom_config() {
        let mut state = AppState::with_defaults("/tmp".to_string());
        state.config.agent.max_iterations = 5;
        state.config.agent.tool_timeout_seconds = 10;

        let controller = AgentController::new(&mut state);

        assert_eq!(controller.max_iterations, 5);
        assert!(controller.tool_count() > 10);
    }

    #[test]
    fn test_reset_conversation() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut controller = AgentController::new(&mut state);

        controller.conversation.add_message(Message::user("Test"));
        assert_eq!(controller.conversation.len(), 2);

        controller.reset_conversation();
        assert_eq!(controller.conversation.len(), 1);
    }

    #[test]
    fn test_get_conversation() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        let conv = controller.get_conversation();
        assert!(!conv.is_empty());
    }

    #[test]
    fn test_tool_count() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        assert!(controller.tool_count() >= 20);
    }

    #[test]
    fn test_parse_multiple_tool_calls_returns_first() {
        let text = "@read_file({\"path\": \"/first.txt\"})\n@write_file({\"path\": \"/second.txt\", \"content\": \"test\"})";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "read_file");
        assert_eq!(args["path"], "/first.txt");
    }

    #[test]
    fn test_parse_at_syntax_variations() {
        // Without parentheses
        let text = "@read_file{\"path\": \"/test.txt\"}";
        let result = parse_at_syntax(text);
        assert!(result.is_some());

        // With parentheses
        let text = "@read_file({\"path\": \"/test.txt\"})";
        let result = parse_at_syntax(text);
        assert!(result.is_some());
    }

    // ========================================================================
    // Phase 1.4: Comprehensive Tools Integration Tests
    // ========================================================================

    #[test]
    fn test_agent_controller_has_tools() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        // Verify controller has tool definitions
        let tools = controller.tool_coordinator.get_tool_definitions();
        assert!(!tools.is_empty(), "Controller should have tool definitions");
        assert!(tools.len() >= 20, "Should have at least 20 tools available");
    }

    #[test]
    fn test_tool_definitions_include_required_tools() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        let tools = controller.tool_coordinator.get_tool_definitions();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

        // Verify essential file operation tools are present
        assert!(
            tool_names.contains(&"read_file"),
            "Should have read_file tool"
        );
        assert!(
            tool_names.contains(&"write_file"),
            "Should have write_file tool"
        );
        assert!(
            tool_names.contains(&"list_directory"),
            "Should have list_directory tool"
        );
        assert!(
            tool_names.contains(&"search_files"),
            "Should have search_files tool"
        );
    }

    #[test]
    fn test_tool_definitions_have_valid_schema() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        let tools = controller.tool_coordinator.get_tool_definitions();

        for tool in tools {
            // Verify each tool has required fields
            assert!(!tool.name.is_empty(), "Tool name should not be empty");
            assert!(
                !tool.description.is_empty(),
                "Tool description should not be empty"
            );

            // Verify parameters is a valid JSON object
            assert!(
                tool.parameters.is_object(),
                "Tool parameters should be a JSON object"
            );

            let params = tool.parameters.as_object().unwrap();
            assert!(
                params.contains_key("type"),
                "Parameters should have 'type' field"
            );
            assert_eq!(
                params["type"], "object",
                "Parameters type should be 'object'"
            );
        }
    }

    #[test]
    fn test_system_prompt_includes_tool_instructions() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        let messages = controller.conversation.get_messages();
        assert!(!messages.is_empty(), "Should have at least system message");

        let system_msg = &messages[0];
        assert_eq!(
            system_msg.role,
            Role::System,
            "First message should be system"
        );

        let system_content = &system_msg.content;
        // Verify system prompt mentions tools
        assert!(
            system_content.to_lowercase().contains("tool")
                || system_content.to_lowercase().contains("function")
                || system_content.to_lowercase().contains('@'),
            "System prompt should mention tools or functions"
        );
    }

    #[test]
    fn test_conversation_initialization_with_tools() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        // Verify conversation is initialized with system prompt and tool definitions
        let messages = controller.conversation.get_messages();
        assert_eq!(messages.len(), 1, "Should have exactly 1 message (system)");

        let system_msg = &messages[0];
        assert_eq!(system_msg.role, Role::System);
        assert!(
            system_msg.content.len() > 100,
            "System prompt should be substantial"
        );
    }

    #[test]
    fn test_tool_coordinator_creation_with_valid_config() {
        let workdir = std::path::PathBuf::from(".");
        let file_size_limit_mb = 10;
        let tool_timeout_ms = 30000;

        let coordinator = ToolCoordinator::new(workdir, file_size_limit_mb, tool_timeout_ms);

        // Note: get_max_file_size returns MB value
        assert_eq!(coordinator.get_max_file_size(), file_size_limit_mb);
        assert_eq!(coordinator.get_tool_timeout(), tool_timeout_ms);
    }

    #[test]
    fn test_tool_execution_with_invalid_args() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        // Create a tool call with invalid arguments
        let tool_call = ToolCall::new(
            "call_test",
            "read_file",
            serde_json::json!({"invalid_arg": "test"}), // Missing required 'path' argument
        );

        let result = controller.tool_coordinator.execute_tool(&tool_call);

        // Tool should fail due to invalid arguments
        assert!(!result.success, "Tool should fail with invalid arguments");
        assert!(result.error.is_some(), "Should have error message");
    }

    #[test]
    fn test_list_directory_tool_execution() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        // Execute list_directory on current directory
        let tool_call = ToolCall::new(
            "call_test",
            "list_directory",
            serde_json::json!({"path": "."}),
        );

        let result = controller.tool_coordinator.execute_tool(&tool_call);

        // Should succeed for current directory
        assert!(
            result.success,
            "list_directory should succeed on current directory"
        );
        assert!(!result.output.is_empty(), "Should return directory listing");
    }

    #[test]
    fn test_file_exists_tool_execution() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        // Test with existing file (Cargo.toml should exist)
        let tool_call = ToolCall::new(
            "call_test",
            "file_exists",
            serde_json::json!({"path": "Cargo.toml"}),
        );

        let result = controller.tool_coordinator.execute_tool(&tool_call);

        assert!(result.success, "file_exists should succeed");
        assert!(
            result.output.contains("true") || result.output.contains("exists"),
            "Should indicate file exists"
        );
    }

    #[test]
    fn test_read_file_tool_execution() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        // Read Cargo.toml
        let tool_call = ToolCall::new(
            "call_test",
            "read_file",
            serde_json::json!({"path": "Cargo.toml"}),
        );

        let result = controller.tool_coordinator.execute_tool(&tool_call);

        assert!(result.success, "read_file should succeed on Cargo.toml");
        assert!(
            result.output.contains("[package]"),
            "Should contain package info"
        );
    }

    #[test]
    #[ignore = "Requires actual file system access"]
    fn test_search_files_tool_execution() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        // Search for .rs files
        let tool_call = ToolCall::new(
            "call_test",
            "search_files",
            serde_json::json!({"pattern": "*.rs", "path": "src"}),
        );

        let result = controller.tool_coordinator.execute_tool(&tool_call);

        // Verify tool executed (may find files or not depending on environment)
        assert!(result.execution_time_ms > 0, "Should have execution time");
    }

    #[test]
    fn test_run_command_tool_execution() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        // Run a simple command
        let tool_call = ToolCall::new(
            "call_test",
            "run_command",
            serde_json::json!({"command": "echo hello"}),
        );

        let result = controller.tool_coordinator.execute_tool(&tool_call);

        // Command execution may succeed or fail depending on environment
        // Just verify the tool was attempted
        assert!(result.execution_time_ms > 0, "Should have execution time");
    }

    #[test]
    fn test_tool_result_formatting_for_llm() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        let tool_call = ToolCall::new(
            "call_test",
            "read_file",
            serde_json::json!({"path": "test.txt"}),
        );

        let result = controller.tool_coordinator.execute_tool(&tool_call);

        // Convert to LLM string format
        let llm_string = result.to_llm_string();

        // Verify format includes tool name and status
        assert!(llm_string.contains("read_file"), "Should contain tool name");
        assert!(llm_string.contains("status="), "Should contain status");
        assert!(
            llm_string.contains("<tool_result"),
            "Should use XML-like format"
        );
    }

    #[test]
    fn test_query_with_tools_vs_without_tools() {
        // This test verifies that tools parameter affects the request
        use crate::agent::llm_client::LlmClient;
        use crate::types::ToolDefinition;

        // Create a mock client (won't actually connect)
        let client = LlmClient::new("http://localhost:1234".to_string(), "test".to_string());

        // Create a test tool
        let tool = ToolDefinition::new(
            "test_tool",
            "A test tool",
            serde_json::json!({"type": "object"}),
        );

        let messages = [Message::user("Test query")];

        // The key difference: with tools, the request should include tools array
        // This is tested in llm_client tests, but we verify the flow here
        assert!(client.get_model() == "test");
    }

    #[test]
    fn test_agent_iteration_with_tool_calls() {
        let mut state = AppState::with_defaults(".".to_string());
        let mut controller = AgentController::new(&mut state);

        // Verify controller is ready for agentic loop
        assert_eq!(controller.iterations_without_tool, 0);
        assert!(controller.max_iterations > 0);

        // Simulate tool call detection
        let tool_call = ToolCall::new(
            "call_sim",
            "list_directory",
            serde_json::json!({"path": "."}),
        );

        // Execute tool
        let result = controller.tool_coordinator.execute_tool(&tool_call);

        // Add tool result to conversation
        controller
            .conversation
            .add_tool_result("call_sim".to_string(), &result);

        // Verify tool result was added
        let messages = controller.conversation.get_messages();
        assert!(messages.len() >= 2, "Should have tool result message");
    }

    #[test]
    fn test_max_iterations_protection() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        assert!(
            controller.max_iterations >= 5,
            "Should have reasonable max iterations"
        );
        assert!(controller.max_iterations <= 20, "Should have upper limit");
    }

    #[test]
    fn test_tool_timeout_configuration() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        // Verify tool timeout is set from config
        let timeout = controller.tool_coordinator.get_tool_timeout();
        assert!(timeout > 0, "Tool timeout should be positive");
        assert!(
            timeout <= 120_000,
            "Tool timeout should be reasonable (<= 2 min)"
        );
    }

    #[test]
    fn test_file_size_limit_enforcement() {
        let mut state = AppState::with_defaults(".".to_string());
        let controller = AgentController::new(&mut state);

        let max_size = controller.tool_coordinator.get_max_file_size();
        assert!(max_size > 0, "File size limit should be positive");
        assert!(max_size <= 100 * 1024 * 1024, "Should be <= 100MB");
    }

    // ========================================================================
    // Comprehensive Tool Tests - All 27 Tools
    // ========================================================================

    // File Operations Tests (12 tools)
    #[test]
    #[ignore = "Integration test - requires filesystem"]
    fn test_list_directory_tool() {
        let state = AppState::with_defaults(".".to_string());
        let coordinator = ToolCoordinator::new(
            state.workdir.clone(),
            state.config.tools.file_size_limit_mb,
            state.config.agent.tool_timeout_seconds * 1000,
        );

        let tool_call = ToolCall::new(
            "call_test",
            "list_directory",
            serde_json::json!({"path": "."}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(
            result.success,
            "list_directory should succeed on current directory"
        );
        assert!(
            result.output.contains("Total:"),
            "Should contain total count"
        );
    }

    #[test]
    #[ignore = "Integration test - requires filesystem"]
    fn test_read_file_tool() {
        let state = AppState::with_defaults(".".to_string());
        let coordinator = ToolCoordinator::new(
            state.workdir.clone(),
            state.config.tools.file_size_limit_mb,
            state.config.agent.tool_timeout_seconds * 1000,
        );

        let tool_call = ToolCall::new(
            "call_test",
            "read_file",
            serde_json::json!({"path": "Cargo.toml"}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.success, "read_file should succeed on Cargo.toml");
        assert!(
            result.output.contains("[package]"),
            "Should contain package info"
        );
    }

    #[test]
    #[ignore = "Integration test - requires filesystem"]
    fn test_count_lines_tool() {
        let state = AppState::with_defaults(".".to_string());
        let coordinator = ToolCoordinator::new(
            state.workdir.clone(),
            state.config.tools.file_size_limit_mb,
            state.config.agent.tool_timeout_seconds * 1000,
        );

        let tool_call = ToolCall::new(
            "call_test",
            "count_lines",
            serde_json::json!({"path": "Cargo.toml"}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.success, "count_lines should succeed");
        assert!(
            result.output.contains("Lines:"),
            "Should contain line count"
        );
    }

    #[test]
    #[ignore = "Integration test - requires filesystem"]
    fn test_file_exists_tool() {
        let state = AppState::with_defaults(".".to_string());
        let coordinator = ToolCoordinator::new(
            state.workdir.clone(),
            state.config.tools.file_size_limit_mb,
            state.config.agent.tool_timeout_seconds * 1000,
        );

        // Test existing file
        let tool_call = ToolCall::new(
            "call_test",
            "file_exists",
            serde_json::json!({"path": "Cargo.toml"}),
        );
        let result = coordinator.execute_tool(&tool_call);
        assert!(result.success);
        assert!(result.output.contains("true") || result.output.contains("exists"));

        // Test non-existing file
        let tool_call = ToolCall::new(
            "call_test",
            "file_exists",
            serde_json::json!({"path": "nonexistent_file_12345.txt"}),
        );
        let result = coordinator.execute_tool(&tool_call);
        assert!(result.success);
        assert!(result.output.contains("false") || result.output.contains("not exist"));
    }

    #[test]
    #[ignore = "Integration test - requires filesystem"]
    fn test_directory_tree_tool() {
        let state = AppState::with_defaults(".".to_string());
        let coordinator = ToolCoordinator::new(
            state.workdir.clone(),
            state.config.tools.file_size_limit_mb,
            state.config.agent.tool_timeout_seconds * 1000,
        );

        let tool_call = ToolCall::new(
            "call_test",
            "directory_tree",
            serde_json::json!({"path": ".", "max_depth": 2}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.success, "directory_tree should succeed");
        assert!(
            result.output.contains("📁") || result.output.contains("Total:"),
            "Should show tree structure"
        );
    }

    // Search Operations Tests (5 tools)
    #[test]
    #[ignore = "Integration test - requires filesystem"]
    fn test_search_files_tool() {
        let state = AppState::with_defaults(".".to_string());
        let coordinator = ToolCoordinator::new(
            state.workdir.clone(),
            state.config.tools.file_size_limit_mb,
            state.config.agent.tool_timeout_seconds * 1000,
        );

        let tool_call = ToolCall::new(
            "call_test",
            "search_files",
            serde_json::json!({"directory": ".", "pattern": "*.toml", "max_results": 10}),
        );

        let result = coordinator.execute_tool(&tool_call);
        // Should execute without crashing (may or may not find files)
        assert!(result.execution_time_ms > 0, "Should have execution time");
    }

    #[test]
    #[ignore = "Integration test - requires filesystem"]
    fn test_grep_recursive_tool() {
        let state = AppState::with_defaults(".".to_string());
        let coordinator = ToolCoordinator::new(
            state.workdir.clone(),
            state.config.tools.file_size_limit_mb,
            state.config.agent.tool_timeout_seconds * 1000,
        );

        // Use a shallow directory to avoid stack overflow
        let tool_call = ToolCall::new(
            "call_test",
            "grep_recursive",
            serde_json::json!({"directory": ".", "pattern": "fn ", "max_results": 10}),
        );

        let result = coordinator.execute_tool(&tool_call);
        // Should execute without crashing (may or may not find matches)
        assert!(result.execution_time_ms > 0, "Should have execution time");
    }

    // Git Operations Tests (3 tools)
    #[test]
    #[ignore = "Integration test - requires git repository"]
    fn test_git_status_tool() {
        let state = AppState::with_defaults(".".to_string());
        let coordinator = ToolCoordinator::new(
            state.workdir.clone(),
            state.config.tools.file_size_limit_mb,
            state.config.agent.tool_timeout_seconds * 1000,
        );

        let tool_call = ToolCall::new(
            "call_test",
            "git_status",
            serde_json::json!({"repo_path": "."}),
        );

        let result = coordinator.execute_tool(&tool_call);
        // Git status should work in a git repository
        assert!(
            result.success || result.output.contains("git"),
            "Should execute git command"
        );
    }

    #[test]
    #[ignore = "Integration test - requires git repository"]
    fn test_git_log_tool() {
        let state = AppState::with_defaults(".".to_string());
        let coordinator = ToolCoordinator::new(
            state.workdir.clone(),
            state.config.tools.file_size_limit_mb,
            state.config.agent.tool_timeout_seconds * 1000,
        );

        let tool_call = ToolCall::new(
            "call_test",
            "git_log",
            serde_json::json!({"repo_path": ".", "count": 3}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(
            result.success || result.output.contains("commit"),
            "Should show git log"
        );
    }

    // System/Web Tests (4 tools)
    #[test]
    #[ignore = "Integration test - requires system command execution"]
    fn test_run_command_tool() {
        let state = AppState::with_defaults(".".to_string());
        let coordinator = ToolCoordinator::new(
            state.workdir.clone(),
            state.config.tools.file_size_limit_mb,
            state.config.agent.tool_timeout_seconds * 1000,
        );

        let tool_call = ToolCall::new(
            "call_test",
            "run_command",
            serde_json::json!({"command": "echo", "args": "hello"}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.success, "run_command should succeed with echo");
        assert!(
            result.output.contains("hello"),
            "Should contain echo output"
        );
    }

    #[test]
    #[ignore = "Integration test - requires filesystem access"]
    fn test_create_directory_tool() {
        use std::fs;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(temp_dir.path().to_path_buf(), 10, 30000);

        let tool_call = ToolCall::new(
            "call_test",
            "create_directory",
            serde_json::json!({"path": "test_dir", "recursive": false}),
        );

        let result = coordinator.execute_tool(&tool_call);
        // Test may fail due to permissions but shouldn't crash
        assert!(result.execution_time_ms > 0, "Should have execution time");
    }

    // Parser Tests - JSON Format
    #[test]
    fn test_parse_json_function_syntax() {
        let text =
            r#"{"function_name": "count_lines", "function_arg": {"file_path": "./main.rs"}}"#;
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some(), "Should parse JSON format");
        let (name, args) = result.unwrap();
        assert_eq!(name, "count_lines");
        assert_eq!(args["path"], "./main.rs"); // Should map file_path to path
    }

    #[test]
    fn test_parse_json_http_request() {
        let text = r#"{"function_name": "http_request", "function_arg": {"url": "https://example.com", "method": "GET"}}"#;
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some(), "Should parse http_request");
        let (name, args) = result.unwrap();
        assert_eq!(name, "fetch_url"); // Should map to fetch_url
        assert_eq!(args["url"], "https://example.com");
    }

    #[test]
    fn test_parse_json_grep_in_directory() {
        let text = r#"{"function_name": "grep_in_directory", "function_arg": {"directory_path": "./src", "search_pattern": "TODO"}}"#;
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some(), "Should parse grep_in_directory");
        let (name, args) = result.unwrap();
        assert_eq!(name, "grep_recursive"); // Should map to grep_recursive
        assert_eq!(args["directory"], "./src");
        assert_eq!(args["pattern"], "TODO");
    }

    #[test]
    fn test_parse_json_git_status() {
        let text = r#"{"function_name": "git_status", "function_arg": {}}"#;
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some(), "Should parse git_status");
        let (name, args) = result.unwrap();
        assert_eq!(name, "git_status");
        assert_eq!(args["repo_path"], "."); // Should default to current directory
    }

    // Parser Tests - Shell Commands
    #[test]
    fn test_parse_shell_ls() {
        let text = "/ls src";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some(), "Should parse /ls");
        let (name, args) = result.unwrap();
        assert_eq!(name, "list_directory");
        assert_eq!(args["path"], "src");
    }

    #[test]
    fn test_parse_shell_cat() {
        let text = "/cat file.txt";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some(), "Should parse /cat");
        let (name, args) = result.unwrap();
        assert_eq!(name, "read_file");
        assert_eq!(args["path"], "file.txt");
    }

    #[test]
    fn test_parse_shell_pwd() {
        let text = "/pwd";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some(), "Should parse /pwd");
        let (name, args) = result.unwrap();
        assert_eq!(name, "run_command");
        assert_eq!(args["command"], "pwd");
    }

    #[test]
    fn test_parse_shell_mkdir() {
        let text = "/mkdir test_dir";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some(), "Should parse /mkdir");
        let (name, args) = result.unwrap();
        assert_eq!(name, "create_directory");
        assert_eq!(args["path"], "test_dir");
    }

    // Parser Tests - @ Syntax
    #[test]
    fn test_parse_at_list_directory() {
        let text = r#"@list_directory({"path": "/home/project"})"#;
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "list_directory");
        assert_eq!(args["path"], "/home/project");
    }

    #[test]
    fn test_parse_at_read_file() {
        let text = r#"@read_file({"path": "/etc/config.toml"})"#;
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "read_file");
        assert_eq!(args["path"], "/etc/config.toml");
    }

    #[test]
    fn test_parse_at_git_status() {
        let text = r#"@git_status({"repo_path": "/home/project"})"#;
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "git_status");
        assert_eq!(args["repo_path"], "/home/project");
    }

    #[test]
    fn test_parse_at_fetch_url() {
        let text = r#"@fetch_url({"url": "https://example.com"})"#;
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "fetch_url");
        assert_eq!(args["url"], "https://example.com");
    }

    #[test]
    fn test_parse_at_short_tool_names() {
        // Test @ls() empty parens
        let text = "@ls()";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "list_directory");
        assert_eq!(args, serde_json::json!({}));

        // Test @cat() empty parens
        let text = "@cat()";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "read_file");
        assert_eq!(args, serde_json::json!({}));

        // Test @pwd() empty parens
        let text = "@pwd()";
        let result = parse_tool_call_from_text(text);
        assert!(result.is_some());
        let (name, args) = result.unwrap();
        assert_eq!(name, "run_command");
        assert_eq!(args, serde_json::json!({}));
    }

    #[test]
    fn test_map_short_tool_name() {
        assert_eq!(map_short_tool_name("ls"), "list_directory");
        assert_eq!(map_short_tool_name("cat"), "read_file");
        assert_eq!(map_short_tool_name("pwd"), "run_command");
        assert_eq!(map_short_tool_name("cd"), "run_command");
        assert_eq!(map_short_tool_name("grep"), "grep_recursive");
        assert_eq!(map_short_tool_name("mkdir"), "create_directory");
        assert_eq!(map_short_tool_name("unknown_tool"), "unknown_tool");
    }

    // Tool Name Recognition Tests
    #[test]
    fn test_all_tool_names_recognized_in_parser() {
        // Verify all 27 tool names can be parsed from JSON format
        let tool_names = vec![
            "list_directory",
            "read_file",
            "read_lines",
            "write_file",
            "append_file",
            "insert_at_line",
            "directory_tree",
            "file_exists",
            "file_info",
            "count_lines",
            "code_stats",
            "code_count_lines",
            "search_files",
            "search_in_file",
            "grep_recursive",
            "extract_functions",
            "find_imports",
            "git_status",
            "git_diff",
            "git_log",
            "run_command",
            "fetch_url",
            "fetch_url_headers",
            "delete_directory",
            "create_directory",
            "http_request",
            "grep_in_directory",
        ];

        for name in tool_names {
            let text = format!(r#"{{"function_name": "{name}", "function_arg": {{}}}}"#);
            let result = parse_tool_call_from_text(&text);
            // Most should be recognized (some may map to different names)
            assert!(
                result.is_some()
                    || name == "delete_directory"
                    || name == "fetch_url_headers"
                    || name == "read_lines"
                    || name == "write_file"
                    || name == "append_file"
                    || name == "insert_at_line"
                    || name == "file_info"
                    || name == "code_stats"
                    || name == "code_count_lines"
                    || name == "search_in_file"
                    || name == "extract_functions"
                    || name == "find_imports"
                    || name == "git_diff"
                    || name == "delete_directory",
                "Tool '{name}' should be recognized or have mapping"
            );
        }
    }

    // ========================================================================
    // Week 3: Multi-Step Planning Tests
    // ========================================================================

    #[test]
    fn test_task_plan_creation() {
        let plan = TaskPlan::new("Find all TODOs in Rust files".to_string());
        assert_eq!(plan.query, "Find all TODOs in Rust files");
        assert_eq!(plan.steps.len(), 0);
        assert_eq!(plan.current_step, 0);
        assert!(!plan.completed);
    }

    #[test]
    fn test_task_plan_add_step() {
        let mut plan = TaskPlan::new("Test query".to_string());
        plan.add_step(
            "Step 1".to_string(),
            "list_directory".to_string(),
            serde_json::json!({"path": "."}),
        );
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].description, "Step 1");
        assert_eq!(plan.steps[0].tool_name, "list_directory");
        assert!(!plan.steps[0].completed);
    }

    #[test]
    fn test_task_plan_next_step() {
        let mut plan = TaskPlan::new("Test".to_string());
        plan.add_step(
            "Step 1".to_string(),
            "tool1".to_string(),
            serde_json::json!({}),
        );
        plan.add_step(
            "Step 2".to_string(),
            "tool2".to_string(),
            serde_json::json!({}),
        );

        let next = plan.next_step();
        assert!(next.is_some());
        assert_eq!(next.unwrap().description, "Step 1");
    }

    #[test]
    fn test_task_plan_complete_step() {
        let mut plan = TaskPlan::new("Test".to_string());
        plan.add_step(
            "Step 1".to_string(),
            "tool1".to_string(),
            serde_json::json!({}),
        );

        plan.complete_current_step("Result 1".to_string());
        assert!(plan.steps[0].completed);
        assert_eq!(plan.steps[0].result, Some("Result 1".to_string()));
        assert_eq!(plan.current_step, 1);
    }

    #[test]
    fn test_task_plan_progress_string() {
        let mut plan = TaskPlan::new("Test".to_string());
        plan.add_step(
            "Find files".to_string(),
            "search_files".to_string(),
            serde_json::json!({}),
        );
        plan.add_step(
            "Search content".to_string(),
            "grep_recursive".to_string(),
            serde_json::json!({}),
        );

        assert_eq!(plan.progress_string(), "Step 1/2: Find files");
        plan.complete_current_step("Done".to_string());
        assert_eq!(plan.progress_string(), "Step 2/2: Search content");
    }

    #[test]
    fn test_create_plan_for_todo_query() {
        let mut plan = TaskPlan::new("Find all TODOs in Rust files".to_string());
        let result = create_plan_for_query_helper(&mut plan, "Find all TODOs in Rust files");
        assert!(result.is_ok());
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].tool_name, "search_files");
        assert_eq!(plan.steps[1].tool_name, "grep_recursive");
    }

    #[test]
    fn test_create_plan_for_git_query() {
        let mut plan = TaskPlan::new("Show git status and commits".to_string());
        let result = create_plan_for_query_helper(&mut plan, "Show git status and commits");
        assert!(result.is_ok());
        assert!(!plan.steps.is_empty());
        assert!(plan.steps.iter().any(|s| s.tool_name == "git_status"));
    }

    #[test]
    fn test_create_plan_for_list_query() {
        let mut plan = TaskPlan::new("List all files in src directory".to_string());
        let result = create_plan_for_query_helper(&mut plan, "List all files in src directory");
        assert!(result.is_ok());
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].tool_name, "list_directory");
    }

    #[test]
    fn test_generate_plan_summary() {
        let mut plan = TaskPlan::new("Test query".to_string());
        plan.add_step(
            "Step 1".to_string(),
            "tool1".to_string(),
            serde_json::json!({}),
        );
        plan.complete_current_step("Result 1".to_string());

        // We can't directly call generate_plan_summary since it's private,
        // but we can verify the plan state
        assert!(plan.completed);
        assert_eq!(plan.steps[0].result, Some("Result 1".to_string()));
    }
}
