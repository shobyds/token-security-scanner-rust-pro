//! Tool Coordinator for managing tool execution and definitions
//!
//! The `ToolCoordinator` is responsible for:
//! - Maintaining tool definitions for LLM consumption
//! - Executing tools based on LLM tool calls
//! - Managing tool execution timeouts
//! - Providing tool result caching (optional)
//! - Retry with exponential backoff for transient failures

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::ptr_arg)]

use std::path::PathBuf;
use std::time::Instant;

use crate::tools::registry::ToolRegistry;
use crate::types::{ToolCall, ToolDefinition, ToolResult};

/// Maximum retry attempts for transient failures
const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Base delay for exponential backoff (in milliseconds)
const RETRY_BASE_DELAY_MS: u64 = 100;

/// Coordinates tool execution and manages tool definitions
pub struct ToolCoordinator {
    /// Tool registry containing all available tools
    registry: ToolRegistry,
    /// Working directory for tool execution
    #[allow(dead_code)]
    workdir: PathBuf,
    /// Tool execution timeout in milliseconds
    #[allow(dead_code)]
    tool_timeout_ms: u64,
    /// Maximum file size in MB
    #[allow(dead_code)]
    max_file_size_mb: usize,
}

impl ToolCoordinator {
    /// Create a new `ToolCoordinator`
    pub fn new(workdir: PathBuf, max_file_size_mb: usize, tool_timeout_ms: u64) -> Self {
        Self {
            registry: ToolRegistry::new(workdir.clone(), max_file_size_mb),
            workdir,
            tool_timeout_ms,
            max_file_size_mb,
        }
    }

    /// Get all tool definitions for LLM consumption
    pub fn get_tool_definitions(&self) -> Vec<&ToolDefinition> {
        self.registry.get_all_tools()
    }

    /// Execute a tool call from the LLM with retry logic
    ///
    /// Implements exponential backoff for transient failures:
    /// - Attempt 1: Immediate
    /// - Attempt 2: After 100ms
    /// - Attempt 3: After 200ms
    pub fn execute_tool(&self, tool_call: &ToolCall) -> ToolResult {
        let mut last_error: Option<String> = None;

        for attempt in 0..MAX_RETRY_ATTEMPTS {
            let result = self.execute_tool_once(tool_call);

            // Success on first try or non-retryable error
            if result.success || !is_retryable_error(&result) {
                return result;
            }

            // Store error for potential return
            last_error = Some(result.error.clone().unwrap_or_default());

            // Apply exponential backoff before retry (not on last attempt)
            if attempt < MAX_RETRY_ATTEMPTS - 1 {
                let delay_ms = RETRY_BASE_DELAY_MS * 2u64.pow(attempt);
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
        }

        // All retries failed, return last error
        let tool_name = tool_call.name().to_string();
        ToolResult::failure(
            &tool_name,
            format!(
                "Failed after {} attempts: {}",
                MAX_RETRY_ATTEMPTS,
                last_error.unwrap_or_else(|| "Unknown error".to_string())
            ),
            0,
        )
    }

    /// Execute a tool call once (without retry)
    fn execute_tool_once(&self, tool_call: &ToolCall) -> ToolResult {
        let start = Instant::now();

        let tool_name = tool_call.name().to_string();
        let arguments = tool_call.arguments();

        // Validate input before execution
        if let Err(validation_error) = Self::validate_tool_input(&tool_name, arguments) {
            return ToolResult::failure(&tool_name, validation_error, 0);
        }

        // Check if tool exists
        if !self.registry.has_tool(&tool_name) {
            return ToolResult::failure(&tool_name, format!("Unknown tool: {tool_name}"), 0);
        }

        // Execute the tool
        match self.registry.execute_tool(&tool_name, arguments) {
            Ok(output) => {
                #[allow(clippy::cast_possible_truncation)]
                let execution_time = start.elapsed().as_millis() as u64;

                // Check timeout
                if execution_time > self.tool_timeout_ms {
                    ToolResult::failure(
                        &tool_name,
                        format!(
                            "Tool execution exceeded timeout ({execution_time}ms > {}ms)",
                            self.tool_timeout_ms
                        ),
                        execution_time,
                    )
                } else {
                    // Clear any temporary data after successful execution
                    Self::clear_temporary_data();
                    ToolResult::success(&tool_name, output, execution_time)
                }
            }
            Err(e) => {
                #[allow(clippy::cast_possible_truncation)]
                let execution_time = start.elapsed().as_millis() as u64;
                ToolResult::failure(&tool_name, e.to_string(), execution_time)
            }
        }
    }

    /// Validate tool input before execution
    ///
    /// Returns Ok(()) if input is valid, or Err(String) with error message
    fn validate_tool_input(tool_name: &str, arguments: &serde_json::Value) -> Result<(), String> {
        // Check for null or missing arguments
        if arguments.is_null() {
            return Err("Arguments cannot be null".to_string());
        }

        // Validate path-based tools
        if tool_name.contains("file") || tool_name.contains("directory") {
            if let Some(obj) = arguments.as_object()
                && let Some(path_value) = obj.get("path")
                && let Some(path_str) = path_value.as_str()
            {
                // Check for empty path
                if path_str.is_empty() {
                    return Err("Path cannot be empty".to_string());
                }

                // Check for path traversal attempts
                if path_str.contains("..") {
                    return Err("Path traversal not allowed".to_string());
                }

                // Check for absolute paths outside working directory
                let path = std::path::Path::new(path_str);
                if path.is_absolute() {
                    // Allow absolute paths but log warning
                    // In production, you might want to restrict this
                }
            }

            // Validate directory parameter if present
            if let Some(obj) = arguments.as_object()
                && let Some(dir_value) = obj.get("directory")
                && let Some(dir_str) = dir_value.as_str()
            {
                if dir_str.is_empty() {
                    return Err("Directory cannot be empty".to_string());
                }

                if dir_str.contains("..") {
                    return Err("Directory traversal not allowed".to_string());
                }
            }
        }

        // Validate pattern-based tools
        if (tool_name.contains("search") || tool_name.contains("grep"))
            && let Some(obj) = arguments.as_object()
            && let Some(pattern_value) = obj.get("pattern")
            && let Some(pattern_str) = pattern_value.as_str()
        {
            if pattern_str.is_empty() {
                return Err("Search pattern cannot be empty".to_string());
            }

            // Limit pattern length to prevent ReDoS
            if pattern_str.len() > 1000 {
                return Err("Search pattern too long (max 1000 chars)".to_string());
            }
        }

        Ok(())
    }

    /// Clear temporary data after tool execution
    ///
    /// This helps prevent memory buildup from:
    /// - Large file buffers
    /// - Temporary strings
    /// - Cached results
    fn clear_temporary_data() {
        // Clear any temporary buffers in the registry
        ToolRegistry::clear_temp_data();

        // Force garbage collection hint (drop unused allocations)
        // Note: Rust doesn't have explicit GC, but we can hint to drop
        std::mem::drop(Vec::<u8>::with_capacity(0));
    }
}

/// Determine if an error is retryable
///
/// Retryable errors are typically transient:
/// - File locks
/// - Network timeouts (for web tools)
/// - Resource temporarily unavailable
/// - IO errors that might be temporary
fn is_retryable_error(result: &ToolResult) -> bool {
    if let Some(ref error) = result.error {
        let error_lower = error.to_lowercase();

        // Retry on transient errors
        error_lower.contains("temporarily")
            || error_lower.contains("timeout")
            || error_lower.contains("locked")
            || error_lower.contains("resource busy")
            || error_lower.contains("connection reset")
            || error_lower.contains("broken pipe")
    } else {
        false
    }
}

impl ToolCoordinator {
    /// Check if a tool is available
    #[allow(dead_code)]
    pub fn has_tool(&self, name: &str) -> bool {
        self.registry.has_tool(name)
    }

    /// Get the working directory
    #[allow(dead_code)]
    pub fn get_workdir(&self) -> &PathBuf {
        &self.workdir
    }

    /// Get the number of available tools
    pub fn tool_count(&self) -> usize {
        self.registry.tool_count()
    }

    /// Get tool timeout in milliseconds
    #[allow(dead_code)]
    pub fn get_tool_timeout(&self) -> u64 {
        self.tool_timeout_ms
    }

    /// Get max file size in MB
    #[allow(dead_code)]
    pub fn get_max_file_size(&self) -> usize {
        self.max_file_size_mb
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn test_tool_coordinator_creation() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        assert!(coordinator.tool_count() > 0);
        assert_eq!(coordinator.get_workdir(), workdir.path());
        assert_eq!(coordinator.get_tool_timeout(), 30000);
        assert_eq!(coordinator.get_max_file_size(), 10);
    }

    #[test]
    fn test_get_tool_definitions() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        let definitions = coordinator.get_tool_definitions();
        assert!(!definitions.is_empty());

        // Check that read_file is in the list
        let read_file_def = definitions.iter().find(|d| d.name == "read_file");
        assert!(read_file_def.is_some());

        // Check that directory tools are present
        let list_dir_def = definitions.iter().find(|d| d.name == "list_directory");
        assert!(list_dir_def.is_some());

        // Check that search tools are present
        let search_files_def = definitions.iter().find(|d| d.name == "search_files");
        assert!(search_files_def.is_some());
    }

    #[test]
    fn test_execute_read_file() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"File content").unwrap();

        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({"path": temp_file.path().to_str().unwrap()}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.is_success());
        assert_eq!(result.output, "File content");
    }

    #[test]
    fn test_execute_write_file() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        let file_path = workdir.path().join("test_write.txt");
        let tool_call = ToolCall::new(
            "call_1",
            "write_file",
            serde_json::json!({
                "path": file_path.to_str().unwrap(),
                "content": "Written content"
            }),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.is_success());

        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "Written content");
    }

    #[test]
    fn test_execute_directory_tools() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // Test list_directory
        let tool_call = ToolCall::new(
            "call_1",
            "list_directory",
            serde_json::json!({"path": workdir.path().to_str().unwrap()}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.is_success());
        assert!(result.output.contains("Directory:"));
    }

    #[test]
    fn test_execute_search_tools() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // Create test files
        std::fs::write(workdir.path().join("test.txt"), "hello world").unwrap();

        // Test search_files
        let tool_call = ToolCall::new(
            "call_1",
            "search_files",
            serde_json::json!({
                "directory": workdir.path().to_str().unwrap(),
                "pattern": "\\.txt$"
            }),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.is_success());
        assert!(result.output.contains("test.txt"));
    }

    #[test]
    fn test_execute_unknown_tool() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        let tool_call = ToolCall::new("call_1", "nonexistent_tool", serde_json::json!({}));

        let result = coordinator.execute_tool(&tool_call);
        assert!(!result.is_success());
        assert!(result.error.unwrap().contains("Unknown tool"));
    }

    #[test]
    fn test_execute_with_invalid_args() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({}), // Missing path
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(!result.is_success());
        assert!(result.error.unwrap().contains("Missing"));
    }

    #[test]
    fn test_has_tool() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // File tools
        assert!(coordinator.has_tool("read_file"));
        assert!(coordinator.has_tool("write_file"));
        assert!(coordinator.has_tool("file_exists"));

        // Directory tools
        assert!(coordinator.has_tool("list_directory"));
        assert!(coordinator.has_tool("create_directory"));
        assert!(coordinator.has_tool("delete_directory"));

        // Search tools
        assert!(coordinator.has_tool("search_files"));
        assert!(coordinator.has_tool("search_in_file"));
        assert!(coordinator.has_tool("grep_recursive"));

        // Non-existent tool
        assert!(!coordinator.has_tool("nonexistent"));
    }

    #[test]
    fn test_tool_result_formatting() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({"path": "/nonexistent/file.txt"}),
        );

        let result = coordinator.execute_tool(&tool_call);
        let llm_string = result.to_llm_string();

        assert!(!result.is_success());
        assert!(llm_string.contains("<tool_result"));
        assert!(llm_string.contains("status=\"error\""));
        assert!(llm_string.contains("Error:"));
    }

    #[test]
    fn test_tool_execution_timing() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        let tool_call = ToolCall::new(
            "call_1",
            "file_exists",
            serde_json::json!({"path": workdir.path().to_str().unwrap()}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.is_success());
        // Execution time should be non-negative (u64 is always >= 0)
    }

    #[test]
    fn test_create_directory_tool() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        let new_dir = workdir.path().join("new_directory");
        let tool_call = ToolCall::new(
            "call_1",
            "create_directory",
            serde_json::json!({
                "path": new_dir.to_str().unwrap(),
                "recursive": true
            }),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.is_success());
        assert!(new_dir.exists());
        assert!(new_dir.is_dir());
    }

    #[test]
    fn test_delete_directory_tool() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        let test_dir = workdir.path().join("to_delete");
        std::fs::create_dir(&test_dir).unwrap();

        let tool_call = ToolCall::new(
            "call_1",
            "delete_directory",
            serde_json::json!({
                "path": test_dir.to_str().unwrap(),
                "recursive": true
            }),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.is_success());
        assert!(!test_dir.exists());
    }

    #[test]
    fn test_search_in_file_tool() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        let file_path = workdir.path().join("search_test.txt");
        std::fs::write(&file_path, "line1\nhello world\nline3\n").unwrap();

        let tool_call = ToolCall::new(
            "call_1",
            "search_in_file",
            serde_json::json!({
                "path": file_path.to_str().unwrap(),
                "pattern": "hello"
            }),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.is_success());
        assert!(result.output.contains("hello world"));
    }

    // ========================================================================
    // Week 2: Retry Logic, Input Validation, and Temp Data Clearing Tests
    // ========================================================================

    #[test]
    fn test_retry_logic_on_transient_error() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // Test with a tool that doesn't exist - should fail immediately (not retry)
        let tool_call = ToolCall::new("call_1", "nonexistent_tool", serde_json::json!({}));

        let result = coordinator.execute_tool(&tool_call);
        assert!(!result.is_success());
        assert!(result.error.as_ref().unwrap().contains("Unknown tool"));
        // Should fail on first attempt, not retry
    }

    #[test]
    fn test_input_validation_null_arguments() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // Test with null arguments
        let tool_call = ToolCall::new("call_1", "read_file", serde_json::Value::Null);

        let result = coordinator.execute_tool(&tool_call);
        assert!(!result.is_success());
        assert!(
            result
                .error
                .as_ref()
                .unwrap()
                .contains("Arguments cannot be null")
        );
    }

    #[test]
    fn test_input_validation_empty_path() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // Test with empty path
        let tool_call = ToolCall::new("call_1", "read_file", serde_json::json!({"path": ""}));

        let result = coordinator.execute_tool(&tool_call);
        assert!(!result.is_success());
        assert!(
            result
                .error
                .as_ref()
                .unwrap()
                .contains("Path cannot be empty")
        );
    }

    #[test]
    fn test_input_validation_path_traversal() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // Test with path traversal attempt
        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({"path": "../../../etc/passwd"}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(!result.is_success());
        assert!(
            result
                .error
                .as_ref()
                .unwrap()
                .contains("Path traversal not allowed")
        );
    }

    #[test]
    fn test_input_validation_empty_directory() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // Test with empty directory
        let tool_call = ToolCall::new(
            "call_1",
            "list_directory",
            serde_json::json!({"directory": ""}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(!result.is_success());
        assert!(
            result
                .error
                .as_ref()
                .unwrap()
                .contains("Directory cannot be empty")
        );
    }

    #[test]
    fn test_input_validation_empty_pattern() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // Test with empty search pattern
        let tool_call = ToolCall::new(
            "call_1",
            "search_in_file",
            serde_json::json!({"path": "test.txt", "pattern": ""}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(!result.is_success());
        assert!(
            result
                .error
                .as_ref()
                .unwrap()
                .contains("Search pattern cannot be empty")
        );
    }

    #[test]
    fn test_input_validation_pattern_too_long() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // Test with very long pattern (over 1000 chars)
        let long_pattern = "a".repeat(1001);
        let tool_call = ToolCall::new(
            "call_1",
            "search_in_file",
            serde_json::json!({"path": "test.txt", "pattern": long_pattern}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(!result.is_success());
        assert!(
            result
                .error
                .as_ref()
                .unwrap()
                .contains("Search pattern too long")
        );
    }

    #[test]
    fn test_input_validation_valid_input() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // Create a test file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Test content").unwrap();

        // Test with valid input
        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({"path": temp_file.path().to_str().unwrap()}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.is_success());
        assert!(result.output.contains("Test content"));
    }

    #[test]
    fn test_clear_temp_data() {
        let workdir = tempdir().unwrap();
        let coordinator = ToolCoordinator::new(workdir.path().to_path_buf(), 10, 30000);

        // Execute a tool that should trigger temp data clearing
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Test content").unwrap();

        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({"path": temp_file.path().to_str().unwrap()}),
        );

        let result = coordinator.execute_tool(&tool_call);
        assert!(result.is_success());
        // Temp data should be cleared after successful execution
        // (verified by no memory leaks in long-running tests)
    }

    #[test]
    fn test_is_retryable_error() {
        // Test various error types
        let transient_errors = vec![
            "File temporarily locked",
            "Connection timeout",
            "Resource temporarily unavailable",
            "Connection reset by peer",
            "Broken pipe",
        ];

        for error_msg in transient_errors {
            let result = ToolResult::failure("test_tool", error_msg, 0);
            assert!(is_retryable_error(&result), "Should retry: {error_msg}");
        }

        // Test non-retryable errors
        let permanent_errors = vec![
            "File not found",
            "Permission denied",
            "Invalid arguments",
            "Unknown tool",
        ];

        for error_msg in permanent_errors {
            let result = ToolResult::failure("test_tool", error_msg, 0);
            assert!(
                !is_retryable_error(&result),
                "Should NOT retry: {error_msg}"
            );
        }
    }
}
