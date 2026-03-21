//! Tool executor for running tools
//!
//! Note: This module is kept for backward compatibility but is no longer used.
//! Use `ToolCoordinator` from `src/agent/tool_coordinator.rs` instead.

#![allow(dead_code)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::ptr_arg)]

use std::path::PathBuf;
use std::time::Instant;

use crate::tools::registry::ToolRegistry;
use crate::types::ToolCall;
use crate::types::tool::ToolResult;

/// Tool executor that runs tools from the registry
pub struct ToolExecutor {
    registry: ToolRegistry,
    tool_timeout_ms: u64,
}

impl ToolExecutor {
    /// Create a new tool executor
    pub fn new(workdir: PathBuf, max_file_size_mb: usize, tool_timeout_ms: u64) -> Self {
        Self {
            registry: ToolRegistry::new(workdir, max_file_size_mb),
            tool_timeout_ms,
        }
    }

    /// Get the tool registry
    #[allow(dead_code)]
    pub fn registry(&self) -> &ToolRegistry {
        &self.registry
    }

    /// Execute a tool call
    pub fn execute(&self, tool_call: &ToolCall) -> ToolResult {
        let start = Instant::now();

        let tool_name = tool_call.name().to_string();
        let arguments = tool_call.arguments();

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

    /// Get all available tool definitions
    pub fn get_tool_definitions(&self) -> Vec<&crate::types::ToolDefinition> {
        self.registry.get_all_tools()
    }

    /// Check if a tool is available
    #[allow(dead_code)]
    pub fn has_tool(&self, name: &str) -> bool {
        self.registry.has_tool(name)
    }

    /// Get the working directory
    #[allow(dead_code)]
    pub fn get_workdir(&self) -> &PathBuf {
        self.registry.get_workdir()
    }

    /// Get the number of available tools
    #[allow(dead_code)]
    pub fn tool_count(&self) -> usize {
        self.registry.tool_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn test_tool_executor_creation() {
        let workdir = tempdir().unwrap();
        let executor = ToolExecutor::new(workdir.path().to_path_buf(), 10, 30000);

        assert!(executor.tool_count() > 0);
        assert_eq!(executor.get_workdir(), workdir.path());
    }

    #[test]
    fn test_execute_read_file() {
        let workdir = tempdir().unwrap();
        let executor = ToolExecutor::new(workdir.path().to_path_buf(), 10, 30000);

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"File content").unwrap();

        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({"path": temp_file.path().to_str().unwrap()}),
        );

        let result = executor.execute(&tool_call);
        assert!(result.is_success());
        assert_eq!(result.output, "File content");
        // Execution time might be 0 for very fast operations
        // assert!(result.execution_time_ms >= 0);
    }

    #[test]
    fn test_execute_write_file() {
        let workdir = tempdir().unwrap();
        let executor = ToolExecutor::new(workdir.path().to_path_buf(), 10, 30000);

        let file_path = workdir.path().join("test_write.txt");
        let tool_call = ToolCall::new(
            "call_1",
            "write_file",
            serde_json::json!({
                "path": file_path.to_str().unwrap(),
                "content": "Written content"
            }),
        );

        let result = executor.execute(&tool_call);
        assert!(result.is_success());

        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "Written content");
    }

    #[test]
    fn test_execute_unknown_tool() {
        let workdir = tempdir().unwrap();
        let executor = ToolExecutor::new(workdir.path().to_path_buf(), 10, 30000);

        let tool_call = ToolCall::new("call_1", "nonexistent_tool", serde_json::json!({}));

        let result = executor.execute(&tool_call);
        assert!(!result.is_success());
        assert!(result.error.unwrap().contains("Unknown tool"));
    }

    #[test]
    fn test_execute_with_invalid_args() {
        let workdir = tempdir().unwrap();
        let executor = ToolExecutor::new(workdir.path().to_path_buf(), 10, 30000);

        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({}), // Missing path
        );

        let result = executor.execute(&tool_call);
        assert!(!result.is_success());
        assert!(result.error.unwrap().contains("Missing"));
    }

    #[test]
    fn test_execute_file_exists() {
        let workdir = tempdir().unwrap();
        let executor = ToolExecutor::new(workdir.path().to_path_buf(), 10, 30000);

        let temp_file = NamedTempFile::new().unwrap();

        let tool_call = ToolCall::new(
            "call_1",
            "file_exists",
            serde_json::json!({"path": temp_file.path().to_str().unwrap()}),
        );

        let result = executor.execute(&tool_call);
        assert!(result.is_success());
        assert!(result.output.contains("exists"));
    }

    #[test]
    fn test_execute_file_info() {
        let workdir = tempdir().unwrap();
        let executor = ToolExecutor::new(workdir.path().to_path_buf(), 10, 30000);

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Test content for info").unwrap();

        let tool_call = ToolCall::new(
            "call_1",
            "file_info",
            serde_json::json!({"path": temp_file.path().to_str().unwrap()}),
        );

        let result = executor.execute(&tool_call);
        assert!(result.is_success());
        assert!(result.output.contains("Size:"));
        assert!(result.output.contains("bytes"));
    }

    #[test]
    fn test_execute_count_lines() {
        let workdir = tempdir().unwrap();
        let executor = ToolExecutor::new(workdir.path().to_path_buf(), 10, 30000);

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(b"Line 1\nLine 2\nLine 3\nLine 4")
            .unwrap();

        let tool_call = ToolCall::new(
            "call_1",
            "count_lines",
            serde_json::json!({"path": temp_file.path().to_str().unwrap()}),
        );

        let result = executor.execute(&tool_call);
        assert!(result.is_success());
        assert!(result.output.contains("Lines: 4"));
    }

    #[test]
    fn test_get_tool_definitions() {
        let workdir = tempdir().unwrap();
        let executor = ToolExecutor::new(workdir.path().to_path_buf(), 10, 30000);

        let definitions = executor.get_tool_definitions();
        assert!(!definitions.is_empty());

        // Check that read_file is in the list
        let read_file_def = definitions.iter().find(|d| d.name == "read_file");
        assert!(read_file_def.is_some());
    }

    #[test]
    fn test_has_tool() {
        let workdir = tempdir().unwrap();
        let executor = ToolExecutor::new(workdir.path().to_path_buf(), 10, 30000);

        assert!(executor.has_tool("read_file"));
        assert!(executor.has_tool("write_file"));
        assert!(!executor.has_tool("nonexistent"));
    }

    #[test]
    fn test_tool_result_formatting() {
        let workdir = tempdir().unwrap();
        let executor = ToolExecutor::new(workdir.path().to_path_buf(), 10, 30000);

        let tool_call = ToolCall::new(
            "call_1",
            "read_file",
            serde_json::json!({"path": "/nonexistent/file.txt"}),
        );

        let result = executor.execute(&tool_call);
        let llm_string = result.to_llm_string();

        assert!(!result.is_success());
        assert!(llm_string.contains("<tool_result"));
        assert!(llm_string.contains("status=\"error\""));
        assert!(llm_string.contains("Error:"));
    }
}
