//! Tool registry for managing available tools

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::ptr_arg)]

use std::collections::HashMap;
use std::path::PathBuf;

use crate::tools::directory::create::create_directory;
use crate::tools::directory::delete::delete_directory;
use crate::tools::directory::list::{directory_tree, list_directory};
use crate::tools::file::{
    append_file, count_lines, file_exists, file_info, insert_at_line, read_file, read_lines,
    write_file,
};
use crate::tools::search::content_search::{grep_recursive, search_in_file};
use crate::tools::search::file_search::search_files;
use crate::types::{SchemaBuilder, ToolDefinition};
// Phase 5 imports
use crate::tools::code::analyze::{code_stats, count_lines as code_count_lines};
use crate::tools::code::parse::{extract_functions, find_imports};
use crate::tools::git::diff::{git_diff, git_diff_file};
use crate::tools::git::log::git_log;
use crate::tools::git::status::git_status;
use crate::tools::scanner::token_scanner::{create_scan_token_tool, scan_token};
use crate::tools::system::command::run_command;
use crate::tools::web::fetch::{fetch_url, fetch_url_headers};

/// Tool function type
pub type ToolFn =
    Box<dyn Fn(&serde_json::Value) -> Result<String, crate::types::error::ToolError> + Send + Sync>;

/// Tool registry containing all available tools
pub struct ToolRegistry {
    tools: HashMap<String, ToolDefinition>,
    functions: HashMap<String, ToolFn>,
    #[allow(dead_code)]
    workdir: PathBuf,
    #[allow(dead_code)]
    max_file_size_mb: usize,
}

impl ToolRegistry {
    /// Create a new tool registry
    pub fn new(workdir: PathBuf, max_file_size_mb: usize) -> Self {
        let mut registry = Self {
            tools: HashMap::new(),
            functions: HashMap::new(),
            workdir,
            max_file_size_mb,
        };

        // Register built-in tools
        registry.register_file_tools();
        registry.register_directory_tools();
        registry.register_search_tools();
        registry.register_git_tools();
        registry.register_code_tools();
        registry.register_system_tools();
        registry.register_web_tools();
        registry.register_scanner_tools();

        registry
    }

    /// Register file operation tools
    #[allow(clippy::too_many_lines)]
    fn register_file_tools(&mut self) {
        // read_file
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the file to read", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "read_file",
                "Read the entire contents of a file",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                read_file(std::path::Path::new(path), 10)
            }),
        );

        // read_lines
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the file", true)
            .integer_property("start_line", "Starting line number (1-based)", true)
            .integer_property("end_line", "Ending line number (optional, 1-based)", false)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "read_lines",
                "Read specific lines from a file",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                #[allow(clippy::cast_possible_truncation)]
                let start_line = args["start_line"].as_u64().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'start_line' argument".to_string(),
                    )
                })? as usize;
                #[allow(clippy::cast_possible_truncation)]
                let end_line = args["end_line"].as_u64().map(|v| v as usize);
                read_lines(std::path::Path::new(path), start_line, end_line, 10)
            }),
        );

        // write_file
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the file to write", true)
            .string_property("content", "Content to write to the file", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "write_file",
                "Write content to a file (overwrites if exists)",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                let content = args["content"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'content' argument".to_string(),
                    )
                })?;
                write_file(std::path::Path::new(path), content)
            }),
        );

        // append_file
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the file to append to", true)
            .string_property("content", "Content to append to the file", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "append_file",
                "Append content to a file",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                let content = args["content"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'content' argument".to_string(),
                    )
                })?;
                append_file(std::path::Path::new(path), content)
            }),
        );

        // insert_at_line
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the file", true)
            .integer_property("line_number", "Line number to insert at (1-based)", true)
            .string_property("content", "Content to insert", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "insert_at_line",
                "Insert content at a specific line in a file",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                #[allow(clippy::cast_possible_truncation)]
                let line_number = args["line_number"].as_u64().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'line_number' argument".to_string(),
                    )
                })? as usize;
                let content = args["content"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'content' argument".to_string(),
                    )
                })?;
                insert_at_line(std::path::Path::new(path), line_number, content)
            }),
        );

        // file_exists
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to check", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema("file_exists", "Check if a file exists", &required, props),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                Ok(file_exists(std::path::Path::new(path)))
            }),
        );

        // file_info
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the file", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "file_info",
                "Get information about a file (size, modified time, etc.)",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                file_info(std::path::Path::new(path))
            }),
        );

        // count_lines
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the file", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "count_lines",
                "Count lines, characters, and bytes in a file",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                count_lines(std::path::Path::new(path), 10)
            }),
        );
    }

    /// Register directory operation tools
    #[allow(clippy::too_many_lines)]
    fn register_directory_tools(&mut self) {
        // list_directory
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the directory to list", true)
            .integer_property("max_results", "Maximum number of results to return", false)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "list_directory",
                "List contents of a directory (files and subdirectories)",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                #[allow(clippy::cast_possible_truncation)]
                let max_results = args["max_results"].as_u64().unwrap_or(100) as usize;
                list_directory(std::path::Path::new(path), max_results)
            }),
        );

        // directory_tree
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the directory", true)
            .integer_property("max_depth", "Maximum depth to traverse", false)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "directory_tree",
                "Display directory structure as a tree",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                #[allow(clippy::cast_possible_truncation)]
                let max_depth = args["max_depth"].as_u64().unwrap_or(5) as usize;
                directory_tree(std::path::Path::new(path), max_depth)
            }),
        );

        // create_directory
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the directory to create", true)
            .boolean_property("recursive", "Create parent directories if needed", false)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "create_directory",
                "Create a new directory (optionally with parent directories)",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                let recursive = args["recursive"].as_bool().unwrap_or(true);
                create_directory(std::path::Path::new(path), recursive)
            }),
        );

        // delete_directory
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the directory to delete", true)
            .boolean_property("recursive", "Delete directory contents recursively", false)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "delete_directory",
                "Delete a directory (optionally recursively)",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                let recursive = args["recursive"].as_bool().unwrap_or(true);
                delete_directory(std::path::Path::new(path), recursive)
            }),
        );
    }

    /// Register search operation tools
    #[allow(clippy::too_many_lines)]
    fn register_search_tools(&mut self) {
        // search_files
        let (props, required) = SchemaBuilder::new()
            .string_property("directory", "Directory to search in", true)
            .string_property("pattern", "Regex pattern to match file names", true)
            .integer_property("max_results", "Maximum number of results", false)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "search_files",
                "Search for files by name pattern (regex) recursively",
                &required,
                props,
            ),
            Box::new(|args| {
                let directory = args["directory"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'directory' argument".to_string(),
                    )
                })?;
                let pattern_str = args["pattern"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'pattern' argument".to_string(),
                    )
                })?;
                let pattern = regex::Regex::new(pattern_str).map_err(|e| {
                    crate::types::error::ToolError::InvalidArguments(format!(
                        "Invalid regex pattern: {e}"
                    ))
                })?;
                #[allow(clippy::cast_possible_truncation)]
                let max_results = args["max_results"].as_u64().unwrap_or(100) as usize;
                search_files(std::path::Path::new(directory), &pattern, max_results)
            }),
        );

        // search_in_file
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the file to search", true)
            .string_property("pattern", "Regex pattern to search for", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "search_in_file",
                "Search for a pattern in a file (grep-like)",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                let pattern_str = args["pattern"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'pattern' argument".to_string(),
                    )
                })?;
                let pattern = regex::Regex::new(pattern_str).map_err(|e| {
                    crate::types::error::ToolError::InvalidArguments(format!(
                        "Invalid regex pattern: {e}"
                    ))
                })?;
                search_in_file(std::path::Path::new(path), &pattern)
            }),
        );

        // grep_recursive
        let (props, required) = SchemaBuilder::new()
            .string_property("directory", "Directory to search in", true)
            .string_property("pattern", "Regex pattern to search for", true)
            .string_property(
                "file_pattern",
                "Optional regex to filter files by name",
                false,
            )
            .integer_property("max_results", "Maximum number of results", false)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "grep_recursive",
                "Recursively search for a pattern in all files within a directory",
                &required,
                props,
            ),
            Box::new(|args| {
                let directory = args["directory"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'directory' argument".to_string(),
                    )
                })?;
                let pattern_str = args["pattern"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'pattern' argument".to_string(),
                    )
                })?;
                let pattern = regex::Regex::new(pattern_str).map_err(|e| {
                    crate::types::error::ToolError::InvalidArguments(format!(
                        "Invalid regex pattern: {e}"
                    ))
                })?;
                let file_pattern = args["file_pattern"]
                    .as_str()
                    .map(regex::Regex::new)
                    .transpose()
                    .map_err(|e| {
                        crate::types::error::ToolError::InvalidArguments(format!(
                            "Invalid file pattern regex: {e}"
                        ))
                    })?;
                #[allow(clippy::cast_possible_truncation)]
                let max_results = args["max_results"].as_u64().unwrap_or(100) as usize;
                grep_recursive(
                    std::path::Path::new(directory),
                    &pattern,
                    file_pattern.as_ref(),
                    max_results,
                )
            }),
        );
    }

    /// Register git operation tools
    #[allow(clippy::too_many_lines)]
    fn register_git_tools(&mut self) {
        // git_status
        let (props, required) = SchemaBuilder::new()
            .string_property("repo_path", "Path to the git repository", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "git_status",
                "Get the git status of a repository",
                &required,
                props,
            ),
            Box::new(|args| {
                let repo_path = args["repo_path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'repo_path' argument".to_string(),
                    )
                })?;
                git_status(std::path::Path::new(repo_path))
            }),
        );

        // git_diff
        let (props, required) = SchemaBuilder::new()
            .string_property("repo_path", "Path to the git repository", true)
            .string_property("file", "Optional specific file to diff", false)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "git_diff",
                "Get git diff for a repository or specific file",
                &required,
                props,
            ),
            Box::new(|args| {
                let repo_path = args["repo_path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'repo_path' argument".to_string(),
                    )
                })?;
                if let Some(file) = args["file"].as_str() {
                    git_diff_file(std::path::Path::new(repo_path), std::path::Path::new(file))
                } else {
                    git_diff(std::path::Path::new(repo_path))
                }
            }),
        );

        // git_log
        let (props, required) = SchemaBuilder::new()
            .string_property("repo_path", "Path to the git repository", true)
            .integer_property("count", "Number of commits to show", false)
            .build();

        self.register_tool(
            ToolDefinition::with_schema("git_log", "Get git commit history", &required, props),
            Box::new(|args| {
                let repo_path = args["repo_path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'repo_path' argument".to_string(),
                    )
                })?;
                #[allow(clippy::cast_possible_truncation)]
                let count = args["count"].as_u64().unwrap_or(10) as usize;
                git_log(std::path::Path::new(repo_path), count)
            }),
        );
    }

    /// Register code analysis tools
    #[allow(clippy::too_many_lines)]
    fn register_code_tools(&mut self) {
        // code_count_lines
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the file to analyze", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "code_count_lines",
                "Count lines, characters, and bytes in a code file",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                code_count_lines(std::path::Path::new(path))
            }),
        );

        // code_stats
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the code file", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "code_stats",
                "Get detailed code statistics (lines, comments, blanks)",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                code_stats(std::path::Path::new(path))
            }),
        );

        // extract_functions
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the source file", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "extract_functions",
                "Extract function names from a source file (Rust/Python)",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                extract_functions(std::path::Path::new(path))
            }),
        );

        // find_imports
        let (props, required) = SchemaBuilder::new()
            .string_property("path", "Path to the source file", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "find_imports",
                "Extract import statements from a source file (Rust/Python)",
                &required,
                props,
            ),
            Box::new(|args| {
                let path = args["path"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'path' argument".to_string(),
                    )
                })?;
                find_imports(std::path::Path::new(path))
            }),
        );
    }

    /// Register system command tools
    #[allow(clippy::too_many_lines)]
    fn register_system_tools(&mut self) {
        // run_command
        let (props, required) = SchemaBuilder::new()
            .string_property("command", "Command to execute", true)
            .string_property("args", "Command arguments as space-separated string", false)
            .string_property("working_dir", "Working directory", false)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "run_command",
                "Execute a system command",
                &required,
                props,
            ),
            Box::new(|args| {
                let cmd = args["command"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'command' argument".to_string(),
                    )
                })?;
                let args_str = args["args"].as_str().unwrap_or("");
                let args_vec: Vec<&str> = args_str.split_whitespace().collect();
                let working_dir = args["working_dir"].as_str().map(std::path::Path::new);
                run_command(cmd, &args_vec, working_dir)
            }),
        );
    }

    /// Register web fetch tools
    #[allow(clippy::too_many_lines)]
    fn register_web_tools(&mut self) {
        // fetch_url
        let (props, required) = SchemaBuilder::new()
            .string_property("url", "URL to fetch", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema("fetch_url", "Fetch content from a URL", &required, props),
            Box::new(|args| {
                let url = args["url"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'url' argument".to_string(),
                    )
                })?;
                fetch_url(url)
            }),
        );

        // fetch_url_headers
        let (props, required) = SchemaBuilder::new()
            .string_property("url", "URL to fetch headers from", true)
            .build();

        self.register_tool(
            ToolDefinition::with_schema(
                "fetch_url_headers",
                "Fetch HTTP headers from a URL",
                &required,
                props,
            ),
            Box::new(|args| {
                let url = args["url"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments(
                        "Missing 'url' argument".to_string(),
                    )
                })?;
                fetch_url_headers(url)
            }),
        );
    }

    /// Register scanner tools (Section 16)
    fn register_scanner_tools(&mut self) {
        self.register_tool(
            create_scan_token_tool(),
            Box::new(|args| {
                scan_token(args)
                    .map_err(|e| crate::types::error::ToolError::CommandFailed(e.to_string()))
            }),
        );
    }

    /// Register a tool
    pub fn register_tool(&mut self, definition: ToolDefinition, function: ToolFn) {
        let name = definition.name.clone();
        self.tools.insert(name.clone(), definition);
        self.functions.insert(name.clone(), function);
    }

    /// Get a tool definition
    #[allow(dead_code)]
    pub fn get_tool(&self, name: &str) -> Option<&ToolDefinition> {
        self.tools.get(name)
    }

    /// Get all tool definitions
    pub fn get_all_tools(&self) -> Vec<&ToolDefinition> {
        self.tools.values().collect()
    }

    /// Check if a tool exists
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// Execute a tool by name
    pub fn execute_tool(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<String, crate::types::error::ToolError> {
        let function = self.functions.get(name).ok_or_else(|| {
            crate::types::error::ToolError::InvalidArguments(format!("Unknown tool: {name}"))
        })?;

        function(arguments)
    }

    /// Get the working directory
    #[allow(dead_code)]
    pub fn get_workdir(&self) -> &PathBuf {
        &self.workdir
    }

    /// Get the number of registered tools
    #[allow(dead_code)]
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Clear temporary data after tool execution
    ///
    /// This is called after each successful tool execution to prevent
    /// memory buildup from temporary buffers and cached data.
    pub fn clear_temp_data() {
        // Clear any cached data in the registry
        // Note: HashMap doesn't have a capacity reduction method,
        // but we can hint to drop and recreate if needed
        // For now, just a placeholder for future optimization
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn test_tool_registry_creation() {
        let workdir = tempdir().unwrap().path().to_path_buf();
        let registry = ToolRegistry::new(workdir.clone(), 10);

        assert!(registry.tool_count() > 0);
        assert_eq!(registry.get_workdir(), &workdir);
    }

    #[test]
    fn test_tool_registry_has_file_tools() {
        let workdir = tempdir().unwrap().path().to_path_buf();
        let registry = ToolRegistry::new(workdir, 10);

        assert!(registry.has_tool("read_file"));
        assert!(registry.has_tool("write_file"));
        assert!(registry.has_tool("file_exists"));
        assert!(registry.has_tool("file_info"));
        assert!(registry.has_tool("count_lines"));
        assert!(registry.has_tool("read_lines"));
        assert!(registry.has_tool("append_file"));
        assert!(registry.has_tool("insert_at_line"));
    }

    #[test]
    fn test_get_tool_definition() {
        let workdir = tempdir().unwrap().path().to_path_buf();
        let registry = ToolRegistry::new(workdir, 10);

        let tool = registry.get_tool("read_file");
        assert!(tool.is_some());
        let tool = tool.unwrap();
        assert_eq!(tool.name, "read_file");
        assert!(tool.description.contains("Read"));
    }

    #[test]
    fn test_get_all_tools() {
        let workdir = tempdir().unwrap().path().to_path_buf();
        let registry = ToolRegistry::new(workdir, 10);

        let tools = registry.get_all_tools();
        assert!(!tools.is_empty());
        assert!(tools.len() >= 8); // At least 8 file tools
    }

    #[test]
    fn test_execute_read_file() {
        let workdir = tempdir().unwrap();
        let registry = ToolRegistry::new(workdir.path().to_path_buf(), 10);

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Test content").unwrap();

        let args = json!({"path": temp_file.path().to_str().unwrap()});
        let result = registry.execute_tool("read_file", &args);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Test content");
    }

    #[test]
    fn test_execute_write_file() {
        let workdir = tempdir().unwrap();
        let registry = ToolRegistry::new(workdir.path().to_path_buf(), 10);

        let file_path = workdir.path().join("test.txt");
        let args = json!({
            "path": file_path.to_str().unwrap(),
            "content": "Hello from tool"
        });

        let result = registry.execute_tool("write_file", &args);
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "Hello from tool");
    }

    #[test]
    fn test_execute_file_exists() {
        let workdir = tempdir().unwrap();
        let registry = ToolRegistry::new(workdir.path().to_path_buf(), 10);

        let temp_file = NamedTempFile::new().unwrap();

        let args = json!({"path": temp_file.path().to_str().unwrap()});
        let result = registry.execute_tool("file_exists", &args);

        assert!(result.is_ok());
        assert!(result.unwrap().contains("exists"));
    }

    #[test]
    fn test_execute_unknown_tool() {
        let workdir = tempdir().unwrap();
        let registry = ToolRegistry::new(workdir.path().to_path_buf(), 10);

        let args = json!({});
        let result = registry.execute_tool("nonexistent_tool", &args);

        assert!(result.is_err());
    }

    #[test]
    fn test_execute_with_missing_args() {
        let workdir = tempdir().unwrap();
        let registry = ToolRegistry::new(workdir.path().to_path_buf(), 10);

        let args = json!({}); // Missing 'path'
        let result = registry.execute_tool("read_file", &args);

        assert!(result.is_err());
    }

    #[test]
    fn test_custom_tool_registration() {
        let workdir = tempdir().unwrap();
        let mut registry = ToolRegistry::new(workdir.path().to_path_buf(), 10);

        registry.register_tool(
            ToolDefinition::with_schema(
                "echo",
                "Echo back the input message",
                &["message"],
                serde_json::json!({
                    "message": {"type": "string", "description": "Message to echo"}
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
            Box::new(|args| {
                let message = args["message"].as_str().ok_or_else(|| {
                    crate::types::error::ToolError::InvalidArguments("Missing message".to_string())
                })?;
                Ok(message.to_string())
            }),
        );

        assert!(registry.has_tool("echo"));

        let args = json!({"message": "Hello!"});
        let result = registry.execute_tool("echo", &args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Hello!");
    }
}
