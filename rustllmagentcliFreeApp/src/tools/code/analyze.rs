//! Code analysis operations

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(dead_code)]

use std::fs;
use std::path::Path;

use crate::types::error::ToolError;

/// Count lines, characters, and bytes in a file
pub fn count_lines(path: &Path) -> Result<String, ToolError> {
    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    if !path.is_file() {
        return Err(ToolError::InvalidPath(format!(
            "Path is not a file: {}",
            path.display()
        )));
    }

    let content = fs::read_to_string(path)
        .map_err(|e| ToolError::PermissionDenied(format!("Cannot read file: {}", e)))?;

    let lines = content.lines().count();
    let chars = content.chars().count();
    let bytes = content.as_bytes().len();

    Ok(format!(
        "File: {}\nLines: {}\nCharacters: {}\nBytes: {}",
        path.display(),
        lines,
        chars,
        bytes
    ))
}

/// Count lines in multiple files
pub fn count_lines_multiple(paths: &[&Path]) -> Result<String, ToolError> {
    let mut total_lines = 0;
    let mut total_chars = 0;
    let mut total_bytes = 0;
    let mut results = Vec::new();

    for path in paths {
        match count_lines(path) {
            Ok(result) => {
                // Parse the result to extract counts
                for line in result.lines() {
                    if line.starts_with("Lines:") {
                        if let Some(count) = line
                            .split(':')
                            .nth(1)
                            .and_then(|s| s.trim().parse::<usize>().ok())
                        {
                            total_lines += count;
                        }
                    } else if line.starts_with("Characters:") {
                        if let Some(count) = line
                            .split(':')
                            .nth(1)
                            .and_then(|s| s.trim().parse::<usize>().ok())
                        {
                            total_chars += count;
                        }
                    } else if line.starts_with("Bytes:") {
                        if let Some(count) = line
                            .split(':')
                            .nth(1)
                            .and_then(|s| s.trim().parse::<usize>().ok())
                        {
                            total_bytes += count;
                        }
                    }
                }
                results.push(result);
            }
            Err(e) => {
                results.push(format!("Error reading {}: {}", path.display(), e));
            }
        }
    }

    results.push(format!(
        "\n---\nTotal: {} lines, {} characters, {} bytes",
        total_lines, total_chars, total_bytes
    ));

    Ok(results.join("\n\n"))
}

/// Get code statistics for a file
pub fn code_stats(path: &Path) -> Result<String, ToolError> {
    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    if !path.is_file() {
        return Err(ToolError::InvalidPath(format!(
            "Path is not a file: {}",
            path.display()
        )));
    }

    let content = fs::read_to_string(path)
        .map_err(|e| ToolError::PermissionDenied(format!("Cannot read file: {}", e)))?;

    let total_lines = content.lines().count();
    let blank_lines = content.lines().filter(|l| l.trim().is_empty()).count();
    let code_lines = total_lines - blank_lines;

    // Count comment lines (simple heuristic for common languages)
    let comment_lines = content
        .lines()
        .filter(|l| {
            l.trim().starts_with("//")
                || l.trim().starts_with('#')
                || l.trim().starts_with("/*")
                || l.trim().starts_with('*')
        })
        .count();

    let chars = content.chars().count();
    let bytes = content.as_bytes().len();

    // Detect file extension
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("unknown");

    Ok(format!(
        "Code Statistics for {}\n\
         Extension: {}\n\
         ---\n\
         Total lines: {}\n\
         Code lines: {}\n\
         Blank lines: {}\n\
         Comment lines: {}\n\
         Characters: {}\n\
         Bytes: {}",
        path.display(),
        extension,
        total_lines,
        code_lines,
        blank_lines,
        comment_lines,
        chars,
        bytes
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn test_count_lines_not_found() {
        let result = count_lines(&Path::new("/nonexistent/file.txt"));
        assert!(matches!(result, Err(ToolError::FileNotFound(_))));
    }

    #[test]
    fn test_count_lines_directory() {
        let dir = tempdir().unwrap();
        let result = count_lines(dir.path());
        assert!(matches!(result, Err(ToolError::InvalidPath(_))));
    }

    #[test]
    fn test_count_lines_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let result = count_lines(file.path());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Lines: 0"));
    }

    #[test]
    fn test_count_lines_single_line() {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), "Hello, World!").unwrap();

        let result = count_lines(file.path());
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("Lines: 1"));
        assert!(output.contains("Characters: 13"));
    }

    #[test]
    fn test_count_lines_multiline() {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), "Line 1\nLine 2\nLine 3\n").unwrap();

        let result = count_lines(file.path());
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("Lines: 3"));
    }

    #[test]
    fn test_code_stats() {
        let file = NamedTempFile::new().unwrap();
        let content = "// Comment\nfn main() {\n    println!(\"Hello\");\n}\n";
        fs::write(file.path(), content).unwrap();

        let result = code_stats(file.path());
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("Total lines: 4"));
        assert!(output.contains("Comment lines: 1"));
        assert!(output.contains("Extension:"));
    }

    #[test]
    fn test_code_stats_blank_lines() {
        let file = NamedTempFile::new().unwrap();
        let content = "Line 1\n\nLine 3\n\n\nLine 6\n";
        fs::write(file.path(), content).unwrap();

        let result = code_stats(file.path());
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("Total lines: 6"));
        assert!(output.contains("Blank lines: 3"));
    }

    #[test]
    fn test_count_lines_multiple() {
        let dir = tempdir().unwrap();
        let file1 = dir.path().join("file1.txt");
        let file2 = dir.path().join("file2.txt");

        fs::write(&file1, "Line 1\nLine 2\n").unwrap();
        fs::write(&file2, "Line A\nLine B\nLine C\n").unwrap();

        let paths = vec![file1.as_path(), file2.as_path()];
        let result = count_lines_multiple(&paths);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("Total: 5 lines"));
    }
}
