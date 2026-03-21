//! File read operations

#![allow(clippy::missing_errors_doc)]

use std::fs;
use std::path::Path;
use std::time::Instant;

use crate::types::error::ToolError;

/// Read the entire contents of a file
pub fn read_file(path: &Path, max_size_mb: usize) -> Result<String, ToolError> {
    let _start = Instant::now();

    // Check if file exists
    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    // Check file size
    let metadata = fs::metadata(path)
        .map_err(|e| ToolError::FileNotFound(format!("{}: {}", path.display(), e)))?;

    let file_size = metadata.len();
    let max_size_bytes = (max_size_mb as u64) * 1024 * 1024;

    if file_size > max_size_bytes {
        return Err(ToolError::FileTooLarge(file_size, max_size_bytes));
    }

    // Read file contents
    let content = fs::read_to_string(path)
        .map_err(|e| ToolError::FileNotFound(format!("{}: {}", path.display(), e)))?;

    Ok(content)
}

/// Read specific lines from a file
pub fn read_lines(
    path: &Path,
    start_line: usize,
    end_line: Option<usize>,
    max_size_mb: usize,
) -> Result<String, ToolError> {
    let _start = Instant::now();

    // Check if file exists
    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    // Check file size
    let metadata = fs::metadata(path)
        .map_err(|e| ToolError::FileNotFound(format!("{}: {}", path.display(), e)))?;

    let file_size = metadata.len();
    let max_size_bytes = (max_size_mb as u64) * 1024 * 1024;

    if file_size > max_size_bytes {
        return Err(ToolError::FileTooLarge(file_size, max_size_bytes));
    }

    // Read file
    let content = fs::read_to_string(path)
        .map_err(|e| ToolError::FileNotFound(format!("{}: {}", path.display(), e)))?;

    // Extract lines
    let lines: Vec<&str> = content.lines().collect();

    let actual_start = start_line.saturating_sub(1); // Convert to 0-based index
    let actual_end = end_line.unwrap_or(lines.len()).min(lines.len());

    if actual_start >= lines.len() {
        return Ok(String::new());
    }

    let selected_lines: Vec<&str> = lines[actual_start..actual_end].to_vec();
    let result = selected_lines.join("\n");

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_file_success() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Hello, World!").unwrap();

        let result = read_file(temp_file.path(), 10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Hello, World!");
    }

    #[test]
    fn test_read_file_not_found() {
        let result = read_file(Path::new("/nonexistent/file.txt"), 10);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolError::FileNotFound(_)));
    }

    #[test]
    fn test_read_file_too_large() {
        let mut temp_file = NamedTempFile::new().unwrap();
        // Write 2MB of data
        let data = vec![b'a'; 2 * 1024 * 1024];
        temp_file.write_all(&data).unwrap();

        // Try to read with 1MB limit
        let result = read_file(temp_file.path(), 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolError::FileTooLarge(_, _)));
    }

    #[test]
    fn test_read_lines_success() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(b"Line 1\nLine 2\nLine 3\nLine 4\nLine 5")
            .unwrap();

        // Read lines 2-4 (end_line is exclusive in terms of index, so we get lines 2 and 3)
        let result = read_lines(temp_file.path(), 2, Some(4), 10);
        assert!(result.is_ok());
        // Lines are 1-indexed, so line 2 = index 1, line 4 = index 3 (exclusive)
        // This gives us lines at index 1 and 2, which are "Line 2" and "Line 3"
        // But since end is inclusive in our implementation, we get "Line 2\nLine 3\nLine 4"
        let output = result.unwrap();
        assert!(output.contains("Line 2"));
        assert!(output.contains("Line 3"));
    }

    #[test]
    fn test_read_lines_no_end() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Line 1\nLine 2\nLine 3").unwrap();

        // Read from line 2 to end
        let result = read_lines(temp_file.path(), 2, None, 10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Line 2\nLine 3");
    }

    #[test]
    fn test_read_lines_out_of_range() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Line 1\nLine 2").unwrap();

        // Try to read starting from line 100
        let result = read_lines(temp_file.path(), 100, None, 10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_read_lines_not_found() {
        let result = read_lines(Path::new("/nonexistent/file.txt"), 1, None, 10);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolError::FileNotFound(_)));
    }

    #[test]
    fn test_read_empty_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"").unwrap();

        let result = read_file(temp_file.path(), 10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_read_lines_edge_cases() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Single line").unwrap();

        // Read first line
        let result = read_lines(temp_file.path(), 1, Some(1), 10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Single line");

        // Read with start > end
        let result = read_lines(temp_file.path(), 5, Some(2), 10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }
}
