//! File write operations

#![allow(clippy::missing_errors_doc)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use crate::types::error::ToolError;

/// Write content to a file (overwrites if exists)
pub fn write_file(path: &Path, content: &str) -> Result<String, ToolError> {
    let _start = Instant::now();

    // Create parent directories if they don't exist
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .map_err(|e| ToolError::PermissionDenied(format!("Cannot create directory: {e}")))?;
    }

    // Write file
    fs::write(path, content)
        .map_err(|e| ToolError::PermissionDenied(format!("Cannot write file: {e}")))?;

    Ok(format!(
        "Successfully wrote {} bytes to {}",
        content.len(),
        path.display()
    ))
}

/// Append content to a file
pub fn append_file(path: &Path, content: &str) -> Result<String, ToolError> {
    let _start = Instant::now();

    // Check if file exists
    if !path.exists() {
        // If file doesn't exist, create it by writing
        return write_file(path, content);
    }

    // Append to file
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| ToolError::PermissionDenied(format!("Cannot open file for appending: {e}")))?;

    file.write_all(content.as_bytes())
        .map_err(|e| ToolError::PermissionDenied(format!("Cannot append to file: {e}")))?;

    Ok(format!(
        "Successfully appended {} bytes to {}",
        content.len(),
        path.display()
    ))
}

/// Insert content at a specific line in a file
pub fn insert_at_line(path: &Path, line_number: usize, content: &str) -> Result<String, ToolError> {
    let _start = Instant::now();

    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    // Read file
    let file_content = fs::read_to_string(path)
        .map_err(|e| ToolError::FileNotFound(format!("{}: {}", path.display(), e)))?;

    let mut lines: Vec<&str> = file_content.lines().collect();

    // Convert to 0-based index
    let insert_index = (line_number.saturating_sub(1)).min(lines.len());

    // Insert content as new lines
    let new_lines: Vec<&str> = content.lines().collect();
    for (i, new_line) in new_lines.iter().enumerate() {
        lines.insert(insert_index + i, new_line);
    }

    // Write back
    let new_content = lines.join("\n");
    fs::write(path, new_content)
        .map_err(|e| ToolError::PermissionDenied(format!("Cannot write file: {e}")))?;

    Ok(format!(
        "Successfully inserted {} lines at line {} in {}",
        content.lines().count(),
        line_number,
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn test_write_file_success() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let result = write_file(&file_path, "Hello, World!");
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Successfully wrote"));

        // Verify content
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "Hello, World!");
    }

    #[test]
    fn test_write_file_creates_directories() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("subdir/nested/test.txt");

        let result = write_file(&file_path, "Nested content");
        assert!(result.is_ok());

        // Verify file exists
        assert!(file_path.exists());
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "Nested content");
    }

    #[test]
    fn test_write_file_overwrites() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Original content").unwrap();

        let result = write_file(temp_file.path(), "New content");
        assert!(result.is_ok());

        let content = fs::read_to_string(temp_file.path()).unwrap();
        assert_eq!(content, "New content");
    }

    #[test]
    fn test_append_file_success() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Original\n").unwrap();

        let result = append_file(temp_file.path(), "Appended\n");
        assert!(result.is_ok());

        let content = fs::read_to_string(temp_file.path()).unwrap();
        assert_eq!(content, "Original\nAppended\n");
    }

    #[test]
    fn test_append_file_creates_if_not_exists() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("new.txt");

        let result = append_file(&file_path, "First content");
        assert!(result.is_ok());

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "First content");
    }

    #[test]
    fn test_insert_at_line_success() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Line 1\nLine 2\nLine 4").unwrap();

        let result = insert_at_line(temp_file.path(), 3, "Line 3");
        assert!(result.is_ok());

        let content = fs::read_to_string(temp_file.path()).unwrap();
        assert_eq!(content, "Line 1\nLine 2\nLine 3\nLine 4");
    }

    #[test]
    fn test_insert_at_line_beginning() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Line 2\nLine 3").unwrap();

        let result = insert_at_line(temp_file.path(), 1, "Line 1");
        assert!(result.is_ok());

        let content = fs::read_to_string(temp_file.path()).unwrap();
        assert_eq!(content, "Line 1\nLine 2\nLine 3");
    }

    #[test]
    fn test_insert_at_line_end() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Line 1\nLine 2").unwrap();

        let result = insert_at_line(temp_file.path(), 100, "Line 3");
        assert!(result.is_ok());

        let content = fs::read_to_string(temp_file.path()).unwrap();
        assert_eq!(content, "Line 1\nLine 2\nLine 3");
    }

    #[test]
    fn test_insert_at_line_not_found() {
        let result = insert_at_line(Path::new("/nonexistent/file.txt"), 1, "Content");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolError::FileNotFound(_)));
    }

    #[test]
    fn test_insert_multiple_lines() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Line 1\nLine 4").unwrap();

        let result = insert_at_line(temp_file.path(), 2, "Line 2\nLine 3");
        assert!(result.is_ok());

        let content = fs::read_to_string(temp_file.path()).unwrap();
        assert_eq!(content, "Line 1\nLine 2\nLine 3\nLine 4");
    }

    #[test]
    fn test_write_empty_content() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("empty.txt");

        let result = write_file(&file_path, "");
        assert!(result.is_ok());

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "");
    }
}
