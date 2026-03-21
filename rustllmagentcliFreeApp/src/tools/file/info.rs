//! File information operations

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]

use std::fs;
use std::path::Path;
use std::time::Instant;

use crate::types::error::ToolError;

/// Check if a file exists
pub fn file_exists(path: &Path) -> String {
    let _start = Instant::now();

    let exists = path.exists();
    format!(
        "File {} {}",
        path.display(),
        if exists { "exists" } else { "does not exist" }
    )
}

/// Get file information (size, modified time, etc.)
pub fn file_info(path: &Path) -> Result<String, ToolError> {
    let _start = Instant::now();

    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    let metadata = fs::metadata(path)
        .map_err(|e| ToolError::FileNotFound(format!("{}: {}", path.display(), e)))?;

    let size = metadata.len();
    let is_file = metadata.is_file();
    let is_dir = metadata.is_dir();

    let modified = metadata.modified().ok().map_or(0, |t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    let created = metadata.created().ok().map_or(0, |t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    let info = format!(
        "Path: {}\nType: {}\nSize: {} bytes\nModified: {} (Unix timestamp)\nCreated: {} (Unix timestamp)",
        path.display(),
        if is_file {
            "File"
        } else if is_dir {
            "Directory"
        } else {
            "Other"
        },
        size,
        modified,
        created
    );

    Ok(info)
}

/// Get file metadata as JSON
#[allow(dead_code)]
pub fn file_info_json(path: &Path) -> Result<serde_json::Value, ToolError> {
    let _start = Instant::now();

    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    let metadata = fs::metadata(path)
        .map_err(|e| ToolError::FileNotFound(format!("{}: {}", path.display(), e)))?;

    let modified = metadata.modified().ok().map_or(0, |t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    let created = metadata.created().ok().map_or(0, |t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    let json = serde_json::json!({
        "path": path.display().to_string(),
        "is_file": metadata.is_file(),
        "is_directory": metadata.is_dir(),
        "size_bytes": metadata.len(),
        "modified_timestamp": modified,
        "created_timestamp": created,
    });

    Ok(json)
}

/// Count lines in a file
pub fn count_lines(path: &Path, max_size_mb: usize) -> Result<String, ToolError> {
    let _start = Instant::now();

    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    let metadata = fs::metadata(path)
        .map_err(|e| ToolError::FileNotFound(format!("{}: {}", path.display(), e)))?;

    let file_size = metadata.len();
    let max_size_bytes = (max_size_mb as u64) * 1024 * 1024;

    if file_size > max_size_bytes {
        return Err(ToolError::FileTooLarge(file_size, max_size_bytes));
    }

    let content = fs::read_to_string(path)
        .map_err(|e| ToolError::FileNotFound(format!("{}: {}", path.display(), e)))?;

    let line_count = content.lines().count();
    let char_count = content.chars().count();
    let byte_count = content.len();

    Ok(format!(
        "File: {}\nLines: {}\nCharacters: {}\nBytes: {}",
        path.display(),
        line_count,
        char_count,
        byte_count
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn test_file_exists_true() {
        let temp_file = NamedTempFile::new().unwrap();
        let result = file_exists(temp_file.path());
        assert!(result.contains("exists"));
    }

    #[test]
    fn test_file_exists_false() {
        let result = file_exists(Path::new("/nonexistent/file.txt"));
        assert!(result.contains("does not exist"));
    }

    #[test]
    fn test_file_info_success() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Test content").unwrap();

        let result = file_info(temp_file.path());
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.contains("File"));
        assert!(info.contains("Size:"));
    }

    #[test]
    fn test_file_info_not_found() {
        let result = file_info(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolError::FileNotFound(_)));
    }

    #[test]
    fn test_file_info_json_success() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Test").unwrap();

        let result = file_info_json(temp_file.path());
        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.is_object());
        assert_eq!(json["is_file"], true);
        assert!(json["size_bytes"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_count_lines_success() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Line 1\nLine 2\nLine 3").unwrap();

        let result = count_lines(temp_file.path(), 10);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.contains("Lines: 3"));
    }

    #[test]
    fn test_count_lines_empty_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"").unwrap();

        let result = count_lines(temp_file.path(), 10);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.contains("Lines: 0"));
    }

    #[test]
    fn test_count_lines_not_found() {
        let result = count_lines(Path::new("/nonexistent/file.txt"), 10);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolError::FileNotFound(_)));
    }

    #[test]
    fn test_count_lines_too_large() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = vec![b'a'; 2 * 1024 * 1024];
        temp_file.write_all(&data).unwrap();

        let result = count_lines(temp_file.path(), 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolError::FileTooLarge(_, _)));
    }

    #[test]
    fn test_file_info_directory() {
        let temp_dir = tempdir().unwrap();
        let result = file_info(temp_dir.path());
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.contains("Directory"));
    }

    #[test]
    fn test_file_info_json_directory() {
        let temp_dir = tempdir().unwrap();
        let result = file_info_json(temp_dir.path());
        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(json["is_file"], false);
        assert_eq!(json["is_directory"], true);
    }
}
