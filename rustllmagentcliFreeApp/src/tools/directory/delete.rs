//! Delete directory operations

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use std::fs;
use std::path::Path;

use crate::types::error::ToolError;

/// Delete a directory and all its contents
pub fn delete_directory(path: &Path, recursive: bool) -> Result<String, ToolError> {
    if !path.exists() {
        return Err(ToolError::DirectoryNotFound(path.display().to_string()));
    }

    if !path.is_dir() {
        return Err(ToolError::InvalidPath(format!(
            "Path is not a directory: {}",
            path.display()
        )));
    }

    // Check if directory is empty
    let is_empty = fs::read_dir(path)
        .map(|mut i| i.next().is_none())
        .unwrap_or(false);

    if !is_empty && !recursive {
        return Err(ToolError::InvalidPath(format!(
            "Directory is not empty and recursive deletion is not enabled: {}",
            path.display()
        )));
    }

    fs::remove_dir_all(path).map_err(|e| {
        ToolError::PermissionDenied(format!("Cannot delete directory {}: {}", path.display(), e))
    })?;

    Ok(format!(
        "Successfully deleted directory: {}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_delete_directory_empty() {
        let dir = tempdir().unwrap();
        let empty_dir = dir.path().join("empty");
        fs::create_dir(&empty_dir).unwrap();

        let result = delete_directory(&empty_dir, false).unwrap();
        assert!(result.contains("Successfully deleted"));
        assert!(!empty_dir.exists());
    }

    #[test]
    fn test_delete_directory_recursive() {
        let dir = tempdir().unwrap();
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("file.txt"), "content").unwrap();

        let result = delete_directory(&subdir, true).unwrap();
        assert!(result.contains("Successfully deleted"));
        assert!(!subdir.exists());
    }

    #[test]
    fn test_delete_directory_non_recursive_not_empty() {
        let dir = tempdir().unwrap();
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("file.txt"), "content").unwrap();

        let result = delete_directory(&subdir, false);
        assert!(matches!(result, Err(ToolError::InvalidPath(_))));
        assert!(subdir.exists());
    }

    #[test]
    fn test_delete_directory_not_found() {
        let result = delete_directory(&Path::new("/nonexistent/dir"), false);
        assert!(matches!(result, Err(ToolError::DirectoryNotFound(_))));
    }

    #[test]
    fn test_delete_directory_not_a_directory() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("file.txt");
        fs::write(&file_path, "content").unwrap();

        let result = delete_directory(&file_path, false);
        assert!(matches!(result, Err(ToolError::InvalidPath(_))));
    }
}
