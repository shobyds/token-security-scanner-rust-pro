//! Create directory operations

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use std::fs;
use std::path::Path;

use crate::types::error::ToolError;

/// Create a directory (including parent directories if needed)
pub fn create_directory(path: &Path, recursive: bool) -> Result<String, ToolError> {
    if path.exists() {
        if path.is_dir() {
            return Ok(format!("Directory already exists: {}", path.display()));
        }

        return Err(ToolError::InvalidPath(format!(
            "A file with the same name already exists: {}",
            path.display()
        )));
    }

    if recursive {
        fs::create_dir_all(path).map_err(|e| {
            ToolError::PermissionDenied(format!(
                "Cannot create directory {}: {}",
                path.display(),
                e
            ))
        })?;
    } else {
        // Ensure parent exists for non-recursive creation
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                return Err(ToolError::DirectoryNotFound(format!(
                    "Parent directory does not exist: {}",
                    parent.display()
                )));
            }
        }

        fs::create_dir(path).map_err(|e| {
            ToolError::PermissionDenied(format!(
                "Cannot create directory {}: {}",
                path.display(),
                e
            ))
        })?;
    }

    Ok(format!(
        "Successfully created directory: {}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_create_directory_simple() {
        let dir = tempdir().unwrap();
        let new_dir = dir.path().join("new_dir");

        let result = create_directory(&new_dir, false).unwrap();
        assert!(result.contains("Successfully created"));
        assert!(new_dir.exists());
        assert!(new_dir.is_dir());
    }

    #[test]
    fn test_create_directory_recursive() {
        let dir = tempdir().unwrap();
        let new_dir = dir.path().join("parent").join("child").join("grandchild");

        let result = create_directory(&new_dir, true).unwrap();
        assert!(result.contains("Successfully created"));
        assert!(new_dir.exists());
        assert!(new_dir.is_dir());
    }

    #[test]
    fn test_create_directory_already_exists() {
        let dir = tempdir().unwrap();
        let new_dir = dir.path().join("existing_dir");
        fs::create_dir(&new_dir).unwrap();

        let result = create_directory(&new_dir, false).unwrap();
        assert!(result.contains("already exists"));
    }

    #[test]
    fn test_create_directory_file_exists() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("existing_file.txt");
        fs::write(&file_path, "content").unwrap();

        let result = create_directory(&file_path, false);
        assert!(matches!(result, Err(ToolError::InvalidPath(_))));
    }

    #[test]
    fn test_create_directory_non_recursive_missing_parent() {
        let dir = tempdir().unwrap();
        let new_dir = dir.path().join("nonexistent").join("child");

        let result = create_directory(&new_dir, false);
        assert!(matches!(result, Err(ToolError::DirectoryNotFound(_))));
    }
}
