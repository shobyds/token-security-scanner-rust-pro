//! Git diff operations

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

use crate::types::error::ToolError;

/// Get git diff for a repository (working tree vs index)
pub fn git_diff(repo_path: &Path) -> Result<String, ToolError> {
    if !repo_path.exists() {
        return Err(ToolError::DirectoryNotFound(
            repo_path.display().to_string(),
        ));
    }

    let output = Command::new("git")
        .args(["diff"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| ToolError::GitOperation(format!("Failed to execute git diff: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::GitOperation(format!(
            "Git diff failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.is_empty() {
        return Ok(format!(
            "No changes in working tree for {}",
            repo_path.display()
        ));
    }

    Ok(format!(
        "Git diff for {}:\n\n{}",
        repo_path.display(),
        stdout
    ))
}

/// Get git diff for a specific file
pub fn git_diff_file(repo_path: &Path, file_path: &Path) -> Result<String, ToolError> {
    if !repo_path.exists() {
        return Err(ToolError::DirectoryNotFound(
            repo_path.display().to_string(),
        ));
    }

    let file_str = file_path.to_string_lossy();
    let output = Command::new("git")
        .args(["diff", "--", &file_str])
        .current_dir(repo_path)
        .output()
        .map_err(|e| ToolError::GitOperation(format!("Failed to execute git diff: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::GitOperation(format!(
            "Git diff failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.is_empty() {
        return Ok(format!(
            "No changes for file {} in {}",
            file_path.display(),
            repo_path.display()
        ));
    }

    Ok(format!(
        "Git diff for {}:\n\n{}",
        file_path.display(),
        stdout
    ))
}

/// Get git diff between staged and HEAD
pub fn git_diff_staged(repo_path: &Path) -> Result<String, ToolError> {
    if !repo_path.exists() {
        return Err(ToolError::DirectoryNotFound(
            repo_path.display().to_string(),
        ));
    }

    let output = Command::new("git")
        .args(["diff", "--cached"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| ToolError::GitOperation(format!("Failed to execute git diff: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::GitOperation(format!(
            "Git diff failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.is_empty() {
        return Ok(format!("No staged changes for {}", repo_path.display()));
    }

    Ok(format!(
        "Staged changes for {}:\n\n{}",
        repo_path.display(),
        stdout
    ))
}

/// Get git diff stats
pub fn git_diff_stats(repo_path: &Path) -> Result<String, ToolError> {
    if !repo_path.exists() {
        return Err(ToolError::DirectoryNotFound(
            repo_path.display().to_string(),
        ));
    }

    let output = Command::new("git")
        .args(["diff", "--stat"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| ToolError::GitOperation(format!("Failed to execute git diff: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::GitOperation(format!(
            "Git diff failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.is_empty() {
        return Ok(format!(
            "No changes in working tree for {}",
            repo_path.display()
        ));
    }

    Ok(format!(
        "Git diff stats for {}:\n\n{}",
        repo_path.display(),
        stdout
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn init_git_repo(dir: &Path) {
        Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .expect("Failed to init git repo");

        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(dir)
            .output()
            .expect("Failed to config git email");

        Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(dir)
            .output()
            .expect("Failed to config git name");
    }

    #[test]
    fn test_git_diff_not_found() {
        let result = git_diff(&Path::new("/nonexistent/path"));
        assert!(matches!(result, Err(ToolError::DirectoryNotFound(_))));
    }

    #[test]
    fn test_git_diff_no_changes() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        let result = git_diff(dir.path());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("No changes"));
    }

    #[test]
    fn test_git_diff_with_changes() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        // Create and commit a file
        fs::write(dir.path().join("test.txt"), "original").unwrap();
        Command::new("git")
            .args(["add", "test.txt"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "Initial"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        // Modify the file
        fs::write(dir.path().join("test.txt"), "modified").unwrap();

        let result = git_diff(dir.path());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("modified"));
    }

    #[test]
    fn test_git_diff_file() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        fs::write(dir.path().join("test.txt"), "original").unwrap();
        Command::new("git")
            .args(["add", "test.txt"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "Initial"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        fs::write(dir.path().join("test.txt"), "modified").unwrap();

        let result = git_diff_file(dir.path(), &dir.path().join("test.txt"));
        assert!(result.is_ok());
        assert!(result.unwrap().contains("original"));
    }

    #[test]
    fn test_git_diff_staged() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        fs::write(dir.path().join("test.txt"), "content").unwrap();
        Command::new("git")
            .args(["add", "test.txt"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        let result = git_diff_staged(dir.path());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("content"));
    }

    #[test]
    fn test_git_diff_stats() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        fs::write(dir.path().join("test.txt"), "original").unwrap();
        Command::new("git")
            .args(["add", "test.txt"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "Initial"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        fs::write(
            dir.path().join("test.txt"),
            "modified content with more lines",
        )
        .unwrap();

        let result = git_diff_stats(dir.path());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("test.txt"));
    }
}
