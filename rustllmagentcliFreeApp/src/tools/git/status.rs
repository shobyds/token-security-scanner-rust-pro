//! Git status operations

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

use crate::types::error::ToolError;

/// Get git status for a repository
pub fn git_status(repo_path: &Path) -> Result<String, ToolError> {
    if !repo_path.exists() {
        return Err(ToolError::DirectoryNotFound(
            repo_path.display().to_string(),
        ));
    }

    let output = Command::new("git")
        .args(["status"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| ToolError::GitOperation(format!("Failed to execute git status: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::GitOperation(format!(
            "Git status failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(format!(
        "Git status for {}:\n\n{}",
        repo_path.display(),
        stdout
    ))
}

/// Get git status in short format
pub fn git_status_short(repo_path: &Path) -> Result<String, ToolError> {
    if !repo_path.exists() {
        return Err(ToolError::DirectoryNotFound(
            repo_path.display().to_string(),
        ));
    }

    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| ToolError::GitOperation(format!("Failed to execute git status: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::GitOperation(format!(
            "Git status failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.trim().is_empty() {
        return Ok(format!("Working tree clean for {}", repo_path.display()));
    }

    Ok(format!(
        "Modified files in {}:\n\n{}",
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
    fn test_git_status_not_found() {
        let result = git_status(&Path::new("/nonexistent/path"));
        assert!(matches!(result, Err(ToolError::DirectoryNotFound(_))));
    }

    #[test]
    fn test_git_status_on_empty_repo() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        let result = git_status(dir.path());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Git status"));
    }

    #[test]
    fn test_git_status_short() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        // Create a file
        fs::write(dir.path().join("test.txt"), "content").unwrap();

        let result = git_status_short(dir.path());
        assert!(result.is_ok());
        // File is untracked, so it should appear in status
    }

    #[test]
    fn test_git_status_clean() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        // Create and commit a file
        fs::write(dir.path().join("test.txt"), "content").unwrap();

        Command::new("git")
            .args(["add", "test.txt"])
            .current_dir(dir.path())
            .output()
            .expect("Failed to add file");

        Command::new("git")
            .args(["commit", "-m", "Initial commit"])
            .current_dir(dir.path())
            .output()
            .expect("Failed to commit");

        let result = git_status_short(dir.path());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("clean"));
    }
}
