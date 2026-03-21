//! Git log operations

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

use crate::types::error::ToolError;

/// Get git log for a repository
pub fn git_log(repo_path: &Path, count: usize) -> Result<String, ToolError> {
    if !repo_path.exists() {
        return Err(ToolError::DirectoryNotFound(
            repo_path.display().to_string(),
        ));
    }

    let count_str = count.to_string();
    let output = Command::new("git")
        .args(["log", &format!("-{}", count_str), "--oneline"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| ToolError::GitOperation(format!("Failed to execute git log: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::GitOperation(format!(
            "Git log failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(format!(
        "Git log for {} (last {} commits):\n\n{}",
        repo_path.display(),
        count,
        stdout
    ))
}

/// Get git log with detailed format
pub fn git_log_detailed(repo_path: &Path, count: usize) -> Result<String, ToolError> {
    if !repo_path.exists() {
        return Err(ToolError::DirectoryNotFound(
            repo_path.display().to_string(),
        ));
    }

    let count_str = count.to_string();
    let output = Command::new("git")
        .args([
            "log",
            &format!("-{}", count_str),
            "--pretty=format:%H%n%an%n%ae%n%ad%n%s%n%b%n---",
        ])
        .current_dir(repo_path)
        .output()
        .map_err(|e| ToolError::GitOperation(format!("Failed to execute git log: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ToolError::GitOperation(format!(
            "Git log failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(format!(
        "Detailed git log for {} (last {} commits):\n\n{}",
        repo_path.display(),
        count,
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
    fn test_git_log_not_found() {
        let result = git_log(&Path::new("/nonexistent/path"), 10);
        assert!(matches!(result, Err(ToolError::DirectoryNotFound(_))));
    }

    #[test]
    fn test_git_log_empty_repo() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        let result = git_log(dir.path(), 10);
        // Empty repo will have no commits
        assert!(result.is_err()); // Will fail because no commits
    }

    #[test]
    fn test_git_log_with_commits() {
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

        let result = git_log(dir.path(), 10);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Initial commit"));
    }

    #[test]
    fn test_git_log_count() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        // Create multiple commits
        for i in 0..5 {
            fs::write(dir.path().join(format!("test{}.txt", i)), "content").unwrap();
            Command::new("git")
                .args(["add", "."])
                .current_dir(dir.path())
                .output()
                .expect("Failed to add file");
            Command::new("git")
                .args(["commit", "-m", &format!("Commit {}", i)])
                .current_dir(dir.path())
                .output()
                .expect("Failed to commit");
        }

        let result = git_log(dir.path(), 3);
        assert!(result.is_ok());
        let log = result.unwrap();
        assert!(log.contains("Commit"));
        // Should only have 3 commits in output
        let commit_count = log.matches("Commit").count();
        assert_eq!(commit_count, 3);
    }

    #[test]
    fn test_git_log_detailed() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        fs::write(dir.path().join("test.txt"), "content").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "Test commit"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        let result = git_log_detailed(dir.path(), 1);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Test commit"));
    }
}
