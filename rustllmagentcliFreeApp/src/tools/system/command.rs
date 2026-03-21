//! System command execution

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

use crate::types::error::ToolError;

/// Run a shell command and return the output
pub fn run_command(
    cmd: &str,
    args: &[&str],
    working_dir: Option<&Path>,
) -> Result<String, ToolError> {
    let mut command = Command::new(cmd);
    command.args(args);

    if let Some(dir) = working_dir {
        if !dir.exists() {
            return Err(ToolError::DirectoryNotFound(dir.display().to_string()));
        }
        command.current_dir(dir);
    }

    let output = command
        .output()
        .map_err(|e| ToolError::CommandFailed(format!("Failed to execute command: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let mut result = String::new();

    if !stdout.is_empty() {
        result.push_str(&format!("Output:\n{}\n", stdout));
    }

    if !stderr.is_empty() {
        result.push_str(&format!("Errors:\n{}\n", stderr));
    }

    if output.status.success() {
        if result.is_empty() {
            Ok("Command executed successfully (no output)".to_string())
        } else {
            Ok(result)
        }
    } else {
        Err(ToolError::CommandFailed(format!(
            "Command failed with exit code {:?}\n{}",
            output.status.code(),
            result
        )))
    }
}

/// Run a shell command in a specific directory
pub fn run_command_in_dir(
    cmd: &str,
    args: &[&str],
    working_dir: &Path,
) -> Result<String, ToolError> {
    run_command(cmd, args, Some(working_dir))
}

/// Run a shell command with timeout (simplified - actual timeout would need async)
pub fn run_command_with_timeout(
    cmd: &str,
    args: &[&str],
    _timeout_secs: u64,
) -> Result<String, ToolError> {
    // For now, just run without timeout
    // A full implementation would use tokio::time::timeout
    run_command(cmd, args, None)
}

/// Execute a shell script
pub fn run_script(script_path: &Path, args: &[&str]) -> Result<String, ToolError> {
    if !script_path.exists() {
        return Err(ToolError::FileNotFound(script_path.display().to_string()));
    }

    let shell = if cfg!(windows) { "cmd" } else { "sh" };

    let shell_arg = if cfg!(windows) { "/c" } else { "-c" };

    let script_path_str = script_path.to_string_lossy();
    let mut full_args = vec![shell_arg, &script_path_str];
    full_args.extend_from_slice(args);

    run_command(shell, &full_args, script_path.parent())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_run_command_echo() {
        let result = run_command("echo", &["Hello, World!"], None);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Hello, World!"));
    }

    #[test]
    fn test_run_command_pwd() {
        let result = run_command("pwd", &[], None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_command_in_dir() {
        let dir = tempdir().unwrap();
        let result = run_command_in_dir("pwd", &[], dir.path());
        assert!(result.is_ok());
        assert!(
            result
                .unwrap()
                .contains(dir.path().to_string_lossy().as_ref())
        );
    }

    #[test]
    fn test_run_command_invalid() {
        let result = run_command("nonexistent_command_xyz", &[], None);
        assert!(matches!(result, Err(ToolError::CommandFailed(_))));
    }

    #[test]
    fn test_run_command_with_error() {
        // This command should fail
        let result = run_command("ls", &["/nonexistent/path/xyz"], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_run_command_no_output() {
        // true command succeeds with no output
        let result = run_command("true", &[], None);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("successfully"));
    }

    #[test]
    fn test_run_script_not_found() {
        let result = run_script(&Path::new("/nonexistent/script.sh"), &[]);
        assert!(matches!(result, Err(ToolError::FileNotFound(_))));
    }

    #[test]
    fn test_run_script() {
        let dir = tempdir().unwrap();
        let script_path = dir.path().join("test.sh");
        fs::write(&script_path, "#!/bin/sh\necho 'Script executed'\n").unwrap();

        #[cfg(unix)]
        {
            std::process::Command::new("chmod")
                .args(["+x", script_path.to_str().unwrap()])
                .output()
                .expect("Failed to chmod script");
        }

        let result = run_script(&script_path, &[]);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Script executed"));
    }

    #[test]
    fn test_run_command_cat() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), "test content").unwrap();

        let result = run_command("cat", &[file.path().to_str().unwrap()], None);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("test content"));
    }

    #[test]
    fn test_run_command_working_dir() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();

        let result = run_command("cat", &["test.txt"], Some(dir.path()));
        assert!(result.is_ok());
        assert!(result.unwrap().contains("content"));
    }
}
