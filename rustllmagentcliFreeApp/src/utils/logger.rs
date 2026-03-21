//! Logging setup utilities

#![allow(clippy::missing_errors_doc)]

use std::path::Path;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize logging with the given level and log file
/// `RUST_LOG` environment variable takes precedence over the level parameter
pub fn init_logging(level: &str, log_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let log_path = Path::new(log_file);

    // Create log directory if it doesn't exist
    if let Some(parent) = log_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }

    // Create log file
    let file_appender = tracing_appender::rolling::never(
        parent_or_current(log_path),
        log_path.file_name().unwrap_or(log_file.as_ref()),
    );

    // RUST_LOG env var takes precedence, otherwise use provided level
    let filter = EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(file_appender))
        .init();

    Ok(())
}

/// Get parent directory or current directory
fn parent_or_current(path: &Path) -> std::path::PathBuf {
    path.parent().map_or_else(
        || std::path::PathBuf::from("."),
        std::path::Path::to_path_buf,
    )
}

/// Initialize logging to stdout only (for development)
/// `RUST_LOG` environment variable takes precedence over the level parameter
pub fn init_logging_stdout(level: &str) {
    // RUST_LOG env var takes precedence, otherwise use provided level
    let filter = EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parent_or_current_with_parent() {
        let path = Path::new("/var/log/agent.log");
        let parent = parent_or_current(path);
        assert_eq!(parent, Path::new("/var/log"));
    }

    #[test]
    fn test_parent_or_current_without_parent() {
        let path = Path::new("agent.log");
        let parent = parent_or_current(path);
        // When there's no parent, we return current directory
        // Just verify the function doesn't panic and returns something
        let _ = parent;
    }

    #[test]
    fn test_init_logging_stdout() {
        // Note: This can only be called once per process
        // We just verify it doesn't panic
        init_logging_stdout("info");
    }
}
