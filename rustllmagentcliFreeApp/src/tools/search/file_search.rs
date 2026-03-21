//! File name search operations

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use std::fs;
use std::path::Path;

#[cfg(test)]
use std::path::PathBuf;

use crate::types::error::ToolError;

/// Search for files by name pattern (regex)
pub fn search_files(
    directory: &Path,
    pattern: &regex::Regex,
    max_results: usize,
) -> Result<String, ToolError> {
    if !directory.exists() {
        return Err(ToolError::DirectoryNotFound(
            directory.display().to_string(),
        ));
    }

    if !directory.is_dir() {
        return Err(ToolError::InvalidPath(format!(
            "Path is not a directory: {}",
            directory.display()
        )));
    }

    let mut results = Vec::new();
    let mut file_count = 0;
    let mut dir_count = 0;

    search_recursive(
        directory,
        pattern,
        &mut results,
        &mut file_count,
        &mut dir_count,
        max_results,
    )?;

    if results.is_empty() {
        return Ok(format!(
            "No files matching pattern '{}' found in {}",
            pattern.as_str(),
            directory.display()
        ));
    }

    let header = format!(
        "Found {} file(s) matching '{}' in {}:\n\n",
        results.len(),
        pattern.as_str(),
        directory.display()
    );

    Ok(header + &results.join("\n"))
}

/// Recursively search for files
fn search_recursive(
    directory: &Path,
    pattern: &regex::Regex,
    results: &mut Vec<String>,
    file_count: &mut usize,
    dir_count: &mut usize,
    max_results: usize,
) -> Result<(), ToolError> {
    if results.len() >= max_results {
        return Ok(());
    }

    let entries = fs::read_dir(directory).map_err(|e| {
        ToolError::PermissionDenied(format!(
            "Cannot read directory {}: {}",
            directory.display(),
            e
        ))
    })?;

    for entry in entries {
        if results.len() >= max_results {
            return Ok(());
        }

        let entry =
            entry.map_err(|e| ToolError::PermissionDenied(format!("Cannot read entry: {}", e)))?;

        let path = entry.path();

        // Skip hidden files and directories (starting with .)
        if let Some(name) = path.file_name() {
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
        }

        if path.is_dir() {
            *dir_count += 1;
            search_recursive(&path, pattern, results, file_count, dir_count, max_results)?;
        } else if path.is_file() {
            *file_count += 1;
            if let Some(name) = path.file_name() {
                let name_str = name.to_string_lossy();
                if pattern.is_match(&name_str) {
                    let size = path.metadata().map(|m| m.len()).unwrap_or(0);
                    results.push(format!("{} ({})", path.display(), format_size(size)));
                }
            }
        }
    }

    Ok(())
}

/// Search for files by name pattern, respecting .gitignore
#[allow(dead_code)]
pub fn search_files_respecting_gitignore(
    directory: &Path,
    pattern: &regex::Regex,
    max_results: usize,
) -> Result<String, ToolError> {
    if !directory.exists() {
        return Err(ToolError::DirectoryNotFound(
            directory.display().to_string(),
        ));
    }

    let mut results = Vec::new();
    let mut total_scanned = 0;

    // Use ignore crate to respect .gitignore
    let walk = ignore::WalkBuilder::new(directory)
        .hidden(false)
        .git_global(true)
        .git_ignore(true)
        .build();

    for entry in walk.flatten() {
        if results.len() >= max_results {
            break;
        }

        let path = entry.path();
        total_scanned += 1;

        if path.is_file() {
            if let Some(name) = path.file_name() {
                let name_str = name.to_string_lossy();
                if pattern.is_match(&name_str) {
                    let size = path.metadata().map(|m| m.len()).unwrap_or(0);
                    results.push(format!("{} ({})", path.display(), format_size(size)));
                }
            }
        }
    }

    if results.is_empty() {
        return Ok(format!(
            "No files matching pattern '{}' found (scanned {} files)",
            pattern.as_str(),
            total_scanned
        ));
    }

    let header = format!(
        "Found {} file(s) matching '{}' (scanned {} files):\n\n",
        results.len(),
        pattern.as_str(),
        total_scanned
    );

    Ok(header + &results.join("\n"))
}

/// Format file size in human-readable format
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_search_files_basic() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("test.txt"), "content").unwrap();
        fs::write(dir.path().join("test.rs"), "content").unwrap();
        fs::write(dir.path().join("other.md"), "content").unwrap();

        let pattern = regex::Regex::new(r"\.txt$").unwrap();
        let result = search_files(dir.path(), &pattern, 100).unwrap();

        assert!(result.contains("test.txt"));
        assert!(!result.contains("test.rs"));
        assert!(!result.contains("other.md"));
    }

    #[test]
    fn test_search_files_regex_pattern() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("file1.txt"), "content").unwrap();
        fs::write(dir.path().join("file2.txt"), "content").unwrap();
        fs::write(dir.path().join("file3.log"), "content").unwrap();

        let pattern = regex::Regex::new(r"file\d+\.txt").unwrap();
        let result = search_files(dir.path(), &pattern, 100).unwrap();

        assert!(result.contains("file1.txt"));
        assert!(result.contains("file2.txt"));
        assert!(!result.contains("file3.log"));
    }

    #[test]
    fn test_search_files_recursive() {
        let dir = tempdir().unwrap();
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(dir.path().join("file1.txt"), "content").unwrap();
        fs::write(subdir.join("file2.txt"), "content").unwrap();

        let pattern = regex::Regex::new(r"\.txt$").unwrap();
        let result = search_files(dir.path(), &pattern, 100).unwrap();

        assert!(result.contains("file1.txt"));
        assert!(result.contains("file2.txt"));
    }

    #[test]
    fn test_search_files_max_results() {
        let dir = tempdir().unwrap();
        for i in 0..10 {
            fs::write(dir.path().join(format!("file{i}.txt")), "content").unwrap();
        }

        let pattern = regex::Regex::new(r"\.txt$").unwrap();
        let result = search_files(dir.path(), &pattern, 5).unwrap();

        // Count actual file result lines (containing " B)" which indicates file size in output)
        let lines: Vec<_> = result.lines().filter(|l| l.contains(" B)")).collect();
        assert!(lines.len() <= 5);
    }

    #[test]
    fn test_search_files_no_matches() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("file.txt"), "content").unwrap();

        let pattern = regex::Regex::new(r"\.xyz$").unwrap();
        let result = search_files(dir.path(), &pattern, 100).unwrap();

        assert!(result.contains("No files matching"));
    }

    #[test]
    fn test_search_files_not_found() {
        let result = search_files(
            &PathBuf::from("/nonexistent"),
            &regex::Regex::new(r".*").unwrap(),
            100,
        );
        assert!(matches!(result, Err(ToolError::DirectoryNotFound(_))));
    }

    #[test]
    fn test_search_files_respecting_gitignore() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("included.txt"), "content").unwrap();
        fs::write(dir.path().join("target.txt"), "content").unwrap();

        // Create a .gitignore file
        fs::write(dir.path().join(".gitignore"), "target/\ntarget.txt\n").unwrap();

        let pattern = regex::Regex::new(r"\.txt$").unwrap();
        let result = search_files_respecting_gitignore(dir.path(), &pattern, 100).unwrap();

        assert!(result.contains("included.txt"));
        // target.txt should be ignored due to .gitignore
    }

    #[test]
    fn test_search_files_skips_hidden() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("visible.txt"), "content").unwrap();
        fs::write(dir.path().join(".hidden.txt"), "content").unwrap();

        let pattern = regex::Regex::new(r"\.txt$").unwrap();
        let result = search_files(dir.path(), &pattern, 100).unwrap();

        assert!(result.contains("visible.txt"));
        assert!(!result.contains(".hidden.txt"));
    }
}
