//! List directory contents

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use std::fs;
use std::path::{Path, PathBuf};

use crate::types::error::ToolError;

/// Result of a directory listing
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DirectoryEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: Option<u64>,
}

/// List directory contents (non-recursive)
pub fn list_directory(path: &Path, max_results: usize) -> Result<String, ToolError> {
    if !path.exists() {
        return Err(ToolError::DirectoryNotFound(path.display().to_string()));
    }

    if !path.is_dir() {
        return Err(ToolError::InvalidPath(format!(
            "Path is not a directory: {}",
            path.display()
        )));
    }

    let entries = fs::read_dir(path).map_err(|e| {
        ToolError::PermissionDenied(format!("Cannot read directory {}: {}", path.display(), e))
    })?;

    let mut result = Vec::new();
    let mut dir_count = 0;
    let mut file_count = 0;

    for entry in entries.take(max_results) {
        let entry = entry.map_err(|e: std::io::Error| {
            ToolError::PermissionDenied(format!("Cannot read entry: {}", e))
        })?;

        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = entry.path().is_dir();
        let size = if is_dir {
            None
        } else {
            entry.metadata().map(|m: std::fs::Metadata| m.len()).ok()
        };

        if is_dir {
            dir_count += 1;
            result.push(format!("📁 {name}/"));
        } else {
            file_count += 1;
            let size_str = format_size(size.unwrap_or(0));
            result.push(format!("📄 {name} ({size_str})"));
        }
    }

    let header = format!(
        "Directory: {}\nTotal: {} directories, {} files\n\n",
        path.display(),
        dir_count,
        file_count
    );

    Ok(header + &result.join("\n"))
}

/// List directory contents recursively with tree structure
pub fn directory_tree(path: &Path, max_depth: usize) -> Result<String, ToolError> {
    if !path.exists() {
        return Err(ToolError::DirectoryNotFound(path.display().to_string()));
    }

    if !path.is_dir() {
        return Err(ToolError::InvalidPath(format!(
            "Path is not a directory: {}",
            path.display()
        )));
    }

    let mut result = String::new();
    result.push_str(&format!(
        "{}\n",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));

    build_tree(path, &mut result, 0, max_depth, "")?;

    Ok(result)
}

/// Recursively build tree structure
fn build_tree(
    path: &Path,
    result: &mut String,
    current_depth: usize,
    max_depth: usize,
    prefix: &str,
) -> Result<(), ToolError> {
    if current_depth >= max_depth {
        return Ok(());
    }

    let entries = fs::read_dir(path).map_err(|e| {
        ToolError::PermissionDenied(format!("Cannot read directory {}: {}", path.display(), e))
    })?;

    let mut entries: Vec<_> = entries
        .filter_map(|e: Result<std::fs::DirEntry, std::io::Error>| e.ok())
        .collect();

    // Sort entries: directories first, then files, alphabetically
    entries.sort_by(|a: &std::fs::DirEntry, b: &std::fs::DirEntry| {
        let a_is_dir = a.path().is_dir();
        let b_is_dir = b.path().is_dir();
        match (a_is_dir, b_is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.file_name().cmp(&b.file_name()),
        }
    });

    let mut entries = entries.into_iter().peekable();
    while let Some(entry) = entries.next() {
        let is_last = entries.peek().is_none();
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = entry.path().is_dir();

        let connector = if is_last { "└── " } else { "├── " };
        let icon = if is_dir { "📁 " } else { "📄 " };

        result.push_str(&format!("{prefix}{connector}{icon}{name}"));

        if is_dir {
            result.push('\n');
            let new_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });
            build_tree(
                &entry.path(),
                result,
                current_depth + 1,
                max_depth,
                &new_prefix,
            )?;
        } else {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            result.push_str(&format!(" ({})\n", format_size(size)));
        }
    }

    Ok(())
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
    fn test_list_directory_empty() {
        let dir = tempdir().unwrap();
        let result = list_directory(dir.path(), 100).unwrap();

        assert!(result.contains("Directory:"));
        assert!(result.contains("Total: 0 directories, 0 files"));
    }

    #[test]
    fn test_list_directory_with_files() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("file1.txt"), "content1").unwrap();
        fs::write(dir.path().join("file2.txt"), "content2").unwrap();

        let result = list_directory(dir.path(), 100).unwrap();
        assert!(result.contains("file1.txt"));
        assert!(result.contains("file2.txt"));
        assert!(result.contains("Total: 0 directories, 2 files"));
    }

    #[test]
    fn test_list_directory_with_subdirs() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("subdir1")).unwrap();
        fs::create_dir(dir.path().join("subdir2")).unwrap();
        fs::write(dir.path().join("file.txt"), "content").unwrap();

        let result = list_directory(dir.path(), 100).unwrap();
        assert!(result.contains("subdir1/"));
        assert!(result.contains("subdir2/"));
        assert!(result.contains("file.txt"));
        assert!(result.contains("Total: 2 directories, 1 files"));
    }

    #[test]
    fn test_list_directory_not_found() {
        let result = list_directory(&PathBuf::from("/nonexistent/dir"), 100);
        assert!(matches!(result, Err(ToolError::DirectoryNotFound(_))));
    }

    #[test]
    fn test_list_directory_not_a_directory() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("file.txt");
        fs::write(&file_path, "content").unwrap();

        let result = list_directory(&file_path, 100);
        assert!(matches!(result, Err(ToolError::InvalidPath(_))));
    }

    #[test]
    fn test_list_directory_max_results() {
        let dir = tempdir().unwrap();
        for i in 0..10 {
            fs::write(dir.path().join(format!("file{i}.txt")), "content").unwrap();
        }

        let result = list_directory(dir.path(), 5).unwrap();
        // Should only contain 5 files (excluding header lines)
        let lines: Vec<_> = result.lines().filter(|l| l.contains("📄")).collect();
        assert_eq!(lines.len(), 5);
    }

    #[test]
    fn test_directory_tree() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        fs::write(dir.path().join("file.txt"), "content").unwrap();
        fs::write(dir.path().join("subdir").join("nested.txt"), "nested").unwrap();

        let result = directory_tree(dir.path(), 3).unwrap();
        assert!(result.contains("├──"));
        assert!(result.contains("└──"));
        assert!(result.contains("file.txt"));
        assert!(result.contains("subdir"));
    }

    #[test]
    fn test_directory_tree_max_depth() {
        let dir = tempdir().unwrap();
        let level1 = dir.path().join("level1");
        let level2 = level1.join("level2");
        let level3 = level2.join("level3");
        fs::create_dir_all(&level3).unwrap();
        fs::write(level3.join("deep.txt"), "deep").unwrap();

        let result = directory_tree(dir.path(), 2).unwrap();
        assert!(result.contains("level1"));
        assert!(result.contains("level2"));
        assert!(!result.contains("level3"));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1_572_864), "1.5 MB");
        assert_eq!(format_size(1_610_612_736), "1.5 GB");
    }
}
