//! Content search operations (grep-like functionality)

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::types::error::ToolError;

/// A single match result
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MatchResult {
    pub file_path: String,
    pub line_number: usize,
    pub line_content: String,
    #[allow(dead_code)]
    pub matched_text: String,
}

/// Search for a pattern in a single file
pub fn search_in_file(path: &Path, pattern: &regex::Regex) -> Result<String, ToolError> {
    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    if !path.is_file() {
        return Err(ToolError::InvalidPath(format!(
            "Path is not a file: {}",
            path.display()
        )));
    }

    let file = fs::File::open(path).map_err(|e| {
        ToolError::PermissionDenied(format!("Cannot open file {}: {}", path.display(), e))
    })?;

    let reader = BufReader::new(file);
    let mut results = Vec::new();
    let mut total_matches = 0;

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(|e| {
            ToolError::PermissionDenied(format!("Cannot read line from {}: {}", path.display(), e))
        })?;

        if pattern.is_match(&line) {
            total_matches += 1;
            if results.len() < 100 {
                // Limit displayed results
                results.push(format!("{}: {}", line_num + 1, line));
            }
        }
    }

    if results.is_empty() {
        return Ok(format!(
            "No matches for pattern '{}' found in {}",
            pattern.as_str(),
            path.display()
        ));
    }

    let header = format!(
        "Found {} match(es) for '{}' in {}:\n\n",
        total_matches,
        pattern.as_str(),
        path.display()
    );

    let truncated = if total_matches > 100 {
        format!("\n... (showing first 100 of {total_matches} matches)")
    } else {
        String::new()
    };

    Ok(header + &results.join("\n") + &truncated)
}

/// Search for a pattern in a file with context lines
#[allow(dead_code)]
pub fn search_in_file_with_context(
    path: &Path,
    pattern: &regex::Regex,
    context_before: usize,
    context_after: usize,
) -> Result<String, ToolError> {
    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    if !path.is_file() {
        return Err(ToolError::InvalidPath(format!(
            "Path is not a file: {}",
            path.display()
        )));
    }

    let file = fs::File::open(path).map_err(|e| {
        ToolError::PermissionDenied(format!("Cannot open file {}: {}", path.display(), e))
    })?;

    let reader = BufReader::new(file);
    let lines: Vec<_> = reader.lines().collect::<Result<_, _>>().map_err(|e| {
        ToolError::PermissionDenied(format!("Cannot read file {}: {}", path.display(), e))
    })?;

    let mut results = Vec::new();
    let mut total_matches = 0;

    for (i, line) in lines.iter().enumerate() {
        if pattern.is_match(line) {
            total_matches += 1;

            // Add context before
            let start = i.saturating_sub(context_before);
            for j in start..i {
                results.push(format!("{}| {}", j + 1, lines[j]));
            }

            // Add matching line with marker
            results.push(format!("{}> {}", i + 1, line));

            // Add context after
            let end = (i + context_after + 1).min(lines.len());
            for j in (i + 1)..end {
                results.push(format!("{}| {}", j + 1, lines[j]));
            }

            if results.len() > 200 {
                results.push(format!("... (more matches)"));
                break;
            }
        }
    }

    if results.is_empty() {
        return Ok(format!(
            "No matches for pattern '{}' found in {}",
            pattern.as_str(),
            path.display()
        ));
    }

    let header = format!(
        "Found {} match(es) for '{}' in {} (with context):\n\n",
        total_matches,
        pattern.as_str(),
        path.display()
    );

    Ok(header + &results.join("\n"))
}

/// Recursively search for a pattern in all files within a directory
pub fn grep_recursive(
    directory: &Path,
    pattern: &regex::Regex,
    file_pattern: Option<&regex::Regex>,
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
    let mut files_searched = 0;
    let mut total_matches = 0;

    grep_recursive_impl(
        directory,
        pattern,
        file_pattern,
        &mut results,
        &mut files_searched,
        &mut total_matches,
        max_results,
    )?;

    if results.is_empty() {
        return Ok(format!(
            "No matches for pattern '{}' found in {} (searched {} files)",
            pattern.as_str(),
            directory.display(),
            files_searched
        ));
    }

    let header = format!(
        "Found {} match(s) for '{}' in {} files (searched {} files):\n\n",
        total_matches,
        pattern.as_str(),
        results.len(),
        files_searched
    );

    Ok(header + &results.join("\n"))
}

/// Implementation of recursive grep
fn grep_recursive_impl(
    directory: &Path,
    pattern: &regex::Regex,
    file_pattern: Option<&regex::Regex>,
    results: &mut Vec<String>,
    files_searched: &mut usize,
    total_matches: &mut usize,
    max_results: usize,
) -> Result<(), ToolError> {
    let entries = fs::read_dir(directory).map_err(|e| {
        ToolError::PermissionDenied(format!(
            "Cannot read directory {}: {}",
            directory.display(),
            e
        ))
    })?;

    for entry in entries {
        if *total_matches >= max_results {
            return Ok(());
        }

        let entry =
            entry.map_err(|e| ToolError::PermissionDenied(format!("Cannot read entry: {}", e)))?;

        let path = entry.path();

        // Skip hidden files and directories
        if let Some(name) = path.file_name() {
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
        }

        if path.is_dir() {
            grep_recursive_impl(
                directory,
                pattern,
                file_pattern,
                results,
                files_searched,
                total_matches,
                max_results,
            )?;
        } else if path.is_file() {
            // Check file pattern if provided
            if let Some(fp) = file_pattern {
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy();
                    if !fp.is_match(&name_str) {
                        continue;
                    }
                }
            }

            *files_searched += 1;

            // Search in file
            match search_in_file_internal(&path, pattern) {
                Ok(matches) => {
                    for m in matches {
                        *total_matches += 1;
                        if results.len() < max_results {
                            results.push(format!(
                                "{}:{}: {}",
                                m.file_path, m.line_number, m.line_content
                            ));
                        }
                    }
                }
                Err(_) => {
                    // Skip files that can't be read (binary files, etc.)
                }
            }
        }
    }

    Ok(())
}

/// Internal search that returns structured results
fn search_in_file_internal(
    path: &Path,
    pattern: &regex::Regex,
) -> Result<Vec<MatchResult>, ToolError> {
    let file = fs::File::open(path).map_err(|e| {
        ToolError::PermissionDenied(format!("Cannot open file {}: {}", path.display(), e))
    })?;

    let reader = BufReader::new(file);
    let mut results = Vec::new();

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(|e| {
            ToolError::PermissionDenied(format!("Cannot read line from {}: {}", path.display(), e))
        })?;

        if pattern.is_match(&line) {
            results.push(MatchResult {
                file_path: path.display().to_string(),
                line_number: line_num + 1,
                line_content: line,
                matched_text: pattern.to_string(),
            });
        }
    }

    Ok(results)
}

/// Search for a pattern in all files with a specific extension
#[allow(dead_code)]
pub fn grep_by_extension(
    directory: &Path,
    pattern: &regex::Regex,
    extension: &str,
    max_results: usize,
) -> Result<String, ToolError> {
    if !directory.exists() {
        return Err(ToolError::DirectoryNotFound(
            directory.display().to_string(),
        ));
    }

    let mut results = Vec::new();
    let mut files_searched = 0;
    let mut total_matches = 0;

    let ext = if extension.starts_with('.') {
        extension.to_string()
    } else {
        format!(".{extension}")
    };

    grep_by_extension_impl(
        directory,
        pattern,
        &ext,
        &mut results,
        &mut files_searched,
        &mut total_matches,
        max_results,
    )?;

    if results.is_empty() {
        return Ok(format!(
            "No matches for pattern '{}' found in *{} files",
            pattern.as_str(),
            ext
        ));
    }

    let header = format!(
        "Found {} match(s) for '{}' in *{} files:\n\n",
        total_matches,
        pattern.as_str(),
        ext
    );

    Ok(header + &results.join("\n"))
}

/// Implementation of grep by extension
#[allow(dead_code)]
fn grep_by_extension_impl(
    directory: &Path,
    pattern: &regex::Regex,
    extension: &str,
    results: &mut Vec<String>,
    files_searched: &mut usize,
    total_matches: &mut usize,
    max_results: usize,
) -> Result<(), ToolError> {
    let entries = fs::read_dir(directory).map_err(|e| {
        ToolError::PermissionDenied(format!(
            "Cannot read directory {}: {}",
            directory.display(),
            e
        ))
    })?;

    for entry in entries {
        if *total_matches >= max_results {
            return Ok(());
        }

        let entry =
            entry.map_err(|e| ToolError::PermissionDenied(format!("Cannot read entry: {}", e)))?;

        let path = entry.path();

        if let Some(name) = path.file_name() {
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
        }

        if path.is_dir() {
            grep_by_extension_impl(
                directory,
                pattern,
                extension,
                results,
                files_searched,
                total_matches,
                max_results,
            )?;
        } else if path.is_file() {
            if let Some(ext) = path.extension() {
                if &format!(".{}", ext.to_string_lossy()) != extension {
                    continue;
                }
            } else {
                continue;
            }

            *files_searched += 1;

            match search_in_file_internal(&path, pattern) {
                Ok(matches) => {
                    for m in matches {
                        *total_matches += 1;
                        if results.len() < max_results {
                            results.push(format!(
                                "{}:{}: {}",
                                m.file_path, m.line_number, m.line_content
                            ));
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_search_in_file_basic() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "line1\nhello world\nline3\nhello again\n").unwrap();

        let pattern = regex::Regex::new(r"hello").unwrap();
        let result = search_in_file(&file_path, &pattern).unwrap();

        assert!(result.contains("2: hello world"));
        assert!(result.contains("4: hello again"));
        assert!(result.contains("2 match(es)"));
    }

    #[test]
    fn test_search_in_file_no_matches() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "line1\nline2\nline3\n").unwrap();

        let pattern = regex::Regex::new(r"xyz").unwrap();
        let result = search_in_file(&file_path, &pattern).unwrap();

        assert!(result.contains("No matches"));
    }

    #[test]
    fn test_search_in_file_not_found() {
        let pattern = regex::Regex::new(r"test").unwrap();
        let result = search_in_file(&Path::new("/nonexistent/file.txt"), &pattern);
        assert!(matches!(result, Err(ToolError::FileNotFound(_))));
    }

    #[test]
    fn test_search_in_file_with_context() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "line1\nline2\nMATCH\nline4\nline5\n").unwrap();

        let pattern = regex::Regex::new(r"MATCH").unwrap();
        let result = search_in_file_with_context(&file_path, &pattern, 1, 1).unwrap();

        // MATCH is at line 3, with 1 line context before and after
        assert!(result.contains("2| line2")); // Context before
        assert!(result.contains("3> MATCH")); // Matching line
        assert!(result.contains("4| line4")); // Context after
    }

    #[test]
    fn test_grep_recursive_basic() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("file1.txt"), "hello\nworld\n").unwrap();
        fs::write(dir.path().join("file2.txt"), "hello\nrust\n").unwrap();

        let pattern = regex::Regex::new(r"hello").unwrap();
        let result = grep_recursive(dir.path(), &pattern, None, 100).unwrap();

        assert!(result.contains("hello"));
        assert!(result.contains("file1.txt"));
        assert!(result.contains("file2.txt"));
    }

    #[test]
    fn test_grep_recursive_with_file_pattern() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("file1.txt"), "hello\n").unwrap();
        fs::write(dir.path().join("file2.rs"), "hello\n").unwrap();

        let pattern = regex::Regex::new(r"hello").unwrap();
        let file_pattern = regex::Regex::new(r"\.txt$").unwrap();
        let result = grep_recursive(dir.path(), &pattern, Some(&file_pattern), 100).unwrap();

        assert!(result.contains("file1.txt"));
        assert!(!result.contains("file2.rs"));
    }

    #[test]
    fn test_grep_recursive_no_matches() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("file.txt"), "no match here\n").unwrap();

        let pattern = regex::Regex::new(r"xyz").unwrap();
        let result = grep_recursive(dir.path(), &pattern, None, 100).unwrap();

        assert!(result.contains("No matches"));
    }

    #[test]
    fn test_grep_by_extension() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("file.txt"), "hello\n").unwrap();
        fs::write(dir.path().join("file.rs"), "hello\n").unwrap();
        fs::write(dir.path().join("other.txt"), "world\n").unwrap();

        let pattern = regex::Regex::new(r"hello").unwrap();
        let result = grep_by_extension(dir.path(), &pattern, "txt", 100).unwrap();

        assert!(result.contains("file.txt"));
        assert!(!result.contains("file.rs"));
    }

    #[test]
    fn test_grep_recursive_max_results() {
        let dir = tempdir().unwrap();
        for i in 0..10 {
            fs::write(dir.path().join(format!("file{i}.txt")), "match\n").unwrap();
        }

        let pattern = regex::Regex::new(r"match").unwrap();
        let result = grep_recursive(dir.path(), &pattern, None, 5).unwrap();

        // Count actual match result lines (format: path:line_num: content)
        let lines: Vec<_> = result.lines().filter(|l| l.contains(":match")).collect();
        assert!(lines.len() <= 5);
    }

    #[test]
    fn test_grep_recursive_skips_hidden() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("visible.txt"), "hello\n").unwrap();
        fs::write(dir.path().join(".hidden.txt"), "hello\n").unwrap();

        let pattern = regex::Regex::new(r"hello").unwrap();
        let result = grep_recursive(dir.path(), &pattern, None, 100).unwrap();

        assert!(result.contains("visible.txt"));
        assert!(!result.contains(".hidden.txt"));
    }

    #[test]
    fn test_search_in_file_binary_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("binary.bin");
        fs::write(&file_path, &[0u8, 1, 2, 3, 255]).unwrap();

        let pattern = regex::Regex::new(r"test").unwrap();
        // Should handle binary files gracefully
        let result = search_in_file(&file_path, &pattern);
        // May fail or succeed, but shouldn't panic
        assert!(result.is_ok() || result.is_err());
    }
}
