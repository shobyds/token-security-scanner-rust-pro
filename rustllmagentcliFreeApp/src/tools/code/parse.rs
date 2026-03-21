//! Code parsing operations

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use regex::Regex;
use std::fs;
use std::path::Path;

use crate::types::error::ToolError;

/// Extract function names from a Rust file
pub fn extract_functions_rust(path: &Path) -> Result<String, ToolError> {
    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    let content = fs::read_to_string(path)
        .map_err(|e| ToolError::PermissionDenied(format!("Cannot read file: {}", e)))?;

    // Match Rust function definitions
    let re = Regex::new(r"(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*\(")
        .map_err(|e| ToolError::InvalidArguments(format!("Invalid regex: {}", e)))?;

    let functions: Vec<_> = re
        .captures_iter(&content)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .collect();

    if functions.is_empty() {
        return Ok(format!("No functions found in {}", path.display()));
    }

    Ok(format!(
        "Functions in {} ({} found):\n\n{}",
        path.display(),
        functions.len(),
        functions.join("\n")
    ))
}

/// Extract function names from a Python file
pub fn extract_functions_python(path: &Path) -> Result<String, ToolError> {
    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    let content = fs::read_to_string(path)
        .map_err(|e| ToolError::PermissionDenied(format!("Cannot read file: {}", e)))?;

    // Match Python function definitions (with multiline mode, including async)
    let re = Regex::new(r"(?m)^(?:async\s+)?def\s+(\w+)\s*\(")
        .map_err(|e| ToolError::InvalidArguments(format!("Invalid regex: {}", e)))?;

    let functions: Vec<_> = re
        .captures_iter(&content)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .collect();

    if functions.is_empty() {
        return Ok(format!("No functions found in {}", path.display()));
    }

    Ok(format!(
        "Functions in {} ({} found):\n\n{}",
        path.display(),
        functions.len(),
        functions.join("\n")
    ))
}

/// Extract imports from a Rust file
pub fn find_imports_rust(path: &Path) -> Result<String, ToolError> {
    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    let content = fs::read_to_string(path)
        .map_err(|e| ToolError::PermissionDenied(format!("Cannot read file: {}", e)))?;

    // Match Rust use statements (with multiline mode)
    let re = Regex::new(r"(?m)^use\s+([^;]+);")
        .map_err(|e| ToolError::InvalidArguments(format!("Invalid regex: {}", e)))?;

    let imports: Vec<_> = re
        .captures_iter(&content)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str().trim().to_string())
        .collect();

    if imports.is_empty() {
        return Ok(format!("No imports found in {}", path.display()));
    }

    Ok(format!(
        "Imports in {} ({} found):\n\n{}",
        path.display(),
        imports.len(),
        imports.join("\n")
    ))
}

/// Extract imports from a Python file
pub fn find_imports_python(path: &Path) -> Result<String, ToolError> {
    if !path.exists() {
        return Err(ToolError::FileNotFound(path.display().to_string()));
    }

    let content = fs::read_to_string(path)
        .map_err(|e| ToolError::PermissionDenied(format!("Cannot read file: {}", e)))?;

    let mut imports = Vec::new();

    // Match Python import statements
    let import_re = Regex::new(r"^import\s+(.+)")
        .map_err(|e| ToolError::InvalidArguments(format!("Invalid regex: {}", e)))?;
    let from_re = Regex::new(r"^from\s+(\S+)\s+import\s+(.+)")
        .map_err(|e| ToolError::InvalidArguments(format!("Invalid regex: {}", e)))?;

    for line in content.lines() {
        if let Some(cap) = import_re.captures(line) {
            if let Some(module) = cap.get(1) {
                imports.push(format!("import {}", module.as_str().trim()));
            }
        } else if let Some(cap) = from_re.captures(line) {
            if let (Some(module), Some(items)) = (cap.get(1), cap.get(2)) {
                imports.push(format!(
                    "from {} import {}",
                    module.as_str().trim(),
                    items.as_str().trim()
                ));
            }
        }
    }

    if imports.is_empty() {
        return Ok(format!("No imports found in {}", path.display()));
    }

    Ok(format!(
        "Imports in {} ({} found):\n\n{}",
        path.display(),
        imports.len(),
        imports.join("\n")
    ))
}

/// Generic function extractor (auto-detects language)
pub fn extract_functions(path: &Path) -> Result<String, ToolError> {
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match extension {
        "rs" => extract_functions_rust(path),
        "py" => extract_functions_python(path),
        _ => Err(ToolError::InvalidPath(format!(
            "Unsupported file type: {}",
            extension
        ))),
    }
}

/// Generic import finder (auto-detects language)
pub fn find_imports(path: &Path) -> Result<String, ToolError> {
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match extension {
        "rs" => find_imports_rust(path),
        "py" => find_imports_python(path),
        _ => Err(ToolError::InvalidPath(format!(
            "Unsupported file type: {}",
            extension
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_extract_functions_rust() {
        let file = NamedTempFile::new().unwrap();
        let content = r#"
pub fn public_func() {}
fn private_func() {}
pub async fn async_func() {}
"#;
        fs::write(file.path(), content).unwrap();

        let result = extract_functions_rust(file.path());
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("public_func"));
        assert!(output.contains("private_func"));
        assert!(output.contains("async_func"));
    }

    #[test]
    fn test_extract_functions_python() {
        let file = NamedTempFile::new().unwrap();
        let content = r#"
def regular_func():
    pass

async def async_func():
    pass
"#;
        fs::write(file.path(), content).unwrap();

        let result = extract_functions_python(file.path());
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("regular_func"));
        assert!(output.contains("async_func"));
    }

    #[test]
    fn test_find_imports_rust() {
        let file = NamedTempFile::new().unwrap();
        let content = r#"
use std::io;
use std::collections::HashMap;
use crate::module::Item;
"#;
        fs::write(file.path(), content).unwrap();

        let result = find_imports_rust(file.path());
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("std::io"));
        assert!(output.contains("std::collections::HashMap"));
        assert!(output.contains("crate::module::Item"));
    }

    #[test]
    fn test_find_imports_python() {
        let file = NamedTempFile::new().unwrap();
        let content = r#"
import os
import sys
from pathlib import Path
from typing import List, Dict
"#;
        fs::write(file.path(), content).unwrap();

        let result = find_imports_python(file.path());
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("import os"));
        assert!(output.contains("from pathlib import Path"));
    }

    #[test]
    fn test_extract_functions_not_found() {
        let result = extract_functions(&Path::new("/nonexistent/file.rs"));
        assert!(matches!(result, Err(ToolError::FileNotFound(_))));
    }

    #[test]
    fn test_extract_functions_unsupported() {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), "content").unwrap();

        // Change extension to unsupported
        let unsupported_path = file.path().with_extension("xyz");
        let result = extract_functions(&unsupported_path);
        assert!(matches!(result, Err(ToolError::InvalidPath(_))));
    }

    #[test]
    fn test_extract_functions_no_functions() {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), "// No functions here\nlet x = 5;").unwrap();

        let result = extract_functions_rust(file.path());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("No functions found"));
    }

    #[test]
    fn test_find_imports_no_imports() {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), "fn main() {}").unwrap();

        let result = find_imports_rust(file.path());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("No imports found"));
    }
}
