//! Web URL fetching operations

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(dead_code)]

use crate::types::error::ToolError;

/// Fetch content from a URL
pub fn fetch_url(url: &str) -> Result<String, ToolError> {
    // Validate URL format
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(ToolError::InvalidArguments(
            "URL must start with http:// or https://".to_string(),
        ));
    }

    // Use reqwest blocking client for simplicity
    // In a real async application, you'd use the async client
    let response = reqwest::blocking::get(url)
        .map_err(|e| ToolError::CommandFailed(format!("Failed to fetch URL: {}", e)))?;

    if !response.status().is_success() {
        return Err(ToolError::CommandFailed(format!(
            "HTTP request failed with status: {}",
            response.status()
        )));
    }

    let content = response
        .text()
        .map_err(|e| ToolError::CommandFailed(format!("Failed to read response: {}", e)))?;

    Ok(format!(
        "Content from {} ({} bytes):\n\n{}",
        url,
        content.len(),
        truncate_content(&content, 5000)
    ))
}

/// Fetch URL and return only headers
pub fn fetch_url_headers(url: &str) -> Result<String, ToolError> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(ToolError::InvalidArguments(
            "URL must start with http:// or https://".to_string(),
        ));
    }

    let client = reqwest::blocking::Client::new();
    let response = client
        .head(url)
        .send()
        .map_err(|e| ToolError::CommandFailed(format!("Failed to fetch URL headers: {}", e)))?;

    let mut headers_text = String::new();
    headers_text.push_str(&format!("Headers for {}:\n\n", url));
    headers_text.push_str(&format!("Status: {}\n", response.status()));

    for (name, value) in response.headers() {
        headers_text.push_str(&format!(
            "{}: {}\n",
            name,
            value.to_str().unwrap_or("<invalid>")
        ));
    }

    Ok(headers_text)
}

/// Fetch URL with custom timeout
pub fn fetch_url_with_timeout(url: &str, timeout_secs: u64) -> Result<String, ToolError> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(ToolError::InvalidArguments(
            "URL must start with http:// or https://".to_string(),
        ));
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| ToolError::CommandFailed(format!("Failed to create HTTP client: {}", e)))?;

    let response = client
        .get(url)
        .send()
        .map_err(|e| ToolError::CommandFailed(format!("Failed to fetch URL: {}", e)))?;

    if !response.status().is_success() {
        return Err(ToolError::CommandFailed(format!(
            "HTTP request failed with status: {}",
            response.status()
        )));
    }

    let content = response
        .text()
        .map_err(|e| ToolError::CommandFailed(format!("Failed to read response: {}", e)))?;

    Ok(format!(
        "Content from {} ({} bytes):\n\n{}",
        url,
        content.len(),
        truncate_content(&content, 5000)
    ))
}

/// Download file from URL
pub fn download_file(url: &str, output_path: &std::path::Path) -> Result<String, ToolError> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(ToolError::InvalidArguments(
            "URL must start with http:// or https://".to_string(),
        ));
    }

    let response = reqwest::blocking::get(url)
        .map_err(|e| ToolError::CommandFailed(format!("Failed to fetch URL: {}", e)))?;

    if !response.status().is_success() {
        return Err(ToolError::CommandFailed(format!(
            "HTTP request failed with status: {}",
            response.status()
        )));
    }

    let content = response
        .bytes()
        .map_err(|e| ToolError::CommandFailed(format!("Failed to read response: {}", e)))?;

    std::fs::write(output_path, &content)
        .map_err(|e| ToolError::PermissionDenied(format!("Failed to write file: {}", e)))?;

    Ok(format!(
        "Downloaded {} ({} bytes) to {}",
        url,
        content.len(),
        output_path.display()
    ))
}

/// Truncate content to max length
fn truncate_content(content: &str, max_len: usize) -> &str {
    if content.len() <= max_len {
        content
    } else {
        &content[..max_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_fetch_url_invalid_format() {
        let result = fetch_url("not-a-url");
        assert!(matches!(result, Err(ToolError::InvalidArguments(_))));
    }

    #[test]
    fn test_fetch_url_invalid_format_ftp() {
        let result = fetch_url("ftp://example.com");
        assert!(matches!(result, Err(ToolError::InvalidArguments(_))));
    }

    #[test]
    fn test_fetch_url_headers_invalid() {
        let result = fetch_url_headers("not-a-url");
        assert!(matches!(result, Err(ToolError::InvalidArguments(_))));
    }

    #[test]
    fn test_fetch_url_with_timeout_invalid() {
        let result = fetch_url_with_timeout("invalid", 10);
        assert!(matches!(result, Err(ToolError::InvalidArguments(_))));
    }

    #[test]
    fn test_download_file_invalid() {
        let result = download_file("invalid", &std::path::Path::new("/tmp/test"));
        assert!(matches!(result, Err(ToolError::InvalidArguments(_))));
    }

    #[test]
    fn test_truncate_content() {
        assert_eq!(truncate_content("short", 10), "short");
        assert_eq!(truncate_content("hello world", 5), "hello");
        assert_eq!(truncate_content("test", 100), "test");
    }

    // Integration test - requires network
    #[test]
    #[ignore] // Requires network access
    fn test_fetch_url_real() {
        // This would test against a real URL
        // let result = fetch_url("https://httpbin.org/get");
        // assert!(result.is_ok());
    }

    // Integration test - requires network
    #[test]
    #[ignore] // Requires network access
    fn test_download_file_real() {
        let dir = tempdir().unwrap();
        let _output_path = dir.path().join("test.txt");

        // This would test against a real URL
        // let result = download_file("https://httpbin.org/bytes/100", &output_path);
        // assert!(result.is_ok());
        // assert!(output_path.exists());
    }
}
