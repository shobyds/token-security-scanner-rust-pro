//! Report Directory Manager for Organized Scan Storage
//!
//! This module provides directory management functionality for organizing
//! token scan reports in a structured hierarchy suitable for LLM analysis.

#![allow(clippy::module_name_repetitions)]

use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

/// Manages organized report directory structure
pub struct ReportDirectoryManager {
    /// Base reports directory
    pub base_dir: PathBuf,
}

/// Represents a token scan directory structure
pub struct TokenScanDirectory {
    /// Full path to the scan directory
    pub scan_dir: PathBuf,
    /// Path to JSON subdirectory
    pub json_dir: PathBuf,
    /// Path to reports subdirectory
    pub reports_dir: PathBuf,
    /// Relative path from base (for manifest)
    pub relative_path: String,
    /// Token name (e.g., "Uniswap")
    pub token_name: Option<String>,
    /// Token symbol (e.g., "UNI")
    pub token_symbol: Option<String>,
}

impl ReportDirectoryManager {
    /// Create a new directory manager
    #[must_use]
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Create from default reports directory
    #[must_use]
    pub fn from_default() -> Self {
        Self {
            base_dir: PathBuf::from("/home/serverhp/qwenAg/reports"),
        }
    }

    /// Generate directory structure for a token scan
    ///
    /// # Directory Structure
    /// ```text
    /// reports/
    /// └── {token_name}/
    ///     └── {dd_mm_yyyy_hh_mm}/
    ///         ├── json/
    ///         └── reports/
    /// ```
    ///
    /// # Arguments
    /// * `scan_result` - The scan result containing token data
    ///
    /// # Returns
    /// * `Ok(TokenScanDirectory)` - Created directory structure
    /// * `Err(std::io::Error)` - Directory creation failed
    pub fn create_scan_directory(
        &self,
        scan_result: &crate::api::ScanResult,
    ) -> std::io::Result<TokenScanDirectory> {
        // Token name and symbol would come from Dexscreener or other source
        // For now, use None and let manifest handle it
        let token_name: Option<String> = None;
        let token_symbol: Option<String> = None;
        
        // Use token symbol if available, otherwise name, otherwise address prefix
        let dir_name = if let Some(symbol) = &token_symbol {
            format!("{}_{}", symbol, &scan_result.token_address[..10])
        } else if let Some(name) = &token_name {
            format!("{}_{}", name, &scan_result.token_address[..10])
        } else {
            scan_result.token_address[..10].to_string()
        };

        // Format timestamp as dd_mm_yyyy_hh_min
        let timestamp = Utc::now();
        let timestamp_str = timestamp.format("%d_%m_%Y_%H_%M").to_string();

        // Create full directory path
        let scan_dir = self.base_dir.join(&dir_name).join(&timestamp_str);

        // Create directories
        std::fs::create_dir_all(&scan_dir)?;
        std::fs::create_dir_all(scan_dir.join("json"))?;
        std::fs::create_dir_all(scan_dir.join("reports"))?;

        // Calculate relative path for manifest
        let relative_path = format!("{dir_name}/{timestamp_str}");

        let scan_dir_clone = scan_dir.clone();

        Ok(TokenScanDirectory {
            scan_dir,
            json_dir: scan_dir_clone.join("json"),
            reports_dir: scan_dir_clone.join("reports"),
            relative_path,
            token_name,
            token_symbol,
        })
    }

    /// Save API response to JSON file
    ///
    /// # Arguments
    /// * `scan_dir` - Scan directory structure
    /// * `provider` - API provider name
    /// * `data` - JSON response data
    ///
    /// # Returns
    /// * `Ok(PathBuf)` - Path to saved file
    /// * `Err(std::io::Error)` - File write failed
    pub fn save_api_response(
        &self,
        scan_dir: &TokenScanDirectory,
        provider: &str,
        data: &str,
    ) -> std::io::Result<PathBuf> {
        let file_path = scan_dir.json_dir.join(format!("{provider}.json"));
        std::fs::write(&file_path, data)?;
        Ok(file_path)
    }

    /// Save API error to JSON file
    ///
    /// # Arguments
    /// * `scan_dir` - Scan directory structure
    /// * `provider` - API provider name
    /// * `error` - Error message
    ///
    /// # Returns
    /// * `Ok(PathBuf)` - Path to saved error file
    /// * `Err(std::io::Error)` - File write failed
    pub fn save_api_error(
        &self,
        scan_dir: &TokenScanDirectory,
        provider: &str,
        error: &str,
    ) -> std::io::Result<PathBuf> {
        let error_data = serde_json::json!({
            "error": error,
            "provider": provider,
            "timestamp": Utc::now().to_rfc3339(),
            "success": false
        });
        let file_path = scan_dir.json_dir.join(format!("{provider}.json"));
        let json = serde_json::to_string_pretty(&error_data)
            .map_err(std::io::Error::other)?;
        std::fs::write(&file_path, json)?;
        Ok(file_path)
    }

    /// Copy final reports to organized directory
    ///
    /// # Arguments
    /// * `scan_dir` - Scan directory structure
    /// * `json_report_path` - Path to source JSON report
    /// * `html_report_path` - Path to source HTML report
    ///
    /// # Returns
    /// * `Ok((json_path, html_path))` - New report paths
    /// * `Err(std::io::Error)` - File copy failed
    pub fn copy_reports(
        &self,
        scan_dir: &TokenScanDirectory,
        json_report_path: &str,
        html_report_path: &str,
    ) -> std::io::Result<(String, String)> {
        // Read original files
        let json_content = std::fs::read(json_report_path)?;
        let html_content = std::fs::read(html_report_path)?;

        // Write to new locations
        let new_json_path = scan_dir.reports_dir.join("token_report.json");
        let new_html_path = scan_dir.reports_dir.join("token_report.html");

        std::fs::write(&new_json_path, json_content)?;
        std::fs::write(&new_html_path, html_content)?;

        Ok((
            new_json_path.to_string_lossy().to_string(),
            new_html_path.to_string_lossy().to_string(),
        ))
    }

    /// Save scan manifest to file
    ///
    /// # Arguments
    /// * `scan_dir` - Scan directory structure
    /// * `manifest` - Scan manifest to save
    ///
    /// # Returns
    /// * `Ok(PathBuf)` - Path to saved manifest
    /// * `Err(std::io::Error)` - File write failed
    pub fn save_manifest(
        &self,
        scan_dir: &TokenScanDirectory,
        manifest: &crate::report::manifest::ScanManifest,
    ) -> std::io::Result<PathBuf> {
        let manifest_path = scan_dir.scan_dir.join("scan_manifest.json");
        let json = serde_json::to_string_pretty(manifest)
            .map_err(std::io::Error::other)?;
        std::fs::write(&manifest_path, json)?;
        Ok(manifest_path)
    }

    /// Get file size in bytes
    #[must_use]
    pub fn get_file_size(path: &Path) -> Option<u64> {
        std::fs::metadata(path).ok().map(|m| m.len())
    }
}

impl TokenScanDirectory {
    /// Get the scan directory path
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.scan_dir
    }

    /// Get the relative path string
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use crate::api::{ScanResult, TimingBreakdown};
    use crate::models::TokenData;

    #[test]
    fn test_create_scan_directory() {
        let temp_dir = std::env::temp_dir().join("test_reports");
        let manager = ReportDirectoryManager::new(temp_dir.clone());

        // Create a minimal ScanResult for testing
        let scan_result = ScanResult {
            token_address: "0x1234567890123456789012345678901234567890".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: vec![],
        };

        let result = manager.create_scan_directory(&scan_result);

        assert!(result.is_ok());
        let scan_dir = result.unwrap();
        assert!(scan_dir.scan_dir.exists());
        assert!(scan_dir.json_dir.exists());
        assert!(scan_dir.reports_dir.exists());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_save_api_response() {
        let temp_dir = std::env::temp_dir().join("test_reports2");
        let manager = ReportDirectoryManager::new(temp_dir.clone());

        // Create a minimal ScanResult for testing
        let scan_result = ScanResult {
            token_address: "0x1234567890123456789012345678901234567890".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: vec![],
        };

        let scan_dir = manager
            .create_scan_directory(&scan_result)
            .unwrap();

        let result = manager.save_api_response(&scan_dir, "test_api", r#"{"test": "data"}"#);
        assert!(result.is_ok());

        let file_path = scan_dir.json_dir.join("test_api.json");
        assert!(file_path.exists());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_save_api_error() {
        let temp_dir = std::env::temp_dir().join("test_reports3");
        let manager = ReportDirectoryManager::new(temp_dir.clone());

        // Create a minimal ScanResult for testing
        let scan_result = ScanResult {
            token_address: "0x1234567890123456789012345678901234567890".to_string(),
            chain: "ethereum".to_string(),
            scan_time_ms: 100,
            timing_breakdown: TimingBreakdown::default(),
            dexscreener: None,
            honeypot: None,
            goplus: None,
            etherscan: None,
            ethplorer: None,
            moralis_holders: None,
            deployer_profile: None,
            source_code: None,
            total_supply: None,
            dedaub: None,
            transfer_events: None,
            blockscout: None,
            alchemy_simulation: None,
            rpc_simulation: None,
            tenderly: None,
            deployer: None,
            source_analysis: None,
            blacklist_analysis: None,
            honeypot_is: None,
            scammer_detection: None,
            lp_lock: None,
            graph_analytics: None,
            defillama_price: None,
            aggregated: TokenData::default(),
            errors: vec![],
        };

        let scan_dir = manager
            .create_scan_directory(&scan_result)
            .unwrap();

        let result = manager.save_api_error(&scan_dir, "test_api", "Test error message");
        assert!(result.is_ok());

        let file_path = scan_dir.json_dir.join("test_api.json");
        assert!(file_path.exists());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
