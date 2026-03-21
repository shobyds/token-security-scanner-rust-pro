//! JSON Report Generator

#![allow(clippy::must_use_candidate)]
#![allow(clippy::unnecessary_debug_formatting)]

use anyhow::Context;
use serde_json;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::info;

use super::{ReportGenerator, TokenSecurityReport};

/// JSON report generator
pub struct JsonReportGenerator;

impl Default for JsonReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonReportGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate and save JSON report to organized directory structure
    ///
    /// # Arguments
    /// * `report` - The security report to save
    /// * `reports_dir` - The reports subdirectory in the organized structure
    ///
    /// # Returns
    /// * `Ok(PathBuf)` - Path to saved report
    /// * `Err(anyhow::Error)` - Error saving report
    pub fn save_to_organized_dir(
        &self,
        report: &TokenSecurityReport,
        reports_dir: &Path,
    ) -> Result<PathBuf, anyhow::Error> {
        fs::create_dir_all(reports_dir).context(format!(
            "Failed to create reports directory: {reports_dir:?}"
        ))?;

        let file_path = reports_dir.join("token_report.json");

        let json =
            serde_json::to_string_pretty(report).context("Failed to serialize report to JSON")?;

        let mut file = fs::File::create(&file_path)
            .context(format!("Failed to create report file: {file_path:?}"))?;

        file.write_all(json.as_bytes())
            .context("Failed to write JSON report")?;

        info!("JSON report generated (organized): {:?}", file_path);
        Ok(file_path)
    }
}

impl ReportGenerator for JsonReportGenerator {
    fn generate_report(
        &self,
        report: &TokenSecurityReport,
        output_dir: &Path,
    ) -> Result<PathBuf, anyhow::Error> {
        fs::create_dir_all(output_dir).context(format!(
            "Failed to create output directory: {output_dir:?}"
        ))?;

        let filename = format!(
            "token_report_{}_{}.json",
            &report.token_data.token_address[..10],
            chrono::Utc::now().format("%Y%m%d_%H%M%S")
        );

        let file_path = output_dir.join(&filename);

        let json =
            serde_json::to_string_pretty(report).context("Failed to serialize report to JSON")?;

        let mut file = fs::File::create(&file_path)
            .context(format!("Failed to create report file: {file_path:?}"))?;

        file.write_all(json.as_bytes())
            .context("Failed to write JSON report")?;

        info!("JSON report generated: {:?}", file_path);
        Ok(file_path)
    }

    fn file_extension(&self) -> &'static str {
        "json"
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ReportMetadata, RiskAssessment, RiskFactor, RiskLevel};
    use super::*;
    use crate::api::{ScanResult, TimingBreakdown};
    use crate::models::TokenData;

    #[test]
    fn test_json_report_generator() {
        let generator = JsonReportGenerator::new();
        assert_eq!(generator.file_extension(), "json");
    }
}
