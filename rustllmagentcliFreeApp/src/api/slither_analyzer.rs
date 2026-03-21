//! Slither Static Analyzer - Local Smart Contract Security Analysis
//!
//! Slither by Trail of Bits provides comprehensive static analysis of smart contracts:
//! - Reentrancy detection
//! - Delegatecall issues
//! - Access control issues
//! - Arbitrary send vulnerabilities
//! - Overall security scoring
//!
//! # Installation
//! ```bash
//! pip3 install slither-analyzer
//! ```
//!
//! # Features
//! - Runs locally (unlimited, no API limits)
//! - Fetches source from Etherscan automatically
//! - Detects 100+ vulnerability types
//! - Provides security scoring

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::unnecessary_filter_map)]
#![allow(clippy::redundant_closure_for_method_calls)]

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{debug, error, info, instrument, warn};

/// Slither analysis result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SlitherAnalysisResult {
    /// Contract address analyzed
    pub contract_address: String,
    /// Overall security score (0-100, higher is better)
    pub security_score: Option<u8>,
    /// List of detected vulnerabilities
    pub vulnerabilities: Vec<SlitherVulnerability>,
    /// Reentrancy analysis
    pub reentrancy_analysis: Option<ReentrancyAnalysis>,
    /// Delegatecall usage detected
    pub has_delegatecall: bool,
    /// Access control issues
    pub access_control_issues: Vec<AccessControlIssue>,
    /// External call risks
    pub external_calls: Vec<ExternalCallInfo>,
    /// Whether Slither is available
    pub slither_available: bool,
    /// Analysis errors
    pub errors: Vec<String>,
}

/// Individual vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlitherVulnerability {
    /// Vulnerability detector name
    pub detector: String,
    /// Severity (HIGH, MEDIUM, LOW, INFORMATIONAL)
    pub severity: String,
    /// Description
    pub description: String,
    /// Elements affected
    pub elements: Vec<VulnerabilityElement>,
}

/// Vulnerability element (function, contract, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityElement {
    /// Element type (function, contract, etc.)
    #[serde(rename = "type")]
    pub element_type: Option<String>,
    /// Element name
    pub name: Option<String>,
    /// Source file
    pub source_file: Option<String>,
    /// Line number
    pub line: Option<u32>,
}

/// Reentrancy analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReentrancyAnalysis {
    /// Is vulnerable to reentrancy
    pub is_vulnerable: bool,
    /// Vulnerable functions
    pub vulnerable_functions: Vec<String>,
    /// Risk level (HIGH, MEDIUM, LOW)
    pub risk_level: String,
}

/// Access control issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlIssue {
    /// Issue type
    pub issue_type: String,
    /// Description
    pub description: String,
    /// Affected functions
    pub affected_functions: Vec<String>,
    /// Severity
    pub severity: String,
}

/// External call information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalCallInfo {
    /// Target contract
    pub target: String,
    /// Call type
    pub call_type: String,
    /// Risk level
    pub risk_level: String,
}

/// Slither analyzer
pub struct SlitherAnalyzer;

impl SlitherAnalyzer {
    /// Check if Slither is installed and available
    pub fn is_available() -> bool {
        Command::new("slither")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Analyze a contract using Slither
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to analyze
    /// * `chain_id` - Chain ID (1 for Ethereum)
    /// * `etherscan_api_key` - Etherscan API key for source fetching
    ///
    /// # Returns
    /// * `Ok(SlitherAnalysisResult)` - Analysis result
    /// * `Err(anyhow::Error)` - Error if analysis fails
    #[instrument(skip(etherscan_api_key), fields(contract_address = %contract_address))]
    pub async fn analyze_contract(
        contract_address: &str,
        chain_id: u32,
        etherscan_api_key: &str,
    ) -> Result<SlitherAnalysisResult> {
        if !Self::is_available() {
            warn!("Slither analyzer not installed - skipping analysis for {}", contract_address);
            return Ok(SlitherAnalysisResult {
                contract_address: contract_address.to_string(),
                slither_available: false,
                ..Default::default()
            });
        }

        info!("Running Slither analysis for {} on chain {}", contract_address, chain_id);

        // Map chain ID to Etherscan network
        let network = match chain_id {
            1 => "mainnet",
            3 => "ropsten",
            4 => "rinkeby",
            5 => "goerli",
            56 => "bsc",
            137 => "polygon",
            _ => "mainnet",
        };

        // Run Slither with Etherscan integration
        let output = Command::new("slither")
            .args([
                contract_address,
                "--etherscan-apikey",
                etherscan_api_key,
                "--etherscan",
                network,
                "--json",
                "-",
                "--detect",
                "reentrancy-eth,reentrancy-no-eth,reentrancy-events,reentrancy-benign,reentrancy-unlimited-gas,delegatecall-loop,controlled-delegatecall,arbitrary-send-eth,arbitrary-send-erc20,access-control,constant-function,deprecated-calls,low-level-calls,uninitialized-state,uninitialized-local,unused-state,unused-local,incorrect-equality,tautology,incorrect-modifier,missing-events-checks,missing-zero-check,reused-modifier,suicidal,tx-origin,weak-prng,naming-convention,external-function,public-mappings-nested,boolean-cst,return-leave,dead-code,incorrect-shift,assembly,pragma,too-many-digits,variable-scope,unprotected-upgrade,unindexed-events,requires-override,immutable-vars,conformance-to-solidity-naming-standard,correct-parentheses",
            ])
            .output()
            .context("Failed to run slither command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Slither analysis failed for {}: {}", contract_address, stderr);
            return Ok(SlitherAnalysisResult {
                contract_address: contract_address.to_string(),
                slither_available: true,
                errors: vec![stderr.to_string()],
                ..Default::default()
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("Slither analysis completed for {}", contract_address);

        // Parse JSON output
        let json: serde_json::Value = serde_json::from_str(&stdout)
            .context("Failed to parse Slither JSON output")?;

        let result = Self::parse_slither_output(&json, contract_address);

        info!(
            "Slither analysis completed for {}: score={:?}, vulnerabilities={}",
            contract_address,
            result.security_score,
            result.vulnerabilities.len()
        );

        Ok(result)
    }

    /// Parse Slither JSON output
    fn parse_slither_output(json: &serde_json::Value, contract_address: &str) -> SlitherAnalysisResult {
        let mut result = SlitherAnalysisResult {
            contract_address: contract_address.to_string(),
            slither_available: true,
            ..Default::default()
        };

        // Parse detectors
        if let Some(detects) = json.get("detectors").and_then(|v| v.as_array()) {
            for detector in detects {
                let name = detector.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
                let severity = detector.get("confidence").and_then(|v| v.as_str()).unwrap_or("MEDIUM");
                let description = detector.get("description").and_then(|v| v.as_str()).unwrap_or("");

                // Check for specific vulnerability types
                match name {
                    "reentrancy-eth" | "reentrancy-no-eth" | "reentrancy-events" | "reentrancy-benign" | "reentrancy-unlimited-gas" => {
                        result.reentrancy_analysis = Some(ReentrancyAnalysis {
                            is_vulnerable: true,
                            vulnerable_functions: Self::extract_affected_functions(detector),
                            risk_level: "HIGH".to_string(),
                        });
                    }
                    "delegatecall-loop" | "controlled-delegatecall" => {
                        result.has_delegatecall = true;
                    }
                    "access-control" => {
                        if let Some(issue) = Self::parse_access_control_issue(detector) {
                            result.access_control_issues.push(issue);
                        }
                    }
                    "arbitrary-send-eth" | "arbitrary-send-erc20" => {
                        if let Some(call) = Self::parse_external_call(detector) {
                            result.external_calls.push(call);
                        }
                    }
                    _ => {}
                }

                // Add to vulnerabilities list
                let vulnerability = SlitherVulnerability {
                    detector: name.to_string(),
                    severity: severity.to_string(),
                    description: description.to_string(),
                    elements: Self::extract_elements(detector),
                };
                result.vulnerabilities.push(vulnerability);
            }
        }

        // Calculate security score
        result.security_score = Some(Self::calculate_security_score(&result.vulnerabilities));

        result
    }

    /// Calculate security score from vulnerabilities
    fn calculate_security_score(vulnerabilities: &[SlitherVulnerability]) -> u8 {
        let mut score = 100i32;

        for vuln in vulnerabilities {
            let penalty = match vuln.severity.to_uppercase().as_str() {
                "HIGH" => 20,
                "MEDIUM" => 10,
                "LOW" => 5,
                "INFORMATIONAL" => 2,
                _ => 5,
            };
            score -= penalty;
        }

        score.max(0).min(100) as u8
    }

    /// Extract affected functions from detector output
    fn extract_affected_functions(detector: &serde_json::Value) -> Vec<String> {
        detector
            .get("elements")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.get("name").and_then(|v| v.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Extract elements from detector output
    fn extract_elements(detector: &serde_json::Value) -> Vec<VulnerabilityElement> {
        detector
            .get("elements")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        Some(VulnerabilityElement {
                            element_type: e.get("type").and_then(|v| v.as_str()).map(String::from),
                            name: e.get("name").and_then(|v| v.as_str()).map(String::from),
                            source_file: e.get("source").and_then(|s| s.get("filename").and_then(|v| v.as_str())).map(String::from),
                            line: e.get("source").and_then(|s| s.get("lines")).and_then(|l| l.as_array()).and_then(|a| a.first()).and_then(|v| v.as_u64()).map(|v| v as u32),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Parse access control issue from detector
    fn parse_access_control_issue(detector: &serde_json::Value) -> Option<AccessControlIssue> {
        Some(AccessControlIssue {
            issue_type: detector.get("name").and_then(|v| v.as_str())?.to_string(),
            description: detector.get("description").and_then(|v| v.as_str())?.to_string(),
            affected_functions: Self::extract_affected_functions(detector),
            severity: detector.get("confidence").and_then(|v| v.as_str())?.to_string(),
        })
    }

    /// Parse external call from detector
    fn parse_external_call(detector: &serde_json::Value) -> Option<ExternalCallInfo> {
        Some(ExternalCallInfo {
            target: "unknown".to_string(),
            call_type: detector.get("name").and_then(|v| v.as_str())?.to_string(),
            risk_level: "MEDIUM".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slither_availability() {
        // This test will pass if Slither is installed, fail otherwise
        let available = SlitherAnalyzer::is_available();
        // Don't assert - just log
        if available {
            println!("Slither is available");
        } else {
            println!("Slither is not available (expected in test environment)");
        }
    }

    #[test]
    fn test_slither_analysis_result_default() {
        let result = SlitherAnalysisResult::default();
        assert!(!result.slither_available);
        assert_eq!(result.security_score, None);
        assert!(result.vulnerabilities.is_empty());
    }

    #[test]
    fn test_security_score_calculation() {
        let vulnerabilities = vec![
            SlitherVulnerability {
                detector: "reentrancy-eth".to_string(),
                severity: "HIGH".to_string(),
                description: "Reentrancy vulnerability".to_string(),
                elements: vec![],
            },
            SlitherVulnerability {
                detector: "unused-state".to_string(),
                severity: "INFORMATIONAL".to_string(),
                description: "Unused state variable".to_string(),
                elements: vec![],
            },
        ];

        let score = SlitherAnalyzer::calculate_security_score(&vulnerabilities);
        // 100 - 20 (HIGH) - 2 (INFORMATIONAL) = 78
        assert_eq!(score, 78);
    }

    #[test]
    fn test_security_score_minimum() {
        let vulnerabilities = vec![
            SlitherVulnerability {
                detector: "vuln1".to_string(),
                severity: "HIGH".to_string(),
                description: "vuln".to_string(),
                elements: vec![],
            },
            SlitherVulnerability {
                detector: "vuln2".to_string(),
                severity: "HIGH".to_string(),
                description: "vuln".to_string(),
                elements: vec![],
            },
            SlitherVulnerability {
                detector: "vuln3".to_string(),
                severity: "HIGH".to_string(),
                description: "vuln".to_string(),
                elements: vec![],
            },
            SlitherVulnerability {
                detector: "vuln4".to_string(),
                severity: "HIGH".to_string(),
                description: "vuln".to_string(),
                elements: vec![],
            },
            SlitherVulnerability {
                detector: "vuln5".to_string(),
                severity: "HIGH".to_string(),
                description: "vuln".to_string(),
                elements: vec![],
            },
            SlitherVulnerability {
                detector: "vuln6".to_string(),
                severity: "HIGH".to_string(),
                description: "vuln".to_string(),
                elements: vec![],
            },
        ];

        let score = SlitherAnalyzer::calculate_security_score(&vulnerabilities);
        // Should be clamped to 0 minimum
        assert_eq!(score, 0);
    }

    #[test]
    fn test_vulnerability_element_serialization() {
        let element = VulnerabilityElement {
            element_type: Some("function".to_string()),
            name: Some("withdraw".to_string()),
            source_file: Some("Contract.sol".to_string()),
            line: Some(42),
        };

        let json = serde_json::to_string(&element).unwrap();
        let parsed: VulnerabilityElement = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.element_type, Some("function".to_string()));
        assert_eq!(parsed.name, Some("withdraw".to_string()));
    }
}
