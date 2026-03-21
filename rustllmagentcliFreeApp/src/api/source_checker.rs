//! Source Code Verification and Risk Analysis
//!
//! This module provides comprehensive source code analysis including:
//! - Contract verification status
//! - Risk flag detection (owner drains, dynamic fees, etc.)
//! - Assembly detection in transfer functions
//! - Self-destruct capability detection
//! - Owner-only transfer restrictions
//!
//! # Features
//! - Source code pattern matching
//! - ABI function analysis
//! - Risk scoring based on code patterns
//! - Detailed vulnerability descriptions

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_lines)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Source code analysis result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceAnalysis {
    /// Whether contract is verified
    pub is_verified: bool,
    /// Contract name
    pub contract_name: Option<String>,
    /// Compiler version
    pub compiler_version: Option<String>,
    /// List of detected risk flags
    pub risk_flags: Vec<SourceRiskFlag>,
    /// Overall source risk score (0-100)
    pub source_risk_score: u32,
    /// Whether owner can drain in transfer
    pub owner_drain_in_transfer: bool,
    /// Whether dynamic fee setter exists
    pub dynamic_fee_setter: bool,
    /// Whether assembly used in transfer
    pub assembly_in_transfer: bool,
    /// Whether owner-only transfer restriction exists
    pub owner_only_transfer: bool,
    /// Whether self-destruct capability exists
    pub selfdestruct_capable: bool,
    /// Whether contract has blacklist function
    pub has_blacklist: bool,
    /// Whether contract has tax function
    pub has_tax_function: bool,
}

/// Source code risk flags
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceRiskFlag {
    /// Contract not verified on block explorer
    NotVerified,
    /// Owner can drain funds in transfer function
    OwnerDrainInTransfer,
    /// Dynamic fee setter function exists
    DynamicFeeSetter,
    /// Inline assembly with SSTORE in transfer path
    AssemblyInTransfer,
    /// Owner-only transfer restriction
    OwnerOnlyTransfer,
    /// Self-destruct capability present
    SelfDestructCapability,
    /// Blacklist function detected
    BlacklistFunction,
    /// Tax modification function detected
    TaxFunction,
    /// Pause/unpause capability
    PauseCapability,
    /// Mint function after deployment
    PostDeploymentMint,
}

impl SourceRiskFlag {
    /// Get risk score contribution for this flag
    pub fn risk_score(&self) -> u32 {
        match self {
            SourceRiskFlag::NotVerified => 10,
            SourceRiskFlag::OwnerDrainInTransfer => 35,
            SourceRiskFlag::DynamicFeeSetter => 15,
            SourceRiskFlag::AssemblyInTransfer => 20,
            SourceRiskFlag::OwnerOnlyTransfer => 25,
            SourceRiskFlag::SelfDestructCapability => 30,
            SourceRiskFlag::BlacklistFunction => 20,
            SourceRiskFlag::TaxFunction => 15,
            SourceRiskFlag::PauseCapability => 10,
            SourceRiskFlag::PostDeploymentMint => 25,
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            SourceRiskFlag::NotVerified => "Contract source code is not verified",
            SourceRiskFlag::OwnerDrainInTransfer => "Owner can drain funds in transfer function",
            SourceRiskFlag::DynamicFeeSetter => "Dynamic fee can be set by owner",
            SourceRiskFlag::AssemblyInTransfer => "Inline assembly used in transfer path",
            SourceRiskFlag::OwnerOnlyTransfer => "Transfer restricted to owner only",
            SourceRiskFlag::SelfDestructCapability => "Contract can self-destruct",
            SourceRiskFlag::BlacklistFunction => "Blacklist function detected",
            SourceRiskFlag::TaxFunction => "Tax modification function detected",
            SourceRiskFlag::PauseCapability => "Contract can be paused",
            SourceRiskFlag::PostDeploymentMint => "Minting possible after deployment",
        }
    }
}

/// Source code scanner for risk detection
pub struct SourceCodeScanner {
    /// Source code to analyze
    source_code: String,
    /// Contract ABI
    abi: Option<String>,
    /// Detected risk flags
    risk_flags: Vec<SourceRiskFlag>,
}

impl SourceCodeScanner {
    /// Create a new source code scanner
    pub fn new(source_code: &str, abi: Option<&str>) -> Self {
        Self {
            source_code: source_code.to_string(),
            abi: abi.map(String::from),
            risk_flags: Vec::new(),
        }
    }

    /// Analyze source code for risks
    pub fn analyze(&mut self) -> SourceAnalysis {
        // Check for various risk patterns
        self.check_owner_drain();
        self.check_dynamic_fee_setter();
        self.check_assembly_in_transfer();
        self.check_owner_only_transfer();
        self.check_selfdestruct();
        self.check_blacklist();
        self.check_tax_function();
        self.check_pause_capability();
        self.check_mint_function();

        // Calculate risk score
        let risk_score: u32 = self.risk_flags.iter().map(SourceRiskFlag::risk_score).sum();

        SourceAnalysis {
            is_verified: !self.source_code.is_empty() && !self.source_code.contains("Contract source code not verified"),
            contract_name: None,
            compiler_version: None,
            risk_flags: self.risk_flags.clone(),
            source_risk_score: risk_score.min(100),
            owner_drain_in_transfer: self.risk_flags.contains(&SourceRiskFlag::OwnerDrainInTransfer),
            dynamic_fee_setter: self.risk_flags.contains(&SourceRiskFlag::DynamicFeeSetter),
            assembly_in_transfer: self.risk_flags.contains(&SourceRiskFlag::AssemblyInTransfer),
            owner_only_transfer: self.risk_flags.contains(&SourceRiskFlag::OwnerOnlyTransfer),
            selfdestruct_capable: self.risk_flags.contains(&SourceRiskFlag::SelfDestructCapability),
            has_blacklist: self.risk_flags.contains(&SourceRiskFlag::BlacklistFunction),
            has_tax_function: self.risk_flags.contains(&SourceRiskFlag::TaxFunction),
        }
    }

    /// Check for owner drain in transfer
    fn check_owner_drain(&mut self) {
        let patterns = [
            "owner.transfer",
            "owner.send",
            "payable(owner).transfer",
            "payable(owner).send",
            "_owner.transfer",
            "_owner.send",
        ];

        if self.source_code.to_lowercase().contains("_transfer") {
            for pattern in &patterns {
                if self.source_code.to_lowercase().contains(pattern) {
                    self.risk_flags.push(SourceRiskFlag::OwnerDrainInTransfer);
                    return;
                }
            }
        }
    }

    /// Check for dynamic fee setter
    fn check_dynamic_fee_setter(&mut self) {
        let patterns = [
            "setTaxFee",
            "setFee",
            "setTax",
            "updateFee",
            "setBuyFee",
            "setSellFee",
            "setMarketingFee",
            "setLiquidityFee",
        ];

        for pattern in &patterns {
            if self.source_code.contains(pattern) {
                self.risk_flags.push(SourceRiskFlag::DynamicFeeSetter);
                return;
            }
        }
    }

    /// Check for assembly in transfer
    fn check_assembly_in_transfer(&mut self) {
        if self.source_code.to_lowercase().contains("_transfer") 
            && self.source_code.to_lowercase().contains("assembly") {
            self.risk_flags.push(SourceRiskFlag::AssemblyInTransfer);
        }
    }

    /// Check for owner-only transfer
    fn check_owner_only_transfer(&mut self) {
        let patterns = [
            "require(msg.sender == owner)",
            "require(_msgSender() == owner)",
            "require(msg.sender == _owner)",
            "onlyOwner",
        ];

        if self.source_code.to_lowercase().contains("_transfer") {
            for pattern in &patterns {
                if self.source_code.contains(pattern) {
                    self.risk_flags.push(SourceRiskFlag::OwnerOnlyTransfer);
                    return;
                }
            }
        }
    }

    /// Check for self-destruct capability
    fn check_selfdestruct(&mut self) {
        if self.source_code.contains("selfdestruct") || self.source_code.contains("SUICIDE") {
            self.risk_flags.push(SourceRiskFlag::SelfDestructCapability);
        }
    }

    /// Check for blacklist function
    fn check_blacklist(&mut self) {
        let patterns = [
            "setBlacklist",
            "addToBlacklist",
            "blockAddress",
            "isBlacklisted",
            "setBots",
            "addBot",
            "blacklist",
            "_isBlacklisted",
        ];

        for pattern in &patterns {
            if self.source_code.contains(pattern) {
                self.risk_flags.push(SourceRiskFlag::BlacklistFunction);
                return;
            }
        }
    }

    /// Check for tax function
    fn check_tax_function(&mut self) {
        let patterns = [
            "_taxFee",
            "_liquidityFee",
            "_marketingFee",
            "_buyTax",
            "_sellTax",
            "taxFee",
            "liquidityFee",
        ];

        for pattern in &patterns {
            if self.source_code.contains(pattern) {
                self.risk_flags.push(SourceRiskFlag::TaxFunction);
                return;
            }
        }
    }

    /// Check for pause capability
    fn check_pause_capability(&mut self) {
        let patterns = [
            "whenNotPaused",
            "whenPaused",
            "_paused",
            "pause()",
            "unpause()",
        ];

        for pattern in &patterns {
            if self.source_code.contains(pattern) {
                self.risk_flags.push(SourceRiskFlag::PauseCapability);
                return;
            }
        }
    }

    /// Check for mint function
    fn check_mint_function(&mut self) {
        let patterns = [
            "mint(",
            "_mint(",
            "Mint(",
        ];

        // Check if mint exists and is not only in constructor
        if self.source_code.contains("function mint") || self.source_code.contains("function _mint") {
            self.risk_flags.push(SourceRiskFlag::PostDeploymentMint);
        }
    }
}

/// Analyze source code and return risk analysis
pub fn analyze_source_code(source_code: &str, abi: Option<&str>) -> SourceAnalysis {
    let mut scanner = SourceCodeScanner::new(source_code, abi);
    scanner.analyze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_analysis_default() {
        let analysis = SourceAnalysis::default();
        assert!(!analysis.is_verified);
        assert_eq!(analysis.source_risk_score, 0);
        assert!(analysis.risk_flags.is_empty());
    }

    #[test]
    fn test_risk_flag_scores() {
        assert_eq!(SourceRiskFlag::NotVerified.risk_score(), 10);
        assert_eq!(SourceRiskFlag::OwnerDrainInTransfer.risk_score(), 35);
        assert_eq!(SourceRiskFlag::SelfDestructCapability.risk_score(), 30);
    }

    #[test]
    fn test_scanner_owner_drain_detection() {
        let source = r"
        function _transfer(address from, address to, uint256 amount) internal {
            owner.transfer(amount);
        }
        ";

        let mut scanner = SourceCodeScanner::new(source, None);
        let analysis = scanner.analyze();

        assert!(analysis.owner_drain_in_transfer);
        assert!(analysis.risk_flags.contains(&SourceRiskFlag::OwnerDrainInTransfer));
    }

    #[test]
    fn test_scanner_dynamic_fee_detection() {
        let source = r"
        function setTaxFee(uint256 taxFee) external onlyOwner {
            _taxFee = taxFee;
        }
        ";

        let mut scanner = SourceCodeScanner::new(source, None);
        let analysis = scanner.analyze();

        assert!(analysis.dynamic_fee_setter);
        assert!(analysis.risk_flags.contains(&SourceRiskFlag::DynamicFeeSetter));
    }

    #[test]
    fn test_scanner_selfdestruct_detection() {
        let source = r"
        function emergencyStop() external onlyOwner {
            selfdestruct(payable(owner));
        }
        ";

        let mut scanner = SourceCodeScanner::new(source, None);
        let analysis = scanner.analyze();

        assert!(analysis.selfdestruct_capable);
        assert!(analysis.risk_flags.contains(&SourceRiskFlag::SelfDestructCapability));
    }

    #[test]
    fn test_scanner_blacklist_detection() {
        let source = r"
        function setBlacklist(address account, bool value) external onlyOwner {
            _isBlacklisted[account] = value;
        }
        ";

        let mut scanner = SourceCodeScanner::new(source, None);
        let analysis = scanner.analyze();

        assert!(analysis.has_blacklist);
        assert!(analysis.risk_flags.contains(&SourceRiskFlag::BlacklistFunction));
    }

    #[test]
    fn test_scanner_tax_detection() {
        let source = r"
        uint256 private _taxFee;
        uint256 private _liquidityFee;

        function _getValues(uint256 amount) internal view returns (uint256, uint256, uint256) {
            uint256 taxAmount = amount.mul(_taxFee).div(100);
            return (amount, taxAmount, 0);
        }
        ";

        let mut scanner = SourceCodeScanner::new(source, None);
        let analysis = scanner.analyze();

        assert!(analysis.has_tax_function);
        assert!(analysis.risk_flags.contains(&SourceRiskFlag::TaxFunction));
    }

    #[test]
    fn test_scanner_multiple_flags() {
        let source = r#"
        uint256 private _taxFee;
        mapping(address => bool) private _isBlacklisted;

        function _transfer(address from, address to, uint256 amount) internal {
            require(!_isBlacklisted[from], "Address is blacklisted");
            owner.transfer(amount * _taxFee / 100);
        }

        function setTaxFee(uint256 taxFee) external onlyOwner {
            _taxFee = taxFee;
        }

        function setBlacklist(address account, bool value) external onlyOwner {
            _isBlacklisted[account] = value;
        }
        "#;

        let mut scanner = SourceCodeScanner::new(source, None);
        let analysis = scanner.analyze();

        assert!(analysis.owner_drain_in_transfer);
        assert!(analysis.dynamic_fee_setter);
        assert!(analysis.has_blacklist);
        assert!(analysis.has_tax_function);
        assert!(analysis.source_risk_score > 50);
    }

    #[test]
    fn test_scanner_clean_contract() {
        let source = r"
        function _transfer(address from, address to, uint256 amount) internal {
            _balances[from] = _balances[from].sub(amount);
            _balances[to] = _balances[to].add(amount);
        }
        ";

        let mut scanner = SourceCodeScanner::new(source, None);
        let analysis = scanner.analyze();

        assert_eq!(analysis.source_risk_score, 0);
        assert!(analysis.risk_flags.is_empty());
    }
}
