//! Source Code Analyzer for Solidity smart contracts
//!
//! This module scans verified Solidity source code for dangerous patterns
//! that could indicate rug pull mechanisms or malicious functionality.

#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};

/// Source code risk analysis result
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceRisk {
    /// Risk score (0-100)
    pub risk_score: u32,
    /// List of detected risk flags
    pub flags: Vec<SourceRiskFlag>,
}

/// Source code risk flag types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceRiskFlag {
    /// Contract source code not verified
    NotVerified,
    /// Owner can drain ETH in transfer function
    OwnerDrainInTransfer,
    /// Dynamic fee setter function exists
    DynamicFeeSetter,
    /// Assembly with sstore in transfer path
    AssemblyInTransfer,
    /// Owner-only transfer restriction
    OwnerOnlyTransfer,
    /// Selfdestruct function present
    SelfDestructPresent,
    /// Trading pause function exists
    TransferPauseFunction,
    /// Router changeable by owner
    RouterChangeableByOwner,
    /// Hidden minter address
    HiddenMinterAddress,
}

impl SourceRiskFlag {
    /// Get string representation of the flag
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotVerified => "Source code not verified",
            Self::OwnerDrainInTransfer => "Owner can drain ETH in transfer",
            Self::DynamicFeeSetter => "Dynamic fee setter function",
            Self::AssemblyInTransfer => "Assembly with sstore in transfer",
            Self::OwnerOnlyTransfer => "Owner-only transfer restriction",
            Self::SelfDestructPresent => "Selfdestruct function present",
            Self::TransferPauseFunction => "Trading pause function exists",
            Self::RouterChangeableByOwner => "Router changeable by owner",
            Self::HiddenMinterAddress => "Hidden minter address",
        }
    }
}

/// Analyze Solidity source code for dangerous patterns
///
/// # Arguments
/// * `source` - Solidity source code (None if unverified)
///
/// # Returns
/// * `SourceRisk` - Risk analysis result with score and flags
#[must_use]
pub fn analyze_source(source: Option<&str>) -> SourceRisk {
    let mut risk = 0u32;
    let mut flags = Vec::new();

    let src = match source {
        Some(s) if !s.is_empty() => s,
        _ => {
            flags.push(SourceRiskFlag::NotVerified);
            return SourceRisk { risk_score: 10, flags };
        }
    };

    let src_lower = src.to_lowercase();

    // 1. Owner drain: sending ETH to owner inside _transfer
    if (src_lower.contains("payable(owner).transfer")
        || src_lower.contains("owner.transfer("))
        && src_lower.contains("_transfer")
    {
        flags.push(SourceRiskFlag::OwnerDrainInTransfer);
        risk += 35;
    }

    // 2. Dynamic fee setter
    let fee_setters = [
        "settaxfee",
        "setfee(",
        "settax(",
        "updatetax(",
        "setsellfee",
        "setbuyfee",
        "setmarketingfee",
    ];
    if fee_setters.iter().any(|f| src_lower.contains(f)) {
        flags.push(SourceRiskFlag::DynamicFeeSetter);
        risk += 15;
    }

    // 3. Assembly with sstore inside transfer
    if src_lower.contains("assembly")
        && src_lower.contains("sstore")
        && (src_lower.contains("_transfer") || src_lower.contains("transfer("))
    {
        flags.push(SourceRiskFlag::AssemblyInTransfer);
        risk += 20;
    }

    // 4. Owner-only transfer restriction
    if src_lower.contains("require(msg.sender == owner")
        && (src_lower.contains("transfer(") || src_lower.contains("_transfer"))
    {
        flags.push(SourceRiskFlag::OwnerOnlyTransfer);
        risk += 25;
    }

    // 5. Selfdestruct capability
    if src_lower.contains("selfdestruct(") || src_lower.contains("suicide(") {
        flags.push(SourceRiskFlag::SelfDestructPresent);
        risk += 30;
    }

    // 6. Trading pause function
    let pause_fns = [
        "settradingenabled",
        "pausetrading",
        "setenabled(",
        "settransferenabled",
        "tradeenabled =",
        "tradingenabled =",
    ];
    if pause_fns.iter().any(|f| src_lower.contains(f)) {
        flags.push(SourceRiskFlag::TransferPauseFunction);
        risk += 20;
    }

    // 7. Router changeable
    if src_lower.contains("setrouter(") || src_lower.contains("updaterouter(") {
        flags.push(SourceRiskFlag::RouterChangeableByOwner);
        risk += 15;
    }

    // 8. Hidden minter address
    if (src_lower.contains("address public minter")
        || src_lower.contains("address private minter"))
        && src_lower.contains("owner")
    {
        flags.push(SourceRiskFlag::HiddenMinterAddress);
        risk += 15;
    }

    SourceRisk {
        risk_score: risk.min(100),
        flags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_source_unverified() {
        let result = analyze_source(None);
        assert_eq!(result.risk_score, 10);
        assert!(result.flags.contains(&SourceRiskFlag::NotVerified));
    }

    #[test]
    fn test_analyze_source_empty() {
        let result = analyze_source(Some(""));
        assert_eq!(result.risk_score, 10);
        assert!(result.flags.contains(&SourceRiskFlag::NotVerified));
    }

    #[test]
    fn test_analyze_source_safe_contract() {
        let source = r"
            pragma solidity ^0.8.0;
            contract SafeToken {
                function transfer(address to, uint256 amount) public returns (bool) {
                    _transfer(msg.sender, to, amount);
                    return true;
                }
                
                function _transfer(address from, address to, uint256 amount) internal {
                    // Standard transfer logic
                }
            }
        ";
        let result = analyze_source(Some(source));
        assert_eq!(result.flags.len(), 0);
    }

    #[test]
    fn test_analyze_source_owner_drain() {
        let source = r"
            function _transfer(address from, address to, uint256 amount) internal {
                payable(owner).transfer(address(this).balance);
            }
        ";
        let result = analyze_source(Some(source));
        assert!(result.flags.contains(&SourceRiskFlag::OwnerDrainInTransfer));
        assert!(result.risk_score >= 35);
    }

    #[test]
    fn test_analyze_source_dynamic_fee() {
        let source = r"
            function setTaxFee(uint256 taxFee) external onlyOwner {
                _taxFee = taxFee;
            }
        ";
        let result = analyze_source(Some(source));
        assert!(result.flags.contains(&SourceRiskFlag::DynamicFeeSetter));
    }

    #[test]
    fn test_analyze_source_assembly_transfer() {
        let source = r"
            function _transfer(address from, address to, uint256 amount) internal {
                assembly {
                    sstore(slot, value)
                }
            }
        ";
        let result = analyze_source(Some(source));
        assert!(result.flags.contains(&SourceRiskFlag::AssemblyInTransfer));
    }

    #[test]
    fn test_analyze_source_owner_only_transfer() {
        let source = r"
            function _transfer(address from, address to, uint256 amount) internal {
                require(msg.sender == owner, 'Only owner can transfer');
            }
        ";
        let result = analyze_source(Some(source));
        assert!(result.flags.contains(&SourceRiskFlag::OwnerOnlyTransfer));
    }

    #[test]
    fn test_analyze_source_selfdestruct() {
        let source = r"
            function emergencyWithdraw() external onlyOwner {
                selfdestruct(payable(owner));
            }
        ";
        let result = analyze_source(Some(source));
        assert!(result.flags.contains(&SourceRiskFlag::SelfDestructPresent));
    }

    #[test]
    fn test_analyze_source_pause_function() {
        let source = r"
            function setTradingEnabled(bool enabled) external onlyOwner {
                tradingEnabled = enabled;
            }
        ";
        let result = analyze_source(Some(source));
        assert!(result.flags.contains(&SourceRiskFlag::TransferPauseFunction));
    }

    #[test]
    fn test_analyze_source_router_changeable() {
        let source = r"
            function setRouter(address newRouter) external onlyOwner {
                router = newRouter;
            }
        ";
        let result = analyze_source(Some(source));
        assert!(result.flags.contains(&SourceRiskFlag::RouterChangeableByOwner));
    }

    #[test]
    fn test_analyze_source_hidden_minter() {
        let source = r"
            address public minter;
            address public owner;
            
            function mint(uint256 amount) external {
                require(msg.sender == minter || msg.sender == owner);
            }
        ";
        let result = analyze_source(Some(source));
        assert!(result.flags.contains(&SourceRiskFlag::HiddenMinterAddress));
    }

    #[test]
    fn test_analyze_source_multiple_flags() {
        let source = r"
            pragma solidity ^0.8.0;
            contract MaliciousToken {
                address public owner;
                address public minter;
                bool public tradingEnabled = true;
                
                function _transfer(address from, address to, uint256 amount) internal {
                    require(tradingEnabled, 'Trading paused');
                    require(msg.sender == owner, 'Only owner');
                    payable(owner).transfer(address(this).balance);
                }
                
                function setTaxFee(uint256 fee) external {
                    _taxFee = fee;
                }
                
                function setTradingEnabled(bool enabled) external {
                    tradingEnabled = enabled;
                }
                
                function emergencyWithdraw() external {
                    selfdestruct(payable(owner));
                }
            }
        ";
        let result = analyze_source(Some(source));
        assert!(result.flags.len() >= 5);
        assert!(result.risk_score >= 100);
    }
}
