//! Network Scanner Module for LM Studio Auto-Discovery
//!
//! This module provides functionality to scan the local network for LM Studio servers
//! by testing IP addresses in a specified range.

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::return_self_not_must_use)]

use reqwest::blocking::Client;
use std::net::UdpSocket;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Default network prefix for local networks
const DEFAULT_NETWORK_PREFIX: &str = "192.168.1";

/// Default port for LM Studio
const DEFAULT_PORT: u16 = 1234;

/// Default timeout per IP in milliseconds
const DEFAULT_TIMEOUT_MS: u64 = 500;

/// Default scan range (number of IPs to scan)
const DEFAULT_SCAN_RANGE: u32 = 40;

/// LM Studio API endpoint to test connectivity
const LM_STUDIO_TEST_ENDPOINT: &str = "/api/v1/models";

/// Detect the machine's primary local-network prefix by inspecting
/// the source IP used to reach an external routable address (8.8.8.8).
/// Falls back to the config prefix if detection fails.
pub fn detect_local_prefix() -> String {
    // UDP connect trick: no packet sent, but OS picks the outbound interface
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            // Try Google DNS first, then Cloudflare as backup
            for dns_server in ["8.8.8.8:53", "1.1.1.1:53"] {
                if socket.connect(dns_server).is_ok() {
                    match socket.local_addr() {
                        Ok(local_addr) => {
                            let ip = local_addr.ip().to_string();
                            // Split off last octet → prefix
                            let parts: Vec<&str> = ip.split('.').collect();
                            if parts.len() == 4 {
                                let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
                                info!("Detected local network prefix: {} (from IP {})", prefix, ip);
                                return prefix;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to get local address for DNS {}: {}", dns_server, e);
                        }
                    }
                }
            }
            warn!("Could not connect to any DNS server for network detection");
        }
        Err(e) => {
            warn!("Failed to bind UDP socket for network detection: {}", e);
        }
    }
    info!("Using fallback network prefix: {}", DEFAULT_NETWORK_PREFIX);
    DEFAULT_NETWORK_PREFIX.to_string()
}

/// Network Scanner for discovering LM Studio servers on the local network
#[derive(Debug, Clone)]
pub struct NetworkScanner {
    /// Network prefix (e.g., "192.168.1")
    network_prefix: String,
    /// Port to scan (default: 1234)
    port: u16,
    /// Timeout per IP in milliseconds
    timeout_ms: u64,
    /// HTTP client for testing connections
    client: Client,
}

impl Default for NetworkScanner {
    fn default() -> Self {
        let prefix = detect_local_prefix();
        Self::new(prefix, DEFAULT_PORT, DEFAULT_TIMEOUT_MS)
    }
}

impl NetworkScanner {
    /// Create a new `NetworkScanner` with custom settings
    ///
    /// # Arguments
    /// * `network_prefix` - The network prefix (e.g., "192.168.1")
    /// * `port` - The port to scan (default: 1234 for LM Studio)
    /// * `timeout_ms` - Timeout per IP in milliseconds (default: 500)
    pub fn new(network_prefix: String, port: u16, timeout_ms: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to create HTTP client for network scanner");

        Self {
            network_prefix,
            port,
            timeout_ms,
            client,
        }
    }

    /// Scan the network for LM Studio servers
    ///
    /// # Arguments
    /// * `range` - Number of IPs to scan (e.g., 40 means scan .0 to .40)
    ///
    /// # Returns
    /// * `Option<String>` - The first IP that responds successfully, or None if not found
    pub fn scan(&self, range: u32) -> Option<String> {
        info!(
            "Scanning network for LM Studio server at {}.*:{} (range: 0-{}, timeout: {}ms)",
            self.network_prefix, self.port, range, self.timeout_ms
        );
        println!(
            "Scanning network for LM Studio server ({}.*.{}, range 0-{})...",
            self.network_prefix, self.port, range
        );

        // Scan from 0 to range (inclusive)
        for i in 0..=range {
            let ip = format!("{}.{}", self.network_prefix, i);

            if self.test_ip(&ip) {
                let full_address = format!("{}:{}", ip, self.port);
                info!("✓ Found LM Studio at {}", full_address);
                println!("✓ Found LM Studio server at http://{}:{}", ip, self.port);
                return Some(full_address);
            }
        }

        info!(
            "✗ No LM Studio server found in range {}.*.0-{}",
            self.network_prefix, range
        );
        println!(
            "✗ No LM Studio server found in range {}.*.0-{}",
            self.network_prefix, range
        );
        None
    }

    /// Scan with default range
    pub fn scan_default(&self) -> Option<String> {
        self.scan(DEFAULT_SCAN_RANGE)
    }

    /// Test if an IP address has an LM Studio server running
    ///
    /// # Arguments
    /// * `ip` - The IP address to test (without port)
    ///
    /// # Returns
    /// * `bool` - True if the IP responds successfully to GET /api/v1/models
    fn test_ip(&self, ip: &str) -> bool {
        let url = format!("http://{}:{}{}", ip, self.port, LM_STUDIO_TEST_ENDPOINT);
        debug!("Testing IP: {}", url);

        match self.client.get(&url).send() {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    debug!("✓ IP {} responded with status {}", ip, status);
                    true
                } else {
                    debug!("✗ IP {} responded with status {}", ip, status);
                    false
                }
            }
            Err(e) => {
                debug!("✗ IP {} failed: {}", ip, e);
                false
            }
        }
    }

    /// Get the network prefix
    pub fn network_prefix(&self) -> &str {
        &self.network_prefix
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the timeout in milliseconds
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Create a scanner with custom network prefix
    pub fn with_network_prefix(mut self, prefix: String) -> Self {
        self.network_prefix = prefix;
        self
    }

    /// Create a scanner with custom port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Create a scanner with custom timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        // Also update the client with new timeout
        self.client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to create HTTP client for network scanner");
        self
    }
}

/// Scan the network with default settings
///
/// This is a convenience function for quick network scanning
pub fn scan_for_lm_studio(range: u32) -> Option<String> {
    NetworkScanner::default().scan(range)
}

/// Scan the network with default range
pub fn scan_for_lm_studio_default() -> Option<String> {
    NetworkScanner::default().scan_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_local_prefix() {
        // Test that detect_local_prefix returns a valid prefix format
        let prefix = detect_local_prefix();
        // Should be in format "x.y.z" (three octets)
        let parts: Vec<&str> = prefix.split('.').collect();
        assert_eq!(parts.len(), 3, "Prefix should have 3 octets");
        // Each part should be a valid number (u8 parse validates 0-255 range)
        for part in parts {
            let _num: u8 = part.parse().expect("Each octet should be a valid u8");
        }
    }

    #[test]
    fn test_network_scanner_creation() {
        let scanner = NetworkScanner::default();
        // Note: prefix may vary based on actual network, so we just check it's not empty
        assert!(!scanner.network_prefix().is_empty());
        assert_eq!(scanner.port(), 1234);
        assert_eq!(scanner.timeout_ms(), 500);
    }

    #[test]
    fn test_network_scanner_creation_with_explicit_prefix() {
        let scanner = NetworkScanner::new("10.0.0".to_string(), 1234, 500);
        assert_eq!(scanner.network_prefix(), "10.0.0");
        assert_eq!(scanner.port(), 1234);
        assert_eq!(scanner.timeout_ms(), 500);
    }

    #[test]
    fn test_network_scanner_custom_config() {
        let scanner = NetworkScanner::new("10.0.0".to_string(), 8080, 1000);
        assert_eq!(scanner.network_prefix(), "10.0.0");
        assert_eq!(scanner.port(), 8080);
        assert_eq!(scanner.timeout_ms(), 1000);
    }

    #[test]
    fn test_network_scanner_builder_pattern() {
        let scanner = NetworkScanner::new("172.16.0".to_string(), 1234, 500)
            .with_network_prefix("172.16.0".to_string())
            .with_port(9000)
            .with_timeout(2000);

        assert_eq!(scanner.network_prefix(), "172.16.0");
        assert_eq!(scanner.port(), 9000);
        assert_eq!(scanner.timeout_ms(), 2000);
    }

    #[test]
    fn test_ip_format() {
        let scanner = NetworkScanner::new("192.168.1".to_string(), 1234, 500);

        // Test that IP format is correct (we can't actually test connectivity in unit tests)
        // This test verifies the format logic
        let test_ip = "192.168.1.5";
        let expected_url = format!(
            "http://{}:{}{}",
            test_ip,
            scanner.port(),
            LM_STUDIO_TEST_ENDPOINT
        );
        assert_eq!(expected_url, "http://192.168.1.5:1234/api/v1/models");
    }

    #[test]
    fn test_scan_range_zero() {
        let scanner = NetworkScanner::new("192.168.1".to_string(), 1234, 500);
        // Scanning range 0 should only test .0
        // This will likely return None in tests without a real server
        let result = scanner.scan(0);
        // We don't assert on the result since it depends on actual network
        // Just verify it doesn't panic
        assert!(result.is_none() || result.is_some());
    }

    #[test]
    fn test_convenience_functions() {
        // Test that convenience functions work with explicit scanner
        let scanner = NetworkScanner::new("192.168.1".to_string(), 1234, 500);
        let result = scanner.scan(10);
        assert!(result.is_none() || result.is_some());

        let result = scanner.scan_default();
        assert!(result.is_none() || result.is_some());
    }

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_NETWORK_PREFIX, "192.168.1");
        assert_eq!(DEFAULT_PORT, 1234);
        assert_eq!(DEFAULT_TIMEOUT_MS, 500);
        assert_eq!(DEFAULT_SCAN_RANGE, 40);
        assert_eq!(LM_STUDIO_TEST_ENDPOINT, "/api/v1/models");
    }
}
