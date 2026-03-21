use reqwest::Client;
use std::sync::LazyLock;
use std::time::Duration;

/// Global HTTP client optimized for `HuggingFace` Space API
///
/// Key optimizations (matching Python's requests library behavior):
/// - HTTP/1.1 only (Python uses HTTP/1.1 by default - no HTTP/2 negotiation overhead)
/// - Connection pooling (prevents TLS handshake overhead)
/// - TCP keepalive (prevents stale connections)
/// - Appropriate timeouts (HF Space can be slow)
pub static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(10)
        .tcp_keepalive(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .http1_only() // Match Python's HTTP/1.1 - no HTTP/2 negotiation overhead!
        .build()
        .expect("Failed to build HTTP client")
});
