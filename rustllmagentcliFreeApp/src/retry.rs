#![allow(clippy::missing_errors_doc)]

use tokio::time::{Duration, sleep};
use tracing::warn;

/// Retry system for handling HF Space instability
///
/// HF Spaces sometimes drop connections or return transient errors.
/// This retry wrapper handles up to 3 attempts with 2-second delays.
pub async fn retry_async<F, Fut, T>(mut f: F) -> Result<T, reqwest::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, reqwest::Error>>,
{
    let mut attempts = 0;

    loop {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                attempts += 1;

                if attempts >= 3 {
                    warn!("Request failed after {} attempts: {}", attempts, e);
                    return Err(e);
                }

                warn!(
                    "Request failed (attempt {}), retrying in 2s: {}",
                    attempts, e
                );
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Retry with custom delay
pub async fn retry_async_with_delay<F, Fut, T>(
    mut f: F,
    max_attempts: usize,
    delay_secs: u64,
) -> Result<T, reqwest::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, reqwest::Error>>,
{
    let mut attempts = 0;

    loop {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                attempts += 1;

                if attempts >= max_attempts {
                    warn!("Request failed after {} attempts: {}", attempts, e);
                    return Err(e);
                }

                warn!(
                    "Request failed (attempt {}), retrying in {}s: {}",
                    attempts, delay_secs, e
                );
                sleep(Duration::from_secs(delay_secs)).await;
            }
        }
    }
}
