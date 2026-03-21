use crate::http_client::HTTP_CLIENT;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

/// Base URL for the Groq API chat completions endpoint
const GROQ_URL: &str = "https://api.groq.com/openai/v1/chat/completions";

/// Model to use for Groq API (Llama-3.1-8B-Instant)
const GROQ_MODEL: &str = "llama-3.1-8b-instant";

/// Groq API key from environment
const GROQ_API_KEY: Option<&str> = option_env!("GROQ_API_KEY");

/// Background warmup task for Groq API
///
/// Groq API is a hosted service that doesn't sleep.
/// This warmup loop simply verifies API connectivity on startup.
pub fn start_warmup_loop() {
    tokio::spawn(async {
        info!("Starting Groq API warmup loop");

        // Initial warmup - verify API is accessible with a minimal request
        let payload = serde_json::json!({
            "model": GROQ_MODEL,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1
        });

        let mut request = HTTP_CLIENT
            .post(GROQ_URL)
            .json(&payload);

        if let Some(api_key) = GROQ_API_KEY {
            request = request.header("Authorization", format!("Bearer {api_key}"));
        }

        match request.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    info!("Groq API warmup: API is accessible (status: {})", status);
                } else {
                    warn!(
                        "Groq API warmup returned status: {} (service may be unavailable)",
                        status
                    );
                }
            }
            Err(e) => warn!("Groq API warmup failed (will retry): {}", e),
        }

        // No periodic keep-alive needed - Groq API doesn't sleep
        // Loop runs once on startup, then exits
        info!("Groq API warmup complete - no periodic keep-alive required");
    });
}
