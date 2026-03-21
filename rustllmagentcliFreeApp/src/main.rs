//! Rust LLM Agent CLI - Entry point

#![allow(clippy::large_futures)]

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{info, warn};

#[cfg(feature = "tui")]
use rust_llm_agent::tui::app::TuiApp;

#[derive(Parser, Debug)]
#[command(name = "rust-llm-agent")]
#[command(about = "Rust LLM Agent CLI with Ratatui TUI", long_about = None)]
#[command(version = "0.1.0")]
struct Cli {
    /// LLM API base URL (overrides config)
    #[arg(long)]
    llm_url: Option<String>,

    /// Model name to use (overrides config)
    #[arg(long)]
    model: Option<String>,

    /// Working directory
    #[arg(long, default_value = ".")]
    workdir: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Disable TUI (use CLI mode)
    #[arg(long)]
    no_tui: bool,

    /// Direct query (non-interactive mode)
    #[arg(short, long)]
    query: Option<String>,

    /// Configuration file path
    #[arg(long, short = 'c')]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file (if exists)
    match dotenvy::dotenv() {
        Ok(path) => {
            info!("Loaded .env file from: {:?}", path);
            // Verify GROQ_API_KEY is loaded
            if let Ok(key) = std::env::var("GROQ_API_KEY") {
                let key_preview = if key.len() > 8 {
                    format!("{}...{}", &key[..4], &key[key.len() - 4..])
                } else {
                    "***".to_string()
                };
                info!("GROQ_API_KEY loaded: {}", key_preview);
            } else {
                warn!("GROQ_API_KEY not found in .env or environment");
            }
        }
        Err(_) => {
            info!("No .env file found, using environment variables");
        }
    }

    let cli = Cli::parse();

    // Load configuration
    let mut config = if let Some(config_path) = &cli.config {
        rust_llm_agent::app::config::AppConfig::load_from_path(config_path)?
    } else {
        rust_llm_agent::app::config::AppConfig::load()
            .unwrap_or_else(|_| rust_llm_agent::app::config::AppConfig::default())
    };

    // Override config with CLI arguments if provided
    if let Some(url) = &cli.llm_url {
        config.llm.url.clone_from(url);
    }
    if let Some(model) = &cli.model {
        config.llm.model.clone_from(model);
    }

    // Initialize logging
    let log_level = if cli.verbose {
        "debug"
    } else {
        &config.logging.level
    };

    // Try to initialize file logging, fall back to stdout
    if let Err(e) = rust_llm_agent::utils::init_logging(log_level, &config.logging.file) {
        rust_llm_agent::utils::init_logging_stdout(log_level);
        eprintln!("Warning: Could not initialize file logging: {e}");
    }

    // Check if GROQ_API_KEY is configured
    let groq_key_configured = std::env::var("GROQ_API_KEY")
        .ok()
        .filter(|k| !k.is_empty())
        .is_some()
        || config.phi3.api_key.as_ref().filter(|k| !k.is_empty()).is_some();

    if !groq_key_configured {
        eprintln!("⚠ WARNING: No GROQ_API_KEY found. LLM analysis will be disabled.");
        eprintln!("  Set GROQ_API_KEY in .env or export it before starting:");
        eprintln!("  export GROQ_API_KEY=gsk_your_groq_api_key_here");
        eprintln!();
    }

    info!("Starting Rust LLM Agent");
    info!("LLM URL: {}", config.llm.url);
    info!("Model: {}", config.llm.model);
    info!("Working directory: {}", cli.workdir);

    // Start Groq API warmup loop (verifies API connectivity on startup)
    rust_llm_agent::warmup::start_warmup_loop();

    // Initialize application state
    let mut app_state = rust_llm_agent::app::state::AppState::new(
        config.llm.url.clone(),
        config.llm.model.clone(),
        cli.workdir.clone(),
        config,
    );

    // Handle direct query mode
    if let Some(query) = cli.query {
        return run_direct_query(&mut app_state, &query).await;
    }

    // Launch TUI or CLI mode
    if cli.no_tui {
        info!("Starting in CLI mode");
        run_cli_mode(&mut app_state).await
    } else {
        info!("Starting in TUI mode");
        run_tui_mode(&mut app_state).await
    }
}

/// Run a direct query and exit
async fn run_direct_query(
    state: &mut rust_llm_agent::app::state::AppState,
    query: &str,
) -> Result<()> {
    use rust_llm_agent::agent::controller::AgentController;

    let mut controller = AgentController::new(state);

    match controller.process_query(query).await {
        Ok(response) => {
            println!("{response}");
            Ok(())
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

/// Run in CLI mode (interactive terminal)
async fn run_cli_mode(state: &mut rust_llm_agent::app::state::AppState) -> Result<()> {
    use rust_llm_agent::agent::controller::AgentController;
    use std::io::{self, Write};

    let mut controller = AgentController::new(state);

    println!("Rust LLM Agent CLI Mode");
    println!("Type 'exit' or 'quit' to exit, 'clear' to clear history\n");

    loop {
        print!(">>> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let query = input.trim();
        if query.is_empty() {
            continue;
        }
        if query == "exit" || query == "quit" {
            break;
        }
        if query == "clear" {
            controller.reset_conversation();
            println!("Conversation history cleared\n");
            continue;
        }

        match controller.process_query(query).await {
            Ok(response) => println!("\n{response}\n"),
            Err(e) => eprintln!("Error: {e}\n"),
        }
    }

    Ok(())
}

/// Run in TUI mode (Ratatui interface)
#[cfg(feature = "tui")]
async fn run_tui_mode(state: &mut rust_llm_agent::app::state::AppState) -> Result<()> {
    info!("Launching TUI interface");
    TuiApp::new(state).run().await
}

/// Run in TUI mode (stub for non-tui builds)
#[cfg(not(feature = "tui"))]
async fn run_tui_mode(state: &mut rust_llm_agent::app::state::AppState) -> Result<()> {
    println!("TUI mode is not available in this build. Falling back to CLI mode.\n");
    run_cli_mode(state).await
}
