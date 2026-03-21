//! Rust LLM Agent Library
//!
//! A terminal-based intelligent coding agent powered by local LLMs.

#![recursion_limit = "256"]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::field_reassign_with_default)]

pub mod agent;
pub mod app;
pub mod http_client;
pub mod llm;
pub mod retry;
pub mod scanner;
pub mod tools;
pub mod types;
pub mod utils;
pub mod warmup;

// Token scanner API layer (Section 14)
pub mod api;
pub mod models;

// Report generation module (Section 16)
pub mod report;

// TUI module (also needed by utils::csv_todo)
#[cfg(feature = "tui")]
pub mod tui;

// Include tui for non-TUI builds to support csv_todo
#[cfg(not(feature = "tui"))]
mod tui;
