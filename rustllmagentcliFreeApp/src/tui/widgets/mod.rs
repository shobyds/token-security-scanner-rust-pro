//! TUI Widgets module

pub mod chat;
pub mod domain_bars;
pub mod llm_insight;
pub mod red_flags;
pub mod scan_dialog;
pub mod todo_widget;
pub mod tool_log;
pub mod tri_gauge;

// Re-export widgets for convenience
pub use domain_bars::DomainBars;
pub use llm_insight::LlmInsightPanel;
pub use red_flags::RedFlagsList;
pub use tri_gauge::TriGauge;
