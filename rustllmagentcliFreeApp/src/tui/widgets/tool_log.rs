//! Tool Log widget for displaying tool execution history
//!
//! Note: This widget is NO LONGER RENDERED in the UI (removed to give chat full width).
//! Tool execution is now logged to agent.log file instead.
//! This file is kept for potential future re-enablement.

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(dead_code)]

use ratatui::Frame;
use ratatui::layout::Rect;

use crate::tui::app::TuiApp;

/// Render the tool log widget
/// Note: No longer used - tool execution logged to agent.log instead
pub fn render(_frame: &mut Frame, _area: Rect, _app: &TuiApp) {
    // Widget removed - tool execution now logged to agent.log file only
    // This function kept for potential future use
}

/// Render tool log with execution details (not used)
pub fn render_with_details(_frame: &mut Frame, _area: Rect, _app: &TuiApp, _max_entries: usize) {
    // Widget removed - tool execution now logged to agent.log file only
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::state::AppState;

    #[test]
    fn test_tool_log_render_stub() {
        // Test that the stub function exists and compiles
        let state = AppState::with_defaults(".".to_string());
        let state = Box::leak(Box::new(state));
        let app = TuiApp::new(state);
        let area = Rect::new(0, 0, 80, 20);

        // Create a dummy frame - this test just verifies the function signature
        // In a real scenario, we'd need a proper Frame instance
        let _ = app;
        let _ = area;
    }
}
