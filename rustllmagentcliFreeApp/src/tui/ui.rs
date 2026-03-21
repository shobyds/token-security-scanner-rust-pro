//! UI Rendering module
//!
//! This module handles all UI rendering for the TUI application.

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::tui::app::{GroqStatus, TuiApp};
use crate::tui::widgets::{chat, domain_bars::DomainBars, llm_insight::LlmInsightPanel, red_flags::RedFlagsList, todo_widget, tri_gauge::TriGauge};

/// Render the entire UI
pub fn render(frame: &mut Frame, app: &TuiApp) {
    // Check if TODO panel should be shown
    let has_todos = !app.todo_list.tasks.is_empty();
    
    // Check if scan results are available
    let has_scan_results = app.last_tri.is_some();

    let chunks = if has_todos {
        // Split main area between chat and TODO
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),      // Header
                Constraint::Percentage(70), // Chat (70%)
                Constraint::Percentage(30), // TODO list (30%)
                Constraint::Length(4),      // Input box
                Constraint::Length(1),      // Status bar
            ])
            .split(frame.area());

        // Render header
        render_header(frame, main_chunks[0]);

        // Render chat panel
        chat::render(frame, main_chunks[1], app);

        // Render TODO panel
        todo_widget::render_todo_list(frame, main_chunks[2], &app.todo_list);

        // Render input box
        render_input_box(frame, main_chunks[3], app);

        // Render status bar
        render_status_bar(frame, main_chunks[4], app);

        main_chunks
    } else if has_scan_results {
        // Split layout: Chat (60%) + Scan Panel (40%)
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),      // Header
                Constraint::Min(0),         // Main content (split horizontally)
                Constraint::Length(4),      // Input box
                Constraint::Length(1),      // Status bar
            ])
            .split(frame.area());

        // Render header
        render_header(frame, main_chunks[0]);

        // Split main content horizontally
        let content_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(60), // Chat panel
                Constraint::Percentage(40), // Scan results panel
            ])
            .split(main_chunks[1]);

        // Render chat panel (left)
        chat::render(frame, content_chunks[0], app);

        // Render scan results panel (right)
        render_scan_panel(frame, content_chunks[1], app);

        // Render input box
        render_input_box(frame, main_chunks[2], app);

        // Render status bar
        render_status_bar(frame, main_chunks[3], app);

        main_chunks
    } else {
        // No TODOs, no scan results - use original layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Main content
                Constraint::Length(4), // Input box
                Constraint::Length(1), // Status bar
            ])
            .split(frame.area());

        // Render header
        render_header(frame, chunks[0]);

        // Render main content (chat only - full width)
        render_main_content(frame, chunks[1], app);

        // Render input box
        render_input_box(frame, chunks[2], app);

        // Render status bar
        render_status_bar(frame, chunks[3], app);

        chunks
    };

    // Handle panel switching to TODO
    if app.active_panel == crate::tui::app::Panel::Todo && !has_todos {
        // If TODO panel is active but no TODOs, switch to Chat
        // This is handled in the app logic
    }

    // Render scan confirmation dialog if visible (always on top)
    if app.scan_dialog_state.visible {
        use crate::tui::widgets::scan_dialog::render_scan_dialog;
        render_scan_dialog(frame, &app.scan_dialog_state, frame.area());
    }

    // Render toast notifications (always on top, bottom-right corner)
    if app.toast_manager.has_toasts() {
        app.toast_manager.render(frame, frame.area());
    }
}

/// Render the header
fn render_header(frame: &mut Frame, area: Rect) {
    let title = Paragraph::new("🤖 Rust LLM Agent CLI")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));

    frame.render_widget(title, area);
}

/// Render main content area (chat only - tool log removed)
fn render_main_content(frame: &mut Frame, area: Rect, app: &TuiApp) {
    // Render chat panel (full width now)
    chat::render(frame, area, app);
}

/// Render scan results panel (right side)
fn render_scan_panel(frame: &mut Frame, area: Rect, app: &TuiApp) {
    // Split panel vertically into 4 sections
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),  // TRI Gauge
            Constraint::Length(10), // Domain Bars (8 domains + borders)
            Constraint::Percentage(35), // Red/Green Flags
            Constraint::Percentage(45), // LLM Insight
        ])
        .split(area);

    // Render TRI Gauge
    if let Some(ref tri_result) = app.last_tri {
        let tri_gauge = TriGauge::new(tri_result);
        tri_gauge.render(frame, chunks[0]);

        // Render Domain Bars
        let domain_bars = DomainBars::new(tri_result);
        domain_bars.render(frame, chunks[1]);

        // Render Red Flags
        let red_flags = RedFlagsList::new(tri_result);
        red_flags.render(frame, chunks[2]);

        // Render LLM Insight
        if let Some(ref pipeline_result) = app.last_pipeline_result {
            let llm_insight = LlmInsightPanel::new(
                pipeline_result.llm_analysis.as_ref(),
                pipeline_result.rug_probability,
                0.35, // Default threshold
            );
            llm_insight.render(frame, chunks[3]);
        }
    }
}

/// Render input box
pub fn render_input_box(frame: &mut Frame, area: Rect, app: &TuiApp) {
    let is_active = app.get_active_panel() == crate::tui::app::Panel::Input;

    // Render input box (thinking indicator now appears in chat history)
    render_input_field(frame, area, app, is_active);
}

/// Render the actual input field
fn render_input_field(frame: &mut Frame, area: Rect, app: &TuiApp, is_active: bool) {
    let input_text = format!(">>> {}", app.get_input_buffer());
    let input = Paragraph::new(input_text)
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Input (Press Enter to submit, Tab to switch panels, Esc to clear) ")
                .border_style(if is_active {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default()
                }),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(input, area);

    // Set cursor position - AFTER the last character (at the end of input)
    if is_active {
        // ">>> " = 4 chars prefix, border left adds 1 col, border top adds 1 row
        let prefix_len: u16 = 4; // ">>> "
        let buf_len: u16 = app
            .get_input_buffer()
            .chars()
            .map(|c| unicode_width::UnicodeWidthChar::width(c).unwrap_or(1) as u16)
            .sum();
        let cursor_col = area.x + 1 + prefix_len + buf_len; // +1 for left border
        let cursor_row = area.y + 1; // +1 for top border
        // Clamp so cursor never escapes the box
        if cursor_col < area.x + area.width.saturating_sub(1) {
            frame.set_cursor_position((cursor_col, cursor_row));
        }
    }
}

/// Render status bar
fn render_status_bar(frame: &mut Frame, area: Rect, app: &TuiApp) {
    // Connection status indicator with tooltip
    let (connection_indicator, connection_tooltip) = match app.connection_status {
        crate::tui::app::ConnectionStatus::Checking => (
            Span::styled("◌", Style::default().fg(Color::Yellow)),
            "Connecting...",
        ),
        crate::tui::app::ConnectionStatus::Connected => (
            Span::styled("●", Style::default().fg(Color::Green)),
            "Connected",
        ),
        crate::tui::app::ConnectionStatus::Failed => (
            Span::styled("●", Style::default().fg(Color::Red)),
            "Connection failed",
        ),
    };

    // Groq API status indicator
    let (groq_indicator, groq_tooltip) = match app.groq_status {
        GroqStatus::Unknown => (
            Span::styled("◌", Style::default().fg(Color::DarkGray)),
            "Groq: Not checked",
        ),
        GroqStatus::Available => (
            Span::styled("●", Style::default().fg(Color::Green)),
            "Groq: Available",
        ),
        GroqStatus::Unavailable => (
            Span::styled("✗", Style::default().fg(Color::Red)),
            "Groq: Unavailable",
        ),
        GroqStatus::Calling => (
            Span::styled("◐", Style::default().fg(Color::Yellow)),
            "Groq: Calling...",
        ),
    };

    // Scan status indicator
    let scan_text = if app.scan_in_progress {
        vec![
            Span::raw(" | "),
            Span::styled("🔍", Style::default().fg(Color::Yellow)),
            Span::raw(" Scanning: "),
            Span::styled(
                app.scan_token_address.clone().unwrap_or_default(),
                Style::default().fg(Color::White),
            ),
        ]
    } else if let Some(ref addr) = app.scan_token_address {
        let tri_text = if let Some(ref tri) = app.last_tri {
            format!(" [{} {:.1}]", tri.tri_label.display(), tri.tri)
        } else {
            String::new()
        };
        vec![
            Span::raw(" | "),
            Span::styled("✓", Style::default().fg(Color::Green)),
            Span::raw(" Last: "),
            Span::styled(addr, Style::default().fg(Color::White)),
            Span::styled(tri_text, Style::default().fg(Color::Cyan)),
        ]
    } else {
        vec![]
    };

    let mut status_parts = vec![
        connection_indicator,
        Span::raw(" "),
        Span::styled(connection_tooltip, Style::default().fg(Color::White)),
        Span::raw(" | "),
        groq_indicator,
        Span::raw(" "),
        Span::styled(groq_tooltip, Style::default().fg(Color::White)),
        Span::raw(" | Model: "),
        Span::styled(
            app.detected_model
                .clone()
                .unwrap_or_else(|| app.state.config.llm.model.clone()),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(" | Msgs: "),
        Span::styled(
            app.state.get_messages().len().to_string(),
            Style::default().fg(Color::White),
        ),
    ];

    status_parts.extend(scan_text);

    status_parts.extend(vec![
        Span::raw(" | Tab: Toggle Input/Chat | "),
        Span::styled("Ctrl+C", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" quit"),
    ]);

    let status_text = Line::from(status_parts);

    let status = Paragraph::new(status_text).style(Style::default().bg(Color::DarkGray));

    frame.render_widget(status, area);
}

/// Render a help popup
#[allow(dead_code)]
pub fn render_help_popup(frame: &mut Frame, area: Rect) {
    let help_text = vec![
        Line::from("Keyboard Shortcuts"),
        Line::from(""),
        Line::from(vec![
            Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" - Submit query"),
        ]),
        Line::from(vec![
            Span::styled("Tab", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" - Switch panels"),
        ]),
        Line::from(vec![
            Span::styled("↑/↓", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" - Scroll chat"),
        ]),
        Line::from(vec![
            Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" - Clear input"),
        ]),
        Line::from(vec![
            Span::styled("Ctrl+C", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" - Quit"),
        ]),
        Line::from(vec![
            Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" - Quit (when not in input)"),
        ]),
    ];

    let help = Paragraph::new(help_text)
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Help ")
                .border_style(Style::default().fg(Color::Cyan)),
        );

    frame.render_widget(help, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::state::AppState;
    use crate::types::message::Message;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn create_test_app() -> (TuiApp<'static>, Terminal<TestBackend>) {
        let state = AppState::with_defaults(".".to_string());
        // Leak state to get static lifetime for testing
        let state = Box::leak(Box::new(state));
        let app = TuiApp::new(state);
        let backend = TestBackend::new(80, 24);
        let terminal = Terminal::new(backend).unwrap();
        (app, terminal)
    }

    #[test]
    fn test_render_header() {
        let (_app, mut terminal) = create_test_app();

        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 80, 3);
                render_header(frame, area);
            })
            .unwrap();

        // Just verify rendering doesn't panic
        let buffer = terminal.backend().buffer();
        assert!(!buffer.content().is_empty());
    }

    #[test]
    fn test_render_status_bar() {
        let (app, mut terminal) = create_test_app();

        terminal
            .draw(|frame| {
                let area = Rect::new(0, 23, 80, 1);
                render_status_bar(frame, area, &app);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();
        assert!(content.contains("Model"));
        assert!(content.contains("Msgs"));
    }

    #[test]
    fn test_render_input_box() {
        let (mut app, mut terminal) = create_test_app();
        app.input_buffer = "test input".to_string();

        terminal
            .draw(|frame| {
                let area = Rect::new(0, 20, 80, 4);
                render_input_box(frame, area, &app);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();
        assert!(content.contains("test input"));
    }

    #[test]
    fn test_layout_constraints() {
        let area = Rect::new(0, 0, 80, 24);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(4),
                Constraint::Length(1),
            ])
            .split(area);

        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].height, 3); // Header
        assert_eq!(chunks[3].height, 1); // Status bar
        assert_eq!(chunks[2].height, 4); // Input
    }

    #[test]
    fn test_main_content_layout() {
        let area = Rect::new(0, 3, 80, 16);

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(area);

        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].width > chunks[1].width); // Chat wider than tool log
    }

    #[test]
    fn test_render_with_messages() {
        let (app, mut terminal) = create_test_app();
        app.state.add_message(Message::user("Hello"));
        app.state.add_message(Message::assistant("Hi there!"));

        terminal
            .draw(|frame| {
                render(frame, &app);
            })
            .unwrap();

        // Should render without errors
        let buffer = terminal.backend().buffer();
        assert!(!buffer.content().is_empty());
    }
}
