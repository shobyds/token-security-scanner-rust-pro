//! Chat widget for displaying conversation history with word wrapping and thinking indicator

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap},
};

use crate::tui::app::TuiApp;
use crate::types::message::Role;

/// Format timestamp as HH:MM:SS
fn format_timestamp(timestamp: u64) -> String {
    let secs = timestamp % 60;
    let mins = (timestamp / 60) % 60;
    let hours = (timestamp / 3600) % 24;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}

/// Format duration in milliseconds to MM:SS or SS format
fn format_duration(duration_ms: u64) -> String {
    let total_secs = duration_ms / 1000;
    let mins = total_secs / 60;
    let secs = total_secs % 60;

    if mins > 0 {
        format!("{:02}:{:02}", mins, secs)
    } else {
        format!("{}s", secs)
    }
}

/// Render the chat widget with word-wrapped messages
pub fn render(frame: &mut Frame, area: Rect, app: &TuiApp) {
    let is_active = app.get_active_panel() == crate::tui::app::Panel::Chat;
    let messages = app.state.get_messages();
    let scroll_offset = app.get_scroll_offset();

    // Calculate visible area (subtract borders)
    let inner_area = area.inner(ratatui::layout::Margin {
        horizontal: 1,
        vertical: 1,
    });

    // Build all messages as a single text block
    let mut lines = Vec::new();

    // Display ALL messages in REVERSE order (newest on TOP)
    // This allows users to see the latest response immediately
    // and scroll UP to see older messages
    for message in messages.iter().rev() {
        // Format timestamp
        let time_str = format_timestamp(message.timestamp);

        // Format duration if available
        let duration_str = message
            .duration_ms
            .map(|d| format!(" [{}]", format_duration(d)))
            .unwrap_or_default();

        // Role-based styling and prefix
        let (prefix, style) = match message.role {
            Role::User => (
                "👤 You:",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Role::Assistant => (
                "🤖 Assistant:",
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            ),
            Role::System => (
                "⚙️ System:",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Role::Tool => (
                "🔧 Tool:",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
        };

        // Header line with timestamp, prefix, and duration
        lines.push(Line::from(vec![
            Span::styled(
                format!("{} |", time_str),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(" "),
            Span::styled(prefix, style),
            Span::styled(duration_str, Style::default().fg(Color::DarkGray)),
        ]));

        // Content line(s) with word wrapping
        // Split content into paragraphs and wrap each line
        let content = &message.content;

        // Wrap text to fit the available width
        let width = inner_area.width as usize;
        for line in content.lines() {
            if line.len() <= width {
                lines.push(Line::from(Span::raw(line.to_string())));
            } else {
                // Manual word wrap for very long lines
                // Use chars() instead of byte slicing to handle Unicode correctly
                let chars: Vec<char> = line.chars().collect();
                let mut current_pos = 0;
                while current_pos < chars.len() {
                    let end_pos = (current_pos + width).min(chars.len());
                    let segment: String = chars[current_pos..end_pos].iter().collect();
                    lines.push(Line::from(Span::raw(segment)));
                    current_pos = end_pos;
                }
            }
        }

        // Empty line for spacing between messages
        lines.push(Line::from(""));
    }

    // Add thinking indicator as the FIRST message (newest, at the top)
    if app.assistant_thinking {
        use ratatui::style::Modifier;

        // Format thinking duration
        let duration_str = app
            .assistant_thinking_start
            .map(|start| {
                let elapsed = start.elapsed();
                let secs = elapsed.as_secs();
                let mins = secs / 60;
                let secs = secs % 60;
                if mins > 0 {
                    format!("[{}m {:02}s]", mins, secs)
                } else {
                    format!("[{}s]", secs)
                }
            })
            .unwrap_or_else(|| "[...]".to_string());

        // Insert thinking indicator at the BEGINNING (top of chat)
        lines.insert(0, Line::from("")); // Spacing at top
        lines.insert(
            0,
            Line::from(vec![
                Span::styled(
                    "🤖 Assistant:",
                    Style::default()
                        .fg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    format!("Processing your request... {}", duration_str),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
        );
    }

    // Calculate content height for scrollbar before moving lines
    let content_height = lines.len();
    let viewport_height = inner_area.height as usize;

    // Calculate scroll offset in lines (not messages)
    // With reversed messages (newest on top), scroll UP to see older messages
    let avg_lines_per_message = if messages.len() > 0 {
        content_height / messages.len()
    } else {
        3
    };
    let scroll_offset_lines =
        (scroll_offset * avg_lines_per_message).min(content_height.saturating_sub(viewport_height));

    let chat_text = Text::from(lines);

    let chat_paragraph = Paragraph::new(chat_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Chat History (↑ for older, ↓ for newer) ")
                .border_style(if is_active {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default()
                }),
        )
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: false })
        .scroll((scroll_offset_lines as u16, 0)); // Scroll by lines, not messages

    frame.render_widget(chat_paragraph, area);

    // Render scrollbar if content is taller than viewport
    // Only show scrollbar if content overflows
    if content_height > viewport_height && content_height > 0 {
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"))
            .thumb_symbol("█")
            .track_symbol(Some("│"));

        // Calculate the maximum scroll position (content that can be scrolled through)
        let max_scroll = content_height.saturating_sub(viewport_height);

        // Use the line-based scroll position for scrollbar
        let mut scrollbar_state = ScrollbarState::new(max_scroll).position(scroll_offset_lines);

        // Render scrollbar in the rightmost column of the area
        frame.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
    }
}

/// Render chat with custom constraints and word wrapping
#[allow(dead_code)]
pub fn render_with_constraints(frame: &mut Frame, area: Rect, app: &TuiApp, max_messages: usize) {
    let is_active = app.get_active_panel() == crate::tui::app::Panel::Chat;
    let messages = app.state.get_messages();

    let mut lines = Vec::new();
    let start_idx = messages.len().saturating_sub(max_messages);

    for message in messages.iter().skip(start_idx) {
        let (prefix, style) = match message.role {
            Role::User => (
                "👤 You:",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Role::Assistant => (
                "🤖 Assistant:",
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            ),
            Role::System => (
                "⚙️ System:",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Role::Tool => (
                "🔧 Tool:",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
        };

        // Header with prefix
        lines.push(Line::from(Span::styled(prefix, style)));

        // Content with word wrapping
        for line in message.content.lines() {
            lines.push(Line::from(Span::raw(line.to_string())));
        }

        // Empty line for spacing
        lines.push(Line::from(""));
    }

    // Calculate content height for scrollbar (not used in this function yet)
    let _content_height = lines.len();

    let chat_text = Text::from(lines);

    let chat_paragraph = Paragraph::new(chat_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Chat History ({} messages) ", messages.len()))
                .border_style(if is_active {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default()
                }),
        )
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: false });

    frame.render_widget(chat_paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::state::AppState;
    use crate::types::message::Message;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn create_test_app() -> (TuiApp<'static>, Terminal<TestBackend>) {
        let mut state = AppState::with_defaults(".".to_string());
        state.add_message(Message::user("Hello"));
        state.add_message(Message::assistant("Hi there! How can I help?"));
        let state = Box::leak(Box::new(state));
        let app = TuiApp::new(state);
        let backend = TestBackend::new(80, 24);
        let terminal = Terminal::new(backend).unwrap();
        (app, terminal)
    }

    #[test]
    fn test_chat_render() {
        let (app, mut terminal) = create_test_app();
        let area = Rect::new(0, 0, 80, 20);

        terminal
            .draw(|frame| {
                render(frame, area, &app);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();

        assert!(content.contains("Chat History"));
        assert!(content.contains("You:"));
        assert!(content.contains("Assistant:"));
    }

    #[test]
    fn test_chat_with_many_messages() {
        let mut state = AppState::with_defaults(".".to_string());
        for i in 0..30 {
            state.add_message(Message::user(&format!("Message {}", i)));
            state.add_message(Message::assistant(&format!("Response {}", i)));
        }
        let state = Box::leak(Box::new(state));
        let app = TuiApp::new(state);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| {
                render(frame, Rect::new(0, 0, 80, 20), &app);
            })
            .unwrap();

        // Should render without errors even with many messages
        let buffer = terminal.backend().buffer();
        assert!(!buffer.content().is_empty());
    }

    #[test]
    fn test_chat_with_all_roles() {
        let mut state = AppState::with_defaults(".".to_string());
        state.add_message(Message::user("User message"));
        state.add_message(Message::assistant("Assistant response"));
        state.add_message(Message::system("System message"));
        state.add_message(Message::tool("Tool result", "call_123"));
        let state = Box::leak(Box::new(state));
        let app = TuiApp::new(state);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| {
                render(frame, Rect::new(0, 0, 80, 20), &app);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = buffer.content().iter().map(|c| c.symbol()).collect();

        assert!(content.contains("System:"));
        assert!(content.contains("Tool:"));
    }

    #[test]
    fn test_chat_scroll_offset() {
        let mut state = AppState::with_defaults(".".to_string());
        for i in 0..50 {
            state.add_message(Message::user(&format!("Message {}", i)));
        }
        let state = Box::leak(Box::new(state));
        let mut app = TuiApp::new(state);

        // Set scroll offset
        app.scroll_offset = 10;

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| {
                render(frame, Rect::new(0, 0, 80, 20), &app);
            })
            .unwrap();

        // Should render without errors with scroll offset
    }

    #[test]
    fn test_chat_empty() {
        let state = AppState::with_defaults(".".to_string());
        let state = Box::leak(Box::new(state));
        let app = TuiApp::new(state);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| {
                render(frame, Rect::new(0, 0, 80, 20), &app);
            })
            .unwrap();

        // Should render empty chat without errors
    }

    #[test]
    fn test_chat_active_border() {
        let mut state = AppState::with_defaults(".".to_string());
        state.add_message(Message::user("Test"));
        let state = Box::leak(Box::new(state));
        let mut app = TuiApp::new(state);

        // Set active panel to Chat
        app.active_panel = crate::tui::app::Panel::Chat;

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| {
                render(frame, Rect::new(0, 0, 80, 20), &app);
            })
            .unwrap();

        // Should render with active border
    }
}
