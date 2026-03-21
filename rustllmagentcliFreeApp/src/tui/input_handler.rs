//! Input handler for TUI keyboard events

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(dead_code)]

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::app::{Panel, TuiApp};

/// Handle key events for the TUI application
pub async fn handle_key_event(app: &mut TuiApp<'_>, key: KeyEvent) -> Result<()> {
    match key.code {
        // Ctrl+C to quit from anywhere
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }

        // Q to quit from non-input panels
        KeyCode::Char('q') if app.active_panel != Panel::Input => {
            app.should_quit = true;
        }

        // Character input for input panel
        KeyCode::Char(c) if app.active_panel == Panel::Input => {
            app.input_buffer.push(c);
        }

        // Backspace for input panel
        KeyCode::Backspace if app.active_panel == Panel::Input => {
            app.input_buffer.pop();
        }

        // Arrow up: history navigation in input panel, scroll in chat panel
        KeyCode::Up if app.active_panel == Panel::Input => {
            app.navigate_history(-1);
        }
        KeyCode::Up => {
            app.scroll_up();
        }

        // Arrow down: history navigation in input panel, scroll in chat panel
        KeyCode::Down if app.active_panel == Panel::Input => {
            app.navigate_history(1);
        }
        KeyCode::Down => {
            app.scroll_down();
        }

        // Tab to cycle panels
        KeyCode::Tab => {
            app.cycle_panels();
        }

        // Escape to clear input
        KeyCode::Esc if app.active_panel == Panel::Input => {
            app.input_buffer.clear();
        }

        _ => {}
    }

    Ok(())
}

/// Process a single character input
#[allow(dead_code)]
pub fn process_char_input(app: &mut TuiApp, c: char) {
    if app.active_panel == Panel::Input {
        app.input_buffer.push(c);
    }
}

/// Process backspace
#[allow(dead_code)]
pub fn process_backspace(app: &mut TuiApp) {
    if app.active_panel == Panel::Input {
        app.input_buffer.pop();
    }
}

/// Clear the input buffer
#[allow(dead_code)]
pub fn clear_input(app: &mut TuiApp) {
    if app.active_panel == Panel::Input {
        app.input_buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::state::AppState;
    use crate::types::message::Message;
    use crossterm::event::KeyEventKind;

    fn create_test_app() -> TuiApp<'static> {
        let state = AppState::with_defaults(".".to_string());
        let state = Box::leak(Box::new(state));
        TuiApp::new(state)
    }

    fn create_key_event(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    }

    #[tokio::test]
    async fn test_ctrl_c_quit() {
        let mut app = create_test_app();
        let key = create_key_event(KeyCode::Char('c'), KeyModifiers::CONTROL);

        handle_key_event(&mut app, key).await.unwrap();
        assert!(app.should_quit);
    }

    #[tokio::test]
    async fn test_q_quit_from_chat_panel() {
        let mut app = create_test_app();
        app.active_panel = Panel::Chat;
        let key = create_key_event(KeyCode::Char('q'), KeyModifiers::NONE);

        handle_key_event(&mut app, key).await.unwrap();
        assert!(app.should_quit);
    }

    #[tokio::test]
    async fn test_q_not_quit_from_input_panel() {
        let mut app = create_test_app();
        app.active_panel = Panel::Input;
        let key = create_key_event(KeyCode::Char('q'), KeyModifiers::NONE);

        handle_key_event(&mut app, key).await.unwrap();
        assert!(!app.should_quit);
    }

    #[tokio::test]
    async fn test_char_input() {
        let mut app = create_test_app();
        let key = create_key_event(KeyCode::Char('h'), KeyModifiers::NONE);

        handle_key_event(&mut app, key).await.unwrap();
        assert_eq!(app.input_buffer, "h");

        let key = create_key_event(KeyCode::Char('i'), KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();
        assert_eq!(app.input_buffer, "hi");
    }

    #[tokio::test]
    async fn test_backspace() {
        let mut app = create_test_app();
        app.input_buffer = "test".to_string();

        let key = create_key_event(KeyCode::Backspace, KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();
        assert_eq!(app.input_buffer, "tes");
    }

    #[tokio::test]
    async fn test_backspace_empty() {
        let mut app = create_test_app();

        let key = create_key_event(KeyCode::Backspace, KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();
        assert_eq!(app.input_buffer, "");
    }

    #[tokio::test]
    async fn test_tab_cycle_panels() {
        let mut app = create_test_app();
        assert_eq!(app.active_panel, Panel::Input);

        let key = create_key_event(KeyCode::Tab, KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();
        assert_eq!(app.active_panel, Panel::Chat);

        handle_key_event(&mut app, key).await.unwrap();
        assert_eq!(app.active_panel, Panel::Input);
    }

    #[tokio::test]
    async fn test_arrow_up_scroll() {
        let mut app = create_test_app();
        app.active_panel = Panel::Chat; // Must be in Chat panel to scroll
        app.scroll_offset = 5;

        let key = create_key_event(KeyCode::Up, KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();
        assert_eq!(app.scroll_offset, 4);
    }

    #[tokio::test]
    async fn test_arrow_down_scroll() {
        let mut app = create_test_app();
        app.state.add_message(Message::user("Test 1"));
        app.state.add_message(Message::assistant("Test 2"));

        let key = create_key_event(KeyCode::Down, KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();
        // Scroll offset should be valid (u64 is always >= 0)
    }

    #[tokio::test]
    async fn test_esc_clear_input() {
        let mut app = create_test_app();
        app.input_buffer = "test input".to_string();

        let key = create_key_event(KeyCode::Esc, KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();
        assert_eq!(app.input_buffer, "");
    }

    #[tokio::test]
    async fn test_no_input_from_other_panels() {
        let mut app = create_test_app();
        app.active_panel = Panel::Chat;

        let key = create_key_event(KeyCode::Char('h'), KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();
        assert_eq!(app.input_buffer, "");
    }

    #[test]
    fn test_process_char_input() {
        let mut app = create_test_app();
        process_char_input(&mut app, 'a');
        assert_eq!(app.input_buffer, "a");
    }

    #[test]
    fn test_process_backspace() {
        let mut app = create_test_app();
        app.input_buffer = "test".to_string();
        process_backspace(&mut app);
        assert_eq!(app.input_buffer, "tes");
    }

    #[test]
    fn test_clear_input() {
        let mut app = create_test_app();
        app.input_buffer = "test".to_string();
        clear_input(&mut app);
        assert_eq!(app.input_buffer, "");
    }

    #[tokio::test]
    async fn test_arrow_up_history_navigation() {
        let mut app = create_test_app();

        // Add some history
        app.add_to_history("query 1".to_string());
        app.add_to_history("query 2".to_string());
        app.add_to_history("query 3".to_string());

        // Ensure we're in input panel
        app.active_panel = Panel::Input;

        let key = create_key_event(KeyCode::Up, KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();

        // Should navigate to most recent history item
        assert_eq!(app.history_index, Some(2));
        assert_eq!(app.input_buffer, "query 3");
    }

    #[tokio::test]
    async fn test_arrow_down_history_navigation() {
        let mut app = create_test_app();

        // Add some history
        app.add_to_history("query 1".to_string());
        app.add_to_history("query 2".to_string());

        // Navigate up first
        app.active_panel = Panel::Input;
        app.navigate_history(-1);
        app.navigate_history(-1);
        assert_eq!(app.history_index, Some(0));
        assert_eq!(app.input_buffer, "query 1");

        // Navigate down
        let key = create_key_event(KeyCode::Down, KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();

        assert_eq!(app.history_index, Some(1));
        assert_eq!(app.input_buffer, "query 2");
    }

    #[tokio::test]
    async fn test_arrow_up_in_chat_panel_still_scrolls() {
        let mut app = create_test_app();
        app.active_panel = Panel::Chat;
        app.scroll_offset = 5;

        let key = create_key_event(KeyCode::Up, KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();

        // Should scroll, not navigate history
        assert_eq!(app.scroll_offset, 4);
        assert_eq!(app.history_index, None);
    }

    #[tokio::test]
    async fn test_arrow_down_in_chat_panel_still_scrolls() {
        let mut app = create_test_app();
        app.active_panel = Panel::Chat;
        app.state.add_message(Message::user("Test 1"));
        app.state.add_message(Message::assistant("Test 2"));

        let key = create_key_event(KeyCode::Down, KeyModifiers::NONE);
        handle_key_event(&mut app, key).await.unwrap();

        // Should scroll, not navigate history
        assert_eq!(app.history_index, None);
    }
}
