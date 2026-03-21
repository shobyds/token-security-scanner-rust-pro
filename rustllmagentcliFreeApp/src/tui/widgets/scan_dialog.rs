//! Scan Confirmation Dialog Widget for TUI

#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::useless_format)]
#![allow(clippy::uninlined_format_args)]

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};

use crate::tools::scanner::token_scanner::{ApiProviderStatus, ScanConfirmationDialog, ScanOption};

/// State for the scan confirmation dialog
pub struct ScanDialogState {
    /// Whether dialog is visible
    pub visible: bool,
    /// The dialog data
    pub dialog: Option<ScanConfirmationDialog>,
    /// Selected option index
    pub selected_option: usize,
    /// Confirmed options
    pub confirmed_options: Vec<bool>,
    /// User has confirmed
    pub confirmed: bool,
    /// User has cancelled
    pub cancelled: bool,
}

impl Default for ScanDialogState {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanDialogState {
    pub fn new() -> Self {
        Self {
            visible: false,
            dialog: None,
            selected_option: 0,
            confirmed_options: vec![],
            confirmed: false,
            cancelled: false,
        }
    }

    pub fn show(&mut self, dialog: ScanConfirmationDialog) {
        self.dialog = Some(dialog);
        self.confirmed_options = vec![false; self.dialog.as_ref().unwrap().options.len()];
        self.visible = true;
        self.confirmed = false;
        self.cancelled = false;
        self.selected_option = 0;
    }

    pub fn hide(&mut self) {
        self.visible = false;
        self.dialog = None;
    }

    pub fn toggle_option(&mut self) {
        if self.selected_option < self.confirmed_options.len() {
            self.confirmed_options[self.selected_option] =
                !self.confirmed_options[self.selected_option];
        }
    }

    pub fn select_next(&mut self) {
        if let Some(dialog) = &self.dialog {
            if self.selected_option < dialog.options.len() - 1 {
                self.selected_option += 1;
            }
        }
    }

    pub fn select_previous(&mut self) {
        if self.selected_option > 0 {
            self.selected_option -= 1;
        }
    }

    pub fn confirm(&mut self) {
        self.confirmed = true;
        self.visible = false;
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.visible = false;
    }
}

/// Render the scan confirmation dialog
pub fn render_scan_dialog(frame: &mut Frame, state: &ScanDialogState, area: Rect) {
    if !state.visible || state.dialog.is_none() {
        return;
    }

    let dialog = state.dialog.as_ref().unwrap();

    // Create centered popup area
    let popup_area = centered_rect(70, 70, area);

    // Clear the area behind the dialog
    frame.render_widget(Clear, popup_area);

    // Main block
    let block = Block::default()
        .title(" 🔍 Token Scan Confirmation ")
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Rgb(30, 30, 46)).fg(Color::Cyan));

    frame.render_widget(block, popup_area);

    // Inner area for content
    let inner = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Token info
            Constraint::Length(3), // Chain info
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // API Status header
            Constraint::Length(7), // API Status list (5 providers + borders)
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Options header
            Constraint::Min(6),    // Options list
            Constraint::Length(1), // Instructions
        ])
        .split(popup_area);

    // Token address
    let token_text = format!("Token: {}", dialog.token_address);
    let token_widget = Paragraph::new(token_text)
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Token Address"),
        );
    frame.render_widget(token_widget, inner[0]);

    // Chain
    let chain_text = format!(
        "Chain: {} | Est. Time: {}s",
        dialog.chain, dialog.estimated_time_secs
    );
    let chain_widget = Paragraph::new(chain_text)
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Scan Configuration"),
        );
    frame.render_widget(chain_widget, inner[1]);

    // API Provider Status
    let api_header = Paragraph::new("API Provider Status:").style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(api_header, inner[3]);

    let api_items: Vec<ListItem> = dialog
        .provider_status
        .iter()
        .map(|provider| {
            let status_icon = if provider.available { "✅" } else { "❌" };
            let key_status = if provider.has_api_key {
                "🔑"
            } else {
                "⚠️"
            };
            let color = if provider.available {
                Color::Green
            } else {
                Color::Red
            };

            ListItem::new(Line::from(vec![
                Span::raw(format!("{} {} ", status_icon, provider.name)),
                Span::styled(
                    format!("({}) ", provider.message),
                    Style::default().fg(color),
                ),
                Span::raw(format!("{}", key_status)),
            ]))
        })
        .collect();

    let api_list = List::new(api_items).block(Block::default().borders(Borders::ALL));
    frame.render_widget(api_list, inner[4]);

    // Options header
    let options_header = Paragraph::new("Scan Options (toggle with Space):").style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(options_header, inner[6]);

    // Options list
    let option_items: Vec<ListItem> = dialog
        .options
        .iter()
        .enumerate()
        .map(|(i, opt)| {
            let checkbox = if state.confirmed_options[i] {
                "[✅]"
            } else {
                "[ ] "
            };
            let selected_style = if i == state.selected_option {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let value = match opt.name.as_str() {
                "format" => dialog.options[i].default_value.clone(),
                "include_market_data" => if state.confirmed_options[i] {
                    "true"
                } else {
                    "false"
                }
                .to_string(),
                _ => opt.default_value.clone(),
            };

            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", checkbox), selected_style),
                Span::styled(format!("{}: ", opt.name), selected_style),
                Span::raw(format!("{} ({})", value, opt.description)),
            ]))
        })
        .collect();

    let option_list = List::new(option_items).block(Block::default().borders(Borders::ALL));
    frame.render_widget(option_list, inner[7]);

    // Instructions
    let instructions = Paragraph::new(Line::from(vec![
        Span::styled("↑/↓ ", Style::default().fg(Color::Yellow)),
        Span::raw("Navigate  "),
        Span::styled("Space ", Style::default().fg(Color::Yellow)),
        Span::raw("Toggle  "),
        Span::styled("Enter ", Style::default().fg(Color::Green)),
        Span::raw("Confirm  "),
        Span::styled("Esc ", Style::default().fg(Color::Red)),
        Span::raw("Cancel"),
    ]))
    .style(Style::default().fg(Color::Gray))
    .alignment(Alignment::Center);
    frame.render_widget(instructions, inner[8]);
}

/// Helper function to create a centered rect
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
