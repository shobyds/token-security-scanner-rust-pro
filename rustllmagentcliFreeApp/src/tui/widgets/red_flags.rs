//! Red Flags Widget for displaying red and green flags
//!
//! This widget renders a scrollable list of red and green flags.

#![allow(clippy::module_name_repetitions)]

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::scanner::{GreenFlag, RedFlag, TriResult};

/// Red Flags List widget for displaying flags
pub struct RedFlagsList<'a> {
    pub tri_result: &'a TriResult,
    pub scroll_offset: usize,
}

impl<'a> RedFlagsList<'a> {
    /// Create a new red flags list
    #[must_use]
    pub fn new(tri_result: &'a TriResult) -> Self {
        Self {
            tri_result,
            scroll_offset: 0,
        }
    }

    /// Render the red flags list
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let mut items = Vec::new();

        // Add red flags
        for flag in &self.tri_result.red_flags {
            let item_text = Self::format_red_flag(flag);
            items.push(ListItem::new(Line::from(vec![
                Span::styled("⛔ ", Style::default().fg(Color::Red)),
                Span::raw(item_text),
            ])));
        }

        // Add green flags
        for flag in &self.tri_result.green_flags {
            let item_text = Self::format_green_flag(flag);
            items.push(ListItem::new(Line::from(vec![
                Span::styled("✅ ", Style::default().fg(Color::Green)),
                Span::raw(item_text),
            ])));
        }

        // Handle empty case
        if items.is_empty() {
            items.push(ListItem::new(Line::from(Span::raw("No flags detected"))));
        }

        // Apply scroll offset
        let visible_items: Vec<ListItem> = items
            .iter()
            .skip(self.scroll_offset)
            .cloned()
            .collect();

        let list = List::new(visible_items)
            .block(
                Block::default()
                    .title(format!(
                        " Flags ({}/{}) ",
                        self.tri_result.red_flag_count(),
                        self.tri_result.green_flag_count()
                    ))
                    .borders(Borders::ALL),
            );

        frame.render_widget(list, area);
    }

    /// Format a red flag for display
    fn format_red_flag(flag: &RedFlag) -> String {
        format!("[{}] {} (w: {:.2})", flag.category, flag.description, flag.weight)
    }

    /// Format a green flag for display
    fn format_green_flag(flag: &GreenFlag) -> String {
        format!("[{}] {}", flag.category, flag.description)
    }

    /// Scroll up (decrease offset)
    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
        }
    }

    /// Scroll down (increase offset)
    pub fn scroll_down(&mut self, max_items: usize) {
        let total_items = self.tri_result.red_flag_count() + self.tri_result.green_flag_count();
        if total_items == 0 {
            return;
        }
        let max_offset = total_items.saturating_sub(max_items);
        if self.scroll_offset < max_offset {
            self.scroll_offset += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tri_result() -> TriResult {
        use std::time::{SystemTime, UNIX_EPOCH};
        TriResult {
            token_address: "0x1234".to_string(),
            chain: "ethereum".to_string(),
            contract_risk: 40.0,
            lp_score: 20.0,
            ownership_risk: 30.0,
            tax_risk: 15.0,
            honeypot_risk: 10.0,
            volume_risk: 5.0,
            dev_behavior: 0.0,
            age_risk: 2.0,
            tri: 25.5,
            tri_label: crate::scanner::TriLabel::ModerateRisk,
            red_flags: vec![
                RedFlag::new("Contract", "Owner can mint", 0.7),
                RedFlag::new("Liquidity", "LP not locked", 0.6),
            ],
            green_flags: vec![GreenFlag::new("Age", "Token is 7 days old")],
            computed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    #[test]
    fn test_format_red_flag() {
        let flag = RedFlag::new("Contract", "Owner can mint", 0.7);
        let formatted = RedFlagsList::format_red_flag(&flag);
        assert!(formatted.contains("[Contract]"));
        assert!(formatted.contains("Owner can mint"));
        assert!(formatted.contains("w: 0.70"));
    }

    #[test]
    fn test_format_green_flag() {
        let flag = GreenFlag::new("Age", "Token is 7 days old");
        let formatted = RedFlagsList::format_green_flag(&flag);
        assert!(formatted.contains("[Age]"));
        assert!(formatted.contains("Token is 7 days old"));
    }

    #[test]
    fn test_scroll_up() {
        let tri_result = create_test_tri_result();
        let mut list = RedFlagsList::new(&tri_result);
        list.scroll_offset = 5;
        list.scroll_up();
        assert_eq!(list.scroll_offset, 4);
    }

    #[test]
    fn test_scroll_down() {
        let tri_result = create_test_tri_result();
        let mut list = RedFlagsList::new(&tri_result);
        list.scroll_offset = 0;
        list.scroll_down(10);
        assert_eq!(list.scroll_offset, 1);
    }

    #[test]
    fn test_scroll_bounds() {
        let tri_result = create_test_tri_result();
        let mut list = RedFlagsList::new(&tri_result);
        
        // Can't scroll up past 0
        list.scroll_up();
        assert_eq!(list.scroll_offset, 0);
        
        // Can't scroll down past max
        list.scroll_down(100);
        assert!(list.scroll_offset <= 3); // 3 total flags
    }
}
