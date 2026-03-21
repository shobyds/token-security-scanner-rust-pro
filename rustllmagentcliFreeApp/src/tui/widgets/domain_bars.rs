//! Domain Bars Widget for displaying all 8 domain scores
//!
//! This widget renders a bar chart showing all domain risk scores.

#![allow(clippy::module_name_repetitions)]

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::scanner::TriResult;

/// Domain Bars widget for displaying all domain scores
pub struct DomainBars<'a> {
    pub tri_result: &'a TriResult,
}

impl<'a> DomainBars<'a> {
    /// Create a new domain bars widget
    #[must_use]
    pub fn new(tri_result: &'a TriResult) -> Self {
        Self { tri_result }
    }

    /// Get the color for a domain score
    fn get_score_color(score: f32) -> Color {
        if score < 30.0 {
            Color::Green
        } else if score < 50.0 {
            Color::Yellow
        } else {
            Color::Red
        }
    }

    /// Create a bar string for a given score
    fn create_bar(score: f32, width: usize) -> String {
        #[allow(clippy::cast_sign_loss)]
        #[allow(clippy::cast_precision_loss)]
        #[allow(clippy::cast_possible_truncation)]
        let filled = ((score / 100.0) * width as f32).round() as usize;
        let empty = width.saturating_sub(filled);
        format!("{}{}", "█".repeat(filled), "░".repeat(empty))
    }

    /// Render the domain bars
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let tri = self.tri_result;

        // Domain names and their scores
        let domains = vec![
            ("Contract", tri.contract_risk),
            ("Ownership", tri.ownership_risk),
            ("LP Score", tri.lp_score),
            ("Tax Risk", tri.tax_risk),
            ("Honeypot", tri.honeypot_risk),
            ("Volume", tri.volume_risk),
            ("Dev Behavior", tri.dev_behavior),
            ("Age Risk", tri.age_risk),
        ];

        // Calculate bar width (reserve space for name and score)
        let bar_width = area.width.saturating_sub(20) as usize;
        let bar_width = bar_width.max(10); // Minimum bar width

        // Build lines for each domain
        let mut lines = Vec::new();
        for (name, score) in domains {
            let color = Self::get_score_color(score);
            let bar = Self::create_bar(score, bar_width);
            
            let line = Line::from(vec![
                Span::raw(format!("{name:<12} ")),
                Span::styled(bar, Style::default().fg(color)),
                Span::raw(format!(" {score:>5.1}")),
            ]);
            lines.push(line);
        }

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" Domain Scores ")
                    .borders(Borders::ALL),
            );

        frame.render_widget(paragraph, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_score_color() {
        assert_eq!(DomainBars::get_score_color(0.0), Color::Green);
        assert_eq!(DomainBars::get_score_color(29.9), Color::Green);
        assert_eq!(DomainBars::get_score_color(30.0), Color::Yellow);
        assert_eq!(DomainBars::get_score_color(49.9), Color::Yellow);
        assert_eq!(DomainBars::get_score_color(50.0), Color::Red);
        assert_eq!(DomainBars::get_score_color(100.0), Color::Red);
    }

    #[test]
    fn test_create_bar_full() {
        let bar = DomainBars::create_bar(100.0, 20);
        assert_eq!(bar, "████████████████████");
    }

    #[test]
    fn test_create_bar_empty() {
        let bar = DomainBars::create_bar(0.0, 20);
        assert_eq!(bar, "░░░░░░░░░░░░░░░░░░░░");
    }

    #[test]
    fn test_create_bar_half() {
        let bar = DomainBars::create_bar(50.0, 20);
        assert_eq!(bar, "██████████░░░░░░░░░░");
    }
}
