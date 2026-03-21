//! TRI Gauge Widget for displaying TRI score as a progress bar
//!
//! This widget renders a horizontal progress bar that color-codes the TRI score.

#![allow(clippy::module_name_repetitions)]

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, Gauge},
};

use crate::scanner::{TriLabel, TriResult};

/// TRI Gauge widget for displaying TRI score
pub struct TriGauge<'a> {
    pub tri_result: &'a TriResult,
}

impl<'a> TriGauge<'a> {
    /// Create a new TRI gauge
    #[must_use]
    pub fn new(tri_result: &'a TriResult) -> Self {
        Self { tri_result }
    }

    /// Get the color for the TRI score based on risk level
    fn get_tri_color(score: f32) -> Color {
        if score < 25.0 {
            Color::Green
        } else if score < 45.0 {
            Color::Yellow
        } else if score < 65.0 {
            Color::Rgb(255, 140, 0) // Orange for High Risk
        } else {
            Color::Red
        }
    }

    /// Get the emoji for the TRI label
    fn get_tri_emoji(label: &TriLabel) -> &'static str {
        match label {
            TriLabel::VerySafe => "🟢",
            TriLabel::ModerateRisk => "🟡",
            TriLabel::HighRisk => "🟠",
            TriLabel::Avoid => "🔴",
        }
    }

    /// Render the TRI gauge
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let score = self.tri_result.tri;
        let label = &self.tri_result.tri_label;
        let emoji = Self::get_tri_emoji(label);
        let color = Self::get_tri_color(score);

        // Create gauge with ratio (0.0 to 1.0)
        #[allow(clippy::cast_possible_truncation)]
        let ratio = f64::from((score / 100.0).clamp(0.0, 1.0));

        let gauge = Gauge::default()
            .block(
                Block::default()
                    .title(format!(" TRI Score {emoji} "))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(color)),
            )
            .gauge_style(Style::default().fg(color))
            .ratio(ratio)
            .label(format!("{:.1}/100 [{}]", score, label.display()));

        frame.render_widget(gauge, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tri_color_very_safe() {
        assert_eq!(TriGauge::get_tri_color(0.0), Color::Green);
        assert_eq!(TriGauge::get_tri_color(24.9), Color::Green);
    }

    #[test]
    fn test_get_tri_color_moderate() {
        assert_eq!(TriGauge::get_tri_color(25.0), Color::Yellow);
        assert_eq!(TriGauge::get_tri_color(44.9), Color::Yellow);
    }

    #[test]
    fn test_get_tri_color_high_risk() {
        assert_eq!(TriGauge::get_tri_color(45.0), Color::Rgb(255, 140, 0));
        assert_eq!(TriGauge::get_tri_color(64.9), Color::Rgb(255, 140, 0));
    }

    #[test]
    fn test_get_tri_color_avoid() {
        assert_eq!(TriGauge::get_tri_color(65.0), Color::Red);
        assert_eq!(TriGauge::get_tri_color(100.0), Color::Red);
    }

    #[test]
    fn test_get_tri_emoji() {
        assert_eq!(TriGauge::get_tri_emoji(&TriLabel::VerySafe), "🟢");
        assert_eq!(TriGauge::get_tri_emoji(&TriLabel::ModerateRisk), "🟡");
        assert_eq!(TriGauge::get_tri_emoji(&TriLabel::HighRisk), "🟠");
        assert_eq!(TriGauge::get_tri_emoji(&TriLabel::Avoid), "🔴");
    }
}
