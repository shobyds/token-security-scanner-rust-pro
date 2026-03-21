//! LLM Insight Panel Widget for displaying Groq LLM analysis
//!
//! This widget renders the Groq LLM analysis with recommendation badge.

#![allow(clippy::module_name_repetitions)]

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::llm::LlmAnalysis;

/// LLM Insight Panel widget for displaying Groq analysis
pub struct LlmInsightPanel<'a> {
    pub analysis: Option<&'a LlmAnalysis>,
    pub rug_probability: f32,
    pub threshold: f32,
}

impl<'a> LlmInsightPanel<'a> {
    /// Create a new LLM insight panel
    #[must_use]
    pub fn new(
        analysis: Option<&'a LlmAnalysis>,
        rug_probability: f32,
        threshold: f32,
    ) -> Self {
        Self {
            analysis,
            rug_probability,
            threshold,
        }
    }

    /// Get the color for the recommendation
    fn get_recommendation_color(recommendation: &crate::llm::LlmRecommendation) -> Color {
        match recommendation {
            crate::llm::LlmRecommendation::Avoid => Color::Red,
            crate::llm::LlmRecommendation::Caution => Color::Yellow,
            crate::llm::LlmRecommendation::Safe => Color::Green,
        }
    }

    /// Render the LLM insight panel
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let mut lines = Vec::new();

        if let Some(analysis) = self.analysis {
            // Header with model info
            lines.push(Line::from(Span::styled(
                "🤖 Groq AI Analysis (llama-3.1-8b-instant)",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));

            // Recommendation badge
            let emoji = analysis.recommendation.emoji();
            let display = analysis.recommendation.display();
            let color = Self::get_recommendation_color(&analysis.recommendation);
            
            lines.push(Line::from(vec![
                Span::raw("Recommendation: "),
                Span::styled(
                    format!("{emoji} {display}"),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
            ]));

            // Confidence level
            #[allow(clippy::cast_sign_loss)]
            #[allow(clippy::cast_possible_truncation)]
            let confidence_pct = (analysis.confidence_level * 100.0).round() as u32;
            lines.push(Line::from(format!("Confidence: {confidence_pct}%")));
            lines.push(Line::from(""));

            // Explanation
            lines.push(Line::from(Span::styled(
                "Analysis:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            
            // Word wrap the explanation
            let explanation_lines = textwrap::wrap(&analysis.explanation, area.width.saturating_sub(2) as usize);
            for line in explanation_lines {
                lines.push(Line::from(Span::raw(line.to_string())));
            }
            lines.push(Line::from(""));

            // LLM Red Flags
            if !analysis.red_flags.is_empty() {
                lines.push(Line::from(Span::styled(
                    "Red Flags:",
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                for flag in &analysis.red_flags {
                    lines.push(Line::from(vec![
                        Span::raw("  • "),
                        Span::raw(flag.clone()),
                    ]));
                }
            }
        } else {
            // No LLM analysis available
            lines.push(Line::from(Span::styled(
                "⚠️ Groq LLM Analysis",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));

            let rug_pct = self.rug_probability * 100.0;
            let threshold_pct = self.threshold * 100.0;

            lines.push(Line::from(format!("Rug Probability: {rug_pct:.1}%")));
            lines.push(Line::from(format!("Threshold: {threshold_pct:.1}%")));
            lines.push(Line::from(""));

            if rug_pct < threshold_pct {
                lines.push(Line::from(Span::raw(
                    "Groq analysis not triggered — rug probability below threshold.",
                )));
            } else {
                lines.push(Line::from(Span::raw(
                    "Groq analysis failed — check API key and connectivity.",
                )));
            }
        }

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" AI Insight ")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false });

        frame.render_widget(paragraph, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_analysis() -> LlmAnalysis {
        LlmAnalysis {
            explanation: "This token shows multiple high-risk indicators including unlocked LP and owner mint capability.".to_string(),
            red_flags: vec![
                "High sell tax".to_string(),
                "Honeypot risk".to_string(),
                "Low liquidity".to_string(),
            ],
            recommendation: crate::llm::LlmRecommendation::Avoid,
            confidence_level: 0.87,
        }
    }

    #[test]
    fn test_get_recommendation_color() {
        assert_eq!(
            LlmInsightPanel::get_recommendation_color(&crate::llm::LlmRecommendation::Avoid),
            Color::Red
        );
        assert_eq!(
            LlmInsightPanel::get_recommendation_color(&crate::llm::LlmRecommendation::Caution),
            Color::Yellow
        );
        assert_eq!(
            LlmInsightPanel::get_recommendation_color(&crate::llm::LlmRecommendation::Safe),
            Color::Green
        );
    }

    #[test]
    fn test_llm_insight_panel_with_analysis() {
        let analysis = create_test_analysis();
        let panel = LlmInsightPanel::new(Some(&analysis), 0.6, 0.35);
        
        assert!(panel.analysis.is_some());
        assert!((panel.rug_probability - 0.6).abs() < 0.01);
        assert!((panel.threshold - 0.35).abs() < 0.01);
    }

    #[test]
    fn test_llm_insight_panel_without_analysis() {
        let panel = LlmInsightPanel::new(None, 0.2, 0.35);
        
        assert!(panel.analysis.is_none());
        assert!((panel.rug_probability - 0.2).abs() < 0.01);
    }
}
