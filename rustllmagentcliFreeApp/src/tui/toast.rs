//! Toast notification system for critical alerts
//!
//! Provides a simple toast notification widget for displaying important messages
//! such as API token expiration warnings.

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::unchecked_time_subtraction)]
#![allow(clippy::uninlined_format_args)]

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use std::time::{Duration, Instant};

/// Toast notification types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastType {
    /// Informational message
    Info,
    /// Warning message (e.g., token expiring soon)
    Warning,
    /// Error message (e.g., token expired)
    Error,
    /// Success message
    Success,
}

impl ToastType {
    /// Get the color for this toast type
    fn color(&self) -> Color {
        match self {
            ToastType::Info => Color::Blue,
            ToastType::Warning => Color::Yellow,
            ToastType::Error => Color::Red,
            ToastType::Success => Color::Green,
        }
    }

    /// Get the icon prefix for this toast type
    fn icon(&self) -> &'static str {
        match self {
            ToastType::Info => "ℹ️",
            ToastType::Warning => "⚠️",
            ToastType::Error => "❌",
            ToastType::Success => "✅",
        }
    }
}

/// A toast notification
#[derive(Debug, Clone)]
pub struct Toast {
    /// The message to display
    pub message: String,
    /// The type of toast
    pub toast_type: ToastType,
    /// When this toast was created
    pub created_at: Instant,
    /// How long this toast should be displayed
    pub duration: Duration,
}

impl Toast {
    /// Create a new toast notification
    pub fn new(message: impl Into<String>, toast_type: ToastType, duration: Duration) -> Self {
        Self {
            message: message.into(),
            toast_type,
            created_at: Instant::now(),
            duration,
        }
    }

    /// Create an info toast
    pub fn info(message: impl Into<String>) -> Self {
        Self::new(message, ToastType::Info, Duration::from_secs(5))
    }

    /// Create a warning toast
    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(message, ToastType::Warning, Duration::from_secs(10))
    }

    /// Create an error toast
    pub fn error(message: impl Into<String>) -> Self {
        Self::new(message, ToastType::Error, Duration::from_secs(10))
    }

    /// Create a success toast
    pub fn success(message: impl Into<String>) -> Self {
        Self::new(message, ToastType::Success, Duration::from_secs(5))
    }

    /// Check if this toast has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.duration
    }

    /// Get remaining time in seconds
    pub fn remaining_secs(&self) -> u64 {
        let elapsed = self.created_at.elapsed();
        if elapsed >= self.duration {
            0
        } else {
            (self.duration - elapsed).as_secs()
        }
    }
}

/// Toast notification manager
#[derive(Debug, Default)]
pub struct ToastManager {
    /// Active toasts (newest first)
    toasts: Vec<Toast>,
    /// Maximum number of toasts to display at once
    max_toasts: usize,
}

impl ToastManager {
    /// Create a new toast manager
    pub fn new() -> Self {
        Self {
            toasts: Vec::new(),
            max_toasts: 3,
        }
    }

    /// Add a toast notification
    pub fn add(&mut self, toast: Toast) {
        self.toasts.insert(0, toast);
        // Keep only the most recent toasts
        if self.toasts.len() > self.max_toasts {
            self.toasts.truncate(self.max_toasts);
        }
    }

    /// Add an info toast
    pub fn info(&mut self, message: impl Into<String>) {
        self.add(Toast::info(message));
    }

    /// Add a warning toast
    pub fn warning(&mut self, message: impl Into<String>) {
        self.add(Toast::warning(message));
    }

    /// Add an error toast
    pub fn error(&mut self, message: impl Into<String>) {
        self.add(Toast::error(message));
    }

    /// Add a success toast
    pub fn success(&mut self, message: impl Into<String>) {
        self.add(Toast::success(message));
    }

    /// Remove expired toasts
    pub fn cleanup(&mut self) {
        self.toasts.retain(|toast| !toast.is_expired());
    }

    /// Get active toasts
    pub fn active_toasts(&self) -> &[Toast] {
        &self.toasts
    }

    /// Check if there are any active toasts
    pub fn has_toasts(&self) -> bool {
        !self.toasts.is_empty()
    }

    /// Clear all toasts
    pub fn clear(&mut self) {
        self.toasts.clear();
    }

    /// Render toasts on the screen (bottom-right corner)
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        if self.toasts.is_empty() {
            return;
        }

        // Calculate toast area (bottom-right, max 40% of screen width, 30% height)
        let toast_width = (area.width * 2 / 5).min(60);
        let toast_height = (area.height / 4).min(10);

        let toast_area = Rect::new(
            area.x + area.width - toast_width - 2,
            area.y + area.height - toast_height - 2,
            toast_width,
            toast_height,
        );

        // Clear the area
        frame.render_widget(Clear, toast_area);

        // Render each toast
        let mut current_y = toast_area.y;
        for toast in &self.toasts {
            let toast_height = 3u16; // Fixed height per toast
            if current_y + toast_height > toast_area.y + toast_area.height {
                break;
            }

            let toast_rect = Rect::new(
                toast_area.x,
                current_y,
                toast_area.width,
                toast_height,
            );

            // Create toast content
            let icon = toast.toast_type.icon();
            let color = toast.toast_type.color();

            let paragraph = Paragraph::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(color)),
                Span::raw(" "),
                Span::raw(&toast.message),
            ]))
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(color).add_modifier(Modifier::BOLD))
                    .title(format!(" {} ", toast.toast_type.as_str())),
            )
            .wrap(Wrap { trim: true });

            frame.render_widget(paragraph, toast_rect);
            current_y += toast_height;
        }
    }
}

impl ToastType {
    fn as_str(&self) -> &'static str {
        match self {
            ToastType::Info => "INFO",
            ToastType::Warning => "WARNING",
            ToastType::Error => "ERROR",
            ToastType::Success => "SUCCESS",
        }
    }
}

/// Check Bitquery token expiration and add appropriate toast
///
/// # Arguments
/// * `toast_manager` - The toast manager to add notifications to
/// * `expire_str` - The expiration timestamp string (format: "YYYY-MM-DD HH:MM:SS")
///
/// # Returns
/// * `true` if token is expired or expiring soon
/// * `false` if token is valid with sufficient time remaining
pub fn check_bitquery_expiration(toast_manager: &mut ToastManager, expire_str: Option<&str>) -> bool {
    let Some(expire_str) = expire_str else {
        // No expiration set - can't check
        return false;
    };

    // Parse the expiration timestamp
    // Expected format: "2026-03-10 18:38:18"
    let expire_datetime = match chrono::NaiveDateTime::parse_from_str(expire_str, "%Y-%m-%d %H:%M:%S") {
        Ok(dt) => dt,
        Err(e) => {
            toast_manager.error(format!("Failed to parse Bitquery expiration: {}", e));
            return false;
        }
    };

    // Convert to chrono DateTime with UTC
    let expire_utc = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(expire_datetime, chrono::Utc);
    let now_utc = chrono::Utc::now();

    let duration_until_expire = expire_utc - now_utc;

    if duration_until_expire.num_seconds() <= 0 {
        // Token already expired
        toast_manager.error("Bitquery API token has EXPIRED! Update BITQUERY_API_TOKEN_EXPIRE in .env");
        true
    } else if duration_until_expire.num_hours() < 24 {
        // Token expires within 24 hours
        let hours = duration_until_expire.num_hours();
        let mins = (duration_until_expire.num_minutes() % 60).abs();
        toast_manager.warning(
            format!("Bitquery API token expires in {hours}h {mins}m! Update BITQUERY_API_TOKEN_EXPIRE in .env")
        );
        true
    } else {
        // Token is valid
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toast_creation() {
        let toast = Toast::info("Test message");
        assert_eq!(toast.message, "Test message");
        assert_eq!(toast.toast_type, ToastType::Info);
        assert!(!toast.is_expired());
    }

    #[test]
    fn test_toast_expiration() {
        let mut toast = Toast::info("Test message");
        toast.duration = Duration::from_millis(10);
        
        std::thread::sleep(Duration::from_millis(20));
        assert!(toast.is_expired());
    }

    #[test]
    fn test_toast_manager() {
        let mut manager = ToastManager::new();
        
        manager.info("Info message");
        manager.warning("Warning message");
        manager.error("Error message");
        
        assert_eq!(manager.active_toasts().len(), 3);
        assert!(manager.has_toasts());
        
        manager.cleanup();
        assert_eq!(manager.active_toasts().len(), 3); // None expired yet
        
        manager.clear();
        assert!(!manager.has_toasts());
    }

    #[test]
    fn test_toast_type_colors() {
        assert_eq!(ToastType::Info.color(), Color::Blue);
        assert_eq!(ToastType::Warning.color(), Color::Yellow);
        assert_eq!(ToastType::Error.color(), Color::Red);
        assert_eq!(ToastType::Success.color(), Color::Green);
    }
}
