//! Output formatting utilities

#![allow(clippy::must_use_candidate)]

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Truncate a string to a maximum width, adding ellipsis if needed
#[allow(dead_code)]
pub fn truncate_str(s: &str, max_width: usize) -> String {
    if s.width() <= max_width {
        return s.to_string();
    }

    let mut result = String::with_capacity(max_width + 1);
    let mut current_width = 0;

    for c in s.chars() {
        let char_width = c.width().unwrap_or(0);
        if current_width + char_width > max_width - 1 {
            break;
        }
        result.push(c);
        current_width += char_width;
    }

    result.push('…');
    result
}

/// Wrap text to a maximum width
#[allow(dead_code)]
pub fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();
    let mut current_width = 0;

    for word in text.split_whitespace() {
        let word_width = word.width();

        if current_width + word_width + usize::from(current_width > 0) > max_width
            && !current_line.is_empty()
        {
            lines.push(current_line);
            current_line = String::new();
            current_width = 0;
        }

        if current_width > 0 {
            current_line.push(' ');
            current_width += 1;
        }

        current_line.push_str(word);
        current_width += word_width;
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

/// Format a duration in milliseconds to a human-readable string
#[allow(dead_code)]
pub fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        #[allow(clippy::cast_precision_loss)]
        {
            format!("{:.1}s", ms as f64 / 1000.0)
        }
    } else {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1000;
        format!("{mins}m {secs}s")
    }
}

/// Format a file size in bytes to a human-readable string
#[allow(dead_code)]
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        #[allow(clippy::cast_precision_loss)]
        {
            format!("{:.1} KB", bytes as f64 / KB as f64)
        }
    } else if bytes < GB {
        #[allow(clippy::cast_precision_loss)]
        {
            format!("{:.1} MB", bytes as f64 / MB as f64)
        }
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            format!("{:.1} GB", bytes as f64 / GB as f64)
        }
    }
}

/// Indent a string with a given number of spaces
#[allow(dead_code)]
pub fn indent(text: &str, spaces: usize) -> String {
    let indent_str = " ".repeat(spaces);
    text.lines()
        .map(|line| format!("{indent_str}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Strip ANSI escape codes from a string
#[allow(dead_code)]
pub fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(&'[') = chars.peek() {
                chars.next(); // consume '['
                // Skip until we find the end of the escape sequence
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() || c == 'm' {
                        break;
                    }
                }
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_str_short() {
        assert_eq!(truncate_str("Hello", 10), "Hello");
    }

    #[test]
    fn test_truncate_str_long() {
        let result = truncate_str("Hello, World!", 10);
        assert_eq!(result.width(), 10);
        assert!(result.ends_with('…'));
        assert!(result.starts_with("Hello,"));
    }

    #[test]
    fn test_truncate_str_empty() {
        assert_eq!(truncate_str("", 10), "");
    }

    #[test]
    fn test_wrap_text_short() {
        let lines = wrap_text("Hello World", 20);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "Hello World");
    }

    #[test]
    fn test_wrap_text_long() {
        let lines = wrap_text("Hello World this is a long text", 15);
        assert!(lines.len() > 1);
        for line in lines {
            assert!(line.width() <= 15);
        }
    }

    #[test]
    fn test_wrap_text_empty() {
        let lines = wrap_text("", 10);
        assert!(lines.is_empty());
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(500), "500ms");
        assert_eq!(format_duration(1500), "1.5s");
        assert_eq!(format_duration(65000), "1m 5s");
        assert_eq!(format_duration(120_000), "2m 0s");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1_572_864), "1.5 MB");
        assert_eq!(format_size(1_610_612_736), "1.5 GB");
    }

    #[test]
    fn test_indent() {
        let result = indent("Hello\nWorld", 2);
        assert_eq!(result, "  Hello\n  World");
    }

    #[test]
    fn test_indent_single_line() {
        let result = indent("Hello", 4);
        assert_eq!(result, "    Hello");
    }

    #[test]
    fn test_strip_ansi_codes() {
        let input = "\x1b[31mRed\x1b[0m \x1b[32mGreen\x1b[0m";
        let result = strip_ansi_codes(input);
        assert_eq!(result, "Red Green");
    }

    #[test]
    fn test_strip_ansi_codes_no_codes() {
        let input = "Plain text";
        let result = strip_ansi_codes(input);
        assert_eq!(result, "Plain text");
    }
}
