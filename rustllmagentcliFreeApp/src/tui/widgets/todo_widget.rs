//! TODO List Widget for TUI
//!
//! Renders a TODO list with 3-state status indicators:
//! - Pending (○): Yellow empty circle
//! - `InProgress` (◐): Cyan half-circle
//! - Completed (●): Green filled circle with strikethrough text

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

use crate::tui::todo::{TaskStatus, TodoList};

/// Render the TODO list widget with 3-state status visualization
pub fn render_todo_list(frame: &mut Frame, area: Rect, todo_list: &TodoList) {
    if todo_list.tasks.is_empty() {
        // Show empty state
        let empty_text = Paragraph::new("No tasks yet.\n\nType /todo <task> to add a task.")
            .block(
                Block::default()
                    .title(" TODO List ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::DarkGray));

        frame.render_widget(empty_text, area);
        return;
    }

    // Get status counts for enhanced title
    let (pending, in_progress, completed) = todo_list.count_by_status();
    let total = todo_list.tasks.len();

    // Create list items from tasks
    let items: Vec<ListItem> = todo_list
        .tasks
        .iter()
        .map(|task| {
            let checkbox = task.checkbox();
            // Determine color based on task status
            let checkbox_color = match task.status {
                TaskStatus::Pending => Color::Yellow,
                TaskStatus::InProgress => Color::Cyan,
                TaskStatus::Completed => Color::Green,
            };

            // Text style: strikethrough only for completed tasks
            let text_style = match task.status {
                TaskStatus::Completed => Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::CROSSED_OUT),
                TaskStatus::InProgress => Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
                TaskStatus::Pending => Style::default().fg(Color::White),
            };

            // Task ID style based on status
            let id_style = match task.status {
                TaskStatus::Completed => Style::default().fg(Color::DarkGray),
                TaskStatus::InProgress => Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
                TaskStatus::Pending => Style::default().fg(Color::Cyan),
            };

            let line = Line::from(vec![
                Span::styled(
                    format!("{checkbox} "),
                    Style::default()
                        .fg(checkbox_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("#{}", task.id), id_style),
                Span::raw(": "),
                Span::styled(task.description.clone(), text_style),
            ]);

            ListItem::new(line)
        })
        .collect();

    // Create enhanced progress text with status breakdown
    let progress = todo_list.completion_percentage();
    let progress_text = if todo_list.is_complete() && total > 0 {
        format!("✓ All {total} tasks completed!")
    } else {
        format!("{progress:.0}% | ○:{pending} ◐:{in_progress} ●:{completed} | {completed}/{total}")
    };

    let progress_style = if todo_list.is_complete() && total > 0 {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else if in_progress > 0 {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Yellow)
    };

    // Create title with enhanced progress
    let title = todo_list.title.as_deref().unwrap_or(" TODO List ");
    let title_with_progress = format!("{title} | {progress_text} ");

    // Render list
    let list = List::new(items)
        .block(
            Block::default()
                .title(title_with_progress)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default());

    frame.render_widget(list, area);
}

/// Render compact TODO status in a small area with 3-state awareness
pub fn render_todo_status(frame: &mut Frame, area: Rect, todo_list: &TodoList) {
    let (pending, in_progress, completed) = todo_list.count_by_status();
    let total = todo_list.tasks.len();

    let status_text = if total == 0 {
        "No tasks".to_string()
    } else if todo_list.is_complete() {
        format!("✓ {completed}/{total} done")
    } else if in_progress > 0 {
        format!("◐ {in_progress}/{total} in progress")
    } else {
        format!("○ {pending}/{total} pending")
    };

    let style = if todo_list.is_complete() && total > 0 {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else if in_progress > 0 {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else if total > 0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let status = Paragraph::new(status_text).style(style).block(
        Block::default()
            .title(" Tasks ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    frame.render_widget(status, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::todo::{Task, TaskStatus};

    // ==================== Empty State Tests ====================

    #[test]
    fn test_todo_list_empty_render() {
        let list = TodoList::new();
        assert!(list.tasks.is_empty());
        assert_eq!(list.progress_string(), "0/0 completed");
    }

    // ==================== Basic Task Tests ====================

    #[test]
    fn test_todo_list_with_tasks() {
        let mut list = TodoList::with_title("Test".to_string());
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());
        list.complete_task(1);

        assert_eq!(list.tasks.len(), 2);
        assert_eq!(list.progress_string(), "1/2 completed");
        assert!((list.completion_percentage() - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_task_display_text() {
        let mut task = Task::new(1, "Test task".to_string());
        assert_eq!(task.display_text(), "Test task");

        task.complete();
        assert!(task.display_text().contains("~~"));
    }

    #[test]
    fn test_task_checkbox() {
        let mut task = Task::new(1, "Test".to_string());
        assert_eq!(task.checkbox(), "○");

        task.complete();
        assert_eq!(task.checkbox(), "●");
    }

    // ==================== Phase 5: 3-State Visual Tests ====================

    #[test]
    fn test_task_status_pending_visual() {
        let task = Task::new(1, "Pending task".to_string());
        assert_eq!(task.status, TaskStatus::Pending);
        assert_eq!(task.checkbox(), "○");
        assert_eq!(task.display_text(), "Pending task");
        assert!(!task.display_text().contains("~~"));
    }

    #[test]
    fn test_task_status_in_progress_visual() {
        let mut task = Task::new(1, "In progress task".to_string());
        task.start();
        assert_eq!(task.status, TaskStatus::InProgress);
        assert_eq!(task.checkbox(), "◐");
        assert_eq!(task.display_text(), "In progress task");
        assert!(!task.display_text().contains("~~"));
    }

    #[test]
    fn test_task_status_completed_visual() {
        let mut task = Task::new(1, "Completed task".to_string());
        task.complete();
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.checkbox(), "●");
        assert!(task.display_text().contains("~~"));
        assert!(task.display_text().contains("Completed task"));
    }

    #[test]
    fn test_todo_list_count_by_status() {
        let mut list = TodoList::new();
        list.add_task("Pending 1".to_string());
        list.add_task("Pending 2".to_string());
        list.add_task("In progress".to_string());
        list.add_task("Completed".to_string());

        // Start one task
        list.start_task(2);

        // Complete one task
        list.complete_task(3);

        let (pending, in_progress, completed) = list.count_by_status();
        assert_eq!(pending, 2);
        assert_eq!(in_progress, 1);
        assert_eq!(completed, 1);
    }

    #[test]
    fn test_todo_list_status_summary() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());
        list.add_task("Task 3".to_string());

        list.start_task(1);
        list.complete_task(2);

        let summary = list.status_summary();
        assert!(summary.contains("Total: 3"));
        assert!(summary.contains("○ Pending: 1"));
        assert!(summary.contains("◐ In Progress: 1"));
        assert!(summary.contains("● Completed: 1"));
    }

    #[test]
    fn test_todo_list_all_pending() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());

        let (pending, in_progress, completed) = list.count_by_status();
        assert_eq!(pending, 2);
        assert_eq!(in_progress, 0);
        assert_eq!(completed, 0);
    }

    #[test]
    fn test_todo_list_all_in_progress() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());
        list.start_task(1);
        list.start_task(2);

        let (pending, in_progress, completed) = list.count_by_status();
        assert_eq!(pending, 0);
        assert_eq!(in_progress, 2);
        assert_eq!(completed, 0);
    }

    #[test]
    fn test_todo_list_all_completed() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());
        list.complete_task(1);
        list.complete_task(2);

        let (pending, in_progress, completed) = list.count_by_status();
        assert_eq!(pending, 0);
        assert_eq!(in_progress, 0);
        assert_eq!(completed, 2);

        assert!(list.is_complete());
        assert!((list.completion_percentage() - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_task_cycle_status_visual() {
        let mut task = Task::new(1, "Cycling task".to_string());

        // Initial: Pending
        assert_eq!(task.status, TaskStatus::Pending);
        assert_eq!(task.checkbox(), "○");
        assert!(!task.display_text().contains("~~"));

        // Cycle to InProgress
        task.cycle_status();
        assert_eq!(task.status, TaskStatus::InProgress);
        assert_eq!(task.checkbox(), "◐");
        assert!(!task.display_text().contains("~~"));

        // Cycle to Completed
        task.cycle_status();
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.checkbox(), "●");
        assert!(task.display_text().contains("~~"));

        // Cycle back to Pending
        task.cycle_status();
        assert_eq!(task.status, TaskStatus::Pending);
        assert_eq!(task.checkbox(), "○");
        assert!(!task.display_text().contains("~~"));
    }

    #[test]
    fn test_mixed_status_workflow() {
        let mut list = TodoList::with_title("Workflow".to_string());

        // Add 5 tasks
        for i in 1..=5 {
            list.add_task(format!("Task {i}"));
        }

        // Start tasks 1 and 2
        list.start_task(1);
        list.start_task(2);

        // Complete task 1
        list.complete_task(1);

        let (pending, in_progress, completed) = list.count_by_status();
        assert_eq!(pending, 3); // Tasks 3, 4, 5
        assert_eq!(in_progress, 1); // Task 2
        assert_eq!(completed, 1); // Task 1

        assert!(!list.is_complete());
        assert!((list.completion_percentage() - 20.0).abs() < 0.1);
    }

    #[test]
    fn test_progress_string_with_mixed_status() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());
        list.add_task("Task 3".to_string());
        list.add_task("Task 4".to_string());

        list.complete_task(1);
        list.complete_task(2);
        list.start_task(3);

        // Progress string should show completed count
        assert_eq!(list.progress_string(), "2/4 completed");

        // Completion percentage
        assert!((list.completion_percentage() - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_task_with_notes() {
        let mut task = Task::with_notes(
            1,
            "Task with notes".to_string(),
            "Important note".to_string(),
        );
        assert_eq!(task.status, TaskStatus::Pending);
        assert_eq!(task.checkbox(), "○");
        assert_eq!(task.notes, Some("Important note".to_string()));

        task.start();
        assert_eq!(task.status, TaskStatus::InProgress);
        assert_eq!(task.checkbox(), "◐");

        task.complete();
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.checkbox(), "●");
        assert!(task.display_text().contains("~~"));
    }
}
