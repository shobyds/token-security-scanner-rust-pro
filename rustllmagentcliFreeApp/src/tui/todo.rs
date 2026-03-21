//! TODO List Manager for task tracking
//!
//! This module provides functionality to:
//! - Parse tasks from text
//! - Track task completion state with 3 statuses: Pending, `InProgress`, Completed
//! - Store temporary CSV files for AI review workflow
//! - Render TODO lists in the TUI

#![allow(clippy::must_use_candidate)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Represents the status of a task
///
/// Each status has a visual representation:
/// - Pending: ○ (empty circle)
/// - `InProgress`: ◐ (half circle)
/// - Completed: ● (filled circle) with strikethrough text
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TaskStatus {
    /// Task not yet started (○)
    #[default]
    Pending,
    /// Task currently being worked on (◐)
    InProgress,
    /// Task completed (●)
    Completed,
}

impl TaskStatus {
    /// Get the checkbox symbol for this status
    pub fn checkbox(&self) -> &'static str {
        match self {
            Self::Pending => "○",
            Self::InProgress => "◐",
            Self::Completed => "●",
        }
    }

    /// Check if this status is Completed
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }

    /// Check if this status is Pending
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Check if this status is `InProgress`
    pub fn is_in_progress(&self) -> bool {
        matches!(self, Self::InProgress)
    }

    /// Create `TaskStatus` from bool for backward compatibility
    /// - false → Pending
    /// - true → Completed
    pub fn from_bool(completed: bool) -> Self {
        if completed {
            Self::Completed
        } else {
            Self::Pending
        }
    }

    /// Convert `TaskStatus` to bool for backward compatibility
    /// - Completed → true
    /// - Pending/`InProgress` → false
    pub fn to_bool(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// Represents a single task in the TODO list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    /// Unique task identifier
    pub id: usize,
    /// Task description/text
    pub description: String,
    /// Current status of the task (Pending, `InProgress`, or Completed)
    pub status: TaskStatus,
    /// Optional notes about the task
    pub notes: Option<String>,
}

impl Task {
    /// Create a new task with Pending status
    pub fn new(id: usize, description: String) -> Self {
        Self {
            id,
            description,
            status: TaskStatus::Pending,
            notes: None,
        }
    }

    /// Create a new task with a specific status
    pub fn with_status(id: usize, description: String, status: TaskStatus) -> Self {
        Self {
            id,
            description,
            status,
            notes: None,
        }
    }

    /// Create a new task with notes
    pub fn with_notes(id: usize, description: String, notes: String) -> Self {
        Self {
            id,
            description,
            status: TaskStatus::Pending,
            notes: Some(notes),
        }
    }

    /// Mark task as completed (transition to Completed status)
    pub fn complete(&mut self) {
        self.status = TaskStatus::Completed;
    }

    /// Mark task as in progress (transition to `InProgress` status)
    pub fn start(&mut self) {
        self.status = TaskStatus::InProgress;
    }

    /// Mark task as pending (transition to Pending status, i.e., reset)
    pub fn reset(&mut self) {
        self.status = TaskStatus::Pending;
    }

    /// Mark task as incomplete (alias for reset, for backward compatibility)
    pub fn uncomplete(&mut self) {
        self.reset();
    }

    /// Get display text with strikethrough if completed
    pub fn display_text(&self) -> String {
        if self.status.is_completed() {
            format!("~~{}~~", self.description)
        } else {
            self.description.clone()
        }
    }

    /// Get checkbox symbol based on status
    pub fn checkbox(&self) -> &'static str {
        self.status.checkbox()
    }

    /// Check if task is completed
    pub fn is_completed(&self) -> bool {
        self.status.is_completed()
    }

    /// Check if task is in progress
    pub fn is_in_progress(&self) -> bool {
        self.status.is_in_progress()
    }

    /// Check if task is pending
    pub fn is_pending(&self) -> bool {
        self.status.is_pending()
    }

    /// Transition task to next status
    /// Pending → `InProgress` → Completed → Pending (cycle)
    pub fn cycle_status(&mut self) {
        self.status = match self.status {
            TaskStatus::Pending => TaskStatus::InProgress,
            TaskStatus::InProgress => TaskStatus::Completed,
            TaskStatus::Completed => TaskStatus::Pending,
        };
    }
}

/// TODO List manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoList {
    /// List of tasks
    pub tasks: Vec<Task>,
    /// Next task ID
    pub next_id: usize,
    /// Title of the TODO list
    pub title: Option<String>,
    /// Path to temporary CSV file (for AI review workflow)
    pub temp_csv_path: Option<PathBuf>,
    /// Original text content saved to CSV
    pub csv_content: String,
    /// Whether AI has reviewed the CSV content
    pub ai_reviewed: bool,
}

impl TodoList {
    /// Create a new empty TODO list
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            next_id: 1,
            title: None,
            temp_csv_path: None,
            csv_content: String::new(),
            ai_reviewed: false,
        }
    }

    /// Create a TODO list with a title
    pub fn with_title(title: String) -> Self {
        Self {
            tasks: Vec::new(),
            next_id: 1,
            title: Some(title),
            temp_csv_path: None,
            csv_content: String::new(),
            ai_reviewed: false,
        }
    }

    /// Add a task to the list
    pub fn add_task(&mut self, description: String) -> usize {
        let task = Task::new(self.next_id, description);
        let id = self.next_id;
        self.tasks.push(task);
        self.next_id += 1;
        id
    }

    /// Add a task with a specific status
    pub fn add_task_with_status(&mut self, description: String, status: TaskStatus) -> usize {
        let task = Task::with_status(self.next_id, description, status);
        let id = self.next_id;
        self.tasks.push(task);
        self.next_id += 1;
        id
    }

    /// Mark a task as completed
    pub fn complete_task(&mut self, task_id: usize) -> bool {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == task_id) {
            task.complete();
            true
        } else {
            false
        }
    }

    /// Mark a task as in progress
    pub fn start_task(&mut self, task_id: usize) -> bool {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == task_id) {
            task.start();
            true
        } else {
            false
        }
    }

    /// Mark a task as pending (reset)
    pub fn reset_task(&mut self, task_id: usize) -> bool {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == task_id) {
            task.reset();
            true
        } else {
            false
        }
    }

    /// Mark a task as incomplete (alias for `reset_task`, for backward compatibility)
    pub fn uncomplete_task(&mut self, task_id: usize) -> bool {
        self.reset_task(task_id)
    }

    /// Remove a task
    pub fn remove_task(&mut self, task_id: usize) -> bool {
        let initial_len = self.tasks.len();
        self.tasks.retain(|t| t.id != task_id);
        self.tasks.len() < initial_len
    }

    /// Clear all completed tasks
    pub fn clear_completed(&mut self) {
        self.tasks.retain(|t| !t.is_completed());
    }

    /// Clear all tasks
    pub fn clear_all(&mut self) {
        self.tasks.clear();
        self.next_id = 1;
    }

    /// Get progress string (e.g., "2/5 completed")
    pub fn progress_string(&self) -> String {
        let completed = self.tasks.iter().filter(|t| t.is_completed()).count();
        let total = self.tasks.len();
        format!("{completed}/{total} completed")
    }

    /// Get completion percentage
    #[allow(clippy::cast_precision_loss)]
    pub fn completion_percentage(&self) -> f32 {
        if self.tasks.is_empty() {
            0.0
        } else {
            let completed = self.tasks.iter().filter(|t| t.is_completed()).count() as f32;
            let total = self.tasks.len() as f32;
            (completed / total) * 100.0
        }
    }

    /// Check if all tasks are completed
    pub fn is_complete(&self) -> bool {
        !self.tasks.is_empty() && self.tasks.iter().all(Task::is_completed)
    }

    /// Set the temporary CSV path
    pub fn set_csv_path(&mut self, path: PathBuf) {
        self.temp_csv_path = Some(path);
    }

    /// Clear CSV tracking fields
    pub fn clear_csv(&mut self) {
        self.temp_csv_path = None;
        self.csv_content.clear();
        self.ai_reviewed = false;
    }

    /// Check if a CSV file is tracked
    pub fn has_csv(&self) -> bool {
        self.temp_csv_path.is_some()
    }

    /// Get the CSV path if it exists
    pub fn csv_path(&self) -> Option<&PathBuf> {
        self.temp_csv_path.as_ref()
    }

    /// Check if all tasks are completed (for CSV cleanup workflow)
    pub fn all_tasks_completed(&self) -> bool {
        !self.tasks.is_empty() && self.tasks.iter().all(Task::is_completed)
    }

    /// Get count of tasks by status
    pub fn count_by_status(&self) -> (usize, usize, usize) {
        let mut pending = 0;
        let mut in_progress = 0;
        let mut completed = 0;

        for task in &self.tasks {
            match task.status {
                TaskStatus::Pending => pending += 1,
                TaskStatus::InProgress => in_progress += 1,
                TaskStatus::Completed => completed += 1,
            }
        }

        (pending, in_progress, completed)
    }

    /// Get status summary string
    pub fn status_summary(&self) -> String {
        let (pending, in_progress, completed) = self.count_by_status();
        let total = self.tasks.len();
        format!(
            "Total: {total} | ○ Pending: {pending} | ◐ In Progress: {in_progress} | ● Completed: {completed}"
        )
    }
}

impl Default for TodoList {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse tasks from text
///
/// Looks for patterns like:
/// - Numbered lists: "1. Task description"
/// - Bullet points: "- Task description" or "* Task description"
/// - Checkboxes: "[ ] Task" or "[x] Task"
/// - Lines starting with verbs (common task indicators)
pub fn parse_tasks_from_text(text: &str) -> Vec<String> {
    let mut in_code_block = false;
    let mut tasks = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();

        // Track code block state
        if trimmed.starts_with("```") {
            in_code_block = !in_code_block;
            continue;
        }

        // Skip lines inside code blocks
        if in_code_block {
            continue;
        }

        // Skip empty lines
        if trimmed.is_empty() {
            continue;
        }

        // Skip headers
        if trimmed.starts_with('#') {
            continue;
        }

        // Pattern 1: Numbered list (1. 2. 3. etc.)
        if let Some(task) = extract_numbered_item(trimmed) {
            tasks.push(task);
            continue;
        }

        // Pattern 2: Bullet points (- or *)
        if let Some(task) = extract_bullet_item(trimmed) {
            tasks.push(task);
            continue;
        }

        // Pattern 3: Checkbox ([ ] or [x])
        if let Some(task) = extract_checkbox_item(trimmed) {
            tasks.push(task);
            continue;
        }

        // Pattern 4: Lines with action verbs (heuristic)
        if let Some(task) = extract_action_item(trimmed) {
            tasks.push(task);
        }
    }

    tasks
}

/// Extract numbered list item (e.g., "1. Task description")
fn extract_numbered_item(line: &str) -> Option<String> {
    // Match patterns like "1. ", "2. ", "10. ", etc.
    if let Some(pos) = line.find(". ") {
        let prefix = &line[..pos];
        if prefix.chars().all(|c| c.is_ascii_digit()) && !prefix.is_empty() {
            let task = line[pos + 2..].trim();
            if !task.is_empty() && task.len() > 3 {
                return Some(task.to_string());
            }
        }
    }
    None
}

/// Extract bullet point item (e.g., "- Task" or "* Task")
fn extract_bullet_item(line: &str) -> Option<String> {
    if line.starts_with("- ") || line.starts_with("* ") {
        let task = line[2..].trim();
        if !task.is_empty() && task.len() > 3 {
            return Some(task.to_string());
        }
    }
    None
}

/// Extract checkbox item (e.g., "[ ] Task" or "[x] Task")
fn extract_checkbox_item(line: &str) -> Option<String> {
    if line.starts_with("[ ] ") || line.starts_with("[x] ") || line.starts_with("[X] ") {
        let task = line[4..].trim();
        if !task.is_empty() && task.len() > 3 {
            return Some(task.to_string());
        }
    }
    None
}

/// Extract action item based on common task verbs
fn extract_action_item(line: &str) -> Option<String> {
    // Common action verbs that indicate a task
    let action_verbs = [
        "implement",
        "create",
        "build",
        "add",
        "fix",
        "update",
        "review",
        "test",
        "deploy",
        "configure",
        "setup",
        "install",
        "remove",
        "check",
        "verify",
        "ensure",
        "make",
        "write",
        "design",
    ];

    let lower = line.to_lowercase();

    // Check if line starts with an action verb
    for verb in &action_verbs {
        if lower.starts_with(verb) {
            // Make sure it's a reasonable task length
            if line.len() > 10 && line.len() < 500 {
                return Some(line.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== TaskStatus Enum Tests ====================

    #[test]
    fn test_task_status_enum_variants() {
        // Verify all 3 status variants exist and are distinct
        let pending = TaskStatus::Pending;
        let in_progress = TaskStatus::InProgress;
        let completed = TaskStatus::Completed;

        assert_ne!(pending, in_progress);
        assert_ne!(pending, completed);
        assert_ne!(in_progress, completed);
    }

    #[test]
    fn test_task_status_checkbox_symbols() {
        // Verify correct symbols for each status
        assert_eq!(TaskStatus::Pending.checkbox(), "○");
        assert_eq!(TaskStatus::InProgress.checkbox(), "◐");
        assert_eq!(TaskStatus::Completed.checkbox(), "●");
    }

    #[test]
    fn test_task_status_is_methods() {
        // Test is_completed()
        assert!(!TaskStatus::Pending.is_completed());
        assert!(!TaskStatus::InProgress.is_completed());
        assert!(TaskStatus::Completed.is_completed());

        // Test is_pending()
        assert!(TaskStatus::Pending.is_pending());
        assert!(!TaskStatus::InProgress.is_pending());
        assert!(!TaskStatus::Completed.is_pending());

        // Test is_in_progress()
        assert!(!TaskStatus::Pending.is_in_progress());
        assert!(TaskStatus::InProgress.is_in_progress());
        assert!(!TaskStatus::Completed.is_in_progress());
    }

    #[test]
    fn test_task_status_from_bool_backward_compat() {
        // Test backward compatibility conversion
        assert_eq!(TaskStatus::from_bool(false), TaskStatus::Pending);
        assert_eq!(TaskStatus::from_bool(true), TaskStatus::Completed);
    }

    #[test]
    fn test_task_status_to_bool_backward_compat() {
        // Test backward compatibility conversion
        assert!(!TaskStatus::Pending.to_bool());
        assert!(!TaskStatus::InProgress.to_bool());
        assert!(TaskStatus::Completed.to_bool());
    }

    #[test]
    fn test_task_status_default() {
        // Verify default is Pending
        assert_eq!(TaskStatus::default(), TaskStatus::Pending);
    }

    // ==================== Task Struct Tests ====================

    #[test]
    fn test_task_creation_default_pending() {
        // New tasks should start as Pending
        let task = Task::new(1, "Test task".to_string());
        assert_eq!(task.id, 1);
        assert_eq!(task.description, "Test task");
        assert_eq!(task.status, TaskStatus::Pending);
        assert!(task.is_pending());
        assert!(!task.is_completed());
        assert!(!task.is_in_progress());
    }

    #[test]
    fn test_task_creation_with_status() {
        // Test creating task with specific status
        let task_pending = Task::with_status(1, "Task".to_string(), TaskStatus::Pending);
        let task_progress = Task::with_status(2, "Task".to_string(), TaskStatus::InProgress);
        let task_completed = Task::with_status(3, "Task".to_string(), TaskStatus::Completed);

        assert_eq!(task_pending.status, TaskStatus::Pending);
        assert_eq!(task_progress.status, TaskStatus::InProgress);
        assert_eq!(task_completed.status, TaskStatus::Completed);
    }

    #[test]
    fn test_task_creation_with_notes() {
        let task = Task::with_notes(1, "Test task".to_string(), "Some notes".to_string());
        assert_eq!(task.notes, Some("Some notes".to_string()));
        assert_eq!(task.status, TaskStatus::Pending);
    }

    #[test]
    fn test_task_status_transitions() {
        // Test all status transitions
        let mut task = Task::new(1, "Test task".to_string());

        // Initial state: Pending
        assert_eq!(task.status, TaskStatus::Pending);

        // Transition to InProgress
        task.start();
        assert_eq!(task.status, TaskStatus::InProgress);
        assert!(task.is_in_progress());

        // Transition to Completed
        task.complete();
        assert_eq!(task.status, TaskStatus::Completed);
        assert!(task.is_completed());

        // Reset to Pending
        task.reset();
        assert_eq!(task.status, TaskStatus::Pending);
        assert!(task.is_pending());
    }

    #[test]
    fn test_task_cycle_status() {
        let mut task = Task::new(1, "Test task".to_string());

        // Pending → InProgress
        task.cycle_status();
        assert_eq!(task.status, TaskStatus::InProgress);

        // InProgress → Completed
        task.cycle_status();
        assert_eq!(task.status, TaskStatus::Completed);

        // Completed → Pending (cycle)
        task.cycle_status();
        assert_eq!(task.status, TaskStatus::Pending);
    }

    #[test]
    fn test_task_checkbox_symbols() {
        let mut task = Task::new(1, "Test task".to_string());

        // Pending: ○
        assert_eq!(task.checkbox(), "○");

        // InProgress: ◐
        task.start();
        assert_eq!(task.checkbox(), "◐");

        // Completed: ●
        task.complete();
        assert_eq!(task.checkbox(), "●");
    }

    #[test]
    fn test_task_display_text_strikethrough() {
        let mut task = Task::new(1, "Test task".to_string());

        // Pending: no strikethrough
        assert_eq!(task.display_text(), "Test task");
        assert!(!task.display_text().contains("~~"));

        // InProgress: no strikethrough
        task.start();
        assert_eq!(task.display_text(), "Test task");
        assert!(!task.display_text().contains("~~"));

        // Completed: strikethrough
        task.complete();
        assert_eq!(task.display_text(), "~~Test task~~");
        assert!(task.display_text().contains("~~"));
    }

    #[test]
    fn test_task_uncomplete_backward_compat() {
        let mut task = Task::new(1, "Test task".to_string());
        task.complete();
        assert!(task.is_completed());

        task.uncomplete();
        assert!(task.is_pending());
    }

    #[test]
    fn test_task_serialize_deserialize() {
        let mut task = Task::new(1, "Test task".to_string());
        task.complete();
        task.notes = Some("Completed!".to_string());

        // Serialize
        let serialized = serde_json::to_string(&task).expect("Failed to serialize");

        // Deserialize
        let deserialized: Task = serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Verify
        assert_eq!(deserialized.id, 1);
        assert_eq!(deserialized.description, "Test task");
        assert_eq!(deserialized.status, TaskStatus::Completed);
        assert_eq!(deserialized.notes, Some("Completed!".to_string()));
    }

    // ==================== TodoList Struct Tests ====================

    #[test]
    fn test_todolist_creation() {
        let list = TodoList::new();
        assert!(list.tasks.is_empty());
        assert_eq!(list.next_id, 1);
        assert!(list.title.is_none());
        assert!(!list.has_csv());
        assert!(!list.ai_reviewed);
    }

    #[test]
    fn test_todolist_csv_tracking() {
        let mut list = TodoList::new();

        // Initially no CSV
        assert!(!list.has_csv());
        assert!(list.csv_path().is_none());

        // Set CSV path
        let path = PathBuf::from("/tmp/test.csv");
        list.set_csv_path(path.clone());

        assert!(list.has_csv());
        assert_eq!(list.csv_path(), Some(&path));

        // Clear CSV
        list.clear_csv();
        assert!(!list.has_csv());
        assert!(list.csv_path().is_none());
        assert!(list.csv_content.is_empty());
        assert!(!list.ai_reviewed);
    }

    #[test]
    fn test_todolist_csv_content_storage() {
        let mut list = TodoList::new();
        let content = "This is the original text content for CSV.";
        list.csv_content = content.to_string();

        assert_eq!(list.csv_content, content);

        list.clear_csv();
        assert!(list.csv_content.is_empty());
    }

    #[test]
    fn test_todolist_ai_reviewed_flag() {
        let mut list = TodoList::new();
        assert!(!list.ai_reviewed);

        list.ai_reviewed = true;
        assert!(list.ai_reviewed);

        list.clear_csv();
        assert!(!list.ai_reviewed);
    }

    #[test]
    fn test_todolist_add_task() {
        let mut list = TodoList::new();
        let id = list.add_task("Task 1".to_string());
        assert_eq!(id, 1);
        assert_eq!(list.tasks.len(), 1);
        assert_eq!(list.tasks[0].status, TaskStatus::Pending);
    }

    #[test]
    fn test_todolist_add_task_with_status() {
        let mut list = TodoList::new();
        let id = list.add_task_with_status("Task 1".to_string(), TaskStatus::InProgress);
        assert_eq!(id, 1);
        assert_eq!(list.tasks.len(), 1);
        assert_eq!(list.tasks[0].status, TaskStatus::InProgress);
    }

    #[test]
    fn test_todolist_complete_task() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        assert!(list.complete_task(1));
        assert_eq!(list.tasks[0].status, TaskStatus::Completed);
    }

    #[test]
    fn test_todolist_start_task() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        assert!(list.start_task(1));
        assert_eq!(list.tasks[0].status, TaskStatus::InProgress);
    }

    #[test]
    fn test_todolist_reset_task() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.complete_task(1);
        assert!(list.reset_task(1));
        assert_eq!(list.tasks[0].status, TaskStatus::Pending);
    }

    #[test]
    fn test_todolist_progress_string() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());
        list.add_task("Task 3".to_string());
        list.complete_task(1);
        list.complete_task(2);

        assert_eq!(list.progress_string(), "2/3 completed");
    }

    #[test]
    fn test_todolist_completion_percentage() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());
        list.add_task("Task 3".to_string());
        list.complete_task(1);
        list.complete_task(2);

        assert!((list.completion_percentage() - 66.67).abs() < 0.1);
    }

    #[test]
    fn test_todolist_all_tasks_completed_empty() {
        let list = TodoList::new();
        // Empty list should return false
        assert!(!list.all_tasks_completed());
    }

    #[test]
    fn test_todolist_all_tasks_completed_mixed() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());
        list.add_task("Task 3".to_string());
        list.complete_task(1);
        list.start_task(2);
        // Task 3 is still pending
        assert!(!list.all_tasks_completed());
    }

    #[test]
    fn test_todolist_all_tasks_completed_all_done() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());
        list.complete_task(1);
        list.complete_task(2);
        assert!(list.all_tasks_completed());
    }

    #[test]
    fn test_todolist_count_by_status() {
        let mut list = TodoList::new();
        list.add_task("Pending task".to_string());
        list.add_task("In progress task".to_string());
        list.add_task("Completed task".to_string());
        list.start_task(2);
        list.complete_task(3);

        let (pending, in_progress, completed) = list.count_by_status();
        assert_eq!(pending, 1);
        assert_eq!(in_progress, 1);
        assert_eq!(completed, 1);
    }

    #[test]
    fn test_todolist_status_summary() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());
        list.add_task("Task 3".to_string());
        list.complete_task(1);
        list.start_task(2);

        let summary = list.status_summary();
        assert!(summary.contains("Total: 3"));
        assert!(summary.contains("○ Pending: 1"));
        assert!(summary.contains("◐ In Progress: 1"));
        assert!(summary.contains("● Completed: 1"));
    }

    #[test]
    fn test_todolist_is_complete() {
        let mut list = TodoList::new();
        assert!(!list.is_complete()); // Empty list

        list.add_task("Task 1".to_string());
        assert!(!list.is_complete()); // Not completed

        list.complete_task(1);
        assert!(list.is_complete()); // All completed
    }

    #[test]
    fn test_todolist_clear_all() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());

        list.clear_all();
        assert!(list.tasks.is_empty());
        assert_eq!(list.next_id, 1);
    }

    #[test]
    fn test_todolist_clear_completed() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());
        list.complete_task(1);

        list.clear_completed();
        assert_eq!(list.tasks.len(), 1);
        assert_eq!(list.tasks[0].status, TaskStatus::Pending); // Task 2 is still pending
    }

    #[test]
    fn test_todolist_remove_task() {
        let mut list = TodoList::new();
        list.add_task("Task 1".to_string());
        list.add_task("Task 2".to_string());

        assert!(list.remove_task(1));
        assert_eq!(list.tasks.len(), 1);
        assert_eq!(list.tasks[0].id, 2);

        assert!(!list.remove_task(999)); // Non-existent task
    }

    // ==================== Integration Tests ====================

    #[test]
    fn test_task_full_workflow() {
        let mut list = TodoList::with_title("Test Project".to_string());

        // Add tasks
        let id1 = list.add_task("Implement feature".to_string());
        let id2 = list.add_task("Write tests".to_string());
        let id3 = list.add_task("Deploy".to_string());

        // Start working on first task
        list.start_task(id1);
        assert_eq!(list.tasks[0].status, TaskStatus::InProgress);
        assert_eq!(list.tasks[0].checkbox(), "◐");

        // Complete first task
        list.complete_task(id1);
        assert_eq!(list.tasks[0].status, TaskStatus::Completed);
        assert_eq!(list.tasks[0].checkbox(), "●");
        assert!(list.tasks[0].display_text().contains("~~"));

        // Start second task
        list.start_task(id2);
        assert_eq!(list.tasks[1].status, TaskStatus::InProgress);

        // Verify summary
        let summary = list.status_summary();
        assert!(summary.contains("Total: 3"));
        assert!(summary.contains("○ Pending: 1")); // Task 3
        assert!(summary.contains("◐ In Progress: 1")); // Task 2
        assert!(summary.contains("● Completed: 1")); // Task 1

        // Not all tasks completed yet
        assert!(!list.all_tasks_completed());

        // Complete remaining tasks
        list.complete_task(id2);
        list.complete_task(id3);

        // Now all tasks are completed
        assert!(list.all_tasks_completed());
        assert!(list.is_complete());
        assert!((list.completion_percentage() - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_csv_workflow() {
        let mut list = TodoList::new();

        // Simulate CSV workflow
        let csv_path = PathBuf::from("/tmp/test_todo.csv");
        let content = "1. Task one\n2. Task two\n3. Task three";

        list.set_csv_path(csv_path);
        list.csv_content = content.to_string();

        assert!(list.has_csv());
        assert_eq!(list.csv_content, content);

        // Parse tasks from content
        let tasks = parse_tasks_from_text(&list.csv_content);
        for task_text in &tasks {
            list.add_task(task_text.clone());
        }

        assert_eq!(list.tasks.len(), 3);

        // Mark AI as reviewed
        list.ai_reviewed = true;

        // Complete all tasks
        for i in 1..=3 {
            list.complete_task(i);
        }

        // Verify all completed
        assert!(list.all_tasks_completed());
        assert!(list.ai_reviewed);

        // Clear CSV after completion
        list.clear_csv();
        assert!(!list.has_csv());
        assert!(list.csv_content.is_empty());
        assert!(!list.ai_reviewed);
    }
}
