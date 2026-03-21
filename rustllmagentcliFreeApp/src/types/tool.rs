//! Tool types and definitions

#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

use serde::{Deserialize, Serialize};

/// A tool definition for the LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// The name of the tool
    pub name: String,
    /// A description of what the tool does
    pub description: String,
    /// JSON schema for the tool's parameters
    pub parameters: serde_json::Value,
}

impl ToolDefinition {
    /// Create a new tool definition
    #[allow(dead_code)]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        parameters: serde_json::Value,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters,
        }
    }

    /// Create a tool definition with JSON schema builder
    pub fn with_schema(
        name: impl Into<String>,
        description: impl Into<String>,
        required: &[&str],
        properties: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        let mut params = serde_json::Map::new();
        params.insert(
            "type".to_string(),
            serde_json::Value::String("object".to_string()),
        );

        if !required.is_empty() {
            params.insert(
                "required".to_string(),
                serde_json::Value::Array(
                    required
                        .iter()
                        .map(|s| serde_json::Value::String((*s).to_string()))
                        .collect(),
                ),
            );
        }

        params.insert(
            "properties".to_string(),
            serde_json::Value::Object(properties),
        );

        Self {
            name: name.into(),
            description: description.into(),
            parameters: serde_json::Value::Object(params),
        }
    }

    /// Convert to API format (`OpenAI` compatible)
    #[allow(dead_code)]
    pub fn to_api_format(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters
            }
        })
    }
}

/// Result of a tool execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// The name of the tool that was executed
    pub tool_name: String,
    /// Whether the tool execution was successful
    pub success: bool,
    /// The output of the tool (stdout or error message)
    pub output: String,
    /// Optional error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Optional structured data output
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
}

impl ToolResult {
    /// Create a successful tool result
    pub fn success(
        tool_name: impl Into<String>,
        output: impl Into<String>,
        execution_time_ms: u64,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            success: true,
            output: output.into(),
            error: None,
            data: None,
            execution_time_ms,
        }
    }

    /// Create a successful tool result with data
    #[allow(dead_code)]
    pub fn success_with_data(
        tool_name: impl Into<String>,
        output: impl Into<String>,
        data: serde_json::Value,
        execution_time_ms: u64,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            success: true,
            output: output.into(),
            error: None,
            data: Some(data),
            execution_time_ms,
        }
    }

    /// Create a failed tool result
    pub fn failure(
        tool_name: impl Into<String>,
        error: impl Into<String>,
        execution_time_ms: u64,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            success: false,
            output: String::new(),
            error: Some(error.into()),
            data: None,
            execution_time_ms,
        }
    }

    /// Create a tool result from a Result
    #[allow(dead_code)]
    pub fn from_result(
        tool_name: impl Into<String>,
        result: Result<String, String>,
        execution_time_ms: u64,
    ) -> Self {
        match result {
            Ok(output) => Self::success(tool_name, output, execution_time_ms),
            Err(error) => Self::failure(tool_name, error, execution_time_ms),
        }
    }

    /// Check if the tool execution was successful
    #[allow(dead_code)]
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get the output or error message
    #[allow(dead_code)]
    pub fn get_output_or_error(&self) -> &str {
        if self.success {
            &self.output
        } else {
            self.error.as_deref().unwrap_or("Unknown error")
        }
    }

    /// Convert to a string representation for the LLM
    /// Uses distinctive formatting to help the LLM recognize tool results
    pub fn to_llm_string(&self) -> String {
        if self.success {
            if let Some(ref data) = self.data {
                format!(
                    "<tool_result name=\"{}\" status=\"success\">\nOutput: {}\nData: {}\n</tool_result>",
                    self.tool_name, self.output, data
                )
            } else {
                format!(
                    "<tool_result name=\"{}\" status=\"success\">\n{}\n</tool_result>",
                    self.tool_name, self.output
                )
            }
        } else {
            format!(
                "<tool_result name=\"{}\" status=\"error\">\nError: {}\n</tool_result>",
                self.tool_name,
                self.error.as_deref().unwrap_or("Unknown error")
            )
        }
    }
}

/// Input schema helper for building tool parameters
pub struct SchemaBuilder {
    properties: serde_json::Map<String, serde_json::Value>,
    required: Vec<&'static str>,
}

impl SchemaBuilder {
    /// Create a new schema builder
    pub fn new() -> Self {
        Self {
            properties: serde_json::Map::new(),
            required: Vec::new(),
        }
    }

    /// Add a string property
    pub fn string_property(
        mut self,
        name: &'static str,
        description: &'static str,
        required: bool,
    ) -> Self {
        let mut prop = serde_json::Map::new();
        prop.insert(
            "type".to_string(),
            serde_json::Value::String("string".to_string()),
        );
        prop.insert(
            "description".to_string(),
            serde_json::Value::String(description.to_string()),
        );
        self.properties
            .insert(name.to_string(), serde_json::Value::Object(prop));
        if required {
            self.required.push(name);
        }
        self
    }

    /// Add an integer property
    pub fn integer_property(
        mut self,
        name: &'static str,
        description: &'static str,
        required: bool,
    ) -> Self {
        let mut prop = serde_json::Map::new();
        prop.insert(
            "type".to_string(),
            serde_json::Value::String("integer".to_string()),
        );
        prop.insert(
            "description".to_string(),
            serde_json::Value::String(description.to_string()),
        );
        self.properties
            .insert(name.to_string(), serde_json::Value::Object(prop));
        if required {
            self.required.push(name);
        }
        self
    }

    /// Add a boolean property
    #[allow(dead_code)]
    pub fn boolean_property(
        mut self,
        name: &'static str,
        description: &'static str,
        required: bool,
    ) -> Self {
        let mut prop = serde_json::Map::new();
        prop.insert(
            "type".to_string(),
            serde_json::Value::String("boolean".to_string()),
        );
        prop.insert(
            "description".to_string(),
            serde_json::Value::String(description.to_string()),
        );
        self.properties
            .insert(name.to_string(), serde_json::Value::Object(prop));
        if required {
            self.required.push(name);
        }
        self
    }

    /// Add an array property
    #[allow(dead_code)]
    pub fn array_property(
        mut self,
        name: &'static str,
        description: &'static str,
        items_type: &str,
        required: bool,
    ) -> Self {
        let mut prop = serde_json::Map::new();
        prop.insert(
            "type".to_string(),
            serde_json::Value::String("array".to_string()),
        );
        prop.insert(
            "description".to_string(),
            serde_json::Value::String(description.to_string()),
        );
        let mut items = serde_json::Map::new();
        items.insert(
            "type".to_string(),
            serde_json::Value::String(items_type.to_string()),
        );
        prop.insert("items".to_string(), serde_json::Value::Object(items));
        self.properties
            .insert(name.to_string(), serde_json::Value::Object(prop));
        if required {
            self.required.push(name);
        }
        self
    }

    /// Add an object property
    #[allow(dead_code)]
    pub fn object_property(
        mut self,
        name: &'static str,
        description: &'static str,
        properties: serde_json::Map<String, serde_json::Value>,
        required: bool,
    ) -> Self {
        let mut prop = serde_json::Map::new();
        prop.insert(
            "type".to_string(),
            serde_json::Value::String("object".to_string()),
        );
        prop.insert(
            "description".to_string(),
            serde_json::Value::String(description.to_string()),
        );
        prop.insert(
            "properties".to_string(),
            serde_json::Value::Object(properties),
        );
        self.properties
            .insert(name.to_string(), serde_json::Value::Object(prop));
        if required {
            self.required.push(name);
        }
        self
    }

    /// Build the schema
    pub fn build(
        self,
    ) -> (
        serde_json::Map<String, serde_json::Value>,
        Vec<&'static str>,
    ) {
        (self.properties, self.required)
    }
}

impl Default for SchemaBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_definition_creation() {
        let tool = ToolDefinition::new(
            "read_file",
            "Read the contents of a file",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                }
            }),
        );

        assert_eq!(tool.name, "read_file");
        assert_eq!(tool.description, "Read the contents of a file");
    }

    #[test]
    fn test_tool_definition_with_schema() {
        let properties = serde_json::json!({
            "path": {"type": "string", "description": "File path"}
        })
        .as_object()
        .unwrap()
        .clone();

        let tool =
            ToolDefinition::with_schema("read_file", "Read file contents", &["path"], properties);

        assert_eq!(tool.name, "read_file");
        assert!(tool.description.contains("Read file"));

        let params = tool.parameters.as_object().unwrap();
        assert!(params.contains_key("required"));
        assert!(params.contains_key("properties"));
    }

    #[test]
    fn test_tool_definition_to_api_format() {
        let tool = ToolDefinition::new("test_tool", "A test tool", serde_json::json!({}));
        let api_format = tool.to_api_format();

        let obj = api_format.as_object().unwrap();
        assert_eq!(obj.get("type").unwrap(), "function");

        let function = obj.get("function").unwrap().as_object().unwrap();
        assert_eq!(function.get("name").unwrap(), "test_tool");
    }

    #[test]
    fn test_tool_result_success() {
        let result = ToolResult::success("read_file", "File contents here", 150);

        assert!(result.success);
        assert_eq!(result.tool_name, "read_file");
        assert_eq!(result.output, "File contents here");
        assert!(result.error.is_none());
        assert_eq!(result.execution_time_ms, 150);
    }

    #[test]
    fn test_tool_result_failure() {
        let result = ToolResult::failure("read_file", "File not found", 50);

        assert!(!result.success);
        assert_eq!(result.tool_name, "read_file");
        assert_eq!(result.error, Some("File not found".to_string()));
        assert!(result.output.is_empty());
    }

    #[test]
    fn test_tool_result_from_result() {
        let ok_result: Result<String, String> = Ok("Success output".to_string());
        let result = ToolResult::from_result("test_tool", ok_result, 100);
        assert!(result.success);
        assert_eq!(result.output, "Success output");

        let err_result: Result<String, String> = Err("Error occurred".to_string());
        let result = ToolResult::from_result("test_tool", err_result, 100);
        assert!(!result.success);
        assert_eq!(result.error, Some("Error occurred".to_string()));
    }

    #[test]
    fn test_tool_result_to_llm_string() {
        let result = ToolResult::success("read_file", "Contents", 100);
        let llm_str = result.to_llm_string();
        assert!(llm_str.contains("<tool_result"));
        assert!(llm_str.contains("status=\"success\""));
        assert!(llm_str.contains("Contents"));
        assert!(llm_str.contains("</tool_result>"));

        let failed_result = ToolResult::failure("read_file", "Not found", 100);
        let llm_str = failed_result.to_llm_string();
        assert!(llm_str.contains("<tool_result"));
        assert!(llm_str.contains("status=\"error\""));
        assert!(llm_str.contains("Not found"));
    }

    #[test]
    fn test_schema_builder() {
        let (properties, required) = SchemaBuilder::new()
            .string_property("path", "File path", true)
            .integer_property("limit", "Max lines", false)
            .boolean_property("recursive", "Search recursively", false)
            .build();

        assert!(properties.contains_key("path"));
        assert!(properties.contains_key("limit"));
        assert!(properties.contains_key("recursive"));

        assert_eq!(required.len(), 1);
        assert!(required.contains(&"path"));
    }

    #[test]
    fn test_schema_builder_array_property() {
        let (properties, required) = SchemaBuilder::new()
            .array_property("patterns", "File patterns", "string", true)
            .build();

        assert!(properties.contains_key("patterns"));
        let prop = properties.get("patterns").unwrap().as_object().unwrap();
        assert_eq!(prop.get("type").unwrap(), "array");
        assert!(required.contains(&"patterns"));
    }

    #[test]
    fn test_tool_result_with_data() {
        let data = serde_json::json!({
            "lines": 100,
            "size": 2048
        });
        let result = ToolResult::success_with_data("file_info", "File info retrieved", data, 75);

        assert!(result.success);
        assert!(result.data.is_some());
        let result_data = result.data.unwrap();
        assert_eq!(result_data["lines"], 100);
        assert_eq!(result_data["size"], 2048);
    }
}
