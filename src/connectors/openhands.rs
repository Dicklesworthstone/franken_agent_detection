use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::{env_path_nonempty, excluded_scan_paths_from_env, path_is_excluded};
use super::{
    Connector, file_modified_since, flatten_content, franken_detection_for_connector,
    parse_timestamp,
};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
    NormalizedSnippet,
};

pub struct OpenHandsConnector;

impl Default for OpenHandsConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenHandsConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn conversations_root() -> PathBuf {
        if let Some(root) = env_path_nonempty("CASS_OPENHANDS_DATA_ROOT") {
            return root;
        }

        dirs::home_dir().map_or_else(
            || PathBuf::from(".openhands/conversations"),
            |home| home.join(".openhands/conversations"),
        )
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots = if ctx.use_default_detection() {
            vec![ScanRoot::local(Self::conversations_root())]
        } else {
            ctx.scan_roots.clone()
        };

        roots.sort_by(|left, right| left.path.cmp(&right.path));
        roots.dedup_by(|left, right| left.path == right.path);
        roots
    }

    fn is_conversation_dir(path: &Path) -> bool {
        path.join("events").is_dir()
    }

    fn conversation_dirs(scan_target: &Path) -> Vec<PathBuf> {
        if Self::is_conversation_dir(scan_target) {
            return vec![scan_target.to_path_buf()];
        }

        let mut conversation_dirs = Vec::new();

        for entry in WalkDir::new(scan_target)
            .min_depth(1)
            .max_depth(2)
            .into_iter()
            .flatten()
        {
            if !entry.file_type().is_dir() {
                continue;
            }

            let path = entry.path();
            if Self::is_conversation_dir(path) {
                conversation_dirs.push(path.to_path_buf());
            }
        }

        conversation_dirs.sort();
        conversation_dirs
    }

    fn event_files(conversation_dir: &Path) -> Vec<PathBuf> {
        let events_dir = conversation_dir.join("events");
        let Ok(entries) = fs::read_dir(events_dir) else {
            return Vec::new();
        };

        let mut event_files = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };

            if file_name.starts_with("event-") && file_name.ends_with(".json") {
                event_files.push(path);
            }
        }

        event_files.sort();
        event_files
    }

    fn read_json_file(path: &Path) -> Option<Value> {
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    fn read_base_state(conversation_dir: &Path) -> Option<Value> {
        Self::read_json_file(&conversation_dir.join("base_state.json"))
    }

    fn conversation_modified_since(conversation_dir: &Path, since_ts: Option<i64>) -> bool {
        if since_ts.is_none() {
            return true;
        }

        let base_state_path = conversation_dir.join("base_state.json");
        if file_modified_since(&base_state_path, since_ts) {
            return true;
        }

        Self::event_files(conversation_dir)
            .iter()
            .any(|event_path| file_modified_since(event_path, since_ts))
    }

    fn conversation_id(conversation_dir: &Path, base_state: Option<&Value>) -> Option<String> {
        base_state
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(String::from)
            .or_else(|| {
                conversation_dir
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(String::from)
            })
    }

    fn workspace_from_base_state(base_state: Option<&Value>) -> Option<PathBuf> {
        let workspace = base_state?.get("workspace")?;

        if let Some(path) = workspace.as_str() {
            return nonempty_path(path);
        }

        workspace
            .get("path")
            .or_else(|| workspace.get("root"))
            .or_else(|| workspace.get("cwd"))
            .and_then(Value::as_str)
            .and_then(nonempty_path)
    }

    fn model_from_base_state(base_state: Option<&Value>) -> Option<String> {
        base_state?
            .pointer("/agent/llm/model")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(String::from)
    }

    fn compact_base_state_metadata(base_state: Option<&Value>) -> Value {
        let Some(base_state) = base_state else {
            return serde_json::json!({ "source": "openhands" });
        };

        let configured_tools: Vec<Value> = base_state
            .pointer("/agent/tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .filter(|name| !name.trim().is_empty())
            .map(|name| Value::String(name.to_string()))
            .collect();

        let skill_summaries: Vec<Value> = base_state
            .pointer("/agent/agent_context/skills")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|skill| {
                serde_json::json!({
                    "name": skill.get("name").and_then(Value::as_str),
                    "source": skill.get("source").and_then(Value::as_str),
                    "version": skill.get("version").and_then(Value::as_str),
                    "description": skill.get("description").and_then(Value::as_str),
                    "is_agentskills_format": skill.get("is_agentskills_format").and_then(Value::as_bool),
                })
            })
            .collect();

        serde_json::json!({
            "source": "openhands",
            "id": base_state.get("id"),
            "model": base_state.pointer("/agent/llm/model"),
            "configured_tools": configured_tools,
            "include_default_tools": base_state.pointer("/agent/include_default_tools"),
            "confirmation_policy": base_state.get("confirmation_policy"),
            "execution_status": base_state.get("execution_status"),
            "stats": base_state.get("stats"),
            "tags": base_state.get("tags"),
            "activated_knowledge_skills": base_state.get("activated_knowledge_skills"),
            "invoked_skills": base_state.get("invoked_skills"),
            "skills": skill_summaries,
        })
    }

    fn compact_system_prompt_metadata(event: &Value) -> Value {
        let available_tools: Vec<Value> = event
            .get("tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|tool| {
                serde_json::json!({
                    "title": tool.get("title").and_then(Value::as_str),
                    "kind": tool.get("kind").and_then(Value::as_str),
                    "action_type": tool.get("action_type").and_then(Value::as_str),
                    "observation_type": tool.get("observation_type").and_then(Value::as_str),
                    "annotations": tool.get("annotations"),
                })
            })
            .collect();

        serde_json::json!({
            "id": event.get("id"),
            "created_at": event.get("timestamp"),
            "available_tools": available_tools,
        })
    }

    fn merge_metadata(base_state: Option<&Value>, system_prompt_event: Option<&Value>) -> Value {
        let mut metadata = Self::compact_base_state_metadata(base_state);

        if let Some(system_prompt_event) = system_prompt_event
            && let Some(map) = metadata.as_object_mut()
        {
            map.insert(
                "system_prompt".to_string(),
                Self::compact_system_prompt_metadata(system_prompt_event),
            );
        }

        metadata
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        Self::discover_sources_with_exclusions(ctx, &excluded_scan_paths_from_env())
    }

    fn discover_sources_with_exclusions(
        ctx: &ScanContext,
        excluded_paths: &[PathBuf],
    ) -> Vec<DiscoveredSourceFile> {
        let mut discovered_sources = Vec::new();

        for root in Self::source_roots(ctx) {
            if !root.path.exists() {
                continue;
            }

            for conversation_dir in Self::conversation_dirs(&root.path) {
                if path_is_excluded(&conversation_dir, excluded_paths) {
                    tracing::debug!(
                        path = %conversation_dir.display(),
                        "openhands skipping excluded conversation directory"
                    );
                    continue;
                }

                if !Self::conversation_modified_since(&conversation_dir, ctx.since_ts) {
                    continue;
                }

                discovered_sources.push(
                    DiscoveredSourceFile::new(
                        "openhands",
                        &root,
                        conversation_dir,
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
        }

        discovered_sources
    }

    fn parse_message_event(
        event: &Value,
        default_model: Option<&str>,
    ) -> Option<NormalizedMessage> {
        let content_value = event
            .pointer("/llm_message/content")
            .or_else(|| event.pointer("/message/content"))
            .or_else(|| event.get("content"))?;

        let content = flatten_content(content_value);
        if content.trim().is_empty() {
            return None;
        }

        Some(NormalizedMessage {
            idx: 0,
            role: Self::role_from_event(event),
            author: Self::author_from_event(event, default_model),
            created_at: event.get("timestamp").and_then(parse_timestamp),
            content,
            extra: Self::compact_message_event_extra(event),
            snippets: Vec::new(),
            invocations: Vec::new(),
        })
    }

    fn role_from_event(event: &Value) -> String {
        event
            .pointer("/llm_message/role")
            .and_then(Value::as_str)
            .or_else(|| event.pointer("/message/role").and_then(Value::as_str))
            .or_else(|| event.get("source").and_then(Value::as_str))
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("agent")
            .to_string()
    }

    fn author_from_event(event: &Value, default_model: Option<&str>) -> Option<String> {
        event
            .pointer("/llm_message/model")
            .or_else(|| event.pointer("/message/model"))
            .or_else(|| event.get("model"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(String::from)
            .or_else(|| {
                let role = Self::role_from_event(event);
                if role == "assistant" || role == "agent" {
                    default_model.map(String::from)
                } else {
                    None
                }
            })
    }

    fn compact_message_event_extra(event: &Value) -> Value {
        serde_json::json!({
            "id": event.get("id"),
            "kind": event.get("kind"),
            "source": event.get("source"),
            "activated_skills": event.get("activated_skills"),
            "extended_content_present": event
                .get("extended_content")
                .and_then(Value::as_array)
                .is_some_and(|items| !items.is_empty()),
            "llm_response_id": event.get("llm_response_id"),
            "responses_reasoning_item": compact_reasoning_item(event.pointer("/llm_message/responses_reasoning_item")
                .or_else(|| event.get("responses_reasoning_item"))),
        })
    }

    fn parse_action_event(event: &Value, default_model: Option<&str>) -> Option<NormalizedMessage> {
        let tool_name = event
            .get("tool_name")
            .and_then(Value::as_str)
            .or_else(|| event.pointer("/tool_call/name").and_then(Value::as_str))
            .or_else(|| event.pointer("/action/kind").and_then(Value::as_str))
            .filter(|value| !value.trim().is_empty())?;

        let action = event.get("action").cloned().unwrap_or(Value::Null);
        let action_kind = action.get("kind").and_then(Value::as_str).map(String::from);

        let arguments = Self::tool_arguments_from_action_event(event);

        let invocation = NormalizedInvocation {
            kind: "tool".to_string(),
            name: tool_name.to_string(),
            raw_name: action_kind,
            call_id: event
                .get("tool_call_id")
                .and_then(Value::as_str)
                .map(String::from),
            arguments: arguments.clone(),
        };

        let snippets = snippets_from_path_fields(&action);

        Some(NormalizedMessage {
            idx: 0,
            role: "agent".to_string(),
            author: default_model.map(String::from),
            created_at: event.get("timestamp").and_then(parse_timestamp),
            content: Self::action_event_content(event, tool_name, arguments.as_ref()),
            extra: Self::compact_action_event_extra(event),
            snippets,
            invocations: vec![invocation],
        })
    }

    fn tool_arguments_from_action_event(event: &Value) -> Option<Value> {
        let arguments = event.pointer("/tool_call/arguments")?;

        if let Some(argument_string) = arguments.as_str() {
            if argument_string.trim().is_empty() {
                return None;
            }

            return serde_json::from_str::<Value>(argument_string)
                .ok()
                .or_else(|| Some(Value::String(argument_string.to_string())));
        }

        Some(arguments.clone())
    }

    fn action_event_content(event: &Value, tool_name: &str, arguments: Option<&Value>) -> String {
        let mut lines = vec![format!("Tool call: {tool_name}")];

        if let Some(summary) = event.get("summary").and_then(Value::as_str) {
            lines.push(format!("Summary: {summary}"));
        }

        if let Some(security_risk) = event.get("security_risk").and_then(Value::as_str) {
            lines.push(format!("Security risk: {security_risk}"));
        }

        let command = event
            .pointer("/action/command")
            .or_else(|| arguments.and_then(|value| value.get("command")))
            .and_then(Value::as_str);
        if let Some(command) = command {
            lines.push(format!("Command: {command}"));
        }

        let path = event
            .pointer("/action/path")
            .or_else(|| arguments.and_then(|value| value.get("path")))
            .and_then(Value::as_str);
        if let Some(path) = path {
            lines.push(format!("Path: {path}"));
        }

        lines.join("\n")
    }

    fn compact_action_event_extra(event: &Value) -> Value {
        serde_json::json!({
            "id": event.get("id"),
            "kind": event.get("kind"),
            "source": event.get("source"),
            "tool_name": event.get("tool_name"),
            "tool_call_id": event.get("tool_call_id"),
            "llm_response_id": event.get("llm_response_id"),
            "security_risk": event.get("security_risk"),
            "summary": event.get("summary"),
            "action": event.get("action"),
            "action_kind": event.pointer("/action/kind"),
            "responses_reasoning_item": compact_reasoning_item(event.get("responses_reasoning_item")),
        })
    }

    fn parse_observation_event(event: &Value) -> Option<NormalizedMessage> {
        let tool_name = event
            .get("tool_name")
            .and_then(Value::as_str)
            .or_else(|| event.pointer("/observation/kind").and_then(Value::as_str))
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("tool");

        let observation = event.get("observation")?;
        let content = Self::observation_event_content(event, tool_name);
        if content.trim().is_empty() {
            return None;
        }

        Some(NormalizedMessage {
            idx: 0,
            role: "environment".to_string(),
            author: None,
            created_at: event.get("timestamp").and_then(parse_timestamp),
            content,
            extra: Self::compact_observation_event_extra(event),
            snippets: snippets_from_path_fields(observation),
            invocations: Vec::new(),
        })
    }

    fn observation_event_content(event: &Value, tool_name: &str) -> String {
        let mut lines = vec![format!("Tool result: {tool_name}")];

        let observation = event.get("observation");

        if let Some(is_error) = observation
            .and_then(|value| value.get("is_error"))
            .and_then(Value::as_bool)
        {
            lines.push(format!("Error: {is_error}"));
        }

        if let Some(exit_code) = observation
            .and_then(|value| value.get("exit_code"))
            .and_then(Value::as_i64)
        {
            lines.push(format!("Exit code: {exit_code}"));
        }

        if let Some(command) = observation
            .and_then(|value| value.get("command"))
            .and_then(Value::as_str)
        {
            lines.push(format!("Command: {command}"));
        }

        if let Some(path) = observation
            .and_then(|value| value.get("path"))
            .and_then(Value::as_str)
        {
            lines.push(format!("Path: {path}"));
        }

        if let Some(content_value) = observation.and_then(|value| value.get("content")) {
            let content = flatten_content(content_value);
            if !content.trim().is_empty() {
                lines.push("Output:".to_string());
                lines.push(content);
            }
        }

        lines.join("\n")
    }

    fn compact_observation_event_extra(event: &Value) -> Value {
        let observation = event.get("observation");

        serde_json::json!({
            "id": event.get("id"),
            "kind": event.get("kind"),
            "source": event.get("source"),
            "tool_name": event.get("tool_name"),
            "tool_call_id": event.get("tool_call_id"),
            "action_id": event.get("action_id"),
            "observation_kind": observation.and_then(|value| value.get("kind")),
            "is_error": observation
                .and_then(|value| value.get("is_error"))
                .and_then(Value::as_bool),
            "exit_code": observation
                .and_then(|value| value.get("exit_code"))
                .and_then(Value::as_i64),
            "timeout": observation
                .and_then(|value| value.get("timeout"))
                .and_then(Value::as_bool),
            "full_output_save_dir": observation.and_then(|value| value.get("full_output_save_dir")),
            "metadata": observation.and_then(|value| value.get("metadata")),
        })
    }

    fn title_from_messages(
        messages: &[NormalizedMessage],
        workspace: Option<&PathBuf>,
    ) -> Option<String> {
        messages
            .iter()
            .find(|message| message.role == "user")
            .map(|message| {
                message
                    .content
                    .lines()
                    .next()
                    .unwrap_or(&message.content)
                    .chars()
                    .take(100)
                    .collect::<String>()
            })
            .or_else(|| {
                workspace
                    .and_then(|path| path.file_name())
                    .and_then(|name| name.to_str())
                    .map(String::from)
            })
    }

    fn parse_conversation(conversation_dir: &Path) -> Result<Option<NormalizedConversation>> {
        let base_state = Self::read_base_state(conversation_dir);
        let workspace = Self::workspace_from_base_state(base_state.as_ref());
        let default_model = Self::model_from_base_state(base_state.as_ref());

        let mut messages = Vec::new();
        let mut system_prompt_event: Option<Value> = None;
        let mut started_at: Option<i64> = None;
        let mut ended_at: Option<i64> = None;

        for event_path in Self::event_files(conversation_dir) {
            let content = fs::read_to_string(&event_path)
                .with_context(|| format!("read {}", event_path.display()))?;

            let event: Value = match serde_json::from_str(&content) {
                Ok(value) => value,
                Err(error) => {
                    tracing::debug!(
                        path = %event_path.display(),
                        error = %error,
                        "openhands skipping malformed event JSON"
                    );
                    continue;
                }
            };

            let created_at = event.get("timestamp").and_then(parse_timestamp);
            started_at = min_optional_timestamp(started_at, created_at);
            ended_at = max_optional_timestamp(ended_at, created_at);

            let message = match event.get("kind").and_then(Value::as_str) {
                Some("SystemPromptEvent") => {
                    if system_prompt_event.is_none() {
                        system_prompt_event = Some(event);
                    }
                    None
                }
                Some("MessageEvent") => Self::parse_message_event(&event, default_model.as_deref()),
                Some("ActionEvent") => Self::parse_action_event(&event, default_model.as_deref()),
                Some("ObservationEvent") => Self::parse_observation_event(&event),
                Some(other_kind) => {
                    tracing::debug!(
                        kind = other_kind,
                        path = %event_path.display(),
                        "openhands skipping unsupported event kind"
                    );
                    None
                }
                None => None,
            };

            if let Some(message) = message {
                messages.push(message);
            }
        }

        crate::types::reindex_messages(&mut messages);

        if messages.is_empty() {
            return Ok(None);
        }

        let title = Self::title_from_messages(&messages, workspace.as_ref());

        Ok(Some(NormalizedConversation {
            agent_slug: "openhands".into(),
            external_id: Self::conversation_id(conversation_dir, base_state.as_ref()),
            title,
            workspace,
            source_path: conversation_dir.to_path_buf(),
            started_at,
            ended_at,
            metadata: Self::merge_metadata(base_state.as_ref(), system_prompt_event.as_ref()),
            messages,
        }))
    }
}

fn nonempty_path(path: &str) -> Option<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn compact_reasoning_item(reasoning_item: Option<&Value>) -> Value {
    let Some(reasoning_item) = reasoning_item else {
        return Value::Null;
    };

    serde_json::json!({
        "id": reasoning_item.get("id"),
        "summary": reasoning_item.get("summary"),
        "encrypted_content_present": reasoning_item.get("encrypted_content").is_some(),
    })
}

fn snippets_from_path_fields(value: &Value) -> Vec<NormalizedSnippet> {
    let mut snippets = Vec::new();

    if let Some(path) = value
        .get("path")
        .and_then(Value::as_str)
        .and_then(nonempty_path)
    {
        snippets.push(NormalizedSnippet {
            file_path: Some(path),
            start_line: value
                .get("start_line")
                .or_else(|| value.get("start"))
                .and_then(Value::as_i64),
            end_line: value
                .get("end_line")
                .or_else(|| value.get("end"))
                .and_then(Value::as_i64),
            language: None,
            snippet_text: None,
        });
    }

    snippets
}

fn min_optional_timestamp(current: Option<i64>, candidate: Option<i64>) -> Option<i64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.min(candidate)),
        (None, Some(candidate)) => Some(candidate),
        (current, None) => current,
    }
}

fn max_optional_timestamp(current: Option<i64>, candidate: Option<i64>) -> Option<i64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.max(candidate)),
        (None, Some(candidate)) => Some(candidate),
        (current, None) => current,
    }
}

fn scan_openhands_with_callback(
    ctx: &ScanContext,
    on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
) -> Result<()> {
    scan_openhands_with_callback_with_exclusions(
        ctx,
        on_conversation,
        &excluded_scan_paths_from_env(),
    )
}

fn scan_openhands_with_callback_with_exclusions(
    ctx: &ScanContext,
    on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    excluded_paths: &[PathBuf],
) -> Result<()> {
    for root in OpenHandsConnector::source_roots(ctx) {
        if !root.path.exists() {
            continue;
        }

        for conversation_dir in OpenHandsConnector::conversation_dirs(&root.path) {
            if path_is_excluded(&conversation_dir, excluded_paths) {
                tracing::debug!(
                    path = %conversation_dir.display(),
                    "openhands skipping excluded conversation directory"
                );
                continue;
            }

            if !OpenHandsConnector::conversation_modified_since(&conversation_dir, ctx.since_ts) {
                continue;
            }

            let Some(conversation) = OpenHandsConnector::parse_conversation(&conversation_dir)?
            else {
                continue;
            };

            on_conversation(conversation)?;
        }
    }

    Ok(())
}

impl Connector for OpenHandsConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("openhands").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut conversations = Vec::new();

        scan_openhands_with_callback(ctx, &mut |conversation| {
            conversations.push(conversation);
            Ok(())
        })?;

        Ok(conversations)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        scan_openhands_with_callback(ctx, on_conversation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_conversation_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("openhands")
            .join("conversations")
            .join("72b897ec80734566a3431f49ef7b8945")
    }

    /* Checks the basic happy path: the connector can scan that
     * conversation directory, returns exactly one
     * `NormalizedConversation`, marks it as `agent_slug = "openhands"`,
     * extracts the expected external ID, and gets at least one
     * message.
     */
    #[test]
    fn real_conversation_scans_successfully() {
        let conversation_dir = fixture_conversation_path();
        let connector = OpenHandsConnector::new();
        let roots = vec![ScanRoot::local(conversation_dir.clone())];
        let ctx = ScanContext::with_roots(conversation_dir.clone(), roots, None);
        let conversations = connector.scan(&ctx).unwrap();

        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].agent_slug, "openhands");
        assert_eq!(
            conversations[0].external_id.as_deref(),
            Some("72b897ec-8073-4566-a343-1f49ef7b8945"),
            "external_id should prefer base_state.id over the compact directory name"
        );
        assert!(!conversations[0].messages.is_empty());
    }

    /* Verifies normal `MessageEvents` are converted correctly: the
     * first user prompt is searchable as a `role = "user"` message,
     * and the assistant reply is searchable as `role = "assistant"`.
     */
    #[test]
    fn real_conversation_extracts_user_and_assistant_messages() {
        let conversation_dir = fixture_conversation_path();
        let connector = OpenHandsConnector::new();
        let roots = vec![ScanRoot::local(conversation_dir.clone())];
        let ctx = ScanContext::with_roots(conversation_dir.clone(), roots, None);
        let conversations = connector.scan(&ctx).unwrap();
        let messages = &conversations[0].messages;

        assert!(
            messages.iter().any(|message| message.role == "user"),
            "expected at least one user MessageEvent to become a user NormalizedMessage"
        );
        assert!(
            messages.iter().any(|message| message.role == "assistant"),
            "expected at least one assistant MessageEvent to become an assistant NormalizedMessage"
        );
    }

    /* Verifies `ActionEvent` becomes a synthetic `role = "agent"`
     * message with a `NormalizedInvocation`. Specifically, it checks the
     * `file_editor` call, its `tool_call_id`, `raw_name = FileEditorAction`,
     * and arguments.
     */
    #[test]
    fn real_conversation_extracts_action_events_as_tool_invocations() {
        let conversation_dir = fixture_conversation_path();
        let connector = OpenHandsConnector::new();
        let roots = vec![ScanRoot::local(conversation_dir.clone())];
        let ctx = ScanContext::with_roots(conversation_dir.clone(), roots, None);
        let conversations = connector.scan(&ctx).unwrap();
        let messages = &conversations[0].messages;
        let file_editor_call = messages
            .iter()
            .find(|message| {
                message.role == "agent"
                    && message
                        .invocations
                        .iter()
                        .any(|invocation| invocation.name == "file_editor")
            })
            .expect("expected file_editor ActionEvent to become an invocation");

        assert!(file_editor_call.content.contains("Tool call: file_editor"));
        assert!(file_editor_call.content.contains("README.md"));

        let invocation = &file_editor_call.invocations[0];
        assert_eq!(invocation.kind, "tool");
        assert_eq!(invocation.name, "file_editor");
        assert_eq!(invocation.raw_name.as_deref(), Some("FileEditorAction"));
        assert_eq!(
            invocation.call_id.as_deref(),
            Some("call_bs8Q0qjMyVYNe4UMTDaK5MRX")
        );
        assert!(invocation.arguments.is_some());
    }

    /* Verifies `ObservationEvent` becomes a synthetic `role = "environment"`
     * message, not an invocation. It checks the terminal result includes
     * `Tool result: terminal`, `Exit code: 0`, and preserves
     * `TerminalObservation` metadata.
     */
    #[test]
    fn real_conversation_extracts_observation_events_as_environment_messages() {
        let conversation_dir = fixture_conversation_path();
        let connector = OpenHandsConnector::new();
        let roots = vec![ScanRoot::local(conversation_dir.clone())];
        let ctx = ScanContext::with_roots(conversation_dir.clone(), roots, None);
        let conversations = connector.scan(&ctx).unwrap();
        let messages = &conversations[0].messages;
        let terminal_result = messages
            .iter()
            .find(|message| {
                message.role == "environment"
                    && message.content.contains("Tool result: terminal")
                    && message.content.contains("Exit code: 0")
            })
            .expect("expected terminal ObservationEvent to become environment message");

        assert!(terminal_result.invocations.is_empty());
        assert_eq!(
            terminal_result.extra["observation_kind"],
            serde_json::json!("TerminalObservation")
        );
    }

    /* Checks file paths from file-editor events are captured as
     * `NormalizedSnippet`s, so CASS can associate the conversation
     * with `/mnt/2TBSSD/Projects/uuid_service/README.md`.
     */
    #[test]
    fn real_conversation_extracts_file_paths_as_snippets() {
        let conversation_dir = fixture_conversation_path();
        let connector = OpenHandsConnector::new();
        let roots = vec![ScanRoot::local(conversation_dir.clone())];
        let ctx = ScanContext::with_roots(conversation_dir.clone(), roots, None);
        let conversations = connector.scan(&ctx).unwrap();
        let messages = &conversations[0].messages;

        assert!(
            messages.iter().any(|message| {
                message.snippets.iter().any(|snippet| {
                    snippet.file_path.as_deref()
                        == Some(Path::new("/mnt/2TBSSD/Projects/uuid_service/README.md"))
                })
            }),
            "expected README.md file_editor path to become a NormalizedSnippet"
        );
    }

    /* Checks `activated_skills: ["docker"]` is recorded in the metadata
     */
    #[test]
    fn fixture_conversation_preserves_activated_skills_as_message_metadata() {
        let conversation_dir = fixture_conversation_path();
        let connector = OpenHandsConnector::new();
        let roots = vec![ScanRoot::local(conversation_dir.clone())];
        let ctx = ScanContext::with_roots(conversation_dir.clone(), roots, None);

        let conversations = connector.scan(&ctx).unwrap();
        let docker_skill_message = conversations[0]
            .messages
            .iter()
            .find(|message| {
                message
                    .extra
                    .get("activated_skills")
                    .and_then(Value::as_array)
                    .is_some_and(|skills| skills.iter().any(|skill| skill == "docker"))
            })
            .expect("expected a message with activated_skills=[\"docker\"] metadata");

        assert!(
            docker_skill_message.invocations.is_empty(),
            "activated_skills is context metadata, not a tool/skill invocation"
        );
    }

    /* Checks messages are reindexed sequentially and that timeline
     * order is preserved: user message comes before file-editor
     * action, which comes before the matching observation.
     */
    #[test]
    fn real_conversation_preserves_event_order_after_normalization() {
        let conversation_dir = fixture_conversation_path();
        let connector = OpenHandsConnector::new();
        let roots = vec![ScanRoot::local(conversation_dir.clone())];
        let ctx = ScanContext::with_roots(conversation_dir.clone(), roots, None);

        let conversations = connector.scan(&ctx).unwrap();
        let messages = &conversations[0].messages;

        for (expected_idx, message) in messages.iter().enumerate() {
            assert_eq!(message.idx, expected_idx as i64);
        }

        let first_user_idx = messages
            .iter()
            .position(|message| message.role == "user")
            .unwrap();
        let first_action_idx = messages
            .iter()
            .position(|message| {
                message
                    .invocations
                    .iter()
                    .any(|invocation| invocation.name == "file_editor")
            })
            .unwrap();
        let first_observation_idx = messages
            .iter()
            .position(|message| {
                message.role == "environment"
                    && message.content.contains("Tool result: file_editor")
            })
            .unwrap();

        assert!(first_user_idx < first_action_idx);
        assert!(first_action_idx < first_observation_idx);
    }

    /* Checks `SystemPromptEvent` is not turned into a message, but
     * its compact tool metadata is stored on the conversation. It
     * verifies tools like `terminal` and `file_editor` appear in
     * `metadata.system_prompt.available_tools`.
     */
    #[test]
    fn real_conversation_has_compact_system_prompt_metadata() {
        let conversation_dir = fixture_conversation_path();
        let connector = OpenHandsConnector::new();
        let roots = vec![ScanRoot::local(conversation_dir.clone())];
        let ctx = ScanContext::with_roots(conversation_dir.clone(), roots, None);

        let conversations = connector.scan(&ctx).unwrap();
        let metadata = &conversations[0].metadata;

        assert_eq!(metadata["source"], "openhands");
        assert!(metadata.get("system_prompt").is_some());

        let available_tools = metadata["system_prompt"]["available_tools"]
            .as_array()
            .expect("available_tools should be an array");

        assert!(
            available_tools
                .iter()
                .any(|tool| tool["title"] == "terminal")
        );
        assert!(
            available_tools
                .iter()
                .any(|tool| tool["title"] == "file_editor")
        );
    }
}
