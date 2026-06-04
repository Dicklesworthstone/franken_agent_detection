//! `OpenHands` connector.
//!
//! `OpenHands` persists each conversation as a directory under
//! `~/.openhands/conversations/<conversation-id>/` containing:
//!
//! - `base_state.json` — session metadata (conversation `id`, the agent's LLM
//!   `model`, configured `tools`, and cached agent `skills`).
//! - `events/event-NNNNN-<uuid>.json` — one JSON file per timeline event, where
//!   the zero-padded `NNNNN` ordinal makes lexical filename order match timeline
//!   order.
//!
//! Unlike the message-centric normalized schema, `OpenHands` stores conversations
//! as a flat, heterogeneous **event stream** (see issue #10). Each event file
//! has a `"kind"` discriminator:
//!
//! - `SystemPromptEvent` — the system prompt plus tool definitions. Treated as
//!   conversation metadata; it does not become a message.
//! - `MessageEvent` — a chat message. `source: "user"` maps to `role: "user"`,
//!   `source: "agent"` maps to `role: "assistant"`. The text lives in
//!   `llm_message.content` (a Claude-style content-block array). `activated_skills`
//!   is preserved as message metadata.
//! - `ActionEvent` — a tool invocation. We synthesize an `assistant` message
//!   carrying a [`NormalizedInvocation`] built from `tool_name` /
//!   `tool_call_id` / the parsed `tool_call.arguments`. Any agent `thought`
//!   becomes the message content.
//! - `ObservationEvent` — the result of an `ActionEvent`. We fold the observation
//!   text back onto the originating action's invocation (joined via
//!   `tool_call_id`) under `extra.cass.tool_result`, and also emit a synthetic
//!   `role: "tool"` message so the result remains a first-class timeline entry.
//!
//! This mirrors the synthetic-message convention established by the Codex
//! connector, which is itself an event-stream source.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::{dedupe_path_key, env_path_nonempty};
use super::{
    Connector, file_modified_since, flatten_content, franken_detection_for_connector,
    parse_timestamp,
};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
};

/// Connector for the `OpenHands` coding agent.
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

    /// Default on-disk root holding per-conversation directories.
    fn conversations_root() -> PathBuf {
        if let Some(explicit) = env_path_nonempty("CASS_OPENHANDS_DATA_ROOT") {
            return explicit;
        }
        dirs::home_dir()
            .unwrap_or_default()
            .join(".openhands")
            .join("conversations")
    }

    /// A conversation directory is recognized by the presence of an `events/`
    /// subdirectory.
    fn is_conversation_dir(path: &Path) -> bool {
        path.join("events").is_dir()
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots = if ctx.use_default_detection() {
            vec![ScanRoot::local(Self::conversations_root())]
        } else {
            ctx.scan_roots.clone()
        };

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    /// Resolve every conversation directory reachable from a scan target.
    ///
    /// The target may itself be a conversation directory (an explicit single
    /// session) or a parent directory containing many of them.
    fn conversation_dirs(scan_target: &Path) -> Vec<PathBuf> {
        if Self::is_conversation_dir(scan_target) {
            return vec![scan_target.to_path_buf()];
        }

        let mut out = Vec::new();
        // Conversations live exactly one level under the root, but allow a
        // little nesting tolerance for users who group sessions in subfolders.
        for entry in WalkDir::new(scan_target)
            .min_depth(1)
            .max_depth(3)
            .into_iter()
            .flatten()
        {
            if entry.file_type().is_dir() && Self::is_conversation_dir(entry.path()) {
                out.push(entry.path().to_path_buf());
            }
        }

        out.sort();
        out.dedup();
        out
    }

    /// Event files for a conversation, in timeline (lexical filename) order.
    fn event_files(conversation_dir: &Path) -> Vec<PathBuf> {
        let events_dir = conversation_dir.join("events");
        let Ok(entries) = fs::read_dir(&events_dir) else {
            return Vec::new();
        };

        let mut files = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let is_json = path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
            if name.starts_with("event-") && is_json {
                files.push(path);
            }
        }
        // Sort by the numeric event ordinal, NOT lexically. OpenHands names
        // events `event-NNNNN-uuid.json`; a plain string sort only matches
        // timeline order while the zero-padding width is fixed, so once a
        // session passes 99,999 events `event-100000-` sorts before
        // `event-99999-`, reordering messages and — because ObservationEvents
        // fold onto their ActionEvent by processing order — orphaning tool
        // results. Parse the ordinal and sort on (ordinal, filename); files
        // whose ordinal can't be parsed sort last, then lexically.
        let event_ordinal = |p: &Path| -> u64 {
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(|name| name.strip_prefix("event-"))
                .and_then(|rest| rest.split('-').next())
                .and_then(|digits| digits.parse::<u64>().ok())
                .unwrap_or(u64::MAX)
        };
        files.sort_by(|a, b| {
            event_ordinal(a)
                .cmp(&event_ordinal(b))
                .then_with(|| a.cmp(b))
        });
        files
    }

    /// True when the base state or any event file is newer than `since_ts`.
    fn conversation_modified_since(conversation_dir: &Path, since_ts: Option<i64>) -> bool {
        if since_ts.is_none() {
            return true;
        }
        if file_modified_since(&conversation_dir.join("base_state.json"), since_ts) {
            return true;
        }
        Self::event_files(conversation_dir)
            .iter()
            .any(|path| file_modified_since(path, since_ts))
    }

    fn read_json_file(path: &Path) -> Option<Value> {
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    fn read_base_state(conversation_dir: &Path) -> Option<Value> {
        Self::read_json_file(&conversation_dir.join("base_state.json"))
    }

    fn conversation_id(conversation_dir: &Path, base_state: Option<&Value>) -> Option<String> {
        base_state
            .and_then(|v| v.get("id"))
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(String::from)
            .or_else(|| {
                conversation_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(String::from)
            })
    }

    fn model_from_base_state(base_state: Option<&Value>) -> Option<String> {
        base_state?
            .pointer("/agent/llm/model")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(String::from)
    }

    /// Distill the verbose `base_state.json` into compact conversation metadata.
    ///
    /// We keep only the model and the configured tool kinds; the rest (system
    /// prompts, full skill bodies, retry config) is large and not needed for
    /// timeline reconstruction.
    fn conversation_metadata(base_state: Option<&Value>, configured_tools: &[String]) -> Value {
        let mut map = serde_json::Map::new();
        map.insert("source".to_string(), Value::String("openhands".to_string()));
        if let Some(model) = Self::model_from_base_state(base_state) {
            map.insert("model".to_string(), Value::String(model));
        }
        if !configured_tools.is_empty() {
            map.insert(
                "tools".to_string(),
                Value::Array(
                    configured_tools
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
        Value::Object(map)
    }

    /// Tool names declared in a `SystemPromptEvent`'s `tools` array.
    fn tool_names_from_system_prompt(event: &Value) -> Vec<String> {
        event
            .get("tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|tool| {
                tool.get("title")
                    .or_else(|| tool.get("kind"))
                    .and_then(Value::as_str)
                    .map(String::from)
            })
            .collect()
    }
}

/// Parse an `OpenHands` event timestamp.
///
/// `OpenHands` records naive `ISO-8601` timestamps in UTC *without* a `Z` suffix
/// (e.g. `2026-05-20T19:00:55.619644`), which the shared [`parse_timestamp`]
/// helper does not accept. Normalize by appending `Z` so it is read as UTC,
/// then fall back to the shared parser for any other shape (epoch ints, `RFC3339`).
fn parse_event_timestamp(val: &Value) -> Option<i64> {
    if let Some(s) = val.as_str() {
        let trimmed = s.trim();
        let looks_naive_iso = trimmed.len() >= 19
            && trimmed.as_bytes().get(10) == Some(&b'T')
            && !trimmed.ends_with('Z')
            && !trimmed.contains('+')
            // Exclude a trailing numeric-offset like `-05:00`; a bare naive
            // datetime has no '-' after the date portion.
            && !trimmed[10..].contains('-');
        if looks_naive_iso {
            let normalized = format!("{trimmed}Z");
            if let Some(ms) = parse_timestamp(&Value::String(normalized)) {
                return Some(ms);
            }
        }
    }
    parse_timestamp(val)
}

/// Map an `OpenHands` `source` to a normalized message role.
fn role_for_source(source: &str) -> &'static str {
    match source {
        "user" => "user",
        // OpenHands "environment" carries tool results; everything else
        // (notably "agent") is the assistant speaking.
        _ => "assistant",
    }
}

/// Parse an `ActionEvent`'s tool arguments.
///
/// `OpenHands` stores arguments twice: as a JSON string in `tool_call.arguments`
/// (the raw model output) and as a structured object in `action`. Prefer the
/// parsed string form; fall back to the structured `action` object.
fn action_arguments(event: &Value) -> Option<Value> {
    if let Some(raw) = event
        .pointer("/tool_call/arguments")
        .and_then(Value::as_str)
    {
        if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
            return Some(parsed);
        }
        return Some(Value::String(raw.to_string()));
    }
    event.get("action").cloned()
}

fn update_time_bounds(started_at: &mut Option<i64>, ended_at: &mut Option<i64>, ts: Option<i64>) {
    if let Some(ts) = ts {
        *started_at = Some(started_at.map_or(ts, |cur| cur.min(ts)));
        *ended_at = Some(ended_at.map_or(ts, |cur| cur.max(ts)));
    }
}

/// Fold an observation's result text onto the originating action message.
///
/// Returns `true` when a matching action message was found and updated.
fn attach_observation_to_action(
    messages: &mut [NormalizedMessage],
    action_index_by_call_id: &HashMap<String, usize>,
    tool_call_id: &str,
    result_text: &str,
    is_error: bool,
) -> bool {
    let Some(&idx) = action_index_by_call_id.get(tool_call_id) else {
        return false;
    };
    let Some(message) = messages.get_mut(idx) else {
        return false;
    };

    if !message.extra.is_object() {
        message.extra = Value::Object(serde_json::Map::new());
    }
    if let Some(extra) = message.extra.as_object_mut() {
        let cass = extra
            .entry("cass".to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if !cass.is_object() {
            *cass = Value::Object(serde_json::Map::new());
        }
        if let Some(cass_obj) = cass.as_object_mut() {
            let mut result = serde_json::Map::new();
            result.insert(
                "content".to_string(),
                Value::String(result_text.to_string()),
            );
            result.insert("is_error".to_string(), Value::Bool(is_error));
            cass_obj.insert("tool_result".to_string(), Value::Object(result));
        }
    }
    true
}

#[allow(clippy::too_many_lines)]
fn parse_conversation(
    conversation_dir: &Path,
    scan_root: &ScanRoot,
) -> Option<NormalizedConversation> {
    let base_state = OpenHandsConnector::read_base_state(conversation_dir);
    let external_id = OpenHandsConnector::conversation_id(conversation_dir, base_state.as_ref());

    let mut messages: Vec<NormalizedMessage> = Vec::new();
    let mut started_at = None;
    let mut ended_at = None;
    let mut configured_tools: Vec<String> = Vec::new();
    let mut workspace: Option<PathBuf> = None;
    // call_id -> index of the action message carrying its invocation.
    let mut action_index_by_call_id: HashMap<String, usize> = HashMap::new();

    let event_files = OpenHandsConnector::event_files(conversation_dir);
    // The first event file is the conversation's stable representative source
    // path, matching the file-oriented `discover_source_files` contract.
    let source_path = event_files
        .first()
        .cloned()
        .unwrap_or_else(|| conversation_dir.to_path_buf());

    for event_path in &event_files {
        let Some(event) = OpenHandsConnector::read_json_file(event_path) else {
            continue;
        };
        let kind = event.get("kind").and_then(Value::as_str).unwrap_or("");
        let created = event.get("timestamp").and_then(parse_event_timestamp);

        match kind {
            "SystemPromptEvent" => {
                // Metadata only: collect tool names, no message emitted.
                for name in OpenHandsConnector::tool_names_from_system_prompt(&event) {
                    if !configured_tools.contains(&name) {
                        configured_tools.push(name);
                    }
                }
                update_time_bounds(&mut started_at, &mut ended_at, created);
            }
            "MessageEvent" => {
                let source = event
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or("agent");
                // Prefer the authoritative llm_message.role when present (a
                // MessageEvent may carry source:"environment" while its
                // llm_message.role is the real user/assistant role); fall back
                // to the top-level source otherwise.
                let role = event
                    .pointer("/llm_message/role")
                    .and_then(Value::as_str)
                    .map_or_else(|| role_for_source(source), role_for_source);
                let content = event
                    .pointer("/llm_message/content")
                    .map(flatten_content)
                    .unwrap_or_default();
                if content.trim().is_empty() {
                    continue;
                }

                let mut extra = serde_json::Map::new();
                if let Some(skills) = event
                    .get("activated_skills")
                    .and_then(Value::as_array)
                    .filter(|arr| !arr.is_empty())
                {
                    extra.insert("activated_skills".to_string(), Value::Array(skills.clone()));
                }

                update_time_bounds(&mut started_at, &mut ended_at, created);
                messages.push(NormalizedMessage {
                    idx: 0,
                    role: role.to_string(),
                    author: None,
                    created_at: created,
                    content,
                    extra: Value::Object(extra),
                    invocations: Vec::new(),
                    snippets: Vec::new(),
                });
            }
            "ActionEvent" => {
                let tool_name = event
                    .get("tool_name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let call_id = event
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .map(String::from);
                let arguments = action_arguments(&event);

                // The agent's pre-tool reasoning, when present, is the message
                // content; otherwise summarize the tool call.
                let thought = event
                    .get("thought")
                    .map(flatten_content)
                    .unwrap_or_default();
                let summary = event
                    .get("summary")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let content = if !thought.trim().is_empty() {
                    thought
                } else if !summary.trim().is_empty() {
                    format!("[Tool: {tool_name} - {summary}]")
                } else {
                    format!("[Tool: {tool_name}]")
                };

                update_time_bounds(&mut started_at, &mut ended_at, created);
                let message_index = messages.len();
                if let Some(id) = &call_id {
                    action_index_by_call_id.insert(id.clone(), message_index);
                }
                messages.push(NormalizedMessage {
                    idx: 0,
                    role: "assistant".to_string(),
                    author: None,
                    created_at: created,
                    content,
                    extra: Value::Object(serde_json::Map::new()),
                    invocations: vec![NormalizedInvocation {
                        kind: "tool".to_string(),
                        name: tool_name,
                        raw_name: None,
                        call_id,
                        arguments,
                    }],
                    snippets: Vec::new(),
                });
            }
            "ObservationEvent" => {
                let tool_call_id = event
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let result_text = event
                    .pointer("/observation/content")
                    .map(flatten_content)
                    .unwrap_or_default();
                let is_error = event
                    .pointer("/observation/is_error")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if let Some(cwd) = event
                    .pointer("/observation/metadata/working_dir")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                {
                    workspace.get_or_insert_with(|| PathBuf::from(cwd));
                }

                // Fold the result onto the originating action's invocation.
                if !tool_call_id.is_empty() {
                    attach_observation_to_action(
                        &mut messages,
                        &action_index_by_call_id,
                        tool_call_id,
                        &result_text,
                        is_error,
                    );
                }

                if result_text.trim().is_empty() {
                    continue;
                }

                let mut extra = serde_json::Map::new();
                if !tool_call_id.is_empty() {
                    extra.insert(
                        "tool_call_id".to_string(),
                        Value::String(tool_call_id.to_string()),
                    );
                }
                extra.insert("is_error".to_string(), Value::Bool(is_error));

                update_time_bounds(&mut started_at, &mut ended_at, created);
                // Emit the result as a first-class timeline entry. Role "tool"
                // is one of the schema's standard roles for tool results.
                messages.push(NormalizedMessage {
                    idx: 0,
                    role: "tool".to_string(),
                    author: Some("environment".to_string()),
                    created_at: created,
                    content: result_text,
                    extra: Value::Object(extra),
                    invocations: Vec::new(),
                    snippets: Vec::new(),
                });
            }
            _ => {}
        }
    }

    if messages.is_empty() {
        return None;
    }

    crate::types::reindex_messages(&mut messages);

    let title = messages
        .iter()
        .find(|m| m.role == "user")
        .or_else(|| messages.first())
        .and_then(|m| m.content.lines().next())
        .map(|line| line.chars().take(100).collect::<String>());

    let metadata =
        OpenHandsConnector::conversation_metadata(base_state.as_ref(), &configured_tools);

    Some(NormalizedConversation {
        agent_slug: "openhands".to_string(),
        external_id,
        title,
        workspace: workspace
            .map(|path| scan_root.rewrite_workspace(&path.to_string_lossy(), Some("openhands")))
            .map(PathBuf::from),
        source_path,
        started_at,
        ended_at,
        metadata,
        messages,
    })
}

fn scan_openhands_with_callback(
    ctx: &ScanContext,
    on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
) -> Result<()> {
    let roots = OpenHandsConnector::source_roots(ctx);
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for root in roots {
        if !root.path.exists() {
            continue;
        }
        for conversation_dir in OpenHandsConnector::conversation_dirs(&root.path) {
            if !seen.insert(dedupe_path_key(&conversation_dir)) {
                continue;
            }
            if !OpenHandsConnector::conversation_modified_since(&conversation_dir, ctx.since_ts) {
                continue;
            }
            if let Some(conversation) = parse_conversation(&conversation_dir, &root) {
                on_conversation(conversation)
                    .with_context(|| format!("emit conversation {}", conversation_dir.display()))?;
            }
        }
    }

    Ok(())
}

fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
    let roots = OpenHandsConnector::source_roots(ctx);
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for root in roots {
        if !root.path.exists() {
            continue;
        }
        for conversation_dir in OpenHandsConnector::conversation_dirs(&root.path) {
            if !OpenHandsConnector::conversation_modified_since(&conversation_dir, ctx.since_ts) {
                continue;
            }

            // The base_state.json is a metadata sidecar (model, tools, skills).
            let base_state_path = conversation_dir.join("base_state.json");
            if base_state_path.is_file() && seen.insert(dedupe_path_key(&base_state_path)) {
                out.push(
                    DiscoveredSourceFile::new(
                        "openhands",
                        &root,
                        base_state_path,
                        DiscoveredSourceRole::MetadataSidecar,
                        false,
                    )
                    .with_fs_metadata(),
                );
            }

            // Each event file is a required primary-session-log fragment.
            for event_path in OpenHandsConnector::event_files(&conversation_dir) {
                if !seen.insert(dedupe_path_key(&event_path)) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "openhands",
                        &root,
                        event_path,
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
        }
    }

    out
}

impl Connector for OpenHandsConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("openhands").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        scan_openhands_with_callback(ctx, &mut |conv| {
            convs.push(conv);
            Ok(())
        })?;
        Ok(convs)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(discover_sources(ctx))
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
    use crate::connectors::assert_discovery_covers_scan_sources;
    use std::path::Path;
    use tempfile::TempDir;

    /// Path to the checked-in realistic fixture conversation directory.
    fn fixture_conversation_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("openhands")
            .join("conversations")
            .join("a1b2c3d4e5f64718a9b0c1d2e3f40516")
    }

    fn fixture_ctx() -> ScanContext {
        let dir = fixture_conversation_dir();
        ScanContext::with_roots(dir.clone(), vec![ScanRoot::local(dir)], None)
    }

    #[test]
    fn new_creates_connector() {
        let _ = OpenHandsConnector::new();
        let _ = OpenHandsConnector;
    }

    #[test]
    fn is_conversation_dir_requires_events_subdir() {
        let dir = TempDir::new().unwrap();
        assert!(!OpenHandsConnector::is_conversation_dir(dir.path()));
        fs::create_dir_all(dir.path().join("events")).unwrap();
        assert!(OpenHandsConnector::is_conversation_dir(dir.path()));
    }

    #[test]
    fn event_files_sort_by_numeric_ordinal_past_99999() {
        let dir = TempDir::new().unwrap();
        let events = dir.path().join("events");
        fs::create_dir_all(&events).unwrap();
        // Names chosen so a lexical sort would wrongly place event-100000/100001
        // BEFORE event-99999. Written in non-sorted order to defeat readdir luck.
        for name in [
            "event-100001-cccc.json",
            "event-00009-aaaa.json",
            "event-100000-bbbb.json",
            "event-99999-dddd.json",
        ] {
            fs::write(events.join(name), "{}").unwrap();
        }
        let got: Vec<String> = OpenHandsConnector::event_files(dir.path())
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            got,
            vec![
                "event-00009-aaaa.json".to_string(),
                "event-99999-dddd.json".to_string(),
                "event-100000-bbbb.json".to_string(),
                "event-100001-cccc.json".to_string(),
            ],
            "event files must sort by numeric ordinal, not lexically",
        );
    }

    #[test]
    fn event_files_are_sorted_and_filtered() {
        let dir = TempDir::new().unwrap();
        let events = dir.path().join("events");
        fs::create_dir_all(&events).unwrap();
        fs::write(events.join("event-00002-z.json"), "{}").unwrap();
        fs::write(events.join("event-00000-a.json"), "{}").unwrap();
        fs::write(events.join("event-00001-m.json"), "{}").unwrap();
        fs::write(events.join("notes.txt"), "ignore").unwrap();
        fs::write(events.join("base_state.json"), "{}").unwrap();

        let files = OpenHandsConnector::event_files(dir.path());
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                "event-00000-a.json",
                "event-00001-m.json",
                "event-00002-z.json"
            ]
        );
    }

    #[test]
    fn discovery_covers_scan_sources_for_fixture() {
        let ctx = fixture_ctx();
        let connector = OpenHandsConnector::new();
        assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn discovery_finds_fixture_event_files_and_base_state() {
        let ctx = fixture_ctx();
        let connector = OpenHandsConnector::new();
        let discovered = connector.discover_source_files(&ctx).unwrap();

        assert!(
            discovered
                .iter()
                .any(|d| d.source_path.ends_with("base_state.json")
                    && d.role == DiscoveredSourceRole::MetadataSidecar
                    && !d.required_for_reconstruction),
            "base_state.json should be discovered as an optional metadata sidecar"
        );
        let event_count = discovered
            .iter()
            .filter(|d| d.role == DiscoveredSourceRole::PrimarySessionLog)
            .count();
        assert!(
            event_count >= 8,
            "expected the fixture's event files to be discovered, got {event_count}"
        );
        assert!(
            discovered.iter().all(|d| d.provider_slug == "openhands"),
            "every discovered source should be tagged openhands"
        );
    }

    #[test]
    fn scan_parses_fixture_into_messages_and_invocations() {
        let ctx = fixture_ctx();
        let connector = OpenHandsConnector::new();
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1, "fixture is a single conversation");
        let conv = &convs[0];
        assert_eq!(conv.agent_slug, "openhands");
        assert_eq!(
            conv.external_id.as_deref(),
            Some("a1b2c3d4-e5f6-4718-a9b0-c1d2e3f40516"),
            "external_id should come from base_state.json id"
        );
        assert_eq!(conv.metadata["model"], "openai/gpt-5.1");
        assert!(conv.started_at.is_some() && conv.ended_at.is_some());
        assert!(conv.started_at.unwrap() <= conv.ended_at.unwrap());

        // SystemPromptEvent contributes no message but populates tool metadata.
        let tool_meta = conv.metadata["tools"]
            .as_array()
            .expect("tools metadata array");
        assert!(tool_meta.iter().any(|t| t == "terminal"));
        assert!(tool_meta.iter().any(|t| t == "file_editor"));

        // Roles: at least one user, assistant, and tool message.
        assert!(conv.messages.iter().any(|m| m.role == "user"));
        assert!(conv.messages.iter().any(|m| m.role == "assistant"));
        assert!(conv.messages.iter().any(|m| m.role == "tool"));

        // Sequential indices.
        for (i, m) in conv.messages.iter().enumerate() {
            assert_eq!(m.idx, i64::try_from(i).unwrap());
        }
    }

    #[test]
    fn first_user_message_is_first_in_timeline() {
        let ctx = fixture_ctx();
        let convs = OpenHandsConnector::new().scan(&ctx).unwrap();
        let conv = &convs[0];
        // The first event after the system prompt is a user MessageEvent.
        assert_eq!(conv.messages[0].role, "user");
        assert!(
            conv.messages[0].content.contains("uuid_service"),
            "first user message content should be preserved, got: {}",
            conv.messages[0].content
        );
    }

    #[test]
    fn action_event_yields_assistant_message_with_invocation() {
        let ctx = fixture_ctx();
        let convs = OpenHandsConnector::new().scan(&ctx).unwrap();
        let conv = &convs[0];

        let action_msg = conv
            .messages
            .iter()
            .find(|m| m.invocations.iter().any(|inv| inv.name == "file_editor"))
            .expect("file_editor action message");
        assert_eq!(action_msg.role, "assistant");
        let inv = &action_msg.invocations[0];
        assert_eq!(inv.kind, "tool");
        assert_eq!(inv.call_id.as_deref(), Some("call_view_readme_0001"));
        // Arguments parsed from the JSON-string form.
        assert_eq!(inv.arguments.as_ref().unwrap()["command"], "view");
        assert_eq!(
            inv.arguments.as_ref().unwrap()["path"],
            "/mnt/2TBSSD/Projects/uuid_service/README.md"
        );
    }

    #[test]
    fn observation_joins_action_by_call_id() {
        let ctx = fixture_ctx();
        let convs = OpenHandsConnector::new().scan(&ctx).unwrap();
        let conv = &convs[0];

        let action_msg = conv
            .messages
            .iter()
            .find(|m| {
                m.invocations
                    .iter()
                    .any(|inv| inv.call_id.as_deref() == Some("call_view_readme_0001"))
            })
            .expect("action message with call id");

        let result = action_msg
            .extra
            .pointer("/cass/tool_result/content")
            .and_then(Value::as_str)
            .expect("tool_result folded onto action via call_id");
        assert!(
            result.contains("UUID Service"),
            "observation content should be joined onto the action, got: {result}"
        );
        assert_eq!(
            action_msg
                .extra
                .pointer("/cass/tool_result/is_error")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn observation_also_emitted_as_tool_message() {
        let ctx = fixture_ctx();
        let convs = OpenHandsConnector::new().scan(&ctx).unwrap();
        let conv = &convs[0];

        let tool_msg = conv
            .messages
            .iter()
            .find(|m| {
                m.role == "tool"
                    && m.extra.get("tool_call_id").and_then(Value::as_str)
                        == Some("call_view_readme_0001")
            })
            .expect("synthetic tool-result message");
        assert_eq!(tool_msg.author.as_deref(), Some("environment"));
        assert!(tool_msg.content.contains("UUID Service"));
    }

    #[test]
    fn activated_skills_preserved_as_message_metadata() {
        let ctx = fixture_ctx();
        let convs = OpenHandsConnector::new().scan(&ctx).unwrap();
        let conv = &convs[0];

        let skilled = conv
            .messages
            .iter()
            .find(|m| m.extra.get("activated_skills").is_some())
            .expect("a message with activated_skills");
        let skills = skilled.extra["activated_skills"]
            .as_array()
            .expect("activated_skills array");
        assert!(skills.iter().any(|s| s == "docker"));
    }

    #[test]
    fn timeline_ordering_is_preserved() {
        let ctx = fixture_ctx();
        let convs = OpenHandsConnector::new().scan(&ctx).unwrap();
        let conv = &convs[0];

        // Every action message must precede its joined tool-result message.
        for (action_idx, msg) in conv.messages.iter().enumerate() {
            for inv in &msg.invocations {
                let Some(call_id) = inv.call_id.as_deref() else {
                    continue;
                };
                let result_pos = conv.messages.iter().position(|m| {
                    m.role == "tool"
                        && m.extra.get("tool_call_id").and_then(Value::as_str) == Some(call_id)
                });
                if let Some(result_idx) = result_pos {
                    assert!(
                        action_idx < result_idx,
                        "action for {call_id} (idx {action_idx}) must precede its result (idx {result_idx})"
                    );
                }
            }
        }
    }

    #[test]
    fn scan_with_callback_matches_scan() {
        let ctx = fixture_ctx();
        let connector = OpenHandsConnector::new();
        let scanned = connector.scan(&ctx).unwrap();
        let mut streamed = Vec::new();
        connector
            .scan_with_callback(&ctx, &mut |conv| {
                streamed.push(conv);
                Ok(())
            })
            .unwrap();

        assert_eq!(streamed.len(), scanned.len());
        assert_eq!(streamed[0].messages.len(), scanned[0].messages.len());
    }

    #[test]
    fn discovery_finds_conversation_under_parent_root() {
        // Point at the conversations/ parent rather than the conversation dir.
        let parent = fixture_conversation_dir().parent().unwrap().to_path_buf();
        let ctx = ScanContext::with_roots(parent.clone(), vec![ScanRoot::local(parent)], None);
        let convs = OpenHandsConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1, "should resolve nested conversation dir");
    }

    #[test]
    fn scan_returns_empty_for_missing_root() {
        let ctx = ScanContext::with_roots(
            PathBuf::from("/no/such/openhands"),
            vec![ScanRoot::local(PathBuf::from("/no/such/openhands"))],
            None,
        );
        let convs = OpenHandsConnector::new().scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn since_ts_in_future_skips_conversation() {
        let ctx = ScanContext::with_roots(
            fixture_conversation_dir(),
            vec![ScanRoot::local(fixture_conversation_dir())],
            Some(i64::MAX),
        );
        let convs = OpenHandsConnector::new().scan(&ctx).unwrap();
        assert!(
            convs.is_empty(),
            "future since_ts should skip older fixture"
        );
    }
}
