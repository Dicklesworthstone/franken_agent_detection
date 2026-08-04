//! Connector for Kimi Code (Moonshot AI) session logs.
//!
//! Two on-disk schemas are supported (cass#351, cass#105):
//!
//! **Current Kimi Code** (`$KIMI_CODE_HOME`, default `~/.kimi-code`):
//! - `~/.kimi-code/sessions/<workDirKey>/<sessionId>/agents/<agentId>/wire.jsonl`
//! - Each line is a JSON object with a top-level `time` and a top-level `type`
//!   such as `turn.prompt`, `context.append_message`, or
//!   `context.append_loop_event` (whose nested `event.type` is
//!   `content.part`, `tool.call`, `tool.result`, `step.begin`, `step.end`, …).
//! - Session metadata (`title`, `workDir`) lives in `state.json` at the
//!   session root (`.../<sessionId>/state.json`), two levels above the wire.
//! - The session id is the directory above `agents/<agentId>`; the main-agent
//!   external id is `<sessionId>`, sub-agents are `<sessionId>:<agentId>` so
//!   sibling `main` directories never collide.
//!
//! **Legacy Kimi CLI** (`~/.kimi/sessions`):
//! - `~/.kimi/sessions/<workspace-hash>/<session-uuid>/wire.jsonl`
//! - Each line carries a top-level `timestamp` and a nested `message.type`
//!   (`TurnBegin`, `StepBegin`, `ContentPart`, `ToolCall`, …); `state.json`
//!   sits next to the wire file.

use std::collections::HashSet;
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::{
    Connector, file_modified_since, flatten_content, franken_detection_for_connector,
    parse_timestamp, utils::dedupe_path_key,
};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

/// Parse a Kimi timestamp, which may be a floating-point epoch seconds value.
/// Falls through to the standard `parse_timestamp` for other formats.
fn parse_kimi_timestamp(val: &Value) -> Option<i64> {
    // Kimi uses floating-point seconds (e.g., 1772857971.158032)
    if let Some(f) = val.as_f64() {
        if f.is_finite() && f > 0.0 {
            #[allow(clippy::cast_possible_truncation)]
            let ms = if f < 100_000_000_000.0 {
                (f * 1000.0).round() as i64
            } else {
                f.round() as i64
            };
            return Some(ms);
        }
    }
    parse_timestamp(val)
}

pub struct KimiConnector;

impl Default for KimiConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl KimiConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Default Kimi sessions roots, most-current first. Honors
    /// `$KIMI_CODE_HOME` (current Kimi Code), then `~/.kimi-code/sessions`,
    /// then the legacy `~/.kimi/sessions` layout. Only existing directories
    /// are returned. cass#351.
    fn default_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        let mut push_if_exists = |p: PathBuf| {
            if p.exists() && !roots.contains(&p) {
                roots.push(p);
            }
        };

        if let Some(home) = std::env::var_os("KIMI_CODE_HOME") {
            let home = PathBuf::from(home);
            if !home.as_os_str().is_empty() {
                push_if_exists(home.join("sessions"));
            }
        }

        if let Some(home) = dirs::home_dir() {
            push_if_exists(home.join(".kimi-code").join("sessions"));
            push_if_exists(home.join(".kimi").join("sessions"));
        }

        roots
    }

    fn looks_like_kimi_storage(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        // `.kimi-code` contains the `.kimi` substring, so this matches both the
        // current and legacy storage roots once a `sessions` segment is present.
        path_str.contains(".kimi") && path_str.contains("sessions")
    }

    fn append_kimi_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        if Self::looks_like_kimi_storage(base) {
            roots.push(base.to_path_buf());
            return;
        }

        // An explicit data root (`~/.kimi-code` or legacy `~/.kimi`): descend
        // into its `sessions/` subtree.
        if base
            .file_name()
            .is_some_and(|name| name == ".kimi-code" || name == ".kimi")
        {
            let candidate = base.join("sessions");
            if candidate.exists() {
                roots.push(candidate);
            }
            return;
        }

        for nested in [".kimi-code/sessions", ".kimi/sessions"] {
            let candidate = base.join(nested);
            if candidate.exists() {
                roots.push(candidate);
            }
        }
    }

    /// Find all wire.jsonl files under a root.
    fn wire_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if !root.exists() {
            return out;
        }

        for entry in WalkDir::new(root).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }

            if entry.file_name() == "wire.jsonl" {
                out.push(entry.path().to_path_buf());
            }
        }

        out.sort();
        out
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            let data_dir_is_kimi_storage =
                Self::looks_like_kimi_storage(&ctx.data_dir) && ctx.data_dir.exists();
            if data_dir_is_kimi_storage {
                roots.push(ScanRoot::local(ctx.data_dir.clone()));
            } else {
                for fallback in Self::default_roots() {
                    roots.push(ScanRoot::local(fallback));
                }
            }
        } else {
            for scan_root in &ctx.scan_roots {
                let mut candidates = Vec::new();
                Self::append_kimi_roots(&mut candidates, &scan_root.path);
                roots.extend(candidates.into_iter().map(|path| scan_root.with_path(path)));
            }

            if ctx.data_dir.exists() {
                let mut candidates = Vec::new();
                Self::append_kimi_roots(&mut candidates, &ctx.data_dir);
                roots.extend(candidates.into_iter().map(ScanRoot::local));
            }
        }

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        let mut seen_files: HashSet<PathBuf> = HashSet::new();
        for root in Self::source_roots(ctx) {
            if !root.path.exists() {
                continue;
            }
            for wire_path in Self::wire_files(&root.path) {
                if !seen_files.insert(dedupe_path_key(&wire_path)) {
                    continue;
                }
                if !file_modified_since(&wire_path, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "kimi",
                        &root,
                        wire_path.clone(),
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
                if let Some(state) = state_json_path(&wire_path) {
                    if state.exists() {
                        out.push(
                            DiscoveredSourceFile::new(
                                "kimi",
                                &root,
                                state,
                                DiscoveredSourceRole::MetadataSidecar,
                                false,
                            )
                            .with_fs_metadata(),
                        );
                    }
                }
            }
        }
        out
    }
}

impl Connector for KimiConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("kimi").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut roots: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();

        if roots.is_empty() {
            return Ok(Vec::new());
        }

        roots.sort();
        roots.dedup();

        let mut convs = Vec::new();
        let mut seen_files: HashSet<PathBuf> = HashSet::new();

        for root in roots {
            if !root.exists() {
                continue;
            }

            for wire_path in Self::wire_files(&root) {
                if !seen_files.insert(dedupe_path_key(&wire_path)) {
                    continue;
                }

                if !file_modified_since(&wire_path, ctx.since_ts) {
                    continue;
                }

                match parse_kimi_session(&wire_path) {
                    Ok(Some(conv)) => convs.push(conv),
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(
                            path = %wire_path.display(),
                            error = %e,
                            "kimi parse error"
                        );
                    }
                }
            }
        }

        Ok(convs)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

fn update_time_bounds(started_at: &mut Option<i64>, ended_at: &mut Option<i64>, ts: Option<i64>) {
    if let Some(ts) = ts {
        *started_at = Some(started_at.map_or(ts, |curr| curr.min(ts)));
        *ended_at = Some(ended_at.map_or(ts, |curr| curr.max(ts)));
    }
}

/// Resolved current-Kimi-Code layout coordinates for a `wire.jsonl` at
/// `.../<sessionId>/agents/<agentId>/wire.jsonl`.
struct ModernKimiLayout {
    session_id: String,
    agent_id: String,
    session_root: PathBuf,
}

/// Detect the current Kimi Code per-agent layout and return its coordinates.
/// Returns `None` for the legacy `<workspace>/<session>/wire.jsonl` layout.
fn modern_layout(wire_path: &Path) -> Option<ModernKimiLayout> {
    let agent_dir = wire_path.parent()?;
    let agents_dir = agent_dir.parent()?;
    if agents_dir.file_name().and_then(|n| n.to_str()) != Some("agents") {
        return None;
    }
    let session_root = agents_dir.parent()?.to_path_buf();
    let agent_id = agent_dir.file_name().and_then(|n| n.to_str())?.to_string();
    let session_id = session_root.file_name().and_then(|n| n.to_str())?.to_string();
    Some(ModernKimiLayout {
        session_id,
        agent_id,
        session_root,
    })
}

/// Read a workspace path from a Kimi `state.json` value, honoring both the
/// current `workDir` field and legacy `cwd`/`workspace`/… fields.
fn workspace_from_state(val: &Value) -> Option<PathBuf> {
    for key in &["workDir", "cwd", "workspace", "workspacePath", "projectPath"] {
        if let Some(path_str) = val.get(*key).and_then(|v| v.as_str()) {
            if !path_str.is_empty() {
                return Some(PathBuf::from(path_str));
            }
        }
    }
    None
}

/// Resolved conversation identity for a Kimi wire file, covering both the
/// current and legacy layouts.
struct KimiIdentity {
    /// Collision-free external id: `<sessionId>` for the main agent,
    /// `<sessionId>:<agentId>` for sub-agents, or the legacy session-dir name.
    external_id: Option<String>,
    /// Stable session id used in conversation metadata.
    session_id: Option<String>,
    workspace: Option<PathBuf>,
    /// Title taken from `state.json` when present (current layout).
    title: Option<String>,
}

fn resolve_identity(wire_path: &Path) -> KimiIdentity {
    if let Some(layout) = modern_layout(wire_path) {
        let external_id = if layout.agent_id == "main" {
            layout.session_id.clone()
        } else {
            format!("{}:{}", layout.session_id, layout.agent_id)
        };

        let mut workspace = None;
        let mut title = None;
        let state_path = layout.session_root.join("state.json");
        if let Ok(content) = fs::read_to_string(&state_path) {
            if let Ok(val) = serde_json::from_str::<Value>(&content) {
                workspace = workspace_from_state(&val);
                title = val
                    .get("title")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| s.chars().take(100).collect::<String>());
            }
        }

        return KimiIdentity {
            external_id: Some(external_id),
            session_id: Some(layout.session_id),
            workspace,
            title,
        };
    }

    // Legacy layout: `<workspace-hash>/<session-uuid>/wire.jsonl`.
    let session_id = wire_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(String::from);
    let workspace = wire_path.parent().and_then(|session_dir| {
        let state_path = session_dir.join("state.json");
        let content = fs::read_to_string(&state_path).ok()?;
        let val = serde_json::from_str::<Value>(&content).ok()?;
        workspace_from_state(&val)
    });

    KimiIdentity {
        external_id: session_id.clone(),
        session_id,
        workspace,
        title: None,
    }
}

/// Locate the `state.json` sidecar for either layout: at the session root two
/// levels above a modern wire, or next to a legacy wire.
fn state_json_path(wire_path: &Path) -> Option<PathBuf> {
    if let Some(layout) = modern_layout(wire_path) {
        return Some(layout.session_root.join("state.json"));
    }
    wire_path.parent().map(|dir| dir.join("state.json"))
}

/// Extract text content from a Kimi `ContentPart` payload.
fn extract_content_part_text(payload: &Value) -> String {
    // Try payload.content (string or array)
    if let Some(content) = payload.get("content") {
        let text = flatten_content(content);
        if !text.is_empty() {
            return text;
        }
    }

    // Try payload.text
    if let Some(text) = payload.get("text").and_then(|v| v.as_str()) {
        if !text.is_empty() {
            return text.to_string();
        }
    }

    // Try payload.value
    if let Some(text) = payload.get("value").and_then(|v| v.as_str()) {
        if !text.is_empty() {
            return text.to_string();
        }
    }

    String::new()
}

/// Extract tool call description from a `ToolCall` payload.
fn extract_tool_call_text(payload: &Value) -> String {
    let tool_name = payload
        .get("name")
        .or_else(|| payload.get("toolName"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let desc = payload
        .get("input")
        .and_then(|i| {
            i.get("description")
                .or_else(|| i.get("file_path"))
                .or_else(|| i.get("command"))
                .and_then(|v| v.as_str())
        })
        .or_else(|| {
            payload
                .get("arguments")
                .and_then(|a| a.as_str())
                .or_else(|| payload.get("parameters").and_then(|p| p.as_str()))
        })
        .unwrap_or("");

    if desc.is_empty() {
        format!("[Tool: {tool_name}]")
    } else {
        format!("[Tool: {tool_name} - {desc}]")
    }
}

/// Parse a Kimi wire.jsonl session file into a `NormalizedConversation`.
/// Streaming state for the current Kimi Code wire schema. Holds only the last
/// emitted user text so an adjacent `turn.prompt` and `context.append_message`
/// representing the same prompt collapse to a single normalized message.
#[derive(Default)]
struct ModernParseState {
    last_user_text: Option<String>,
}

/// Emit a deduplicated user message. `turn.prompt` and the following
/// `context.append_message` (role `user`) carry identical text; only the first
/// is kept until an assistant message resets the guard, so genuinely distinct
/// prompts in later turns are preserved.
fn push_modern_user_message(
    state: &mut ModernParseState,
    messages: &mut Vec<NormalizedMessage>,
    text: String,
    created: Option<i64>,
    extra: &Value,
) {
    if text.trim().is_empty() {
        return;
    }
    if state.last_user_text.as_deref() == Some(text.as_str()) {
        return;
    }
    state.last_user_text = Some(text.clone());
    messages.push(NormalizedMessage {
        idx: 0,
        role: "user".to_string(),
        author: None,
        created_at: created,
        content: text,
        extra: extra.clone(),
        invocations: Vec::new(),
        snippets: Vec::new(),
    });
}

/// Derive a human-readable tool description from a modern `tool.call` event's
/// `args` object.
fn modern_tool_description(args: Option<&Value>) -> String {
    args.and_then(|a| {
        a.get("path")
            .or_else(|| a.get("file_path"))
            .or_else(|| a.get("command"))
            .or_else(|| a.get("description"))
            .and_then(|v| v.as_str())
    })
    .unwrap_or("")
    .to_string()
}

/// Handle one current-Kimi-Code wire event (dispatched on its top-level
/// `type`). Unknown event types (`llm.request`, `usage.record`, `step.begin`,
/// `step.end`, `tool.result`, …) are skipped safely.
fn push_modern_kimi_event(
    state: &mut ModernParseState,
    messages: &mut Vec<NormalizedMessage>,
    event_type: &str,
    val: &Value,
    created: Option<i64>,
) {
    match event_type {
        "turn.prompt" => {
            let text = val.get("input").map(flatten_content).unwrap_or_default();
            push_modern_user_message(state, messages, text, created, val);
        }
        "context.append_message" => {
            let message = val.get("message");
            let role = message
                .and_then(|m| m.get("role"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Only the user turn is normalized here; assistant text is streamed
            // as `content.part` events, so emitting it again from
            // `append_message` would duplicate every assistant reply.
            if role == "user" {
                let text = message
                    .and_then(|m| m.get("content"))
                    .map(flatten_content)
                    .unwrap_or_default();
                push_modern_user_message(state, messages, text, created, val);
            }
        }
        "context.append_loop_event" => {
            let event = val.get("event");
            let inner_type = event
                .and_then(|e| e.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match inner_type {
                "content.part" => {
                    let part = event.and_then(|e| e.get("part"));
                    let part_type = part
                        .and_then(|p| p.get("type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("text");
                    // `think` parts are reasoning content and are intentionally
                    // not surfaced as visible assistant text.
                    if part_type != "text" {
                        return;
                    }
                    let content = part
                        .and_then(|p| p.get("text"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if !content.trim().is_empty() {
                        state.last_user_text = None;
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: "assistant".to_string(),
                            author: None,
                            created_at: created,
                            content: content.to_string(),
                            extra: val.clone(),
                            invocations: Vec::new(),
                            snippets: Vec::new(),
                        });
                    }
                }
                "tool.call" => {
                    let event = event.unwrap_or(val);
                    let tool_name = event
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let args = event.get("args");
                    let desc = modern_tool_description(args);
                    let content = if desc.is_empty() {
                        format!("[Tool: {tool_name}]")
                    } else {
                        format!("[Tool: {tool_name} - {desc}]")
                    };
                    let call_id = event
                        .get("toolCallId")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    state.last_user_text = None;
                    messages.push(NormalizedMessage {
                        idx: 0,
                        role: "assistant".to_string(),
                        author: None,
                        created_at: created,
                        content,
                        extra: val.clone(),
                        invocations: vec![crate::types::NormalizedInvocation {
                            kind: "tool".to_string(),
                            name: tool_name.to_string(),
                            raw_name: None,
                            call_id,
                            arguments: args.cloned(),
                        }],
                        snippets: Vec::new(),
                    });
                }
                _ => {}
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_lines)]
fn parse_kimi_session(path: &Path) -> Result<Option<NormalizedConversation>> {
    let file =
        fs::File::open(path).with_context(|| format!("open kimi wire file {}", path.display()))?;
    let reader = std::io::BufReader::new(file);

    let mut messages = Vec::new();
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut current_role = String::from("assistant");
    let mut modern_state = ModernParseState::default();

    for line_res in reader.lines() {
        let Ok(line) = line_res else {
            tracing::debug!("skipping unreadable JSONL line");
            continue;
        };

        if line.trim().is_empty() {
            continue;
        }

        let Ok(val) = serde_json::from_str::<Value>(&line) else {
            continue;
        };

        // Legacy lines carry a top-level `timestamp` (float seconds); current
        // Kimi Code lines carry a top-level `time` (ISO-8601 string).
        let created = val
            .get("timestamp")
            .and_then(parse_kimi_timestamp)
            .or_else(|| val.get("time").and_then(parse_kimi_timestamp));
        update_time_bounds(&mut started_at, &mut ended_at, created);

        let msg = val.get("message");
        let msg_type = msg.and_then(|m| m.get("type")).and_then(|v| v.as_str());

        // Also check top-level type for metadata lines
        let top_type = val.get("type").and_then(|v| v.as_str());

        // Current Kimi Code events are identified by a top-level `type` and have
        // no nested `message.type`; dispatch them to the modern handler.
        if msg_type.is_none() {
            if let Some(event_type) = top_type {
                push_modern_kimi_event(
                    &mut modern_state,
                    &mut messages,
                    event_type,
                    &val,
                    created,
                );
            }
            continue;
        }

        match (msg_type, top_type) {
            (Some("TurnBegin"), _) => {
                // TurnBegin signals a new turn; extract the role from the payload
                let payload = msg.and_then(|m| m.get("payload"));
                let turn_role = payload.and_then(|p| p.get("role")).and_then(|v| v.as_str());

                let is_user = matches!(turn_role, Some("human" | "user"));

                if is_user {
                    current_role = "user".to_string();
                } else {
                    current_role = "assistant".to_string();
                }

                // TurnBegin may carry initial content
                if let Some(payload) = payload {
                    let content = extract_content_part_text(payload);
                    if !content.trim().is_empty() {
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: current_role.clone(),
                            author: None,
                            created_at: created,
                            content,
                            extra: val.clone(),
                            invocations: Vec::new(),
                            snippets: Vec::new(),
                        });
                    }
                }

                // After a user TurnBegin, subsequent ContentParts are assistant responses
                if is_user {
                    current_role = "assistant".to_string();
                }
            }
            (Some("ContentPart"), _) => {
                let payload = msg.and_then(|m| m.get("payload"));
                let content = payload.map(extract_content_part_text).unwrap_or_default();

                if !content.trim().is_empty() {
                    messages.push(NormalizedMessage {
                        idx: 0,
                        role: current_role.clone(),
                        author: None,
                        created_at: created,
                        content,
                        extra: val,
                        invocations: Vec::new(),
                        snippets: Vec::new(),
                    });
                }
            }
            (Some("ToolCall"), _) => {
                let payload = msg.and_then(|m| m.get("payload"));
                let content =
                    payload.map_or_else(|| "[Tool: unknown]".to_string(), extract_tool_call_text);

                let invocations = payload.map_or_else(Vec::new, |p| {
                    let tool_name = p
                        .get("name")
                        .or_else(|| p.get("toolName"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    vec![crate::types::NormalizedInvocation {
                        kind: "tool".to_string(),
                        name: tool_name.to_string(),
                        raw_name: None,
                        call_id: None,
                        arguments: p
                            .get("input")
                            .or_else(|| p.get("arguments"))
                            .or_else(|| p.get("parameters"))
                            .cloned(),
                    }]
                });

                messages.push(NormalizedMessage {
                    idx: 0,
                    role: "assistant".to_string(),
                    author: None,
                    created_at: created,
                    content,
                    extra: val,
                    invocations,
                    snippets: Vec::new(),
                });
            }
            // Skip metadata, StepBegin, and other non-content types
            _ => {}
        }
    }

    crate::types::reindex_messages(&mut messages);

    if messages.is_empty() {
        return Ok(None);
    }

    let identity = resolve_identity(path);

    let title = identity.title.clone().or_else(|| {
        messages.iter().find(|m| m.role == "user").map(|m| {
            m.content
                .lines()
                .next()
                .unwrap_or(&m.content)
                .chars()
                .take(100)
                .collect::<String>()
        })
    });

    Ok(Some(NormalizedConversation {
        agent_slug: "kimi".into(),
        external_id: identity.external_id.clone(),
        title,
        workspace: identity.workspace,
        source_path: path.to_path_buf(),
        started_at,
        ended_at,
        metadata: serde_json::json!({
            "source": "kimi",
            "sessionId": identity.session_id,
        }),
        messages,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // =========================================================================
    // Constructor tests
    // =========================================================================

    #[test]
    fn new_creates_connector() {
        let connector = KimiConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = KimiConnector;
        let _ = connector;
    }

    // =========================================================================
    // Helper to create Kimi storage layout
    // =========================================================================

    fn create_kimi_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join(".kimi").join("sessions");
        fs::create_dir_all(&storage).unwrap();
        storage
    }

    fn write_wire_file(storage: &Path, workspace_hash: &str, session_id: &str, lines: &[&str]) {
        let session_dir = storage.join(workspace_hash).join(session_id);
        fs::create_dir_all(&session_dir).unwrap();
        let file_path = session_dir.join("wire.jsonl");
        fs::write(&file_path, lines.join("\n")).unwrap();
    }

    // =========================================================================
    // Detection tests
    // =========================================================================

    #[test]
    fn detect_not_found_without_sessions_dir() {
        let connector = KimiConnector::new();
        let result = connector.detect();
        let _ = result.detected;
    }

    // =========================================================================
    // JSONL parsing tests
    // =========================================================================

    #[test]
    fn scan_parses_turn_begin_and_content_parts() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"type": "metadata", "protocol_version": "1.3"}"#,
            r#"{"timestamp": 1772857971.158, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Hello Kimi"}}}"#,
            r#"{"timestamp": 1772857980.325, "message": {"type": "ContentPart", "payload": {"content": "Hello! How can I help you?"}}}"#,
        ];
        write_wire_file(&storage, "abc123", "sess-001", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "kimi");
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Kimi");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert!(
            convs[0].messages[1]
                .content
                .contains("Hello! How can I help")
        );
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_with_explicit_roots_scans_all_roots() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let storage_a = create_kimi_storage(&dir_a);
        let storage_b = create_kimi_storage(&dir_b);

        let lines_a = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Hello A"}}}"#,
            r#"{"timestamp": 1772857980.0, "message": {"type": "ContentPart", "payload": {"content": "Hi A"}}}"#,
        ];
        let lines_b = vec![
            r#"{"timestamp": 1772857972.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Hello B"}}}"#,
            r#"{"timestamp": 1772857981.0, "message": {"type": "ContentPart", "payload": {"content": "Hi B"}}}"#,
        ];

        write_wire_file(&storage_a, "work-a", "sess-a", &lines_a);
        write_wire_file(&storage_b, "work-b", "sess-b", &lines_b);

        let connector = KimiConnector::new();
        let ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![
                ScanRoot::local(dir_a.path().to_path_buf()),
                ScanRoot::local(dir_b.path().to_path_buf()),
            ],
            None,
        );

        let mut convs = connector.scan(&ctx).unwrap();
        convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));
        let ids: Vec<_> = convs
            .iter()
            .filter_map(|c| c.external_id.as_deref())
            .collect();
        assert_eq!(ids, vec!["sess-a", "sess-b"]);
    }

    #[test]
    fn scan_with_explicit_root_at_kimi_dir() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"type": "metadata", "protocol_version": "1.3"}"#,
            r#"{"timestamp": 1772857971.158, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Hello Kimi"}}}"#,
        ];
        write_wire_file(&storage, "abc123", "sess-001", &lines);

        let kimi_dir = dir.path().join(".kimi");

        let connector = KimiConnector::new();
        let ctx = ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(kimi_dir)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id, Some("sess-001".to_string()));
    }

    #[test]
    fn scan_extracts_tool_calls() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Read main.rs"}}}"#,
            r#"{"timestamp": 1772857980.0, "message": {"type": "ToolCall", "payload": {"name": "Read", "input": {"file_path": "/src/main.rs"}}}}"#,
            r#"{"timestamp": 1772857985.0, "message": {"type": "ContentPart", "payload": {"content": "Here is the file content."}}}"#,
        ];
        write_wire_file(&storage, "abc123", "sess-002", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 3);
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert!(convs[0].messages[1].content.contains("[Tool: Read"));
    }

    #[test]
    fn scan_infers_session_id_from_directory() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "test"}}}"#,
        ];
        write_wire_file(&storage, "wshash", "my-session-uuid", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id, Some("my-session-uuid".to_string()));
    }

    #[test]
    fn scan_reads_workspace_from_state_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let session_dir = storage.join("wshash").join("sess-ws");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(
            session_dir.join("wire.jsonl"),
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "hello"}}}"#,
        )
        .unwrap();
        fs::write(
            session_dir.join("state.json"),
            r#"{"cwd": "/home/user/myproject"}"#,
        )
        .unwrap();

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/myproject"))
        );
    }

    #[test]
    fn scan_generates_title_from_first_user_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Explain the architecture of this project"}}}"#,
            r#"{"timestamp": 1772857980.0, "message": {"type": "ContentPart", "payload": {"content": "Sure, let me explain..."}}}"#,
        ];
        write_wire_file(&storage, "wshash", "sess-title", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].title,
            Some("Explain the architecture of this project".to_string())
        );
    }

    #[test]
    fn scan_tracks_time_bounds() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "first"}}}"#,
            r#"{"timestamp": 1772858000.0, "message": {"type": "ContentPart", "payload": {"content": "second"}}}"#,
        ];
        write_wire_file(&storage, "wshash", "sess-time", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
        assert!(convs[0].started_at.unwrap() <= convs[0].ended_at.unwrap());
    }

    #[test]
    fn scan_role_switches_on_turn_begin() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "User message"}}}"#,
            r#"{"timestamp": 1772857980.0, "message": {"type": "ContentPart", "payload": {"content": "Assistant reply"}}}"#,
            r#"{"timestamp": 1772857990.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Second user message"}}}"#,
        ];
        write_wire_file(&storage, "wshash", "sess-roles", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert_eq!(convs[0].messages[2].role, "user");
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn edge_empty_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let session_dir = storage.join("ws").join("sess-empty");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("wire.jsonl"), b"").unwrap();

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs.is_empty());
    }

    #[test]
    fn edge_metadata_only_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![r#"{"type": "metadata", "protocol_version": "1.3"}"#];
        write_wire_file(&storage, "ws", "sess-meta-only", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs.is_empty());
    }

    #[test]
    fn edge_malformed_json_lines_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let session_dir = storage.join("ws").join("sess-malformed");
        fs::create_dir_all(&session_dir).unwrap();
        let content = concat!(
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Valid"}}}"#,
            "\n",
            "not valid json {{{",
            "\n",
            r#"{"timestamp": 1772857980.0, "message": {"type": "ContentPart", "payload": {"content": "Also valid"}}}"#,
            "\n",
        );
        fs::write(session_dir.join("wire.jsonl"), content).unwrap();

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn edge_empty_content_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "ContentPart", "payload": {"content": ""}}}"#,
            r#"{"timestamp": 1772857975.0, "message": {"type": "ContentPart", "payload": {"content": "   "}}}"#,
            r#"{"timestamp": 1772857980.0, "message": {"type": "ContentPart", "payload": {"content": "Real content"}}}"#,
        ];
        write_wire_file(&storage, "ws", "sess-empty-content", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Real content");
    }

    #[test]
    fn edge_multiple_sessions_found() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines1 = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Session 1"}}}"#,
        ];
        let lines2 = vec![
            r#"{"timestamp": 1772858000.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Session 2"}}}"#,
        ];
        write_wire_file(&storage, "ws1", "sess-a", &lines1);
        write_wire_file(&storage, "ws2", "sess-b", &lines2);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn edge_step_begin_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_storage(&dir);

        let lines = vec![
            r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "Hello"}}}"#,
            r#"{"timestamp": 1772857975.0, "message": {"type": "StepBegin", "payload": {"step": 1}}}"#,
            r#"{"timestamp": 1772857980.0, "message": {"type": "ContentPart", "payload": {"content": "Response"}}}"#,
        ];
        write_wire_file(&storage, "ws", "sess-step", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].content, "Hello");
        assert_eq!(convs[0].messages[1].content, "Response");
    }

    // =========================================================================
    // Current Kimi Code layout (cass#351): $KIMI_CODE_HOME / nested wire schema
    // =========================================================================

    /// Build a modern `~/.kimi-code`-style layout and return the `sessions`
    /// root. Path: `<sessions>/<workDirKey>/<sessionId>/agents/<agentId>/wire.jsonl`
    /// with `state.json` at the session root.
    fn create_kimi_code_storage(dir: &TempDir) -> PathBuf {
        let sessions = dir.path().join(".kimi-code").join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        sessions
    }

    fn write_modern_wire(
        sessions: &Path,
        work_dir_key: &str,
        session_id: &str,
        agent_id: &str,
        lines: &[&str],
        state_json: Option<&str>,
    ) {
        let session_root = sessions.join(work_dir_key).join(session_id);
        let agent_dir = session_root.join("agents").join(agent_id);
        fs::create_dir_all(&agent_dir).unwrap();
        fs::write(agent_dir.join("wire.jsonl"), lines.join("\n")).unwrap();
        if let Some(state) = state_json {
            fs::write(session_root.join("state.json"), state).unwrap();
        }
    }

    fn scan_modern(sessions: &Path) -> Vec<NormalizedConversation> {
        let connector = KimiConnector::new();
        let ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![ScanRoot::local(sessions.to_path_buf())],
            None,
        );
        connector.scan(&ctx).unwrap()
    }

    #[test]
    fn modern_main_agent_session_normalizes_user_assistant_and_tool() {
        let dir = TempDir::new().unwrap();
        let sessions = create_kimi_code_storage(&dir);
        let lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Read the config"}],"origin":"cli","time":"2026-01-01T00:00:00Z"}"#,
            r#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"Read the config"}],"toolCalls":[],"origin":"cli"},"time":"2026-01-01T00:00:00Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"step.begin"},"time":"2026-01-01T00:00:01Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"think","text":"internal reasoning"}},"time":"2026-01-01T00:00:02Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","text":"Here is the config"}},"time":"2026-01-01T00:00:03Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"tool.call","toolCallId":"call_1","name":"ReadFile","args":{"path":"/proj/config.toml"}},"time":"2026-01-01T00:00:04Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"tool.result","toolCallId":"call_1","result":{"output":"..."}},"time":"2026-01-01T00:00:05Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"step.end"},"time":"2026-01-01T00:00:06Z"}"#,
            r#"{"type":"usage.record","time":"2026-01-01T00:00:07Z"}"#,
        ];
        write_modern_wire(
            &sessions,
            "wd_abc",
            "session_xyz",
            "main",
            &lines,
            Some(r#"{"title":"Config review","workDir":"/proj","createdAt":"2026-01-01T00:00:00Z"}"#),
        );

        let convs = scan_modern(&sessions);
        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        // Main-agent external id is the session id (no `main` collision).
        assert_eq!(conv.external_id, Some("session_xyz".to_string()));
        assert_eq!(conv.workspace, Some(PathBuf::from("/proj")));
        assert_eq!(conv.title, Some("Config review".to_string()));
        // user (deduped once), assistant text (think skipped), tool call.
        assert_eq!(conv.messages.len(), 3);
        assert_eq!(conv.messages[0].role, "user");
        assert_eq!(conv.messages[0].content, "Read the config");
        assert_eq!(conv.messages[1].role, "assistant");
        assert_eq!(conv.messages[1].content, "Here is the config");
        assert_eq!(conv.messages[2].role, "assistant");
        assert!(conv.messages[2].content.contains("[Tool: ReadFile"));
        assert_eq!(conv.messages[2].invocations.len(), 1);
        assert_eq!(conv.messages[2].invocations[0].name, "ReadFile");
        assert_eq!(
            conv.messages[2].invocations[0].call_id,
            Some("call_1".to_string())
        );
        assert!(conv.started_at.is_some() && conv.ended_at.is_some());
    }

    #[test]
    fn modern_turn_prompt_without_append_message_still_emits_user() {
        let dir = TempDir::new().unwrap();
        let sessions = create_kimi_code_storage(&dir);
        let lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Only a prompt"}],"time":"2026-01-01T00:00:00Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","text":"Reply"}},"time":"2026-01-01T00:00:01Z"}"#,
        ];
        write_modern_wire(&sessions, "wd", "sess_only_prompt", "main", &lines, None);
        let convs = scan_modern(&sessions);
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Only a prompt");
    }

    #[test]
    fn modern_sibling_main_sessions_do_not_collide() {
        let dir = TempDir::new().unwrap();
        let sessions = create_kimi_code_storage(&dir);
        let lines_a = vec![
            r#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"A"}]},"time":"2026-01-01T00:00:00Z"}"#,
        ];
        let lines_b = vec![
            r#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"B"}]},"time":"2026-01-01T00:00:00Z"}"#,
        ];
        write_modern_wire(&sessions, "wd1", "session_one", "main", &lines_a, None);
        write_modern_wire(&sessions, "wd2", "session_two", "main", &lines_b, None);
        let mut convs = scan_modern(&sessions);
        convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));
        let ids: Vec<_> = convs.iter().filter_map(|c| c.external_id.as_deref()).collect();
        assert_eq!(ids, vec!["session_one", "session_two"]);
    }

    #[test]
    fn modern_sub_agent_gets_namespaced_external_id() {
        let dir = TempDir::new().unwrap();
        let sessions = create_kimi_code_storage(&dir);
        let main_lines = vec![
            r#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"main task"}]},"time":"2026-01-01T00:00:00Z"}"#,
        ];
        let sub_lines = vec![
            r#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"sub task"}]},"time":"2026-01-01T00:00:00Z"}"#,
        ];
        write_modern_wire(&sessions, "wd", "session_multi", "main", &main_lines, None);
        write_modern_wire(&sessions, "wd", "session_multi", "sub-agent-7", &sub_lines, None);
        let mut convs = scan_modern(&sessions);
        convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));
        let ids: Vec<_> = convs.iter().filter_map(|c| c.external_id.as_deref()).collect();
        assert_eq!(ids, vec!["session_multi", "session_multi:sub-agent-7"]);
    }

    #[test]
    fn modern_malformed_and_truncated_lines_do_not_abort() {
        let dir = TempDir::new().unwrap();
        let sessions = create_kimi_code_storage(&dir);
        let lines = vec![
            r#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"Valid one"}]},"time":"2026-01-01T00:00:00Z"}"#,
            "not json at all {{{",
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","text":"Valid reply"}},"time":"2026-01-01T00:00:01Z"}"#,
            r#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"trunc"#,
        ];
        write_modern_wire(&sessions, "wd", "sess_malformed", "main", &lines, None);
        let convs = scan_modern(&sessions);
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn modern_explicit_kimi_code_root_is_discovered() {
        // An explicit `~/.kimi-code` data root (as diag/scan would pass) is
        // descended into its `sessions/` subtree and parsed. This mirrors the
        // KIMI_CODE_HOME production path without mutating the process env
        // (`std::env::set_var` is unsafe and forbidden crate-wide).
        let dir = TempDir::new().unwrap();
        let sessions = create_kimi_code_storage(&dir);
        write_modern_wire(
            &sessions,
            "wd",
            "sess_root",
            "main",
            &[r#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"root marker"}]},"time":"2026-01-01T00:00:00Z"}"#],
            None,
        );

        let kimi_code_dir = dir.path().join(".kimi-code");
        let connector = KimiConnector::new();
        let ctx =
            ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(kimi_code_dir)], None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id, Some("sess_root".to_string()));
        assert_eq!(convs[0].messages[0].content, "root marker");
    }
}
