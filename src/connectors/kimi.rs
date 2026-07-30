//! Connector for Kimi Code (Moonshot AI) session logs.
//!
//! Kimi Code stores sessions in JSONL files in two layouts:
//!
//! **Legacy** (`~/.kimi/`):
//! - `~/.kimi/sessions/<workspace-hash>/<session-uuid>/wire.jsonl`
//!
//! Each legacy line is a JSON object with `timestamp` and `message` fields.
//! Message types include: `TurnBegin`, `StepBegin`, `ContentPart`, `ToolCall`, etc.
//! Additional files in each legacy session directory:
//! - `context.jsonl` — context/conversation data
//! - `state.json` — session state
//!
//! **Modern** (Kimi Code 0.28+, `$KIMI_CODE_HOME`, default `~/.kimi-code/`):
//! - `~/.kimi-code/sessions/<workDirKey>/<sessionId>/state.json`
//! - `~/.kimi-code/sessions/<workDirKey>/<sessionId>/agents/<agentId>/wire.jsonl`
//!
//! Each modern line is a JSON object with a top-level `type` (`turn.prompt`,
//! `context.append_message`, `context.append_loop_event`, `llm.request`,
//! `usage.record`, ...) and an RFC3339 `time` field. `state.json` carries
//! `title`, `workDir`, `createdAt`, and `updatedAt`.

use std::collections::{HashMap, HashSet};
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

    /// All candidate Kimi sessions roots in priority order.
    ///
    /// `$KIMI_CODE_HOME/sessions` (when the env var is set) is probed first,
    /// then the modern default `~/.kimi-code/sessions`, then the legacy
    /// `~/.kimi/sessions`.
    fn kimi_session_roots() -> Vec<PathBuf> {
        Self::kimi_session_roots_from(
            super::utils::env_path_nonempty("KIMI_CODE_HOME"),
            dirs::home_dir().as_deref(),
        )
    }

    /// Pure candidate-root derivation shared by [`Self::kimi_session_roots`],
    /// split out so env-driven resolution can be unit-tested without mutating
    /// process environment (`std::env::set_var` is `unsafe` and forbidden at
    /// the crate level).
    fn kimi_session_roots_from(
        override_home: Option<PathBuf>,
        home: Option<&Path>,
    ) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(env_home) = override_home {
            out.push(env_home.join("sessions"));
        }
        if let Some(home) = home {
            out.push(home.join(".kimi-code").join("sessions"));
            out.push(home.join(".kimi").join("sessions"));
        }
        out
    }

    /// Check whether a path looks like Kimi session storage.
    ///
    /// Uses component-window matching (not substring matching) so `.kimi`
    /// and `.kimi-code` are matched as whole path segments: either a
    /// `.kimi/sessions` / `.kimi-code/sessions` pair anywhere in the path,
    /// or a path whose final component is the `.kimi` / `.kimi-code` home
    /// itself.
    fn looks_like_kimi_storage(path: &Path) -> bool {
        let segments: Vec<String> = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect();

        // <...>/.kimi/sessions/<...> or <...>/.kimi-code/sessions/<...>
        if segments
            .windows(2)
            .any(|pair| (pair[0] == ".kimi" || pair[0] == ".kimi-code") && pair[1] == "sessions")
        {
            return true;
        }

        // The directory itself is a `.kimi` / `.kimi-code` home.
        segments
            .last()
            .is_some_and(|s| s == ".kimi" || s == ".kimi-code")
    }

    fn append_kimi_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        // A direct wire.jsonl file path: scan from its parent directory so
        // `wire_files` (a WalkDir) finds exactly that file.
        if base.file_name().is_some_and(|name| name == "wire.jsonl") && base.is_file() {
            if let Some(parent) = base.parent() {
                roots.push(parent.to_path_buf());
            }
            return;
        }

        // A `.kimi` / `.kimi-code` home directory: scan its sessions dir.
        if base
            .file_name()
            .is_some_and(|name| name == ".kimi" || name == ".kimi-code")
        {
            let candidate = base.join("sessions");
            if candidate.exists() {
                roots.push(candidate);
            }
            return;
        }

        // Anything at or below a sessions root (a sessions dir, workDirKey
        // bucket, session dir, or agents/<agentId> dir).
        if Self::looks_like_kimi_storage(base) {
            roots.push(base.to_path_buf());
            return;
        }

        // A directory containing a `.kimi-code` / `.kimi` home as a child.
        let mut found_child = false;
        for child in [".kimi-code", ".kimi"] {
            let candidate = base.join(child).join("sessions");
            if candidate.exists() {
                roots.push(candidate);
                found_child = true;
            }
        }
        if found_child {
            return;
        }

        // A relocated session or agent directory outside any `.kimi*` tree:
        // legacy session dirs hold wire.jsonl directly (as do modern
        // agents/<agentId> dirs); modern session dirs hold an agents/ dir.
        if base.join("wire.jsonl").is_file() || base.join("agents").is_dir() {
            roots.push(base.to_path_buf());
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
                for candidate in Self::kimi_session_roots() {
                    if candidate.exists() {
                        roots.push(ScanRoot::local(candidate));
                    }
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
                // Legacy sessions keep state.json next to wire.jsonl; modern
                // sessions keep one state.json at the session root shared by
                // every agents/<agentId>/wire.jsonl (dedupe handles overlap).
                let state = modern_wire_layout(&wire_path).map_or_else(
                    || wire_path.parent().map(|dir| dir.join("state.json")),
                    |layout| Some(layout.session_root.join("state.json")),
                );
                if let Some(state) = state {
                    if state.exists() && seen_files.insert(dedupe_path_key(&state)) {
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

                let parsed = modern_wire_layout(&wire_path).map_or_else(
                    || parse_kimi_session(&wire_path),
                    |layout| parse_kimi_code_session(&wire_path, &layout),
                );

                match parsed {
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

/// Infer workspace from the session directory structure.
/// Path pattern: `~/.kimi/sessions/<workspace-hash>/<session-uuid>/wire.jsonl`
/// We try to read `state.json` in the same directory for workspace info.
fn infer_workspace(wire_path: &Path) -> Option<PathBuf> {
    let session_dir = wire_path.parent()?;

    // Try reading state.json for workspace/cwd info
    let state_path = session_dir.join("state.json");
    if let Ok(content) = fs::read_to_string(&state_path) {
        if let Ok(val) = serde_json::from_str::<Value>(&content) {
            // Check common fields for workspace path
            for key in &["cwd", "workspace", "workspacePath", "projectPath"] {
                if let Some(path_str) = val.get(*key).and_then(|v| v.as_str()) {
                    if !path_str.is_empty() {
                        return Some(PathBuf::from(path_str));
                    }
                }
            }
        }
    }

    None
}

/// Infer session UUID from the directory structure.
/// Path pattern: `~/.kimi/sessions/<workspace-hash>/<session-uuid>/wire.jsonl`
fn infer_session_id(wire_path: &Path) -> Option<String> {
    wire_path
        .parent()?
        .file_name()
        .and_then(|n| n.to_str())
        .map(String::from)
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
#[allow(clippy::too_many_lines)]
fn parse_kimi_session(path: &Path) -> Result<Option<NormalizedConversation>> {
    let file =
        fs::File::open(path).with_context(|| format!("open kimi wire file {}", path.display()))?;
    let reader = std::io::BufReader::new(file);

    let mut messages = Vec::new();
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut current_role = String::from("assistant");

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

        // Parse timestamp (floating-point seconds or ISO string)
        let created = val.get("timestamp").and_then(parse_kimi_timestamp);
        update_time_bounds(&mut started_at, &mut ended_at, created);

        let msg = val.get("message");
        let msg_type = msg.and_then(|m| m.get("type")).and_then(|v| v.as_str());

        // Also check top-level type for metadata lines
        let top_type = val.get("type").and_then(|v| v.as_str());

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

    let session_id = infer_session_id(path);
    let workspace = infer_workspace(path);

    let title = messages.iter().find(|m| m.role == "user").map(|m| {
        m.content
            .lines()
            .next()
            .unwrap_or(&m.content)
            .chars()
            .take(100)
            .collect::<String>()
    });

    Ok(Some(NormalizedConversation {
        agent_slug: "kimi".into(),
        external_id: session_id.clone(),
        title,
        workspace,
        source_path: path.to_path_buf(),
        started_at,
        ended_at,
        metadata: serde_json::json!({
            "source": "kimi",
            "sessionId": session_id,
        }),
        messages,
    }))
}

// ---------------------------------------------------------------------------
// Modern Kimi Code (0.28+) layout
// ---------------------------------------------------------------------------

/// Placement of a modern Kimi Code wire file:
/// `<sessions>/<workDirKey>/<sessionId>/agents/<agentId>/wire.jsonl`.
struct ModernWireLayout {
    /// The `<sessionId>` directory (holds `state.json` and `agents/`).
    session_root: PathBuf,
    session_id: String,
    agent_id: String,
}

impl ModernWireLayout {
    /// Stable conversation identifier. The main agent owns the plain session
    /// id; sub-agents are suffixed so two agents of one session never collide
    /// (and two sessions' `main` agent dirs never collapse to `"main"`).
    fn external_id(&self) -> String {
        if self.agent_id == "main" {
            self.session_id.clone()
        } else {
            format!("{}:{}", self.session_id, self.agent_id)
        }
    }
}

/// Classify a wire file as modern-layout when it lives in
/// `<sessionId>/agents/<agentId>/wire.jsonl`. Returns `None` for the legacy
/// `<sessionId>/wire.jsonl` layout.
fn modern_wire_layout(wire_path: &Path) -> Option<ModernWireLayout> {
    // wire_dir is `agents/<agentId>`; its parent must be the `agents` dir.
    let wire_dir = wire_path.parent()?;
    let agents_dir = wire_dir.parent()?;
    if agents_dir.file_name()? != "agents" {
        return None;
    }
    let session_root = agents_dir.parent()?;
    let session_id = session_root.file_name()?.to_str()?.to_string();
    let agent_id = wire_dir.file_name()?.to_str()?.to_string();
    Some(ModernWireLayout {
        session_root: session_root.to_path_buf(),
        session_id,
        agent_id,
    })
}

/// Session-level metadata parsed from a modern session's `state.json`.
#[derive(Default)]
struct KimiCodeState {
    title: Option<String>,
    workspace: Option<PathBuf>,
    created_at: Option<i64>,
    updated_at: Option<i64>,
}

/// Best-effort read of `<sessionId>/state.json`. Missing or malformed files
/// yield an empty state; parsing continues from the wire log alone.
fn read_kimi_code_state(session_root: &Path) -> KimiCodeState {
    let Ok(content) = fs::read_to_string(session_root.join("state.json")) else {
        return KimiCodeState::default();
    };
    let Ok(val) = serde_json::from_str::<Value>(&content) else {
        return KimiCodeState::default();
    };
    KimiCodeState {
        title: val
            .get("title")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(String::from),
        workspace: val
            .get("workDir")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
        created_at: val.get("createdAt").and_then(parse_timestamp),
        updated_at: val.get("updatedAt").and_then(parse_timestamp),
    }
}

/// Render a modern `tool.call` loop event in the same `[Tool: ...]` style as
/// the legacy `extract_tool_call_text`.
fn extract_kimi_code_tool_call_text(event: &Value) -> String {
    let tool_name = event
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let desc = event
        .get("args")
        .and_then(|args| {
            args.get("description")
                .or_else(|| args.get("file_path"))
                .or_else(|| args.get("path"))
                .or_else(|| args.get("command"))
                .and_then(Value::as_str)
        })
        .unwrap_or("");

    if desc.is_empty() {
        format!("[Tool: {tool_name}]")
    } else {
        format!("[Tool: {tool_name} - {desc}]")
    }
}

/// Extract result text from a modern `tool.result` loop event.
fn extract_kimi_code_tool_result_text(event: &Value) -> String {
    let Some(result) = event.get("result") else {
        return String::new();
    };
    if let Some(s) = result.as_str() {
        return s.to_string();
    }
    if let Some(output) = result.get("output") {
        let text = flatten_content(output);
        if !text.is_empty() {
            return text;
        }
    }
    flatten_content(result)
}

/// Fold a `tool.result` onto the originating `tool.call` message (matched by
/// `toolCallId`), storing the payload under `extra.cass.tool_result` like the
/// openhands connector does for observations.
fn attach_tool_result_to_call(
    messages: &mut [NormalizedMessage],
    call_index_by_id: &HashMap<String, usize>,
    tool_call_id: &str,
    result_text: &str,
    is_error: bool,
) -> bool {
    let Some(&idx) = call_index_by_id.get(tool_call_id) else {
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

/// A `turn.prompt` awaiting its `context.append_message` echo: prompt text,
/// timestamp, and the raw wire line.
type PendingPrompt = (String, Option<i64>, Value);

/// Emit an un-matched pending `turn.prompt` as a user message.
fn flush_pending_prompt(
    messages: &mut Vec<NormalizedMessage>,
    pending: &mut Option<PendingPrompt>,
) {
    if let Some((text, created, raw)) = pending.take() {
        messages.push(NormalizedMessage {
            idx: 0,
            role: "user".to_string(),
            author: None,
            created_at: created,
            content: text,
            extra: raw,
            invocations: Vec::new(),
            snippets: Vec::new(),
        });
    }
}

/// Parse a modern Kimi Code wire.jsonl (one JSON event per line, RFC3339
/// timestamps in top-level `time`) into a `NormalizedConversation`.
///
/// Tolerance matches the legacy parser: unreadable, blank, and malformed
/// lines are skipped silently; a file with no renderable messages yields
/// `Ok(None)`.
#[allow(clippy::too_many_lines)]
fn parse_kimi_code_session(
    path: &Path,
    layout: &ModernWireLayout,
) -> Result<Option<NormalizedConversation>> {
    let file =
        fs::File::open(path).with_context(|| format!("open kimi wire file {}", path.display()))?;
    let reader = std::io::BufReader::new(file);

    let mut messages: Vec<NormalizedMessage> = Vec::new();
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    // A turn.prompt is held back until the next event: the user prompt is
    // usually echoed as a context.append_message with identical text, and the
    // pair must collapse into a single user message.
    let mut pending_prompt: Option<PendingPrompt> = None;
    // toolCallId -> index of the message carrying that tool.call invocation.
    let mut call_index_by_id: HashMap<String, usize> = HashMap::new();

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

        let created = val.get("time").and_then(parse_kimi_timestamp);
        update_time_bounds(&mut started_at, &mut ended_at, created);

        let top_type = val.get("type").and_then(Value::as_str).unwrap_or_default();

        match top_type {
            "turn.prompt" => {
                // Two prompts in a row: the first was never echoed, emit it.
                flush_pending_prompt(&mut messages, &mut pending_prompt);
                let text = val.get("input").map(flatten_content).unwrap_or_default();
                if !text.trim().is_empty() {
                    pending_prompt = Some((text, created, val));
                }
            }
            "context.append_message" => {
                let message = val.get("message");
                let role = message
                    .and_then(|m| m.get("role"))
                    .and_then(Value::as_str)
                    .unwrap_or("assistant")
                    .to_string();
                let text = message
                    .and_then(|m| m.get("content"))
                    .map(flatten_content)
                    .unwrap_or_default();

                if role == "user"
                    && pending_prompt
                        .as_ref()
                        .is_some_and(|(pending_text, _, _)| *pending_text == text)
                {
                    // The echo of the held-back turn.prompt: emit exactly once.
                    flush_pending_prompt(&mut messages, &mut pending_prompt);
                    continue;
                }

                flush_pending_prompt(&mut messages, &mut pending_prompt);
                if !text.trim().is_empty() {
                    messages.push(NormalizedMessage {
                        idx: 0,
                        role,
                        author: None,
                        created_at: created,
                        content: text,
                        extra: val,
                        invocations: Vec::new(),
                        snippets: Vec::new(),
                    });
                }
            }
            "context.append_loop_event" => {
                flush_pending_prompt(&mut messages, &mut pending_prompt);
                let Some(event) = val.get("event") else {
                    continue;
                };
                let event_type = event
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default();

                match event_type {
                    "content.part" => {
                        let part = event.get("part");
                        let part_type = part
                            .and_then(|p| p.get("type"))
                            .and_then(Value::as_str)
                            .unwrap_or("text");
                        let text = part
                            .and_then(|p| p.get("text"))
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        if text.trim().is_empty() {
                            continue;
                        }
                        let author = (part_type == "think").then(|| "reasoning".to_string());
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: "assistant".to_string(),
                            author,
                            created_at: created,
                            content: text.to_string(),
                            extra: val,
                            invocations: Vec::new(),
                            snippets: Vec::new(),
                        });
                    }
                    "tool.call" => {
                        let tool_name = event
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown");
                        let call_id = event
                            .get("toolCallId")
                            .and_then(Value::as_str)
                            .map(String::from);
                        let content = extract_kimi_code_tool_call_text(event);
                        let invocation = crate::types::NormalizedInvocation {
                            kind: "tool".to_string(),
                            name: tool_name.to_string(),
                            raw_name: None,
                            call_id: call_id.clone(),
                            arguments: event.get("args").cloned(),
                        };
                        if let Some(id) = call_id {
                            call_index_by_id.insert(id, messages.len());
                        }
                        messages.push(NormalizedMessage {
                            idx: 0,
                            role: "assistant".to_string(),
                            author: None,
                            created_at: created,
                            content,
                            extra: val,
                            invocations: vec![invocation],
                            snippets: Vec::new(),
                        });
                    }
                    "tool.result" => {
                        let Some(tool_call_id) = event.get("toolCallId").and_then(Value::as_str)
                        else {
                            continue;
                        };
                        let result_text = extract_kimi_code_tool_result_text(event);
                        if result_text.trim().is_empty() {
                            continue;
                        }
                        let is_error = event
                            .pointer("/result/error")
                            .is_some_and(|err| !err.is_null());
                        if !attach_tool_result_to_call(
                            &mut messages,
                            &call_index_by_id,
                            tool_call_id,
                            &result_text,
                            is_error,
                        ) {
                            tracing::debug!(
                                tool_call_id,
                                "kimi tool.result without matching tool.call"
                            );
                        }
                    }
                    // step.begin / step.end and unknown loop events carry no
                    // renderable content.
                    _ => {}
                }
            }
            // llm.request, usage.record, and unknown top-level types are
            // bookkeeping. They still end any pending prompt: the echo (when
            // present) always directly follows its turn.prompt.
            _ => {
                flush_pending_prompt(&mut messages, &mut pending_prompt);
            }
        }
    }

    flush_pending_prompt(&mut messages, &mut pending_prompt);

    crate::types::reindex_messages(&mut messages);

    if messages.is_empty() {
        return Ok(None);
    }

    let state = read_kimi_code_state(&layout.session_root);
    update_time_bounds(&mut started_at, &mut ended_at, state.created_at);
    update_time_bounds(&mut started_at, &mut ended_at, state.updated_at);

    let title = state.title.or_else(|| {
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
        external_id: Some(layout.external_id()),
        title,
        workspace: state.workspace,
        source_path: path.to_path_buf(),
        started_at,
        ended_at,
        metadata: serde_json::json!({
            "source": "kimi",
            "sessionId": layout.session_id,
            "agentId": layout.agent_id,
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
    // Modern Kimi Code (0.28+) layout helpers
    // =========================================================================

    fn create_kimi_code_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join(".kimi-code").join("sessions");
        fs::create_dir_all(&storage).unwrap();
        storage
    }

    fn write_modern_wire_file(
        storage: &Path,
        work_dir_key: &str,
        session_id: &str,
        agent_id: &str,
        lines: &[&str],
    ) -> PathBuf {
        let agent_dir = storage
            .join(work_dir_key)
            .join(session_id)
            .join("agents")
            .join(agent_id);
        fs::create_dir_all(&agent_dir).unwrap();
        let file_path = agent_dir.join("wire.jsonl");
        fs::write(&file_path, lines.join("\n")).unwrap();
        file_path
    }

    fn write_modern_state(storage: &Path, work_dir_key: &str, session_id: &str, json: &str) {
        let session_dir = storage.join(work_dir_key).join(session_id);
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("state.json"), json).unwrap();
    }

    fn ts(rfc3339: &str) -> i64 {
        parse_timestamp(&serde_json::json!(rfc3339)).unwrap()
    }

    // =========================================================================
    // Modern Kimi Code (0.28+) tests
    // =========================================================================

    #[test]
    fn modern_main_agent_session_end_to_end() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        let lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Fix the bug"}],"origin":"cli","time":"2026-01-01T00:00:00Z"}"#,
            r#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"Fix the bug"}],"toolCalls":[],"origin":"cli"},"time":"2026-01-01T00:00:01Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"step.begin"},"time":"2026-01-01T00:00:02Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","text":"Looking at the bug now."}},"time":"2026-01-01T00:00:03Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"tool.call","toolCallId":"call_1","name":"ReadFile","args":{"path":"/src/main.rs"}},"time":"2026-01-01T00:00:04Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"tool.result","toolCallId":"call_1","result":{"output":"fn main() {}"}},"time":"2026-01-01T00:00:05Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"step.end"},"time":"2026-01-01T00:00:06Z"}"#,
            r#"{"type":"usage.record","usage":{"input":10},"time":"2026-01-01T00:00:07Z"}"#,
        ];
        let wire_path = write_modern_wire_file(&storage, "wdk-1", "sess-e2e", "main", &lines);
        write_modern_state(
            &storage,
            "wdk-1",
            "sess-e2e",
            r#"{"title":"Bug fix session","createdAt":"2025-12-31T23:59:59Z","updatedAt":"2026-01-01T00:01:00Z","workDir":"/home/user/proj","agents":{"main":{"type":"main"}}}"#,
        );

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        assert_eq!(conv.agent_slug, "kimi");
        // external_id is the session id, NOT the agent dir name "main".
        assert_eq!(conv.external_id, Some("sess-e2e".to_string()));
        assert_eq!(conv.source_path, wire_path);
        assert_eq!(conv.workspace, Some(PathBuf::from("/home/user/proj")));
        assert_eq!(conv.title, Some("Bug fix session".to_string()));
        assert_eq!(conv.metadata["sessionId"], "sess-e2e");
        assert_eq!(conv.metadata["agentId"], "main");

        // Time bounds merge state.json createdAt/updatedAt with wire times.
        assert_eq!(conv.started_at, Some(ts("2025-12-31T23:59:59Z")));
        assert_eq!(conv.ended_at, Some(ts("2026-01-01T00:01:00Z")));

        // turn.prompt + duplicate context.append_message collapse to ONE
        // user message.
        assert_eq!(conv.messages.len(), 3);
        assert_eq!(conv.messages[0].role, "user");
        assert_eq!(conv.messages[0].content, "Fix the bug");
        assert_eq!(
            conv.messages[0].created_at,
            Some(ts("2026-01-01T00:00:00Z"))
        );

        assert_eq!(conv.messages[1].role, "assistant");
        assert_eq!(conv.messages[1].content, "Looking at the bug now.");
        assert!(conv.messages[1].author.is_none());

        assert_eq!(conv.messages[2].role, "assistant");
        assert_eq!(conv.messages[2].content, "[Tool: ReadFile - /src/main.rs]");
        assert_eq!(conv.messages[2].invocations.len(), 1);
        let invocation = &conv.messages[2].invocations[0];
        assert_eq!(invocation.kind, "tool");
        assert_eq!(invocation.name, "ReadFile");
        assert_eq!(invocation.raw_name, None);
        assert_eq!(invocation.call_id, Some("call_1".to_string()));
        assert_eq!(
            invocation.arguments,
            Some(serde_json::json!({"path": "/src/main.rs"}))
        );

        // The tool.result is folded onto the tool.call message.
        assert_eq!(
            conv.messages[2]
                .extra
                .pointer("/cass/tool_result/content")
                .and_then(Value::as_str),
            Some("fn main() {}")
        );
        assert_eq!(
            conv.messages[2]
                .extra
                .pointer("/cass/tool_result/is_error")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn modern_two_main_agent_sessions_have_distinct_external_ids() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        let lines_a = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Session one"}],"time":"2026-01-01T00:00:00Z"}"#,
        ];
        let lines_b = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Session two"}],"time":"2026-01-02T00:00:00Z"}"#,
        ];
        write_modern_wire_file(&storage, "wdk-1", "sess-one", "main", &lines_a);
        write_modern_wire_file(&storage, "wdk-2", "sess-two", "main", &lines_b);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let mut convs = connector.scan(&ctx).unwrap();
        convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));

        let ids: Vec<_> = convs
            .iter()
            .filter_map(|c| c.external_id.as_deref())
            .collect();
        // The agent dir is literally `main` for both; external ids must not
        // collapse to "main".
        assert_eq!(ids, vec!["sess-one", "sess-two"]);
    }

    #[test]
    fn modern_subagent_external_id_includes_agent_id() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        let lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Research the codebase"}],"time":"2026-01-01T00:00:00Z"}"#,
        ];
        write_modern_wire_file(&storage, "wdk-1", "sess-sub", "researcher-1", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].external_id,
            Some("sess-sub:researcher-1".to_string())
        );
        assert_eq!(convs[0].metadata["agentId"], "researcher-1");
    }

    #[test]
    fn modern_think_part_maps_to_reasoning_author() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        let lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Why is it slow?"}],"time":"2026-01-01T00:00:00Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"think","text":"The user probably means the parser."}},"time":"2026-01-01T00:00:01Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","text":"It is slow because of the parser."}},"time":"2026-01-01T00:00:02Z"}"#,
        ];
        write_modern_wire_file(&storage, "wdk-1", "sess-think", "main", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 3);
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert_eq!(convs[0].messages[1].author, Some("reasoning".to_string()));
        assert_eq!(
            convs[0].messages[1].content,
            "The user probably means the parser."
        );
        assert_eq!(convs[0].messages[2].role, "assistant");
        assert!(convs[0].messages[2].author.is_none());
    }

    #[test]
    fn modern_missing_state_json_still_parses() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        let lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Hello modern Kimi"}],"time":"2026-01-01T00:00:00Z"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","text":"Hi!"}},"time":"2026-01-01T00:00:05Z"}"#,
        ];
        write_modern_wire_file(&storage, "wdk-1", "sess-nostate", "main", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        assert_eq!(conv.external_id, Some("sess-nostate".to_string()));
        assert_eq!(conv.workspace, None);
        // Title falls back to the first user line.
        assert_eq!(conv.title, Some("Hello modern Kimi".to_string()));
        // Time bounds come from the wire `time` fields alone.
        assert_eq!(conv.started_at, Some(ts("2026-01-01T00:00:00Z")));
        assert_eq!(conv.ended_at, Some(ts("2026-01-01T00:00:05Z")));
    }

    #[test]
    fn modern_malformed_middle_line_and_truncated_tail_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        let session_dir = storage.join("wdk-1").join("sess-broken");
        let agent_dir = session_dir.join("agents").join("main");
        fs::create_dir_all(&agent_dir).unwrap();
        let content = concat!(
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Survives"}],"time":"2026-01-01T00:00:00Z"}"#,
            "\n",
            "not valid json {{{",
            "\n",
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","text":"Also survives"}},"time":"2026-01-01T00:00:01Z"}"#,
            "\n",
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","te"#,
        );
        fs::write(agent_dir.join("wire.jsonl"), content).unwrap();

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].content, "Survives");
        assert_eq!(convs[0].messages[1].content, "Also survives");
    }

    #[test]
    fn modern_scan_with_explicit_root_at_kimi_code_dir() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        let lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"From home dir root"}],"time":"2026-01-01T00:00:00Z"}"#,
        ];
        write_modern_wire_file(&storage, "wdk-1", "sess-root-home", "main", &lines);

        let kimi_code_dir = dir.path().join(".kimi-code");

        let connector = KimiConnector::new();
        let ctx =
            ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(kimi_code_dir)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id, Some("sess-root-home".to_string()));
    }

    #[test]
    fn modern_scan_with_explicit_root_at_sessions_dir() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        let lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"From sessions root"}],"time":"2026-01-01T00:00:00Z"}"#,
        ];
        write_modern_wire_file(&storage, "wdk-1", "sess-root-sessions", "main", &lines);

        let connector = KimiConnector::new();
        let ctx =
            ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(storage.clone())], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id, Some("sess-root-sessions".to_string()));
    }

    #[test]
    fn modern_scan_with_explicit_root_at_session_dir() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        let lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"From session dir"}],"time":"2026-01-01T00:00:00Z"}"#,
        ];
        write_modern_wire_file(&storage, "wdk-1", "sess-root-session", "main", &lines);

        let session_dir = storage.join("wdk-1").join("sess-root-session");

        let connector = KimiConnector::new();
        let ctx = ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(session_dir)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id, Some("sess-root-session".to_string()));
    }

    #[test]
    fn modern_scan_with_explicit_root_at_wire_file() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        let lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"From wire file"}],"time":"2026-01-01T00:00:00Z"}"#,
        ];
        let wire_path = write_modern_wire_file(&storage, "wdk-1", "sess-root-wire", "main", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![ScanRoot::local(wire_path.clone())],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id, Some("sess-root-wire".to_string()));
        assert_eq!(convs[0].source_path, wire_path);
    }

    #[test]
    fn modern_prompt_without_echo_flushes_as_user_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        // The append_message text differs from the prompt: both must be
        // emitted, prompt first.
        let lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Original prompt"}],"time":"2026-01-01T00:00:00Z"}"#,
            r#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"Different text"}]},"time":"2026-01-01T00:00:01Z"}"#,
        ];
        write_modern_wire_file(&storage, "wdk-1", "sess-noecho", "main", &lines);

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Original prompt");
        assert_eq!(convs[0].messages[1].role, "user");
        assert_eq!(convs[0].messages[1].content, "Different text");
    }

    #[test]
    fn modern_discovery_covers_scan_sources_and_lists_state_sidecar_once() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);

        let main_lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Main agent"}],"time":"2026-01-01T00:00:00Z"}"#,
        ];
        let sub_lines = vec![
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"Sub agent"}],"time":"2026-01-01T00:00:01Z"}"#,
        ];
        write_modern_wire_file(&storage, "wdk-1", "sess-disc", "main", &main_lines);
        write_modern_wire_file(&storage, "wdk-1", "sess-disc", "sub-1", &sub_lines);
        write_modern_state(
            &storage,
            "wdk-1",
            "sess-disc",
            r#"{"title":"Discovery","workDir":"/w","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:02Z"}"#,
        );

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);

        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);

        let sources = connector.discover_source_files(&ctx).unwrap();
        let sidecars: Vec<_> = sources
            .iter()
            .filter(|s| s.role == DiscoveredSourceRole::MetadataSidecar)
            .collect();
        // Both agents share one session-level state.json; it is listed once.
        assert_eq!(sidecars.len(), 1);
        assert_eq!(
            sidecars[0].source_path,
            storage.join("wdk-1").join("sess-disc").join("state.json")
        );
        assert!(!sidecars[0].required_for_reconstruction);
    }

    // =========================================================================
    // KIMI_CODE_HOME root resolution (pure helper, no env mutation)
    // =========================================================================

    #[test]
    fn kimi_session_roots_from_env_override_is_probed_first() {
        let roots = KimiConnector::kimi_session_roots_from(
            Some(PathBuf::from("/custom/kimi-home")),
            Some(Path::new("/home/u")),
        );
        assert_eq!(
            roots,
            vec![
                PathBuf::from("/custom/kimi-home/sessions"),
                PathBuf::from("/home/u/.kimi-code/sessions"),
                PathBuf::from("/home/u/.kimi/sessions"),
            ]
        );
    }

    #[test]
    fn kimi_session_roots_from_defaults_without_override() {
        let roots = KimiConnector::kimi_session_roots_from(None, Some(Path::new("/home/u")));
        assert_eq!(
            roots,
            vec![
                PathBuf::from("/home/u/.kimi-code/sessions"),
                PathBuf::from("/home/u/.kimi/sessions"),
            ]
        );
    }

    #[test]
    fn kimi_session_roots_from_override_without_home() {
        let roots =
            KimiConnector::kimi_session_roots_from(Some(PathBuf::from("/custom/kimi-home")), None);
        assert_eq!(roots, vec![PathBuf::from("/custom/kimi-home/sessions")]);
    }

    #[test]
    fn kimi_session_roots_from_empty_without_override_or_home() {
        assert!(KimiConnector::kimi_session_roots_from(None, None).is_empty());
    }

    // =========================================================================
    // Storage-shape classification
    // =========================================================================

    #[test]
    fn looks_like_kimi_storage_matches_segment_windows_not_substrings() {
        assert!(KimiConnector::looks_like_kimi_storage(Path::new(
            "/home/u/.kimi/sessions/ws/sess"
        )));
        assert!(KimiConnector::looks_like_kimi_storage(Path::new(
            "/home/u/.kimi-code/sessions"
        )));
        assert!(KimiConnector::looks_like_kimi_storage(Path::new(
            "/home/u/.kimi-code"
        )));
        assert!(KimiConnector::looks_like_kimi_storage(Path::new(
            "/home/u/.kimi"
        )));
        // Substring lookalikes must NOT match.
        assert!(!KimiConnector::looks_like_kimi_storage(Path::new(
            "/home/u/.kimiarchive/sessions"
        )));
        assert!(!KimiConnector::looks_like_kimi_storage(Path::new(
            "/home/sessions-user/backup"
        )));
    }
}
