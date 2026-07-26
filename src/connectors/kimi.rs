//! Connector for Kimi Code (Moonshot AI) session logs.
//!
//! Two on-disk formats are supported by this single connector:
//!
//! **Legacy** (`~/.kimi`, protocol <= 1.3):
//! - `~/.kimi/sessions/<workspace-hash>/<session-uuid>/wire.jsonl`
//! - Each line is a JSON object with `timestamp` and `message` fields.
//!   Message types include: `TurnBegin`, `StepBegin`, `ContentPart`, `ToolCall`.
//! - Additional files in each session directory:
//!   - `context.jsonl` — context/conversation data
//!   - `state.json` — session state
//!
//! **Current kimi-code** (`~/.kimi-code` or `$KIMI_CODE_HOME`, protocol 1.4+):
//! - `<root>/sessions/<wd-slug>/<session-uuid>/agents/<agent-name>/wire.jsonl`
//!   (main agent and sub-agents each write their own wire log)
//! - `<session-uuid>/state.json` — sidecar carrying `title` and `workDir`
//! - Each line is a JSON object with a top-level `type` and a `time` field
//!   (ms epoch). Mapped event types:
//!   - `context.append_message` -> user message
//!   - `context.append_loop_event` / `content.part` (`part.type == "text"`) ->
//!     assistant message (`think` parts go to `extra`, never `content`)
//!   - `context.append_loop_event` / `tool.call` -> assistant message +
//!     `NormalizedInvocation`
//!   - `context.append_loop_event` / `tool.result` -> `tool` role message with
//!     truncated output
//!   - `context.apply_compaction` -> assistant message with the summary
//!   - Unknown event types are skipped so protocol evolution stays
//!     forward-compatible.

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
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

    /// Get the Kimi sessions root directory.
    fn sessions_root() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".kimi")
            .join("sessions")
    }

    fn looks_like_kimi_storage(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        // `.kimi-code` is the current format's store, not legacy `.kimi`.
        path_str.contains(".kimi")
            && !path_str.contains(".kimi-code")
            && path_str.contains("sessions")
    }

    fn append_kimi_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        if Self::looks_like_kimi_storage(base) {
            roots.push(base.to_path_buf());
            return;
        }

        if base.file_name().is_some_and(|name| name == ".kimi") {
            let candidate = base.join("sessions");
            if candidate.exists() {
                roots.push(candidate);
            }
            return;
        }

        let candidate = base.join(".kimi/sessions");
        if candidate.exists() {
            roots.push(candidate);
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
            } else if !Self::looks_like_kimi_code_storage(&ctx.data_dir) {
                // A data dir that already names the modern store is scanned by
                // the modern path only — don't drag in the legacy default too.
                let fallback = Self::sessions_root();
                if fallback.exists() {
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
                if let Some(session_dir) = wire_path.parent() {
                    let state = session_dir.join("state.json");
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
        let mut convs = Self::scan_legacy(ctx);
        let mut seen_paths: HashSet<PathBuf> = convs
            .iter()
            .map(|conv| dedupe_path_key(&conv.source_path))
            .collect();
        for conv in Self::scan_modern(ctx) {
            if seen_paths.insert(dedupe_path_key(&conv.source_path)) {
                convs.push(conv);
            }
        }
        Ok(convs)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        let mut sources = Self::discover_sources(ctx);
        let mut seen_paths: HashSet<PathBuf> = sources
            .iter()
            .map(|source| dedupe_path_key(&source.source_path))
            .collect();
        for source in Self::discover_modern_sources(ctx) {
            if seen_paths.insert(dedupe_path_key(&source.source_path)) {
                sources.push(source);
            }
        }
        Ok(sources)
    }
}

impl KimiConnector {
    /// Scan the legacy `~/.kimi` wire format.
    fn scan_legacy(ctx: &ScanContext) -> Vec<NormalizedConversation> {
        let mut roots: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();

        if roots.is_empty() {
            return Vec::new();
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

        convs
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
// Current kimi-code format (`~/.kimi-code` / `$KIMI_CODE_HOME`, protocol 1.4+)
// ---------------------------------------------------------------------------

const MAX_INDEXED_TOOL_OUTPUT_CHARS: usize = 128 * 1024;

impl KimiConnector {
    /// Modern kimi-code sessions root: `$KIMI_CODE_HOME/sessions` when the
    /// environment override is set, otherwise `~/.kimi-code/sessions`.
    fn modern_sessions_root() -> PathBuf {
        if let Some(home) = std::env::var_os("KIMI_CODE_HOME") {
            if !home.is_empty() {
                return PathBuf::from(home).join("sessions");
            }
        }
        dirs::home_dir()
            .unwrap_or_default()
            .join(".kimi-code")
            .join("sessions")
    }

    fn looks_like_kimi_code_storage(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        path_str.contains(".kimi-code") && path_str.contains("sessions")
    }

    fn append_modern_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        if Self::looks_like_kimi_code_storage(base) {
            roots.push(base.to_path_buf());
            return;
        }

        if base.file_name().is_some_and(|name| name == ".kimi-code") {
            let candidate = base.join("sessions");
            if candidate.exists() {
                roots.push(candidate);
            }
            return;
        }

        let candidate = base.join(".kimi-code/sessions");
        if candidate.exists() {
            roots.push(candidate);
        }
    }

    fn modern_source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            let data_dir_is_kimi_code_storage =
                Self::looks_like_kimi_code_storage(&ctx.data_dir) && ctx.data_dir.exists();
            if data_dir_is_kimi_code_storage {
                roots.push(ScanRoot::local(ctx.data_dir.clone()));
            } else if !Self::looks_like_kimi_storage(&ctx.data_dir) {
                // A data dir that names the legacy store is scanned by the
                // legacy path only — don't drag in the modern default too.
                let fallback = Self::modern_sessions_root();
                if fallback.exists() {
                    roots.push(ScanRoot::local(fallback));
                }
            }
        } else {
            for scan_root in &ctx.scan_roots {
                let mut candidates = Vec::new();
                Self::append_modern_roots(&mut candidates, &scan_root.path);
                roots.extend(candidates.into_iter().map(|path| scan_root.with_path(path)));
            }

            if ctx.data_dir.exists() {
                let mut candidates = Vec::new();
                Self::append_modern_roots(&mut candidates, &ctx.data_dir);
                roots.extend(candidates.into_iter().map(ScanRoot::local));
            }
        }

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    /// Find `<session-uuid>/agents/<agent-name>/wire.jsonl` files under a root.
    fn modern_wire_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if !root.exists() {
            return out;
        }

        for entry in WalkDir::new(root).into_iter().flatten() {
            if entry.file_type().is_file() && is_agent_wire_file(entry.path()) {
                out.push(entry.path().to_path_buf());
            }
        }

        out.sort();
        out
    }

    fn discover_modern_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        let mut seen_files: HashSet<PathBuf> = HashSet::new();
        for root in Self::modern_source_roots(ctx) {
            if !root.path.exists() {
                continue;
            }
            for wire_path in Self::modern_wire_files(&root.path) {
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
                if let Some(dir) = modern_session_dir(&wire_path) {
                    let state = dir.join("state.json");
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

    /// Scan the current kimi-code wire format.
    fn scan_modern(ctx: &ScanContext) -> Vec<NormalizedConversation> {
        let mut convs = Vec::new();
        let mut seen_files: HashSet<PathBuf> = HashSet::new();

        for root in Self::modern_source_roots(ctx) {
            if !root.path.exists() {
                continue;
            }
            for wire_path in Self::modern_wire_files(&root.path) {
                if !seen_files.insert(dedupe_path_key(&wire_path)) {
                    continue;
                }
                if !file_modified_since(&wire_path, ctx.since_ts) {
                    continue;
                }

                match parse_modern_wire(&wire_path) {
                    Ok(Some(conv)) => convs.push(conv),
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(
                            path = %wire_path.display(),
                            error = %e,
                            "kimi-code parse error"
                        );
                    }
                }
            }
        }

        convs
    }
}

fn is_agent_wire_file(path: &Path) -> bool {
    if path.file_name().and_then(|name| name.to_str()) != Some("wire.jsonl") {
        return false;
    }
    path.parent() // <agent-name>
        .and_then(Path::parent) // agents
        .and_then(|agents| agents.file_name())
        .is_some_and(|name| name == "agents")
}

/// `<session-uuid>` directory: parent of `agents/`.
fn modern_session_dir(wire_path: &Path) -> Option<&Path> {
    wire_path.parent()?.parent()?.parent()
}

fn modern_session_uuid(wire_path: &Path) -> Option<String> {
    modern_session_dir(wire_path)?
        .file_name()
        .and_then(|name| name.to_str())
        .map(String::from)
}

fn modern_agent_name(wire_path: &Path) -> Option<String> {
    wire_path
        .parent()?
        .file_name()
        .and_then(|name| name.to_str())
        .map(String::from)
}

/// Read `title` / `workDir` from the session-level `state.json` sidecar.
fn read_modern_state_sidecar(wire_path: &Path) -> (Option<String>, Option<PathBuf>) {
    let Some(dir) = modern_session_dir(wire_path) else {
        return (None, None);
    };
    let state_path = dir.join("state.json");
    let Ok(content) = fs::read_to_string(&state_path) else {
        return (None, None);
    };
    let Ok(val) = serde_json::from_str::<Value>(&content) else {
        return (None, None);
    };

    let title = val
        .get("title")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .map(String::from);
    let workspace = val
        .get("workDir")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from);
    (title, workspace)
}

/// Extract text from a `context.append_message` content payload, which is an
/// array of `{"type": "text", "text": ...}` parts (or a plain string).
fn modern_message_content_text(content: Option<&Value>) -> String {
    let Some(content) = content else {
        return String::new();
    };
    if let Some(text) = content.as_str() {
        return text.to_string();
    }
    let Some(parts) = content.as_array() else {
        return String::new();
    };
    let mut texts = Vec::new();
    for part in parts {
        if let Some(text) = part.as_str() {
            texts.push(text.to_string());
            continue;
        }
        let part_type = part.get("type").and_then(Value::as_str);
        if part_type.is_none() || part_type == Some("text") {
            if let Some(text) = part.get("text").and_then(Value::as_str) {
                texts.push(text.to_string());
            }
        }
    }
    texts.join("\n")
}

fn modern_normalized_message(
    role: &str,
    created_at: Option<i64>,
    content: String,
    extra: Value,
    invocations: Vec<crate::types::NormalizedInvocation>,
) -> NormalizedMessage {
    NormalizedMessage {
        idx: 0,
        role: role.to_string(),
        author: None,
        created_at,
        content,
        extra,
        invocations,
        snippets: Vec::new(),
    }
}

/// Attach buffered `think` parts to the next emitted assistant message via
/// `extra`, keeping chain-of-thought out of the indexed `content`.
fn modern_extra_with_pending_think(raw: &Value, pending_think: &mut Vec<String>) -> Value {
    if pending_think.is_empty() {
        return raw.clone();
    }
    let think = pending_think.join("\n");
    pending_think.clear();
    serde_json::json!({ "think": think, "raw": raw })
}

fn modern_tool_call_content(tool_name: &str, arguments: Option<&Value>) -> String {
    let mut content = format!("[Tool: {tool_name}]");
    if let Some(text) = arguments.and_then(modern_argument_text) {
        content.push('\n');
        content.push_str(&text);
    }
    content
}

fn modern_argument_text(arguments: &Value) -> Option<String> {
    let text = match arguments {
        Value::String(text) => text.trim().to_string(),
        other => serde_json::to_string(other).ok()?,
    };
    (!text.is_empty()).then_some(text)
}

fn modern_tool_output_content(call_id: Option<&str>, output: &str) -> String {
    let label = call_id.map_or_else(
        || "[Tool output]".to_string(),
        |id| format!("[Tool output: {id}]"),
    );
    let output = truncate_modern_tool_output(output.trim());
    if output.is_empty() {
        label
    } else {
        format!("{label}\n{output}")
    }
}

fn truncate_modern_tool_output(output: &str) -> String {
    use std::fmt::Write as _;

    let mut truncated = String::new();
    let mut chars = output.chars();
    for _ in 0..MAX_INDEXED_TOOL_OUTPUT_CHARS {
        let Some(ch) = chars.next() else {
            return output.to_string();
        };
        truncated.push(ch);
    }
    let omitted = chars.count();
    let _ = write!(
        truncated,
        "\n[truncated {omitted} additional chars from tool output]"
    );
    truncated
}

/// Parse one modern kimi-code `agents/<name>/wire.jsonl` into a conversation.
#[allow(clippy::too_many_lines)]
fn parse_modern_wire(path: &Path) -> Result<Option<NormalizedConversation>> {
    let file = fs::File::open(path)
        .with_context(|| format!("open kimi-code wire file {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut messages = Vec::new();
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;
    let mut pending_think: Vec<String> = Vec::new();

    for (line_no_zero, line) in reader.lines().enumerate() {
        let line_no = line_no_zero + 1;
        let Ok(line) = line else {
            tracing::debug!(
                source_path = %path.display(),
                line_no = line_no,
                "kimi-code wire JSONL line unreadable; skipping",
            );
            continue;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let val = match serde_json::from_str::<Value>(line) {
            Ok(value) => value,
            Err(parse_err) => {
                tracing::warn!(
                    source_path = %path.display(),
                    line_no = line_no,
                    error = %parse_err,
                    "kimi-code wire JSONL line failed to parse; skipping",
                );
                continue;
            }
        };

        let created = val.get("time").and_then(parse_timestamp);
        update_time_bounds(&mut started_at, &mut ended_at, created);

        // `tool.call` / `tool.result` / `content.part` arrive nested inside
        // `context.append_loop_event`; everything else keys off the top level.
        let top_type = val.get("type").and_then(Value::as_str);
        let (kind, payload) = if top_type == Some("context.append_loop_event") {
            let event = val.get("event");
            (
                event.and_then(|e| e.get("type")).and_then(Value::as_str),
                event,
            )
        } else {
            (top_type, Some(&val))
        };
        let Some(kind) = kind else { continue };

        match kind {
            "context.append_message" => {
                let Some(message) = payload.and_then(|p| p.get("message")) else {
                    continue;
                };
                let role = message
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or("user");
                let content = modern_message_content_text(message.get("content"));
                if content.trim().is_empty() {
                    continue;
                }
                messages.push(modern_normalized_message(
                    role,
                    created,
                    content,
                    val.clone(),
                    Vec::new(),
                ));
            }
            "content.part" => {
                let Some(part) = payload.and_then(|p| p.get("part")) else {
                    continue;
                };
                match part.get("type").and_then(Value::as_str) {
                    Some("think") => {
                        if let Some(think) = part.get("think").and_then(Value::as_str) {
                            if !think.trim().is_empty() {
                                pending_think.push(think.to_string());
                            }
                        }
                    }
                    Some("text") => {
                        let text = part
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .trim();
                        if !text.is_empty() {
                            let extra = modern_extra_with_pending_think(&val, &mut pending_think);
                            messages.push(modern_normalized_message(
                                "assistant",
                                created,
                                text.to_string(),
                                extra,
                                Vec::new(),
                            ));
                        }
                    }
                    _ => {}
                }
            }
            "tool.call" => {
                let Some(event) = payload else { continue };
                let tool_name = event
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let call_id = event
                    .get("toolCallId")
                    .and_then(Value::as_str)
                    .map(String::from);
                let arguments = event.get("args").cloned();
                let extra = modern_extra_with_pending_think(&val, &mut pending_think);
                messages.push(modern_normalized_message(
                    "assistant",
                    created,
                    modern_tool_call_content(tool_name, arguments.as_ref()),
                    extra,
                    vec![crate::types::NormalizedInvocation {
                        kind: "tool".to_string(),
                        name: tool_name.to_string(),
                        raw_name: None,
                        call_id,
                        arguments: arguments.filter(|args| !args.is_null()),
                    }],
                ));
            }
            "tool.result" => {
                let Some(event) = payload else { continue };
                let output = event.get("result").and_then(|result| result.get("output"));
                let output_text = match output {
                    Some(Value::String(text)) => text.clone(),
                    Some(other) => serde_json::to_string(other).unwrap_or_default(),
                    None => continue,
                };
                let call_id = event.get("toolCallId").and_then(Value::as_str);
                messages.push(modern_normalized_message(
                    "tool",
                    created,
                    modern_tool_output_content(call_id, &output_text),
                    val.clone(),
                    Vec::new(),
                ));
            }
            "context.apply_compaction" => {
                let Some(summary) = payload
                    .and_then(|p| p.get("summary"))
                    .and_then(Value::as_str)
                else {
                    continue;
                };
                let summary = summary.trim();
                if summary.is_empty() {
                    continue;
                }
                messages.push(modern_normalized_message(
                    "assistant",
                    created,
                    format!("[Compaction summary]\n{summary}"),
                    val.clone(),
                    Vec::new(),
                ));
            }
            _ => {}
        }
    }

    crate::types::reindex_messages(&mut messages);

    if messages.is_empty() {
        return Ok(None);
    }

    let session_id = modern_session_uuid(path);
    let agent = modern_agent_name(path);
    let (state_title, workspace) = read_modern_state_sidecar(path);
    let title = state_title.or_else(|| {
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
    let external_id = match (&session_id, &agent) {
        (Some(session), Some(agent)) => Some(format!("{session}/{agent}")),
        (Some(session), None) => Some(session.clone()),
        _ => None,
    };

    Ok(Some(NormalizedConversation {
        agent_slug: "kimi".into(),
        external_id,
        title,
        workspace,
        source_path: path.to_path_buf(),
        started_at,
        ended_at,
        metadata: serde_json::json!({
            "source": "kimi-code",
            "sessionId": session_id,
            "agentName": agent,
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
    // Current kimi-code format (`~/.kimi-code/sessions`, protocol 1.4+)
    // =========================================================================

    fn create_kimi_code_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join(".kimi-code").join("sessions");
        fs::create_dir_all(&storage).unwrap();
        storage
    }

    fn write_modern_wire_file(
        storage: &Path,
        wd_slug: &str,
        session_uuid: &str,
        agent: &str,
        bytes: &[u8],
    ) -> PathBuf {
        let session_dir = storage.join(wd_slug).join(session_uuid);
        let agent_dir = session_dir.join("agents").join(agent);
        fs::create_dir_all(&agent_dir).unwrap();
        fs::write(
            session_dir.join("state.json"),
            r#"{"title":"研究 continues 项目","workDir":"/workspace/kimi-code-project"}"#,
        )
        .unwrap();
        let wire_path = agent_dir.join("wire.jsonl");
        fs::write(&wire_path, bytes).unwrap();
        wire_path
    }

    fn write_modern_wire_file_without_state(
        storage: &Path,
        wd_slug: &str,
        session_uuid: &str,
        agent: &str,
        bytes: &[u8],
    ) -> PathBuf {
        let agent_dir = storage
            .join(wd_slug)
            .join(session_uuid)
            .join("agents")
            .join(agent);
        fs::create_dir_all(&agent_dir).unwrap();
        let wire_path = agent_dir.join("wire.jsonl");
        fs::write(&wire_path, bytes).unwrap();
        wire_path
    }

    /// Desensitized sample trimmed from a real kimi-code wire.jsonl: covers
    /// user message, think part, text part, tool.call, tool.result, and
    /// compaction.
    const MODERN_WIRE_SAMPLE: &str = r#"{"type":"metadata","protocol_version":"1.4","created_at":1782968169532}
{"type":"config.update","profileName":"agent","time":1782968169532}
{"type":"turn.prompt","input":[{"type":"text","text":"duplicate carrier, must be ignored"}],"time":1782968169540}
{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"帮我研究一下 continues 这个项目"}]},"time":1782968169541}
{"type":"context.append_loop_event","event":{"type":"step.begin","uuid":"c6b2f9b4","turnId":"0","step":1},"time":1782968169550}
{"type":"context.append_loop_event","event":{"type":"content.part","uuid":"fd3fca7e","turnId":"0","step":1,"part":{"type":"think","think":"先读 README 再总结要点"}},"time":1782968169551}
{"type":"context.append_loop_event","event":{"type":"content.part","uuid":"5c914f10","turnId":"0","step":1,"part":{"type":"text","text":"我来看一下这个项目的 README。"}},"time":1782968169552}
{"type":"context.append_loop_event","event":{"type":"tool.call","uuid":"tool_1","turnId":"0","step":1,"toolCallId":"tool_1","name":"FetchURL","args":{"url":"https://example.com/readme"}},"time":1782968169553}
{"type":"context.append_loop_event","event":{"type":"tool.result","parentUuid":"tool_1","toolCallId":"tool_1","result":{"output":"README 正文：continues 用来在 Agent 之间搬运会话"}},"time":1782968169554}
{"type":"usage.record","model":"kimi-code/kimi-for-coding","usage":{"output":42},"time":1782968169555}
{"type":"context.apply_compaction","summary":"压缩摘要：已读取 README 并总结要点","time":1782968169600}
"#;

    #[test]
    fn modern_format_parses_all_event_kinds() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);
        let wire_path = write_modern_wire_file(
            &storage,
            "wd_example_0123456789ab",
            "9b47947c-0000-4000-8000-000000000000",
            "main",
            MODERN_WIRE_SAMPLE.as_bytes(),
        );

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        assert_eq!(conv.agent_slug, "kimi");
        assert_eq!(
            conv.external_id.as_deref(),
            Some("9b47947c-0000-4000-8000-000000000000/main")
        );
        assert_eq!(conv.title.as_deref(), Some("研究 continues 项目"));
        assert_eq!(
            conv.workspace,
            Some(PathBuf::from("/workspace/kimi-code-project"))
        );
        assert_eq!(conv.source_path, wire_path);
        // Time bounds track every line's `time` (including skipped event
        // types), matching the legacy parser's behavior.
        assert_eq!(conv.started_at, Some(1_782_968_169_532));
        assert_eq!(conv.ended_at, Some(1_782_968_169_600));
        assert_eq!(
            conv.metadata["sessionId"],
            "9b47947c-0000-4000-8000-000000000000"
        );
        assert_eq!(conv.metadata["agentName"], "main");

        // turn.prompt duplicate, config/usage/step events skipped.
        assert_eq!(conv.messages.len(), 5);

        let user = &conv.messages[0];
        assert_eq!(user.role, "user");
        assert!(user.content.contains("帮我研究一下 continues"));

        let text = &conv.messages[1];
        assert_eq!(text.role, "assistant");
        assert!(text.content.contains("README"));
        // think must stay out of indexed content but remain in extra.
        assert!(!text.content.contains("先读 README 再总结"));
        assert!(
            text.extra["think"]
                .as_str()
                .unwrap_or_default()
                .contains("先读 README 再总结")
        );

        let tool_call = &conv.messages[2];
        assert_eq!(tool_call.role, "assistant");
        assert!(tool_call.content.contains("[Tool: FetchURL]"));
        assert!(tool_call.content.contains("https://example.com/readme"));
        assert_eq!(tool_call.invocations.len(), 1);
        assert_eq!(tool_call.invocations[0].kind, "tool");
        assert_eq!(tool_call.invocations[0].name, "FetchURL");
        assert_eq!(tool_call.invocations[0].call_id.as_deref(), Some("tool_1"));
        assert_eq!(
            tool_call.invocations[0].arguments,
            Some(serde_json::json!({"url": "https://example.com/readme"}))
        );

        let tool_result = &conv.messages[3];
        assert_eq!(tool_result.role, "tool");
        assert!(tool_result.content.contains("[Tool output: tool_1]"));
        assert!(
            tool_result
                .content
                .contains("continues 用来在 Agent 之间搬运会话")
        );

        let compaction = &conv.messages[4];
        assert_eq!(compaction.role, "assistant");
        assert!(compaction.content.contains("压缩摘要"));

        for (idx, message) in conv.messages.iter().enumerate() {
            assert_eq!(message.idx, i64::try_from(idx).unwrap());
        }

        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn modern_format_scans_sub_agents() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);
        write_modern_wire_file(
            &storage,
            "wd_example_0123456789ab",
            "sess-multi",
            "main",
            MODERN_WIRE_SAMPLE.as_bytes(),
        );
        write_modern_wire_file(
            &storage,
            "wd_example_0123456789ab",
            "sess-multi",
            "agent-1",
            br#"{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"sub agent task"}]},"time":1782968169541}
"#,
        );

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
        let mut ids: Vec<_> = convs
            .iter()
            .filter_map(|c| c.external_id.as_deref())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["sess-multi/agent-1", "sess-multi/main"]);
    }

    #[test]
    fn modern_format_title_falls_back_to_first_user_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);
        write_modern_wire_file_without_state(
            &storage,
            "wd_example_0123456789ab",
            "sess-no-state",
            "main",
            MODERN_WIRE_SAMPLE.as_bytes(),
        );

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].title.as_deref(),
            Some("帮我研究一下 continues 这个项目")
        );
        assert_eq!(convs[0].workspace, None);
    }

    #[test]
    fn modern_format_skips_unknown_types_and_malformed_lines() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);
        let wire = r#"{"type":"metadata","protocol_version":"1.9","created_at":1782968169532}
{"type":"some.future.event","payload":{"x":1},"time":1782968169540}
{ not valid json
{"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"valid user message"}]},"time":1782968169541}
{"type":"llm.request","messages":[],"time":1782968169542}
"#;
        write_modern_wire_file(
            &storage,
            "wd_example_0123456789ab",
            "sess-forward-compat",
            "main",
            wire.as_bytes(),
        );

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
    }

    #[test]
    fn modern_format_truncates_oversized_tool_output() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);
        let big_output = "x".repeat(200 * 1024);
        let call_line = r#"{"type":"context.append_loop_event","event":{"type":"tool.call","toolCallId":"tool_big","name":"Bash","args":{"command":"ls"}},"time":1782968169541}"#;
        let result_line = format!(
            r#"{{"type":"context.append_loop_event","event":{{"type":"tool.result","toolCallId":"tool_big","result":{{"output":"{big_output}"}}}},"time":1782968169542}}"#
        );
        let wire = format!("{call_line}\n{result_line}\n");
        write_modern_wire_file(
            &storage,
            "wd_example_0123456789ab",
            "sess-big-output",
            "main",
            wire.as_bytes(),
        );

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        let result_msg = &convs[0].messages[1];
        assert_eq!(result_msg.role, "tool");
        assert!(
            result_msg
                .content
                .contains("[truncated 73728 additional chars from tool output]")
        );
        assert!(result_msg.content.len() < 140 * 1024);
    }

    #[test]
    fn modern_format_discovers_state_sidecar() {
        let dir = TempDir::new().unwrap();
        let storage = create_kimi_code_storage(&dir);
        write_modern_wire_file(
            &storage,
            "wd_example_0123456789ab",
            "sess-discovery",
            "main",
            MODERN_WIRE_SAMPLE.as_bytes(),
        );

        let connector = KimiConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let discovered = connector
            .discover_source_files(&ctx)
            .expect("discovery should succeed");

        assert!(discovered.iter().any(|s| {
            s.role == DiscoveredSourceRole::PrimarySessionLog
                && s.source_path.ends_with("wire.jsonl")
        }));
        assert!(discovered.iter().any(|s| {
            s.role == DiscoveredSourceRole::MetadataSidecar && s.source_path.ends_with("state.json")
        }));
    }

    #[test]
    fn dual_format_scan_merges_legacy_and_modern_sessions() {
        let dir = TempDir::new().unwrap();
        let legacy_storage = create_kimi_storage(&dir);
        let modern_storage = create_kimi_code_storage(&dir);
        write_wire_file(
            &legacy_storage,
            "wshash",
            "legacy-session",
            &[
                r#"{"timestamp": 1772857971.0, "message": {"type": "TurnBegin", "payload": {"role": "human", "content": "legacy hello"}}}"#,
            ],
        );
        write_modern_wire_file(
            &modern_storage,
            "wd_example_0123456789ab",
            "modern-session",
            "main",
            MODERN_WIRE_SAMPLE.as_bytes(),
        );

        let connector = KimiConnector::new();
        let ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![ScanRoot::local(dir.path().to_path_buf())],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
        let mut ids: Vec<_> = convs
            .iter()
            .filter_map(|c| c.external_id.as_deref())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["legacy-session", "modern-session/main"]);

        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }
}
