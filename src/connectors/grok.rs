//! Grok Build (`grok`) connector.
//!
//! Grok Build is xAI's official terminal coding agent (installed from
//! `x.ai/cli` to `~/.grok/bin/grok`). It stores each session in its own
//! directory under `$GROK_HOME/sessions/` (default `~/.grok/sessions/`),
//! grouped by percent-encoded working directory:
//!
//! ```text
//! $GROK_HOME/sessions/<percent-encoded-cwd>/<session-uuid>/
//!   summary.json       ← metadata: id, cwd, title, timestamps, model, counts
//!   updates.jsonl      ← ACP session-update stream (authoritative log)
//!   chat_history.jsonl ← raw chat messages sent to the model
//!   plan.json, events.jsonl, rewind_points.jsonl, …  (ignored)
//! $GROK_HOME/sessions/<percent-encoded-cwd>/prompt_history.jsonl  (ignored)
//! $GROK_HOME/sessions/session_search.sqlite                       (ignored)
//! ```
//!
//! The CLI's bundled docs (`~/.grok/docs/user-guide/17-sessions.md`) state
//! that `updates.jsonl` "is the authoritative conversation log that drives
//! `/resume` and session restore", so it is the primary read path here;
//! `summary.json` supplies metadata. When a session's `updates.jsonl` carries
//! no message-bearing events (e.g. every model call failed), the raw
//! `chat_history.jsonl` is consulted so the user's prompts still index.
//!
//! ## `updates.jsonl` line envelope (empirical, grok 0.2.103)
//!
//! ```json
//! {"timestamp": 1784388059,
//!  "method": "session/update",             // or "_x.ai/session/update"
//!  "params": {
//!    "sessionId": "<uuid>",
//!    "update": {"sessionUpdate": "<kind>", …},
//!    "_meta": {"eventId": "…", "agentTimestampMs": 1784388056266}}}
//! ```
//!
//! Some lines carry `_meta` inside `update` instead (observed:
//! `user_message_chunk` had `update._meta.modelId` / `promptIndex`), so both
//! locations are consulted. `sessionUpdate` kinds are the Agent Client
//! Protocol standard set (`user_message_chunk`, `agent_message_chunk`,
//! `agent_thought_chunk`, `tool_call`, `tool_call_update`, `plan`) plus x.ai
//! extensions observed empirically (`hook_execution`, `retry_state`). Unknown
//! kinds are skipped tolerantly; consecutive same-kind streaming chunks are
//! coalesced into one message.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Map, Value};

use super::flatten_content;
use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::{dedupe_path_key, env_path_nonempty};
use super::{Connector, file_modified_since, franken_detection_for_connector, parse_timestamp};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
    reindex_messages,
};

/// Normalized agent slug emitted for every Grok Build conversation.
const AGENT_SLUG: &str = "grok";

/// Connector for xAI's Grok Build (`grok`) coding agent.
pub struct GrokConnector;

impl Default for GrokConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl GrokConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Base data directory. Respects the CLI-documented `GROK_HOME` override,
    /// otherwise `~/.grok`.
    fn base_root() -> PathBuf {
        if let Some(explicit) = env_path_nonempty("GROK_HOME") {
            return explicit;
        }
        dirs::home_dir().unwrap_or_default().join(".grok")
    }

    /// The sessions root under a base directory.
    fn sessions_root_of(base: &Path) -> PathBuf {
        base.join("sessions")
    }

    /// A session directory is recognized by its `updates.jsonl` or, for a
    /// degraded/partial session, a `chat_history.jsonl`.
    fn is_session_dir(path: &Path) -> bool {
        path.join("updates.jsonl").is_file() || path.join("chat_history.jsonl").is_file()
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots = if ctx.use_default_detection() {
            // Mirror the explicit-root acceptance: a default-detection
            // data_dir that itself resolves as Grok storage (a `$GROK_HOME`
            // base with `sessions/`, the `sessions/` tree, or one session
            // dir) scopes the scan to it, so fixture/mirror scans stay
            // hermetic; otherwise probe the system base. `GROK_HOME` keeps
            // precedence so CI redirection is unaffected.
            let d = &ctx.data_dir;
            let env_override = env_path_nonempty("GROK_HOME").is_some();
            if !env_override && (d.join("sessions").is_dir() || Self::is_session_dir(d)) {
                vec![ScanRoot::local(d.clone())]
            } else {
                vec![ScanRoot::local(Self::base_root())]
            }
        } else {
            ctx.scan_roots.clone()
        };
        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    /// Resolve every session directory reachable from a scan target. The
    /// target may be a session directory itself, a cwd group directory, the
    /// `sessions/` root, or the `$GROK_HOME` base.
    fn session_dirs(scan_target: &Path) -> Vec<PathBuf> {
        if Self::is_session_dir(scan_target) {
            return vec![scan_target.to_path_buf()];
        }

        let mut candidates: Vec<PathBuf> = Vec::new();
        let sessions_root = Self::sessions_root_of(scan_target);
        let group_roots: Vec<PathBuf> = if sessions_root.is_dir() {
            // scan target is $GROK_HOME
            vec![sessions_root]
        } else if scan_target
            .file_name()
            .is_some_and(|name| name == "sessions")
            && scan_target.is_dir()
        {
            vec![scan_target.to_path_buf()]
        } else if scan_target.is_dir() {
            // Could be a cwd group directory containing session dirs directly.
            vec![scan_target.to_path_buf()]
        } else {
            Vec::new()
        };

        for root in group_roots {
            for group in fs::read_dir(&root).into_iter().flatten().flatten() {
                let group_path = group.path();
                if !group_path.is_dir() {
                    continue; // session_search.sqlite, prompt_history.jsonl, …
                }
                if Self::is_session_dir(&group_path) {
                    // The "group" was itself a session dir (scan root was a
                    // cwd group directory).
                    candidates.push(group_path);
                    continue;
                }
                for session in fs::read_dir(&group_path).into_iter().flatten().flatten() {
                    let session_dir = session.path();
                    if session_dir.is_dir() && Self::is_session_dir(&session_dir) {
                        candidates.push(session_dir);
                    }
                }
            }
        }

        candidates.sort();
        candidates.dedup();
        candidates
    }

    /// True when any of the session's readable transcript files is newer than
    /// `since_ts`.
    fn session_modified_since(session_dir: &Path, since_ts: Option<i64>) -> bool {
        if since_ts.is_none() {
            return true;
        }
        file_modified_since(&session_dir.join("updates.jsonl"), since_ts)
            || file_modified_since(&session_dir.join("chat_history.jsonl"), since_ts)
            || file_modified_since(&session_dir.join("summary.json"), since_ts)
    }
}

/// Decode a percent-encoded cwd group directory name back to a path.
///
/// Prefers a `.cwd` file inside the group directory (written by the CLI when
/// the encoded name would exceed 255 bytes), then percent-decoding the name.
fn decode_group_cwd(group_dir: &Path) -> Option<PathBuf> {
    let cwd_file = group_dir.join(".cwd");
    if cwd_file.is_file()
        && let Ok(content) = fs::read_to_string(&cwd_file)
    {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    let name = group_dir.file_name()?.to_str()?;
    let decoded = percent_decode(name)?;
    if decoded.is_empty() {
        return None;
    }
    Some(PathBuf::from(decoded))
}

/// Minimal RFC 3986 percent-decoding (UTF-8). Returns `None` on malformed
/// escapes or invalid UTF-8 rather than guessing.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = bytes.get(i + 1).copied()?;
            let lo = bytes.get(i + 2).copied()?;
            let hex = |b: u8| -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                }
            };
            out.push(hex(hi)? * 16 + hex(lo)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The kind of streaming chunk currently being coalesced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkKind {
    User,
    Thought,
    Agent,
}

const fn chunk_kind_label(kind: ChunkKind) -> &'static str {
    match kind {
        ChunkKind::User => "user_message_chunk",
        ChunkKind::Thought => "agent_thought_chunk",
        ChunkKind::Agent => "agent_message_chunk",
    }
}

/// Extract the best-precision timestamp (epoch millis) from an update line:
/// `params._meta.agentTimestampMs`, then `update._meta.agentTimestampMs`,
/// then the envelope's epoch-seconds `timestamp`.
fn line_timestamp(line: &Value, update: &Value) -> Option<i64> {
    line.pointer("/params/_meta/agentTimestampMs")
        .and_then(parse_timestamp)
        .or_else(|| {
            update
                .pointer("/_meta/agentTimestampMs")
                .and_then(parse_timestamp)
        })
        .or_else(|| line.get("timestamp").and_then(parse_timestamp))
}

/// Flatten an ACP `ContentBlock` — a bare object (`{"type":"text","text":…}`),
/// an array of blocks, or a plain string — into display text.
/// [`flatten_content`] only understands strings and arrays, so a single
/// object block (the empirical ACP chunk shape) is wrapped into a one-element
/// array first.
fn acp_content_text(value: &Value) -> String {
    match value {
        Value::Object(_) => flatten_content(&Value::Array(vec![value.clone()])),
        _ => flatten_content(value),
    }
}

/// Flatten an ACP `ToolCallContent` array (`tool_call` / `tool_call_update`
/// `content`) into display text. Variants per the ACP schema:
/// `{"type":"content","content":<ContentBlock>}`, `{"type":"diff",…}`,
/// `{"type":"terminal",…}`.
fn flatten_tool_content(value: &Value) -> String {
    let Some(items) = value.as_array() else {
        return acp_content_text(value);
    };
    let mut parts: Vec<String> = Vec::new();
    for item in items {
        match item.get("type").and_then(Value::as_str) {
            Some("content") => {
                if let Some(block) = item.get("content") {
                    let text = acp_content_text(block);
                    if !text.is_empty() {
                        parts.push(text);
                    }
                }
            }
            Some("diff") => {
                let path = item.get("path").and_then(Value::as_str).unwrap_or("file");
                parts.push(format!("[Diff: {path}]"));
            }
            Some("terminal") => parts.push("[Terminal output]".to_string()),
            _ => {
                let text = acp_content_text(item);
                if !text.is_empty() {
                    parts.push(text);
                }
            }
        }
    }
    parts.join("\n")
}

/// Render tool output text from a `tool_call` / `tool_call_update` event:
/// prefer `content`, fall back to `rawOutput`.
fn tool_output_text(update: &Value) -> Option<String> {
    if let Some(content) = update.get("content") {
        let text = flatten_tool_content(content);
        if !text.trim().is_empty() {
            return Some(text);
        }
    }
    match update.get("rawOutput") {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        Some(Value::Null) | None => None,
        Some(other) => {
            let text = acp_content_text(other);
            if text.trim().is_empty() {
                serde_json::to_string(other).ok()
            } else {
                Some(text)
            }
        }
    }
}

/// Streaming state that folds ACP session-update events into normalized
/// messages, coalescing consecutive same-kind chunks.
#[derive(Default)]
struct MessageBuilder {
    messages: Vec<NormalizedMessage>,
    /// Kind of the chunk message currently being extended (None after a
    /// non-chunk event breaks the run).
    last_kind: Option<ChunkKind>,
    /// `toolCallId` → index into `messages` holding that tool call.
    tool_call_owner: HashMap<String, usize>,
}

impl MessageBuilder {
    fn push_chunk(&mut self, kind: ChunkKind, text: &str, ts: Option<i64>, author: Option<String>) {
        if self.last_kind == Some(kind)
            && let Some(last) = self.messages.last_mut()
        {
            last.content.push_str(text);
            if last.created_at.is_none() {
                last.created_at = ts;
            }
            if last.author.is_none() {
                last.author = author;
            }
            return;
        }
        let role = match kind {
            ChunkKind::User => "user",
            ChunkKind::Thought | ChunkKind::Agent => "assistant",
        };
        let author = match kind {
            ChunkKind::Thought => author.or_else(|| Some("reasoning".to_string())),
            _ => author,
        };
        let mut extra = Map::new();
        extra.insert(
            "sessionUpdate".to_string(),
            Value::String(chunk_kind_label(kind).to_string()),
        );
        self.messages.push(NormalizedMessage {
            idx: 0,
            role: role.to_string(),
            author,
            created_at: ts,
            content: text.to_string(),
            extra: Value::Object(extra),
            invocations: Vec::new(),
            snippets: Vec::new(),
        });
        self.last_kind = Some(kind);
    }

    /// Record a `tool_call` event as a `tool` role message with a structured
    /// invocation. A completed event may already carry output text.
    fn push_tool_call(&mut self, update: &Value, ts: Option<i64>) {
        let call_id = update
            .get("toolCallId")
            .and_then(Value::as_str)
            .map(String::from);
        let name = update
            .get("title")
            .and_then(Value::as_str)
            .or_else(|| update.get("kind").and_then(Value::as_str))
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("tool")
            .to_string();
        let invocation = NormalizedInvocation {
            kind: "tool".to_string(),
            name,
            raw_name: None,
            call_id: call_id.clone(),
            arguments: update.get("rawInput").filter(|v| !v.is_null()).cloned(),
        };
        let mut extra = Map::new();
        extra.insert(
            "sessionUpdate".to_string(),
            Value::String("tool_call".to_string()),
        );
        if let Some(status) = update.get("status").and_then(Value::as_str) {
            extra.insert("status".to_string(), Value::String(status.to_string()));
        }
        if let Some(kind) = update.get("kind").and_then(Value::as_str) {
            extra.insert("tool_kind".to_string(), Value::String(kind.to_string()));
        }
        self.messages.push(NormalizedMessage {
            idx: 0,
            role: "tool".to_string(),
            author: None,
            created_at: ts,
            content: tool_output_text(update).unwrap_or_default(),
            extra: Value::Object(extra),
            invocations: vec![invocation],
            snippets: Vec::new(),
        });
        self.last_kind = None;
        if let Some(id) = call_id {
            self.tool_call_owner.insert(id, self.messages.len() - 1);
        }
    }

    /// Merge a `tool_call_update` into the owning tool message: refresh the
    /// invocation name/arguments and replace the streamed output. Updates for
    /// unknown call ids (e.g. a truncated log) create a fresh tool message so
    /// the activity is not silently dropped.
    fn push_tool_call_update(&mut self, update: &Value, ts: Option<i64>) {
        let call_id = update.get("toolCallId").and_then(Value::as_str);
        let owner = call_id.and_then(|id| self.tool_call_owner.get(id).copied());
        let Some(idx) = owner else {
            self.push_tool_call(update, ts);
            return;
        };
        let msg = &mut self.messages[idx];
        if let Some(invocation) = msg.invocations.first_mut() {
            if let Some(title) = update
                .get("title")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                invocation.name = title.to_string();
            }
            if let Some(raw_input) = update.get("rawInput").filter(|v| !v.is_null()) {
                invocation.arguments = Some(raw_input.clone());
            }
        }
        if let Some(output) = tool_output_text(update) {
            // Streamed tool_call_update events supersede one another.
            msg.content = output;
        }
        if let Some(status) = update.get("status").and_then(Value::as_str)
            && let Value::Object(extra) = &mut msg.extra
        {
            extra.insert("status".to_string(), Value::String(status.to_string()));
        }
        if msg.created_at.is_none() {
            msg.created_at = ts;
        }
    }

    /// Finish: drop messages with no content and no tool activity.
    fn finish(mut self) -> Vec<NormalizedMessage> {
        self.messages
            .retain(|m| !m.content.trim().is_empty() || !m.invocations.is_empty());
        reindex_messages(&mut self.messages);
        self.messages
    }
}

/// Extract the inner text of every `<TAG>…</TAG>` block in `content`.
fn extract_tagged_blocks(content: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = content;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        out.push(after[..end].trim().to_string());
        rest = &after[end + close.len()..];
    }
    out
}

/// Parse `updates.jsonl` into messages plus observed time bounds.
fn parse_updates(
    updates_path: &Path,
    model_name: Option<&str>,
) -> (Vec<NormalizedMessage>, Option<i64>, Option<i64>) {
    let mut builder = MessageBuilder::default();
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;

    let Ok(file) = fs::File::open(updates_path) else {
        return (Vec::new(), None, None);
    };
    for (lineno, line) in BufReader::new(file).lines().enumerate() {
        let Ok(line) = line else {
            tracing::warn!(
                updates = %updates_path.display(),
                line = lineno + 1,
                "grok: stopping at unreadable updates line"
            );
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(line) else {
            tracing::warn!(
                updates = %updates_path.display(),
                line = lineno + 1,
                "grok: skipping malformed updates line"
            );
            continue;
        };
        // Envelope: {"params":{"update":{…}}}; tolerate a bare
        // {"update":{…}} or a naked SessionUpdate object.
        let update = val
            .pointer("/params/update")
            .or_else(|| val.get("update"))
            .unwrap_or(&val);
        let Some(kind) = update.get("sessionUpdate").and_then(Value::as_str) else {
            continue;
        };

        let ts = line_timestamp(&val, update);
        if let Some(t) = ts {
            started_at = Some(started_at.map_or(t, |s| s.min(t)));
            ended_at = Some(ended_at.map_or(t, |e| e.max(t)));
        }

        match kind {
            "user_message_chunk" | "agent_message_chunk" | "agent_thought_chunk" => {
                let chunk_kind = match kind {
                    "user_message_chunk" => ChunkKind::User,
                    "agent_thought_chunk" => ChunkKind::Thought,
                    _ => ChunkKind::Agent,
                };
                let text = update
                    .get("content")
                    .map(acp_content_text)
                    .unwrap_or_default();
                if text.is_empty() {
                    continue;
                }
                // Model id may ride in update-level _meta.
                let author = if chunk_kind == ChunkKind::Agent {
                    update
                        .pointer("/_meta/modelId")
                        .and_then(Value::as_str)
                        .map(String::from)
                        .or_else(|| model_name.map(String::from))
                } else {
                    None
                };
                builder.push_chunk(chunk_kind, &text, ts, author);
            }
            "tool_call" => builder.push_tool_call(update, ts),
            "tool_call_update" => builder.push_tool_call_update(update, ts),
            // Known non-conversation kinds (plan/TODO state, hook runs, retry
            // telemetry) and unknown future kinds are skipped tolerantly.
            _ => {}
        }
    }

    (builder.finish(), started_at, ended_at)
}

/// Fallback: recover user prompts (and any assistant text) from
/// `chat_history.jsonl` when `updates.jsonl` yielded no message-bearing
/// events (e.g. every model call failed). Real user prompts carry a
/// `prompt_index` field and wrap the prompt in `<user_query>…</user_query>`;
/// synthetic context injections carry `synthetic_reason` and are skipped.
fn parse_chat_history_fallback(chat_history_path: &Path) -> Vec<NormalizedMessage> {
    let Ok(file) = fs::File::open(chat_history_path) else {
        return Vec::new();
    };
    let mut messages: Vec<NormalizedMessage> = Vec::new();
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else {
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let msg_type = val.get("type").and_then(Value::as_str).unwrap_or("");
        match msg_type {
            "user" => {
                // Only index real prompts, not synthetic context injections
                // or the environment preamble.
                if val.get("synthetic_reason").is_some() || val.get("prompt_index").is_none() {
                    continue;
                }
                let text = val.get("content").map(acp_content_text).unwrap_or_default();
                let queries = extract_tagged_blocks(&text, "user_query");
                let body = if queries.is_empty() {
                    text.trim().to_string()
                } else {
                    queries.join("\n\n")
                };
                if body.is_empty() {
                    continue;
                }
                let mut extra = Map::new();
                extra.insert("chat_history_fallback".to_string(), Value::Bool(true));
                if let Some(prompt_index) = val.get("prompt_index").cloned() {
                    extra.insert("prompt_index".to_string(), prompt_index);
                }
                messages.push(NormalizedMessage {
                    idx: 0,
                    role: "user".to_string(),
                    author: None,
                    created_at: None,
                    content: body,
                    extra: Value::Object(extra),
                    invocations: Vec::new(),
                    snippets: Vec::new(),
                });
            }
            "assistant" => {
                let text = val.get("content").map(acp_content_text).unwrap_or_default();
                if text.trim().is_empty() {
                    continue;
                }
                let mut extra = Map::new();
                extra.insert("chat_history_fallback".to_string(), Value::Bool(true));
                messages.push(NormalizedMessage {
                    idx: 0,
                    role: "assistant".to_string(),
                    author: None,
                    created_at: None,
                    content: text,
                    extra: Value::Object(extra),
                    invocations: Vec::new(),
                    snippets: Vec::new(),
                });
            }
            _ => {}
        }
    }
    reindex_messages(&mut messages);
    messages
}

fn parse_session(session_dir: &Path) -> Option<NormalizedConversation> {
    let updates_path = session_dir.join("updates.jsonl");
    let chat_history_path = session_dir.join("chat_history.jsonl");

    let summary: Option<Value> = fs::read_to_string(session_dir.join("summary.json"))
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok());

    let external_id = summary
        .as_ref()
        .and_then(|s| s.pointer("/info/id"))
        .and_then(Value::as_str)
        .map(String::from)
        .or_else(|| {
            session_dir
                .file_name()
                .and_then(|n| n.to_str())
                .map(String::from)
        });

    let workspace = summary
        .as_ref()
        .and_then(|s| s.pointer("/info/cwd"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .or_else(|| session_dir.parent().and_then(decode_group_cwd));

    let model_name = summary
        .as_ref()
        .and_then(|s| s.get("current_model_id"))
        .and_then(Value::as_str)
        .map(String::from);

    let (mut messages, mut started_at, mut ended_at) = if updates_path.is_file() {
        parse_updates(&updates_path, model_name.as_deref())
    } else {
        (Vec::new(), None, None)
    };
    let source_path = if messages.is_empty() && chat_history_path.is_file() {
        messages = parse_chat_history_fallback(&chat_history_path);
        // The normalized messages came from the fallback history, so preserve
        // that exact provenance even when an update stream exists but contains
        // only non-message telemetry (for example a failed model turn).
        chat_history_path
    } else {
        updates_path
    };
    if messages.is_empty() {
        // An un-run or content-less session; nothing to index.
        return None;
    }

    // Summary timestamps take precedence over message-derived bounds.
    if let Some(s) = summary.as_ref() {
        if let Some(t) = s.get("created_at").and_then(parse_timestamp) {
            started_at = Some(t);
        }
        if let Some(t) = s
            .get("last_active_at")
            .and_then(parse_timestamp)
            .or_else(|| s.get("updated_at").and_then(parse_timestamp))
        {
            ended_at = Some(t);
        }
    }

    let title = summary
        .as_ref()
        .and_then(|s| s.get("generated_title"))
        .and_then(Value::as_str)
        .filter(|t| !t.trim().is_empty())
        .map(String::from)
        .or_else(|| {
            summary
                .as_ref()
                .and_then(|s| s.get("session_summary"))
                .and_then(Value::as_str)
                .filter(|t| !t.trim().is_empty())
                .map(String::from)
        })
        .or_else(|| {
            messages
                .iter()
                .find(|m| m.role == "user")
                .or_else(|| messages.first())
                .and_then(|m| m.content.lines().find(|l| !l.trim().is_empty()))
                .map(|line| line.chars().take(100).collect::<String>())
        });

    let mut metadata = Map::new();
    metadata.insert("source".to_string(), Value::String(AGENT_SLUG.to_string()));
    if let Some(model) = model_name {
        metadata.insert("model".to_string(), Value::String(model));
    }
    if let Some(s) = summary.as_ref() {
        for key in ["agent_name", "sandbox_profile", "parent_session_id"] {
            if let Some(v) = s.get(key).filter(|v| !v.is_null()) {
                metadata.insert(key.to_string(), v.clone());
            }
        }
    }

    Some(NormalizedConversation {
        agent_slug: AGENT_SLUG.to_string(),
        external_id,
        title,
        workspace,
        source_path,
        started_at,
        ended_at,
        metadata: Value::Object(metadata),
        messages,
    })
}

fn scan_grok_with_callback(
    ctx: &ScanContext,
    on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
) -> Result<()> {
    let roots = GrokConnector::source_roots(ctx);
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for root in roots {
        if !root.path.exists() {
            continue;
        }
        for session_dir in GrokConnector::session_dirs(&root.path) {
            if !seen.insert(dedupe_path_key(&session_dir)) {
                continue;
            }
            if !GrokConnector::session_modified_since(&session_dir, ctx.since_ts) {
                continue;
            }
            if let Some(conversation) = parse_session(&session_dir) {
                on_conversation(conversation)
                    .with_context(|| format!("emit grok conversation {}", session_dir.display()))?;
            }
        }
    }

    Ok(())
}

fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
    let roots = GrokConnector::source_roots(ctx);
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for root in roots {
        if !root.path.exists() {
            continue;
        }
        for session_dir in GrokConnector::session_dirs(&root.path) {
            if !GrokConnector::session_modified_since(&session_dir, ctx.since_ts) {
                continue;
            }

            // The authoritative update stream we parse.
            let updates = session_dir.join("updates.jsonl");
            if updates.is_file() && seen.insert(dedupe_path_key(&updates)) {
                out.push(
                    DiscoveredSourceFile::new(
                        AGENT_SLUG,
                        &root,
                        updates,
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }

            // The raw model-facing history (fallback read path).
            let chat_history = session_dir.join("chat_history.jsonl");
            if chat_history.is_file() && seen.insert(dedupe_path_key(&chat_history)) {
                out.push(
                    DiscoveredSourceFile::new(
                        AGENT_SLUG,
                        &root,
                        chat_history,
                        DiscoveredSourceRole::PrimarySessionLog,
                        false,
                    )
                    .with_fs_metadata(),
                );
            }

            // Session metadata sidecar.
            let summary = session_dir.join("summary.json");
            if summary.is_file() && seen.insert(dedupe_path_key(&summary)) {
                out.push(
                    DiscoveredSourceFile::new(
                        AGENT_SLUG,
                        &root,
                        summary,
                        DiscoveredSourceRole::MetadataSidecar,
                        false,
                    )
                    .with_fs_metadata(),
                );
            }
        }
    }

    out
}

impl Connector for GrokConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector(AGENT_SLUG).unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        scan_grok_with_callback(ctx, &mut |conv| {
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
        scan_grok_with_callback(ctx, on_conversation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::assert_discovery_covers_scan_sources;
    use serde_json::json;
    use tempfile::TempDir;

    const SESSION_ID: &str = "019f75d0-ebe1-7db0-a59a-60af9ffa9e71";
    const ENCODED_CWD: &str = "%2Fdata%2Fprojects%2Fdemo";

    /// Wrap a `SessionUpdate` object in the empirical grok-0.2.103 envelope.
    fn envelope(update: &Value, ts_secs: i64) -> String {
        serde_json::to_string(&json!({
            "timestamp": ts_secs,
            "method": "_x.ai/session/update",
            "params": {
                "sessionId": SESSION_ID,
                "update": update,
                "_meta": {
                    "eventId": format!("{SESSION_ID}-1"),
                    "agentTimestampMs": ts_secs * 1000
                }
            }
        }))
        .expect("serialize envelope")
    }

    fn text_chunk(kind: &str, text: &str) -> Value {
        json!({
            "sessionUpdate": kind,
            "content": {"type": "text", "text": text}
        })
    }

    fn write_session(root: &Path, updates_lines: &[String]) -> PathBuf {
        let session_dir = root.join("sessions").join(ENCODED_CWD).join(SESSION_ID);
        std::fs::create_dir_all(&session_dir).expect("mkdir session");
        std::fs::write(
            session_dir.join("updates.jsonl"),
            updates_lines.join("\n") + "\n",
        )
        .expect("write updates");
        std::fs::write(
            session_dir.join("summary.json"),
            serde_json::to_string_pretty(&json!({
                "info": {"id": SESSION_ID, "cwd": "/data/projects/demo"},
                "session_summary": "Fix the flaky test",
                "created_at": "2026-07-18T15:20:54.103795421Z",
                "updated_at": "2026-07-18T15:20:59.770364197Z",
                "last_active_at": "2026-07-18T15:20:59.770364197Z",
                "num_messages": 4,
                "current_model_id": "grok-build",
                "generated_title": "Fix the flaky test",
                "agent_name": "grok-build-plan",
                "sandbox_profile": "off"
            }))
            .expect("serialize summary"),
        )
        .expect("write summary");
        session_dir
    }

    fn ctx_for(root: &Path) -> ScanContext {
        ScanContext {
            data_dir: root.join("cass-data"),
            scan_roots: vec![ScanRoot::local(root.to_path_buf())],
            since_ts: None,
            progress_tick: None,
        }
    }

    #[test]
    fn default_detection_scopes_to_grok_base_data_dir() {
        let tmp = TempDir::new().expect("tempdir");
        write_session(
            tmp.path(),
            &[
                envelope(&text_chunk("user_message_chunk", "hello"), 1_784_388_056),
                envelope(
                    &text_chunk("agent_message_chunk", "hi there"),
                    1_784_388_057,
                ),
            ],
        );
        let convs = GrokConnector
            .scan(&ScanContext::local_default(tmp.path().to_path_buf(), None))
            .expect("scan");
        assert_eq!(
            convs.len(),
            1,
            "default detection with a Grok-base data_dir must scan that base, not ~/.grok"
        );
        assert_eq!(convs[0].external_id.as_deref(), Some(SESSION_ID));
    }
    #[test]

    fn parses_chunked_conversation_with_tool_calls() {
        let tmp = TempDir::new().expect("tempdir");
        let lines = vec![
            envelope(
                &json!({
                    "sessionUpdate": "hook_execution",
                    "event_name": "user_prompt_submit",
                    "runs": []
                }),
                1_784_388_056,
            ),
            envelope(
                &text_chunk("user_message_chunk", "Fix the flaky "),
                1_784_388_057,
            ),
            envelope(&text_chunk("user_message_chunk", "test"), 1_784_388_057),
            envelope(
                &text_chunk("agent_thought_chunk", "The test is timing-sensitive."),
                1_784_388_058,
            ),
            envelope(
                &text_chunk("agent_message_chunk", "Looking at the "),
                1_784_388_058,
            ),
            envelope(
                &text_chunk("agent_message_chunk", "test now."),
                1_784_388_058,
            ),
            envelope(
                &json!({
                    "sessionUpdate": "tool_call",
                    "toolCallId": "call-1",
                    "title": "run_shell",
                    "kind": "execute",
                    "status": "in_progress",
                    "rawInput": {"command": "cargo test flaky -- --nocapture"}
                }),
                1_784_388_059,
            ),
            envelope(
                &json!({
                    "sessionUpdate": "tool_call_update",
                    "toolCallId": "call-1",
                    "status": "completed",
                    "content": [
                        {"type": "content", "content": {"type": "text", "text": "test flaky ... ok"}}
                    ]
                }),
                1_784_388_060,
            ),
            envelope(&text_chunk("agent_message_chunk", "Fixed."), 1_784_388_061),
        ];
        let session_dir = write_session(tmp.path(), &lines);

        let conv = parse_session(&session_dir).expect("session parses");
        assert_eq!(conv.agent_slug, "grok");
        assert_eq!(conv.external_id.as_deref(), Some(SESSION_ID));
        assert_eq!(conv.title.as_deref(), Some("Fix the flaky test"));
        assert_eq!(
            conv.workspace.as_deref(),
            Some(Path::new("/data/projects/demo"))
        );
        assert_eq!(
            conv.metadata.get("model").and_then(Value::as_str),
            Some("grok-build")
        );

        let roles: Vec<&str> = conv.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(
            roles,
            vec!["user", "assistant", "assistant", "tool", "assistant"]
        );
        // Chunks coalesced.
        assert_eq!(conv.messages[0].content, "Fix the flaky test");
        assert_eq!(conv.messages[1].author.as_deref(), Some("reasoning"));
        assert_eq!(conv.messages[2].content, "Looking at the test now.");
        // Tool call has invocation + streamed output.
        let tool = &conv.messages[3];
        assert_eq!(tool.invocations.len(), 1);
        assert_eq!(tool.invocations[0].name, "run_shell");
        assert_eq!(tool.invocations[0].call_id.as_deref(), Some("call-1"));
        assert_eq!(tool.content, "test flaky ... ok");
        assert_eq!(
            tool.extra.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert_eq!(conv.messages[4].content, "Fixed.");
        // Summary timestamps take precedence.
        assert_eq!(
            conv.started_at,
            parse_timestamp(&json!("2026-07-18T15:20:54.103795421Z"))
        );
        assert_eq!(
            conv.ended_at,
            parse_timestamp(&json!("2026-07-18T15:20:59.770364197Z"))
        );
    }

    #[test]
    fn falls_back_to_chat_history_when_updates_carry_no_messages() {
        let tmp = TempDir::new().expect("tempdir");
        // updates.jsonl holds only hook/retry telemetry (e.g. every model
        // call failed) — the empirical shape from a real broken session.
        let lines = vec![envelope(
            &json!({
                "sessionUpdate": "retry_state",
                "type": "failed",
                "error_type": "api",
                "message": "API error (status 404 Not Found)"
            }),
            1_784_388_058,
        )];
        let session_dir = write_session(tmp.path(), &lines);
        std::fs::write(
            session_dir.join("chat_history.jsonl"),
            [
                json!({"type": "system", "content": "You are Grok."}).to_string(),
                json!({"type": "user", "content": [{"type": "text", "text": "<user_info>\nOS: linux\n</user_info>"}]})
                    .to_string(),
                json!({"type": "user", "synthetic_reason": "skills", "content": [{"type": "text", "text": "<system-reminder>skills</system-reminder>"}]})
                    .to_string(),
                json!({"type": "user", "prompt_index": 0, "content": [{"type": "text", "text": "<user_query>\nRun the tests\n</user_query>"}]})
                    .to_string(),
            ]
            .join("\n"),
        )
        .expect("write chat history");

        let conv = parse_session(&session_dir).expect("fallback parses");
        assert_eq!(conv.source_path, session_dir.join("chat_history.jsonl"));
        assert_eq!(conv.messages.len(), 1);
        assert_eq!(conv.messages[0].role, "user");
        assert_eq!(conv.messages[0].content, "Run the tests");
        assert_eq!(
            conv.messages[0]
                .extra
                .get("chat_history_fallback")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn unrun_session_yields_no_conversation() {
        let tmp = TempDir::new().expect("tempdir");
        let session_dir = write_session(tmp.path(), &[]);
        assert!(parse_session(&session_dir).is_none());
    }

    #[test]
    fn scan_discovers_sessions_from_base_root() {
        let tmp = TempDir::new().expect("tempdir");
        let lines = vec![
            envelope(&text_chunk("user_message_chunk", "hello"), 1_784_388_057),
            envelope(&text_chunk("agent_message_chunk", "hi"), 1_784_388_058),
        ];
        write_session(tmp.path(), &lines);
        // Root-level noise the walker must ignore.
        std::fs::write(
            tmp.path().join("sessions").join("session_search.sqlite"),
            b"x",
        )
        .expect("write sqlite noise");
        std::fs::write(
            tmp.path()
                .join("sessions")
                .join(ENCODED_CWD)
                .join("prompt_history.jsonl"),
            b"{}\n",
        )
        .expect("write prompt history noise");

        let ctx = ctx_for(tmp.path());
        let connector = GrokConnector::new();
        let convs = connector.scan(&ctx).expect("scan");
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "grok");
        assert_eq!(convs[0].messages.len(), 2);

        // The sessions/ root and the session dir itself also work as targets.
        let sessions_root_ctx = ctx_for(&tmp.path().join("sessions"));
        assert_eq!(connector.scan(&sessions_root_ctx).expect("scan").len(), 1);

        assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn workspace_falls_back_to_percent_decoded_group_name() {
        let tmp = TempDir::new().expect("tempdir");
        let session_dir = tmp
            .path()
            .join("sessions")
            .join(ENCODED_CWD)
            .join(SESSION_ID);
        std::fs::create_dir_all(&session_dir).expect("mkdir");
        std::fs::write(
            session_dir.join("updates.jsonl"),
            envelope(&text_chunk("user_message_chunk", "hi"), 1_784_388_057) + "\n",
        )
        .expect("write updates");
        // No summary.json → workspace comes from the group directory name.
        let conv = parse_session(&session_dir).expect("parses");
        assert_eq!(
            conv.workspace.as_deref(),
            Some(Path::new("/data/projects/demo"))
        );
        assert_eq!(conv.external_id.as_deref(), Some(SESSION_ID));
    }

    #[test]
    fn cwd_file_overrides_group_name_decoding() {
        let tmp = TempDir::new().expect("tempdir");
        let group = tmp.path().join("sessions").join("very-long-slug-abc123");
        let session_dir = group.join(SESSION_ID);
        std::fs::create_dir_all(&session_dir).expect("mkdir");
        std::fs::write(group.join(".cwd"), "/real/workspace/path\n").expect("write .cwd");
        std::fs::write(
            session_dir.join("updates.jsonl"),
            envelope(&text_chunk("user_message_chunk", "hi"), 1_784_388_057) + "\n",
        )
        .expect("write updates");
        let conv = parse_session(&session_dir).expect("parses");
        assert_eq!(
            conv.workspace.as_deref(),
            Some(Path::new("/real/workspace/path"))
        );
    }

    #[test]
    fn percent_decode_rejects_malformed_escapes() {
        assert_eq!(percent_decode("%2Fa%2Fb"), Some("/a/b".to_string()));
        assert_eq!(percent_decode("plain"), Some("plain".to_string()));
        assert_eq!(percent_decode("%2"), None);
        assert_eq!(percent_decode("%zz"), None);
    }
}
