//! Connector for Qwen Code (Alibaba) session logs.
//!
//! Qwen Code stores current sessions as UUID-named JSONL files under
//! `~/.qwen/projects/<project>/chats/` (including `chats/archive/`).
//! Legacy JSON sessions live at
//! `~/.qwen/tmp/<project-hash>/chats/session-<timestamp>-<id>.json`.
//!
//! Each legacy file is a complete JSON object containing:
//! - `sessionId`, `projectHash`, `startTime`, `lastUpdated`
//! - `messages` array with objects: `id`, `timestamp`, `type`, `content`, `tokens`
//!
//! Legacy message types: `user`, `qwen` (assistant). Native JSONL uses
//! `user`, `assistant`, `tool_result` and parent-linked `system` records.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

use super::jsonl::JsonlLines;
use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::read_capped;
use super::{
    Connector, file_modified_since, flatten_content, franken_detection_for_connector,
    parse_timestamp, utils::dedupe_path_key,
};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
};

const LARGE_SESSION_EXTRA_COMPACT_THRESHOLD_BYTES: u64 = 32 * 1024 * 1024;
const QWEN_USAGE_KEYS: [&str; 6] = [
    "promptTokenCount",
    "candidatesTokenCount",
    "totalTokenCount",
    "cachedContentTokenCount",
    "thoughtsTokenCount",
    "toolUsePromptTokenCount",
];

struct QwenSourceRoot {
    root: ScanRoot,
    include_legacy: bool,
}

pub struct QwenConnector;

impl Default for QwenConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl QwenConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn default_root() -> PathBuf {
        crate::qwen_runtime_root_from_env()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".qwen"))
    }

    fn looks_like_qwen_storage(path: &Path) -> bool {
        // Keep the provider identity structural, including exact sources and
        // project/chats subdirectories returned by discovery.
        path.ancestors()
            .any(|ancestor| ancestor.file_name().is_some_and(|n| n == ".qwen"))
    }

    fn append_qwen_roots(roots: &mut Vec<QwenSourceRoot>, scan_root: &ScanRoot) {
        let base = &scan_root.path;
        if Self::looks_like_qwen_storage(base) {
            roots.push(QwenSourceRoot {
                root: scan_root.clone(),
                include_legacy: true,
            });
            return;
        }

        let candidate = base.join(".qwen");
        if candidate.is_dir() {
            roots.push(QwenSourceRoot {
                root: scan_root.with_path(candidate),
                include_legacy: true,
            });
        }

        if Self::looks_like_native_root(base) {
            // Unmarked copies only admit the current, distinctive filename
            // and record schema. Gemini's session-*.json is not Qwen evidence.
            roots.push(QwenSourceRoot {
                root: scan_root.clone(),
                include_legacy: false,
            });
        }
    }

    fn is_native_session_file(path: &Path) -> bool {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        let Some(id) = name.strip_suffix(".jsonl") else {
            return false;
        };
        let in_chats = path.parent().is_some_and(|parent| {
            parent.file_name().is_some_and(|n| n == "chats")
                || (parent.file_name().is_some_and(|n| n == "archive")
                    && parent
                        .parent()
                        .is_some_and(|p| p.file_name().is_some_and(|n| n == "chats")))
        });
        in_chats
            && (32..=36).contains(&id.len())
            && id.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-')
    }

    fn looks_like_native_root(path: &Path) -> bool {
        Self::is_native_session_file(path)
            || path.file_name().is_some_and(|name| name == "chats")
            || (path.file_name().is_some_and(|name| name == "archive")
                && path
                    .parent()
                    .is_some_and(|parent| parent.file_name().is_some_and(|name| name == "chats")))
            || path.join("projects").is_dir()
            || path.join("chats").is_dir()
            || fs::read_dir(path).is_ok_and(|entries| {
                entries.flatten().any(|entry| {
                    Self::is_native_session_file(&entry.path())
                        || entry.path().join("chats").is_dir()
                })
            })
    }

    /// Discovery stays pre-parse so malformed source artifacts can be mirrored.
    fn session_files(root: &Path, include_legacy: bool) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if !root.exists() {
            return out;
        }

        for entry in WalkDir::new(root).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }

            let name = entry.file_name().to_str().unwrap_or("");
            if Self::is_native_session_file(entry.path())
                || (include_legacy
                    && name.starts_with("session-")
                    && entry
                        .path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("json")))
            {
                out.push(entry.path().to_path_buf());
            }
        }

        out.sort();
        out
    }

    fn source_roots(ctx: &ScanContext) -> Vec<QwenSourceRoot> {
        let mut roots = Vec::new();
        if ctx.use_default_detection() {
            // Exclusive scoping (house pattern): a data_dir that IS qwen
            // storage scopes the scan to it; only otherwise probe the
            // default runtime root. Scanning both leaked live-machine sessions
            // into scoped mirror ingests.
            if Self::looks_like_qwen_storage(&ctx.data_dir)
                || Self::looks_like_native_root(&ctx.data_dir)
            {
                Self::append_qwen_roots(&mut roots, &ScanRoot::local(ctx.data_dir.clone()));
            } else {
                let root = Self::default_root();
                if root.is_dir() {
                    roots.push(QwenSourceRoot {
                        root: ScanRoot::local(root),
                        include_legacy: true,
                    });
                }
            }
        } else {
            for scan_root in &ctx.scan_roots {
                Self::append_qwen_roots(&mut roots, scan_root);
            }
        }

        roots.sort_by(|a, b| a.root.path.cmp(&b.root.path));
        roots.dedup_by(|a, b| a.root.path == b.root.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        let mut seen_files: HashSet<PathBuf> = HashSet::new();
        for source_root in Self::source_roots(ctx) {
            let root = source_root.root;
            if !root.path.exists() {
                continue;
            }
            for session_path in Self::session_files(&root.path, source_root.include_legacy) {
                if !seen_files.insert(dedupe_path_key(&session_path)) {
                    continue;
                }
                if !file_modified_since(&session_path, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "qwen",
                        &root,
                        session_path.clone(),
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
                if session_path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
                    && let Some(project_dir) = session_path.parent().and_then(Path::parent)
                {
                    let config = project_dir.join("config.json");
                    if config.exists() {
                        out.push(
                            DiscoveredSourceFile::new(
                                "qwen",
                                &root,
                                config,
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

impl Connector for QwenConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("qwen").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        self.scan_with_callback(ctx, &mut |conversation| {
            convs.push(conversation);
            Ok(())
        })?;
        Ok(convs)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        let mut seen_files: HashSet<PathBuf> = HashSet::new();
        for source_root in Self::source_roots(ctx) {
            let root = source_root.root;
            if !root.path.exists() {
                continue;
            }

            for session_path in Self::session_files(&root.path, source_root.include_legacy) {
                if !seen_files.insert(dedupe_path_key(&session_path)) {
                    continue;
                }

                if !file_modified_since(&session_path, ctx.since_ts) {
                    continue;
                }

                match parse_qwen_session(&session_path) {
                    Ok(Some(conv)) => on_conversation(conv)?,
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(
                            path = %session_path.display(),
                            error = %e,
                            "qwen parse error"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

// Native JSONL semantics follow QwenLM/qwen-code at
// a238b91e7c6fc2b0e36e23436b0e4ced5296617b:
// services/chatRecordingService.ts and utils/transcript-records.ts. UUID
// duplicates are fragments, not replacement snapshots: append their parts,
// keep the first parent/model, and replace usage with the latest observation.
fn merge_qwen_fragments(base: &mut Value, mut fragment: Value) {
    if let Some(message) = fragment.get_mut("message") {
        if let Some(base_message) = base.get_mut("message").and_then(Value::as_object_mut) {
            if let Some(parts) = message.get_mut("parts").and_then(Value::as_array_mut) {
                let base_parts = base_message
                    .entry("parts")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Some(base_parts) = base_parts.as_array_mut() {
                    base_parts.append(parts);
                }
            }
        } else {
            base["message"] = message.take();
        }
    }
    for key in ["usageMetadata", "model", "toolCallResult"] {
        if let Some(value) = fragment.get(key)
            && (value.is_object() || key == "model" && value_is_nonempty_string(value))
        {
            // The latest usage is one logical reply's total, never a sum of
            // the intermediate fragment totals.
            if key == "usageMetadata"
                || base.get(key).is_none_or(Value::is_null)
                || key == "model" && !value_is_nonempty_string(&base[key])
            {
                base[key] = fragment[key].take();
            }
        }
    }
    if fragment["timestamp"].as_str() > base["timestamp"].as_str() {
        base["timestamp"] = fragment["timestamp"].take();
    }
}

fn value_is_nonempty_string(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.trim().is_empty())
}

fn is_qwen_record(record: &Value) -> bool {
    value_is_nonempty_string(&record["uuid"])
        && value_is_nonempty_string(&record["sessionId"])
        && record
            .get("parentUuid")
            .is_some_and(|parent| parent.is_null() || parent.is_string())
        && matches!(
            record["type"].as_str(),
            Some("user" | "assistant" | "tool_result" | "system")
        )
}

fn is_qwen_side_record(record: &Value) -> bool {
    record["type"] == "system"
        && matches!(
            record["subtype"].as_str(),
            Some(
                "session_artifact_event" | "session_artifact_snapshot" | "session_sources_snapshot"
            )
        )
}

#[derive(Default)]
struct QwenHistory {
    records: HashMap<String, Value>,
    leaf: Option<String>,
    session_id: Option<String>,
    workspace: Option<PathBuf>,
    started_at: Option<i64>,
    ended_at: Option<i64>,
    native_signature: bool,
}

fn read_qwen_jsonl(reader: impl BufRead) -> Result<QwenHistory> {
    let mut history = QwenHistory::default();
    for line in JsonlLines::new(reader) {
        let line = line?;
        let Ok(mut record) = serde_json::from_str::<Value>(line.trim_start_matches('\u{feff}'))
        else {
            continue;
        };
        if record["subtype"]
            .as_str()
            .is_some_and(|subtype| subtype.starts_with("managed_session_"))
            || (record["subtype"] == "session_execution_engine"
                && record
                    .pointer("/systemPayload/engine")
                    .and_then(Value::as_str)
                    == Some("managed"))
        {
            anyhow::bail!("qwen: managed session transcripts require a separate format adapter");
        }
        if !is_qwen_record(&record) {
            continue;
        }
        history.native_signature |= record
            .pointer("/message/parts")
            .is_some_and(Value::is_array)
            || QWEN_USAGE_KEYS.iter().any(|key| {
                record
                    .get("usageMetadata")
                    .and_then(|usage| usage.get(key))
                    .is_some_and(Value::is_number)
            });
        // A malformed body does not erase its parent link and disconnect
        // earlier valid messages. Native parts/usage evidence still gates the
        // entire source, so a renamed Claude or Gemini transcript is not Qwen.
        if record.get("message").is_some_and(|message| {
            !message.is_object() || !message.get("parts").is_some_and(Value::is_array)
        }) {
            record
                .as_object_mut()
                .expect("validated object")
                .remove("message");
        }
        let id = record["sessionId"].as_str().expect("validated session ID");
        if history
            .session_id
            .as_deref()
            .is_some_and(|expected| expected != id)
        {
            anyhow::bail!("qwen: transcript contains mixed session IDs");
        }
        if history.session_id.is_none() {
            history.session_id = Some(id.to_string());
            history.workspace = record["cwd"]
                .as_str()
                .filter(|cwd| !cwd.is_empty())
                .map(PathBuf::from);
        }
        if let Some(timestamp) = record.get("timestamp").and_then(parse_timestamp) {
            history.started_at = Some(
                history
                    .started_at
                    .map_or(timestamp, |start: i64| start.min(timestamp)),
            );
            history.ended_at = Some(
                history
                    .ended_at
                    .map_or(timestamp, |end: i64| end.max(timestamp)),
            );
        } else if let Some(object) = record.as_object_mut() {
            object.remove("timestamp");
        }
        if is_qwen_side_record(&record) {
            continue;
        }
        if record["type"] == "system" && record["subtype"] != "custom_title" {
            // System history.records carry parent links but can also embed full file
            // snapshots or compressed histories. Their payload is not needed
            // to reconstruct the visible conversation.
            if let Some(object) = record.as_object_mut() {
                object.remove("systemPayload");
                object.remove("message");
            }
        }
        let uuid = record["uuid"]
            .as_str()
            .expect("validated message UUID")
            .to_string();
        history.leaf = Some(uuid.clone());
        if let Some(base) = history.records.get_mut(&uuid) {
            merge_qwen_fragments(base, record);
        } else {
            history.records.insert(uuid, record);
        }
    }
    Ok(history)
}

fn parse_qwen_jsonl(
    reader: impl BufRead,
    path: &Path,
    compact: bool,
) -> Result<Option<NormalizedConversation>> {
    let QwenHistory {
        mut records,
        leaf,
        session_id,
        workspace,
        started_at,
        ended_at,
        native_signature,
    } = read_qwen_jsonl(reader)?;
    if !native_signature {
        return Ok(None);
    }

    // Remove each payload while walking backwards. This both bounds cycle
    // handling and avoids a second full collection of raw record clones.
    let mut chain = Vec::<Value>::new();
    let mut cursor = leaf.clone();
    let mut missing_parent = None;
    let mut cycle_uuid = None;
    while let Some(uuid) = cursor {
        let Some(record) = records.remove(&uuid) else {
            if chain.iter().any(|record| record["uuid"] == uuid) {
                cycle_uuid = Some(uuid);
            } else {
                missing_parent = Some(uuid);
            }
            break;
        };
        cursor = record["parentUuid"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(String::from);
        chain.push(record);
    }
    drop(records);
    chain.reverse();
    let title = chain.iter().rev().find_map(|record| {
        (record["type"] == "system" && record["subtype"] == "custom_title")
            .then(|| {
                record
                    .pointer("/systemPayload/customTitle")
                    .and_then(Value::as_str)
            })
            .flatten()
            .filter(|title| !title.trim().is_empty())
            .map(String::from)
    });
    let mut messages: Vec<_> = chain
        .into_iter()
        .filter_map(|record| normalize_qwen_record(record, compact))
        .collect();
    if messages.is_empty() {
        return Ok(None);
    }
    crate::types::reindex_messages(&mut messages);
    let title = title.or_else(|| {
        messages
            .iter()
            .find(|message| message.role == "user")
            .map(|message| {
                message
                    .content
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .chars()
                    .take(100)
                    .collect()
            })
    });
    let mut metadata = serde_json::json!({
        "source": "qwen", "format": "jsonl", "sessionId": session_id,
        "active_leaf_uuid": leaf,
    });
    if let Some(parent) = missing_parent {
        metadata["history_gap_parent_uuid"] = Value::String(parent);
    }
    if let Some(uuid) = cycle_uuid {
        metadata["history_cycle_uuid"] = Value::String(uuid);
    }
    Ok(Some(NormalizedConversation {
        agent_slug: "qwen".into(),
        external_id: session_id,
        title,
        workspace,
        source_path: path.to_path_buf(),
        started_at,
        ended_at,
        metadata,
        messages,
    }))
}

fn push_qwen_text(content: &mut String, text: &str) {
    if !text.is_empty() {
        if !content.is_empty() {
            content.push('\n');
        }
        content.push_str(text);
    }
}

fn qwen_user_display(record: &Value) -> (Option<&str>, &[Value]) {
    const OPEN: &str = "<qwen:user-prompt-submit-context>";
    const CLOSE: &str = "</qwen:user-prompt-submit-context>";
    let mut parts = record
        .pointer("/message/parts")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let has_final_hook = parts.len() > 1
        && parts
            .last()
            .and_then(|part| part["text"].as_str())
            .is_some_and(|text| {
                text.trim()
                    .strip_prefix(OPEN)
                    .and_then(|text| text.strip_prefix('\n'))
                    .and_then(|text| text.strip_suffix(CLOSE))
                    .and_then(|text| text.strip_suffix('\n'))
                    .is_some_and(|body| !body.contains(OPEN) && !body.contains(CLOSE))
            });
    let payload = record.get("systemPayload").and_then(Value::as_object);
    let display_text = payload.and_then(|payload| {
        (payload.get("hookContext").is_some_and(Value::is_string) || has_final_hook)
            .then(|| payload.get("displayText").and_then(Value::as_str))
            .flatten()
    });
    if display_text.is_none() && payload.is_none() && has_final_hook {
        parts = &parts[..parts.len() - 1];
    }
    (display_text, parts)
}

fn normalize_qwen_record(record: Value, compact: bool) -> Option<NormalizedMessage> {
    let role = match record["type"].as_str()? {
        "user" => "user",
        "assistant" => "assistant",
        "tool_result" => "tool",
        _ => return None,
    };
    let mut content = String::new();
    let mut invocations = Vec::new();
    let mut author = None;
    let (display_text, parts) = if role == "user" {
        qwen_user_display(&record)
    } else {
        (
            None,
            record
                .pointer("/message/parts")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice),
        )
    };
    if let Some(text) = display_text {
        push_qwen_text(&mut content, text);
    }
    {
        for part in parts {
            if display_text.is_none()
                && let Some(text) = part["text"].as_str()
            {
                if part["thought"] == true {
                    push_qwen_text(&mut content, &format!("[Thinking] {text}"));
                } else {
                    push_qwen_text(&mut content, text);
                }
            }
            if let Some(call) = part.get("functionCall")
                && let Some(name) = call["name"].as_str().filter(|name| !name.trim().is_empty())
            {
                push_qwen_text(&mut content, &format!("[Tool: {name}]"));
                invocations.push(NormalizedInvocation {
                    kind: "tool".into(),
                    name: name.to_string(),
                    raw_name: None,
                    call_id: call["id"].as_str().map(String::from),
                    arguments: call.get("args").cloned(),
                });
            }
            if let Some(result) = part.get("functionResponse")
                && let Some(name) = result["name"]
                    .as_str()
                    .filter(|name| !name.trim().is_empty())
            {
                author.get_or_insert_with(|| name.to_string());
                push_qwen_text(&mut content, &format!("[Tool Result: {name}]"));
                if let Some(text) = result.pointer("/response/output").and_then(Value::as_str) {
                    push_qwen_text(&mut content, text);
                }
                if let Some(error) = result.pointer("/response/error").and_then(Value::as_str) {
                    push_qwen_text(&mut content, &format!("[Error] {error}"));
                }
            }
        }
    }
    if content.trim().is_empty() && record.get("usageMetadata").is_none() {
        return None;
    }
    let created_at = record.get("timestamp").and_then(parse_timestamp);
    let extra = if compact {
        compact_qwen_record(&record, invocations.len())
    } else {
        record
    };
    Some(NormalizedMessage {
        idx: 0,
        role: role.into(),
        author,
        content,
        created_at,
        extra,
        invocations,
        snippets: Vec::new(),
    })
}

fn compact_qwen_record(record: &Value, tool_call_count: usize) -> Value {
    let mut cass = serde_json::Map::new();
    for (native, compact) in [
        ("uuid", "message_id"),
        ("parentUuid", "parent_uuid"),
        ("sessionId", "session_id"),
        ("model", "model"),
        ("subtype", "subtype"),
        ("agentId", "agent_id"),
        ("agentName", "agent_name"),
    ] {
        if let Some(value) = record.get(native).filter(|value| value.is_string()) {
            cass.insert(compact.into(), value.clone());
        }
    }
    if let Some(value) = record.get("isSidechain").filter(|value| value.is_boolean()) {
        cass.insert("is_sidechain".into(), value.clone());
    }
    let mut usage = serde_json::Map::new();
    for key in QWEN_USAGE_KEYS {
        if let Some(value) = record.get("usageMetadata").and_then(|usage| usage.get(key)) {
            if value.as_i64().is_some() {
                usage.insert(key.into(), value.clone());
            } else if key == "toolUsePromptTokenCount" {
                // Missing tool usage means zero when reconciling a complete
                // total; present-but-invalid usage makes that inference
                // unsafe. Retain its presence without cloning the payload.
                usage.insert(key.into(), Value::Null);
            }
        }
    }
    if !usage.is_empty() {
        cass.insert("usage".into(), Value::Object(usage));
    }
    cass.insert("tool_call_count".into(), tool_call_count.into());
    serde_json::json!({ "cass": cass })
}

/// Parse a Qwen session file into a `NormalizedConversation`.
fn parse_qwen_session(path: &Path) -> Result<Option<NormalizedConversation>> {
    if path
        .extension()
        .is_some_and(|extension| extension == "jsonl")
    {
        let file = fs::File::open(path)?;
        let compact = file.metadata()?.len() >= LARGE_SESSION_EXTRA_COMPACT_THRESHOLD_BYTES;
        return parse_qwen_jsonl(BufReader::new(file), path, compact);
    }
    // Whole-session JSON loads into a full DOM; enforce the project's
    // 100MB scan cap (chatgpt policy).
    let content = match read_capped(path) {
        Ok(Some(content)) => content,
        Ok(None) => {
            tracing::warn!(
                path = %path.display(),
                "qwen: session exceeds the scan size cap; skipping"
            );
            return Ok(None);
        }
        Err(e) => {
            return Err(
                anyhow::Error::new(e).context(format!("read qwen session {}", path.display()))
            );
        }
    };

    let val: Value = serde_json::from_str(&content)
        .with_context(|| format!("parse qwen session JSON {}", path.display()))?;

    let session_id = val
        .get("sessionId")
        .and_then(|v| v.as_str())
        .map(String::from);
    let project_hash = val
        .get("projectHash")
        .and_then(|v| v.as_str())
        .map(String::from);

    let started_at = val.get("startTime").and_then(parse_timestamp);
    let ended_at = val.get("lastUpdated").and_then(parse_timestamp);

    let Some(raw_messages) = val.get("messages").and_then(|v| v.as_array()) else {
        return Ok(None);
    };

    let mut messages = Vec::new();

    for raw_msg in raw_messages {
        let msg_type = raw_msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Normalize role: "qwen" -> "assistant", "user" -> "user"
        let role = match msg_type {
            "user" => "user".to_string(),
            "qwen" | "assistant" => "assistant".to_string(),
            _other => {
                // Unknown types normalized to assistant for forward compatibility
                "assistant".to_string()
            }
        };

        // Extract content (string or array)
        let content_val = raw_msg.get("content");
        let content_str = content_val.map(flatten_content).unwrap_or_default();

        if content_str.trim().is_empty() {
            continue;
        }

        let created = raw_msg.get("timestamp").and_then(parse_timestamp);

        messages.push(NormalizedMessage {
            idx: 0,
            role,
            author: None,
            created_at: created,
            content: content_str,
            extra: raw_msg.clone(),
            invocations: Vec::new(),
            snippets: Vec::new(),
        });
    }

    crate::types::reindex_messages(&mut messages);

    if messages.is_empty() {
        return Ok(None);
    }

    // Try to infer workspace from the directory structure
    // Pattern: ~/.qwen/tmp/<project-hash>/chats/session-*.json
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

    let metadata = serde_json::json!({
        "source": "qwen",
        "sessionId": session_id.as_deref(),
        "projectHash": project_hash.as_deref(),
    });

    Ok(Some(NormalizedConversation {
        agent_slug: "qwen".into(),
        external_id: session_id,
        title,
        workspace,
        source_path: path.to_path_buf(),
        started_at,
        ended_at,
        metadata,
        messages,
    }))
}

/// Try to infer workspace from the session path or nearby files.
/// Path pattern: `~/.qwen/tmp/<project-hash>/chats/session-*.json`
fn infer_workspace(path: &Path) -> Option<PathBuf> {
    // Go up to the project-hash directory (parent of "chats")
    let chats_dir = path.parent()?;
    let project_dir = chats_dir.parent()?;

    // Check for a config/workspace file in the project directory
    let config_path = project_dir.join("config.json");
    if let Ok(content) = fs::read_to_string(&config_path) {
        if let Ok(val) = serde_json::from_str::<Value>(&content) {
            for key in &["workspace", "projectPath", "cwd", "path"] {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn native_reader_discards_valid_prefix_on_underlying_io_failure() {
        use std::io::{self, Cursor, ErrorKind, Read};

        struct FailingReader {
            prefix: Cursor<Vec<u8>>,
            kind: ErrorKind,
        }

        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                unreachable!("JSONL reads use BufRead directly")
            }
        }

        impl BufRead for FailingReader {
            fn fill_buf(&mut self) -> io::Result<&[u8]> {
                if usize::try_from(self.prefix.position()).unwrap() < self.prefix.get_ref().len() {
                    self.prefix.fill_buf()
                } else {
                    Err(io::Error::new(self.kind, "native source read failed"))
                }
            }

            fn consume(&mut self, amount: usize) {
                self.prefix.consume(amount);
            }
        }

        let record = serde_json::json!({
            "uuid": "user", "parentUuid": null, "sessionId": "session",
            "type": "user", "message": { "role": "user", "parts": [{ "text": "Complete prefix" }] },
        });
        for kind in [
            ErrorKind::Other,
            ErrorKind::InvalidData,
            ErrorKind::Interrupted,
        ] {
            let result = parse_qwen_jsonl(
                FailingReader {
                    prefix: Cursor::new(format!("{record}\n").into_bytes()),
                    kind,
                },
                Path::new("/fixture/chats/session.jsonl"),
                false,
            );
            let error = result.unwrap_err();
            let io_error = error.downcast_ref::<io::Error>().unwrap();
            assert_eq!(io_error.kind(), kind);
            assert_eq!(io_error.to_string(), "native source read failed");
        }
    }

    // =========================================================================
    // Constructor tests
    // =========================================================================

    #[test]
    fn new_creates_connector() {
        let connector = QwenConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = QwenConnector;
        let _ = connector;
    }

    // =========================================================================
    // Helper to create Qwen storage layout
    // =========================================================================

    fn create_qwen_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join(".qwen").join("tmp");
        fs::create_dir_all(&storage).unwrap();
        storage
    }

    fn write_session_file(storage: &Path, project_hash: &str, filename: &str, content: &str) {
        let chats_dir = storage.join(project_hash).join("chats");
        fs::create_dir_all(&chats_dir).unwrap();
        let file_path = chats_dir.join(filename);
        fs::write(&file_path, content).unwrap();
    }

    // =========================================================================
    // Detection tests
    // =========================================================================

    #[test]
    fn detect_not_found_without_tmp_dir() {
        let connector = QwenConnector::new();
        let result = connector.detect();
        let _ = result.detected;
    }

    // =========================================================================
    // JSON parsing tests
    // =========================================================================

    #[test]
    fn scan_parses_basic_session() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "50ba1660-9b88-4500-8f25-dab05f90d790",
            "projectHash": "abc123",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "Hello Qwen"
                },
                {
                    "id": "msg-002",
                    "timestamp": "2025-11-08T23:19:13.706Z",
                    "type": "qwen",
                    "content": "Hello! How can I help?"
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "abc123",
            "session-1731107950138-50ba1660.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "qwen");
        assert_eq!(
            convs[0].external_id,
            Some("50ba1660-9b88-4500-8f25-dab05f90d790".to_string())
        );
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Qwen");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert!(convs[0].messages[1].content.contains("How can I help"));
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_with_explicit_roots_scans_all_roots() {
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let storage_a = create_qwen_storage(&dir_a);
        let storage_b = create_qwen_storage(&dir_b);

        let session_a = r#"{
            "sessionId": "sess-a",
            "projectHash": "hash-a",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                { "id": "msg-a", "timestamp": "2025-11-08T23:19:10.138Z", "type": "user", "content": "Hi A" }
            ]
        }"#;
        let session_b = r#"{
            "sessionId": "sess-b",
            "projectHash": "hash-b",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                { "id": "msg-b", "timestamp": "2025-11-08T23:19:10.138Z", "type": "user", "content": "Hi B" }
            ]
        }"#;

        write_session_file(&storage_a, "hash-a", "session-a.json", session_a);
        write_session_file(&storage_b, "hash-b", "session-b.json", session_b);

        let connector = QwenConnector::new();
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
    fn scan_with_explicit_root_at_qwen_dir() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-001",
            "projectHash": "hash-001",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                { "id": "msg-001", "timestamp": "2025-11-08T23:19:10.138Z", "type": "user", "content": "Hello Qwen" }
            ]
        }"#;
        write_session_file(&storage, "hash-001", "session-001.json", session_json);

        let qwen_dir = dir.path().join(".qwen");

        let connector = QwenConnector::new();
        let ctx = ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(qwen_dir)], None);

        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id, Some("sess-001".to_string()));
    }

    #[test]
    fn scan_extracts_metadata() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-meta",
            "projectHash": "proj-hash-001",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "Test"
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj-hash-001",
            "session-1731107950138-meta.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["sessionId"], "sess-meta");
        assert_eq!(convs[0].metadata["projectHash"], "proj-hash-001");
        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
    }

    #[test]
    fn scan_generates_title_from_first_user_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-title",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "Explain the architecture of this codebase"
                },
                {
                    "id": "msg-002",
                    "timestamp": "2025-11-08T23:19:13.706Z",
                    "type": "qwen",
                    "content": "Sure, let me walk through it."
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-title.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].title,
            Some("Explain the architecture of this codebase".to_string())
        );
    }

    #[test]
    fn scan_reads_workspace_from_config() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        // Create session
        let session_json = r#"{
            "sessionId": "sess-ws",
            "projectHash": "proj-ws",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "hello"
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj-ws",
            "session-1731107950138-ws.json",
            session_json,
        );

        // Create config.json in project directory
        let project_dir = storage.join("proj-ws");
        fs::write(
            project_dir.join("config.json"),
            r#"{"workspace": "/home/user/my-project"}"#,
        )
        .unwrap();

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/my-project"))
        );
    }

    #[test]
    fn scan_multiple_sessions() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        for i in 1..=3 {
            let session_json = format!(
                r#"{{
                "sessionId": "sess-{i}",
                "projectHash": "proj1",
                "startTime": "2025-11-0{i}T10:00:00.000Z",
                "lastUpdated": "2025-11-0{i}T10:01:00.000Z",
                "messages": [
                    {{
                        "id": "msg-{i}",
                        "timestamp": "2025-11-0{i}T10:00:00.000Z",
                        "type": "user",
                        "content": "Message {i}"
                    }}
                ]
            }}"#
            );
            write_session_file(
                &storage,
                "proj1",
                &format!("session-17311079{i}0000-{i}.json"),
                &session_json,
            );
        }

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 3);
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn edge_empty_messages_returns_none() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-empty",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": []
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-empty.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs.is_empty());
    }

    #[test]
    fn edge_missing_messages_field() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-no-messages",
            "projectHash": "proj1"
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-nomsg.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs.is_empty());
    }

    #[test]
    fn edge_empty_content_messages_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-empty-content",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "Has content"
                },
                {
                    "id": "msg-002",
                    "timestamp": "2025-11-08T23:19:11.000Z",
                    "type": "qwen",
                    "content": ""
                },
                {
                    "id": "msg-003",
                    "timestamp": "2025-11-08T23:19:12.000Z",
                    "type": "qwen",
                    "content": "   "
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-emptyc.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Has content");
    }

    #[test]
    fn edge_malformed_json_returns_error_gracefully() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let chats_dir = storage.join("proj1").join("chats");
        fs::create_dir_all(&chats_dir).unwrap();
        fs::write(
            chats_dir.join("session-1731107950138-bad.json"),
            "not valid json {{{",
        )
        .unwrap();

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        // Should not propagate error, just skip
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn edge_array_content_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-arr",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "qwen",
                    "content": [{"type": "text", "text": "Part A"}, {"type": "text", "text": "Part B"}]
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-arr.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("Part A"));
        assert!(convs[0].messages[0].content.contains("Part B"));
    }

    #[test]
    fn unknown_message_types_normalized_to_assistant() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        let session_json = r#"{
            "sessionId": "sess-unknown-types",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "system",
                    "content": "System prompt text"
                },
                {
                    "id": "msg-002",
                    "timestamp": "2025-11-08T23:19:11.000Z",
                    "type": "metadata",
                    "content": "Some metadata"
                },
                {
                    "id": "msg-003",
                    "timestamp": "2025-11-08T23:19:12.000Z",
                    "type": "user",
                    "content": "Normal user msg"
                },
                {
                    "id": "msg-004",
                    "timestamp": "2025-11-08T23:19:13.000Z",
                    "type": "qwen",
                    "content": "Normal qwen msg"
                }
            ]
        }"#;
        write_session_file(
            &storage,
            "proj1",
            "session-1731107950138-unknown.json",
            session_json,
        );

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 4);
        // "system" and "metadata" should both be normalized to "assistant"
        assert_eq!(convs[0].messages[0].role, "assistant");
        assert_eq!(convs[0].messages[1].role, "assistant");
        // Standard types preserved
        assert_eq!(convs[0].messages[2].role, "user");
        assert_eq!(convs[0].messages[3].role, "assistant");
    }

    #[test]
    fn edge_non_session_json_files_ignored() {
        let dir = TempDir::new().unwrap();
        let storage = create_qwen_storage(&dir);

        // Write a non-session JSON file
        let chats_dir = storage.join("proj1").join("chats");
        fs::create_dir_all(&chats_dir).unwrap();
        fs::write(chats_dir.join("config.json"), r#"{"setting": "value"}"#).unwrap();

        // Write a valid session file
        let session_json = r#"{
            "sessionId": "sess-valid",
            "projectHash": "proj1",
            "startTime": "2025-11-08T23:19:10.138Z",
            "lastUpdated": "2025-11-08T23:19:13.706Z",
            "messages": [
                {
                    "id": "msg-001",
                    "timestamp": "2025-11-08T23:19:10.138Z",
                    "type": "user",
                    "content": "Valid message"
                }
            ]
        }"#;
        fs::write(
            chats_dir.join("session-1731107950138-valid.json"),
            session_json,
        )
        .unwrap();

        let connector = QwenConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
    }
}
