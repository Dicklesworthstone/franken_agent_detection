//! Hermes Agent connector for SQLite session storage.
//!
//! [Hermes Agent](https://github.com/NousResearch/hermes-agent) is a
//! multi-platform coding agent (CLI, Telegram, Discord, Slack, WhatsApp,
//! Signal, Matrix, etc.) that stores sessions in SQLite.
//!
//! Database location: `$HERMES_HOME/state.db` (defaults to `~/.hermes/state.db`).
//!
//! Schema:
//!   `sessions`:  id (TEXT PK), source, model, title, parent_session_id,
//!                started_at (REAL), ended_at (REAL), end_reason,
//!                message_count, tool_call_count, input_tokens, output_tokens
//!   `messages`:  session_id (FK), role, content, tool_calls (JSON),
//!                tool_name, tool_call_id, reasoning, timestamp (REAL)

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::Connection;

use super::scan::ScanContext;
use super::{Connector, franken_detection_for_connector};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
};

pub struct HermesConnector;

impl Default for HermesConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl HermesConnector {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Locate the Hermes SQLite database.
    ///
    /// Resolution order:
    /// 1. `HERMES_SQLITE_DB` env — explicit path to the database file
    /// 2. `HERMES_HOME` env — `$HERMES_HOME/state.db`
    /// 3. Default: `~/.hermes/state.db`
    fn sqlite_db_path() -> Option<PathBuf> {
        if let Ok(path) = dotenvy::var("HERMES_SQLITE_DB") {
            let p = PathBuf::from(path);
            if p.exists() {
                return Some(p);
            }
        }

        if let Ok(home) = dotenvy::var("HERMES_HOME") {
            let home = home.trim().to_string();
            if !home.is_empty() {
                let db = PathBuf::from(&home).join("state.db");
                if db.exists() {
                    return Some(db);
                }
            }
        }

        if let Some(home) = dirs::home_dir() {
            let db = home.join(".hermes").join("state.db");
            if db.exists() {
                return Some(db);
            }
        }

        None
    }

    /// Extract sessions from the Hermes SQLite database.
    fn extract_from_sqlite(
        db_path: &Path,
        since_ts: Option<i64>,
    ) -> Result<Vec<NormalizedConversation>> {
        let conn = Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("failed to open Hermes db: {}", db_path.display()))?;

        conn.busy_timeout(std::time::Duration::from_secs(5))?;

        let mut sessions: Vec<HermesSession> = Vec::new();
        let mut stmt = conn
            .prepare(
                "SELECT id, source, model, title, parent_session_id, \
                        started_at, ended_at, end_reason, \
                        message_count, tool_call_count, input_tokens, output_tokens \
                 FROM sessions",
            )
            .with_context(|| "failed to prepare Hermes sessions query")?;

        let rows = stmt.query_map([], |row| {
            Ok(HermesSession {
                id: row.get(0)?,
                source: row.get(1)?,
                model: row.get(2)?,
                title: row.get(3)?,
                parent_session_id: row.get(4)?,
                started_at: row.get::<_, Option<f64>>(5)?,
                ended_at: row.get::<_, Option<f64>>(6)?,
                end_reason: row.get(7)?,
                message_count: row.get(8)?,
                tool_call_count: row.get(9)?,
                input_tokens: row.get(10)?,
                output_tokens: row.get(11)?,
            })
        })?;

        for row in rows {
            match row {
                Ok(s) => sessions.push(s),
                Err(e) => {
                    tracing::debug!("hermes sqlite: failed to read session row: {e}");
                }
            }
        }

        let mut convs = Vec::new();
        let mut seen_ids = HashSet::new();

        for session in sessions {
            if !seen_ids.insert(session.id.clone()) {
                continue;
            }

            let started_ms = session.started_at.and_then(real_to_millis);
            let ended_ms = session.ended_at.and_then(real_to_millis);

            if let Some(since) = since_ts {
                let latest = ended_ms.or(started_ms).unwrap_or(0);
                if latest < since {
                    continue;
                }
            }

            let messages = Self::load_messages(&conn, &session.id)?;
            if messages.is_empty() {
                continue;
            }

            let msg_started = messages.iter().filter_map(|m| m.created_at).min();
            let msg_ended = messages.iter().filter_map(|m| m.created_at).max();

            let started_at = started_ms.or(msg_started);
            let ended_at = ended_ms.or(msg_ended).or(started_at);

            // Infer workspace from tool calls (terminal workdir, file paths)
            let workspace = Self::infer_workspace(&messages);

            let title = session.title.or_else(|| {
                messages
                    .first()
                    .filter(|m| m.role == "user")
                    .and_then(|m| m.content.lines().next())
                    .map(|s| s.chars().take(100).collect())
            });

            convs.push(NormalizedConversation {
                agent_slug: "hermes".into(),
                external_id: Some(session.id.clone()),
                title,
                workspace,
                source_path: db_path.join(urlencoding::encode(&session.id).as_ref()),
                started_at,
                ended_at,
                metadata: serde_json::json!({
                    "session_id": session.id,
                    "source": session.source,
                    "model": session.model,
                    "parent_session_id": session.parent_session_id,
                    "end_reason": session.end_reason,
                    "message_count": session.message_count,
                    "tool_call_count": session.tool_call_count,
                    "input_tokens": session.input_tokens,
                    "output_tokens": session.output_tokens,
                }),
                messages,
            });
        }

        Ok(convs)
    }

    /// Load and normalize messages for a session.
    fn load_messages(conn: &Connection, session_id: &str) -> Result<Vec<NormalizedMessage>> {
        let mut stmt = conn.prepare(
            "SELECT role, content, tool_calls, tool_name, tool_call_id, reasoning, timestamp \
             FROM messages WHERE session_id = ? ORDER BY timestamp ASC",
        )?;

        let rows = stmt.query_map([session_id], |row| {
            Ok(HermesMessage {
                role: row.get(0)?,
                content: row.get(1)?,
                tool_calls: row.get(2)?,
                tool_name: row.get(3)?,
                tool_call_id: row.get(4)?,
                reasoning: row.get(5)?,
                timestamp: row.get::<_, Option<f64>>(6)?,
            })
        })?;

        let mut messages = Vec::new();

        for row in rows {
            let row = match row {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!("hermes sqlite: failed to read message row: {e}");
                    continue;
                }
            };

            let role = row.role.unwrap_or_else(|| "assistant".to_string());

            // Skip session_meta records — they contain metadata, not conversation content
            if role == "session_meta" {
                continue;
            }

            let content = row.content.unwrap_or_default();
            let reasoning = row.reasoning.unwrap_or_default();

            // Combine content and reasoning if both present
            let full_content = if reasoning.is_empty() {
                content.clone()
            } else if content.is_empty() {
                reasoning.clone()
            } else {
                format!("{content}\n\n[reasoning]\n{reasoning}")
            };

            if full_content.trim().is_empty() && row.tool_calls.is_none() {
                continue;
            }

            let created_at = row.timestamp.and_then(real_to_millis);
            let invocations = parse_tool_calls(row.tool_calls.as_deref());

            let author = if role == "assistant" {
                None // model info is at session level, not message level
            } else if role == "tool" {
                row.tool_name.clone()
            } else {
                Some(role.clone())
            };

            let mut extra = serde_json::json!({});
            if let Some(ref name) = row.tool_name {
                extra["tool_name"] = serde_json::json!(name);
            }
            if let Some(ref call_id) = row.tool_call_id {
                extra["tool_call_id"] = serde_json::json!(call_id);
            }
            if !reasoning.is_empty() {
                extra["has_reasoning"] = serde_json::json!(true);
            }

            messages.push(NormalizedMessage {
                idx: 0,
                role,
                author,
                created_at,
                content: full_content,
                extra,
                invocations,
                snippets: Vec::new(),
            });
        }

        crate::types::reindex_messages(&mut messages);
        Ok(messages)
    }

    /// Infer workspace directory from tool call content.
    ///
    /// Hermes doesn't store workspace explicitly. We look for:
    /// - `terminal` tool calls with `workdir` parameter
    /// - `read_file` / `write_file` / `patch` tool calls with file paths
    fn infer_workspace(messages: &[NormalizedMessage]) -> Option<PathBuf> {
        for msg in messages {
            for inv in &msg.invocations {
                if let Some(args) = &inv.arguments {
                    // terminal tool: look for workdir
                    if inv.name == "terminal" {
                        if let Some(wd) = args.get("workdir").and_then(|v| v.as_str()) {
                            return Some(PathBuf::from(wd));
                        }
                    }
                    // file tools: extract directory from file path
                    if matches!(inv.name.as_str(), "read_file" | "write_file" | "patch") {
                        if let Some(path) = args
                            .get("path")
                            .or_else(|| args.get("file_path"))
                            .and_then(|v| v.as_str())
                        {
                            let p = Path::new(path);
                            if p.is_absolute() {
                                return p.parent().map(Path::to_path_buf);
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

impl Connector for HermesConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("hermes").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let db_path =
            if ctx.data_dir.exists() && ctx.data_dir.extension().is_some_and(|ext| ext == "db") {
                Some(ctx.data_dir.clone())
            } else if ctx.use_default_detection() {
                Self::sqlite_db_path()
            } else {
                let candidate = ctx.data_dir.join("state.db");
                if candidate.exists() {
                    Some(candidate)
                } else {
                    None
                }
            };

        match db_path {
            Some(db) => {
                match Self::extract_from_sqlite(&db, ctx.since_ts) {
                    Ok(convs) => {
                        tracing::debug!(
                            "hermes sqlite: found {} sessions in {}",
                            convs.len(),
                            db.display()
                        );
                        Ok(convs)
                    }
                    Err(e) => {
                        tracing::debug!("hermes sqlite: failed to read {}: {e}", db.display());
                        Ok(Vec::new())
                    }
                }
            }
            None => Ok(Vec::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Private types
// ---------------------------------------------------------------------------

struct HermesSession {
    id: String,
    source: Option<String>,
    model: Option<String>,
    title: Option<String>,
    parent_session_id: Option<String>,
    started_at: Option<f64>,
    ended_at: Option<f64>,
    end_reason: Option<String>,
    message_count: Option<i64>,
    tool_call_count: Option<i64>,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
}

struct HermesMessage {
    role: Option<String>,
    content: Option<String>,
    tool_calls: Option<String>,
    tool_name: Option<String>,
    tool_call_id: Option<String>,
    reasoning: Option<String>,
    timestamp: Option<f64>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a REAL unix timestamp (seconds, possibly fractional) to milliseconds.
fn real_to_millis(val: f64) -> Option<i64> {
    if val.is_nan() || val.is_infinite() || val <= 0.0 {
        return None;
    }
    // Hermes timestamps are REAL unix seconds (e.g. 1700000000.123)
    if (1_000_000_000.0..10_000_000_000.0).contains(&val) {
        Some((val * 1000.0) as i64)
    } else if val >= 10_000_000_000.0 {
        // Already milliseconds
        Some(val as i64)
    } else {
        None
    }
}

/// Parse the `tool_calls` JSON column into normalized invocations.
///
/// Hermes stores tool calls as a JSON array of `{name, arguments}` objects.
fn parse_tool_calls(json_str: Option<&str>) -> Vec<NormalizedInvocation> {
    let Some(json_str) = json_str else {
        return Vec::new();
    };
    let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) else {
        return Vec::new();
    };

    arr.into_iter()
        .filter_map(|obj| {
            let name = obj.get("name")?.as_str()?.to_string();
            let arguments = obj.get("arguments").cloned();
            Some(NormalizedInvocation {
                kind: "tool".into(),
                name,
                raw_name: None,
                call_id: obj.get("id").and_then(|v| v.as_str()).map(String::from),
                arguments,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_to_millis_converts_epoch_seconds() {
        assert_eq!(real_to_millis(1_700_000_000.0), Some(1_700_000_000_000));
        assert_eq!(real_to_millis(1_700_000_000.123), Some(1_700_000_000_123));
    }

    #[test]
    fn real_to_millis_passes_through_epoch_millis() {
        assert_eq!(
            real_to_millis(1_700_000_000_000.0),
            Some(1_700_000_000_000)
        );
    }

    #[test]
    fn real_to_millis_rejects_invalid() {
        assert_eq!(real_to_millis(f64::NAN), None);
        assert_eq!(real_to_millis(f64::INFINITY), None);
        assert_eq!(real_to_millis(0.0), None);
        assert_eq!(real_to_millis(-1.0), None);
    }

    #[test]
    fn parse_tool_calls_extracts_invocations() {
        let json = r#"[{"name":"terminal","arguments":{"command":"ls","workdir":"/tmp"}},{"name":"read_file","arguments":{"path":"/etc/hosts"}}]"#;
        let invocations = parse_tool_calls(Some(json));
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[0].name, "terminal");
        assert_eq!(invocations[1].name, "read_file");
    }

    #[test]
    fn parse_tool_calls_handles_empty_and_null() {
        assert!(parse_tool_calls(None).is_empty());
        assert!(parse_tool_calls(Some("[]")).is_empty());
        assert!(parse_tool_calls(Some("not json")).is_empty());
    }

    #[test]
    fn infer_workspace_from_terminal_workdir() {
        let messages = vec![NormalizedMessage {
            idx: 0,
            role: "assistant".into(),
            author: None,
            created_at: None,
            content: String::new(),
            extra: serde_json::json!({}),
            snippets: Vec::new(),
            invocations: vec![NormalizedInvocation {
                kind: "tool".into(),
                name: "terminal".into(),
                raw_name: None,
                call_id: None,
                arguments: Some(serde_json::json!({"command": "ls", "workdir": "/home/user/project"})),
            }],
        }];
        assert_eq!(
            HermesConnector::infer_workspace(&messages),
            Some(PathBuf::from("/home/user/project"))
        );
    }

    #[test]
    fn infer_workspace_from_file_path() {
        let messages = vec![NormalizedMessage {
            idx: 0,
            role: "assistant".into(),
            author: None,
            created_at: None,
            content: String::new(),
            extra: serde_json::json!({}),
            snippets: Vec::new(),
            invocations: vec![NormalizedInvocation {
                kind: "tool".into(),
                name: "write_file".into(),
                raw_name: None,
                call_id: None,
                arguments: Some(serde_json::json!({"path": "/home/user/project/src/main.rs"})),
            }],
        }];
        assert_eq!(
            HermesConnector::infer_workspace(&messages),
            Some(PathBuf::from("/home/user/project/src"))
        );
    }
}
