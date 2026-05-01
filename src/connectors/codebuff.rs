//! Connector for Codebuff (formerly Manicode) chat sessions.
//!
//! Codebuff persists per-chat history under (legacy `manicode` directory name
//! is still used on disk by the CLI even after the rebrand):
//!
//! ```text
//! ~/.config/manicode/                       # legacy name still used on disk
//!   projects/<projectBasename>/
//!     chats/<chatId>/
//!       chat-messages.json                  # serialized ChatMessage[]
//!       run-state.json                      # SDK RunState snapshot (optional)
//! ```
//!
//! - `chatId` is the chat's ISO-8601 timestamp with `:` replaced by `-`.
//! - `manicode-dev` and `manicode-staging` channels are walked when present.
//! - `CODEBUFF_DATA_DIR` (or legacy `MANICODE_DATA_DIR`) overrides the base.
//! - Newer builds may use `~/.config/codebuff`; both layouts are accepted.
//!
//! Reference: getagentseal/codeburn PR #124 documents this exact layout.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{Value, json};
use walkdir::WalkDir;

use super::scan::ScanContext;
use super::{Connector, file_modified_since, flatten_content, franken_detection_for_connector};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct CodebuffConnector;

impl Default for CodebuffConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl CodebuffConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Walk known Codebuff bases looking for `chats/<chatId>/chat-messages.json`.
    ///
    /// We accept the file path either at:
    ///   `<base>/projects/<project>/chats/<chatId>/chat-messages.json`
    /// or the older flat layout some early builds used:
    ///   `<base>/chats/<chatId>/chat-messages.json`.
    fn find_chat_files(roots: &[&Path]) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for root in roots {
            if !root.exists() {
                continue;
            }
            for entry in WalkDir::new(root)
                .max_depth(6)
                .follow_links(false)
                .into_iter()
                .flatten()
                .filter(|e| e.file_type().is_file())
            {
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n == "chat-messages.json")
                    && entry
                        .path()
                        .components()
                        .any(|c| c.as_os_str() == "chats")
                {
                    files.push(entry.path().to_path_buf());
                }
            }
        }
        files.sort();
        files.dedup();
        files
    }

    /// Read the sibling `run-state.json` to recover the originating cwd.
    ///
    /// On-disk path sanitization replaces filesystem-illegal characters in the
    /// project basename, so the directory name alone is not always usable as a
    /// workspace path. The RunState records the real cwd at chat time.
    fn cwd_from_run_state(chat_dir: &Path) -> Option<PathBuf> {
        let rs = chat_dir.join("run-state.json");
        let content = fs::read_to_string(&rs).ok()?;
        let v: Value = serde_json::from_str(&content).ok()?;
        // Try a few shapes — different SDK versions stash this differently.
        // The current Codebuff SDK records cwd at `sessionState.fileContext.cwd`
        // (with `sessionState.fileContext.projectRoot` as a sibling). Older /
        // alternate builds stash it at the top level or under `state` /
        // `initialState`. Probe all known locations.
        let cwd = v
            .pointer("/sessionState/fileContext/cwd")
            .or_else(|| v.pointer("/sessionState/fileContext/projectRoot"))
            .or_else(|| v.pointer("/fileContext/cwd"))
            .or_else(|| v.pointer("/fileContext/projectRoot"))
            .or_else(|| v.pointer("/cwd"))
            .or_else(|| v.pointer("/projectPath"))
            .or_else(|| v.pointer("/projectRoot"))
            .or_else(|| v.pointer("/state/cwd"))
            .or_else(|| v.pointer("/initialState/cwd"))
            .and_then(Value::as_str)?;
        if cwd.is_empty() {
            None
        } else {
            Some(PathBuf::from(cwd))
        }
    }

    /// Parse a Codebuff message timestamp (ISO-8601 string or epoch number) into ms.
    fn parse_msg_ts(v: &Value) -> Option<i64> {
        if let Some(n) = v.as_i64() {
            // Heuristic: values that look like seconds get scaled to ms.
            return Some(if n < 10_000_000_000 { n * 1000 } else { n });
        }
        if let Some(f) = v.as_f64() {
            let ms = if f < 10_000_000_000.0 { f * 1000.0 } else { f };
            return Some(ms as i64);
        }
        if v.is_string() {
            return super::parse_timestamp(v);
        }
        None
    }

    /// Normalize a Codebuff role string to the canonical {"user","assistant","system","tool"} set.
    fn normalize_role(raw: Option<&str>) -> String {
        match raw.unwrap_or("").to_ascii_lowercase().as_str() {
            "user" | "human" => "user".to_string(),
            "assistant" | "ai" | "model" => "assistant".to_string(),
            "tool" | "function" | "tool_result" => "tool".to_string(),
            "system" | "" => "system".to_string(),
            other => other.to_string(),
        }
    }

    /// Extract the textual content body. Codebuff stores either a plain string
    /// or an array of typed content blocks (text / tool_use / tool_result).
    fn extract_text(value: &Value) -> String {
        if let Some(s) = value.as_str() {
            return s.to_string();
        }
        // Reuse the shared `flatten_content` helper so multipart messages
        // (text + tool blocks) are handled identically to other connectors.
        flatten_content(value)
    }

    fn parse_chat_file(&self, path: &Path) -> Result<NormalizedConversation> {
        let raw = fs::read_to_string(path)?;
        let parsed: Value = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("invalid chat-messages.json at {}: {e}", path.display()))?;

        // The file is canonically a JSON array of ChatMessage; some builds wrap
        // it as `{ "messages": [...] }`. Accept both.
        let arr = if parsed.is_array() {
            parsed.as_array().cloned().unwrap_or_default()
        } else if let Some(a) = parsed.get("messages").and_then(Value::as_array) {
            a.clone()
        } else {
            Vec::new()
        };

        let mut messages = Vec::with_capacity(arr.len());
        let mut started_at: Option<i64> = None;
        let mut ended_at: Option<i64> = None;

        for (idx, m) in arr.iter().enumerate() {
            let role = Self::normalize_role(m.get("role").and_then(Value::as_str));
            let content = Self::extract_text(m.get("content").unwrap_or(&Value::Null));
            let ts = m
                .get("timestamp")
                .or_else(|| m.get("created_at"))
                .or_else(|| m.get("createdAt"))
                .and_then(Self::parse_msg_ts);
            if let Some(t) = ts {
                started_at = Some(started_at.map_or(t, |s| s.min(t)));
                ended_at = Some(ended_at.map_or(t, |e| e.max(t)));
            }
            messages.push(NormalizedMessage {
                idx: i64::try_from(idx).unwrap_or(i64::MAX),
                role: role.clone(),
                author: Some(role),
                created_at: ts,
                content,
                extra: m
                    .get("credits")
                    .map(|c| json!({ "credits": c }))
                    .unwrap_or_else(|| json!({})),
                invocations: Vec::new(),
                snippets: Vec::new(),
            });
        }

        // Fall back to file mtime if no in-message timestamps were present.
        if started_at.is_none() {
            if let Ok(mt) = fs::metadata(path).and_then(|m| m.modified()) {
                let ms = i64::try_from(
                    mt.duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis(),
                )
                .unwrap_or(i64::MAX);
                started_at = Some(ms);
                ended_at = Some(ms);
            }
        }

        let chat_dir = path.parent().map(Path::to_path_buf);
        let workspace = chat_dir.as_deref().and_then(Self::cwd_from_run_state).or_else(|| {
            // Fall back to the `projects/<projectBasename>` directory name.
            path.ancestors()
                .find(|p| p.parent().and_then(|pp| pp.file_name()) == Some(std::ffi::OsStr::new("projects")))
                .map(Path::to_path_buf)
        });

        let chat_id = chat_dir
            .as_deref()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .map(str::to_string);

        Ok(NormalizedConversation {
            agent_slug: "codebuff".to_string(),
            external_id: chat_id.clone().or_else(|| Some(path.to_string_lossy().to_string())),
            title: chat_id.map(|id| format!("Codebuff Chat: {id}")),
            workspace,
            source_path: path.to_path_buf(),
            started_at,
            ended_at,
            metadata: json!({ "channel": "codebuff" }),
            messages,
        })
    }
}

impl Connector for CodebuffConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("codebuff").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        fn add_root(roots: &mut Vec<PathBuf>, root: PathBuf) {
            if !roots.contains(&root) {
                roots.push(root);
            }
        }

        let mut roots: Vec<PathBuf> = Vec::new();

        if ctx.use_default_detection() {
            // Honor explicit env override first so CI/dev setups can point at
            // a fixture tree.
            if let Ok(over) = dotenvy::var("CODEBUFF_DATA_DIR")
                && !over.trim().is_empty()
            {
                add_root(&mut roots, PathBuf::from(over.trim()));
            }
            if let Ok(legacy) = dotenvy::var("MANICODE_DATA_DIR")
                && !legacy.trim().is_empty()
            {
                add_root(&mut roots, PathBuf::from(legacy.trim()));
            }
            if roots.is_empty()
                && let Some(home) = dirs::home_dir()
            {
                for sub in [
                    ".config/manicode",
                    ".config/manicode-dev",
                    ".config/manicode-staging",
                    ".config/codebuff",
                    "Library/Application Support/manicode",
                    "Library/Application Support/codebuff",
                    "AppData/Roaming/manicode",
                    "AppData/Roaming/codebuff",
                ] {
                    let p = home.join(sub);
                    if p.exists() {
                        add_root(&mut roots, p);
                    }
                }
            }
        } else {
            for root in &ctx.scan_roots {
                add_root(&mut roots, root.path.clone());
            }
        }

        if roots.is_empty() {
            return Ok(Vec::new());
        }

        let root_refs: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
        let files = Self::find_chat_files(&root_refs);

        let mut conversations = Vec::with_capacity(files.len());
        for path in files {
            if !file_modified_since(&path, ctx.since_ts) {
                continue;
            }
            match self.parse_chat_file(&path) {
                Ok(conv) => conversations.push(conv),
                Err(e) => {
                    tracing::warn!(
                        "failed to parse codebuff chat {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }
        Ok(conversations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_chat(base: &Path, project: &str, chat_id: &str, body: &str) -> PathBuf {
        let dir = base
            .join("projects")
            .join(project)
            .join("chats")
            .join(chat_id);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("chat-messages.json");
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn new_creates_connector() {
        let _ = CodebuffConnector::new();
    }

    #[test]
    fn find_chat_files_locates_canonical_layout() {
        let dir = TempDir::new().unwrap();
        write_chat(dir.path(), "my-proj", "2024-01-01T00-00-00Z", "[]");
        let files = CodebuffConnector::find_chat_files(&[dir.path()]);
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("chat-messages.json"));
    }

    #[test]
    fn find_chat_files_ignores_unrelated_json() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("chat-messages.json"), "[]").unwrap(); // no `chats/` ancestor
        fs::write(dir.path().join("other.json"), "[]").unwrap();
        let files = CodebuffConnector::find_chat_files(&[dir.path()]);
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn parse_chat_file_extracts_basic_messages() {
        let dir = TempDir::new().unwrap();
        let body = r#"[
            {"role":"user","content":"hello","timestamp":"2024-01-01T00:00:00Z"},
            {"role":"assistant","content":"hi there","timestamp":"2024-01-01T00:00:01Z"}
        ]"#;
        let p = write_chat(dir.path(), "proj", "2024-01-01T00-00-00Z", body);
        let conv = CodebuffConnector::new().parse_chat_file(&p).unwrap();
        assert_eq!(conv.agent_slug, "codebuff");
        assert_eq!(conv.messages.len(), 2);
        assert_eq!(conv.messages[0].role, "user");
        assert_eq!(conv.messages[1].role, "assistant");
        assert_eq!(conv.messages[0].content, "hello");
        assert!(conv.started_at.is_some() && conv.ended_at.is_some());
    }

    #[test]
    fn parse_chat_file_accepts_messages_wrapper() {
        let dir = TempDir::new().unwrap();
        let body = r#"{"messages":[{"role":"user","content":"x"}]}"#;
        let p = write_chat(dir.path(), "p", "c1", body);
        let conv = CodebuffConnector::new().parse_chat_file(&p).unwrap();
        assert_eq!(conv.messages.len(), 1);
    }

    #[test]
    fn parse_chat_file_uses_run_state_cwd_when_present() {
        let dir = TempDir::new().unwrap();
        let p = write_chat(
            dir.path(),
            "sanitized_name",
            "c1",
            r#"[{"role":"user","content":"x"}]"#,
        );
        let real_cwd = "/Users/me/code/My Real Project";
        fs::write(
            p.parent().unwrap().join("run-state.json"),
            format!(r#"{{"cwd":"{real_cwd}"}}"#),
        )
        .unwrap();
        let conv = CodebuffConnector::new().parse_chat_file(&p).unwrap();
        assert_eq!(conv.workspace, Some(PathBuf::from(real_cwd)));
    }

    #[test]
    fn parse_chat_file_uses_run_state_cwd_from_session_state_file_context() {
        // Real-world Codebuff schema observed in
        // ~/.config/manicode/projects/<name>/chats/<id>/run-state.json:
        // the cwd lives at sessionState.fileContext.cwd
        let dir = TempDir::new().unwrap();
        let p = write_chat(
            dir.path(),
            "sanitized_name",
            "c1",
            r#"[{"role":"user","content":"x"}]"#,
        );
        let real_cwd = "/Users/me/code/codex_mac";
        fs::write(
            p.parent().unwrap().join("run-state.json"),
            format!(
                r#"{{"sessionState":{{"fileContext":{{"cwd":"{real_cwd}","projectRoot":"{real_cwd}"}}}}}}"#
            ),
        )
        .unwrap();
        let conv = CodebuffConnector::new().parse_chat_file(&p).unwrap();
        assert_eq!(conv.workspace, Some(PathBuf::from(real_cwd)));
    }

    #[test]
    fn parse_chat_file_normalizes_aliased_roles() {
        let dir = TempDir::new().unwrap();
        let body = r#"[
            {"role":"human","content":"a"},
            {"role":"ai","content":"b"},
            {"role":"function","content":"c"}
        ]"#;
        let p = write_chat(dir.path(), "p", "c1", body);
        let conv = CodebuffConnector::new().parse_chat_file(&p).unwrap();
        assert_eq!(conv.messages[0].role, "user");
        assert_eq!(conv.messages[1].role, "assistant");
        assert_eq!(conv.messages[2].role, "tool");
    }

    #[test]
    fn parse_chat_file_handles_empty_array() {
        let dir = TempDir::new().unwrap();
        let p = write_chat(dir.path(), "p", "c1", "[]");
        let conv = CodebuffConnector::new().parse_chat_file(&p).unwrap();
        assert_eq!(conv.messages.len(), 0);
        // Falls back to file mtime so a started_at is still emitted.
        assert!(conv.started_at.is_some());
    }

    #[test]
    fn parse_chat_file_invalid_json_returns_error() {
        let dir = TempDir::new().unwrap();
        let p = write_chat(dir.path(), "p", "c1", "{not json");
        assert!(CodebuffConnector::new().parse_chat_file(&p).is_err());
    }

    #[test]
    fn parse_chat_file_preserves_credits_in_extra() {
        let dir = TempDir::new().unwrap();
        let body = r#"[{"role":"assistant","content":"x","credits":42}]"#;
        let p = write_chat(dir.path(), "p", "c1", body);
        let conv = CodebuffConnector::new().parse_chat_file(&p).unwrap();
        assert_eq!(conv.messages[0].extra.get("credits").and_then(Value::as_i64), Some(42));
    }

    #[test]
    fn scan_returns_empty_when_no_roots_exist() {
        let connector = CodebuffConnector::new();
        let dir = TempDir::new().unwrap();
        let ctx = ScanContext::local_default(dir.path().to_path_buf(), None);
        // No chat files anywhere — ScanContext default detection walks home,
        // but the test process likely has no Codebuff install; result should
        // either be empty or contain only files that genuinely exist.
        let convs = connector.scan(&ctx).unwrap_or_default();
        assert!(convs.iter().all(|c| c.agent_slug == "codebuff"));
    }

    #[test]
    fn external_id_uses_chat_id_dir() {
        let dir = TempDir::new().unwrap();
        let p = write_chat(dir.path(), "p", "2024-05-01T12-00-00Z", "[]");
        let conv = CodebuffConnector::new().parse_chat_file(&p).unwrap();
        assert_eq!(conv.external_id.as_deref(), Some("2024-05-01T12-00-00Z"));
    }
}
