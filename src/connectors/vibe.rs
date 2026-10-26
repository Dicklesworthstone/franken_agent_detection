//! Connector for Vibe (Mistral) session logs.
//!
//! Vibe stores JSONL sessions at:
//! - ~/.vibe/logs/session/*/messages.jsonl
//!
//! Each line is a message object:
//! {"role":"user|assistant|system","content":"...","timestamp":"..."}

mod mirror;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;
use walkdir::WalkDir;

use std::collections::HashSet;

use super::jsonl::JsonlLines;
use super::scan::{
    DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot, SourceCompletion,
    SourceScanHooks,
};
use super::utils::{
    dedupe_path_key, excluded_scan_paths_from_env, path_is_excluded, unwrap_skill_invocations,
};
use super::{
    Connector, file_modified_since, flatten_content, franken_detection_for_connector,
    parse_timestamp,
};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
};

// The complete native argument string remains in `extra`. Only copy small
// arguments into the structured invocation; tool results and binary payloads
// must not expand the searchable message or acquire another large copy.
const MAX_INVOCATION_ARGUMENT_BYTES: usize = 64 * 1024;

pub struct VibeConnector;

impl Default for VibeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl VibeConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
    fn sessions_root() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_default()
            .join(".vibe")
            .join("logs")
            .join("session")
    }

    fn looks_like_vibe_storage(path: &Path) -> bool {
        // Structural parent-chain check: `<...>/.vibe/logs/session`.
        // A substring test mis-scoped default detection onto lookalikes
        // such as `/home/u/.vibe-backup/logs/session-archive`.
        let matches_layout = path.file_name().is_some_and(|n| n == "session")
            && path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "logs"))
            && path
                .parent()
                .and_then(Path::parent)
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".vibe"));
        let is_logs_dir = path.file_name().is_some_and(|n| n == "logs")
            && path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".vibe"));
        let is_vibe_dir = path.file_name().is_some_and(|n| n == ".vibe")
            && path.join("logs").join("session").is_dir();
        matches_layout || is_logs_dir || is_vibe_dir
    }

    fn append_explicit_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        if base.exists() && Self::looks_like_vibe_storage(base) {
            roots.push(base.to_path_buf());
        }

        if base.file_name().is_some_and(|n| n == ".vibe") {
            let sessions = base.join("logs").join("session");
            if sessions.exists() {
                roots.push(sessions);
            }
        }

        if base.file_name().is_some_and(|n| n == "logs")
            && base
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == ".vibe"))
        {
            let sessions = base.join("session");
            if sessions.exists() {
                roots.push(sessions);
            }
        }
    }

    pub(crate) fn session_files(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if !root.exists() {
            return out;
        }

        for entry in WalkDir::new(root).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }

            if entry.file_name() == "messages.jsonl" {
                out.push(entry.path().to_path_buf());
            }
        }

        // Keep connector traversal deterministic across filesystems/runs.
        out.sort();
        out
    }

    fn source_roots(ctx: &ScanContext) -> Vec<mirror::SessionRoot> {
        let mut roots: Vec<ScanRoot> = Vec::new();
        let mut subtrees = Vec::new();
        if ctx.use_default_detection() {
            if Self::looks_like_vibe_storage(&ctx.data_dir) && ctx.data_dir.exists() {
                roots.push(ScanRoot::local(ctx.data_dir.clone()));
            } else {
                let root = Self::sessions_root();
                if root.exists() {
                    roots.push(ScanRoot::local(root));
                }
            }
        } else {
            for root in &ctx.scan_roots {
                if let Some(selected) = mirror::subtree(root) {
                    subtrees.extend(selected);
                    continue;
                }
                if let Some(path) = root.mirrored_store(&[".vibe", "logs", "session"]) {
                    roots.push(root.with_path(path));
                }
                let candidate = root.path.join(".vibe/logs/session");
                if candidate.exists() {
                    roots.push(root.with_path(candidate));
                }

                let mut explicit = Vec::new();
                Self::append_explicit_roots(&mut explicit, &root.path);
                roots.extend(explicit.into_iter().map(|path| root.with_path(path)));
            }
        }
        let mut roots: Vec<_> = roots
            .into_iter()
            .map(mirror::SessionRoot::native)
            .chain(subtrees)
            .collect();
        roots.sort_by(|a, b| a.root.path.cmp(&b.root.path));
        roots.dedup_by(|a, b| a.root.path == b.root.path);
        roots
    }

    fn discover_sources(ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        let excluded_paths = excluded_scan_paths_from_env()?;
        let mut out = Vec::new();
        // Same cross-root dedupe as scan(): overlapping or symlink-aliased
        // roots must not produce duplicate discovered sources.
        let mut seen_files: HashSet<PathBuf> = HashSet::new();
        for source in Self::source_roots(ctx) {
            if path_is_excluded(&source.root.path, &excluded_paths) {
                continue;
            }
            let mut root = source.root;
            if root.path.is_file() {
                let parent = root.path.parent().unwrap_or(&root.path).to_path_buf();
                root = root.with_path(parent);
            }
            for file in Self::session_files(&root.path) {
                if path_is_excluded(&file, &excluded_paths) {
                    continue;
                }
                if !seen_files.insert(dedupe_path_key(&file)) {
                    continue;
                }
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "vibe",
                        &root,
                        file,
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
        }
        Ok(out)
    }

    fn extract_role(val: &Value) -> String {
        val.get("role")
            .and_then(|v| v.as_str())
            .or_else(|| val.get("speaker").and_then(|v| v.as_str()))
            .or_else(|| {
                val.get("message")
                    .and_then(|m| m.get("role"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("assistant")
            .to_string()
    }

    fn extract_content(val: &Value) -> String {
        if let Some(content) = val.get("content") {
            return flatten_content(content);
        }
        if let Some(content) = val.get("text") {
            return flatten_content(content);
        }
        if let Some(content) = val.get("message").and_then(|msg| msg.get("content")) {
            return flatten_content(content);
        }
        String::new()
    }

    fn normalize_content(val: &Value) -> (String, Vec<NormalizedInvocation>) {
        let plain = Self::extract_content(val);
        // SessionLogger persists flat LLMMessage rows. Limit the additional
        // fields to that native assistant shape; legacy role/content aliases
        // keep their existing projection.
        if val.get("role").and_then(Value::as_str) != Some("assistant") {
            return (plain, Vec::new());
        }

        let mut content = if let Some(reasoning) = val
            .get("reasoning_content")
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
        {
            let mut text = String::from("[Thinking] ");
            text.push_str(reasoning);
            Self::append_text(&mut text, &plain);
            text
        } else {
            plain
        };

        let mut invocations = Vec::new();
        if let Some(calls) = val.get("tool_calls").and_then(Value::as_array) {
            for call in calls {
                // Native calls default to type "function". Allow an omitted
                // default without treating other block types
                // or arbitrary objects as tool activity.
                if call
                    .get("type")
                    .is_some_and(|kind| kind.as_str() != Some("function"))
                {
                    continue;
                }
                let Some(name) = call
                    .pointer("/function/name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.trim().is_empty())
                else {
                    continue;
                };
                if !content.is_empty() {
                    content.push('\n');
                }
                content.push_str("[Tool: ");
                content.push_str(name);
                content.push(']');
                invocations.push(NormalizedInvocation {
                    kind: "tool".to_owned(),
                    name: name.to_owned(),
                    raw_name: None,
                    call_id: call
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|id| !id.trim().is_empty())
                        .map(str::to_owned),
                    arguments: Self::invocation_arguments(call),
                });
            }
        }
        unwrap_skill_invocations(&mut invocations);
        (content, invocations)
    }

    fn append_text(content: &mut String, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        if !content.is_empty() {
            content.push('\n');
        }
        content.push_str(text);
    }

    fn invocation_arguments(call: &Value) -> Option<Value> {
        // Vibe's FunctionCall.arguments is a JSON-encoded string, not an
        // object. Malformed argument text is still useful to consumers;
        // preserve it as text instead of guessing a structure. Oversize and
        // non-string values remain available only in the untouched raw row.
        let arguments = call.pointer("/function/arguments")?.as_str()?;
        if arguments.len() > MAX_INVOCATION_ARGUMENT_BYTES {
            return None;
        }
        Some(
            serde_json::from_str(arguments).unwrap_or_else(|_| Value::String(arguments.to_owned())),
        )
    }

    fn extract_timestamp(val: &Value) -> Option<i64> {
        let candidates = ["timestamp", "created_at", "createdAt", "time", "ts"];

        for key in candidates {
            if let Some(ts) = val.get(key).and_then(parse_timestamp) {
                return Some(ts);
            }
        }

        if let Some(message) = val.get("message") {
            for key in candidates {
                if let Some(ts) = message.get(key).and_then(parse_timestamp) {
                    return Some(ts);
                }
            }
        }

        None
    }
    fn parse_session_reader(
        source: &mirror::SessionRoot,
        source_path: &Path,
        reader: impl std::io::BufRead,
    ) -> Option<NormalizedConversation> {
        let external_id = source.external_id(source_path);

        let mut messages = Vec::new();
        let mut started_at: Option<i64> = None;
        let mut ended_at: Option<i64> = None;

        for line_res in JsonlLines::new(reader) {
            let line = match line_res {
                Ok(line) => line,
                Err(error) => {
                    tracing::debug!(
                        path = %source_path.display(),
                        error = %error,
                        "vibe: discarding incomplete session after read error"
                    );
                    return None;
                }
            };
            if line.trim().is_empty() {
                continue;
            }

            let line = line.trim_start_matches('\u{feff}');
            let val: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let role = Self::extract_role(&val);
            let (content, invocations) = Self::normalize_content(&val);

            if content.trim().is_empty() {
                continue;
            }

            let created = Self::extract_timestamp(&val);
            started_at = match (started_at, created) {
                (Some(curr), Some(ts)) => Some(curr.min(ts)),
                (None, Some(ts)) => Some(ts),
                (other, None) => other,
            };
            ended_at = match (ended_at, created) {
                (Some(curr), Some(ts)) => Some(curr.max(ts)),
                (None, Some(ts)) => Some(ts),
                (other, None) => other,
            };

            messages.push(NormalizedMessage {
                idx: i64::try_from(messages.len()).unwrap_or(i64::MAX),
                role,
                author: None,
                created_at: created,
                content,
                extra: val,
                invocations,
                snippets: Vec::new(),
            });
        }

        if messages.is_empty() {
            return None;
        }

        let title = messages
            .iter()
            .find(|m| m.role == "user")
            .map(|m| {
                m.content
                    .lines()
                    .next()
                    .unwrap_or(&m.content)
                    .chars()
                    .take(100)
                    .collect::<String>()
            })
            .or_else(|| {
                messages
                    .first()
                    .and_then(|m| m.content.lines().next())
                    .map(|s| s.chars().take(100).collect())
            });

        let metadata = serde_json::json!({
            "source": "vibe",
        });

        Some(NormalizedConversation {
            agent_slug: "vibe".to_string(),
            external_id,
            title,
            workspace: None,
            source_path: source_path.to_path_buf(),
            started_at,
            ended_at,
            metadata,
            messages,
        })
    }
}

impl Connector for VibeConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("vibe").unwrap_or_else(DetectionResult::not_found)
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
        self.scan_with_source_boundaries(ctx, &mut SourceScanHooks::default(), on_conversation)
    }

    fn supports_source_boundaries(&self) -> bool {
        true
    }

    fn scan_with_source_boundaries(
        &self,
        ctx: &ScanContext,
        hooks: &mut SourceScanHooks<'_>,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        let excluded_paths = excluded_scan_paths_from_env()?;
        let roots = Self::source_roots(ctx);

        if roots.is_empty() {
            return Ok(());
        }

        // Overlapping or symlink-aliased roots reach the same session file
        // twice; dedupe across ALL roots on the lossless path key.
        let mut seen_files: HashSet<PathBuf> = HashSet::new();

        for mut source in roots {
            if path_is_excluded(&source.root.path, &excluded_paths) {
                continue;
            }
            if source.root.path.is_file() {
                let parent = source
                    .root
                    .path
                    .parent()
                    .unwrap_or(&source.root.path)
                    .to_path_buf();
                source.root = source.root.with_path(parent);
            }

            let files = Self::session_files(&source.root.path);
            for file in files {
                if path_is_excluded(&file, &excluded_paths) {
                    continue;
                }
                if !seen_files.insert(dedupe_path_key(&file)) {
                    continue;
                }
                if !file_modified_since(&file, ctx.since_ts) {
                    continue;
                }

                let discovered = DiscoveredSourceFile::new(
                    "vibe",
                    &source.root,
                    file.clone(),
                    DiscoveredSourceRole::PrimarySessionLog,
                    true,
                )
                .with_fs_metadata();
                if !hooks.should_scan(&discovered) {
                    continue;
                }
                ctx.tick();

                let file_handle = match fs::File::open(&file) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::debug!(
                            path = %file.display(),
                            error = %e,
                            "vibe: skipping unreadable session"
                        );
                        continue;
                    }
                };
                let reader = std::io::BufReader::new(file_handle);
                if let Some(mut conv) = Self::parse_session_reader(&source, &file, reader) {
                    source.root.apply_workspace_rewrite(&mut conv);
                    on_conversation(conv)?;
                    if !discovered.fs_metadata_changed() {
                        hooks.complete(&SourceCompletion {
                            source: discovered,
                            required_sidecars: Vec::new(),
                            conversations_emitted: 1,
                        })?;
                    }
                }
            }
        }

        Ok(())
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Self::discover_sources(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use tempfile::TempDir;

    fn write_session(root: &Path, session_id: &str, lines: &[&str]) -> PathBuf {
        let dir = root.join(session_id);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("messages.jsonl");
        let content = lines.join("\n");
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn scan_parses_basic_jsonl() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".vibe/logs/session");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "sess-123",
            &[
                r#"{"role":"user","content":"Hello there","timestamp":"2025-01-27T03:30:00.000Z"}"#,
                r#"{"role":"assistant","content":"Hi","timestamp":"2025-01-27T03:30:05.000Z"}"#,
            ],
        );

        let connector = VibeConnector::new();
        let ctx = ScanContext::local_default(sessions, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "vibe");
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].title, Some("Hello there".to_string()));
        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
        assert!(
            convs[0]
                .external_id
                .as_deref()
                .unwrap_or("")
                .contains("sess-123")
        );
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_skips_invalid_and_empty_lines() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".vibe/logs/session");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "sess-456",
            &[
                "",
                "not-json",
                r#"{"role":"user","content":"Line 1","timestamp":"2025-01-27T03:30:00.000Z"}"#,
                r#"{"role":"assistant","content":"","timestamp":"2025-01-27T03:30:05.000Z"}"#,
            ],
        );

        let connector = VibeConnector::new();
        let ctx = ScanContext::local_default(sessions, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
    }

    #[test]
    fn scan_skips_invalid_utf8_records_and_keeps_later_messages() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".vibe/logs/session");
        let session = sessions.join("sess-utf8");
        fs::create_dir_all(&session).unwrap();
        fs::write(
            session.join("messages.jsonl"),
            b"{\"role\":\"user\",\"content\":\"Before\"}\n\xff\xfe\n{\"role\":\"assistant\",\"content\":\"After\"}\n",
        )
        .unwrap();

        let convs = VibeConnector::new()
            .scan(&ScanContext::local_default(sessions, None))
            .unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].content, "Before");
        assert_eq!(convs[0].messages[1].content, "After");
        assert_eq!(convs[0].messages[1].idx, 1);
    }

    #[test]
    fn scan_with_vibe_root_scan_root() {
        let tmp = TempDir::new().unwrap();
        let vibe_root = tmp.path().join(".vibe");
        let sessions = vibe_root.join("logs").join("session");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "sess-root",
            &[r#"{"role":"user","content":"Root scan","timestamp":1700000000000}"#],
        );

        let connector = VibeConnector::new();
        let ctx = ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(vibe_root)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Root scan");
    }

    #[test]
    fn session_files_returns_sorted_order() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".vibe/logs/session");
        fs::create_dir_all(&sessions).unwrap();

        write_session(
            &sessions,
            "z-last",
            &[r#"{"role":"user","content":"z","timestamp":"2025-01-27T03:30:00.000Z"}"#],
        );
        write_session(
            &sessions,
            "a-first",
            &[r#"{"role":"user","content":"a","timestamp":"2025-01-27T03:30:00.000Z"}"#],
        );
        write_session(
            &sessions,
            "m-middle",
            &[r#"{"role":"user","content":"m","timestamp":"2025-01-27T03:30:00.000Z"}"#],
        );

        let files = VibeConnector::session_files(&sessions);
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(files, sorted);
    }

    struct FailingReader {
        prefix: std::io::Cursor<Vec<u8>>,
        kind: std::io::ErrorKind,
        attempts: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl std::io::Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            unreachable!("the transcript reader uses BufRead directly")
        }
    }

    impl std::io::BufRead for FailingReader {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if usize::try_from(self.prefix.position()).unwrap() < self.prefix.get_ref().len() {
                return self.prefix.fill_buf();
            }
            self.attempts.set(self.attempts.get() + 1);
            Err(std::io::Error::new(
                self.kind,
                "injected transcript read failure",
            ))
        }

        fn consume(&mut self, amount: usize) {
            self.prefix.consume(amount);
        }
    }

    #[test]
    fn reader_failure_discards_complete_prefix_without_retrying() {
        let tmp = TempDir::new().unwrap();
        let sessions = tmp.path().join(".vibe/logs/session");
        let file = sessions.join("sess-fail/messages.jsonl");
        let source = mirror::SessionRoot::native(ScanRoot::local(sessions));
        let prefix = concat!(
            "{\"role\":\"user\",\"content\":\"complete prefix\"}\n",
            "{\"role\":\"assistant\",\"content\":\"partial",
        );
        let healthy =
            VibeConnector::parse_session_reader(&source, &file, std::io::Cursor::new(prefix))
                .expect("a clean EOF retains the complete record and ignores malformed JSON");
        assert_eq!(healthy.messages[0].content, "complete prefix");

        for kind in [
            std::io::ErrorKind::Other,
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::Interrupted,
        ] {
            let attempts = std::rc::Rc::new(std::cell::Cell::new(0));
            let conversation = VibeConnector::parse_session_reader(
                &source,
                &file,
                FailingReader {
                    prefix: std::io::Cursor::new(prefix.as_bytes().to_vec()),
                    kind,
                    attempts: std::rc::Rc::clone(&attempts),
                },
            );
            assert!(
                conversation.is_none(),
                "{kind:?} must discard accumulated messages"
            );
            assert_eq!(attempts.get(), 1, "the failed read must not be retried");
        }
    }
}
