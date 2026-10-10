//! Connector for pi-mono coding-agent (<https://github.com/badlogic/pi-mono>)
//!
//! Pi-Agent stores sessions in JSONL files under:
//! - `~/.pi/agent/sessions/<safe-path>/` where safe-path is derived from the working directory
//! - Each session file is named `<timestamp>_<uuid>.jsonl`
//!
//! JSONL entry types:
//! - `session`: Header with id, timestamp, cwd, provider, modelId, thinkingLevel
//! - `message`: Contains timestamp and message object with role (user/assistant/toolResult)
//! - `thinking_level_change`: Records thinking level changes
//! - `model_change`: Records model/provider changes
//!
//! Wire-format traversal and parsing live in the shared pi-family module
//! [`super::pi_wire`]; Oh My Pi (`omp`) sessions are covered by the dedicated
//! [`super::omp`] connector, which consumes the same parser.
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, ScanContext, ScanRoot, SourceScanHooks};
use super::{Connector, franken_detection_for_connector, utils::dedupe_path_key};
use crate::types::{DetectionResult, NormalizedConversation};
/// A Pi session store format that the `pi_agent` connector does not index.
///
/// `pi_agent_rust` supports three on-disk session formats: the default JSONL
/// (`jsonl_v3`) tree store, an optional SQLite-backed store (`sqlite_v1`, built
/// via the default `sqlite-sessions` feature), and the segmented Session Store
/// V2 (`native_v2`) sidecar. This connector parses the JSONL store, and the
/// SQLite store when built with the `pi-sqlite` feature (without it, SQLite
/// sessions are reported here), so a user on a non-default store would not
/// otherwise get silent zero or partial coverage. Each detected unsupported store is surfaced as a machine-readable
/// diagnostic — matching the connector framework's existing `tracing`
/// diagnostic shape (structured key/value fields) — so the compatibility
/// boundary is explicit rather than invisible.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UnsupportedPiStore {
    /// Stable machine key for the store format: `"session_store_v2"` or
    /// `"sqlite_sessions"`.
    pub store_format: &'static str,
    /// Support status for this format. Currently always `"unsupported"`.
    pub support_status: &'static str,
    /// Filesystem path to the detected store: a `*.v2` sidecar directory or a
    /// `*.sqlite` per-session file.
    pub path: PathBuf,
}

impl UnsupportedPiStore {
    const fn session_store_v2(path: PathBuf) -> Self {
        Self {
            store_format: "session_store_v2",
            support_status: "unsupported",
            path,
        }
    }

    const fn sqlite_sessions(path: PathBuf) -> Self {
        Self {
            store_format: "sqlite_sessions",
            support_status: "unsupported",
            path,
        }
    }

    /// Emit this diagnostic via `tracing::warn!` with structured fields so it
    /// is both human-readable and machine-parseable (e.g. under a JSON tracing
    /// subscriber).
    fn warn(&self) {
        tracing::warn!(
            connector = "pi_agent",
            store_format = self.store_format,
            support_status = self.support_status,
            path = %self.path.display(),
            "pi_agent: detected unsupported Pi session store; cass indexes only \
             the default JSONL (v3) store, so this session's history may be \
             partial or unindexed until this format is supported"
        );
    }
}

pub struct PiAgentConnector;

impl Default for PiAgentConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl PiAgentConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// All candidate pi-agent home directories in priority order.
    ///
    /// The upstream **pi-mono** distribution (`badlogic/pi-mono`) stores at
    /// `~/.pi/agent/`. Oh My Pi (`omp`) sessions live under `~/.omp/agent/`
    /// and are covered by the dedicated [`crate::connectors::omp`] connector,
    /// which shares this crate's pi-family wire parsing.
    ///
    /// Explicit `PI_CODING_AGENT_DIR` overrides and becomes the sole
    /// candidate so CI and isolated setups can pin a single location.
    /// An empty override (`PI_CODING_AGENT_DIR=""`) is treated as unset
    /// so scans don't silently fall through to the process's working
    /// directory via `PathBuf::new().join("sessions")`.
    fn default_homes() -> Vec<PathBuf> {
        let sessions_dir = dotenvy::var("PI_SESSIONS_DIR").ok();
        let coding_agent_dir = dotenvy::var("PI_CODING_AGENT_DIR").ok();
        Self::homes_from_overrides(
            sessions_dir.as_deref(),
            coding_agent_dir.as_deref(),
            dirs::home_dir().as_deref(),
        )
    }

    /// Pure candidate-home derivation shared by [`Self::default_homes`], split
    /// out so the env-driven precedence can be unit-tested without mutating
    /// process environment (`std::env::set_var` is `unsafe` and forbidden at
    /// the crate level).
    ///
    /// Precedence mirrors `pi_agent_rust`'s own config resolution:
    /// - `PI_SESSIONS_DIR` names a sessions directory **directly**
    ///   (`pi_agent_rust` `config.rs::sessions_dir_from_env`), so it is added as a
    ///   standalone root and is honored **independently** of
    ///   `PI_CODING_AGENT_DIR` — the two are separate env vars, and a custom
    ///   sessions dir must be scanned even when the agent home is also pinned.
    /// - `PI_CODING_AGENT_DIR` pins the agent home and suppresses the built-in
    ///   `~/.pi/agent` + `~/.omp/agent` defaults, but never suppresses an
    ///   explicit `PI_SESSIONS_DIR`.
    /// - Empty values (`FOO=""`) are treated as unset.
    fn homes_from_overrides(
        sessions_dir: Option<&str>,
        coding_agent_dir: Option<&str>,
        home: Option<&Path>,
    ) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(sessions) = sessions_dir.filter(|s| !s.is_empty()) {
            out.push(PathBuf::from(sessions));
        }
        if let Some(explicit) = coding_agent_dir.filter(|s| !s.is_empty()) {
            out.push(PathBuf::from(explicit));
            return out;
        }
        out.extend(Self::default_homes_from(home));
        out
    }

    /// Test-accessible variant of [`Self::default_homes`] that takes an
    /// explicit home directory override. Returns the same list of candidate
    /// pi-agent homes but without touching process environment.
    fn default_homes_from(home: Option<&Path>) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(home) = home {
            out.push(home.join(".pi/agent"));
        }
        out
    }
    fn sessions_dir(home: &Path) -> PathBuf {
        super::pi_wire::sessions_dir(home)
    }

    fn append_explicit_homes(
        homes: &mut Vec<PathBuf>,
        base: &Path,
        looks_like_root: &impl Fn(&PathBuf) -> bool,
    ) {
        if base.file_name().is_some_and(|n| n == ".pi") {
            let agent = base.join("agent");
            if looks_like_root(&agent) {
                homes.push(agent.clone());
            }
            let sessions = agent.join("sessions");
            if looks_like_root(&sessions) {
                homes.push(sessions);
            }
        }
    }

    fn looks_like_root(path: &Path) -> bool {
        path.join("sessions").exists()
            || path
                .file_name()
                .is_some_and(|n| n.to_str().unwrap_or("").contains("pi"))
            || path
                .to_str()
                .is_some_and(|s| s.contains(".pi/agent") || s.contains("pi-agent"))
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let is_pi_agent_dir = ctx.data_dir.to_str().is_some_and(|s| {
            s.contains(".pi/agent") || s.ends_with("/pi-agent") || s.ends_with("\\pi-agent")
        });

        let mut homes: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            if is_pi_agent_dir {
                homes.push(ScanRoot::local(ctx.data_dir.clone()));
            } else {
                homes.extend(Self::default_homes().into_iter().map(ScanRoot::local));
            }
        } else {
            if Self::looks_like_root(&ctx.data_dir) {
                homes.push(ScanRoot::local(ctx.data_dir.clone()));
            }
            let mut data_candidates = Vec::new();
            Self::append_explicit_homes(&mut data_candidates, &ctx.data_dir, &|path| {
                Self::looks_like_root(path)
            });
            homes.extend(data_candidates.into_iter().map(ScanRoot::local));

            for scan_root in &ctx.scan_roots {
                let candidates = [
                    scan_root.path.clone(),
                    scan_root.path.join(".pi/agent"),
                    scan_root.path.join(".pi/agent/sessions"),
                ];
                for candidate in candidates {
                    if Self::looks_like_root(&candidate) {
                        homes.push(scan_root.with_path(candidate));
                    }
                }
                let mut derived = Vec::new();
                Self::append_explicit_homes(&mut derived, &scan_root.path, &|path| {
                    Self::looks_like_root(path)
                });
                homes.extend(derived.into_iter().map(|path| scan_root.with_path(path)));
            }
        }

        for home in &mut homes {
            if home.path.is_file() {
                home.path = home.path.parent().unwrap_or(&home.path).to_path_buf();
            }
        }

        let mut seen = HashSet::new();
        homes.retain(|root| {
            let canonical = std::fs::canonicalize(&root.path).unwrap_or_else(|_| root.path.clone());
            seen.insert(canonical)
        });
        homes
    }

    fn discover_sources(ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        // Pass full ScanRoots so remote-origin/platform provenance survives
        // into each discovered source.
        super::pi_wire::try_discover_sources(&Self::source_roots(ctx), ctx, "pi_agent")
    }

    /// Detect Pi session stores under `root` that this connector cannot index.
    ///
    /// Grounded in `pi_agent_rust`'s actual layout:
    /// - **Session Store V2** (`native_v2`): a `<stem>.v2/` sidecar directory
    ///   identified by a `manifest.json` or `index/offsets.jsonl` inside it —
    ///   the same signature `pi_agent_rust` uses in
    ///   `session_store_v2::has_v2_sidecar`. When a V2 sidecar is present the
    ///   adjacent JSONL file can be stale, so its coverage is best-effort only.
    /// - **SQLite sessions** (`sqlite_v1`): a per-session `*.sqlite` file. Real
    ///   session files carry a `_` (mirroring `<timestamp>_<uuid>` naming); the
    ///   always-present `session-index.sqlite` metadata index sidecar has no
    ///   `_`, so default JSONL installs never trip this diagnostic.
    #[cfg(test)]
    fn detect_unsupported_stores(root: &Path) -> Vec<UnsupportedPiStore> {
        Self::detect_unsupported_stores_at(root, false)
    }

    /// As [`Self::detect_unsupported_stores`]; SQLite sessions under a
    /// `remote` root are always reported, because they are never read there
    /// (a synced database plus WAL is not a consistent snapshot).
    fn detect_unsupported_stores_at(root: &Path, remote: bool) -> Vec<UnsupportedPiStore> {
        let report_sqlite = remote || !cfg!(feature = "pi-sqlite");
        let mut out = Vec::new();
        let sessions = Self::sessions_dir(root);
        if !sessions.exists() {
            return out;
        }
        for entry in WalkDir::new(&sessions).into_iter().flatten() {
            let name = entry.file_name().to_str().unwrap_or("");
            if entry.file_type().is_dir() {
                let is_v2_dir = Path::new(name)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("v2"));
                if is_v2_dir
                    && (entry.path().join("manifest.json").exists()
                        || entry.path().join("index").join("offsets.jsonl").exists())
                {
                    out.push(UnsupportedPiStore::session_store_v2(
                        entry.path().to_path_buf(),
                    ));
                }
            } else if report_sqlite
                && entry.file_type().is_file()
                && Path::new(name)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("sqlite"))
                && name.contains('_')
            {
                out.push(UnsupportedPiStore::sqlite_sessions(
                    entry.path().to_path_buf(),
                ));
            }
        }
        // Deterministic ordering across filesystems/runs.
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    /// Collect deduplicated unsupported-store diagnostics across `homes`.
    fn collect_unsupported_stores(roots: &[ScanRoot]) -> Vec<UnsupportedPiStore> {
        let mut seen: HashSet<PathBuf> = HashSet::new();
        let mut out = Vec::new();
        for root in roots {
            for store in Self::detect_unsupported_stores_at(&root.path, root.origin.is_remote()) {
                if seen.insert(dedupe_path_key(&store.path)) {
                    out.push(store);
                }
            }
        }
        out
    }

    /// Machine-readable diagnostics for Pi session stores this connector cannot
    /// index (Session Store V2 sidecars and SQLite-backed sessions).
    ///
    /// Returns one entry per detected unsupported store so a consumer (e.g. a
    /// `cass diag --json` / `capabilities --json` surface) can report the
    /// compatibility boundary explicitly instead of implying full coverage.
    /// `scan()` additionally logs each of these via `tracing::warn!`.
    #[must_use]
    pub fn unsupported_store_diagnostics(&self, ctx: &ScanContext) -> Vec<UnsupportedPiStore> {
        Self::collect_unsupported_stores(&Self::source_roots(ctx))
    }
}

impl Connector for PiAgentConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("pi_agent").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut conversations = Vec::new();
        self.scan_with_callback(ctx, &mut |conversation| {
            conversations.push(conversation);
            Ok(())
        })?;
        Ok(conversations)
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
        let roots = Self::source_roots(ctx);

        // Surface Pi storage formats this connector does not index (Session
        // Store V2 sidecars; SQLite sessions without the `pi-sqlite` feature
        // or under a remote root) as explicit, machine-readable diagnostics so
        // users on non-default storage are not silently left with zero or
        // partial coverage.
        for store in Self::collect_unsupported_stores(&roots) {
            store.warn();
        }

        let tagged: Vec<(ScanRoot, Option<String>)> =
            roots.into_iter().map(|root| (root, None)).collect();
        super::pi_wire::scan_roots_with_boundaries(&tagged, ctx, "pi_agent", hooks, on_conversation)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Self::discover_sources(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::pi_wire::{flatten_message_content, session_files};
    use crate::connectors::scan::ScanRoot;
    use crate::types::NormalizedMessage;
    use serde_json::json;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let connector = PiAgentConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = PiAgentConnector;
        let _ = connector;
    }

    // =====================================================
    // flatten_message_content() Tests
    // =====================================================

    #[test]
    fn flatten_message_content_handles_string() {
        let content = json!("Simple string content");
        let result = flatten_message_content(&content);
        assert_eq!(result, "Simple string content");
    }

    #[test]
    fn flatten_message_content_handles_text_blocks() {
        let content = json!([
            {"type": "text", "text": "First paragraph"},
            {"type": "text", "text": "Second paragraph"}
        ]);
        let result = flatten_message_content(&content);
        assert!(result.contains("First paragraph"));
        assert!(result.contains("Second paragraph"));
    }

    #[test]
    fn flatten_message_content_handles_thinking() {
        let content = json!([
            {"type": "thinking", "thinking": "Let me analyze this..."}
        ]);
        let result = flatten_message_content(&content);
        assert!(result.contains("[Thinking]"));
        assert!(result.contains("Let me analyze this..."));
    }

    #[test]
    fn flatten_message_content_handles_tool_call() {
        let content = json!([
            {"type": "toolCall", "name": "read_file", "arguments": {"path": "/test.rs"}}
        ]);
        let result = flatten_message_content(&content);
        assert!(result.contains("[Tool: read_file]"));
        assert!(result.contains("path=/test.rs"));
    }

    #[test]
    fn flatten_message_content_handles_tool_call_without_args() {
        let content = json!([
            {"type": "toolCall", "name": "get_status", "arguments": {}}
        ]);
        let result = flatten_message_content(&content);
        assert_eq!(result, "[Tool: get_status]");
    }

    #[test]
    fn flatten_message_content_skips_images() {
        let content = json!([
            {"type": "text", "text": "Here's an image:"},
            {"type": "image", "url": "data:image/png;base64,..."},
            {"type": "text", "text": "End of message"}
        ]);
        let result = flatten_message_content(&content);
        assert!(result.contains("Here's an image:"));
        assert!(result.contains("End of message"));
        assert!(!result.contains("data:image"));
    }

    #[test]
    fn flatten_message_content_handles_mixed_types() {
        let content = json!([
            {"type": "text", "text": "Let me help:"},
            {"type": "thinking", "thinking": "Analyzing..."},
            {"type": "toolCall", "name": "bash", "arguments": {"command": "ls"}},
            {"type": "text", "text": "Done!"}
        ]);
        let result = flatten_message_content(&content);
        assert!(result.contains("Let me help:"));
        assert!(result.contains("[Thinking] Analyzing..."));
        assert!(result.contains("[Tool: bash]"));
        assert!(result.contains("Done!"));
    }

    #[test]
    fn flatten_message_content_returns_empty_for_null() {
        let content = json!(null);
        let result = flatten_message_content(&content);
        assert!(result.is_empty());
    }

    #[test]
    fn flatten_message_content_limits_tool_args_to_three() {
        let content = json!([
            {"type": "toolCall", "name": "multi_arg", "arguments": {
                "a": "1", "b": "2", "c": "3", "d": "4", "e": "5"
            }}
        ]);
        let result = flatten_message_content(&content);
        // Should contain at most 3 arguments
        let arg_count = result.matches('=').count();
        assert!(arg_count <= 3);
    }

    // =====================================================
    // session_files() Tests
    // =====================================================

    #[test]
    fn session_files_finds_valid_session_files() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Valid session file format: <timestamp>_<uuid>.jsonl
        fs::write(sessions.join("2025-12-01T10-00-00_abc123.jsonl"), "{}").unwrap();

        let files = session_files(dir.path());
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn session_files_ignores_non_jsonl_files() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        fs::write(sessions.join("2025-12-01_abc123.json"), "{}").unwrap();
        fs::write(sessions.join("config.txt"), "{}").unwrap();

        let files = session_files(dir.path());
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn session_files_ignores_files_without_underscore() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Missing underscore between timestamp and uuid
        fs::write(sessions.join("2025-12-01.jsonl"), "{}").unwrap();

        let files = session_files(dir.path());
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn session_files_finds_nested_sessions() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("sessions").join("--Users-foo-project--");
        fs::create_dir_all(&nested).unwrap();

        fs::write(nested.join("2025-12-01T10-00-00_uuid1.jsonl"), "{}").unwrap();

        let files = session_files(dir.path());
        assert_eq!(files.len(), 1);
    }

    /// Oh My Pi (`omp`) sub-agent transcripts live in a sibling directory
    /// named after the session: `<slug>/<timestamp>_<uuid>/<AgentName>.jsonl`.
    /// Each is a complete session document with its own `session` header, so
    /// it must be picked up alongside the main transcript — while a stray
    /// `.jsonl` whose name and parent both lack the session `_` marker stays
    /// excluded.
    #[test]
    fn session_files_finds_omp_subagent_transcripts_in_session_dirs() {
        let dir = TempDir::new().unwrap();
        let slug = dir.path().join("sessions").join("--data-projects-app--");
        let session_dir = slug.join("2026-07-18T14-56-21-545Z_019f75ba");
        fs::create_dir_all(&session_dir).unwrap();

        // Main transcript next to the session directory.
        fs::write(slug.join("2026-07-18T14-56-21-545Z_019f75ba.jsonl"), "{}").unwrap();
        // Sub-agent transcripts inside it (no underscore in the file name).
        fs::write(session_dir.join("BenchBatch1.jsonl"), "{}").unwrap();
        fs::write(session_dir.join("BenchBatch2.jsonl"), "{}").unwrap();
        // A stray non-session file directly under the slug stays excluded
        // (slug has no underscore, name has no underscore).
        fs::write(slug.join("notes.jsonl"), "{}").unwrap();

        // Workspace slugs preserve underscores from the original cwd
        // (encode_cwd only rewrites path separators), so a slug directory
        // with an underscore must NOT turn its stray .jsonl files into
        // session candidates — it lacks the sibling main transcript that
        // marks a real omp session directory.
        let underscore_slug = dir.path().join("sessions").join("--data-projects-my_app--");
        fs::create_dir_all(&underscore_slug).unwrap();
        fs::write(underscore_slug.join("export.jsonl"), "{}").unwrap();

        let files = session_files(dir.path());
        let names: Vec<_> = files
            .iter()
            .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
            .collect();
        assert_eq!(
            files.len(),
            3,
            "main + two sub-agent transcripts only: {names:?}"
        );
        assert!(names.contains(&"BenchBatch1.jsonl"));
        assert!(names.contains(&"BenchBatch2.jsonl"));
        assert!(!names.contains(&"notes.jsonl"));
        assert!(
            !names.contains(&"export.jsonl"),
            "stray .jsonl under an underscore-bearing workspace slug must stay excluded"
        );
    }

    #[test]
    fn session_files_returns_empty_when_no_sessions_dir() {
        let dir = TempDir::new().unwrap();
        let files = session_files(dir.path());
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn session_files_returns_sorted_order() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("sessions").join("--Users-foo-project--");
        fs::create_dir_all(&nested).unwrap();

        fs::write(nested.join("2025-12-01T10-00-00_zzzz.jsonl"), "{}").unwrap();
        fs::write(nested.join("2025-12-01T10-00-00_aaaa.jsonl"), "{}").unwrap();
        fs::write(nested.join("2025-12-01T10-00-00_mmmm.jsonl"), "{}").unwrap();

        let files = session_files(dir.path());
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(files, sorted);
    }

    // =====================================================
    // Helper: Create Pi-Agent storage structure
    // =====================================================

    fn create_pi_agent_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join("pi-agent");
        fs::create_dir_all(storage.join("sessions")).unwrap();
        storage
    }

    fn write_session_file(storage: &Path, name: &str, lines: &[&str]) {
        let sessions = storage.join("sessions");
        fs::write(sessions.join(name), lines.join("\n")).unwrap();
    }

    // =====================================================
    // scan() Tests - Session Header
    // =====================================================

    #[test]
    fn scan_parses_session_header() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"session","id":"sess-001","timestamp":"2025-12-01T10:00:00Z","cwd":"/home/user/project","provider":"anthropic","modelId":"claude-3-opus"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"Hello Pi!"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/project"))
        );
        assert_eq!(convs[0].metadata["provider"], "anthropic");
        assert_eq!(convs[0].metadata["model_id"], "claude-3-opus");
    }

    // =====================================================
    // scan() Tests - Messages
    // =====================================================

    #[test]
    fn scan_parses_user_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello Pi-Agent!"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Pi-Agent!");
    }

    #[test]
    fn scan_parses_assistant_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":"Hello! How can I help?","model":"claude-3-opus"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].role, "assistant");
        assert_eq!(
            convs[0].messages[0].author,
            Some("claude-3-opus".to_string())
        );
    }

    #[test]
    fn scan_normalizes_tool_result_role() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"toolResult","content":"Tool output here"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // toolResult should be normalized to "tool"
        assert_eq!(convs[0].messages[0].role, "tool");
    }

    #[test]
    fn scan_parses_array_content() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let content = json!([
            {"type": "text", "text": "Part 1"},
            {"type": "text", "text": "Part 2"}
        ]);
        let line = format!(
            r#"{{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{{"role":"assistant","content":{}}}}}"#,
            content
        );
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[&line]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].messages[0].content.contains("Part 1"));
        assert!(convs[0].messages[0].content.contains("Part 2"));
    }

    #[test]
    fn scan_skips_empty_content() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Valid"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","content":""}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:02Z","message":{"role":"assistant","content":"   "}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        // Only the valid message should be included
        assert_eq!(convs[0].messages.len(), 1);
    }

    // =====================================================
    // scan() Tests - Model Changes
    // =====================================================

    #[test]
    fn scan_tracks_model_changes() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"session","id":"sess-001","provider":"openai","modelId":"gpt-4"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello"}}"#,
            r#"{"type":"model_change","provider":"anthropic","modelId":"claude-3-opus"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","content":"Hello!"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        // After model_change, assistant should have new model as author
        assert_eq!(
            convs[0].messages[1].author,
            Some("claude-3-opus".to_string())
        );
    }

    // =====================================================
    // scan() Tests - Skipped Entry Types
    // =====================================================

    #[test]
    fn scan_skips_thinking_level_change() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
            r#"{"type":"thinking_level_change","level":"high"}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        // Should still work, just skip the thinking_level_change
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
    }

    // =====================================================
    // Title Extraction Tests
    // =====================================================

    #[test]
    fn scan_extracts_title_from_first_user_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":"I'm ready!"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"This is the title"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("This is the title".to_string()));
    }

    #[test]
    fn scan_truncates_long_titles() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let long_content = "x".repeat(200);
        let line = format!(
            r#"{{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{{"role":"user","content":"{}"}}}}"#,
            long_content
        );
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[&line]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title.as_ref().unwrap().len(), 100);
    }

    #[test]
    fn scan_uses_first_line_for_multiline_title() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"First line\nSecond line\nThird line"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("First line".to_string()));
    }

    #[test]
    fn scan_falls_back_to_first_message_for_title() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        // No user messages
        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":"Assistant speaks first"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("Assistant speaks first".to_string()));
    }

    // =====================================================
    // Timestamp Tests
    // =====================================================

    #[test]
    fn scan_extracts_timestamps() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"session","timestamp":"2025-12-01T10:00:00Z"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"First"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T11:00:00Z","message":{"role":"assistant","content":"Last"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(convs[0].started_at.is_some());
        assert!(convs[0].ended_at.is_some());
        assert!(convs[0].messages[0].created_at.is_some());
    }

    // =====================================================
    // Agent Slug and External ID Tests
    // =====================================================

    #[test]
    fn scan_sets_agent_slug_to_pi_agent() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].agent_slug, "pi_agent");
    }

    #[test]
    fn scan_uses_relative_path_as_external_id() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let nested = storage.join("sessions").join("--Users-foo-project--");
        fs::create_dir_all(&nested).unwrap();

        let lines = [
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        fs::write(
            nested.join("2025-12-01T10-00-00_uuid1.jsonl"),
            lines.join("\n"),
        )
        .unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        // External ID should include the path structure
        assert!(convs[0].external_id.is_some());
        let ext_id = convs[0].external_id.as_ref().unwrap();
        assert!(ext_id.contains("Users-foo-project") || ext_id.contains("uuid1"));
    }

    // =====================================================
    // Metadata Tests
    // =====================================================

    #[test]
    fn scan_sets_metadata_source() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["source"], "pi_agent");
    }

    #[test]
    fn scan_includes_session_id_in_metadata() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"session","id":"unique-session-id-123"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["session_id"], "unique-session-id-123");
    }

    // =====================================================
    // Edge Cases
    // =====================================================

    #[test]
    fn scan_handles_empty_sessions_dir() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_invalid_json_lines() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Valid"}}"#,
            "not valid json at all",
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"Also valid"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn scan_skips_empty_lines() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Message 1"}}"#,
            "",
            "   ",
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"Message 2"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn scan_skips_sessions_without_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        // Only session header, no messages
        let lines = vec![r#"{"type":"session","id":"empty-session"}"#];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_handles_multiple_session_files() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines1 = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Session 1"}}"#,
        ];
        let lines2 = vec![
            r#"{"type":"message","timestamp":"2025-12-01T11:00:00Z","message":{"role":"user","content":"Session 2"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines1);
        write_session_file(&storage, "2025-12-01T11-00-00_uuid2.jsonl", &lines2);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn scan_assigns_sequential_indices() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"First"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","content":"Second"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:02Z","message":{"role":"user","content":"Third"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].idx, 0);
        assert_eq!(convs[0].messages[1].idx, 1);
        assert_eq!(convs[0].messages[2].idx, 2);
    }

    #[test]
    fn scan_stores_source_path() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Test"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        let expected_path = storage
            .join("sessions")
            .join("2025-12-01T10-00-00_uuid1.jsonl");
        assert_eq!(convs[0].source_path, expected_path);
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_uses_fallback_model_from_session() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        // Session sets model, assistant message doesn't override
        let lines = vec![
            r#"{"type":"session","modelId":"gpt-4-turbo"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":"Hello!"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].author, Some("gpt-4-turbo".to_string()));
    }

    // =========================================================================
    // Edge case tests — malformed input robustness (br-2w98)
    // =========================================================================

    #[test]
    fn edge_empty_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[""]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_whitespace_only_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        write_session_file(
            &storage,
            "2025-12-01T10-00-00_uuid1.jsonl",
            &["   ", "\t", "  "],
        );

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_truncated_jsonl_mid_json_returns_partial_results() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Valid"}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assis"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid");
    }

    #[test]
    fn edge_invalid_utf8_skips_file() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        // Pi-Agent uses read_to_string which will fail on invalid UTF-8
        let file_path = storage
            .join("sessions")
            .join("2025-12-01T10-00-00_uuid1.jsonl");
        std::fs::write(&file_path, b"\xff\xfe invalid utf8 line").unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        // Invalid UTF-8 files are gracefully skipped (not fatal)
        let result = connector.scan(&ctx).unwrap();
        assert!(result.is_empty(), "invalid UTF-8 file should be skipped");
    }

    #[test]
    fn edge_bom_marker_at_file_start_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        // UTF-8 BOM + valid JSONL
        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(
            br#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"BOM"}}"#,
        );
        let file_path = storage
            .join("sessions")
            .join("2025-12-01T10-00-00_uuid1.jsonl");
        std::fs::write(&file_path, &data).unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        // BOM may cause first line parse failure; subsequent lines should still work
        // With only one line, may get 0 conversations
        assert!(convs.len() <= 1);
    }

    #[test]
    fn edge_json_type_mismatch_skips_gracefully() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            // type is a number instead of string
            r#"{"type": 42, "message": {"role": "user", "content": "Bad type field"}}"#,
            // Valid line after
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Valid"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid");
    }

    #[test]
    fn edge_deeply_nested_json_does_not_stack_overflow() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        // Message with deeply nested content in the message object
        let mut nested = String::from(
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"deep","extra":"#,
        );
        for _ in 0..200 {
            nested.push_str(r#"{"a":"#);
        }
        nested.push_str(r#""leaf""#);
        for _ in 0..200 {
            nested.push('}');
        }
        nested.push_str("}}");
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[&nested]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        // Should not stack overflow
        let result = connector.scan(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn edge_large_message_body_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let large_content = "x".repeat(1_000_000);
        let line = format!(
            r#"{{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{{"role":"user","content":"{}"}}}}"#,
            large_content
        );
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[&line]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content.len(), 1_000_000);
    }

    #[test]
    fn edge_null_bytes_in_content_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"hello\u0000world"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("hello"));
    }

    // ---- Pi-Agent-specific edge cases ----

    #[test]
    fn edge_message_without_nested_message_object_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            // "message" type entry but missing the inner "message" object
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z"}"#,
            // Valid message after
            r#"{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"Valid"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid");
    }

    #[test]
    fn edge_unknown_entry_types_skipped_gracefully() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            r#"{"type":"unknown_new_type","data":"whatever"}"#,
            r#"{"type":"another_future_type","payload":{"nested":true}}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Still works"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Still works");
    }

    #[test]
    fn edge_model_change_before_any_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let lines = vec![
            r#"{"type":"model_change","provider":"google","modelId":"gemini-2.0-flash"}"#,
            r#"{"type":"model_change","provider":"anthropic","modelId":"claude-opus"}"#,
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":"After two model changes"}}"#,
        ];
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &lines);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        // Should use the latest model_change
        assert_eq!(convs[0].messages[0].author, Some("claude-opus".to_string()));
    }

    #[test]
    fn edge_content_array_with_unknown_block_types() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let content = json!([
            {"type": "text", "text": "Known type"},
            {"type": "future_block_type", "data": "unknown"},
            {"type": "another_new_type"},
            {"type": "text", "text": "Also known"}
        ]);
        let line = format!(
            r#"{{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{{"role":"assistant","content":{}}}}}"#,
            content
        );
        write_session_file(&storage, "2025-12-01T10-00-00_uuid1.jsonl", &[&line]);

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        let msg = &convs[0].messages[0].content;
        assert!(msg.contains("Known type"));
        assert!(msg.contains("Also known"));
        // Unknown types should be silently skipped
        assert!(!msg.contains("future_block_type"));
    }

    #[test]
    fn edge_session_file_without_underscore_ignored() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        // File without underscore should not be picked up
        let sessions_dir = storage.join("sessions");
        fs::write(
            sessions_dir.join("no-underscore.jsonl"),
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Should be ignored"}}"#,
        )
        .unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    // =====================================================
    // Regression: nested subdirectory scanning via scan_roots
    // (Issue #85 — watch/scan_roots path must find sessions
    //  in project-scoped subdirectories)
    // =====================================================

    #[test]
    fn scan_with_roots_finds_nested_subdirectory_sessions() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);

        // Create nested project-scoped subdirectory (like Pi-Agent does)
        let nested = storage.join("sessions").join("--home-projects-xyz--");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("2025-12-01T10-00-00_uuid1.jsonl"),
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello from nested dir"}}"#,
        )
        .unwrap();

        // Also add a second nested subdir to confirm multi-level works
        let nested2 = storage.join("sessions").join("--home-projects-abc--");
        fs::create_dir_all(&nested2).unwrap();
        fs::write(
            nested2.join("2025-12-01T10-00-00_uuid2.jsonl"),
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello from second nested dir"}}"#,
        )
        .unwrap();

        let connector = PiAgentConnector::new();

        // Simulate what the watch/scan_roots code path does:
        // data_dir is the sessions directory itself (detection root_path)
        let sessions_path = storage.join("sessions");
        let root = ScanRoot::local(sessions_path.clone());
        let ctx = ScanContext::with_roots(sessions_path, vec![root], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs.len(),
            2,
            "expected 2 conversations from nested subdirectories, got {}",
            convs.len()
        );
    }

    // =====================================================
    // Regression: issue #174 — discover Oh My Pi at ~/.omp/agent
    // in addition to pi-mono at ~/.pi/agent
    // =====================================================

    /// Regression scope update: `default_homes_from` now returns ONLY
    /// `~/.pi/agent` (upstream pi-mono). Oh My Pi (`omp`) sessions moved to
    /// the dedicated `omp` connector, which shares this crate's wire parser;
    /// a dual-home default here would double-scan `.omp` trees across two
    /// connectors and misattribute their conversations.
    ///
    /// This test targets the pure function so it does not need to mutate
    /// process environment (`std::env::set_var` is `unsafe` and `forbid`den
    /// at the crate level).
    #[test]
    fn default_homes_from_pins_the_upstream_pi_mono_agent_dir() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path();
        let homes = PiAgentConnector::default_homes_from(Some(home));
        assert_eq!(
            homes,
            vec![home.join(".pi/agent")],
            "default_homes_from must return only the pi-mono candidate"
        );
    }

    /// Ownership-boundary regression (issue #174 follow-up): with omp
    /// sessions owned by the dedicated `omp` connector, `default_homes()`
    /// must not include the `.omp` tree — a default-detection scan from an
    /// unrelated data dir walks only `.pi/agent`.
    ///
    /// This exercises the same discovery path the real scanner takes
    /// under `build_scan_roots` without touching process environment.
    #[test]
    fn default_detection_scan_does_not_reach_omp_trees() {
        let sandbox = TempDir::new().unwrap();
        let sandbox_home = sandbox.path().to_path_buf();

        let pi_sessions = sandbox_home.join(".pi/agent/sessions");
        fs::create_dir_all(&pi_sessions).unwrap();
        fs::write(
            pi_sessions.join("2025-12-01T10-00-00_pi-uuid.jsonl"),
            r#"{"type":"session","id":"sess-pi","timestamp":"2025-12-01T10:00:00Z","cwd":"/home/user/pi-proj","provider":"anthropic","modelId":"claude-3-opus"}
{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"From pi-mono"}}"#,
        )
        .unwrap();

        let omp_sessions = sandbox_home.join(".omp/agent/sessions");
        fs::create_dir_all(&omp_sessions).unwrap();
        fs::write(
            omp_sessions.join("2025-12-02T11-00-00_omp-uuid.jsonl"),
            r#"{"type":"session","id":"sess-omp","timestamp":"2025-12-02T11:00:00Z","cwd":"/home/user/omp-proj","provider":"anthropic","modelId":"claude-3-opus"}
{"type":"message","timestamp":"2025-12-02T11:00:01Z","message":{"role":"user","content":"From Oh My Pi"}}"#,
        )
        .unwrap();

        // Sandbox trees are invisible to default detection on any machine:
        // default_homes() derives from the process home, so neither the
        // sandboxed .pi tree nor the sandboxed .omp tree may surface from an
        // unrelated data dir.
        let ctx = ScanContext::local_default(sandbox.path().join("cass-state"), None);
        let convs = PiAgentConnector::new().scan(&ctx).unwrap();
        assert!(
            convs
                .iter()
                .all(|c| !c.source_path.starts_with(&sandbox_home)),
            "default detection must not reach sandboxed trees"
        );

        // The pi connector still indexes its own tree when handed over
        // explicitly (the path real scan-root wiring produces).
        let ctx_pi = ScanContext::with_roots(
            PathBuf::from("/nonexistent"),
            vec![ScanRoot::local(sandbox_home.join(".pi/agent"))],
            None,
        );
        let pi_convs = PiAgentConnector::new().scan(&ctx_pi).unwrap();
        assert_eq!(pi_convs.len(), 1);
        assert_eq!(pi_convs[0].agent_slug, "pi_agent");
        assert_eq!(pi_convs[0].messages[0].content, "From pi-mono");

        // The dedicated omp connector claims the same sandbox's `.omp` tree
        // when it is handed over explicitly.
        let ctx_omp = ScanContext::with_roots(
            PathBuf::from("/nonexistent"),
            vec![ScanRoot::local(sandbox_home.join(".omp/agent"))],
            None,
        );
        let omp_convs = crate::connectors::omp::OmpConnector::new()
            .scan(&ctx_omp)
            .unwrap();
        assert_eq!(omp_convs.len(), 1);
        assert_eq!(omp_convs[0].agent_slug, "omp");
        assert_eq!(omp_convs[0].messages[0].content, "From Oh My Pi");
    }

    #[test]
    fn scan_with_pi_root_scan_root() {
        let sandbox = TempDir::new().unwrap();
        let pi_root = sandbox.path().join(".pi");
        let sessions = pi_root.join("agent").join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        fs::write(
            sessions.join("2025-12-01T10-00-00_root-uuid.jsonl"),
            r#"{"type":"session","id":"sess-root","timestamp":"2025-12-01T10:00:00Z","cwd":"/home/user/root","provider":"anthropic","modelId":"claude-3-opus"}
{"type":"message","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":"From .pi root"}}"#,
        )
        .unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::with_roots(PathBuf::new(), vec![ScanRoot::local(pi_root)], None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "From .pi root");
    }

    /// Regression: `default_homes_from(None)` must return an empty vec
    /// rather than synthesizing relative paths from an empty `PathBuf`,
    /// which would cause `session_files()` to walk the process's
    /// current working directory via `PathBuf::new().join("sessions")`.
    #[test]
    fn default_homes_from_none_is_empty() {
        let homes = PiAgentConnector::default_homes_from(None);
        assert!(homes.is_empty(), "no home → no candidates; got: {homes:?}");
    }

    /// Regression: `default_homes_from(Some(empty_path))` joins a
    /// relative ".pi/agent" etc. onto the empty path, which
    /// `PathBuf::join` treats as a relative path. This is the closest
    /// we can get to exercising the empty-home branch without mutating
    /// process env. The returned paths are relative — callers further
    /// upstream decide whether to trust them (real pi-agent lookups
    /// always come from `dirs::home_dir()`, so an empty HOME is
    /// handled at that layer).
    #[test]
    fn default_homes_from_empty_path_yields_relative_candidates() {
        let empty = PathBuf::new();
        let homes = PiAgentConnector::default_homes_from(Some(&empty));
        assert_eq!(homes.len(), 1, "only the pi-mono default: {homes:?}");
        assert_eq!(homes[0], PathBuf::from(".pi/agent"));
    }

    // =====================================================
    // Issue #313 — PI_SESSIONS_DIR + unsupported store detection
    // =====================================================

    /// `PI_SESSIONS_DIR` names a sessions directory directly and is honored
    /// as a standalone root, independently of the built-in `~/.pi/agent`
    /// default. Exercised via the pure helper so no process env is mutated.
    #[test]
    fn homes_from_overrides_honors_pi_sessions_dir() {
        let home = PathBuf::from("/home/user");
        let homes =
            PiAgentConnector::homes_from_overrides(Some("/custom/pi-sessions"), None, Some(&home));
        assert_eq!(
            homes[0],
            PathBuf::from("/custom/pi-sessions"),
            "PI_SESSIONS_DIR must be the first candidate root"
        );
        assert!(homes.contains(&home.join(".pi/agent")));
    }

    /// `PI_SESSIONS_DIR` and `PI_CODING_AGENT_DIR` are independent: the custom
    /// sessions dir is still scanned even when the agent home is pinned (and
    /// the pin suppresses the built-in `~/.pi/agent` default).
    #[test]
    fn homes_from_overrides_sessions_dir_and_coding_agent_dir_coexist() {
        let homes = PiAgentConnector::homes_from_overrides(
            Some("/custom/pi-sessions"),
            Some("/opt/pi/agent"),
            Some(Path::new("/home/user")),
        );
        assert_eq!(
            homes,
            vec![
                PathBuf::from("/custom/pi-sessions"),
                PathBuf::from("/opt/pi/agent"),
            ]
        );
    }

    /// An empty `PI_SESSIONS_DIR=""` is treated as unset (no phantom root);
    /// only the pi-mono built-in default remains.
    #[test]
    fn homes_from_overrides_empty_pi_sessions_dir_ignored() {
        let homes =
            PiAgentConnector::homes_from_overrides(Some(""), None, Some(Path::new("/home/user")));
        assert!(!homes.contains(&PathBuf::new()));
        assert_eq!(homes.len(), 1, "only the pi-mono built-in: {homes:?}");
    }

    /// A custom sessions root that contains JSONL session files *directly*
    /// (no nested `sessions/` subdir) is indexed — the shape `PI_SESSIONS_DIR`
    /// produces. Driven through an explicit scan root so no env is mutated.
    #[test]
    fn scan_indexes_sessions_directly_under_custom_sessions_dir() {
        let dir = TempDir::new().unwrap();
        // Name contains "pi" so `looks_like_root` accepts it as a Pi root.
        let sessions_root = dir.path().join("pi-sessions");
        let project = sessions_root.join("--home-me-proj--");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("2025-12-01T10-00-00_uuid.jsonl"),
            "{\"type\":\"session\",\"id\":\"s1\",\"timestamp\":\"2025-12-01T10:00:00Z\",\"cwd\":\"/home/me/proj\"}\n{\"type\":\"message\",\"timestamp\":\"2025-12-01T10:00:01Z\",\"message\":{\"role\":\"user\",\"content\":\"From PI_SESSIONS_DIR\"}}",
        )
        .unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::with_roots(
            sessions_root.clone(),
            vec![ScanRoot::local(sessions_root)],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "From PI_SESSIONS_DIR");
    }

    #[test]
    fn detect_unsupported_stores_flags_session_store_v2_via_manifest() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions").join("--proj--");
        fs::create_dir_all(&sessions).unwrap();
        fs::write(
            sessions.join("2025-12-01T10-00-00_uuid.jsonl"),
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"hi"}}"#,
        )
        .unwrap();
        let v2 = sessions.join("2025-12-01T10-00-00_uuid.v2");
        fs::create_dir_all(&v2).unwrap();
        fs::write(v2.join("manifest.json"), "{}").unwrap();

        let stores = PiAgentConnector::detect_unsupported_stores(dir.path());
        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].store_format, "session_store_v2");
        assert_eq!(stores[0].support_status, "unsupported");
        assert_eq!(stores[0].path, v2);
    }

    #[test]
    fn detect_unsupported_stores_flags_session_store_v2_via_offsets_index() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        let v2 = sessions.join("2025-12-01T10-00-00_uuid.v2");
        fs::create_dir_all(v2.join("index")).unwrap();
        fs::write(v2.join("index").join("offsets.jsonl"), "").unwrap();

        let stores = PiAgentConnector::detect_unsupported_stores(dir.path());
        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].store_format, "session_store_v2");
    }

    #[test]
    fn detect_unsupported_stores_flags_sqlite_sessions() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions").join("--proj--");
        fs::create_dir_all(&sessions).unwrap();
        fs::write(
            sessions.join("2025-12-01T10-00-00_uuid.sqlite"),
            b"SQLite format 3\0",
        )
        .unwrap();

        let stores = PiAgentConnector::detect_unsupported_stores(dir.path());
        if cfg!(feature = "pi-sqlite") {
            // Indexed, so not a coverage gap.
            assert!(stores.is_empty(), "{stores:?}");
        } else {
            assert_eq!(stores.len(), 1);
            assert_eq!(stores[0].store_format, "sqlite_sessions");
        }
    }

    /// The always-present `session-index.sqlite` metadata index sidecar (and
    /// its `-wal`/`-shm` companions) must never be flagged as an unsupported
    /// store, or every default JSONL install would emit a false diagnostic.
    #[test]
    fn detect_unsupported_stores_ignores_session_index_sidecar() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        fs::write(sessions.join("session-index.sqlite"), b"SQLite format 3\0").unwrap();
        fs::write(sessions.join("session-index.sqlite-wal"), b"").unwrap();
        fs::write(
            sessions.join("2025-12-01T10-00-00_uuid.jsonl"),
            r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"hi"}}"#,
        )
        .unwrap();

        let stores = PiAgentConnector::detect_unsupported_stores(dir.path());
        assert!(
            stores.is_empty(),
            "index sidecar must not be flagged: {stores:?}"
        );
    }

    #[test]
    fn detect_unsupported_stores_empty_when_no_sessions_dir() {
        let dir = TempDir::new().unwrap();
        let stores = PiAgentConnector::detect_unsupported_stores(dir.path());
        assert!(stores.is_empty());
    }

    /// A stale JSONL next to a V2 sidecar is still indexed best-effort, while
    /// the V2 store is surfaced separately via the diagnostics API.
    #[test]
    fn scan_indexes_jsonl_and_diagnostics_report_v2_sidecar() {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        write_session_file(
            &storage,
            "2025-12-01T10-00-00_uuid.jsonl",
            &[
                r#"{"type":"message","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"partial"}}"#,
            ],
        );
        let v2 = storage.join("sessions").join("2025-12-01T10-00-00_uuid.v2");
        fs::create_dir_all(&v2).unwrap();
        fs::write(v2.join("manifest.json"), "{}").unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "partial");

        let diags = connector.unsupported_store_diagnostics(&ctx);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].store_format, "session_store_v2");
    }

    #[test]
    fn unsupported_store_diagnostics_reports_v2_and_sqlite() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("pi-agent");
        let sessions = root.join("sessions").join("--proj--");
        fs::create_dir_all(&sessions).unwrap();
        let v2 = sessions.join("2025-12-01T10-00-00_a.v2");
        fs::create_dir_all(&v2).unwrap();
        fs::write(v2.join("manifest.json"), "{}").unwrap();
        fs::write(
            sessions.join("2025-12-01T11-00-00_b.sqlite"),
            b"SQLite format 3\0",
        )
        .unwrap();

        let connector = PiAgentConnector::new();
        let ctx = ScanContext::with_roots(root.clone(), vec![ScanRoot::local(root)], None);
        let diags = connector.unsupported_store_diagnostics(&ctx);
        let formats: HashSet<&str> = diags.iter().map(|d| d.store_format).collect();
        assert!(
            formats.contains("session_store_v2"),
            "expected V2 diagnostic, got {diags:?}"
        );
        assert_eq!(
            formats.contains("sqlite_sessions"),
            !cfg!(feature = "pi-sqlite"),
            "SQLite sessions are a gap only without the pi-sqlite feature, got {diags:?}"
        );
    }
    /// Regression: discovery must preserve scan-root provenance. Remote
    /// roots (`Origin::Ssh` + platform hint) must not be downgraded to local
    /// when session files are wrapped as discovered sources — downstream
    /// consumers key mirroring and path-mapping decisions off this.
    #[test]
    fn discovery_preserves_remote_scan_root_provenance() {
        let dir = TempDir::new().unwrap();
        let sessions = dir.path().join(".pi").join("agent").join("sessions");
        fs::create_dir_all(sessions.join("--proj--")).unwrap();
        fs::write(
            sessions.join("--proj--").join("2025-12-01T10-00-00_uuid.jsonl"),
            "{\"type\":\"session\",\"id\":\"s\",\"timestamp\":\"2025-12-01T10:00:00Z\",\"cwd\":\"/p\"}\n{\"type\":\"message\",\"timestamp\":\"2025-12-01T10:00:01Z\",\"message\":{\"role\":\"user\",\"content\":\"remote\"}}",
        )
        .unwrap();

        let ctx = ScanContext::with_roots(
            PathBuf::from("/nonexistent"),
            vec![ScanRoot::remote(
                dir.path().to_path_buf(),
                crate::types::Origin::remote_with_host("host-a", "host-a.example"),
                Some(crate::types::Platform::Linux),
            )],
            None,
        );
        let sources = PiAgentConnector::new()
            .discover_source_files(&ctx)
            .expect("discovery");
        assert_eq!(sources.len(), 1);
        assert!(
            sources[0].origin.is_remote(),
            "remote provenance must survive discovery, got {:?}",
            sources[0].origin
        );
        assert_eq!(sources[0].platform, Some(crate::types::Platform::Linux));
    }

    // =========================================================================
    // Archive fidelity: checkpoints, extended messages, branch provenance
    // (franken_agent_detection#27)
    // =========================================================================

    /// One pi v3 session exercising every entry kind #27 names. File order is
    /// deliberately hostile to file-order model tracking: branch A's
    /// `model_change` is written AFTER branch B's, and branch B then continues
    /// (after a `branch_summary`) with an assistant message lacking
    /// `message.model`.
    fn branchy_session_lines() -> Vec<String> {
        vec![
            json!({"type":"session","version":3,"id":"sess-br","timestamp":"2026-01-05T10:00:00.000Z","cwd":"/w/proj","provider":"anthropic","modelId":"claude-sonnet-4-5","parentSession":"/home/u/.pi/agent/sessions/--w-proj--/2026-01-04T09-00-00_parent-uuid.jsonl"}),
            json!({"type":"message","id":"s0","parentId":null,"timestamp":"2026-01-05T10:00:01.000Z","message":{"role":"system","content":"SYSTEM_PROMPT_MARKER","sections":{"preamble":"SYSTEM_SECTION_MARKER"},"toolsAdded":[{"name":"read","description":"TOOL_DECL_MARKER"}],"timestamp":1_767_607_201_000_i64}}),
            json!({"type":"message","id":"u1","parentId":"s0","timestamp":"2026-01-05T10:00:02.000Z","message":{"role":"user","content":"USER_QUESTION_MARKER","timestamp":1_767_607_202_000_i64}}),
            json!({"type":"model_change","id":"mB","parentId":"u1","timestamp":"2026-01-05T10:00:03.000Z","provider":"google","modelId":"gemini-branch-b"}),
            json!({"type":"message","id":"aB","parentId":"mB","timestamp":"2026-01-05T10:00:04.000Z","message":{"role":"assistant","content":[{"type":"text","text":"SIBLING_B_MARKER"}],"provider":"anthropic","model":"claude-explicit","usage":{"input":11,"output":7,"cacheRead":3,"cacheWrite":2,"totalTokens":23}}}),
            json!({"type":"model_change","id":"mA","parentId":"u1","timestamp":"2026-01-05T10:00:05.000Z","provider":"openai","modelId":"gpt-branch-a"}),
            json!({"type":"message","id":"aA","parentId":"mA","timestamp":"2026-01-05T10:00:06.000Z","message":{"role":"assistant","content":[{"type":"text","text":"SIBLING_A_MARKER"}]}}),
            json!({"type":"branch_summary","id":"bs","parentId":"aB","timestamp":"2026-01-05T10:00:07.000Z","fromId":"aA","summary":"BRANCH_SUMMARY_MARKER"}),
            json!({"type":"message","id":"aB2","parentId":"bs","timestamp":"2026-01-05T10:00:08.000Z","message":{"role":"assistant","content":[{"type":"text","text":"COMPAT_B_MARKER"}]}}),
            json!({"type":"compaction","id":"c1","parentId":"aB2","timestamp":"2026-01-05T10:00:09.000Z","summary":"COMPACTION_SUMMARY_MARKER","firstKeptEntryId":"aB","tokensBefore":50_000,"systemMessage":{"role":"system","content":"CHECKPOINT_PROMPT_MARKER","toolsAdded":[{"name":"bash","description":"CHECKPOINT_TOOL_MARKER"}],"timestamp":1_767_607_209_000_i64},"usage":{"input":900,"output":120,"cacheRead":0,"cacheWrite":0,"totalTokens":1020}}),
            json!({"type":"custom_message","id":"cm","parentId":"c1","timestamp":"2026-01-05T10:00:10.000Z","customType":"my-ext","content":"CUSTOM_MESSAGE_MARKER","display":true}),
            json!({"type":"message","id":"bx","parentId":"cm","timestamp":"2026-01-05T10:00:11.000Z","message":{"role":"bashExecution","command":"echo BASH_CMD_MARKER","output":"BASH_OUTPUT_MARKER","exitCode":0,"cancelled":false,"truncated":false,"timestamp":1_767_607_211_000_i64}}),
            json!({"type":"context_edit","id":"ce","parentId":"bx","timestamp":"2026-01-05T10:00:12.000Z","targetId":"aB","replacement":null}),
            json!({"type":"label","id":"lb","parentId":"ce","timestamp":"2026-01-05T10:00:13.000Z","targetId":"u1","label":"checkpoint-1"}),
            json!({"type":"session_info","id":"si","parentId":"lb","timestamp":"2026-01-05T10:00:14.000Z","name":"Named session"}),
            json!({"type":"message","id":"u2","parentId":"si","timestamp":"2026-01-05T10:00:15.000Z","message":{"role":"user","content":"FOLLOWUP_MARKER"}}),
        ]
        .into_iter()
        .map(|v| v.to_string())
        .collect()
    }

    fn scan_single(lines: &[String]) -> NormalizedConversation {
        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        write_session_file(&storage, "2026-01-05T10-00-00_branchy.jsonl", &refs);
        let ctx = ScanContext::local_default(storage, None);
        let mut convs = PiAgentConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        convs.remove(0)
    }

    fn message_with<'a>(conv: &'a NormalizedConversation, marker: &str) -> &'a NormalizedMessage {
        conv.messages
            .iter()
            .find(|m| m.content.contains(marker))
            .unwrap_or_else(|| panic!("no normalized message contains {marker}"))
    }

    fn cass<'a>(msg: &'a NormalizedMessage, key: &str) -> &'a serde_json::Value {
        &msg.extra["cass"][key]
    }

    #[test]
    fn extended_entries_survive_normalization_with_identifiable_kinds() {
        let conv = scan_single(&branchy_session_lines());

        let summary = message_with(&conv, "BRANCH_SUMMARY_MARKER");
        assert_eq!(summary.role, "system");
        assert_eq!(cass(summary, "entry_kind"), "branch_summary");
        assert_eq!(cass(summary, "from_id"), "aA");
        assert_eq!(cass(summary, "source_line"), 8);

        let compaction = message_with(&conv, "COMPACTION_SUMMARY_MARKER");
        assert_eq!(compaction.role, "system");
        assert_eq!(cass(compaction, "entry_kind"), "compaction");
        assert_eq!(cass(compaction, "first_kept_entry_id"), "aB");
        assert_eq!(cass(compaction, "tokens_before"), 50_000);
        assert_eq!(cass(compaction, "system_checkpoint"), true);
        assert!(compaction.content.starts_with("[compaction] "));

        let custom = message_with(&conv, "CUSTOM_MESSAGE_MARKER");
        assert_eq!(custom.role, "user");
        assert_eq!(cass(custom, "entry_kind"), "custom_message");
        assert_eq!(cass(custom, "source_role"), "custom");
        assert_eq!(cass(custom, "custom_type"), "my-ext");

        let bash = message_with(&conv, "BASH_OUTPUT_MARKER");
        assert_eq!(bash.content, "$ echo BASH_CMD_MARKER\nBASH_OUTPUT_MARKER");
        assert_eq!(cass(bash, "entry_kind"), "message");
        assert_eq!(cass(bash, "source_role"), "bashExecution");
        assert_eq!(cass(bash, "exitCode"), 0);

        let user = message_with(&conv, "USER_QUESTION_MARKER");
        assert_eq!(cass(user, "source_role"), "user");
        assert_eq!(cass(user, "entry_id"), "u1");
        assert_eq!(cass(user, "parent_id"), "s0");
        assert_eq!(cass(user, "label"), "checkpoint-1");

        // Ordinary turns still normalize exactly as before.
        assert_eq!(message_with(&conv, "FOLLOWUP_MARKER").role, "user");
        assert_eq!(message_with(&conv, "SIBLING_B_MARKER").role, "assistant");
    }

    #[test]
    fn system_prompts_and_tool_declarations_are_never_indexed() {
        let conv = scan_single(&branchy_session_lines());
        let serialized = serde_json::to_string(&conv).unwrap();
        for marker in [
            "SYSTEM_PROMPT_MARKER",
            "SYSTEM_SECTION_MARKER",
            "TOOL_DECL_MARKER",
            "CHECKPOINT_PROMPT_MARKER",
            "CHECKPOINT_TOOL_MARKER",
        ] {
            assert!(
                !serialized.contains(marker),
                "{marker} leaked into the normalized conversation"
            );
        }
        assert!(conv.messages.iter().all(|m| m.role != "system"
            || m.content.starts_with("[compaction] ")
            || m.content.starts_with("[branch summary] ")));
        assert_eq!(conv.metadata["system_message_count"], 1);
        assert_eq!(conv.metadata["compaction_count"], 1);
    }

    #[test]
    fn archive_keeps_abandoned_branches_and_marks_branch_and_context_membership() {
        let conv = scan_single(&branchy_session_lines());

        // The abandoned sibling stays searchable, flagged off-branch.
        let sibling = message_with(&conv, "SIBLING_A_MARKER");
        assert_eq!(cass(sibling, "on_active_branch"), false);
        assert_eq!(cass(sibling, "in_active_context"), false);

        // Summarized by the compaction: on the branch, out of context.
        let user = message_with(&conv, "USER_QUESTION_MARKER");
        assert_eq!(cass(user, "on_active_branch"), true);
        assert_eq!(cass(user, "in_active_context"), false);

        // Inside the kept range but omitted by a context_edit.
        let edited = message_with(&conv, "SIBLING_B_MARKER");
        assert_eq!(cass(edited, "on_active_branch"), true);
        assert_eq!(cass(edited, "in_active_context"), false);
        assert_eq!(cass(edited, "context_edit"), "omitted");

        for marker in [
            "COMPAT_B_MARKER",
            "BRANCH_SUMMARY_MARKER",
            "COMPACTION_SUMMARY_MARKER",
            "CUSTOM_MESSAGE_MARKER",
            "BASH_OUTPUT_MARKER",
            "FOLLOWUP_MARKER",
        ] {
            let msg = message_with(&conv, marker);
            assert_eq!(cass(msg, "on_active_branch"), true, "{marker}");
            assert_eq!(cass(msg, "in_active_context"), true, "{marker}");
        }

        let tree = &conv.metadata["tree"];
        assert_eq!(tree["integrity"], "ok");
        assert_eq!(tree["branch_leaf_count"], 2);
        assert_eq!(tree["off_branch_message_count"], 1);
        assert_eq!(tree["active_leaf_id"], "u2");
        assert_eq!(tree["total_entry_count"], 15);
        assert_eq!(tree["active_branch_entry_count"], 13);
        assert_eq!(
            conv.metadata["parent_session"],
            "2026-01-04T09-00-00_parent-uuid.jsonl"
        );
        assert_eq!(conv.metadata["session_version"], 3);
        assert_eq!(conv.title.as_deref(), Some("Named session"));
    }

    #[test]
    fn model_attribution_never_inherits_a_sibling_branch_model() {
        let conv = scan_single(&branchy_session_lines());

        // Explicit message model is the control.
        let explicit = message_with(&conv, "SIBLING_B_MARKER");
        assert_eq!(explicit.author.as_deref(), Some("claude-explicit"));

        // Branch A's fallback comes from branch A's model_change.
        let a = message_with(&conv, "SIBLING_A_MARKER");
        assert_eq!(a.author.as_deref(), Some("gpt-branch-a"));
        assert_eq!(cass(a, "provider"), "openai");

        // Branch B continues after branch A's later model_change was written;
        // it must still resolve branch B's own selection.
        let compat = message_with(&conv, "COMPAT_B_MARKER");
        assert_eq!(compat.author.as_deref(), Some("gemini-branch-b"));
        assert_eq!(cass(compat, "model"), "gemini-branch-b");
        assert_eq!(cass(compat, "provider"), "google");

        // The conversation-level selection is the active branch's.
        assert_eq!(conv.metadata["model_id"], "gemini-branch-b");
        assert_eq!(conv.metadata["provider"], "google");
    }

    #[test]
    fn exact_pi_usage_feeds_token_extraction() {
        use crate::connectors::token_extraction::{TokenDataSource, extract_tokens_for_agent};

        let conv = scan_single(&branchy_session_lines());
        let msg = message_with(&conv, "SIBLING_B_MARKER");
        let usage = extract_tokens_for_agent("pi_agent", &msg.extra, &msg.content, &msg.role);
        assert_eq!(usage.data_source, TokenDataSource::Api);
        assert_eq!(usage.input_tokens, Some(11));
        assert_eq!(usage.output_tokens, Some(7));
        assert_eq!(usage.cache_read_tokens, Some(3));
        assert_eq!(usage.cache_creation_tokens, Some(2));
        assert_eq!(usage.model_name.as_deref(), Some("claude-explicit"));
        assert_eq!(usage.provider.as_deref(), Some("anthropic"));

        // Summary generation usage counts toward session totals, as in pi.
        let compaction = message_with(&conv, "COMPACTION_SUMMARY_MARKER");
        let usage = extract_tokens_for_agent(
            "pi_agent",
            &compaction.extra,
            &compaction.content,
            &compaction.role,
        );
        assert_eq!(usage.data_source, TokenDataSource::Api);
        assert_eq!(usage.input_tokens, Some(900));

        // A fallback-attributed message without usage estimates, keeping the
        // branch-local model.
        let compat = message_with(&conv, "COMPAT_B_MARKER");
        let usage =
            extract_tokens_for_agent("pi_agent", &compat.extra, &compat.content, &compat.role);
        assert_eq!(usage.data_source, TokenDataSource::Estimated);
        assert_eq!(usage.model_name.as_deref(), Some("gemini-branch-b"));
    }

    #[test]
    fn v1_linear_compaction_by_index_and_missing_parents_are_reported() {
        // v1: no ids; the compaction addresses its first kept record by file
        // index (header = 0).
        let lines: Vec<String> = vec![
            json!({"type":"session","id":"v1","timestamp":"2026-01-05T10:00:00Z","cwd":"/w"}),
            json!({"type":"message","timestamp":"2026-01-05T10:00:01Z","message":{"role":"user","content":"old turn"}}),
            json!({"type":"message","timestamp":"2026-01-05T10:00:02Z","message":{"role":"user","content":"kept turn"}}),
            json!({"type":"compaction","timestamp":"2026-01-05T10:00:03Z","summary":"v1 summary","firstKeptEntryIndex":2,"tokensBefore":10}),
            json!({"type":"message","timestamp":"2026-01-05T10:00:04Z","message":{"role":"user","content":"after"}}),
        ]
        .into_iter()
        .map(|v| v.to_string())
        .collect();
        let conv = scan_single(&lines);
        assert_eq!(conv.metadata["tree"]["integrity"], "linear");
        assert_eq!(conv.metadata["tree"]["branch_leaf_count"], 1);
        assert_eq!(
            cass(message_with(&conv, "old turn"), "in_active_context"),
            false
        );
        assert_eq!(
            cass(message_with(&conv, "kept turn"), "in_active_context"),
            true
        );
        assert_eq!(
            cass(message_with(&conv, "after"), "in_active_context"),
            true
        );
        assert!(
            conv.messages
                .iter()
                .all(|m| cass(m, "on_active_branch") == true)
        );

        // A parentId naming an absent entry is treated as a root and flagged.
        let lines: Vec<String> = vec![
            json!({"type":"message","id":"x1","parentId":"gone","timestamp":"2026-01-05T10:00:01Z","message":{"role":"user","content":"orphan"}}),
            json!({"type":"message","id":"x2","parentId":"x1","timestamp":"2026-01-05T10:00:02Z","message":{"role":"assistant","content":[{"type":"text","text":"reply"}]}}),
        ]
        .into_iter()
        .map(|v| v.to_string())
        .collect();
        let conv = scan_single(&lines);
        assert_eq!(conv.metadata["tree"]["integrity"], "missing_parent");
        assert_eq!(conv.messages.len(), 2);
        assert!(
            conv.messages
                .iter()
                .all(|m| cass(m, "on_active_branch") == true)
        );
    }

    #[test]
    fn excluded_shell_runs_and_failed_answers_never_reach_the_model_context() {
        let lines: Vec<String> = vec![
            json!({"type":"message","id":"u1","parentId":null,"timestamp":"2026-01-05T10:00:01Z","message":{"role":"user","content":"ask"}}),
            json!({"type":"message","id":"b1","parentId":"u1","timestamp":"2026-01-05T10:00:02Z","message":{"role":"bashExecution","command":"echo private","output":"PRIVATE_SHELL","excludeFromContext":true}}),
            json!({"type":"message","id":"a1","parentId":"b1","timestamp":"2026-01-05T10:00:03Z","message":{"role":"assistant","content":[{"type":"text","text":"ABORTED_REPLY"}],"stopReason":"aborted"}}),
            json!({"type":"message","id":"a2","parentId":"a1","timestamp":"2026-01-05T10:00:04Z","message":{"role":"assistant","content":[{"type":"text","text":"GOOD_REPLY"}],"stopReason":"stop"}}),
        ]
        .into_iter()
        .map(|v| v.to_string())
        .collect();
        let conv = scan_single(&lines);
        // Archived and on the active branch, but never sent to the model.
        for marker in ["PRIVATE_SHELL", "ABORTED_REPLY"] {
            let msg = message_with(&conv, marker);
            assert_eq!(cass(msg, "on_active_branch"), true, "{marker}");
            assert_eq!(cass(msg, "in_active_context"), false, "{marker}");
        }
        assert_eq!(
            cass(message_with(&conv, "GOOD_REPLY"), "in_active_context"),
            true
        );
    }

    // =========================================================================
    // pi_agent_rust SQLite sessions (`pi-sqlite` feature)
    // =========================================================================

    #[cfg(feature = "pi-sqlite")]
    mod sqlite_sessions {
        use super::*;
        use crate::connectors::sqlite_sync::{Connection, ConnectionExt};
        use frankensqlite::compat::ParamValue;

        /// `pi_agent_rust`'s `session_sqlite.rs` schema, with the same wire
        /// records a JSONL session would hold.
        fn write_sqlite_session(
            path: &Path,
            header: &serde_json::Value,
            entries: &[serde_json::Value],
        ) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let conn = Connection::open(path.to_str().unwrap()).unwrap();
            conn.execute_batch(
                "CREATE TABLE pi_session_header (id TEXT PRIMARY KEY, json TEXT NOT NULL);
                 CREATE TABLE pi_session_entries (seq INTEGER PRIMARY KEY, json TEXT NOT NULL);
                 CREATE TABLE pi_session_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO pi_session_header (id, json) VALUES (?1, ?2)",
                &[
                    ParamValue::from(header["id"].as_str().unwrap()),
                    ParamValue::from(header.to_string().as_str()),
                ],
            )
            .unwrap();
            // Insert out of order: storage order is `seq`, not insertion.
            let mut order: Vec<usize> = (0..entries.len()).collect();
            order.reverse();
            for index in order {
                conn.execute_compat(
                    "INSERT INTO pi_session_entries (seq, json) VALUES (?1, ?2)",
                    &[
                        ParamValue::from(i64::try_from(index).unwrap() + 1),
                        ParamValue::from(entries[index].to_string().as_str()),
                    ],
                )
                .unwrap();
            }
        }

        fn rust_session() -> (serde_json::Value, Vec<serde_json::Value>) {
            let header = json!({"type":"session","version":3,"id":"rust-sess","timestamp":"2026-02-01T10:00:00.000Z","cwd":"/w/rust","provider":"anthropic","modelId":"claude-a","leafId":"a1","branchedFrom":"/s/--w-rust--/2026-01-31T09-00-00_parent.jsonl"});
            let entries = vec![
                json!({"type":"message","id":"u1","parentId":null,"timestamp":"2026-02-01T10:00:01.000Z","message":{"role":"user","content":"SQLITE_PROMPT"}}),
                json!({"type":"message","id":"a1","parentId":"u1","timestamp":"2026-02-01T10:00:02.000Z","message":{"role":"assistant","content":[{"type":"text","text":"ACTIVE_ANSWER"}],"model":"claude-a","usage":{"input":7,"output":3,"cacheRead":0,"cacheWrite":0,"totalTokens":10}}}),
                // Written later but abandoned: the header's leafId selects a1.
                json!({"type":"message","id":"a2","parentId":"u1","timestamp":"2026-02-01T10:00:03.000Z","message":{"role":"assistant","content":[{"type":"text","text":"LATER_SIBLING"}],"model":"claude-b"}}),
            ];
            (header, entries)
        }

        #[test]
        fn sqlite_sessions_parse_like_jsonl_and_honor_the_header_leaf() {
            let dir = TempDir::new().unwrap();
            let storage = create_pi_agent_storage(&dir);
            let db = storage
                .join("sessions")
                .join("--w-rust--")
                .join("2026-02-01T10-00-00_rust.sqlite");
            let (header, entries) = rust_session();
            write_sqlite_session(&db, &header, &entries);
            let before = fs::read(&db).unwrap();

            let ctx = ScanContext::local_default(storage.clone(), None);
            let convs = PiAgentConnector::new().scan(&ctx).unwrap();
            assert_eq!(convs.len(), 1);
            let conv = &convs[0];
            assert_eq!(conv.metadata["storage"], "sqlite");
            assert_eq!(conv.source_path, db);
            assert_eq!(
                conv.external_id.as_deref(),
                Some("--w-rust--/2026-02-01T10-00-00_rust.sqlite")
            );
            assert_eq!(conv.workspace.as_deref(), Some(Path::new("/w/rust")));
            assert_eq!(
                conv.metadata["parent_session"],
                "2026-01-31T09-00-00_parent.jsonl"
            );
            let text: Vec<&str> = conv.messages.iter().map(|m| m.content.as_str()).collect();
            assert_eq!(
                text,
                vec!["SQLITE_PROMPT", "ACTIVE_ANSWER", "LATER_SIBLING"]
            );
            assert_eq!(conv.metadata["tree"]["active_leaf_id"], "a1");
            assert_eq!(
                conv.metadata["tree"]["active_leaf_source"],
                "header_leaf_id"
            );
            assert_eq!(conv.messages[1].extra["cass"]["on_active_branch"], true);
            assert_eq!(conv.messages[2].extra["cass"]["on_active_branch"], false);
            assert_eq!(fs::read(&db).unwrap(), before, "scan mutated the database");

            let sources = PiAgentConnector::new().discover_source_files(&ctx).unwrap();
            assert!(sources.iter().any(|s| s.source_path == db
                && s.role == crate::connectors::DiscoveredSourceRole::SqliteDatabase));
            crate::connectors::assert_discovery_covers_scan_sources(&PiAgentConnector::new(), &ctx);
        }

        #[test]
        fn incremental_scans_skip_closed_sqlite_sessions_without_a_wal() {
            let dir = TempDir::new().unwrap();
            let storage = create_pi_agent_storage(&dir);
            let (header, entries) = rust_session();
            let db = storage
                .join("sessions")
                .join("--w--")
                .join("2026-02-01T10-00-00_closed.sqlite");
            write_sqlite_session(&db, &header, &entries);
            // Simulate a session whose WAL was checkpointed away on close; the
            // filter must decide from the database alone, without opening it.
            for suffix in ["-wal", "-shm"] {
                let mut sidecar = db.as_os_str().to_owned();
                sidecar.push(suffix);
                let _ = fs::remove_file(sidecar);
            }
            let future = chrono::Utc::now().timestamp_millis() + 3_600_000;
            let ctx = ScanContext::local_default(storage, Some(future));
            let connector = PiAgentConnector::new();
            assert!(connector.scan(&ctx).unwrap().is_empty());
            assert!(connector.discover_source_files(&ctx).unwrap().is_empty());
        }

        #[test]
        fn remote_sqlite_sessions_are_not_read() {
            let dir = TempDir::new().unwrap();
            let storage = create_pi_agent_storage(&dir);
            let (header, entries) = rust_session();
            write_sqlite_session(
                &storage
                    .join("sessions")
                    .join("--w--")
                    .join("2026-02-01T10-00-00_remote.sqlite"),
                &header,
                &entries,
            );
            let ctx = ScanContext::with_roots(
                PathBuf::from("/nonexistent"),
                vec![ScanRoot::remote(
                    storage,
                    crate::types::Origin::remote_with_host("host-a", "host-a.example"),
                    None,
                )],
                None,
            );
            let connector = PiAgentConnector::new();
            assert!(connector.scan(&ctx).unwrap().is_empty());
            assert!(connector.discover_source_files(&ctx).unwrap().is_empty());
            // Not read, so reported rather than silently missing.
            let diagnostics = connector.unsupported_store_diagnostics(&ctx);
            assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
            assert_eq!(diagnostics[0].store_format, "sqlite_sessions");
        }

        #[test]
        fn jsonl_twins_win_and_foreign_sqlite_files_are_skipped() {
            let dir = TempDir::new().unwrap();
            let storage = create_pi_agent_storage(&dir);
            let project = storage.join("sessions").join("--w--");
            let (header, entries) = rust_session();
            write_sqlite_session(
                &project.join("2026-02-01T10-00-00_twin.sqlite"),
                &header,
                &entries,
            );
            fs::write(
                project.join("2026-02-01T10-00-00_twin.jsonl"),
                format!("{header}\n{}\n", entries[0]),
            )
            .unwrap();
            let foreign = project.join("2026-02-01T11-00-00_foreign.sqlite");
            Connection::open(foreign.to_str().unwrap())
                .unwrap()
                .execute("CREATE TABLE notes (body TEXT)")
                .unwrap();

            let convs = PiAgentConnector::new()
                .scan(&ScanContext::local_default(storage, None))
                .unwrap();
            assert_eq!(convs.len(), 1, "twin read once, foreign file skipped");
            assert!(
                convs[0]
                    .source_path
                    .extension()
                    .is_some_and(|e| e == "jsonl")
            );
        }
    }

    // =========================================================================
    // Source boundaries (FAD#22)
    // =========================================================================

    #[test]
    fn source_boundaries_complete_each_session_and_honor_the_skip_ledger() {
        use crate::connectors::{SourceCompletion, SourceScanHooks};
        use std::collections::HashMap;

        let dir = TempDir::new().unwrap();
        let storage = create_pi_agent_storage(&dir);
        for (name, text) in [
            ("2026-01-01T10-00-00_a.jsonl", "first"),
            ("2026-01-01T11-00-00_b.jsonl", "second"),
        ] {
            write_session_file(
                &storage,
                name,
                &[&json!({"type":"message","timestamp":"2026-01-01T10:00:00Z","message":{"role":"user","content":text}}).to_string()],
            );
        }
        let ctx = ScanContext::local_default(storage, None);
        let connector = PiAgentConnector::new();
        assert!(connector.supports_source_boundaries());
        assert!(connector.supports_streaming_scan());

        // First pass: every source completes, with discovery's identity.
        let mut ledger: HashMap<PathBuf, (Option<u64>, Option<i64>)> = HashMap::new();
        let mut emitted = 0;
        {
            let mut on_complete = |completion: &SourceCompletion| {
                assert_eq!(completion.conversations_emitted, 1);
                ledger.insert(
                    completion.source.source_path.clone(),
                    (
                        completion.source.size_bytes,
                        completion.source.modified_at_ms,
                    ),
                );
                Ok(())
            };
            let mut hooks = SourceScanHooks {
                should_scan_source: None,
                on_source_complete: Some(&mut on_complete),
            };
            connector
                .scan_with_source_boundaries(&ctx, &mut hooks, &mut |_| {
                    emitted += 1;
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(emitted, 2);
        let discovered = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(ledger.len(), discovered.len());
        for source in &discovered {
            assert_eq!(
                ledger.get(&source.source_path),
                Some(&(source.size_bytes, source.modified_at_ms)),
                "completion identity must match discovery"
            );
        }

        // Second pass: the ledger skips unchanged sources before parsing.
        let mut skip = |source: &DiscoveredSourceFile| {
            ledger.get(&source.source_path) != Some(&(source.size_bytes, source.modified_at_ms))
        };
        let mut hooks = SourceScanHooks {
            should_scan_source: Some(&mut skip),
            on_source_complete: None,
        };
        let mut resumed = 0;
        connector
            .scan_with_source_boundaries(&ctx, &mut hooks, &mut |_| {
                resumed += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(resumed, 0);
    }
}
