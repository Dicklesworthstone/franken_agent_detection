//! Connector for Oh My Pi (`omp`, <https://omp.sh>).
//!
//! `omp` is a pi-mono derivative coding agent with a native Rust engine. It
//! keeps its session store under a single canonical home — there is no
//! environment-variable override in the CLI itself, so detection and scanning
//! are anchored on:
//!
//! - `~/.omp/agent/sessions/<safe-path>/<timestamp>_<uuid>.jsonl` — main
//!   transcripts, where `<safe-path>` is derived from the working directory
//! - `~/.omp/agent/sessions/<safe-path>/<timestamp>_<uuid>/<AgentName>.jsonl`
//!   — sub-agent transcripts (each a complete session document)
//!
//! The wire format is the pi-mono JSONL store (`session` header, `message`,
//! `model_change`, `thinking_level_change` entries) plus omp-specific `title`
//! entries and bare-`model` `model_change` records; both are handled by the
//! shared pi-family parser in [`super::pi_wire`].

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;

use super::scan::{DiscoveredSourceFile, ScanContext, ScanRoot};
use super::{Connector, franken_detection_for_connector};
use crate::types::{DetectionResult, NormalizedConversation};

pub struct OmpConnector;

impl Default for OmpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl OmpConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Test-accessible derivation of candidate omp agent homes from an
    /// explicit home directory, split out so precedence stays unit-testable
    /// without touching process environment.
    ///
    /// omp pins its store to `~/.omp/agent`; there is no env or config
    /// relocation contract, so the default list is exactly one entry.
    fn default_homes_from(home: Option<&Path>) -> Vec<PathBuf> {
        home.map(|home| vec![home.join(".omp/agent")])
            .unwrap_or_default()
    }

    /// All candidate omp agent home directories in priority order.
    fn default_homes() -> Vec<PathBuf> {
        Self::default_homes_from(dirs::home_dir().as_deref())
    }

    /// True when `path` plausibly names an omp store: either an explicit
    /// `sessions` directory handed over by a caller, or any path carrying
    /// the canonical `.omp` marker.
    fn looks_like_root(path: &Path) -> bool {
        if path.file_name().is_some_and(|n| n == "sessions") {
            return true;
        }
        path.to_str().is_some_and(|s| s.contains(".omp"))
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let is_omp_agent_dir = ctx
            .data_dir
            .to_str()
            .is_some_and(|s| s.contains(".omp/agent"));

        let mut homes: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            if is_omp_agent_dir {
                homes.push(ScanRoot::local(ctx.data_dir.clone()));
            } else {
                homes.extend(Self::default_homes().into_iter().map(ScanRoot::local));
            }
        } else {
            if Self::looks_like_root(&ctx.data_dir) {
                homes.push(ScanRoot::local(ctx.data_dir.clone()));
            }

            for scan_root in &ctx.scan_roots {
                let candidates = [
                    scan_root.path.clone(),
                    scan_root.path.join(".omp/agent"),
                    scan_root.path.join(".omp/agent/sessions"),
                ];
                for candidate in candidates {
                    // Existence gate: string-marker acceptance must not
                    // fabricate phantom roots under unrelated scan roots.
                    if candidate.exists() && Self::looks_like_root(&candidate) {
                        homes.push(scan_root.with_path(candidate));
                    }
                }
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

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let homes: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();
        super::pi_wire::discover_sources(&homes, ctx, "omp")
    }
}

impl Connector for OmpConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("omp").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let homes: Vec<PathBuf> = Self::source_roots(ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();
        super::pi_wire::scan_homes(&homes, ctx, "omp")
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use serde_json::json;
    use std::fs;

    const SESSION_STEM: &str = "2026-08-23T17-54-58-682Z_01a02fc2-ebfa-72f6-af9a-d40ae5078aa4";
    const WORKSPACE_CWD: &str = "/Users/jemanuel/projects/franken_agent_detection";

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let _ = OmpConnector::new();
    }

    #[test]
    fn default_creates_connector() {
        let _ = OmpConnector;
    }

    // =====================================================
    // default_homes Tests
    // =====================================================

    #[test]
    fn default_homes_pin_the_canonical_omp_agent_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(
            OmpConnector::default_homes_from(Some(dir.path())),
            vec![dir.path().join(".omp/agent")]
        );
    }

    #[test]
    fn default_homes_are_empty_without_a_home() {
        assert!(OmpConnector::default_homes_from(None).is_empty());
    }

    // =====================================================
    // looks_like_root / source_roots Tests
    // =====================================================

    #[test]
    fn looks_like_root_accepts_omp_agent_and_sessions_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        fs::create_dir_all(agent.join("sessions")).unwrap();

        assert!(OmpConnector::looks_like_root(&agent));
        assert!(OmpConnector::looks_like_root(&agent.join("sessions")));

        // Unrelated directories are rejected even when they contain a
        // sessions child.
        let other = dir.path().join("claude-home");
        fs::create_dir_all(other.join("sessions")).unwrap();
        assert!(!OmpConnector::looks_like_root(&other));
    }

    #[test]
    fn source_roots_use_default_home_when_ctx_data_dir_is_unrelated() {
        let dir = tempfile::TempDir::new().unwrap();
        let ctx = ScanContext::local_default(dir.path().join("cass-state"), None);
        let roots = OmpConnector::source_roots(&ctx);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].path, dirs::home_dir().unwrap().join(".omp/agent"));
    }

    #[test]
    fn source_roots_prefer_an_omp_shaped_data_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        fs::create_dir_all(&agent).unwrap();

        let ctx = ScanContext::local_default(agent.clone(), None);
        let roots = OmpConnector::source_roots(&ctx);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].path, agent);
    }

    #[test]
    fn source_roots_expand_explicit_scan_roots_to_omp_layouts() {
        let dir = tempfile::TempDir::new().unwrap();

        // Root whose `.omp/agent/sessions` tree must be discovered by
        // expansion (a typical remote-home scan root).
        let nested = dir.path().join("another-home");
        fs::create_dir_all(
            nested
                .join(".omp")
                .join("agent")
                .join("sessions")
                .join("--data-projects-app--"),
        )
        .unwrap();

        let ctx = ScanContext::with_roots(
            dir.path().join("cass-state"),
            vec![ScanRoot::local(nested.clone())],
            None,
        );

        let mut paths: Vec<PathBuf> = OmpConnector::source_roots(&ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();
        paths.sort();

        // Both the agent home and its sessions subtree qualify; scans
        // deduplicate files reached through overlapping roots.
        assert_eq!(
            paths,
            vec![
                nested.join(".omp").join("agent"),
                nested.join(".omp").join("agent").join("sessions"),
            ]
        );
    }

    #[test]
    fn source_roots_accept_a_bare_sessions_dir_as_explicit_root() {
        let dir = tempfile::TempDir::new().unwrap();
        let sessions = dir.path().join("anywhere").join("sessions");
        fs::create_dir_all(sessions.join("--proj--")).unwrap();

        let ctx = ScanContext::with_roots(
            dir.path().join("state"),
            vec![ScanRoot::local(sessions.clone())],
            None,
        );
        let roots = OmpConnector::source_roots(&ctx);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].path, sessions);
    }

    #[test]
    fn source_roots_demote_file_roots_to_their_parent() {
        let dir = tempfile::TempDir::new().unwrap();
        let sessions = dir.path().join(".omp").join("agent").join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        let file_root = sessions.join(format!("{SESSION_STEM}.jsonl"));
        fs::write(&file_root, "{}").unwrap();

        let ctx = ScanContext::with_roots(
            dir.path().join("state"),
            vec![ScanRoot::local(file_root)],
            None,
        );
        let roots = OmpConnector::source_roots(&ctx);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].path, sessions);
    }

    // =====================================================
    // detect() Tests
    // =====================================================

    #[test]
    fn detect_returns_a_result_with_evidence() {
        let connector = OmpConnector::new();
        let detection = connector.detect();
        // On machines without ~/.omp this reports not-found with evidence;
        // on omp hosts it reports detected. Either way franken detection
        // populates the evidence list.
        assert!(!detection.evidence.is_empty());
    }

    // =====================================================
    // scan()/discovery fixture tests (shared wire parser via omp roots)
    // =====================================================

    /// Build a realistic omp session tree under an agent home: workspace slug
    /// directory, a main transcript named `<timestamp>_<uuid>.jsonl`, plus a
    /// sub-agent transcript inside the sibling `<timestamp>_<uuid>/` directory.
    ///
    /// The main transcript exercises the omp wire-format extensions: a
    /// standalone `title` entry and a `model_change` record with the bare
    /// `model` field.
    fn write_omp_fixture(agent_home: &Path) {
        let slug = agent_home
            .join("sessions")
            .join("-projects-franken_agent_detection");
        fs::create_dir_all(slug.join(SESSION_STEM)).unwrap();

        let title_entry = json!({"type":"title","v":1,"title":"Add omp.sh support to project","source":"auto","updatedAt":"2026-08-23T17:57:16.363Z"});
        let header = json!({
            "type": "session",
            "version": 3,
            "id": "01a02fc2-ebfa-72f6-af9a-d40ae5078aa4",
            "timestamp": "2026-08-23T17:54:58.682Z",
            "cwd": WORKSPACE_CWD,
        });
        let model_change = json!({
            "type": "model_change",
            "id": "91857b1f",
            "parentId": null,
            "timestamp": "2026-08-23T17:54:59.232Z",
            "model": "openrouter/stealth/ox-alpha",
        });
        let user_msg = json!({
            "type": "message",
            "id": "8b70814d",
            "parentId": "9d354805",
            "timestamp": "2026-08-23T17:55:17.199Z",
            "message": {"role": "user", "content": [{"type": "text", "text": "Add complete support for omp"}]},
        });
        let assistant_msg = json!({
            "type": "message",
            "id": "cc0c570e",
            "parentId": "32d6f8a6",
            "timestamp": "2026-08-23T17:55:27.407Z",
            "message": {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "Plan the connector"},
                {"type": "toolCall", "id": "fc_123", "name": "read", "arguments": {"path": "README.md"}},
                {"type": "text", "text": "On it."},
            ]},
        });
        let transcript = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            title_entry, header, model_change, user_msg, assistant_msg
        );
        fs::write(slug.join(format!("{SESSION_STEM}.jsonl")), transcript).unwrap();

        // Sub-agent transcript inside the session directory: own session
        // header, single user message, no underscore in its file name.
        let sub_header = json!({
            "type": "session",
            "version": 3,
            "id": "sub-0001",
            "timestamp": "2026-08-23T17:56:00.000Z",
            "cwd": WORKSPACE_CWD,
        });
        let sub_msg = json!({
            "type": "message",
            "id": "m2",
            "timestamp": "2026-08-23T17:56:05.000Z",
            "message": {"role": "user", "content": [{"type": "text", "text": "Sub-agent task"}]},
        });
        fs::write(
            slug.join(SESSION_STEM).join("BenchBatch1.jsonl"),
            format!("{sub_header}\n{sub_msg}\n"),
        )
        .unwrap();
    }

    fn fixture_ctx(agent_home: &Path) -> ScanContext {
        ScanContext::with_roots(
            PathBuf::from("/nonexistent-cass-state"),
            vec![ScanRoot::local(agent_home.to_path_buf())],
            None,
        )
    }

    #[test]
    fn scan_reads_main_and_subagent_transcripts_from_live_store() {
        let Some(real_home) = dirs::home_dir() else {
            return;
        };
        let agent = real_home.join(".omp").join("agent");
        if !agent.join("sessions").exists() {
            // Graceful empty path on machines without omp.
            let ctx = ScanContext::local_default(PathBuf::from("/nonexistent"), None);
            let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
            assert!(convs.is_empty());
            return;
        }

        let ctx = ScanContext::local_default(PathBuf::from("/nonexistent"), None);
        let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
        assert!(
            !convs.is_empty(),
            "live ~/.omp store should yield conversations"
        );
        for conv in &convs {
            assert_eq!(conv.agent_slug, "omp");
            assert!(
                conv.source_path.starts_with(&agent),
                "omp scan must stay inside ~/.omp/agent, got {}",
                conv.source_path.display()
            );
        }
    }

    #[test]
    fn scan_parses_titles_models_and_tool_calls_via_explicit_roots() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        write_omp_fixture(&agent);

        let mut convs = OmpConnector::new()
            .scan(&fixture_ctx(&agent))
            .expect("scan should succeed");
        convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));

        assert_eq!(convs.len(), 2, "main transcript + sub-agent transcript");

        // Main transcript conversation: omp `title` entry wins over the
        // first-user-message fallback.
        let main = convs
            .iter()
            .find(|conv| conv.title.as_deref() == Some("Add omp.sh support to project"))
            .expect("main conversation with title-entry title");
        assert_eq!(main.agent_slug, "omp");
        assert_eq!(main.workspace.as_deref(), Some(Path::new(WORKSPACE_CWD)));
        assert_eq!(
            main.metadata["source"], "omp",
            "metadata must attribute sessions to the omp connector"
        );
        assert_eq!(
            main.metadata["model_id"], "openrouter/stealth/ox-alpha",
            "bare-model model_change entries must update tracked model"
        );
        let roles: Vec<&str> = main.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, vec!["user", "assistant"]);
        let assistant = &main.messages[1];
        assert_eq!(
            assistant.author.as_deref(),
            Some("openrouter/stealth/ox-alpha")
        );
        assert_eq!(assistant.invocations.len(), 1);
        assert_eq!(assistant.invocations[0].name, "read");
        assert_eq!(assistant.invocations[0].call_id.as_deref(), Some("fc_123"));

        // Sub-agent transcript becomes its own conversation.
        let sub = convs
            .iter()
            .find(|conv| conv.messages.iter().any(|m| m.content == "Sub-agent task"))
            .expect("sub-agent conversation");
        assert_eq!(sub.agent_slug, "omp");
        assert!(
            sub.source_path.ends_with("BenchBatch1.jsonl"),
            "sub-agent transcript should be indexed as its own conversation"
        );

        // External ids are sessions-relative paths.
        assert!(
            main.external_id
                .as_deref()
                .is_some_and(|id| id.starts_with("-projects-franken_agent_detection/")),
            "external id should be sessions-relative, got {:?}",
            main.external_id
        );
    }

    #[test]
    fn discovery_matches_scan_sources_on_fixture() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        write_omp_fixture(&agent);

        crate::connectors::assert_discovery_covers_scan_sources(
            &OmpConnector::new(),
            &fixture_ctx(&agent),
        );
    }

    #[test]
    fn scan_respects_since_ts_filtering() {
        let dir = tempfile::TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        write_omp_fixture(&agent);

        // A high-water mark far in the future excludes everything.
        let ctx = ScanContext::with_roots(
            PathBuf::from("/nonexistent"),
            vec![ScanRoot::local(agent)],
            Some(i64::MAX / 2),
        );
        let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
        assert!(convs.is_empty());
    }

    #[test]
    fn scan_handles_missing_and_empty_roots_gracefully() {
        let dir = tempfile::TempDir::new().unwrap();
        // Explicit root without any omp layout yields nothing and no error.
        let empty_root = dir.path().join("not-omp");
        fs::create_dir_all(&empty_root).unwrap();
        let ctx = ScanContext::with_roots(
            dir.path().join("state"),
            vec![ScanRoot::local(empty_root)],
            None,
        );
        let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
        assert!(convs.is_empty());

        // A nonexistent explicit root is equally harmless.
        let ctx = ScanContext::with_roots(
            dir.path().join("state"),
            vec![ScanRoot::local(dir.path().join("missing-root"))],
            None,
        );
        let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
        assert!(convs.is_empty());
    }

    // =====================================================
    // omp-specific wire extensions through the shared parser
    // =====================================================

    #[test]
    fn title_entry_overrides_header_title_and_message_fallback() {
        let parsed = super::super::pi_wire::parse_session_file;
        let dir = tempfile::TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();

        // Title entry present → wins over header title and message text.
        let file = sessions.join("2026-08-23T10-00-00_alpha.jsonl");
        fs::write(
            &file,
            format!(
                "{}\n{}\n{}\n",
                json!({"type":"title","title":"Entry title"}),
                json!({"type":"session","version":3,"id":"x","timestamp":"2026-08-23T10:00:00Z","cwd":"/w","title":"Header title"}),
                json!({"type":"message","timestamp":"2026-08-23T10:00:05Z","message":{"role":"user","content":"User text"}}),
            ),
        )
        .unwrap();
        let conv = parsed(&file, &sessions, "omp").expect("parses");
        assert_eq!(conv.title.as_deref(), Some("Entry title"));

        // No title entry → header title used.
        let file2 = sessions.join("2026-08-23T10-00-01_beta.jsonl");
        fs::write(
            &file2,
            format!(
                "{}\n{}\n",
                json!({"type":"session","version":3,"id":"y","timestamp":"2026-08-23T10:00:00Z","cwd":"/w","title":"Header only"}),
                json!({"type":"message","timestamp":"2026-08-23T10:00:05Z","message":{"role":"user","content":"User text"}}),
            ),
        )
        .unwrap();
        let conv2 = parsed(&file2, &sessions, "omp").expect("parses");
        assert_eq!(conv2.title.as_deref(), Some("Header only"));

        // Neither → first user message line, truncated to 100 chars.
        let long_text = "x".repeat(250);
        let file3 = sessions.join("2026-08-23T10-00-02_gamma.jsonl");
        fs::write(
            &file3,
            format!(
                "{}\n{}\n",
                json!({"type":"session","version":3,"id":"z","timestamp":"2026-08-23T10:00:00Z"}),
                json!({"type":"message","timestamp":"2026-08-23T10:00:05Z","message":{"role":"user","content":long_text}}),
            ),
        )
        .unwrap();
        let conv3 = parsed(&file3, &sessions, "omp").expect("parses");
        assert_eq!(conv3.title.map(|t| t.chars().count()), Some(100));

        // Files without usable messages parse to None.
        let file4 = sessions.join("2026-08-23T10-00-03_delta.jsonl");
        fs::write(&file4, "{\"type\":\"model_change\"}\n").unwrap();
        assert!(parsed(&file4, &sessions, "omp").is_none());
    }

    #[test]
    fn model_change_bare_model_field_updates_tracked_model() {
        let dir = tempfile::TempDir::new().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        let file = sessions.join("2026-08-23T11-00-00_eps.jsonl");
        fs::write(
            &file,
            format!(
                "{}\n{}\n{}\n{}\n",
                json!({"type":"session","version":3,"id":"m","timestamp":"2026-08-23T11:00:00Z","cwd":"/w"}),
                json!({"type":"model_change","timestamp":"2026-08-23T11:00:01Z","provider":"openrouter","modelId":"first-model"}),
                json!({"type":"model_change","timestamp":"2026-08-23T11:00:02Z","model":"second-model"}),
                json!({"type":"message","timestamp":"2026-08-23T11:00:03Z","message":{"role":"assistant","content":[{"type":"text","text":"reply"}]}}),
            ),
        )
        .unwrap();

        let conv =
            super::super::pi_wire::parse_session_file(&file, &sessions, "omp").expect("parses");
        assert_eq!(conv.messages[0].author.as_deref(), Some("second-model"));
        assert_eq!(conv.metadata["model_id"], "second-model");
        assert_eq!(conv.metadata["provider"], "openrouter");
    }
}
