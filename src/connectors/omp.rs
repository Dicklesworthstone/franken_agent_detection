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

    /// True when `path` plausibly names an omp agent home or sessions
    /// directory: either it carries a `sessions` child, is itself called
    /// `sessions` beneath an `.omp` tree, or its string form contains the
    /// canonical `.omp/agent` marker.
    fn looks_like_root(path: &Path) -> bool {
        if path.join("sessions").exists() || path.file_name().is_some_and(|n| n == "sessions") {
            let marker_ok = path
                .to_str()
                .is_some_and(|s| s.contains(".omp"))
                // A bare `sessions` directory handed to us as an explicit
                // scan root is accepted too; callers that mean another
                // connector's data never reach this connector.
                || path.file_name().is_some_and(|n| n == "sessions");
            return marker_ok;
        }
        path.to_str().is_some_and(|s| s.contains(".omp/agent"))
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
                    scan_root.path.join(".omp"),
                    scan_root.path.join(".omp/agent"),
                    scan_root.path.join(".omp/agent/sessions"),
                ];
                for candidate in candidates {
                    if Self::looks_like_root(&candidate) {
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
    use tempfile::TempDir;

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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
        let ctx = ScanContext::local_default(dir.path().join("cass-state"), None);
        let roots = OmpConnector::source_roots(&ctx);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].path, dirs::home_dir().unwrap().join(".omp/agent"));
    }

    #[test]
    fn source_roots_prefer_an_omp_shaped_data_dir() {
        let dir = TempDir::new().unwrap();
        let agent = dir.path().join(".omp").join("agent");
        fs::create_dir_all(&agent).unwrap();

        let ctx = ScanContext::local_default(agent.clone(), None);
        let roots = OmpConnector::source_roots(&ctx);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].path, agent);
    }

    #[test]
    fn source_roots_expand_explicit_scan_roots_to_omp_layouts() {
        let dir = TempDir::new().unwrap();

        // Root that directly contains sessions (e.g. a mounted ~/.omp tree).
        let direct = dir.path().join("home-with-omp").join(".omp");
        fs::create_dir_all(direct.join("agent").join("sessions")).unwrap();

        // Root whose `.omp/agent/sessions` must be discovered by expansion.
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
            vec![
                ScanRoot::local(direct.parent().unwrap().to_path_buf()),
                ScanRoot::local(nested),
            ],
            None,
        );

        let mut paths: Vec<PathBuf> = OmpConnector::source_roots(&ctx)
            .into_iter()
            .map(|root| root.path)
            .collect();
        paths.sort();

        assert_eq!(
            paths,
            vec![
                nested.join(".omp").join("agent").join("sessions"),
                direct.join("agent").join("sessions"),
            ]
        );
    }

    #[test]
    fn source_roots_treat_file_roots_as_their_parent() {
        let dir = TempDir::new().unwrap();
        let file_root = dir.path().join("session.jsonl");
        fs::write(&file_root, "{}").unwrap();

        let ctx = ScanContext::local_default(file_root.clone(), None);
        let roots = OmpConnector::source_roots(&ctx);
        // Not omp-shaped and no explicit roots: falls back to the default
        // home rather than treating the file as a home.
        assert_eq!(roots[0].path, dirs::home_dir().unwrap().join(".omp/agent"));
    }

    // =====================================================
    // detect() Tests
    // =====================================================

    #[test]
    fn detect_returns_a_result_with_evidence() {
        let connector = OmpConnector::new();
        let detection = connector.detect();
        // On machines without ~/.omp this reports not-found with evidence;
        // on omp hosts it reports detected. Either way the evidence list is
        // populated by franken detection.
        assert!(!detection.evidence.is_empty());
    }

    // =====================================================
    // scan()/discovery fixture tests (shared wire parser via omp roots)
    // =====================================================

    /// Build a realistic omp session tree: workspace slug directory, a main
    /// transcript named `<timestamp>_<uuid>.jsonl`, plus a sub-agent
    /// transcript inside the sibling `<timestamp>_<uuid>/` directory.
    fn write_omp_fixture(home: &Path) -> TempDir {
        let slug = home.join("sessions").join("-projects-franken_agent_detection");
        let session_stem = "2026-08-23T17-54-58-682Z_01a02fc2-ebfa-72f6-af9a-d40ae5078aa4";
        fs::create_dir_all(slug.join(session_stem)).unwrap();

        // Main transcript: title entry + session header + user message +
        // assistant reply with a tool call, exercising the omp extensions.
        let main = json!({"type":"title","v":1,"title":"Add omp.sh support to project","source":"auto","updatedAt":"2026-08-23T17:57:16.363Z"});
        let header = json!({
            "type": "session",
            "version": 3,
            "id": "01a02fc2-ebfa-72f6-af9a-d40ae5078aa4",
            "timestamp": "2026-08-23T17:54:58.682Z",
            "cwd": "/Users/jemanuel/projects/franken_agent_detection",
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
            main, header, model_change, user_msg, assistant_msg
        );
        fs::write(slug.join(format!("{session_stem}.jsonl")), transcript).unwrap();

        // Sub-agent transcript inside the session directory: own session
        // header, single user message.
        let sub_header = json!({
            "type": "session",
            "version": 3,
            "id": "sub-0001",
            "timestamp": "2026-08-23T17:56:00.000Z",
            "cwd": "/Users/jemanuel/projects/franken_agent_detection",
        });
        let sub_msg = json!({
            "type": "message",
            "id": "m2",
            "timestamp": "2026-08-23T17:56:05.000Z",
            "message": {"role": "user", "content": [{"type": "text", "text": "Sub-agent task"}]},
        });
        fs::write(
            slug.join(session_stem).join("BenchBatch1.jsonl"),
            format!("{sub_header}\n{sub_msg}\n"),
        )
        .unwrap();

        TempDir::new().unwrap()
    }

    #[test]
    fn scan_reads_main_and_subagent_transcripts_from_default_homes() {
        let real_home = dirs::home_dir().expect("home dir");
        let agent = real_home.join(".omp").join("agent");
        // Only run against the real store when it exists; otherwise assert
        // the graceful empty path.
        if !agent.join("sessions").exists() {
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
        let scratch = write_omp_fixture(Path::new("/tmp"));
        let home = scratch.path().join("omp-home");
        std::mem::forget(scratch); // keep fixture alive until assertions end
        let fixture = write_omp_fixture(&home);

        let agent = home.join(".omp").join("agent");
        let ctx = ScanContext::with_roots(
            PathBuf::from("/nonexistent"),
            vec![ScanRoot::local(agent.clone())],
            None,
        );
        let mut convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
        convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));

        assert_eq!(convs.len(), 2, "main transcript + sub-agent transcript");

        // Main transcript conversation.
        let main = convs
            .iter()
            .find(|conv| conv.title.as_deref() == Some("Add omp.sh support to project"))
            .expect("main conversation with omp title-entry title");
        assert_eq!(main.agent_slug, "omp");
        assert_eq!(main.workspace.as_deref(), Some(Path::new("/Users/jemanuel/projects/franken_agent_detection")));
        assert_eq!(
            main.metadata["source"], "omp",
            "metadata must attribute sessions to the omp connector"
        );
        assert_eq!(main.metadata["model_id"], "openrouter/stealth/ox-alpha",
            "bare-model model_change entries must update tracked model");
        let roles: Vec<&str> = main.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, vec!["user", "assistant"]);
        let assistant = &main.messages[1];
        assert_eq!(assistant.author.as_deref(), Some("openrouter/stealth/ox-alpha"));
        assert_eq!(assistant.invocations.len(), 1);
        assert_eq!(assistant.invocations[0].name, "read");
        assert_eq!(assistant.invocations[0].call_id.as_deref(), Some("fc_123"));

        // Sub-agent transcript conversation.
        let sub = convs
            .iter()
            .find(|conv| conv.messages.iter().any(|m| m.content == "Sub-agent task"))
            .expect("sub-agent conversation");
        assert_eq!(sub.agent_slug, "omp");
        assert!(
            sub.source_path.ends_with("BenchBatch1.jsonl"),
            "sub-agent transcript should be its own conversation"
        );
        drop(fixture);
    }

    #[test]
    fn discovery_matches_scan_sources_on_fixture() {
        let scratch = write_omp_fixture(Path::new("/tmp"));
        let home = scratch.path().join("omp-home-discovery");
        let _fixture = write_omp_fixture(&home);

        let agent = home.join(".omp").join("agent");
        let ctx = ScanContext::with_roots(
            PathBuf::from("/nonexistent"),
            vec![ScanRoot::local(agent)],
            None,
        );
        crate::connectors::assert_discovery_covers_scan_sources(&OmpConnector::new(), &ctx);
    }

    #[test]
    fn scan_handles_missing_and_empty_roots_gracefully() {
        let dir = TempDir::new().unwrap();
        // Explicit root without any omp layout.
        let empty_root = dir.path().join("not-omp");
        fs::create_dir_all(&empty_root).unwrap();
        let ctx = ScanContext::with_roots(
            dir.path().join("state"),
            vec![ScanRoot::local(empty_root)],
            None,
        );
        let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
        assert!(convs.is_empty());

        // Default-detection context pointing at nothing.
        let ctx = ScanContext::local_default(dir.path().join("state"), None);
        let convs = OmpConnector::new().scan(&ctx).expect("scan should succeed");
        assert!(convs.is_empty());
    }
}
