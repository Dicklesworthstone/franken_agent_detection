//! Exercise Pi and Oh My Pi exclusion policy through the real environment reader.
//! Child processes keep environment changes out of the parallel Rust test suite.
#![cfg(feature = "connectors")]

use std::path::{Path, PathBuf};
use std::process::Command;

use franken_agent_detection::connectors::{omp::OmpConnector, pi_agent::PiAgentConnector, pi_wire};
use franken_agent_detection::{Connector, NormalizedConversation, ScanContext, ScanRoot};
use tempfile::TempDir;

const CHILD_ROOT: &str = "FAD_PI_POLICY_TEST_ROOT";
const CHILD_PROVIDER: &str = "FAD_PI_POLICY_TEST_PROVIDER";
const CHILD_MODE: &str = "FAD_PI_POLICY_TEST_MODE";
const CHILD_FILES: &str = "FAD_PI_POLICY_TEST_FILES";
const CHILD_EXPECTED: &str = "FAD_PI_POLICY_TEST_EXPECTED";

struct Fixture {
    root: TempDir,
    provider: &'static str,
    agent: PathBuf,
    files: Vec<PathBuf>,
}

impl Fixture {
    fn new(provider: &'static str) -> Self {
        let root = TempDir::new().unwrap();
        let marker = if provider == "omp" { ".omp" } else { ".pi" };
        let agent = root.path().join(marker).join("agent");
        let sessions = agent.join("sessions");
        let private = sessions.join("private");
        let stem = "2026-09-19T10-00-00_private";
        let files = vec![
            private.join(format!("{stem}.jsonl")),
            private.join(stem).join("worker.jsonl"),
            private.join(format!("{stem}.jsonl-copy.jsonl")),
            sessions.join("private-copy/2026-09-19T11-00-00_sibling.jsonl"),
            sessions.join("public/2026-09-19T12-00-00_public.JSONL"),
        ];
        for (index, path) in files.iter().enumerate() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let header = serde_json::json!({
                "type": "session", "id": format!("fixture-{index}"),
                "timestamp": "2026-09-19T10:00:00Z", "cwd": root.path(),
            });
            let message = serde_json::json!({
                "type": "message", "timestamp": "2026-09-19T10:00:01Z",
                "message": {"role": "user", "content": format!("fixture-{index}")},
            });
            std::fs::write(path, format!("{header}\n{message}\n")).unwrap();
        }
        Self {
            root,
            provider,
            agent,
            files,
        }
    }

    fn run(&self, exclusions: &str, expected_indices: &[usize]) {
        let expected: Vec<_> = expected_indices
            .iter()
            .map(|&index| &self.files[index])
            .collect();
        let expected = serde_json::to_string(&expected).unwrap();
        let files = serde_json::to_string(&self.files).unwrap();
        let before: Vec<_> = self
            .files
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect();
        for mode in [
            "default",
            "home",
            "agent",
            "overlapping",
            "shared-files",
            "shared-tagged",
        ] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "pi_exclusions_child", "--nocapture"])
                .current_dir(self.root.path())
                .env(CHILD_ROOT, self.root.path())
                .env(CHILD_PROVIDER, self.provider)
                .env(CHILD_MODE, mode)
                .env(CHILD_FILES, &files)
                .env(CHILD_EXPECTED, &expected)
                .env("CASS_EXCLUDE_PATHS", exclusions)
                .env("HOME", self.root.path())
                .env("USERPROFILE", self.root.path())
                .env("XDG_DATA_HOME", self.root.path().join("empty-xdg"))
                .env("PI_CODING_AGENT_DIR", &self.agent)
                .env("PI_CODING_AGENT_SESSION_DIR", "")
                .env("PI_SESSIONS_DIR", "")
                .env("OMP_PROFILE", "")
                .env("PI_PROFILE", "")
                .env("PI_CONFIG_DIR", ".omp")
                .output()
                .expect("run isolated Pi exclusion regression");
            assert!(
                output.status.success(),
                "provider={} mode={mode} exclusions={exclusions:?}\nstdout:\n{}\nstderr:\n{}",
                self.provider,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        for (path, original) in self.files.iter().zip(before) {
            assert_eq!(
                std::fs::read(path).unwrap(),
                original,
                "{} was modified",
                path.display(),
            );
        }
    }
}

fn assert_paths(mut actual: Vec<PathBuf>, expected: &[PathBuf]) {
    let mut expected = expected.to_vec();
    actual.sort();
    expected.sort();
    // A duplicate source is a bug; do not hide it with sort + dedup.
    assert_eq!(actual, expected);
}

fn assert_conversations(
    conversations: &[NormalizedConversation],
    expected: &[PathBuf],
    provider: &str,
    all_files: &[PathBuf],
    root: &Path,
) {
    for conversation in conversations {
        let index = all_files
            .iter()
            .position(|path| path == &conversation.source_path)
            .unwrap();
        assert_eq!(conversation.agent_slug, provider);
        assert_eq!(conversation.workspace.as_deref(), Some(root));
        assert_eq!(conversation.messages.len(), 1);
        assert_eq!(conversation.messages[0].content, format!("fixture-{index}"));
        assert_eq!(conversation.messages[0].idx, 0);
        assert_eq!(
            conversation.metadata["session_id"],
            format!("fixture-{index}"),
        );
    }
    assert_paths(
        conversations
            .iter()
            .map(|conversation| conversation.source_path.clone())
            .collect(),
        expected,
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn pi_exclusions_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let provider = dotenvy::var(CHILD_PROVIDER).unwrap();
    let mode = dotenvy::var(CHILD_MODE).unwrap();
    let files: Vec<PathBuf> = serde_json::from_str(&dotenvy::var(CHILD_FILES).unwrap()).unwrap();
    let expected: Vec<PathBuf> =
        serde_json::from_str(&dotenvy::var(CHILD_EXPECTED).unwrap()).unwrap();
    let (connector, slug, marker): (Box<dyn Connector>, &'static str, &str) =
        match provider.as_str() {
            "omp" => (Box::new(OmpConnector::new()), "omp", ".omp"),
            "pi_agent" => (Box::new(PiAgentConnector::new()), "pi_agent", ".pi"),
            other => panic!("unknown provider: {other}"),
        };
    let agent = root.join(marker).join("agent");
    let sessions = agent.join("sessions");
    for since in [None, Some(0), Some(i64::MAX)] {
        let expected = if since == Some(i64::MAX) {
            &[][..]
        } else {
            expected.as_slice()
        };
        let data_dir = root.join("cass-data");
        let paths = match mode.as_str() {
            "default" => Vec::new(),
            "home" => vec![root.clone()],
            "agent" => vec![agent.clone()],
            "overlapping" => vec![agent.clone(), sessions.clone(), root.clone()],
            "shared-files" => files.clone(),
            "shared-tagged" => vec![agent.clone(), sessions.clone()],
            other => panic!("unknown mode: {other}"),
        };
        let ctx = if mode == "default" {
            ScanContext::local_default(data_dir, since)
        } else {
            ScanContext::with_roots(
                data_dir,
                paths.iter().cloned().map(ScanRoot::local).collect(),
                since,
            )
        };
        if mode.starts_with("shared-") {
            assert_paths(
                pi_wire::discover_sources(&ctx.scan_roots, &ctx, slug)
                    .into_iter()
                    .map(|source| source.source_path)
                    .collect(),
                expected,
            );
            let conversations = pi_wire::scan_homes(&paths, &ctx, slug).unwrap();
            assert_conversations(&conversations, expected, slug, &files, &root);
            let tagged: Vec<_> = paths
                .into_iter()
                .map(|path| (path, Some("work".to_string())))
                .collect();
            let conversations = pi_wire::scan_homes_tagged(&tagged, &ctx, slug).unwrap();
            assert_conversations(&conversations, expected, slug, &files, &root);
            assert!(
                conversations
                    .iter()
                    .all(|conversation| conversation.metadata["profile"] == "work")
            );
            continue;
        }
        assert_paths(
            connector
                .discover_source_files(&ctx)
                .unwrap()
                .into_iter()
                .map(|source| source.source_path)
                .collect(),
            expected,
        );
        let collected = connector.scan(&ctx).unwrap();
        assert_conversations(&collected, expected, slug, &files, &root);
        let mut streamed = Vec::new();
        connector
            .scan_with_callback(&ctx, &mut |conversation| {
                streamed.push(conversation);
                Ok(())
            })
            .unwrap();
        assert_conversations(&streamed, expected, slug, &files, &root);
        // The same admitted sources must retain their identity and metadata.
        assert_eq!(
            serde_json::to_value(&collected).unwrap(),
            serde_json::to_value(&streamed).unwrap(),
        );
        if !expected.is_empty() {
            let mut delivered = 0;
            let error = connector
                .scan_with_callback(&ctx, &mut |_| {
                    delivered += 1;
                    anyhow::bail!("sink must still abort")
                })
                .unwrap_err();
            assert_eq!(delivered, 1);
            assert_eq!(error.to_string(), "sink must still abort");
        }
    }
}

#[test]
fn exact_main_session_exclusion_preserves_subagent_and_prefix_sibling() {
    for provider in ["pi_agent", "omp"] {
        let fixture = Fixture::new(provider);
        fixture.run(fixture.files[0].to_str().unwrap(), &[1, 2, 3, 4]);
    }
}

#[test]
fn exact_subagent_exclusion_preserves_main_session() {
    for provider in ["pi_agent", "omp"] {
        let fixture = Fixture::new(provider);
        fixture.run(fixture.files[1].to_str().unwrap(), &[0, 2, 3, 4]);
    }
}

#[test]
fn directory_exclusion_preserves_similarly_named_directory() {
    for provider in ["pi_agent", "omp"] {
        let fixture = Fixture::new(provider);
        fixture.run(
            fixture.files[0].parent().unwrap().to_str().unwrap(),
            &[3, 4],
        );
    }
}

#[test]
fn mixed_delimiters_whitespace_and_crlf_apply_to_both_providers() {
    for provider in ["pi_agent", "omp"] {
        let fixture = Fixture::new(provider);
        let exclusions = format!(
            " , {} ,\r\n {} \n, ",
            fixture.files[0].display(),
            fixture.files[3].display(),
        );
        fixture.run(&exclusions, &[1, 2, 4]);
    }
}

#[test]
fn sessions_agent_and_ancestor_exclusions_suppress_every_source() {
    for provider in ["pi_agent", "omp"] {
        let fixture = Fixture::new(provider);
        for path in [
            fixture.agent.join("sessions"),
            fixture.agent.clone(),
            fixture.root.path().to_path_buf(),
        ] {
            fixture.run(path.to_str().unwrap(), &[]);
        }
    }
}

#[test]
fn empty_and_unrelated_exclusions_preserve_all_sources() {
    for provider in ["pi_agent", "omp"] {
        let fixture = Fixture::new(provider);
        for exclusions in ["", " , \r\n , "] {
            fixture.run(exclusions, &[0, 1, 2, 3, 4]);
        }
        fixture.run(
            fixture.root.path().join("unrelated").to_str().unwrap(),
            &[0, 1, 2, 3, 4],
        );
    }
}
