#![cfg(feature = "connectors")]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use franken_agent_detection::{Connector, Origin, Platform, ScanContext, ScanRoot, VibeConnector};

const TRANSCRIPT: &[u8] = concat!(
    "{\"role\":\"user\",\"content\":\"selected question\",\"timestamp\":1700000000000}\n",
    "{\"role\":\"assistant\",\"content\":\"selected answer\",\"timestamp\":1700000001000}\n"
)
.as_bytes();

fn put(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, TRANSCRIPT).unwrap();
}

fn remote(container: PathBuf, source: &str) -> ScanRoot {
    ScanRoot::remote(
        container,
        Origin::remote_with_host("laptop", "alice@laptop"),
        Some(Platform::Linux),
    )
    .with_mirrored_source_path(source)
}

#[test]
fn selected_vibe_mirrors_keep_full_store_identities_across_copy_layouts() {
    let connector = VibeConnector::new();
    for (selected, relative_file) in [
        ("run-a", "messages.jsonl"),
        ("team-a", "run-a/messages.jsonl"),
        ("team-a/run-a", "messages.jsonl"),
    ] {
        for (slash, retained) in [(false, true), (true, true), (true, false)] {
            let temp = tempfile::tempdir().unwrap();
            let sessions = temp.path().join("native/.vibe/logs/session");
            put(&sessions.join(selected).join(relative_file));
            let local = ScanContext::with_roots(
                temp.path().join("state"),
                vec![ScanRoot::local(sessions)],
                None,
            );
            let expected = connector.scan(&local).unwrap();
            assert_eq!(expected.len(), 1);
            assert_eq!(expected[0].messages.len(), 2);

            let container = temp.path().join("opaque_hash");
            let payload = if retained {
                container.join(Path::new(selected).file_name().unwrap())
            } else {
                container.clone()
            };
            let file = payload.join(relative_file);
            put(&file);
            if retained {
                // An ordinary home-layout fallback would discover this too.
                put(&container.join(".vibe/logs/session/not-selected/messages.jsonl"));
            }
            let source = format!(
                "~/.vibe/logs/session/{selected}{}",
                if slash { "/" } else { "" }
            );
            let root = remote(container, &source);
            let origin = root.origin.clone();
            let ctx =
                ScanContext::with_roots(temp.path().join("state"), vec![root.clone(), root], None);
            let label = format!("{source}, retained={retained}");
            let found = connector.discover_source_files(&ctx).unwrap();
            assert_eq!(found.len(), 1, "{label}");
            assert_eq!(found[0].source_path, file, "{label}");
            assert_eq!(found[0].origin, origin);
            assert_eq!(found[0].platform, Some(Platform::Linux));
            let actual = connector.scan(&ctx).unwrap();
            assert_eq!(actual.len(), 1, "{label}");
            assert_eq!(actual[0].external_id, expected[0].external_id, "{label}");
            assert!(
                actual[0]
                    .external_id
                    .as_deref()
                    .is_some_and(|id| !id.is_empty())
            );
            assert_eq!(actual[0].source_path, file);
            assert_eq!(actual[0].started_at, expected[0].started_at);
            assert_eq!(actual[0].ended_at, expected[0].ended_at);
            assert_eq!(actual[0].messages.len(), expected[0].messages.len());
            for (actual, expected) in actual[0].messages.iter().zip(&expected[0].messages) {
                assert_eq!(actual.role, expected.role);
                assert_eq!(actual.content, expected.content);
            }
            let mut streamed = Vec::new();
            connector
                .scan_with_callback(&ctx, &mut |conversation| {
                    streamed.push(conversation);
                    Ok(())
                })
                .unwrap();
            assert_eq!(streamed.len(), 1);
            assert_eq!(streamed[0].external_id, expected[0].external_id);
            assert_eq!(fs::read(&file).unwrap(), TRANSCRIPT);
            let mut incremental = ctx;
            incremental.since_ts = Some(i64::MAX);
            assert!(
                connector
                    .discover_source_files(&incremental)
                    .unwrap()
                    .is_empty()
            );
            assert!(connector.scan(&incremental).unwrap().is_empty());
        }
    }
}

#[test]
fn independent_selected_subtrees_with_the_same_basename_do_not_collapse_ids() {
    for retained in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let mut roots = Vec::new();
        let mut expected = HashSet::new();
        for team in ["team-a", "team-b"] {
            let container = temp.path().join(team).join("opaque_hash");
            let payload = if retained {
                container.join("run")
            } else {
                container.clone()
            };
            put(&payload.join("messages.jsonl"));
            roots.push(remote(
                container,
                &format!("~/.vibe/logs/session/{team}/run/"),
            ));
            expected.insert(Path::new(team).join("run").to_string_lossy().into_owned());
        }
        let ctx = ScanContext::with_roots(temp.path().join("state"), roots, None);
        let conversations = VibeConnector::new().scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 2);
        let ids: HashSet<_> = conversations
            .into_iter()
            .map(|conversation| conversation.external_id.unwrap())
            .collect();
        assert_eq!(ids, expected);
    }
}

#[test]
fn invalid_owned_subtrees_do_not_fall_back_to_broader_home_layouts() {
    let temp = tempfile::tempdir().unwrap();
    put(&temp
        .path()
        .join(".vibe/logs/session/unselected/messages.jsonl"));
    for source in [
        "~/.vibe/logs/session/../run",
        "~/.vibe/logs/session/./run",
        "~/\n/.vibe/logs/session/run",
        "~/.vibe/logs/session/C:run",
        "~/.vibe/logs/session/missing",
    ] {
        let ctx = ScanContext::with_roots(
            temp.path().join("state"),
            vec![remote(temp.path().to_path_buf(), source)],
            None,
        );
        assert!(
            VibeConnector::new()
                .discover_source_files(&ctx)
                .unwrap()
                .is_empty(),
            "{source}"
        );
        assert!(
            VibeConnector::new().scan(&ctx).unwrap().is_empty(),
            "{source}"
        );
    }
}

#[cfg(unix)]
#[test]
fn selected_vibe_mirrors_reject_linked_containers_and_payloads() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    put(&outside.join("messages.jsonl"));
    let container = temp.path().join("container");
    put(&container.join(".vibe/logs/session/unselected/messages.jsonl"));
    symlink(&outside, container.join("run")).unwrap();
    let alias = temp.path().join("alias");
    symlink(&container, &alias).unwrap();
    for path in [container, alias] {
        let ctx = ScanContext::with_roots(
            temp.path().join("state"),
            vec![remote(path, "~/.vibe/logs/session/run")],
            None,
        );
        assert!(
            VibeConnector::new()
                .discover_source_files(&ctx)
                .unwrap()
                .is_empty()
        );
        assert!(VibeConnector::new().scan(&ctx).unwrap().is_empty());
    }
    assert_eq!(
        fs::read(outside.join("messages.jsonl")).unwrap(),
        TRANSCRIPT
    );
}
