#![cfg(feature = "connectors")]
//! The real public connector must not deliver or complete failed reads.

use franken_agent_detection::{
    CodexConnector, Connector, DiscoveredSourceFile, ScanContext, ScanRoot, SourceCompletion,
    SourceScanHooks,
};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::TempDir;

fn record(text: &str) -> String {
    serde_json::json!({"type":"response_item","payload":{"role":"user","content":text}}).to_string()
}

fn fixture(bytes: &[u8]) -> (TempDir, PathBuf, ScanContext) {
    let root = TempDir::new().unwrap();
    let path = root.path().join("rollout-integrity.jsonl");
    std::fs::write(&path, bytes).unwrap();
    let ctx = ScanContext::with_roots(
        root.path().join("cass"),
        vec![ScanRoot::local(path.clone())],
        None,
    );
    (root, path, ctx)
}

fn assert_kind(error: &anyhow::Error, kind: io::ErrorKind) {
    assert_eq!(
        error.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(kind),
        "{error:#}"
    );
}

fn assert_rejected(ctx: &ScanContext, kind: io::ErrorKind) {
    let connector = CodexConnector::new();
    assert_kind(&connector.scan(ctx).unwrap_err(), kind);
    let mut emitted = 0;
    let error = connector
        .scan_with_callback(ctx, &mut |_| {
            emitted += 1;
            Ok(())
        })
        .unwrap_err();
    assert_kind(&error, kind);
    assert_eq!(emitted, 0);
    let mut completed = 0;
    let mut complete = |_: &SourceCompletion| {
        completed += 1;
        Ok(())
    };
    let mut hooks = SourceScanHooks {
        should_scan_source: None,
        on_source_complete: Some(&mut complete),
    };
    let error = connector
        .scan_with_source_boundaries(ctx, &mut hooks, &mut |_| {
            emitted += 1;
            Ok(())
        })
        .unwrap_err();
    assert_kind(&error, kind);
    assert_eq!(emitted, 0);
    assert_eq!(completed, 0);
}

#[test]
fn incomplete_tail_and_invalid_utf8_withhold_all_routes_then_retry() {
    let prefix = format!("{}\n", record("valid prefix"));
    for suffix in [
        &b"{\"type\":\"response_item\""[..],
        &b"\xff\n"[..],
        &b"\xf0\x9f"[..],
    ] {
        let mut bytes = prefix.as_bytes().to_vec();
        bytes.extend_from_slice(suffix);
        let (_root, path, mut ctx) = fixture(&bytes);
        let kind = if suffix.starts_with(b"{") {
            io::ErrorKind::UnexpectedEof
        } else {
            io::ErrorKind::InvalidData
        };
        for since in [None, Some(0)] {
            ctx.since_ts = since;
            assert_rejected(&ctx, kind);
        }
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::write(&path, format!("{prefix}{}", record("complete tail"))).unwrap();
        let mut completed = 0;
        let mut complete = |done: &SourceCompletion| {
            assert_eq!(done.conversations_emitted, 1);
            completed += 1;
            Ok(())
        };
        let mut hooks = SourceScanHooks {
            should_scan_source: None,
            on_source_complete: Some(&mut complete),
        };
        let mut conversations = Vec::new();
        CodexConnector::new()
            .scan_with_source_boundaries(&ctx, &mut hooks, &mut |c| {
                conversations.push(c);
                Ok(())
            })
            .unwrap();
        assert_eq!(completed, 1);
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].messages.len(), 2);
        assert_eq!(conversations[0].messages[1].content, "complete tail");
    }
}

#[test]
fn oversized_rollout_is_rejected_before_its_body_or_progress_callback() {
    let (_root, path, mut ctx) = fixture(b"");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(100 * 1024 * 1024 + 1)
        .unwrap();
    ctx.progress_tick = Some(Arc::new(|| panic!("oversized body must not be read")));
    assert_rejected(&ctx, io::ErrorKind::InvalidData);
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        100 * 1024 * 1024 + 1
    );
}

#[test]
fn snapshot_mutations_fail_before_emission_and_stable_retry_succeeds() {
    for mutation in ["append", "truncate", "replace"] {
        let original = format!("{}\n", record("opened prefix"));
        let (_root, path, mut ctx) = fixture(original.as_bytes());
        let changed = AtomicBool::new(false);
        let changing = path.clone();
        ctx.progress_tick = Some(Arc::new(move || {
            if changed.swap(true, Ordering::Relaxed) {
                return;
            }
            match mutation {
                "append" => {
                    writeln!(
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(&changing)
                            .unwrap(),
                        "{}",
                        record("later append")
                    )
                    .unwrap();
                }
                "truncate" => {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&changing)
                        .unwrap()
                        .set_len(0)
                        .unwrap();
                }
                "replace" => {
                    std::fs::rename(&changing, changing.with_extension("retained")).unwrap();
                    std::fs::write(
                        &changing,
                        format!("{}\n", record("replacement with a different length")),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
        }));
        let mut emitted = 0;
        let mut completed = 0;
        let mut complete = |_: &SourceCompletion| {
            completed += 1;
            Ok(())
        };
        let mut hooks = SourceScanHooks {
            should_scan_source: None,
            on_source_complete: Some(&mut complete),
        };
        let error = CodexConnector::new()
            .scan_with_source_boundaries(&ctx, &mut hooks, &mut |_| {
                emitted += 1;
                Ok(())
            })
            .unwrap_err();
        assert_kind(
            &error,
            if mutation == "truncate" {
                io::ErrorKind::UnexpectedEof
            } else {
                io::ErrorKind::Interrupted
            },
        );
        assert_eq!(emitted, 0);
        assert_eq!(completed, 0);
        ctx.progress_tick = None;
        std::fs::write(&path, original).unwrap();
        let conversations = CodexConnector::new().scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].messages[0].content, "opened prefix");
    }
}

#[test]
fn host_veto_precedes_parsing_and_sink_errors_still_abort() {
    let (_root, path, ctx) = fixture(b"\xff\n");
    let mut visited = 0;
    let mut predicate = |_: &DiscoveredSourceFile| {
        visited += 1;
        false
    };
    let mut complete = |_: &SourceCompletion| panic!("vetoed source cannot complete");
    let mut hooks = SourceScanHooks {
        should_scan_source: Some(&mut predicate),
        on_source_complete: Some(&mut complete),
    };
    CodexConnector::new()
        .scan_with_source_boundaries(&ctx, &mut hooks, &mut |_| {
            panic!("vetoed source cannot emit")
        })
        .unwrap();
    assert_eq!(visited, 1);
    std::fs::write(&path, record("valid")).unwrap();
    let error = CodexConnector::new()
        .scan_with_callback(&ctx, &mut |_| anyhow::bail!("sink failure"))
        .unwrap_err();
    assert_eq!(error.to_string(), "sink failure");
}

#[test]
fn malformed_historical_lines_bom_and_complete_eof_remain_supported() {
    let bytes = format!(
        "\u{feff}{}\r\nnot-json\n\n{}",
        record("first"),
        record("last")
    );
    let (_root, path, ctx) = fixture(bytes.as_bytes());
    let conversations = CodexConnector::new().scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].messages.len(), 2);
    assert_eq!(conversations[0].messages[0].content, "first");
    assert_eq!(conversations[0].messages[1].content, "last");
    assert_eq!(std::fs::read_to_string(path).unwrap(), bytes);
}

#[test]
fn host_tail_recovery_preserves_complete_history_on_all_routes_and_later_appends() {
    let tail = record("completed later");
    let split = tail.len() / 2;
    let bytes = format!("{}\n{}", record("retained complete turn"), &tail[..split]);
    let (_root, path, ctx) = fixture(bytes.as_bytes());
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();
    let connector = CodexConnector::new().with_incomplete_tail_recovery(|source| {
        source
            .file_name()
            .is_some_and(|name| name == "rollout-integrity.jsonl")
    });

    for _ in 0..2 {
        for route in 0..3 {
            let mut conversations = Vec::new();
            let mut completed = 0;
            match route {
                0 => conversations = connector.scan(&ctx).unwrap(),
                1 => connector
                    .scan_with_callback(&ctx, &mut |conversation| {
                        conversations.push(conversation);
                        Ok(())
                    })
                    .unwrap(),
                _ => {
                    let mut complete = |done: &SourceCompletion| {
                        assert_eq!(done.source.source_path, path);
                        assert_eq!(done.conversations_emitted, 1);
                        completed += 1;
                        Ok(())
                    };
                    let mut hooks = SourceScanHooks {
                        should_scan_source: None,
                        on_source_complete: Some(&mut complete),
                    };
                    connector
                        .scan_with_source_boundaries(&ctx, &mut hooks, &mut |conversation| {
                            conversations.push(conversation);
                            Ok(())
                        })
                        .unwrap();
                }
            }
            assert_eq!(conversations.len(), 1, "route {route}");
            assert_eq!(conversations[0].messages.len(), 1, "route {route}");
            assert_eq!(
                conversations[0].messages[0].content,
                "retained complete turn"
            );
            assert_eq!(conversations[0].source_path, path);
            assert_eq!(completed, usize::from(route == 2));
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
        // The opt-in is local to this connector. Other scanners and a host's
        // negative activity decision must retain the strict retry contract.
        assert_rejected(&ctx, io::ErrorKind::UnexpectedEof);
        assert_kind(
            &CodexConnector::new()
                .with_incomplete_tail_recovery(|_| false)
                .scan(&ctx)
                .unwrap_err(),
            io::ErrorKind::UnexpectedEof,
        );
    }

    let mut writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    writer.write_all(&tail.as_bytes()[split..]).unwrap();
    writeln!(writer).unwrap();
    drop(writer);
    let completed = std::fs::read(&path).unwrap();
    let conversations = connector.scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].messages.len(), 2);
    assert_eq!(conversations[0].messages[1].content, "completed later");
    assert_eq!(std::fs::read(&path).unwrap(), completed);
}

#[test]
fn host_tail_recovery_preserves_empty_history_without_inventing_output() {
    let bytes = b"{\"type\":\"session_meta\",\"payload\":{}}\n{\"type\":";
    let (_root, path, ctx) = fixture(bytes);
    let connector = CodexConnector::new().with_incomplete_tail_recovery(|_| true);
    // Keep the existing zero-output boundary contract: recovery must not
    // fabricate a completion that normal metadata-only histories do not emit.
    let mut complete =
        |_: &SourceCompletion| panic!("a zero-output source must not invent a completion");
    let mut hooks = SourceScanHooks {
        should_scan_source: None,
        on_source_complete: Some(&mut complete),
    };
    connector
        .scan_with_source_boundaries(&ctx, &mut hooks, &mut |_| {
            panic!("an incomplete first message must not create a conversation")
        })
        .unwrap();
    assert!(connector.scan(&ctx).unwrap().is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_rejected(&ctx, io::ErrorKind::UnexpectedEof);
}

#[test]
fn host_tail_policy_does_not_relax_utf8_or_run_for_complete_records() {
    let connector = CodexConnector::new().with_incomplete_tail_recovery(|_| {
        panic!("only an incomplete final JSON record may ask for recovery")
    });
    for bytes in [
        format!("{}\nnot-json\n", record("complete")).into_bytes(),
        record("complete without newline").into_bytes(),
    ] {
        let (_root, _path, ctx) = fixture(&bytes);
        assert_eq!(connector.scan(&ctx).unwrap()[0].messages.len(), 1);
    }
    for suffix in [&b"\xff\n"[..], &b"\xf0\x9f"[..]] {
        let mut bytes = format!("{}\n", record("complete")).into_bytes();
        bytes.extend_from_slice(suffix);
        let (_root, _path, ctx) = fixture(&bytes);
        assert_kind(
            &connector.scan(&ctx).unwrap_err(),
            io::ErrorKind::InvalidData,
        );
    }
}

#[test]
fn approved_tail_recovery_still_validates_the_final_source_snapshot() {
    fn append(path: &std::path::Path) -> bool {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path).unwrap(),
            "}}"
        )
        .unwrap();
        true
    }
    fn truncate(path: &std::path::Path) -> bool {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(0)
            .unwrap();
        true
    }
    fn replace(path: &std::path::Path) -> bool {
        std::fs::rename(path, path.with_extension("retained")).unwrap();
        std::fs::write(path, record("replacement")).unwrap();
        true
    }

    for recovery in [append, truncate, replace] {
        let bytes = format!("{}\n{{\"type\":", record("complete"));
        let (_root, _path, ctx) = fixture(bytes.as_bytes());
        let mut complete = |_: &SourceCompletion| panic!("a changed source cannot complete");
        let mut hooks = SourceScanHooks {
            should_scan_source: None,
            on_source_complete: Some(&mut complete),
        };
        let error = CodexConnector::new()
            .with_incomplete_tail_recovery(recovery)
            .scan_with_source_boundaries(&ctx, &mut hooks, &mut |_| {
                panic!("a changed source cannot emit")
            })
            .unwrap_err();
        assert_kind(&error, io::ErrorKind::Interrupted);
    }
}

#[test]
#[cfg(feature = "codex-zstd")]
fn compressed_rollouts_never_use_plain_jsonl_tail_recovery() {
    let connector = CodexConnector::new().with_incomplete_tail_recovery(|_| {
        panic!("a compressed source cannot ask for plain JSONL recovery")
    });
    let bytes = format!("{}\n{{\"type\":", record("complete"));
    let (_root, plain, mut ctx) = fixture(b"");
    let path = plain.with_extension("jsonl.zst");
    ctx.scan_roots = vec![ScanRoot::local(path.clone())];
    let frame = zstd::stream::encode_all(bytes.as_bytes(), 0).unwrap();
    for content in [&frame[..], &frame[..frame.len() - 1]] {
        std::fs::write(&path, content).unwrap();
        assert_kind(
            &connector.scan(&ctx).unwrap_err(),
            io::ErrorKind::UnexpectedEof,
        );
        assert_eq!(std::fs::read(&path).unwrap(), content);
    }
}
