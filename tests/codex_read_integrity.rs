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
