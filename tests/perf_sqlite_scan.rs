//! Release-mode wall-clock harness for the `SQLite` connector path (`OpenCode`
//! 1.x store), used for dependency A/B comparisons. Ignored by default:
//!
//! `cargo test --release --features opencode --test perf_sqlite_scan -- --ignored --nocapture`

#![cfg(feature = "opencode")]

use std::time::{Duration, Instant};

use franken_agent_detection::connectors::sqlite_sync::{Connection, ConnectionExt};
use franken_agent_detection::{Connector, OpenCodeConnector, ScanContext, ScanRoot};
use frankensqlite::params;
use serde_json::json;
use tempfile::TempDir;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[test]
#[ignore = "release-mode performance harness; run explicitly for SQLite scan wall-clock evidence"]
fn perf_scan_opencode_sqlite_store() {
    let sessions = env_usize("FAD_SQLITE_BENCH_SESSIONS", 200);
    let messages = env_usize("FAD_SQLITE_BENCH_MESSAGES", 20);
    let runs = env_usize("FAD_SQLITE_BENCH_RUNS", 7);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("opencode.db");
    let conn = Connection::open(db.to_str().unwrap()).unwrap();
    conn.execute_batch(
        "CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT, title TEXT,
            directory TEXT, time_created INTEGER, time_updated INTEGER);
         CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT,
            time_created INTEGER, time_updated INTEGER);
         CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT,
            data TEXT, time_created INTEGER, time_updated INTEGER);
         BEGIN;",
    )
    .unwrap();
    for s in 0..sessions {
        let sid = format!("ses-{s:05}");
        conn.execute_compat(
            "INSERT INTO session VALUES (?, 'project', ?, '/work', 1700000000000, 1700000000000)",
            params![sid.clone(), format!("title {s}")],
        )
        .unwrap();
        for m in 0..messages {
            let mid = format!("{sid}-msg-{m:04}");
            let role = if m % 2 == 0 { "user" } else { "assistant" };
            let ts = 1_700_000_000_000_i64 + i64::try_from(m).unwrap();
            conn.execute_compat(
                "INSERT INTO message VALUES (?, ?, ?, ?, ?)",
                params![
                    mid.clone(),
                    sid.clone(),
                    json!({"role": role}).to_string(),
                    ts,
                    ts
                ],
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO part VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    format!("{mid}-part"),
                    mid,
                    sid.clone(),
                    json!({"type": "text", "text": format!("bench {role} text {s} {m}")})
                        .to_string(),
                    ts,
                    ts
                ],
            )
            .unwrap();
        }
    }
    conn.execute("COMMIT;").unwrap();
    drop(conn);

    let connector = OpenCodeConnector::new();
    let ctx = ScanContext::with_roots(
        dir.path().join("cass-state"),
        vec![ScanRoot::local(db)],
        None,
    );
    let mut samples: Vec<Duration> = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = Instant::now();
        let conversations = connector.scan(&ctx).unwrap();
        samples.push(start.elapsed());
        assert_eq!(conversations.len(), sessions);
        assert!(conversations.iter().all(|c| c.messages.len() == messages));
    }
    samples.sort();
    let median = samples[samples.len() / 2];
    eprintln!(
        "fad_sqlite_scan sessions={sessions} messages_per_session={messages} runs={runs} \
         median_ms={:.2} min_ms={:.2} max_ms={:.2}",
        median.as_secs_f64() * 1e3,
        samples[0].as_secs_f64() * 1e3,
        samples[samples.len() - 1].as_secs_f64() * 1e3,
    );
}
