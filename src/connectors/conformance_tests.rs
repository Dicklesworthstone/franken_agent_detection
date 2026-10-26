//! Conformance test harness for `franken-agent-detection`.
//!
//! This module contains systematic tests that verify the implementation
//! against its documented behavioral contracts:
//!
//! 1. **Timestamp Parsing**: All documented timestamp formats must parse correctly
//! 2. **Connector Factory**: All factories must produce valid, functioning connectors
//! 3. **Schema Conformance**: All connectors must produce valid `NormalizedConversation`
//! 4. **Detection Determinism**: Detection must be deterministic with fixture overrides
//! 5. **Path Mapping Equivalence**: `PathTrie` and linear algorithms must produce identical results

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod conformance {
    use crate::connectors::{
        PathTrie, ScanContext, ScanRoot, get_connector_factories, parse_timestamp,
    };
    use crate::types::{NormalizedConversation, NormalizedMessage, PathMapping};
    use crate::{AgentDetectOptions, AgentDetectRootOverride, detect_installed_agents};
    use serde_json::json;
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // =========================================================================
    // Contract 1: Timestamp Parsing Conformance
    // =========================================================================
    //
    // The parse_timestamp function must handle:
    // - i64 milliseconds (>= 100_000_000_000, < 100_000_000_000_000)
    // - i64 seconds (< 100_000_000_000, converted to ms)
    // - i64 microseconds (100_000_000_000_000..=100_000_000_000_000_000,
    //   converted to ms)
    // - f64 milliseconds and seconds
    // - ISO-8601 / RFC-3339 strings
    // - Numeric strings

    mod timestamp_conformance {
        use super::*;

        /// Test case structure for timestamp parsing conformance
        struct TimestampTestCase {
            input: serde_json::Value,
            expected_ms: Option<i64>,
            description: &'static str,
        }

        fn timestamp_test_cases() -> Vec<TimestampTestCase> {
            vec![
                // ---- i64 milliseconds (passthrough) ----
                TimestampTestCase {
                    input: json!(1_700_000_000_000_i64),
                    expected_ms: Some(1_700_000_000_000),
                    description: "i64 milliseconds should pass through unchanged",
                },
                TimestampTestCase {
                    input: json!(1_000_000_000_000_i64),
                    expected_ms: Some(1_000_000_000_000),
                    description: "i64 at millisecond threshold should pass through",
                },
                // ---- i64 seconds (converted to ms) ----
                TimestampTestCase {
                    input: json!(1_700_000_000_i64),
                    expected_ms: Some(1_700_000_000_000),
                    description: "i64 seconds should be converted to milliseconds",
                },
                TimestampTestCase {
                    input: json!(1_i64),
                    expected_ms: Some(1_000),
                    description: "small i64 seconds should be converted to milliseconds",
                },
                TimestampTestCase {
                    input: json!(0_i64),
                    expected_ms: Some(0),
                    description: "zero timestamp should return 0",
                },
                // ---- f64 timestamps ----
                TimestampTestCase {
                    input: json!(1_700_000_000.5_f64),
                    expected_ms: Some(1_700_000_000_500),
                    description: "f64 seconds with fractional part",
                },
                TimestampTestCase {
                    input: json!(1_700_000_000_000.0_f64),
                    expected_ms: Some(1_700_000_000_000),
                    description: "f64 milliseconds should round correctly",
                },
                // ---- ISO-8601 / RFC-3339 strings ----
                TimestampTestCase {
                    input: json!("2023-11-14T00:00:00Z"),
                    expected_ms: Some(1_699_920_000_000),
                    description: "RFC-3339 UTC timestamp",
                },
                TimestampTestCase {
                    input: json!("2023-11-14T00:00:00.123Z"),
                    expected_ms: Some(1_699_920_000_123),
                    description: "RFC-3339 with milliseconds",
                },
                TimestampTestCase {
                    input: json!("2023-11-14T00:00:00+00:00"),
                    expected_ms: Some(1_699_920_000_000),
                    description: "RFC-3339 with explicit +00:00 offset",
                },
                TimestampTestCase {
                    input: json!("2023-11-14T05:00:00+05:00"),
                    expected_ms: Some(1_699_920_000_000),
                    description: "RFC-3339 with non-zero offset",
                },
                // ---- Numeric strings ----
                TimestampTestCase {
                    input: json!("1700000000000"),
                    expected_ms: Some(1_700_000_000_000),
                    description: "numeric string milliseconds",
                },
                TimestampTestCase {
                    input: json!("1700000000"),
                    expected_ms: Some(1_700_000_000_000),
                    description: "numeric string seconds converted to ms",
                },
                TimestampTestCase {
                    input: json!("1700000000.5"),
                    expected_ms: Some(1_700_000_000_500),
                    description: "numeric string with fractional seconds",
                },
                // ---- Invalid inputs ----
                TimestampTestCase {
                    input: json!(null),
                    expected_ms: None,
                    description: "null should return None",
                },
                TimestampTestCase {
                    input: json!("not a timestamp"),
                    expected_ms: None,
                    description: "invalid string should return None",
                },
                TimestampTestCase {
                    input: json!({}),
                    expected_ms: None,
                    description: "object should return None",
                },
                TimestampTestCase {
                    input: json!([]),
                    expected_ms: None,
                    description: "array should return None",
                },
                TimestampTestCase {
                    input: json!(f64::NAN),
                    expected_ms: None,
                    description: "NaN should return None",
                },
                TimestampTestCase {
                    input: json!(f64::INFINITY),
                    expected_ms: None,
                    description: "Infinity should return None",
                },
                // ---- Negative timestamps ----
                // Note: Negative timestamps are passed through as-is (no conversion)
                // This is intentional since negative timestamps are rare and ambiguous
                TimestampTestCase {
                    input: json!(-1_i64),
                    expected_ms: Some(-1),
                    description: "negative i64 passed through unchanged",
                },
            ]
        }

        #[test]
        fn parse_timestamp_conformance_suite() {
            for case in timestamp_test_cases() {
                let result = parse_timestamp(&case.input);
                assert_eq!(
                    result, case.expected_ms,
                    "FAILED: {} - input: {:?}, expected: {:?}, got: {:?}",
                    case.description, case.input, case.expected_ms, result
                );
            }
        }

        #[test]
        fn parse_timestamp_is_deterministic() {
            let inputs = vec![
                json!(1_700_000_000_000_i64),
                json!("2023-11-14T00:00:00Z"),
                json!(1_700_000_000.5_f64),
            ];

            for input in inputs {
                let results: Vec<_> = (0..100).map(|_| parse_timestamp(&input)).collect();
                let first = &results[0];
                assert!(
                    results.iter().all(|r| r == first),
                    "parse_timestamp should be deterministic for {:?}",
                    input
                );
            }
        }
    }

    // =========================================================================
    // Contract 2: Connector Factory Conformance
    // =========================================================================
    //
    // All connector factories must:
    // - Return a valid Connector impl
    // - Have a unique slug
    // - Produce a DetectionResult from detect()

    mod connector_factory_conformance {
        use super::*;

        #[test]
        fn all_factories_produce_valid_connectors() {
            let factories = get_connector_factories();

            assert!(
                !factories.is_empty(),
                "get_connector_factories should return at least one factory"
            );

            for (slug, factory) in &factories {
                let connector = factory();

                // Connector should produce a DetectionResult
                let detection = connector.detect();

                // DetectionResult should have valid structure
                assert!(
                    detection.evidence.len() <= 1000,
                    "connector {} produced too many evidence items",
                    slug
                );
            }
        }

        #[test]
        fn all_factory_slugs_are_unique() {
            let factories = get_connector_factories();
            let slugs: Vec<_> = factories.iter().map(|(slug, _)| *slug).collect();
            let unique_slugs: HashSet<_> = slugs.iter().collect();

            assert_eq!(
                slugs.len(),
                unique_slugs.len(),
                "connector factory slugs must be unique"
            );
        }

        #[test]
        fn all_factory_slugs_are_lowercase_identifier() {
            let factories = get_connector_factories();

            for (slug, _) in factories {
                assert!(!slug.is_empty(), "connector slug should not be empty");
                assert!(
                    slug.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                    "connector slug '{}' should be lowercase with underscores only",
                    slug
                );
            }
        }

        #[test]
        fn crate_root_reexports_all_connector_types_and_helpers() {
            use crate::{
                AiderConnector, AmpConnector, AntigravityConnector, ClaudeCodeConnector,
                ClawdbotConnector, ClineConnector, CodexConnector, Connector, ContinueConnector,
                CopilotCliConnector, CopilotConnector, DevinConnector, FactoryConnector,
                GeminiConnector, GrokConnector, KimiConnector, KiroConnector, MuseConnector,
                NormalizedInvocation, OmpConnector, OpenClawConnector, OpenHandsConnector,
                PiAgentConnector, PiDurableConnector, PrimeAgentConnector, QwenConnector,
                ScanProgressTick, VibeConnector, percent_decode_utf8, unwrap_skill_invocations,
            };

            let core_connectors: Vec<Box<dyn Connector>> = vec![
                Box::new(AiderConnector::new()),
                Box::new(AmpConnector::new()),
                Box::new(AntigravityConnector::new()),
                Box::new(ClaudeCodeConnector::new()),
                Box::new(ClawdbotConnector::new()),
                Box::new(ClineConnector::new()),
                Box::new(CodexConnector::new()),
                Box::new(ContinueConnector::new()),
                Box::new(CopilotConnector::new()),
                Box::new(CopilotCliConnector::new()),
                Box::new(DevinConnector::new()),
                Box::new(FactoryConnector::new()),
                Box::new(GeminiConnector::new()),
                Box::new(GrokConnector::new()),
                Box::new(KimiConnector::new()),
                Box::new(KiroConnector::new()),
                Box::new(MuseConnector::new()),
                Box::new(OmpConnector::new()),
                Box::new(OpenClawConnector::new()),
                Box::new(OpenHandsConnector::new()),
                Box::new(PiAgentConnector::new()),
                Box::new(PiDurableConnector::new()),
                Box::new(PrimeAgentConnector::new()),
                Box::new(QwenConnector::new()),
                Box::new(VibeConnector::new()),
            ];
            assert_eq!(core_connectors.len(), 25);

            #[cfg(feature = "chatgpt")]
            let _ = crate::ChatGptConnector::new();
            #[cfg(feature = "codebuff")]
            let _ = crate::CodebuffConnector::new();
            #[cfg(feature = "crush")]
            let _ = crate::CrushConnector::new();
            #[cfg(feature = "cursor")]
            let _ = crate::CursorConnector::new();
            #[cfg(feature = "goose")]
            let _ = crate::GooseConnector::new();
            #[cfg(feature = "grok-bot")]
            let _ = crate::GrokBotConnector::new();
            #[cfg(feature = "hermes")]
            let _ = crate::HermesConnector::new();
            #[cfg(feature = "opencode")]
            let _ = crate::OpenCodeConnector::new();
            #[cfg(feature = "shelley")]
            let _ = crate::ShelleyConnector::new();

            let tick: ScanProgressTick = std::sync::Arc::new(|| {});
            tick();

            assert_eq!(percent_decode_utf8("hello%20world"), "hello world");
            let mut invocations = vec![NormalizedInvocation {
                kind: "tool".to_string(),
                name: "Skill".to_string(),
                raw_name: None,
                call_id: Some("call_1".to_string()),
                arguments: Some(json!({"skill": "verify"})),
            }];
            unwrap_skill_invocations(&mut invocations);
            assert_eq!(invocations[0].kind, "skill");
            assert_eq!(invocations[0].name, "verify");
        }

        // Run with --no-default-features --features all-connectors. Using
        // --all-features would hide a missing edge in the aggregate feature.
        #[cfg(feature = "all-connectors")]
        #[test]
        fn all_connectors_scans_devin_sqlite_sessions() {
            use crate::connectors::sqlite_sync::Connection;

            let retained = tempfile::Builder::new()
                .prefix("fad-all-connectors-devin-")
                .tempdir()
                .expect("create Devin fixture directory")
                .keep();
            eprintln!("retained Devin SQLite fixture: {}", retained.display());
            let database = retained.join("sessions.db");
            let connection = Connection::open(database.to_string_lossy().as_ref())
                .expect("open Devin fixture database");
            connection
                .execute_batch(
                    r#"
                    CREATE TABLE sessions (
                        id TEXT PRIMARY KEY, title TEXT, working_directory TEXT,
                        model TEXT, agent_mode TEXT, created_at INTEGER,
                        last_activity_at INTEGER, main_chain_id INTEGER, hidden INTEGER
                    );
                    CREATE TABLE message_nodes (
                        node_id INTEGER PRIMARY KEY, session_id TEXT,
                        parent_node_id INTEGER, chat_message TEXT, created_at INTEGER
                    );
                    INSERT INTO sessions VALUES
                        ('visible', 'Feature coverage', '/workspace/devin', 'test-model',
                         'test', 1700000000, 1700000001, 1, 0),
                        ('hidden', 'Retired session', '/workspace/devin', 'test-model',
                         'test', 1700000000, 1700000001, 3, 1);
                    INSERT INTO message_nodes VALUES
                        (1, 'visible', NULL,
                         '{"role":"user","content":"visible main-chain message"}', 1700000000),
                        (2, 'visible', NULL,
                         '{"role":"user","content":"abandoned branch"}', 1700000000),
                        (3, 'hidden', NULL,
                         '{"role":"user","content":"hidden session message"}', 1700000000);
                    "#,
                )
                .expect("populate Devin fixture");
            drop(connection);
            let original_bytes = fs::read(&database).expect("read closed fixture database");

            let (_, factory) = get_connector_factories()
                .into_iter()
                .find(|(slug, _)| *slug == "devin")
                .expect("Devin factory must be registered");
            let connector = factory();
            let context =
                ScanContext::with_roots(retained, vec![ScanRoot::local(database.clone())], None);
            let conversations = connector.scan(&context).expect("scan Devin fixture");
            assert_eq!(
                conversations.len(),
                1,
                "all-connectors must enable scanning, with hidden sessions excluded"
            );
            let conversation = &conversations[0];
            assert_eq!(conversation.agent_slug, "devin");
            assert_eq!(conversation.external_id.as_deref(), Some("visible"));
            assert_eq!(conversation.source_path, database.join("visible"));
            assert_eq!(
                conversation.workspace,
                Some(PathBuf::from("/workspace/devin"))
            );
            assert_eq!(
                conversation.messages.len(),
                1,
                "off-chain nodes stay excluded"
            );
            assert_eq!(conversation.messages[0].role, "user");
            assert_eq!(
                conversation.messages[0].content,
                "visible main-chain message"
            );

            let sources = connector
                .discover_source_files(&context)
                .expect("discover Devin SQLite source");
            assert_eq!(sources.len(), 1);
            assert_eq!(sources[0].provider_slug, "devin");
            assert_eq!(sources[0].source_path, database);
            assert_eq!(
                fs::read(&database).expect("read fixture after scan and discovery"),
                original_bytes,
                "read-only scanning must preserve the database"
            );
        }

        #[test]
        fn all_factories_support_source_discovery_contract() {
            let temp = TempDir::new().expect("create temp dir");
            let factories = get_connector_factories();

            for (slug, factory) in factories {
                let connector = factory();
                let root = ScanRoot::local(temp.path().join(slug));
                let ctx = ScanContext::with_roots(
                    temp.path().to_path_buf(),
                    vec![root],
                    Some(1_700_000_000_000),
                );
                let sources = connector
                    .discover_source_files(&ctx)
                    .unwrap_or_else(|err| panic!("connector {slug} discovery failed: {err}")); // ubs:ignore[rust.ownership.panic-macro] — Fail conformance with the connector identity on discovery error.

                for source in sources {
                    // Known divergence: the claude connector's own emitted
                    // identity is "claude_code" while its registry slug is
                    // "claude" (public API; alignment is a tracked decision).
                    // The mapping must stay EXPLICIT so any future drift
                    // between factory slugs and provider slugs fails here.
                    let expected_provider: &str = if *slug == *"claude" {
                        "claude_code"
                    } else {
                        slug
                    };
                    assert_eq!(
                        source.provider_slug, expected_provider,
                        "connector {slug} should report its documented provider slug"
                    );
                    assert!(
                        !source.source_path.as_os_str().is_empty(),
                        "connector {slug} produced empty discovered source path"
                    );
                    assert!(
                        !source.scan_root.as_os_str().is_empty(),
                        "connector {slug} produced empty discovered scan root"
                    );
                    assert!(
                        !source.role.as_str().is_empty(),
                        "connector {slug} produced empty discovered source role"
                    );
                }
            }
        }
    }

    // =========================================================================
    // Contract 3: NormalizedConversation Schema Conformance
    // =========================================================================
    //
    // All connectors must produce NormalizedConversation with:
    // - Non-empty agent_slug
    // - Valid source_path
    // - Messages with sequential idx values

    mod schema_conformance {
        use super::*;

        fn validate_conversation(conv: &NormalizedConversation, connector_slug: &str) {
            // agent_slug must match canonical provider identity (OpenClaw qualifies per-agent stores as `openclaw/<agent>`)
            let slug_matches = match connector_slug {
                "claude" => conv.agent_slug == "claude_code",
                "openclaw" => {
                    conv.agent_slug == "openclaw" || conv.agent_slug.starts_with("openclaw/")
                }
                _ => conv.agent_slug == connector_slug,
            };
            assert!(
                slug_matches,
                "connector {} produced conversation with unexpected agent_slug {}",
                connector_slug, conv.agent_slug
            );

            // source_path must be set (even if synthetic)
            assert!(
                !conv.source_path.as_os_str().is_empty(),
                "connector {} produced conversation with empty source_path",
                connector_slug
            );

            // Conversation must contain at least one message
            assert!(
                !conv.messages.is_empty(),
                "connector {} produced conversation with empty messages",
                connector_slug
            );

            // Messages must have sequential indices
            for (i, msg) in conv.messages.iter().enumerate() {
                let expected_idx = i64::try_from(i).expect("message index should fit in i64");
                assert_eq!(
                    msg.idx, expected_idx,
                    "connector {} message at position {} has idx {}, expected {}",
                    connector_slug, i, msg.idx, expected_idx
                );
            }

            // All messages must have non-empty role
            for msg in &conv.messages {
                assert!(
                    !msg.role.is_empty(),
                    "connector {} produced message with empty role",
                    connector_slug
                );
            }

            // Time bounds should be consistent
            if let (Some(start), Some(end)) = (conv.started_at, conv.ended_at) {
                assert!(
                    start <= end,
                    "connector {} has started_at ({}) > ended_at ({})",
                    connector_slug,
                    start,
                    end
                );
            }
        }

        fn validate_message(msg: &NormalizedMessage, connector_slug: &str) {
            // Role must be one of the standard roles
            let valid_roles = ["user", "assistant", "system", "tool", "function", "other"];
            assert!(
                valid_roles.contains(&msg.role.as_str()),
                "connector {} produced message with non-standard role: {}",
                connector_slug,
                msg.role
            );

            // idx must be non-negative
            assert!(
                msg.idx >= 0,
                "connector {} produced message with negative idx",
                connector_slug
            );

            // invocations should have valid kind
            for inv in &msg.invocations {
                assert!(
                    inv.kind == "tool" || inv.kind == "skill",
                    "connector {} produced invocation with invalid kind: {}",
                    connector_slug,
                    inv.kind
                );
                assert!(
                    !inv.name.is_empty(),
                    "connector {} produced invocation with empty name",
                    connector_slug
                );
            }
        }

        #[test]
        fn normalized_conversation_schema_is_valid_json() {
            // Create a sample conversation and verify it serializes to valid JSON
            let conv = NormalizedConversation {
                agent_slug: "test".into(),
                external_id: Some("test-123".into()),
                title: Some("Test Conversation".into()),
                workspace: Some(PathBuf::from("/tmp/test")),
                source_path: PathBuf::from("/tmp/test/session.jsonl"),
                started_at: Some(1_700_000_000_000),
                ended_at: Some(1_700_000_001_000),
                metadata: json!({"key": "value"}),
                messages: vec![
                    NormalizedMessage {
                        idx: 0,
                        role: "user".into(),
                        author: Some("user".into()),
                        created_at: Some(1_700_000_000_000),
                        content: "Hello".into(),
                        extra: json!({}),
                        invocations: vec![],
                        snippets: vec![],
                    },
                    NormalizedMessage {
                        idx: 1,
                        role: "assistant".into(),
                        author: None,
                        created_at: Some(1_700_000_001_000),
                        content: "Hi there!".into(),
                        extra: json!({}),
                        invocations: vec![],
                        snippets: vec![],
                    },
                ],
            };

            // Should serialize to valid JSON
            let json_str = serde_json::to_string(&conv);
            assert!(
                json_str.is_ok(),
                "NormalizedConversation should serialize to JSON"
            );

            // Should deserialize back
            let parsed: Result<NormalizedConversation, _> =
                serde_json::from_str(&json_str.unwrap());
            assert!(
                parsed.is_ok(),
                "NormalizedConversation should deserialize from JSON"
            );
        }

        #[test]
        fn checked_in_fixture_stores_produce_schema_conformant_conversations() {
            // Contract 3 made real: every conversation produced from a
            // checked-in fixture store must satisfy the schema validators
            // below. Without this, `validate_conversation`/`validate_message`
            // were dead code and the schema contract gated nothing.
            let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
            let fixtures: &[(&str, &str)] = &[
                ("antigravity", "fixtures/antigravity"),
                ("codex", "fixtures/codex"),
                ("openhands", "fixtures/openhands"),
            ];

            for &(slug, rel) in fixtures {
                let root = manifest.join(rel);
                assert!(
                    root.exists(),
                    "checked-in fixture store missing: {}",
                    root.display()
                );
                let ctx = ScanContext::with_roots(root.clone(), vec![ScanRoot::local(root)], None);

                let matched = get_connector_factories()
                    .into_iter()
                    .find(|(factory_slug, _)| *factory_slug == slug);
                let Some((_, factory)) = matched else {
                    // ubs:ignore[rust.ownership.panic-macro] — Missing registered fixture connector is a test failure, not a production fallback.
                    panic!("no registered factory for fixture connector {slug}");
                };

                let convs = factory().scan(&ctx).unwrap_or_else(|err| {
                    // ubs:ignore[rust.ownership.panic-macro] — Preserve the fixture scan error and connector slug in the failing test.
                    panic!("{slug}: scan of checked-in fixture failed: {err}")
                });
                assert!(
                    !convs.is_empty(),
                    "{slug}: checked-in fixture store yielded no conversations"
                );

                for conv in &convs {
                    validate_conversation(conv, slug);
                    for msg in &conv.messages {
                        validate_message(msg, slug);
                    }
                }

                let connector = factory();
                let discovered = connector.discover_source_files(&ctx).unwrap_or_else(|err| {
                    // ubs:ignore[rust.ownership.panic-macro] — Preserve connector slug and discovery error in conformance test.
                    panic!("{slug}: discover_source_files on fixture failed: {err}")
                });
                assert!(
                    !discovered.is_empty(),
                    "{slug}: discover_source_files yielded no sources for populated fixture"
                );
                let expected_provider: &str = if matches!(slug, "claude") {
                    "claude_code"
                } else {
                    slug
                };
                for source in &discovered {
                    assert_eq!(
                        source.provider_slug, expected_provider,
                        "{slug}: discovered source reported unexpected provider_slug"
                    );
                    assert!(
                        !source.source_path.as_os_str().is_empty(),
                        "{slug}: discovered source had empty source_path"
                    );
                    assert!(
                        !source.scan_root.as_os_str().is_empty(),
                        "{slug}: discovered source had empty scan_root"
                    );
                    assert!(
                        !source.role.as_str().is_empty(),
                        "{slug}: discovered source had empty role"
                    );
                }
                for conv in &convs {
                    let covered = discovered.iter().any(|src| {
                        conv.source_path == src.source_path
                            || conv.source_path.starts_with(&src.source_path)
                    });
                    assert!(
                        covered,
                        "{slug}: conversation source_path {} not covered by discover_source_files {:?}",
                        conv.source_path.display(),
                        discovered
                            .iter()
                            .map(|s| &s.source_path)
                            .collect::<Vec<_>>()
                    );
                }

                assert!(
                    connector.supports_streaming_scan(),
                    "{slug}: all 34 connectors must support streaming scan"
                );
                let mut streamed = Vec::new();
                connector
                    .scan_with_callback(&ctx, &mut |conv| {
                        streamed.push(conv);
                        Ok(())
                    })
                    .unwrap_or_else(|err| {
                        // ubs:ignore[rust.ownership.panic-macro] — Preserve connector slug and streaming scan error in conformance test.
                        panic!("{slug}: scan_with_callback failed: {err}")
                    });
                assert_eq!(
                    serde_json::to_value(&streamed).expect("serialize streamed"),
                    serde_json::to_value(&convs).expect("serialize convs"),
                    "{slug}: scan_with_callback output differed from scan()"
                );

                let cross_source_connectors: &[&str] =
                    &["cline", "copilot", "cursor", "opencode", "qwen"];
                let expected_boundaries = !cross_source_connectors.contains(&slug);
                assert_eq!(
                    connector.supports_source_boundaries(),
                    expected_boundaries,
                    "{slug}: unexpected supports_source_boundaries() value"
                );
                if connector.supports_source_boundaries() {
                    let mut boundary_convs = Vec::new();
                    let mut completions = Vec::new();
                    let mut should_scan = |_src: &crate::connectors::DiscoveredSourceFile| true;
                    let mut on_complete = |comp: &crate::connectors::SourceCompletion| {
                        completions.push((
                            comp.source.provider_slug.clone(),
                            comp.source.source_path.clone(),
                            comp.conversations_emitted,
                        ));
                        Ok(())
                    };
                    let mut hooks = crate::connectors::SourceScanHooks {
                        should_scan_source: Some(&mut should_scan),
                        on_source_complete: Some(&mut on_complete),
                    };
                    connector
                        .scan_with_source_boundaries(&ctx, &mut hooks, &mut |conv| {
                            boundary_convs.push(conv);
                            Ok(())
                        })
                        .unwrap_or_else(|err| {
                            // ubs:ignore[rust.ownership.panic-macro] — Preserve connector slug and boundary scan error in conformance test.
                            panic!("{slug}: scan_with_source_boundaries failed: {err}")
                        });
                    assert_eq!(
                        serde_json::to_value(&boundary_convs).expect("serialize boundary_convs"),
                        serde_json::to_value(&convs).expect("serialize convs"),
                        "{slug}: scan_with_source_boundaries output differed from scan()"
                    );
                    assert!(
                        !completions.is_empty(),
                        "{slug}: supports_source_boundaries() == true but emitted 0 SourceCompletion events"
                    );
                    for (prov, comp_path, emitted) in &completions {
                        assert_eq!(
                            prov, expected_provider,
                            "{slug}: completion provider_slug mismatch"
                        );
                        assert!(
                            *emitted >= 1,
                            "{slug}: completion reported 0 conversations_emitted"
                        );
                        assert!(
                            discovered.iter().any(|d| &d.source_path == comp_path),
                            "{slug}: completion source_path {} not in discover_source_files",
                            comp_path.display()
                        );
                    }

                    let mut skipped_convs = Vec::new();
                    let mut skipped_completions = 0usize;
                    let mut skip_all = |_src: &crate::connectors::DiscoveredSourceFile| false;
                    let mut on_skip_complete = |_comp: &crate::connectors::SourceCompletion| {
                        skipped_completions += 1;
                        Ok(())
                    };
                    let mut skip_hooks = crate::connectors::SourceScanHooks {
                        should_scan_source: Some(&mut skip_all),
                        on_source_complete: Some(&mut on_skip_complete),
                    };
                    connector
                        .scan_with_source_boundaries(&ctx, &mut skip_hooks, &mut |conv| {
                            skipped_convs.push(conv);
                            Ok(())
                        })
                        .unwrap_or_else(|err| {
                            // ubs:ignore[rust.ownership.panic-macro] — Preserve connector slug and skip boundary scan error in conformance test.
                            panic!("{slug}: scan_with_source_boundaries(skip_all) failed: {err}")
                        });
                    assert!(
                        skipped_convs.is_empty(),
                        "{slug}: should_scan_source=false still emitted {} conversations",
                        skipped_convs.len()
                    );
                    assert_eq!(
                        skipped_completions, 0,
                        "{slug}: should_scan_source=false still emitted {skipped_completions} completions"
                    );
                }
            }
        }

        fn write_fixture_file(path: &std::path::Path, content: &str) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create fixture parent dir");
            }
            fs::write(path, content).expect("write fixture file");
        }

        #[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
        fn build_connector_fixture_context(
            slug: &str,
            base: &std::path::Path,
        ) -> Option<ScanContext> {
            let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
            let root = match slug {
                "antigravity" => manifest.join("fixtures/antigravity"),
                "codex" => manifest.join("fixtures/codex"),
                "openhands" => manifest.join("fixtures/openhands"),
                "claude" => {
                    let r = base.join(".claude/projects");
                    write_fixture_file(
                        &r.join("proj/sess1.jsonl"),
                        "{\"type\":\"user\",\"sessionId\":\"s1\",\"timestamp\":\"2026-03-01T00:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"Hello Claude\"}}\n",
                    );
                    r
                }
                "cline" => {
                    let r = base.join("claude-dev");
                    write_fixture_file(
                        &r.join("task-001/ui_messages.json"),
                        "[{\"role\":\"user\",\"content\":\"Hello Cline\",\"timestamp\":1733000000}]",
                    );
                    r
                }
                "continue" => {
                    let r = base.join(".continue/sessions");
                    write_fixture_file(
                        &r.join("session-1.json"),
                        "{\"sessionId\":\"session-1\",\"title\":\"Test\",\"workspaceDirectory\":\"/work\",\"history\":[{\"message\":{\"role\":\"user\",\"content\":\"Hello Continue\"}}]}",
                    );
                    r
                }
                "gemini" => {
                    let r = base.join("gemini");
                    write_fixture_file(
                        &r.join("gemini_project/chats/session-1.json"),
                        "{\"sessionId\":\"s1\",\"projectHash\":\"p1\",\"messages\":[{\"type\":\"user\",\"content\":\"Hello Gemini\",\"timestamp\":\"2025-01-15T10:00:00Z\"}]}",
                    );
                    r
                }
                "clawdbot" => {
                    let r = base.join(".clawdbot/sessions");
                    write_fixture_file(
                        &r.join("sess-1.jsonl"),
                        "{\"role\":\"user\",\"content\":\"Hello Clawdbot\",\"timestamp\":\"2026-03-01T00:00:00Z\"}\n",
                    );
                    r
                }
                "vibe" => {
                    let r = base.join(".vibe/logs/session");
                    write_fixture_file(
                        &r.join("sess-1/messages.jsonl"),
                        "{\"role\":\"user\",\"content\":\"Hello Vibe\",\"timestamp\":\"2026-03-01T00:00:00Z\"}\n",
                    );
                    r
                }
                "amp" => {
                    let r = base.join("sourcegraph.amp");
                    write_fixture_file(
                        &r.join("conversation.json"),
                        "{\"messages\":[{\"role\":\"user\",\"content\":\"Hello Amp\",\"created_at\":1700000000000}]}",
                    );
                    r
                }
                "aider" => {
                    let r = base.join("aider-project");
                    write_fixture_file(
                        &r.join(".aider.chat.history.md"),
                        "# aider chat started at 2026-03-01 10:00:00\nMain model: claude-sonnet-4-5 with diff edit format\n\n#### /run cargo test\n\nHi from Aider!\n",
                    );
                    r
                }
                "pi_agent" => {
                    let r = base.join(".pi/agent");
                    write_fixture_file(
                        &r.join("sessions/2026-10-09T00-00-00_s1.jsonl"),
                        "{\"type\":\"session\",\"id\":\"0192aa11-0000-7000-8000-000000000001\",\"cwd\":\"/work\",\"version\":3}\n{\"type\":\"message\",\"id\":\"m1\",\"message\":{\"role\":\"user\",\"content\":\"Hello Pi\"}}\n",
                    );
                    r
                }
                "omp" => {
                    let r = base.join(".omp/agent");
                    write_fixture_file(
                        &r.join("sessions/2026-10-09T00-00-00_s1.jsonl"),
                        "{\"type\":\"session\",\"id\":\"0192aa11-0000-7000-8000-000000000001\",\"cwd\":\"/work\",\"version\":3}\n{\"type\":\"message\",\"id\":\"m1\",\"message\":{\"role\":\"user\",\"content\":\"Hello OMP\"}}\n",
                    );
                    r
                }
                "pi_durable" => {
                    let r = base.join("durable");
                    write_fixture_file(
                        &r.join("main.jsonl"),
                        "{\"format\":1,\"type\":\"commit\",\"seq\":1,\"writes\":[{\"type\":\"conversation\",\"value\":{\"id\":1}},{\"type\":\"entry\",\"value\":{\"id\":2,\"conversationId\":1,\"kind\":\"pi.user\",\"model\":[{\"role\":\"user\",\"content\":\"Hello Pi Durable\"}]}}]}\n",
                    );
                    r
                }
                "prime_agent" => {
                    let r = base.join(".prime/agent/sessions");
                    write_fixture_file(
                        &r.join("0192aa11-0000-7000-8000-000000000001.jsonl"),
                        "{\"type\":\"session\",\"id\":\"0192aa11-0000-7000-8000-000000000001\",\"cwd\":\"/work\",\"version\":3}\n{\"type\":\"message\",\"id\":\"a1b2c3d4\",\"parentId\":null,\"timestamp\":\"2026-10-09T00:00:01Z\",\"message\":{\"role\":\"user\",\"content\":\"Hello Prime\"}}\n",
                    );
                    r
                }
                "factory" => {
                    let r = base.join(".factory/sessions");
                    write_fixture_file(
                        &r.join("-work-demo/sess-1.jsonl"),
                        "{\"type\":\"message\",\"id\":\"m1\",\"timestamp\":\"2026-10-09T00:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"Hello Factory\"}}\n",
                    );
                    r
                }
                "kimi" => {
                    let r = base.join(".kimi-code/sessions");
                    write_fixture_file(
                        &r.join("workdir/sess-1/agents/main/wire.jsonl"),
                        "{\"type\":\"turn.prompt\",\"time\":\"2026-10-09T00:00:00Z\",\"input\":\"Hello Kimi\"}\n{\"type\":\"llm.request\",\"time\":\"2026-10-09T00:00:01Z\",\"model\":\"kimi-k2-0711-preview\"}\n{\"type\":\"context.append_loop_event\",\"time\":\"2026-10-09T00:00:02Z\",\"event\":{\"type\":\"tool.call\",\"toolCallId\":\"tc1\",\"name\":\"load_skill\",\"args\":{\"name\":\"debugging\"}}}\n{\"type\":\"context.append_loop_event\",\"time\":\"2026-10-09T00:00:03Z\",\"event\":{\"type\":\"content.part\",\"part\":{\"type\":\"text\",\"text\":\"Hi from Kimi\"}}}\n{\"type\":\"usage.record\",\"time\":\"2026-10-09T00:00:04Z\",\"usage\":{\"input_tokens\":100,\"output_tokens\":25}}\n",
                    );
                    r
                }
                "kiro" => {
                    let r = base.join(".kiro/sessions/cli");
                    write_fixture_file(
                        &r.join("session.jsonl"),
                        "{\"kind\":\"Prompt\",\"data\":{\"content\":\"Hello Kiro\"}}\n",
                    );
                    r
                }
                "muse" => {
                    let r = base.join(".local/share/muse/sessions");
                    write_fixture_file(
                        &r.join("019cccd3-9f97-7351-824f-6b1eb5f199f2/session.jsonl"),
                        "{\"schema_version\":\"v1\",\"stream_id\":\"019cccd3-9f97-7351-824f-6b1eb5f199f2\",\"seq\":1,\"recorded_at_ms\":1772962994000,\"payload_type\":\"runtime.session\",\"payload\":{\"kind\":\"run\",\"event\":{\"kind\":\"started\",\"prompt\":\"Hello Muse\"}}}\n",
                    );
                    r
                }
                "openclaw" => {
                    let r = base.join(".openclaw/agents/main/sessions");
                    write_fixture_file(
                        &r.join("sess-1.jsonl"),
                        "{\"type\":\"message\",\"id\":\"m1\",\"timestamp\":\"2026-10-09T00:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"Hello OpenClaw\"}}\n{\"type\":\"message\",\"id\":\"m2\",\"timestamp\":\"2026-10-09T00:00:01Z\",\"message\":{\"role\":\"assistant\",\"provider\":\"anthropic\",\"model\":\"claude-opus-4-6\",\"content\":[{\"type\":\"text\",\"text\":\"Hi from OpenClaw\"},{\"type\":\"toolCall\",\"id\":\"tc1\",\"name\":\"exec\",\"arguments\":{\"cmd\":\"ls\"}},{\"type\":\"toolCall\",\"id\":\"tc2\",\"name\":\"load_skill\",\"arguments\":{\"name\":\"deploy\"}}],\"usage\":{\"input\":180,\"output\":60,\"cacheRead\":30,\"cacheWrite\":10}}}\n",
                    );
                    r
                }
                "copilot" => {
                    let r = base.join(".config");
                    write_fixture_file(
                        &r.join("Code/User/globalStorage/github.copilot-chat/conversations.json"),
                        "[{\"id\":\"conv-1\",\"workspaceFolder\":\"/work\",\"turns\":[{\"request\":{\"message\":\"Hello Copilot\",\"timestamp\":1700000000000},\"response\":{\"message\":\"Hi\",\"timestamp\":1700000001000}}]}]",
                    );
                    r
                }
                "copilot_cli" => {
                    let r = base.join(".copilot/session-state");
                    write_fixture_file(
                        &r.join("abc-123/events.jsonl"),
                        "{\"type\":\"sessionStart\",\"session_id\":\"abc-123\",\"timestamp\":1700000000000,\"cwd\":\"/work\"}\n{\"type\":\"user.message\",\"role\":\"user\",\"content\":\"Hello Copilot CLI\",\"timestamp\":1700000001000}\n",
                    );
                    r
                }
                "qwen" => {
                    let r = base.join(".qwen");
                    write_fixture_file(
                        &r.join("projects/demo/chats/11111111-2222-3333-4444-555555555555.jsonl"),
                        "{\"uuid\":\"u1\",\"parentUuid\":null,\"sessionId\":\"11111111-2222-3333-4444-555555555555\",\"timestamp\":\"2026-10-09T00:00:00Z\",\"cwd\":\"/work/demo\",\"type\":\"user\",\"message\":{\"role\":\"user\",\"parts\":[{\"text\":\"Hello Qwen\"}]}}\n",
                    );
                    r
                }
                "grok" => {
                    let r = base.join(".grok/sessions");
                    write_fixture_file(
                        &r.join("group-1/sess-1/updates.jsonl"),
                        "{\"timestamp\":\"2026-10-09T00:00:00Z\",\"update\":{\"sessionUpdate\":\"user_message_chunk\",\"content\":{\"type\":\"text\",\"text\":\"Hello Grok\"}}}\n",
                    );
                    r
                }
                "codebuff" => {
                    let r = base.join(".config/manicode/projects");
                    write_fixture_file(
                        &r.join("demo/chats/2026-10-09T00-00-00.000Z/chat-messages.json"),
                        "[{\"id\":\"user-1700000000000\",\"variant\":\"user\",\"content\":\"Hello Codebuff\",\"timestamp\":\"2026-10-09T00:00:00.000Z\"}]",
                    );
                    r
                }
                "chatgpt" => {
                    let r = base.join("com.openai.chat");
                    write_fixture_file(
                        &r.join("conversations-v1/conv-1.json"),
                        "{\"id\":\"conv-1\",\"title\":\"ChatGPT\",\"mapping\":{\"u1\":{\"parent\":null,\"message\":{\"author\":{\"role\":\"user\"},\"content\":{\"parts\":[\"Hello ChatGPT\"]},\"create_time\":1700000000.0}}}}",
                    );
                    r
                }
                "grok_bot" => {
                    let r = base.join("grok_bot");
                    let key = "sand.client.slice.account.auth0%7Cuser_00000000000000000000000000.transcript.replicas.81da155f-cc4c-58b3-aadf-770858d5e55c";
                    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
                    let bits: Vec<bool> = key
                        .bytes()
                        .flat_map(|byte| (0..8).rev().map(move |bit| byte & (1 << bit) != 0))
                        .collect();
                    let encoded: String = bits
                        .chunks(5)
                        .map(|chunk| {
                            let val = chunk
                                .iter()
                                .fold(0_usize, |v, bit| (v << 1) | usize::from(*bit))
                                << (5 - chunk.len());
                            char::from(alphabet[val])
                        })
                        .collect();
                    write_fixture_file(
                        &r.join(format!("{encoded}.blob")),
                        include_str!("../../tests/fixtures/grok_bot_reporter_0440.json"),
                    );
                    r
                }
                "opencode" => {
                    let r = base.join("opencode/storage");
                    write_fixture_file(
                        &r.join("session/proj-001/sess-001.json"),
                        "{\"id\":\"sess-001\",\"title\":\"Test Session\",\"directory\":\"/work\",\"projectID\":\"proj-001\",\"time\":{\"created\":1733000000,\"updated\":1733000100}}",
                    );
                    write_fixture_file(
                        &r.join("message/sess-001/msg-001.json"),
                        "{\"id\":\"msg-001\",\"role\":\"user\",\"sessionID\":\"sess-001\",\"time\":{\"created\":1733000000,\"completed\":1733000001}}",
                    );
                    write_fixture_file(
                        &r.join("part/msg-001/part-001.json"),
                        "{\"id\":\"part-001\",\"messageID\":\"msg-001\",\"type\":\"text\",\"text\":\"Hello OpenCode\"}",
                    );
                    r
                }
                "goose" => {
                    let r = base.join(".goose");
                    write_fixture_file(
                        &r.join("sessions/session1.jsonl"),
                        "{\"role\":\"user\",\"content\":\"Hello Goose\",\"created_at\":1700000000}\n",
                    );
                    r
                }
                "devin" => {
                    #[cfg(feature = "devin")]
                    {
                        let db_path = base.join("sessions.db");
                        let conn = crate::connectors::sqlite_sync::Connection::open(
                            db_path.to_string_lossy().as_ref(),
                        )
                        .expect("open Devin db");
                        conn.execute_batch(
                            "CREATE TABLE sessions (id TEXT PRIMARY KEY, title TEXT, working_directory TEXT, model TEXT, agent_mode TEXT, created_at INTEGER, last_activity_at INTEGER, main_chain_id INTEGER, hidden INTEGER);
                             CREATE TABLE message_nodes (node_id INTEGER PRIMARY KEY, session_id TEXT, parent_node_id INTEGER, chat_message TEXT, created_at INTEGER);
                             INSERT INTO sessions VALUES ('s1', 'Devin', '/work', 'm', 'a', 1700000000, 1700000001, 1, 0);
                             INSERT INTO message_nodes VALUES (1, 's1', NULL, '{\"role\":\"user\",\"content\":\"Hello Devin\"}', 1700000000);",
                        )
                        .expect("populate Devin db");
                        return Some(ScanContext::with_roots(
                            base.to_path_buf(),
                            vec![ScanRoot::local(db_path)],
                            None,
                        ));
                    }
                    #[cfg(not(feature = "devin"))]
                    {
                        return None;
                    }
                }
                #[cfg(feature = "cursor")]
                "cursor" => {
                    let db_path = base.join("Cursor/User/globalStorage/state.vscdb");
                    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
                    let conn = crate::connectors::sqlite_sync::Connection::open(
                        db_path.to_string_lossy().as_ref(),
                    )
                    .expect("open Cursor db");
                    conn.execute_batch(
                        "CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT);
                         CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT);
                         INSERT INTO cursorDiskKV VALUES ('composerData:c1', '{\"text\":\"Hello Cursor\"}');",
                    )
                    .expect("populate Cursor db");
                    db_path
                }
                #[cfg(feature = "crush")]
                "crush" => {
                    let db_path = base.join("crush.db");
                    let conn = crate::connectors::sqlite_sync::Connection::open(
                        db_path.to_string_lossy().as_ref(),
                    )
                    .expect("open Crush db");
                    conn.execute_batch(
                        "CREATE TABLE sessions (id TEXT PRIMARY KEY, title TEXT, prompt_tokens INTEGER, completion_tokens INTEGER, cost REAL);
                         CREATE TABLE messages (session_id TEXT, role TEXT, parts TEXT, created_at INTEGER, model TEXT, provider TEXT);
                         INSERT INTO sessions VALUES ('s1', 'Crush', 1, 2, 0.01);
                         INSERT INTO messages VALUES ('s1', 'user', '[{\"type\":\"text\",\"text\":\"Hello Crush\"}]', 1733000000000, 'm', 'p');",
                    )
                    .expect("populate Crush db");
                    db_path
                }
                #[cfg(feature = "hermes")]
                "hermes" => {
                    let db_path = base.join("state.db");
                    let conn = crate::connectors::sqlite_sync::Connection::open(
                        db_path.to_string_lossy().as_ref(),
                    )
                    .expect("open Hermes db");
                    conn.execute_batch(
                        "CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT, model TEXT, title TEXT, parent_session_id TEXT, started_at REAL, ended_at REAL, end_reason TEXT, message_count INTEGER, tool_call_count INTEGER, input_tokens INTEGER, output_tokens INTEGER);
                         CREATE TABLE messages (session_id TEXT, role TEXT, content TEXT, tool_calls TEXT, tool_name TEXT, tool_call_id TEXT, reasoning TEXT, timestamp REAL);
                         INSERT INTO sessions VALUES ('s1', 'cli', 'm', 'Hermes', NULL, 1700000000.0, 1700000010.0, 'completed', 1, 0, 10, 5);
                         INSERT INTO messages VALUES ('s1', 'user', 'Hello Hermes', NULL, NULL, NULL, NULL, 1700000001.0);",
                    )
                    .expect("populate Hermes db");
                    base.to_path_buf()
                }
                #[cfg(feature = "shelley")]
                "shelley" => {
                    let db_path = base.join("shelley.db");
                    let conn = crate::connectors::sqlite_sync::Connection::open(
                        db_path.to_string_lossy().as_ref(),
                    )
                    .expect("open Shelley db");
                    conn.execute_batch(
                        "CREATE TABLE migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, migration_number INTEGER NOT NULL, migration_name TEXT NOT NULL UNIQUE, executed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
                         CREATE TABLE conversations (conversation_id TEXT PRIMARY KEY, slug TEXT, user_initiated BOOLEAN NOT NULL DEFAULT TRUE, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, cwd TEXT, archived BOOLEAN NOT NULL DEFAULT FALSE, parent_conversation_id TEXT, model TEXT, conversation_options TEXT NOT NULL DEFAULT '{}', current_generation INTEGER NOT NULL DEFAULT 0, tags TEXT NOT NULL DEFAULT '[]', is_draft BOOLEAN NOT NULL DEFAULT FALSE, draft TEXT NOT NULL DEFAULT '', queued_messages TEXT NOT NULL DEFAULT '[]');
                         CREATE TABLE messages (message_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, sequence_id INTEGER NOT NULL, type TEXT NOT NULL, llm_data TEXT, user_data TEXT, usage_data TEXT, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, display_data TEXT, excluded_from_context BOOLEAN NOT NULL DEFAULT FALSE, generation INTEGER NOT NULL DEFAULT 0, llm_api_url TEXT, model_name TEXT, forked_from_message_id TEXT, user_email TEXT, other_usage_data TEXT);
                         INSERT INTO conversations (conversation_id, slug, user_initiated, created_at, updated_at, cwd) VALUES ('c1', 'shelley-test', 1, '2026-08-01 10:00:00', '2026-08-01 11:00:00', '/work');
                         INSERT INTO messages (message_id, conversation_id, sequence_id, type, llm_data, created_at) VALUES ('m1', 'c1', 0, 'user', '{\"Role\":0,\"Content\":[{\"Type\":2,\"Text\":\"Hello Shelley\"}]}', '2026-08-01 10:30:00');",
                    )
                    .expect("populate Shelley db");
                    db_path
                }
                other => panic!("no schema conformance fixture defined for connector {other}"), // ubs:ignore[rust.ownership.panic-macro] — Fail fast if a new connector factory is added without a schema conformance fixture.
            };
            Some(ScanContext::with_roots(
                root.clone(),
                vec![ScanRoot::local(root)],
                None,
            ))
        }

        #[test]
        fn all_compiled_connectors_produce_schema_conformant_conversations() {
            use std::sync::Arc;
            use std::sync::atomic::{AtomicUsize, Ordering};

            for (slug, factory) in get_connector_factories() {
                let tmp = TempDir::new().expect("create temp dir for connector fixture");
                let Some(ctx) = build_connector_fixture_context(slug, tmp.path()) else {
                    // Detection-only build slice (e.g. `devin` without `feature = "devin"`).
                    let empty_ctx = ScanContext::with_roots(
                        tmp.path().to_path_buf(),
                        vec![ScanRoot::local(tmp.path().to_path_buf())],
                        None,
                    );
                    assert!(
                        factory()
                            .scan(&empty_ctx)
                            .expect("detection-only scan")
                            .is_empty(),
                        "{slug}: detection-only connector should emit no conversations"
                    );
                    continue;
                };

                let ticks = Arc::new(AtomicUsize::new(0));
                let ticks_clone = Arc::clone(&ticks);
                let ctx = ctx.with_progress_tick(Arc::new(move || {
                    ticks_clone.fetch_add(1, Ordering::Relaxed);
                }));

                let convs = factory().scan(&ctx).unwrap_or_else(|err| {
                    // ubs:ignore[rust.ownership.panic-macro] — Preserve connector slug and scan error in conformance test.
                    panic!("{slug}: schema conformance fixture scan failed: {err}")
                });
                assert!(
                    !convs.is_empty(),
                    "{slug}: schema conformance fixture yielded no conversations"
                );
                assert!(
                    ticks.load(Ordering::Relaxed) >= 1,
                    "{slug}: scan did not invoke ctx.progress_tick at least once"
                );
                for conv in &convs {
                    validate_conversation(conv, slug);
                    for msg in &conv.messages {
                        validate_message(msg, slug);
                    }
                }

                let connector = factory();
                let discovered = connector.discover_source_files(&ctx).unwrap_or_else(|err| {
                    // ubs:ignore[rust.ownership.panic-macro] — Preserve connector slug and discovery error in conformance test.
                    panic!("{slug}: discover_source_files on fixture failed: {err}")
                });
                assert!(
                    !discovered.is_empty(),
                    "{slug}: discover_source_files yielded no sources for populated fixture"
                );
                let expected_provider: &str = if matches!(slug, "claude") {
                    "claude_code"
                } else {
                    slug
                };
                for source in &discovered {
                    assert_eq!(
                        source.provider_slug, expected_provider,
                        "{slug}: discovered source reported unexpected provider_slug"
                    );
                    assert!(
                        !source.source_path.as_os_str().is_empty(),
                        "{slug}: discovered source had empty source_path"
                    );
                    assert!(
                        !source.scan_root.as_os_str().is_empty(),
                        "{slug}: discovered source had empty scan_root"
                    );
                    assert!(
                        !source.role.as_str().is_empty(),
                        "{slug}: discovered source had empty role"
                    );
                }
                for conv in &convs {
                    let covered = discovered.iter().any(|src| {
                        conv.source_path == src.source_path
                            || conv.source_path.starts_with(&src.source_path)
                    });
                    assert!(
                        covered,
                        "{slug}: conversation source_path {} not covered by discover_source_files {:?}",
                        conv.source_path.display(),
                        discovered
                            .iter()
                            .map(|s| &s.source_path)
                            .collect::<Vec<_>>()
                    );
                }

                assert!(
                    connector.supports_streaming_scan(),
                    "{slug}: all 34 connectors must support streaming scan"
                );
                let mut streamed = Vec::new();
                connector
                    .scan_with_callback(&ctx, &mut |conv| {
                        streamed.push(conv);
                        Ok(())
                    })
                    .unwrap_or_else(|err| {
                        // ubs:ignore[rust.ownership.panic-macro] — Preserve connector slug and streaming scan error in conformance test.
                        panic!("{slug}: scan_with_callback failed: {err}")
                    });
                assert_eq!(
                    serde_json::to_value(&streamed).expect("serialize streamed"),
                    serde_json::to_value(&convs).expect("serialize convs"),
                    "{slug}: scan_with_callback output differed from scan()"
                );

                let cross_source_connectors: &[&str] =
                    &["cline", "copilot", "cursor", "opencode", "qwen"];
                let expected_boundaries = !cross_source_connectors.contains(&slug);
                assert_eq!(
                    connector.supports_source_boundaries(),
                    expected_boundaries,
                    "{slug}: unexpected supports_source_boundaries() value"
                );
                if connector.supports_source_boundaries() {
                    let mut boundary_convs = Vec::new();
                    let mut completions = Vec::new();
                    let mut should_scan = |_src: &crate::connectors::DiscoveredSourceFile| true;
                    let mut on_complete = |comp: &crate::connectors::SourceCompletion| {
                        completions.push((
                            comp.source.provider_slug.clone(),
                            comp.source.source_path.clone(),
                            comp.conversations_emitted,
                        ));
                        Ok(())
                    };
                    let mut hooks = crate::connectors::SourceScanHooks {
                        should_scan_source: Some(&mut should_scan),
                        on_source_complete: Some(&mut on_complete),
                    };
                    connector
                        .scan_with_source_boundaries(&ctx, &mut hooks, &mut |conv| {
                            boundary_convs.push(conv);
                            Ok(())
                        })
                        .unwrap_or_else(|err| {
                            // ubs:ignore[rust.ownership.panic-macro] — Preserve connector slug and boundary scan error in conformance test.
                            panic!("{slug}: scan_with_source_boundaries failed: {err}")
                        });
                    assert_eq!(
                        serde_json::to_value(&boundary_convs).expect("serialize boundary_convs"),
                        serde_json::to_value(&convs).expect("serialize convs"),
                        "{slug}: scan_with_source_boundaries output differed from scan()"
                    );
                    assert!(
                        !completions.is_empty(),
                        "{slug}: supports_source_boundaries() == true but emitted 0 SourceCompletion events"
                    );
                    for (prov, comp_path, emitted) in &completions {
                        assert_eq!(
                            prov, expected_provider,
                            "{slug}: completion provider_slug mismatch"
                        );
                        assert!(
                            *emitted >= 1,
                            "{slug}: completion reported 0 conversations_emitted"
                        );
                        assert!(
                            discovered.iter().any(|d| &d.source_path == comp_path),
                            "{slug}: completion source_path {} not in discover_source_files",
                            comp_path.display()
                        );
                    }

                    let mut skipped_convs = Vec::new();
                    let mut skipped_completions = 0usize;
                    let mut skip_all = |_src: &crate::connectors::DiscoveredSourceFile| false;
                    let mut on_skip_complete = |_comp: &crate::connectors::SourceCompletion| {
                        skipped_completions += 1;
                        Ok(())
                    };
                    let mut skip_hooks = crate::connectors::SourceScanHooks {
                        should_scan_source: Some(&mut skip_all),
                        on_source_complete: Some(&mut on_skip_complete),
                    };
                    connector
                        .scan_with_source_boundaries(&ctx, &mut skip_hooks, &mut |conv| {
                            skipped_convs.push(conv);
                            Ok(())
                        })
                        .unwrap_or_else(|err| {
                            // ubs:ignore[rust.ownership.panic-macro] — Preserve connector slug and skip boundary scan error in conformance test.
                            panic!("{slug}: scan_with_source_boundaries(skip_all) failed: {err}")
                        });
                    assert!(
                        skipped_convs.is_empty(),
                        "{slug}: should_scan_source=false still emitted {} conversations",
                        skipped_convs.len()
                    );
                    assert_eq!(
                        skipped_completions, 0,
                        "{slug}: should_scan_source=false still emitted {skipped_completions} completions"
                    );
                }

                if let Some(orig_ws) = convs[0].workspace.as_ref().and_then(|p| p.to_str()) {
                    let rewritten_roots = ctx
                        .scan_roots
                        .iter()
                        .cloned()
                        .map(|r| r.with_rewrite(orig_ws, "/conformance-rewritten-workspace"))
                        .collect();
                    let rewrite_ctx = ScanContext::with_roots(
                        ctx.data_dir.clone(),
                        rewritten_roots,
                        ctx.since_ts,
                    );
                    let rewritten_convs = factory().scan(&rewrite_ctx).unwrap_or_else(|err| {
                        // ubs:ignore[rust.ownership.panic-macro] — Preserve connector slug and rewrite scan error in conformance test.
                        panic!("{slug}: workspace rewrite conformance scan failed: {err}")
                    });
                    assert_eq!(
                        rewritten_convs[0].workspace.as_deref(),
                        Some(std::path::Path::new("/conformance-rewritten-workspace")),
                        "{slug}: connector did not apply ScanRoot workspace_rewrites"
                    );
                    assert_eq!(
                        rewritten_convs[0]
                            .metadata
                            .pointer("/cass/workspace_original")
                            .and_then(|v| v.as_str()),
                        Some(orig_ws),
                        "{slug}: connector did not record /cass/workspace_original after rewrite"
                    );
                }

                for conv in &convs {
                    for msg in &conv.messages {
                        let usage = crate::connectors::extract_tokens_for_agent(
                            &conv.agent_slug,
                            &msg.extra,
                            &msg.content,
                            &msg.role,
                        );
                        assert_eq!(
                            usage.has_tool_calls,
                            usage.tool_call_count > 0,
                            "{slug}: has_tool_calls must match tool_call_count > 0"
                        );
                        if !msg.content.trim().is_empty() {
                            match msg.role.as_str() {
                                "user" => assert!(
                                    usage.input_tokens.is_some(),
                                    "{slug}: non-empty user message must yield input_tokens"
                                ),
                                "assistant" => assert!(
                                    usage.output_tokens.is_some() || usage.input_tokens.is_some(),
                                    "{slug}: non-empty assistant message must yield token counts"
                                ),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        #[test]
        fn openclaw_qualified_slug_and_kimi_aider_end_to_end_token_and_invocation_conformance() {
            use crate::connectors::Connector;
            let tmp = TempDir::new().expect("tempdir");

            // 1. OpenClaw multi-agent store (`conv.agent_slug == "openclaw/main"`)
            let openclaw_ctx =
                build_connector_fixture_context("openclaw", tmp.path()).expect("openclaw ctx");
            let openclaw_convs = crate::connectors::openclaw::OpenClawConnector::new()
                .scan(&openclaw_ctx)
                .expect("scan openclaw");
            assert_eq!(openclaw_convs.len(), 1);
            let oc_conv = &openclaw_convs[0];
            assert_eq!(oc_conv.agent_slug, "openclaw/main");
            assert_eq!(oc_conv.messages.len(), 2);
            let oc_asst = &oc_conv.messages[1];
            assert_eq!(oc_asst.invocations.len(), 2);
            assert_eq!(oc_asst.invocations[0].kind, "tool");
            assert_eq!(oc_asst.invocations[0].name, "exec");
            assert_eq!(oc_asst.invocations[1].kind, "skill");
            assert_eq!(oc_asst.invocations[1].name, "deploy");
            assert_eq!(
                oc_asst.invocations[1].raw_name.as_deref(),
                Some("load_skill")
            );
            let oc_usage = crate::connectors::extract_tokens_for_agent(
                &oc_conv.agent_slug,
                &oc_asst.extra,
                &oc_asst.content,
                &oc_asst.role,
            );
            assert_eq!(
                oc_usage.data_source,
                crate::connectors::TokenDataSource::Api
            );
            assert_eq!(oc_usage.model_name.as_deref(), Some("claude-opus-4-6"));
            assert_eq!(oc_usage.provider.as_deref(), Some("anthropic"));
            assert_eq!(oc_usage.input_tokens, Some(180));
            assert_eq!(oc_usage.output_tokens, Some(60));
            assert_eq!(oc_usage.cache_read_tokens, Some(30));
            assert_eq!(oc_usage.cache_creation_tokens, Some(10));
            assert!(oc_usage.has_tool_calls);
            assert_eq!(oc_usage.tool_call_count, 2);

            // 2. Kimi Code (`conv.agent_slug == "kimi"`)
            let kimi_ctx = build_connector_fixture_context("kimi", tmp.path()).expect("kimi ctx");
            let kimi_convs = crate::connectors::kimi::KimiConnector::new()
                .scan(&kimi_ctx)
                .expect("scan kimi");
            assert_eq!(kimi_convs.len(), 1);
            let kimi_conv = &kimi_convs[0];
            assert_eq!(kimi_conv.messages.len(), 3);
            let kimi_tool_msg = &kimi_conv.messages[1];
            assert_eq!(kimi_tool_msg.invocations.len(), 1);
            assert_eq!(kimi_tool_msg.invocations[0].kind, "skill");
            assert_eq!(kimi_tool_msg.invocations[0].name, "debugging");
            assert_eq!(
                kimi_tool_msg.invocations[0].raw_name.as_deref(),
                Some("load_skill")
            );
            let kimi_tool_usage = crate::connectors::extract_tokens_for_agent(
                &kimi_conv.agent_slug,
                &kimi_tool_msg.extra,
                &kimi_tool_msg.content,
                &kimi_tool_msg.role,
            );
            assert_eq!(
                kimi_tool_usage.model_name.as_deref(),
                Some("kimi-k2-0711-preview")
            );
            assert_eq!(kimi_tool_usage.provider.as_deref(), Some("moonshot"));
            assert!(kimi_tool_usage.has_tool_calls);
            assert_eq!(kimi_tool_usage.tool_call_count, 1);

            let kimi_reply_msg = &kimi_conv.messages[2];
            let kimi_reply_usage = crate::connectors::extract_tokens_for_agent(
                &kimi_conv.agent_slug,
                &kimi_reply_msg.extra,
                &kimi_reply_msg.content,
                &kimi_reply_msg.role,
            );
            assert_eq!(
                kimi_reply_usage.data_source,
                crate::connectors::TokenDataSource::Api
            );
            assert_eq!(
                kimi_reply_usage.model_name.as_deref(),
                Some("kimi-k2-0711-preview")
            );
            assert_eq!(kimi_reply_usage.provider.as_deref(), Some("moonshot"));
            assert_eq!(kimi_reply_usage.input_tokens, Some(100));
            assert_eq!(kimi_reply_usage.output_tokens, Some(25));

            // 3. Aider (`conv.agent_slug == "aider"`)
            let aider_ctx =
                build_connector_fixture_context("aider", tmp.path()).expect("aider ctx");
            let aider_convs = crate::connectors::aider::AiderConnector::new()
                .scan(&aider_ctx)
                .expect("scan aider");
            assert_eq!(aider_convs.len(), 1);
            let aider_conv = &aider_convs[0];
            let aider_user_msg = aider_conv
                .messages
                .iter()
                .find(|m| m.role == "user")
                .expect("aider user message");
            assert_eq!(aider_user_msg.invocations.len(), 1);
            assert_eq!(aider_user_msg.invocations[0].name, "run");
            assert_eq!(
                aider_user_msg.invocations[0].raw_name.as_deref(),
                Some("/run")
            );
            let aider_user_usage = crate::connectors::extract_tokens_for_agent(
                &aider_conv.agent_slug,
                &aider_user_msg.extra,
                &aider_user_msg.content,
                &aider_user_msg.role,
            );
            assert!(aider_user_usage.has_tool_calls);
            assert_eq!(aider_user_usage.tool_call_count, 1);

            let aider_asst_msg = aider_conv
                .messages
                .iter()
                .find(|m| m.role == "assistant")
                .expect("aider assistant message");
            let aider_asst_usage = crate::connectors::extract_tokens_for_agent(
                &aider_conv.agent_slug,
                &aider_asst_msg.extra,
                &aider_asst_msg.content,
                &aider_asst_msg.role,
            );
            assert_eq!(
                aider_asst_usage.model_name.as_deref(),
                Some("claude-sonnet-4-5")
            );
            assert_eq!(aider_asst_usage.provider.as_deref(), Some("anthropic"));
        }
    }

    // =========================================================================
    // Contract 4: Detection Determinism
    // =========================================================================
    //
    // Detection with the same inputs must produce the same outputs

    mod detection_determinism {
        use super::*;

        #[test]
        fn detection_is_deterministic_with_overrides() {
            let tmp = TempDir::new().expect("create temp dir");

            // Create fixture directories
            let codex_root = tmp.path().join("codex/sessions");
            fs::create_dir_all(&codex_root).expect("create codex dir");

            let claude_root = tmp.path().join("claude");
            fs::create_dir_all(&claude_root).expect("create claude dir");

            let opts = AgentDetectOptions {
                only_connectors: Some(vec!["codex".into(), "claude".into()]),
                include_undetected: true,
                root_overrides: vec![
                    AgentDetectRootOverride {
                        slug: "codex".into(),
                        root: codex_root,
                    },
                    AgentDetectRootOverride {
                        slug: "claude".into(),
                        root: claude_root,
                    },
                ],
            };

            // Run detection multiple times
            let results: Vec<_> = (0..10)
                .map(|_| detect_installed_agents(&opts).expect("detection"))
                .collect();

            // All results should be identical. `generated_at` is wall-clock
            // and excluded; entries and summary are compared IN FULL, so any
            // drift in detection verdicts, evidence, or root ordering fails.
            let first = &results[0];
            for (i, result) in results.iter().enumerate() {
                assert_eq!(
                    result.installed_agents, first.installed_agents,
                    "run {} has different installed_agents",
                    i
                );
                assert_eq!(
                    result.summary, first.summary,
                    "run {} has different summary",
                    i
                );
            }
        }

        #[test]
        fn detection_order_is_deterministic() {
            let tmp = TempDir::new().expect("create temp dir");

            // Create multiple connectors
            let connectors = ["aider", "amp", "claude", "codex", "gemini"];
            for conn in &connectors {
                let root = tmp.path().join(conn);
                fs::create_dir_all(&root).expect("create dir");
            }

            let opts = AgentDetectOptions {
                only_connectors: Some(connectors.iter().map(ToString::to_string).collect()),
                include_undetected: true,
                root_overrides: connectors
                    .iter()
                    .map(|&conn| AgentDetectRootOverride {
                        slug: conn.into(),
                        root: tmp.path().join(conn),
                    })
                    .collect(),
            };

            let results: Vec<_> = (0..5)
                .map(|_| detect_installed_agents(&opts).expect("detection"))
                .collect();

            let first_slugs: Vec<_> = results[0]
                .installed_agents
                .iter()
                .map(|a| &a.slug)
                .collect();

            for result in &results[1..] {
                let slugs: Vec<_> = result.installed_agents.iter().map(|a| &a.slug).collect();
                assert_eq!(slugs, first_slugs, "agent order should be deterministic");
            }
        }
    }

    // =========================================================================
    // Contract 5: Path Mapping Equivalence
    // =========================================================================
    //
    // PathTrie and linear search must produce identical results for all inputs

    mod path_mapping_equivalence {
        use super::*;

        fn generate_test_mappings() -> Vec<PathMapping> {
            vec![
                PathMapping::new("/remote/home/user", "/local/home/user"),
                PathMapping::new("/remote/home/user/projects", "/local/projects"),
                PathMapping::new("/data/mirror", "/local/data"),
                PathMapping::new("/mnt/nfs/shared", "/home/shared"),
                PathMapping::new("C:\\Users\\remote", "D:\\local"),
            ]
        }

        fn generate_test_paths() -> Vec<&'static str> {
            vec![
                "/remote/home/user/projects/myapp/src/main.rs",
                "/remote/home/user/documents/readme.txt",
                "/data/mirror/archive/old.zip",
                "/mnt/nfs/shared/team/docs/spec.md",
                "/unrelated/path/file.txt",
                "/remote/home/user",
                "/remote/home/user/projects",
                "C:\\Users\\remote\\Documents\\file.txt",
                "",
                "/",
            ]
        }

        #[test]
        fn trie_and_linear_produce_identical_results() {
            let mappings = generate_test_mappings();
            let trie = PathTrie::from_mappings(&mappings);

            let root = ScanRoot::local(PathBuf::from("/test"));
            let mut root_with_mappings = root;
            for mapping in &mappings {
                root_with_mappings = root_with_mappings.with_rewrite(&mapping.from, &mapping.to);
            }

            for path in generate_test_paths() {
                let trie_result = trie.lookup(path, None);
                let linear_result = root_with_mappings.rewrite_workspace_linear(path, None);

                assert_eq!(
                    trie_result, linear_result,
                    "trie and linear differ for path '{}': trie='{}', linear='{}'",
                    path, trie_result, linear_result
                );
            }
        }

        #[test]
        fn path_mapping_boundary_conditions() {
            let cases = vec![
                // (from, to, input, expected_output_or_none)
                ("/a", "/b", "/a", Some("/b")),
                ("/a", "/b", "/a/", Some("/b/")),
                ("/a", "/b", "/a/file", Some("/b/file")),
                ("/a", "/b", "/ab", None), // no match (not a prefix boundary)
                ("/a/", "/b/", "/a/file", Some("/b/file")),
                // Cross-sep combinations — these pin the "emit exactly one
                // separator at the splice" contract across every combination
                // of trailing-sep-on-`from`, trailing-sep-on-`to`, and
                // leading-sep-on-`rest`:
                //
                //   from has `/`, to has `/`   → to + rest           (rest has no sep)
                ("/a/", "/b/", "/a/file/x", Some("/b/file/x")),
                //   from has `/`, to no `/`    → to + sep + rest     (rest has no sep)
                ("/a/", "/b", "/a/file", Some("/b/file")),
                //   from no `/`, to has `/`    → to + rest[1..]      (drop rest's sep)
                //   Regression: without the drop this produced `"/b//file"`.
                ("/a", "/b/", "/a/file", Some("/b/file")),
                //   from no `/`, to no `/`     → to + rest            (rest keeps its sep)
                (
                    "/a",
                    "/b",
                    "/a/deep/nested/file",
                    Some("/b/deep/nested/file"),
                ),
                // Windows-style backslash flavor of each shape:
                ("C:\\a", "D:\\b\\", "C:\\a\\file", Some("D:\\b\\file")),
                ("C:\\a\\", "D:\\b", "C:\\a\\file", Some("D:\\b\\file")),
            ];

            for (from, to, input, expected) in cases {
                let mapping = PathMapping::new(from, to);
                let result = mapping.apply(input);

                assert_eq!(
                    result.as_deref(),
                    expected,
                    "PathMapping({:?} -> {:?}).apply({:?}) = {:?}, expected {:?}",
                    from,
                    to,
                    input,
                    result,
                    expected
                );
            }
        }

        #[test]
        fn path_mapping_emits_single_separator_at_splice() {
            // Property: for any (from, to, path) where `apply` returns
            // Some(output), `output` never contains `//` or `\\` (as a
            // doubled separator, not the Windows UNC prefix). Consecutive
            // separators are semantically safe under POSIX canonicalization
            // but break string-based path-equality checks in downstream
            // consumers (workspace-matching, cache keys, export manifests).
            let shapes: &[(&str, &str)] = &[
                ("/a", "/b"),
                ("/a", "/b/"),
                ("/a/", "/b"),
                ("/a/", "/b/"),
                ("C:\\a", "D:\\b"),
                ("C:\\a", "D:\\b\\"),
                ("C:\\a\\", "D:\\b"),
                ("C:\\a\\", "D:\\b\\"),
            ];
            let posix_inputs = ["/a", "/a/", "/a/file", "/a/deep/dir/file"];
            let windows_inputs = ["C:\\a", "C:\\a\\", "C:\\a\\file", "C:\\a\\deep\\dir\\file"];

            for (from, to) in shapes {
                let mapping = PathMapping::new(*from, *to);
                let inputs: &[&str] = if from.contains('\\') {
                    &windows_inputs
                } else {
                    &posix_inputs
                };
                for input in inputs {
                    if let Some(output) = mapping.apply(input) {
                        assert!(
                            !output.contains("//"),
                            "PathMapping({:?} -> {:?}).apply({:?}) = {:?} contains `//`",
                            from,
                            to,
                            input,
                            output
                        );
                        // Allow the `\\` UNC prefix only at the start of a
                        // Windows path; look for a doubled backslash anywhere
                        // after position 0.
                        if let Some(pos) = output[1..].find("\\\\") {
                            // ubs:ignore[rust.ownership.panic-macro] — This property assertion reports an unexpected doubled separator with its input and offset.
                            panic!(
                                "PathMapping({:?} -> {:?}).apply({:?}) = {:?} contains doubled `\\\\` at offset {}",
                                from,
                                to,
                                input,
                                output,
                                pos + 1
                            );
                        }
                    }
                }
            }
        }

        #[test]
        fn trie_longest_prefix_match_wins() {
            let mut trie = PathTrie::new();
            trie.insert("/a", "/short", None);
            trie.insert("/a/b", "/medium", None);
            trie.insert("/a/b/c", "/long", None);

            assert_eq!(trie.lookup("/a/x", None), "/short/x");
            assert_eq!(trie.lookup("/a/b/x", None), "/medium/x");
            assert_eq!(trie.lookup("/a/b/c/x", None), "/long/x");
            assert_eq!(trie.lookup("/a/b/c", None), "/long");
        }
    }

    // =========================================================================
    // Contract 6: Connector Scan Contract
    // =========================================================================
    //
    // All connectors must handle empty/missing directories gracefully
    // when given explicit scan roots (not default detection).

    mod connector_scan_contract {
        use super::*;

        #[test]
        fn all_connectors_handle_nonexistent_directory_with_explicit_roots() {
            let nonexistent = PathBuf::from("/nonexistent/path/that/does/not/exist");
            // Use explicit scan roots to disable default detection fallback
            let roots = vec![ScanRoot::local(nonexistent.clone())];
            let ctx = ScanContext::with_roots(nonexistent, roots, None);

            for (slug, factory) in get_connector_factories() {
                let connector = factory();
                let result = connector.scan(&ctx);

                // Should not panic - may return Ok(empty) or Err
                if let Ok(convs) = result {
                    // Empty result is expected for nonexistent explicit root
                    assert!(
                        convs.is_empty(),
                        "connector {} returned conversations for nonexistent explicit root",
                        slug
                    );
                }
            }
        }

        #[test]
        fn all_connectors_handle_empty_directory_with_explicit_roots() {
            let tmp = TempDir::new().expect("create temp dir");
            let tmp_path = tmp.path().to_path_buf();
            // Use explicit scan roots to disable default detection fallback
            let roots = vec![ScanRoot::local(tmp_path.clone())];
            let ctx = ScanContext::with_roots(tmp_path, roots, None);

            for (slug, factory) in get_connector_factories() {
                let connector = factory();
                let result = connector.scan(&ctx);

                if let Ok(convs) = result {
                    assert!(
                        convs.is_empty(),
                        "connector {} returned conversations for empty explicit root",
                        slug
                    );
                }
            }
        }

        #[test]
        fn scan_does_not_panic_on_permission_denied_path() {
            // Use a path that exists but likely has no agent data
            let system_path = if cfg!(target_os = "windows") {
                PathBuf::from("C:\\Windows\\System32")
            } else {
                PathBuf::from("/etc")
            };

            if !system_path.exists() {
                return; // Skip if path doesn't exist
            }

            let roots = vec![ScanRoot::local(system_path.clone())];
            let ctx = ScanContext::with_roots(system_path, roots, None);

            for (_slug, factory) in get_connector_factories() {
                let connector = factory();
                // Should not panic, regardless of result
                let _ = connector.scan(&ctx);
            }
        }
    }

    // =========================================================================
    // Contract 7: Metamorphic Conformance Laws (Bead franken_agent_detection-o9y)
    // =========================================================================
    //
    // Law 1 (Detection-Discovery Monotonicity):
    //   When a canonical session store is populated at root R, both
    //   `detect_installed_agents` (with root override R) and the corresponding
    //   connector's `discover_source_files` + `scan` agree that the store is
    //   present and non-empty.
    //
    // Law 2 (Remote Mirror Equivalence):
    //   Scanning a basename-preserving SSH mirror container `<hash>/<leaf>`
    //   (and trailing-slash contents copy `<hash>/`) with `mirrored_source_path`
    //   yields the same conversations and message content as scanning the local
    //   store directly, while ignoring sibling directories inside `<hash>` and
    //   preserving `Origin::remote(...)`.
    //
    // Law 3 (Atomic I/O Fault Discard):
    //   `JsonlLines` halts immediately on mid-stream reader failure without
    //   polling the broken reader a second time.

    mod metamorphic_conformance_laws {
        use super::*;
        use crate::connectors::jsonl::JsonlLines;
        use crate::types::Origin;
        use std::io::{self, Read};

        struct MirrorCase {
            detect_slug: &'static str,
            factory_slug: &'static str,
            tilde_source: &'static str,
            leaf_dir: &'static str,
            rel_file: &'static str,
            payload: &'static str,
        }

        fn mirror_cases() -> Vec<MirrorCase> {
            vec![
                MirrorCase {
                    detect_slug: "kiro",
                    factory_slug: "kiro",
                    tilde_source: "~/.kiro/sessions/cli",
                    leaf_dir: "cli",
                    rel_file: "a1b2c3d4-0000-0000-0000-000000000001.jsonl",
                    payload: "{\"kind\":\"Prompt\",\"data\":{\"content\":\"hello kiro\"},\"timestamp\":\"2026-03-01T00:00:00Z\"}\n",
                },
                MirrorCase {
                    detect_slug: "pi_agent",
                    factory_slug: "pi_agent",
                    tilde_source: "~/.pi/agent/sessions",
                    leaf_dir: "sessions",
                    rel_file: "--work--/2026-03-01_s1.jsonl",
                    payload: "{\"type\":\"session\",\"id\":\"pi-s1\",\"timestamp\":\"2026-03-01T00:00:00Z\",\"cwd\":\"/work\"}\n{\"type\":\"message\",\"id\":\"m1\",\"timestamp\":\"2026-03-01T00:00:01Z\",\"message\":{\"role\":\"user\",\"content\":\"hello pi\"}}\n",
                },
                MirrorCase {
                    detect_slug: "omp",
                    factory_slug: "omp",
                    tilde_source: "~/.omp/agent/sessions",
                    leaf_dir: "sessions",
                    rel_file: "--work--/2026-03-01_s1.jsonl",
                    payload: "{\"type\":\"session\",\"id\":\"omp-s1\",\"timestamp\":\"2026-03-01T00:00:00Z\",\"cwd\":\"/work\"}\n{\"type\":\"message\",\"id\":\"m1\",\"timestamp\":\"2026-03-01T00:00:01Z\",\"message\":{\"role\":\"user\",\"content\":\"hello omp\"}}\n",
                },
                MirrorCase {
                    detect_slug: "kimi",
                    factory_slug: "kimi",
                    tilde_source: "~/.kimi/sessions",
                    leaf_dir: "sessions",
                    rel_file: "wkey/sess1/wire.jsonl",
                    payload: "{\"type\":\"metadata\",\"protocol_version\":\"1.3\"}\n{\"timestamp\":1770000000.0,\"message\":{\"type\":\"TurnBegin\",\"payload\":{\"role\":\"human\",\"content\":\"hello kimi\"}}}\n",
                },
                MirrorCase {
                    detect_slug: "qwen",
                    factory_slug: "qwen",
                    tilde_source: "~/.qwen/projects",
                    leaf_dir: "projects",
                    rel_file: "proj/chats/0123456789abcdef0123456789abcdef.jsonl",
                    payload: "{\"uuid\":\"u1\",\"parentUuid\":null,\"sessionId\":\"0123456789abcdef0123456789abcdef\",\"timestamp\":\"2026-03-01T00:00:00Z\",\"type\":\"user\",\"message\":{\"role\":\"user\",\"parts\":[{\"text\":\"hello qwen\"}]}}\n",
                },
                MirrorCase {
                    detect_slug: "grok",
                    factory_slug: "grok",
                    tilde_source: "~/.grok/sessions",
                    leaf_dir: "sessions",
                    rel_file: "%2Fwork/sess1/updates.jsonl",
                    payload: "{\"timestamp\":1784388059,\"method\":\"_x.ai/session/update\",\"params\":{\"sessionId\":\"sess1\",\"update\":{\"sessionUpdate\":\"user_message_chunk\",\"content\":{\"type\":\"text\",\"text\":\"hello grok\"}}}}\n",
                },
                MirrorCase {
                    detect_slug: "muse",
                    factory_slug: "muse",
                    tilde_source: "~/.local/share/muse/sessions",
                    leaf_dir: "sessions",
                    rel_file: "2026/03/01/sess1/session.jsonl",
                    payload: "{\"schema_version\":1,\"id\":\"705d0e90-0000-0000-0000-000000000001\",\"stream\":{\"kind\":\"session\",\"id\":\"sess1\"},\"sequence\":1,\"recorded_at\":1785972468194395,\"record_type\":\"event\",\"durability\":\"durable\",\"causation_id\":null,\"payload_type\":\"runtime.session\",\"payload\":{\"kind\":\"run\",\"event\":{\"kind\":\"started\",\"prompt\":\"hello muse\"}}}\n",
                },
                MirrorCase {
                    detect_slug: "continue",
                    factory_slug: "continue",
                    tilde_source: "~/.continue/sessions",
                    leaf_dir: "sessions",
                    rel_file: "sess1.json",
                    payload: "{\"sessionId\":\"sess1\",\"title\":\"Continue\",\"workspaceDirectory\":\"/work\",\"history\":[{\"message\":{\"role\":\"user\",\"content\":\"hello continue\"}}]}\n",
                },
                MirrorCase {
                    detect_slug: "claude",
                    factory_slug: "claude",
                    tilde_source: "~/.claude/projects",
                    leaf_dir: "projects",
                    rel_file: "proj/sess1.jsonl",
                    payload: "{\"type\":\"user\",\"timestamp\":\"2026-03-01T00:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"hello claude\"}}\n",
                },
                MirrorCase {
                    detect_slug: "codex",
                    factory_slug: "codex",
                    tilde_source: "~/.codex/sessions",
                    leaf_dir: "sessions",
                    rel_file: "2026/03/01/rollout-2026-03-01T00-00-00-sess1.jsonl",
                    payload: "{\"timestamp\":\"2026-03-01T00:00:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"hello codex\"}}\n",
                },
                MirrorCase {
                    detect_slug: "prime_agent",
                    factory_slug: "prime_agent",
                    tilde_source: "~/.prime/agent/sessions",
                    leaf_dir: "sessions",
                    rel_file: "proj/sess1.jsonl",
                    payload: "{\"type\":\"session\",\"id\":\"prime-s1\",\"timestamp\":\"2026-03-01T00:00:00Z\",\"cwd\":\"/work\"}\n{\"type\":\"message\",\"id\":\"m1\",\"timestamp\":\"2026-03-01T00:00:01Z\",\"message\":{\"role\":\"user\",\"content\":\"hello prime\"}}\n",
                },
                MirrorCase {
                    detect_slug: "factory",
                    factory_slug: "factory",
                    tilde_source: "~/.factory/sessions",
                    leaf_dir: "sessions",
                    rel_file: "proj/sess1.jsonl",
                    payload: "{\"type\":\"message\",\"id\":\"m1\",\"timestamp\":\"2026-03-01T00:00:00Z\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hello factory\"}]}}\n",
                },
            ]
        }

        fn connector_for(slug: &str) -> Box<dyn crate::connectors::Connector> {
            let (_, factory) = get_connector_factories()
                .into_iter()
                .find(|(s, _)| *s == slug)
                .unwrap_or_else(|| panic!("missing factory for {slug}"));
            factory()
        }

        #[test]
        fn law1_detection_discovery_scan_monotonicity() {
            for case in mirror_cases() {
                let tmp = TempDir::new().expect("tempdir");
                let rel_store = case.tilde_source.trim_start_matches("~/");
                let store_root = tmp.path().join(rel_store);
                let target_file = store_root.join(case.rel_file);
                if let Some(parent) = target_file.parent() {
                    fs::create_dir_all(parent).expect("create parent");
                }
                fs::write(&target_file, case.payload).expect("write fixture");

                let report = detect_installed_agents(&AgentDetectOptions {
                    only_connectors: Some(vec![case.detect_slug.to_string()]),
                    include_undetected: true,
                    root_overrides: vec![AgentDetectRootOverride {
                        slug: case.detect_slug.to_string(),
                        root: store_root.clone(),
                    }],
                })
                .expect("detect_installed_agents");
                assert_eq!(
                    report.summary.detected_count, 1,
                    "Law 1: detect_installed_agents failed for {}",
                    case.detect_slug
                );

                let connector = connector_for(case.factory_slug);
                let ctx = ScanContext::with_roots(
                    store_root.clone(),
                    vec![ScanRoot::local(store_root)],
                    None,
                );
                let discovered = connector
                    .discover_source_files(&ctx)
                    .expect("discover_source_files");
                assert!(
                    !discovered.is_empty(),
                    "Law 1: discover_source_files returned empty for {}",
                    case.factory_slug
                );
                let conversations = connector.scan(&ctx).expect("scan");
                assert_eq!(
                    conversations.len(),
                    1,
                    "Law 1: scan conversation count mismatch for {}",
                    case.factory_slug
                );
                assert!(
                    !conversations[0].messages.is_empty(),
                    "Law 1: scan produced empty messages for {}",
                    case.factory_slug
                );
            }
        }

        #[test]
        fn law2_remote_mirror_equivalence_and_containment() {
            for case in mirror_cases() {
                // 1. Local baseline
                let local_tmp = TempDir::new().expect("local tempdir");
                let rel_store = case.tilde_source.trim_start_matches("~/");
                let local_store = local_tmp.path().join(rel_store);
                let local_file = local_store.join(case.rel_file);
                if let Some(parent) = local_file.parent() {
                    fs::create_dir_all(parent).expect("create local parent");
                }
                fs::write(&local_file, case.payload).expect("write local fixture");

                let connector = connector_for(case.factory_slug);
                let local_ctx = ScanContext::with_roots(
                    local_store.clone(),
                    vec![ScanRoot::local(local_store)],
                    None,
                );
                let local_convs = connector.scan(&local_ctx).expect("local scan");
                assert_eq!(
                    local_convs.len(),
                    1,
                    "baseline scan for {}",
                    case.factory_slug
                );

                // 2. Basename-preserving SSH mirror container `<hash>/<leaf>` + sibling noise
                let mirror_tmp = TempDir::new().expect("mirror tempdir");
                let container = mirror_tmp.path().join("opaque_hash_container");
                let mirrored_leaf = container.join(case.leaf_dir);
                let mirrored_file = mirrored_leaf.join(case.rel_file);
                if let Some(parent) = mirrored_file.parent() {
                    fs::create_dir_all(parent).expect("create mirror parent");
                }
                fs::write(&mirrored_file, case.payload).expect("write mirror fixture");

                // Add unrelated sibling noise inside the container to verify narrow scoping
                let sibling_noise = container.join("unrelated_sibling").join(case.rel_file);
                if let Some(parent) = sibling_noise.parent() {
                    fs::create_dir_all(parent).expect("create sibling parent");
                }
                fs::write(&sibling_noise, case.payload).expect("write sibling noise");

                let remote_origin = Origin::remote("mirror-host");
                let remote_root = ScanRoot::remote(container.clone(), remote_origin.clone(), None)
                    .with_mirrored_source_path(case.tilde_source);
                let remote_ctx = ScanContext::with_roots(container, vec![remote_root], None);

                let remote_discovered = connector
                    .discover_source_files(&remote_ctx)
                    .expect("remote discover");
                assert_eq!(
                    remote_discovered.len(),
                    1,
                    "Law 2: remote mirror discovery count mismatch for {} (source={})",
                    case.factory_slug,
                    case.tilde_source
                );
                assert_eq!(
                    remote_discovered[0].origin, remote_origin,
                    "Law 2: remote mirror discovery lost origin for {}",
                    case.factory_slug
                );

                let remote_convs = connector.scan(&remote_ctx).expect("remote scan");
                assert_eq!(
                    remote_convs.len(),
                    local_convs.len(),
                    "Law 2: remote mirror scan count mismatch for {}",
                    case.factory_slug
                );
                assert_eq!(
                    remote_convs[0].messages.len(),
                    local_convs[0].messages.len(),
                    "Law 2: remote mirror message count mismatch for {}",
                    case.factory_slug
                );
                assert_eq!(
                    remote_convs[0].messages[0].content, local_convs[0].messages[0].content,
                    "Law 2: remote mirror message content mismatch for {}",
                    case.factory_slug
                );

                // 3. Trailing-slash rsync contents copy (`<tilde_source>/` directly into `<hash>/`)
                let contents_tmp = TempDir::new().expect("contents tempdir");
                let contents_container = contents_tmp.path().join("contents_hash_container");
                let contents_file = contents_container.join(case.rel_file);
                if let Some(parent) = contents_file.parent() {
                    fs::create_dir_all(parent).expect("create contents parent");
                }
                fs::write(&contents_file, case.payload).expect("write contents fixture");

                let trailing_source = format!("{}/", case.tilde_source);
                let contents_root =
                    ScanRoot::remote(contents_container.clone(), remote_origin, None)
                        .with_mirrored_source_path(trailing_source);
                let contents_ctx =
                    ScanContext::with_roots(contents_container, vec![contents_root], None);
                let contents_convs = connector.scan(&contents_ctx).expect("contents scan");
                assert_eq!(
                    contents_convs.len(),
                    1,
                    "Law 2: trailing-slash contents copy scan mismatch for {}",
                    case.factory_slug
                );
            }
        }

        struct FaultAfterPrefixReader {
            prefix: io::Cursor<Vec<u8>>,
            kind: io::ErrorKind,
            faulted: bool,
        }

        impl Read for FaultAfterPrefixReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let n = self.prefix.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                assert!(
                    !self.faulted,
                    "Law 3 violation: reader polled again after returning an I/O error"
                );
                self.faulted = true;
                Err(io::Error::new(self.kind, "injected mid-stream fault"))
            }
        }

        #[test]
        fn law3_jsonl_lines_halts_immediately_on_io_fault_across_error_kinds() {
            for kind in [
                io::ErrorKind::Other,
                io::ErrorKind::UnexpectedEof,
                io::ErrorKind::InvalidData,
                io::ErrorKind::PermissionDenied,
            ] {
                let reader = io::BufReader::new(FaultAfterPrefixReader {
                    prefix: io::Cursor::new(b"{\"line\":1}\n{\"partial\":".to_vec()),
                    kind,
                    faulted: false,
                });
                let mut lines = JsonlLines::new(reader);
                assert_eq!(
                    lines.next().transpose().expect("first line ok").as_deref(),
                    Some("{\"line\":1}")
                );
                let err = lines
                    .next()
                    .expect("second item must be Err")
                    .expect_err("mid-stream fault must surface as Err");
                assert_eq!(err.kind(), kind);
                assert!(
                    lines.next().is_none(),
                    "JsonlLines must fuse to None after an I/O error"
                );
            }
        }
    }
}
