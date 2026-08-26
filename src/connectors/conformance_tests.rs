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
                    .unwrap_or_else(|err| panic!("connector {slug} discovery failed: {err}"));

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
            // agent_slug must not be empty
            assert!(
                !conv.agent_slug.is_empty(),
                "connector {} produced conversation with empty agent_slug",
                connector_slug
            );

            // source_path must be set (even if synthetic)
            assert!(
                !conv.source_path.as_os_str().is_empty(),
                "connector {} produced conversation with empty source_path",
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
            let valid_roles = ["user", "assistant", "system", "tool", "function"];
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

            for (slug, rel) in fixtures {
                let root = manifest.join(rel);
                assert!(
                    root.exists(),
                    "checked-in fixture store missing: {}",
                    root.display()
                );
                let ctx = ScanContext::with_roots(root.clone(), vec![ScanRoot::local(root)], None);

                let matched = get_connector_factories()
                    .into_iter()
                    .find(|(factory_slug, _)| factory_slug == slug);
                let Some((_, factory)) = matched else {
                    panic!("no registered factory for fixture connector {slug}");
                };

                let convs = factory().scan(&ctx).unwrap_or_else(|err| {
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
            }
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
}
