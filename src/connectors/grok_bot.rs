//! Grok Bot desktop's chat-only, lossy rolling transcript replicas (GH447).
//!
//! This is separate from the Grok CLI connector. A replica belongs to an
//! account and agent, not a session or local workspace. Provider entry IDs are
//! retained for hosts to reconcile FIFO rewrites; `idx` is document order in
//! the current window, not a durable sequence number.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use super::utils::{dedupe_path_key, env_var_nonempty, read_capped};
use super::{
    Connector, DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot, SourceCompletion,
    SourceScanHooks, file_modified_since, franken_detection_for_connector,
};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

const SLUG: &str = "grok_bot";
const REPLICA_PREFIX: &str = "sand.client.slice.account.";
const REPLICA_SEPARATOR: &str = ".transcript.replicas.";

#[derive(Default)]
pub struct GrokBotConnector;

impl GrokBotConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        if !ctx.use_default_detection() {
            return ctx.scan_roots.clone();
        }
        let root = env_var_nonempty("CASS_GROK_BOT_DATA_ROOT")
            .map(|raw| crate::expand_leading_tilde(&raw, dirs::home_dir().as_deref()))
            .or_else(|| {
                dirs::home_dir().map(|home| {
                    home.join("Library/Application Support/Grok Bot/sand-client-persistence")
                })
            });
        root.into_iter().map(ScanRoot::local).collect()
    }

    fn discover(ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        let mut sources = Vec::new();
        let mut seen = HashSet::new();
        for root in Self::source_roots(ctx) {
            // Explicit roots may be a replica, its persistence directory, or
            // the Grok Bot configuration directory. Never recurse elsewhere.
            let paths = if root.path.is_file() {
                vec![root.path.clone()]
            } else {
                let persistence = root.path.join("sand-client-persistence");
                let directory = if persistence.is_dir() {
                    &persistence
                } else {
                    &root.path
                };
                if !directory.exists() {
                    continue;
                }
                fs::read_dir(directory)
                    .with_context(|| format!("read Grok Bot directory {}", directory.display()))?
                    .map(|entry| entry.map(|entry| entry.path()))
                    .collect::<std::io::Result<Vec<_>>>()?
            };
            for path in paths {
                if !path.is_file()
                    || replica_key(&path).is_none()
                    || !file_modified_since(&path, ctx.since_ts)
                    || !seen.insert(dedupe_path_key(&path))
                {
                    continue;
                }
                sources.push(
                    DiscoveredSourceFile::new(
                        SLUG,
                        &root,
                        path,
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }
        }
        sources.sort_by(|a, b| a.source_path.cmp(&b.source_path));
        Ok(sources)
    }
}

/// Decode only canonical lowercase, unpadded RFC4648 base32. Checking the
/// residual bits prevents alternate filenames from naming the same key.
fn decode_filename(name: &str) -> Option<String> {
    if name.is_empty() || !matches!(name.len() % 8, 0 | 2 | 4 | 5 | 7) {
        return None;
    }
    let mut output = Vec::new();
    let mut bits = 0_u32;
    let mut pending = 0_u16;
    for byte in name.bytes() {
        let digit = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        pending = (pending << 5) | u16::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(u8::try_from(pending >> bits).ok()?);
            pending &= (1 << bits) - 1;
        }
    }
    if pending != 0 {
        return None;
    }
    String::from_utf8(output).ok()
}

fn replica_key(path: &Path) -> Option<String> {
    let encoded = path.file_name()?.to_str()?.strip_suffix(".blob")?;
    let key = decode_filename(encoded)?;
    let (account, agent) = key
        .strip_prefix(REPLICA_PREFIX)?
        .split_once(REPLICA_SEPARATOR)?;
    let subject = account.strip_prefix("auth0%7Cuser_")?;
    // The reported account subject is a 26-character ULID. Keep the key
    // grammar narrow rather than accidentally accepting other account slices.
    if subject.len() != 26
        || !matches!(subject.as_bytes()[0], b'0'..=b'7')
        || !subject
            .bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
    {
        return None;
    }
    if agent.len() != 36
        || !agent.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
    {
        return None;
    }
    Some(key)
}

fn parse_replica(source: &DiscoveredSourceFile) -> Result<Option<NormalizedConversation>> {
    let key = replica_key(&source.source_path).context("not a Grok Bot transcript replica key")?;
    let raw =
        read_capped(&source.source_path)?.context("Grok Bot replica exceeds scan size cap")?;
    let envelope: Value = serde_json::from_str(&raw).context("invalid Grok Bot replica JSON")?;
    if envelope.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        bail!("unsupported Grok Bot replica schemaVersion");
    }
    let entries = envelope
        .get("value")
        .and_then(|v| v.get("entries"))
        .and_then(Value::as_array)
        .context("Grok Bot replica value.entries must be an array")?;
    let mut messages = Vec::new();
    let mut missing_entry_id_count = 0_usize;
    for entry in entries {
        let kind = entry.get("kind").and_then(Value::as_str);
        let (role, content) = match kind {
            Some("message") => {
                let Some(role @ ("user" | "assistant")) = entry.get("role").and_then(Value::as_str)
                else {
                    continue;
                };
                (role, entry.get("content").and_then(Value::as_str))
            }
            Some("send-message")
                if entry
                    .get("message")
                    .and_then(|v| v.get("type"))
                    .and_then(Value::as_str)
                    == Some("text") =>
            {
                (
                    "assistant",
                    entry
                        .get("message")
                        .and_then(|v| v.get("content"))
                        .and_then(Value::as_str),
                )
            }
            _ => continue,
        };
        let Some(content) = content.filter(|s| !s.trim().is_empty()) else {
            continue;
        };
        let Some(id) = entry
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
        else {
            missing_entry_id_count += 1;
            continue;
        };
        // Never copy raw entries: even chat entries can carry rich text links,
        // routing information or future non-chat payloads beside the text.
        let mut extra = json!({"grok_bot_entry_kind": kind, "grok_bot_entry_id": id});
        if let Some(request) = entry.get("requestId").and_then(Value::as_str) {
            extra["request_id"] = json!(request);
        }
        messages.push(NormalizedMessage {
            idx: i64::try_from(messages.len()).context("too many Grok Bot messages")?,
            role: role.to_string(),
            author: None,
            created_at: entry.get("timestampMs").and_then(Value::as_i64),
            content: content.to_string(),
            extra,
            snippets: Vec::new(),
            invocations: Vec::new(),
        });
    }
    if messages.is_empty() {
        if missing_entry_id_count > 0 {
            bail!("Grok Bot replica has {missing_entry_id_count} chat entries without native IDs");
        }
        return Ok(None);
    }
    Ok(Some(NormalizedConversation {
        agent_slug: SLUG.to_string(),
        external_id: Some(key),
        title: Some("Grok Bot rolling transcript".to_string()),
        workspace: None,
        source_path: source.source_path.clone(),
        started_at: messages.iter().filter_map(|m| m.created_at).min(),
        ended_at: messages.iter().filter_map(|m| m.created_at).max(),
        metadata: json!({
            "history_kind": "rolling_agent_transcript", "history_complete": false,
            "chat_only": true, "observed_entry_cap": 200, "source_entry_count": entries.len(),
            "schema_version": 1, "source_id": source.origin.source_id,
            "missing_entry_id_count": missing_entry_id_count,
        }),
        messages,
    }))
}

impl Connector for GrokBotConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector(SLUG).unwrap_or_else(DetectionResult::not_found)
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
    fn supports_source_boundaries(&self) -> bool {
        true
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Self::discover(ctx)
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        self.scan_with_source_boundaries(ctx, &mut SourceScanHooks::default(), on_conversation)
    }

    fn scan_with_source_boundaries(
        &self,
        ctx: &ScanContext,
        hooks: &mut SourceScanHooks<'_>,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        for source in Self::discover(ctx)? {
            if !hooks.should_scan(&source) {
                continue;
            }
            let conversation = match parse_replica(&source) {
                Ok(conversation) => conversation,
                Err(error) => {
                    tracing::warn!(path = %source.source_path.display(), %error, "skipping malformed Grok Bot replica");
                    continue;
                }
            };
            let conversations_emitted = usize::from(conversation.is_some());
            if let Some(conversation) = conversation {
                on_conversation(conversation)?;
            }
            if !source.fs_metadata_changed() {
                hooks.complete(&SourceCompletion {
                    source,
                    required_sidecars: Vec::new(),
                    conversations_emitted,
                })?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // Original sanitized 13-entry excerpt, with JSON whitespace changed only:
    // https://github.com/Dicklesworthstone/coding_agent_session_search/issues/447#issuecomment-5592555144
    // This fixture proves the reported structure, not native-app interoperability.
    const REPORTER_SAMPLE: &str = include_str!("../../tests/fixtures/grok_bot_reporter_0440.json");
    const KEY: &str = "sand.client.slice.account.auth0%7Cuser_00000000000000000000000000.transcript.replicas.81da155f-cc4c-58b3-aadf-770858d5e55c";

    fn encode(key: &str) -> String {
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        // Deliberately use a bit-vector reference encoder independent of the
        // production decoder's accumulator and padding checks.
        let bits: Vec<bool> = key
            .bytes()
            .flat_map(|byte| (0..8).rev().map(move |bit| byte & (1 << bit) != 0))
            .collect();
        bits.chunks(5)
            .map(|chunk| {
                let value = chunk
                    .iter()
                    .fold(0_usize, |v, bit| (v << 1) | usize::from(*bit))
                    << (5 - chunk.len());
                char::from(ALPHABET[value])
            })
            .collect()
    }

    fn context(root: &Path, since_ts: Option<i64>) -> ScanContext {
        ScanContext {
            data_dir: root.to_path_buf(),
            scan_roots: vec![ScanRoot::local(root.to_path_buf())],
            since_ts,
            progress_tick: None,
        }
    }

    fn write_sample(root: &Path) -> PathBuf {
        fs::create_dir_all(root).unwrap();
        let path = root.join(format!("{}.blob", encode(KEY)));
        fs::write(&path, REPORTER_SAMPLE).unwrap();
        path
    }

    #[test]
    fn grok_bot_reporter_sample_preserves_chat_order_and_excludes_non_chat_payloads() {
        let temp = TempDir::new().unwrap();
        let path = write_sample(temp.path());
        let before_bytes = fs::read(&path).unwrap();
        let before_mtime = fs::metadata(&path).unwrap().modified().unwrap();
        let conversations = GrokBotConnector::new().scan(&context(&path, None)).unwrap();
        assert_eq!(conversations.len(), 1);
        let conversation = &conversations[0];
        assert_eq!(conversation.external_id.as_deref(), Some(KEY));
        assert_eq!(conversation.agent_slug, "grok_bot");
        assert_eq!(conversation.workspace, None);
        assert_eq!(conversation.source_path, path);
        assert_eq!(conversation.metadata["history_complete"], false);
        assert_eq!(conversation.metadata["chat_only"], true);
        assert_eq!(conversation.metadata["source_entry_count"], 13);
        assert_eq!(conversation.started_at, Some(1_767_225_622_759));
        assert_eq!(conversation.ended_at, Some(1_767_485_345_477));
        let messages = &conversation.messages;
        assert_eq!(
            messages
                .iter()
                .map(|m| m.extra["grok_bot_entry_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["t79t", "t28y4", "p63f6", "f65h7", "h45w", "l08t", "g02u2"]
        );
        assert_eq!(
            messages.iter().map(|m| m.role.as_str()).collect::<Vec<_>>(),
            [
                "user",
                "assistant",
                "assistant",
                "assistant",
                "user",
                "user",
                "assistant"
            ]
        );
        assert_eq!(
            messages.iter().map(|m| m.idx).collect::<Vec<_>>(),
            (0..7).collect::<Vec<_>>()
        );
        assert_eq!(
            messages[2].extra["request_id"],
            messages[3].extra["request_id"]
        );
        assert!(
            messages
                .iter()
                .filter(|m| m.role == "user")
                .all(|m| m.extra["request_id"] != messages[2].extra["request_id"])
        );
        // Compare every admitted content field to the genuine-structure input.
        let original: Value = serde_json::from_str(REPORTER_SAMPLE).unwrap();
        for (message, source_idx) in messages.iter().zip([1, 2, 3, 4, 5, 7, 12]) {
            let entry = &original["value"]["entries"][source_idx];
            let expected = if entry["kind"] == "message" {
                &entry["content"]
            } else {
                &entry["message"]["content"]
            };
            assert_eq!(message.content, expected.as_str().unwrap());
            assert!(message.snippets.is_empty());
            assert!(message.invocations.is_empty());
        }
        let serialized = serde_json::to_string(conversation).unwrap();
        for excluded in [
            "secretRequest",
            "service-f62cc8",
            "proposedRule",
            "respondedValue",
            "helpText",
            "service-fc6467",
            "file_path",
            "segc45381",
            "automationName",
            "richText",
            "toAgent",
            "lorem sit labore commodo",
        ] {
            assert!(
                !serialized.contains(excluded),
                "non-chat field leaked: {excluded}"
            );
        }
        assert_eq!(fs::read(&path).unwrap(), before_bytes);
        assert_eq!(
            fs::metadata(&path).unwrap().modified().unwrap(),
            before_mtime
        );
    }

    #[test]
    fn grok_bot_filename_admission_is_canonical_and_replica_only() {
        for (plain, encoded) in [
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(decode_filename(encoded).as_deref(), Some(plain));
            assert_eq!(encode(plain), encoded);
        }
        for malformed in ["", "m", "MY", "my======", "mz", "m0", "m1", "m8", "é"] {
            assert_eq!(decode_filename(malformed), None, "{malformed}");
        }
        assert_eq!(
            replica_key(Path::new(&format!("{}.blob", encode(KEY)))).as_deref(),
            Some(KEY)
        );
        for foreign in [
            KEY.replace("transcript.replicas", "roster.last-roster"),
            KEY.replace("transcript.replicas", "composer-drafts"),
            KEY.replace("account.", "accountx."),
            KEY.replace("auth0%7Cuser_", "auth0|user_"),
            KEY.replace("auth0%7Cuser_", "auth0%7cuser_"),
            KEY.replace("00000000000000000000000000", ""),
            KEY.replace("user_000", "user_800"),
            KEY.replace("81da155f", "81DA155F"),
            format!("{KEY}.extra"),
            format!("{KEY}/secret"),
        ] {
            assert_eq!(
                replica_key(Path::new(&format!("{}.blob", encode(&foreign)))),
                None,
                "{foreign}"
            );
        }
        for suffix in ["", ".json", ".BLOB", ".blob.json", ".blob.blob"] {
            assert_eq!(
                replica_key(Path::new(&format!("{}{suffix}", encode(KEY)))),
                None
            );
        }
    }

    #[test]
    fn grok_bot_roots_discovery_and_boundaries_preserve_provenance() {
        let temp = TempDir::new().unwrap();
        let config = temp.path().join("Grok Bot 空間");
        let persistence = config.join("sand-client-persistence");
        let path = write_sample(&persistence);
        fs::write(
            persistence.join(format!(
                "{}.blob",
                encode(&KEY.replace("transcript.replicas", "roster.last-roster"),)
            )),
            REPORTER_SAMPLE,
        )
        .unwrap();
        let nested = persistence.join("unrelated");
        write_sample(&nested);
        let connector = GrokBotConnector::new();
        for root in [&config, &persistence, &path] {
            let mut ctx = context(root, None);
            ctx.scan_roots[0].origin.source_id = "remote-fixture".to_string();
            let sources = connector.discover_source_files(&ctx).unwrap();
            assert_eq!(sources.len(), 1);
            assert_eq!(sources[0].source_path, path);
            assert_eq!(sources[0].scan_root, *root);
            assert_eq!(sources[0].origin.source_id, "remote-fixture");
            let mut completions = Vec::new();
            let mut complete = |c: &SourceCompletion| {
                completions.push(c.clone());
                Ok(())
            };
            let mut conversations = Vec::new();
            connector
                .scan_with_source_boundaries(
                    &ctx,
                    &mut SourceScanHooks {
                        should_scan_source: None,
                        on_source_complete: Some(&mut complete),
                    },
                    &mut |c| {
                        conversations.push(c);
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(conversations.len(), 1);
            assert_eq!(completions.len(), 1);
            assert_eq!(completions[0].source, sources[0]);
            assert_eq!(completions[0].conversations_emitted, 1);
            assert_eq!(conversations[0].metadata["source_id"], "remote-fixture");
        }
        assert!(
            connector
                .scan(&context(temp.path(), None))
                .unwrap()
                .is_empty(),
            "must not search arbitrary home descendants"
        );
        assert!(
            connector
                .scan(&context(&temp.path().join("missing"), None))
                .unwrap()
                .is_empty()
        );
        assert!(
            connector
                .scan(&context(&path, Some(i64::MAX)))
                .unwrap()
                .is_empty()
        );
        let detection = crate::detect_installed_agents(&crate::AgentDetectOptions {
            only_connectors: Some(vec!["grok-bot".to_string()]),
            include_undetected: true,
            root_overrides: vec![crate::AgentDetectRootOverride {
                slug: "grok_bot".to_string(),
                root: persistence.clone(),
            }],
        })
        .unwrap();
        assert!(detection.installed_agents[0].detected);
        assert_eq!(detection.installed_agents[0].slug, "grok_bot");
    }

    #[test]
    fn grok_bot_malformed_empty_and_callback_failure_never_fake_completion() {
        let temp = TempDir::new().unwrap();
        let path = write_sample(temp.path());
        let ctx = context(&path, None);
        for body in [
            "{",
            "{}",
            r#"{"schemaVersion":2,"value":{"entries":[]}}"#,
            r#"{"schemaVersion":1,"value":{"entries":{}}}"#,
            r#"{"schemaVersion":1,"value":{"entries":[{"kind":"message","role":"user","content":"missing identity"}]}}"#,
        ] {
            fs::write(&path, body).unwrap();
            let mut completions = 0;
            let mut complete = |_: &SourceCompletion| {
                completions += 1;
                Ok(())
            };
            GrokBotConnector::new()
                .scan_with_source_boundaries(
                    &ctx,
                    &mut SourceScanHooks {
                        should_scan_source: None,
                        on_source_complete: Some(&mut complete),
                    },
                    &mut |_| panic!("malformed input emitted a conversation"),
                )
                .unwrap();
            assert_eq!(completions, 0);
        }
        fs::write(&path, r#"{"schemaVersion":1,"value":{"entries":[]}}"#).unwrap();
        assert!(GrokBotConnector::new().scan(&ctx).unwrap().is_empty());
        fs::write(&path, REPORTER_SAMPLE).unwrap();
        let mut completions = 0;
        let mut complete = |_: &SourceCompletion| {
            completions += 1;
            Ok(())
        };
        let error = GrokBotConnector::new()
            .scan_with_source_boundaries(
                &ctx,
                &mut SourceScanHooks {
                    should_scan_source: None,
                    on_source_complete: Some(&mut complete),
                },
                &mut |_| bail!("host transaction failed"),
            )
            .unwrap_err();
        assert!(error.to_string().contains("host transaction failed"));
        assert_eq!(completions, 0);
    }

    #[test]
    fn grok_bot_missing_native_ids_are_counted_and_do_not_expand_the_chat_allowlist() {
        let temp = TempDir::new().unwrap();
        let path = write_sample(temp.path());
        fs::write(&path, json!({"schemaVersion":1,"value":{"entries":[
            {"kind":"message","role":"user","content":"excluded missing identity"},
            {"kind":"send-message","id":"   ","message":{"type":"text","content":"excluded blank identity"}},
            {"kind":"message","id":"","role":"assistant","content":"excluded empty identity"},
            {"kind":"message","role":"system","content":"excluded system payload"},
            {"kind":"message","role":"assistant","content":{"text":"excluded structured content"}},
            {"kind":"send-message","message":{"content":"excluded missing type"}},
            {"kind":"send-message","id":"native-reply","message":{"type":"text","content":"outbound text","approval":{"proposedRule":"excluded adjacent permission"}}},
            {"kind":"message","role":"user","content":"   ","nested":{"content":"excluded recursive content"}}
        ]}}).to_string()).unwrap();
        let conversations = GrokBotConnector::new().scan(&context(&path, None)).unwrap();
        let messages = &conversations[0].messages;
        assert_eq!(messages.len(), 1);
        assert_eq!(conversations[0].metadata["missing_entry_id_count"], 3);
        assert_eq!(messages[0].content, "outbound text");
        assert_eq!(messages[0].created_at, None);
        assert_eq!(messages[0].extra["grok_bot_entry_id"], "native-reply");
        assert!(
            !serde_json::to_string(&conversations)
                .unwrap()
                .contains("excluded")
        );
    }

    #[test]
    fn grok_bot_fifo_rewrite_keeps_replica_and_entry_ids_without_claiming_full_history() {
        let temp = TempDir::new().unwrap();
        let path = write_sample(temp.path());
        let window = |start: u32| {
            json!({"schemaVersion":1,"value":{"entries": (start..start + 200).map(|i| json!({
            "kind":"send-message", "id":format!("entry-{i}"), "message":{"type":"text","content":"same-time identical chat"}, "timestampMs":1_767_225_622_759_i64
        })).collect::<Vec<_>>()}})
        };
        fs::write(&path, window(1).to_string()).unwrap();
        let first = GrokBotConnector::new()
            .scan(&context(&path, None))
            .unwrap()
            .pop()
            .unwrap();
        let watermark = fs::metadata(&path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        fs::write(&path, window(2).to_string()).unwrap();
        let second = GrokBotConnector::new()
            .scan(&context(&path, Some(i64::try_from(watermark).unwrap())))
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(first.external_id, second.external_id);
        assert_eq!(first.messages.len(), 200);
        assert_eq!(second.messages.len(), 200);
        assert_eq!(
            first.messages[1].extra["grok_bot_entry_id"],
            second.messages[0].extra["grok_bot_entry_id"]
        );
        assert_eq!(second.messages[199].extra["grok_bot_entry_id"], "entry-201");
        assert_eq!(second.metadata["history_complete"], false);
        assert_eq!(second.metadata["observed_entry_cap"], 200);
        let replay = GrokBotConnector::new().scan(&context(&path, None)).unwrap();
        assert_eq!(
            serde_json::to_value(&replay[0]).unwrap(),
            serde_json::to_value(&second).unwrap()
        );
        for other in [
            KEY.replace("user_000", "user_001"),
            KEY.replace("81da155f", "91da155f"),
        ] {
            let other_path = temp.path().join(format!("{}.blob", encode(&other)));
            fs::write(&other_path, window(2).to_string()).unwrap();
            let other_conversation = GrokBotConnector::new()
                .scan(&context(&other_path, None))
                .unwrap()
                .pop()
                .unwrap();
            assert_ne!(other_conversation.external_id, first.external_id);
        }
    }
}
