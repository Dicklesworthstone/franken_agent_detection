//! Shared Codebuff / Freebuff CLI history (CASS GH423, FAD #21).
//!
//! Source contract: CodebuffAI/freebuff commit
//! 0cbff57aed44d5a012b9dbb93912884ba1be0ccc, cli/src/types/chat.ts,
//! cli/src/project-files.ts and cli/src/utils/run-state-storage.ts. Both
//! product names resolve to repository 826515105 and the same Manicode store.
//! No per-chat writer/version marker exists: this connector names the lineage,
//! never the writing binary. The transcript is an unversioned `ChatMessage[]`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use walkdir::WalkDir;

use super::utils::{env_var_nonempty, read_capped};
use super::{
    Connector, DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot,
    file_modified_since, franken_detection_for_connector, parse_timestamp,
};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
};

const SLUG: &str = "codebuff";
const MESSAGES: &str = "chat-messages.json";
const RUN_STATE: &str = "run-state.json";

#[derive(Default)]
pub struct CodebuffConnector;

impl CodebuffConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        if !ctx.use_default_detection() {
            return ctx.scan_roots.clone();
        }
        env_var_nonempty("CASS_CODEBUFF_DATA_ROOT")
            .map(|raw| crate::expand_leading_tilde(&raw, dirs::home_dir().as_deref()))
            .or_else(|| dirs::home_dir().map(|home| home.join(".config/manicode/projects")))
            .into_iter()
            .map(ScanRoot::local)
            .collect()
    }

    fn discover(ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        let mut sources = Vec::new();
        let mut seen = HashSet::new();
        for root in Self::roots(ctx) {
            // Only the shared projects tree or an explicitly named transcript
            // is eligible. Do not walk arbitrary sibling-product directories.
            let candidates = if root.path.is_file() {
                vec![root.path.clone()]
            } else {
                let projects = if root.path.file_name().is_some_and(|name| name == "projects") {
                    root.path.clone()
                } else if root.path.join("projects").is_dir() {
                    root.path.join("projects")
                } else {
                    root.path.join(".config/manicode/projects")
                };
                if !projects.exists() {
                    continue;
                }
                let mut candidates = Vec::new();
                for entry in WalkDir::new(projects).min_depth(4).max_depth(4) {
                    let entry = entry.context("cannot enumerate Codebuff / Freebuff history")?;
                    if entry.file_type().is_file() {
                        candidates.push(entry.into_path());
                    }
                }
                candidates
            };
            for path in candidates {
                let Some(key) = session_key(&path) else {
                    continue;
                };
                if !seen.insert((root.origin.source_id.clone(), key)) {
                    continue;
                }
                let state_path = path.with_file_name(RUN_STATE);
                let changed = file_modified_since(&path, ctx.since_ts)
                    || (state_path.is_file() && file_modified_since(&state_path, ctx.since_ts));
                if !changed {
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
                if state_path.is_file() {
                    sources.push(
                        DiscoveredSourceFile::new(
                            SLUG,
                            &root,
                            state_path,
                            DiscoveredSourceRole::MetadataSidecar,
                            false,
                        )
                        .with_fs_metadata(),
                    );
                }
            }
        }
        sources.sort_by(|a, b| a.source_path.cmp(&b.source_path));
        Ok(sources)
    }
}

// The directory ID is native, not synthesized from a message timestamp.
// Include the physical store and project: independent config profiles can
// contain the same native project/chat IDs. Like Aider's path-scoped identity,
// relocation is a new namespace; this path is never treated as a workspace.
// Canonicalizing makes the key independent of home/config/projects/file scan
// selectors and of symlink aliases of the same store.
fn session_key(path: &Path) -> Option<String> {
    let canonical_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let path = canonical_path.as_path();
    if path.file_name()? != MESSAGES {
        return None;
    }
    let chat = path.parent()?;
    let chats = chat.parent()?;
    let project = chats.parent()?;
    if chats.file_name()? != "chats" || project.parent()?.file_name()? != "projects" {
        return None;
    }
    let id = chat.file_name()?.to_str()?;
    let store = project.parent()?.parent()?;
    let project = project.file_name()?.to_str()?;
    serde_json::to_string(&(store, project, id)).ok()
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("unsupported Codebuff / Freebuff record: missing string {key}"))
}

fn render_blocks(blocks: &[Value], invocations: &mut Vec<NormalizedInvocation>) -> Result<String> {
    let mut content = Vec::new();
    for block in blocks {
        match required_string(block, "type")? {
            "text" | "plan" => content.push(required_string(block, "content")?.to_owned()),
            "tool" => {
                let name = required_string(block, "toolName")?;
                let call_id = required_string(block, "toolCallId")?;
                let input = block.get("input").context("tool block has no input")?;
                invocations.push(NormalizedInvocation {
                    kind: "tool".into(),
                    name: name.into(),
                    raw_name: None,
                    call_id: Some(call_id.into()),
                    arguments: Some(input.clone()),
                });
                content.push(format!("{name}: {input}"));
                if let Some(output) = block.get("output") {
                    content.push(
                        output
                            .as_str()
                            .context("tool output must be a string")?
                            .into(),
                    );
                } else if let Some(output) = block.get("outputRaw") {
                    content.push(output.to_string());
                }
            }
            "agent" => {
                content.push(required_string(block, "content")?.to_owned());
                if let Some(blocks) = block.get("blocks") {
                    content.push(render_blocks(
                        blocks.as_array().context("agent blocks must be an array")?,
                        invocations,
                    )?);
                }
            }
            "image" => {
                // Preserve the original block in extra, but do not index base64.
                let media = required_string(block, "mediaType")?;
                content.push(format!("[image: {media}]"));
            }
            "agent-list" | "mode-divider" | "ask-user" | "sponsored-proposal" => {
                content.push(block.to_string());
            }
            // Upstream marks html blocks as nonserializable UI state. Treat
            // persisted html and future block types as unsupported, not empty.
            _ => bail!("unsupported Codebuff / Freebuff content block type"),
        }
    }
    Ok(content.join("\n"))
}

fn parse_session(source: &DiscoveredSourceFile) -> Result<Option<NormalizedConversation>> {
    let external_id =
        session_key(&source.source_path).context("not a shared CLI transcript path")?;
    let raw =
        read_capped(&source.source_path)?.context("shared CLI transcript exceeds scan size cap")?;
    let records: Value =
        serde_json::from_str(&raw).context("invalid Codebuff / Freebuff transcript JSON")?;
    let records = records
        .as_array()
        .context("unsupported Codebuff / Freebuff transcript: expected ChatMessage array")?;
    let mut messages = Vec::new();
    let mut ids = HashSet::new();
    for (idx, record) in records.iter().enumerate() {
        let id = required_string(record, "id")?;
        ensure!(
            !id.trim().is_empty() && ids.insert(id),
            "missing or duplicate shared CLI message ID at record {idx}"
        );
        let variant = required_string(record, "variant")?;
        let role = match variant {
            "user" => "user",
            "ai" | "agent" => "assistant",
            "error" => "system",
            _ => bail!("unsupported shared CLI message variant at record {idx}"),
        };
        let base = required_string(record, "content")?;
        let timestamp = required_string(record, "timestamp")?;
        let created_at = parse_timestamp(&Value::String(timestamp.into()))
            .with_context(|| format!("invalid shared CLI timestamp at record {idx}"))?;
        let mut invocations = Vec::new();
        let block_text = record
            .get("blocks")
            .map(|blocks| {
                render_blocks(
                    blocks
                        .as_array()
                        .context("message blocks must be an array")?,
                    &mut invocations,
                )
            })
            .transpose()?
            .unwrap_or_default();
        let content = if block_text.is_empty() || block_text == base {
            base.to_owned()
        } else if base.is_empty() {
            block_text
        } else {
            format!("{base}\n{block_text}")
        };
        // Preserve chat fields and all original blocks without projecting the
        // embedded SDK execution state (file trees, system prompts, etc.) into
        // the normalized transcript. Credits are never re-labelled as tokens.
        let mut extra = record.clone();
        if let Some(metadata) = extra.get_mut("metadata").and_then(Value::as_object_mut) {
            metadata.remove("runState");
        }
        extra["codebuff_message_id"] = json!(id);
        messages.push(NormalizedMessage {
            idx: i64::try_from(idx).context("too many shared CLI messages")?,
            role: role.into(),
            author: record
                .pointer("/agent/agentName")
                .and_then(Value::as_str)
                .map(str::to_owned),
            created_at: Some(created_at),
            content,
            extra,
            snippets: Vec::new(),
            invocations,
        });
    }
    if messages.is_empty() {
        return Ok(None);
    }
    let (workspace, metadata) = session_metadata(source);
    Ok(Some(NormalizedConversation {
        agent_slug: SLUG.into(),
        external_id: Some(external_id),
        title: messages
            .iter()
            .find(|m| m.role == "user")
            .map(|m| m.content.chars().take(120).collect()),
        workspace,
        source_path: source.source_path.clone(),
        started_at: messages.iter().filter_map(|m| m.created_at).min(),
        ended_at: messages.iter().filter_map(|m| m.created_at).max(),
        metadata,
        messages,
    }))
}

fn session_metadata(source: &DiscoveredSourceFile) -> (Option<PathBuf>, Value) {
    let state_path = source.source_path.with_file_name(RUN_STATE);
    let mut metadata = json!({
        "display_name": "Codebuff / Freebuff",
        "shared_lineage": true,
        "storage_format": "manicode-chat-messages-array",
        "origin": source.origin,
    });
    let mut workspace = None;
    if state_path.is_file() {
        if let Some(state) = read_capped(&state_path)
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        {
            workspace = state
                .pointer("/sessionState/fileContext/projectRoot")
                .and_then(Value::as_str)
                .filter(|path| !path.trim().is_empty())
                .map(PathBuf::from);
            if let Some(tokens) = state
                .pointer("/sessionState/mainAgentState/contextTokenCount")
                .and_then(Value::as_u64)
            {
                metadata["context_token_estimate"] = json!({
                    "tokens": tokens,
                    "source": "run-state.sessionState.mainAgentState.contextTokenCount",
                    "method": "upstream_local_gpt4o_bpe",
                    "is_provider_usage": false,
                });
            }
        } else {
            metadata["run_state_status"] = json!("unreadable_or_oversized");
            tracing::warn!(path = %state_path.display(), "shared CLI run state unreadable; retaining transcript without inferred workspace");
        }
    }
    (workspace, metadata)
}

impl Connector for CodebuffConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector(SLUG).unwrap_or_else(DetectionResult::not_found)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Self::discover(ctx)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut conversations = Vec::new();
        self.scan_with_callback(ctx, &mut |conversation| {
            conversations.push(conversation);
            Ok(())
        })?;
        Ok(conversations)
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        emit: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        for source in Self::discover(ctx)? {
            if source.role == DiscoveredSourceRole::PrimarySessionLog {
                if let Some(conversation) = parse_session(&source)? {
                    emit(conversation)?;
                }
                if let Some(tick) = &ctx.progress_tick {
                    tick();
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Origin;
    use std::fs;

    // Generated from the public TypeScript persistence schema at the exact
    // commit in this module's header. These are source-schema fixtures, not
    // captured native app history and not evidence of which binary wrote it.
    fn records() -> Value {
        json!([
            {"id":"user-native-1", "variant":"user", "content":"Find the needle 雪",
             "timestamp":"2026-09-01T12:00:00.000Z"},
            {"id":"ai-native-2", "variant":"ai", "content":"",
             "timestamp":"2026-09-01T12:00:00.000Z", "credits":1.25,
             "blocks":[
                 {"type":"text", "content":"Looking first", "textType":"reasoning"},
                 {"type":"tool", "toolCallId":"call-native-1", "toolName":"read_files",
                  "input":{"paths":["src/main.rs"]}, "output":"needle is on line 7"},
                 {"type":"agent", "agentId":"helper-1", "agentName":"Reviewer",
                  "agentType":"reviewer", "content":"Nested assessment", "status":"complete",
                  "blocks":[{"type":"plan","content":"Preserve the original"}]},
                 {"type":"text", "content":"Found the needle"}
             ], "metadata":{"runState":{"unrelated_private_context":"not transcript"}}},
            {"id":"agent-native-3", "variant":"agent", "content":"Review done",
             "parentId":"ai-native-2", "timestamp":"2026-09-01T12:00:01.000Z",
             "agent":{"agentName":"Reviewer", "agentType":"reviewer", "responseCount":1}},
            {"id":"error-native-4", "variant":"error", "content":"Optional tool unavailable",
             "timestamp":"2026-09-01T12:00:02.000Z"}
        ])
    }

    fn fixture(root: &Path, project: &str, records: &Value) -> PathBuf {
        let directory = root
            .join(".config/manicode/projects")
            .join(project)
            .join("chats/2026-09-01T12-00-00.000Z");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(MESSAGES);
        fs::write(&path, serde_json::to_vec(records).unwrap()).unwrap();
        fs::write(directory.join(RUN_STATE), serde_json::to_vec(&json!({
            "traceSessionId":"trace-native-1",
            "output":{"type":"structuredOutput","value":{}},
            "sessionState":{
                "fileContext":{"projectRoot":"/work/actual full project 雪","cwd":"/work/actual full project 雪"},
                "mainAgentState":{"contextTokenCount":321,"creditsUsed":1.25}
            }
        })).unwrap()).unwrap();
        path
    }

    fn context(root: &Path) -> ScanContext {
        ScanContext::with_roots(
            root.join("cass-state"),
            vec![ScanRoot::local(root.into())],
            None,
        )
    }

    #[test]
    fn gh423_shared_schema_preserves_chronology_ids_workspace_tools_and_token_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), "ambiguous-basename", &records());
        let before = fs::read(&path).unwrap();
        let state_before = fs::read(path.with_file_name(RUN_STATE)).unwrap();
        let connector = CodebuffConnector::new();
        let ctx = context(dir.path());
        let discovered = connector.discover_source_files(&ctx).unwrap();
        assert_eq!(discovered.len(), 2);
        assert!(
            discovered
                .iter()
                .any(|s| s.source_path == path && s.required_for_reconstruction)
        );
        let conversations = connector.scan(&ctx).unwrap();
        assert_eq!(conversations.len(), 1);
        let conv = &conversations[0];
        assert_eq!(conv.agent_slug, "codebuff");
        assert_eq!(
            conv.external_id,
            Some(
                serde_json::to_string(&json!([
                    dir.path().join(".config/manicode").canonicalize().unwrap(),
                    "ambiguous-basename",
                    "2026-09-01T12-00-00.000Z"
                ]))
                .unwrap()
            )
        );
        assert_eq!(
            conv.workspace,
            Some(PathBuf::from("/work/actual full project 雪"))
        );
        assert_eq!(conv.source_path, path);
        assert_eq!(
            conv.messages
                .iter()
                .map(|m| (m.idx, m.role.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (0, "user"),
                (1, "assistant"),
                (2, "assistant"),
                (3, "system")
            ]
        );
        assert_eq!(conv.messages[0].created_at, Some(1_788_264_000_000));
        assert_eq!(conv.messages[1].created_at, conv.messages[0].created_at);
        assert_eq!(
            conv.messages[1].content,
            "Looking first\nread_files: {\"paths\":[\"src/main.rs\"]}\nneedle is on line 7\nNested assessment\nPreserve the original\nFound the needle"
        );
        assert_eq!(conv.messages[1].extra["codebuff_message_id"], "ai-native-2");
        assert_eq!(conv.messages[1].extra["credits"], 1.25);
        assert_eq!(conv.messages[1].extra["blocks"], records()[1]["blocks"]);
        assert!(conv.messages[1].extra["metadata"].get("runState").is_none());
        assert_eq!(conv.messages[1].invocations.len(), 1);
        assert_eq!(conv.messages[1].invocations[0].name, "read_files");
        assert_eq!(
            conv.messages[1].invocations[0].call_id.as_deref(),
            Some("call-native-1")
        );
        assert_eq!(conv.messages[2].author.as_deref(), Some("Reviewer"));
        assert_eq!(conv.messages[2].extra["parentId"], "ai-native-2");
        assert_eq!(conv.metadata["shared_lineage"], true);
        assert_eq!(conv.metadata["display_name"], "Codebuff / Freebuff");
        assert!(conv.metadata.get("writer_product").is_none());
        assert_eq!(conv.metadata["context_token_estimate"]["tokens"], 321);
        assert_eq!(
            conv.metadata["context_token_estimate"]["is_provider_usage"],
            false
        );
        assert!(
            conv.messages
                .iter()
                .all(|m| m.extra.get("input_tokens").is_none())
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(
            fs::read(path.with_file_name(RUN_STATE)).unwrap(),
            state_before
        );
    }

    #[test]
    fn gh423_append_replay_overlap_project_identity_and_remote_origin() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), "one", &records());
        let connector = CodebuffConnector::new();
        let mut ctx = context(dir.path());
        ctx.scan_roots.push(ScanRoot::local(path.clone()));
        let first = connector.scan(&ctx).unwrap();
        assert_eq!(
            first.len(),
            1,
            "overlapping roots must not duplicate the file"
        );
        let mut appended = records();
        appended.as_array_mut().unwrap().push(json!({
            "id":"new-native-5","variant":"user","content":"next turn",
            "timestamp":"2026-09-01T12:00:03.000Z"
        }));
        fs::write(&path, serde_json::to_vec(&appended).unwrap()).unwrap();
        let second = connector.scan(&ctx).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].external_id, first[0].external_id);
        assert_eq!(second[0].messages.len(), 5);
        assert_eq!(
            serde_json::to_value(&second[0].messages[..4]).unwrap(),
            serde_json::to_value(&first[0].messages).unwrap()
        );
        assert_eq!(
            serde_json::to_value(connector.scan(&ctx).unwrap()).unwrap(),
            serde_json::to_value(&second).unwrap()
        );
        fixture(dir.path(), "two", &records());
        let separate = connector.scan(&ctx).unwrap();
        assert_eq!(separate.len(), 2);
        assert_ne!(separate[0].external_id, separate[1].external_id);
        let origin = Origin::remote_with_host("source-machine", "host-label");
        let remote_ctx = ScanContext::with_roots(
            dir.path().join("cass"),
            vec![ScanRoot::remote(path, origin.clone(), None)],
            None,
        );
        let remote = connector.scan(&remote_ctx).unwrap();
        assert_eq!(remote.len(), 1);
        assert_eq!(
            remote[0].metadata["origin"],
            serde_json::to_value(origin).unwrap()
        );
    }

    #[test]
    fn gh423_malformed_partial_unknown_and_duplicate_records_fail_then_recover() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), "one", &records());
        let ctx = context(dir.path());
        let connector = CodebuffConnector::new();
        for malformed in ["[", "{}", "[null]", "[{\"variant\":\"user\"}]"] {
            fs::write(&path, malformed).unwrap();
            assert!(
                connector.scan(&ctx).is_err(),
                "malformed source must not become a successful empty scan"
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), malformed);
        }
        for (field, bad) in [
            ("variant", json!("future-role")),
            ("timestamp", json!("bad")),
            ("id", json!("")),
            ("blocks", json!([{"type":"future-block"}])),
        ] {
            let mut invalid = records();
            invalid[1][field] = bad;
            fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(connector.scan(&ctx).is_err());
        }
        let mut duplicate = records();
        duplicate[1]["id"] = duplicate[0]["id"].clone();
        fs::write(&path, serde_json::to_vec(&duplicate).unwrap()).unwrap();
        assert!(connector.scan(&ctx).is_err());
        fs::write(&path, b"[]").unwrap();
        assert!(connector.scan(&ctx).unwrap().is_empty());
        fs::write(&path, serde_json::to_vec(&records()).unwrap()).unwrap();
        assert_eq!(connector.scan(&ctx).unwrap()[0].messages.len(), 4);
        fs::write(path.with_file_name(RUN_STATE), b"{").unwrap();
        let recovered = connector.scan(&ctx).unwrap();
        assert_eq!(recovered[0].messages.len(), 4);
        assert!(
            recovered[0].workspace.is_none(),
            "never infer a full workspace from a basename"
        );
        assert_eq!(
            recovered[0].metadata["run_state_status"],
            "unreadable_or_oversized"
        );
    }

    #[test]
    fn gh423_modified_since_includes_sidecar_and_sibling_product_is_not_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture(dir.path(), "one", &records());
        let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(10);
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let mut ctx = context(dir.path());
        ctx.since_ts = Some(20_000);
        let connector = CodebuffConnector::new();
        assert_eq!(
            connector.scan(&ctx).unwrap().len(),
            1,
            "fresh run-state can supply a newly persisted workspace"
        );
        fs::File::options()
            .write(true)
            .open(path.with_file_name(RUN_STATE))
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(connector.scan(&ctx).unwrap().is_empty());
        let sibling = dir
            .path()
            .join(".config/unrelated/projects/one/chats/2026-09-01T12-00-00.000Z");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(
            sibling.join(MESSAGES),
            serde_json::to_vec(&records()).unwrap(),
        )
        .unwrap();
        assert!(connector.scan(&ctx).unwrap().is_empty());
        // An explicitly named file still needs the actual lineage schema.
        fs::write(
            sibling.join(MESSAGES),
            r#"[{"role":"user","content":"unrelated"}]"#,
        )
        .unwrap();
        let explicit = context(&sibling.join(MESSAGES));
        assert!(connector.scan(&explicit).is_err());
    }

    #[test]
    fn gh423_distinct_stores_keep_same_native_ids_separate_and_aliases_stable() {
        let dir = tempfile::tempdir().unwrap();
        let home_a = dir.path().join("profile-a");
        let home_b = dir.path().join("profile-b");
        let first_path = fixture(&home_a, "same-project", &records());
        let mut other_records = records();
        other_records[0]["content"] = json!("Different profile's transcript");
        let second_path = fixture(&home_b, "same-project", &other_records);
        let ctx = ScanContext::with_roots(
            dir.path().join("cass"),
            vec![
                ScanRoot::local(home_a.clone()),
                ScanRoot::local(home_b.clone()),
                ScanRoot::local(first_path.clone()),
            ],
            None,
        );
        let connector = CodebuffConnector::new();
        let both = connector.scan(&ctx).unwrap();
        assert_eq!(
            both.len(),
            2,
            "same native IDs in distinct stores are independent"
        );
        assert_ne!(both[0].external_id, both[1].external_id);
        assert_eq!(
            both[0].messages[0].extra["codebuff_message_id"],
            both[1].messages[0].extra["codebuff_message_id"]
        );
        assert_ne!(both[0].messages[0].content, both[1].messages[0].content);
        assert!(
            both.iter()
                .all(|conv| conv.metadata["origin"]["source_id"] == "local")
        );
        let direct = ScanContext::with_roots(
            dir.path().join("cass"),
            vec![ScanRoot::local(second_path), ScanRoot::local(first_path)],
            None,
        );
        assert_eq!(
            serde_json::to_value(&both).unwrap(),
            serde_json::to_value(connector.scan(&direct).unwrap()).unwrap()
        );
        #[cfg(unix)]
        {
            let alias = dir.path().join("alias-store");
            std::os::unix::fs::symlink(home_a.join(".config/manicode"), &alias).unwrap();
            let mut alias_ctx = ctx.clone();
            alias_ctx.scan_roots.push(ScanRoot::local(alias));
            assert_eq!(
                serde_json::to_value(connector.scan(&alias_ctx).unwrap()).unwrap(),
                serde_json::to_value(&both).unwrap()
            );
        }
    }

    #[test]
    fn gh423_same_id_inflight_blocks_are_emitted_as_revisions() {
        let dir = tempfile::tempdir().unwrap();
        let mut in_flight = records();
        in_flight[1]["isComplete"] = json!(false);
        in_flight[1]["blocks"][0]["status"] = json!("running");
        in_flight[1]["blocks"][1]["output"] = json!("partial tool result");
        let path = fixture(dir.path(), "one", &in_flight);
        let ctx = context(dir.path());
        let connector = CodebuffConnector::new();
        let before = connector.scan(&ctx).unwrap().remove(0);
        let mut finished = in_flight;
        finished[1]["isComplete"] = json!(true);
        finished[1]["blocks"][0]["status"] = json!("complete");
        finished[1]["blocks"][1]["output"] = json!("complete tool result with the needle");
        finished[1]["blocks"].as_array_mut().unwrap().push(json!({
            "type":"text", "content":"Final response appended to the same native message"
        }));
        fs::write(&path, serde_json::to_vec(&finished).unwrap()).unwrap();
        let after = connector.scan(&ctx).unwrap().remove(0);
        assert_eq!(after.external_id, before.external_id);
        assert_eq!(after.messages.len(), before.messages.len());
        let old = &before.messages[1];
        let revised = &after.messages[1];
        assert_eq!(revised.idx, old.idx);
        assert_eq!(revised.created_at, old.created_at);
        assert_eq!(
            revised.extra["codebuff_message_id"],
            old.extra["codebuff_message_id"]
        );
        assert_eq!(revised.invocations, old.invocations);
        assert_ne!(revised.content, old.content);
        assert_eq!(
            revised.content,
            "Looking first\nread_files: {\"paths\":[\"src/main.rs\"]}\ncomplete tool result with the needle\nNested assessment\nPreserve the original\nFound the needle\nFinal response appended to the same native message"
        );
        assert_eq!(revised.extra["blocks"], finished[1]["blocks"]);
        assert_eq!(revised.extra["isComplete"], true);
        for idx in [0, 2, 3] {
            assert_eq!(
                serde_json::to_value(&after.messages[idx]).unwrap(),
                serde_json::to_value(&before.messages[idx]).unwrap()
            );
        }
    }
}
