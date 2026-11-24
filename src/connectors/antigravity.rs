//! Antigravity connector (the Antigravity IDE and the `agy` CLI).
//!
//! [Antigravity](https://antigravity.google) ships both an IDE and the `agy`
//! CLI, Google's successor to the Gemini CLI (`gmi`). Each keeps its own store
//! under `~/.gemini/` (a directory they share with — but keep separate from —
//! the legacy Gemini CLI, whose data lives under `~/.gemini/tmp/`):
//!
//! - `~/.gemini/antigravity/` — the Antigravity **IDE** workspace sessions.
//! - `~/.gemini/antigravity-cli/` — the `agy` **CLI** conversations.
//!
//! The two stores are structurally identical. By default the connector probes
//! BOTH and indexes every root that exists; `CASS_ANTIGRAVITY_DATA_ROOT`
//! replaces the pair with a single explicit base (tests / remote mirrors).
//! Inside a base:
//!
//! - `conversations/<uuid>.db` — one stock-SQLite database per conversation. The
//!   payload columns are an undocumented protobuf trajectory/steps model; this is
//!   the durable source of truth but expensive to read.
//! - `brain/<uuid>/.system_generated/logs/transcript.jsonl` — a **clean JSONL
//!   transcript** of the same conversation. This is the connector's primary read
//!   path: a simple, stable line-per-step JSON shape, no protobuf required. A
//!   fuller `transcript_full.jsonl` sits beside it and is read when the primary
//!   is absent; the two transcripts are never combined.
//!
//! The `<uuid>` keying `conversations/<uuid>.db` and `brain/<uuid>/` is the same
//! id used by `agy --conversation <uuid>`.
//!
//! ## Provenance across the two stores
//!
//! Consumers key a conversation by `(agent, external_id)`, so the IDE and CLI
//! stores must never yield the same `external_id` for different
//! conversations. A conversation under the IDE base (`.gemini/antigravity`)
//! is emitted with `external_id = "ide/<uuid>"`; a conversation under the CLI
//! base (`.gemini/antigravity-cli`) — or under any base the connector cannot
//! classify (fixtures, relocated mirrors) — keeps the bare `<uuid>` so
//! existing archives stay stable. Every conversation additionally records
//! `metadata.layout` (`"ide"` / `"cli"`, when classified) and
//! `metadata.data_root` (the base directory it was read from).
//!
//! ## transcript.jsonl record shape
//!
//! Each line is one JSON object: `{ step_index, source, type, status,
//! created_at, content?, thinking?, tool_calls? }`.
//!
//! - `step_index` (i64) — timeline order. Indices may have gaps; we sort by it.
//! - `source` — `USER_EXPLICIT` | `MODEL` | `SYSTEM`.
//! - `type` — the step kind. Known kinds and their normalized mapping:
//!   - `USER_INPUT` (`USER_EXPLICIT`) → `role: "user"`. The real prompt is wrapped
//!     in `<USER_REQUEST>…</USER_REQUEST>`; `<ADDITIONAL_METADATA>` (local time)
//!     and `<USER_SETTINGS_CHANGE>` (records the model) are appended. We extract
//!     the request body and keep the wrappers in `extra`.
//!   - `PLANNER_RESPONSE` (`MODEL`) → `role: "assistant"`. `content` is the visible
//!     reply; `thinking` is the model's reasoning, preserved in `extra.thinking`.
//!   - any other `MODEL` kind (`VIEW_FILE`, `EDIT_FILE`, `RUN_COMMAND`, …) → a
//!     `role: "tool"` step. `content` is the tool result; `tool_calls` (when
//!     present) are the structured calls. We synthesize a [`NormalizedInvocation`]
//!     named after the step so the tool is searchable even when `tool_calls` is
//!     absent. The raw `type` is preserved in `extra.agy_type`.
//!   - `EPHEMERAL_MESSAGE` / `SYSTEM_MESSAGE` (`SYSTEM`) → `role: "system"`
//!     (preserved faithfully; tagged in `extra` so consumers can down-rank the
//!     repetitive ephemeral reminders).
//!   - `CONVERSATION_HISTORY` (`SYSTEM`) — a null-content marker; no message.
//! - `created_at` — RFC3339 UTC (`2026-06-11T20:14:42Z`), read by [`parse_timestamp`].
//!
//! Unknown future `type`s are never dropped or crashed on: they are emitted as a
//! best-effort message keyed off `source`, with the raw `type` kept in
//! `extra.agy_type`. (See the agy version-compatibility guard work.)

use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use walkdir::WalkDir;

use super::jsonl::JsonlLines;
use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::token_extraction::{antigravity_tool_call_id, antigravity_tool_name};
use super::utils::{
    dedupe_path_key, env_path_nonempty, excluded_scan_paths_from_env, path_is_excluded,
    read_capped, unwrap_skill_invocations,
};
use super::{Connector, file_modified_since, franken_detection_for_connector, parse_timestamp};
use crate::types::{
    DetectionResult, NormalizedConversation, NormalizedInvocation, NormalizedMessage,
    reindex_messages,
};

/// Normalized agent slug emitted for every Antigravity conversation.
const AGENT_SLUG: &str = "antigravity";

/// Which Antigravity product wrote a store.
///
/// Classified from the on-disk location shape only — `.gemini/antigravity`
/// is the IDE, `.gemini/antigravity-cli` is the `agy` CLI — so the answer does
/// not depend on how the scan reached the base (default probe, env override,
/// or an explicit root). Any other base (fixtures, relocated mirrors) is
/// unclassified and treated like the CLI for identity purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AntigravityLayout {
    /// The Antigravity IDE (`~/.gemini/antigravity`).
    Ide,
    /// The `agy` CLI (`~/.gemini/antigravity-cli`).
    Cli,
}

impl AntigravityLayout {
    /// The base directory name under `~/.gemini/` for this layout.
    const fn base_dir_name(self) -> &'static str {
        match self {
            Self::Ide => "antigravity",
            Self::Cli => "antigravity-cli",
        }
    }

    /// The `metadata.layout` value for this layout.
    const fn metadata_value(self) -> &'static str {
        match self {
            Self::Ide => "ide",
            Self::Cli => "cli",
        }
    }

    /// Classify a base directory by its `.gemini/<name>` location shape.
    fn from_base(base: &Path) -> Option<Self> {
        let parent_is_dot_gemini = base
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n == ".gemini");
        if !parent_is_dot_gemini {
            return None;
        }
        let name = base.file_name()?;
        [Self::Ide, Self::Cli]
            .into_iter()
            .find(|layout| name == layout.base_dir_name())
    }

    /// The `external_id` for a conversation `<uuid>` under this layout.
    ///
    /// IDE conversations are qualified (`ide/<uuid>`) so a uuid that appears
    /// under both stores cannot collide in `(agent, external_id)`-keyed
    /// consumers; the CLI keeps the bare `<uuid>` (the id `agy --conversation`
    /// resumes by) so archives indexed before the IDE store was probed stay
    /// stable.
    fn external_id(self, uuid: &str) -> String {
        match self {
            Self::Ide => format!("ide/{uuid}"),
            Self::Cli => uuid.to_string(),
        }
    }
}

/// A safely resolved store keeps its product identity even when the transport
/// copied only the store's contents and omitted the `.gemini` ancestor.
struct AntigravitySourceRoot {
    root: ScanRoot,
    layout: Option<AntigravityLayout>,
    conversation_uuid: Option<String>,
    metadata: AntigravityMetadataScope,
}

enum AntigravityMetadataScope {
    /// Ordinary filesystem roots can use the standard `brain/<uuid>` siblings.
    Structural,
    /// A mirror owns sidecars only when it copied the surrounding product base.
    Mirrored(Option<PathBuf>),
}

impl AntigravitySourceRoot {
    fn metadata_base<'a>(&'a self, conversation_dir: &'a Path) -> Option<&'a Path> {
        match &self.metadata {
            AntigravityMetadataScope::Structural => {
                AntigravityConnector::base_of_conversation_dir(conversation_dir)
            }
            AntigravityMetadataScope::Mirrored(base) => base.as_deref(),
        }
    }
}

/// Connector for the Antigravity (`agy`) coding agent.
pub struct AntigravityConnector;

impl Default for AntigravityConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl AntigravityConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Base directories holding `conversations/` and `brain/`.
    ///
    /// `CASS_ANTIGRAVITY_DATA_ROOT` (tests / remote mirrors) names a single
    /// explicit base and replaces the defaults. Otherwise both product stores
    /// are candidates — `~/.gemini/antigravity` (IDE) and
    /// `~/.gemini/antigravity-cli` (`agy` CLI) — and the scan indexes every one
    /// that exists (cass #454).
    fn base_roots() -> Vec<PathBuf> {
        if let Some(explicit) = env_path_nonempty("CASS_ANTIGRAVITY_DATA_ROOT") {
            return vec![explicit];
        }
        Self::default_base_roots(&dirs::home_dir().unwrap_or_default())
    }

    /// The default IDE + CLI bases under a home directory, IDE first.
    fn default_base_roots(home: &Path) -> Vec<PathBuf> {
        let dot_gemini = home.join(".gemini");
        vec![
            dot_gemini.join(AntigravityLayout::Ide.base_dir_name()),
            dot_gemini.join(AntigravityLayout::Cli.base_dir_name()),
        ]
    }

    /// The `<base>` directory (`brain/`'s parent) for a `brain/<uuid>`
    /// conversation directory.
    fn base_of_conversation_dir(conversation_dir: &Path) -> Option<&Path> {
        // A qualified mirror can contain only `<uuid>/`, with no surrounding
        // store. Do not infer metadata outside that transport container.
        conversation_dir
            .parent()
            .filter(|parent| parent.file_name().is_some_and(|name| name == "brain"))?
            .parent()
    }

    /// Transcript path for a `brain/<uuid>` conversation directory.
    fn transcript_path(conversation_dir: &Path) -> PathBuf {
        conversation_dir
            .join(".system_generated")
            .join("logs")
            .join("transcript.jsonl")
    }

    /// The fuller transcript variant, when agy wrote one.
    fn transcript_full_path(conversation_dir: &Path) -> PathBuf {
        conversation_dir
            .join(".system_generated")
            .join("logs")
            .join("transcript_full.jsonl")
    }

    /// Select one transcript authority for both discovery and normalization.
    /// A full transcript can replace a genuinely absent primary, never an
    /// excluded, unreadable, malformed, or otherwise unusable existing primary.
    fn selected_transcript_path(
        conversation_dir: &Path,
        excluded_paths: &[PathBuf],
    ) -> Option<PathBuf> {
        let primary = Self::transcript_path(conversation_dir);
        // An exclusion of the primary continues to suppress its duplicate
        // transcript and all sidecars, even when the primary is absent.
        if path_is_excluded(conversation_dir, excluded_paths)
            || path_is_excluded(&primary, excluded_paths)
        {
            return None;
        }
        let selected = match fs::symlink_metadata(&primary) {
            Ok(_) => primary.is_file().then_some(primary),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let full = Self::transcript_full_path(conversation_dir);
                full.is_file().then_some(full)
            }
            Err(_) => None,
        }?;
        (!path_is_excluded(&selected, excluded_paths)).then_some(selected)
    }

    /// A conversation directory has either the primary transcript or a usable
    /// full-only fallback, under the same authority rules as scanning.
    fn is_conversation_dir(path: &Path) -> bool {
        Self::selected_transcript_path(path, &[]).is_some()
    }

    /// The `<uuid>` for a conversation directory (its directory name).
    fn conversation_uuid(conversation_dir: &Path) -> Option<String> {
        conversation_dir
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.trim().is_empty())
            .map(String::from)
    }

    /// The sibling `conversations/<uuid>.db` for a `brain/<uuid>` directory, when
    /// the standard layout is intact (`<base>/brain/<uuid>` ↔
    /// `<base>/conversations/<uuid>.db`).
    fn sibling_db_path(conversation_dir: &Path, base: Option<&Path>) -> Option<PathBuf> {
        let uuid = Self::conversation_uuid(conversation_dir)?;
        let base = base?;
        let db = base.join("conversations").join(format!("{uuid}.db"));
        db.is_file().then_some(db)
    }

    /// The sibling `annotations/<uuid>.pbtxt` title sidecar, when present.
    fn sibling_annotation_path(conversation_dir: &Path, base: Option<&Path>) -> Option<PathBuf> {
        let uuid = Self::conversation_uuid(conversation_dir)?;
        let base = base?;
        let annotation = base.join("annotations").join(format!("{uuid}.pbtxt"));
        annotation.is_file().then_some(annotation)
    }

    /// The shared `<base>/conversation_summaries.db` summary database, when present.
    fn sibling_summaries_db_path(base: Option<&Path>) -> Option<PathBuf> {
        let base = base?;
        let db = base.join("conversation_summaries.db");
        db.is_file().then_some(db)
    }

    /// Snapshot metadata sources for discovery and incremental freshness.
    /// The summary database and WAL form one read unit.
    fn metadata_sidecars(
        conversation_dir: &Path,
        root: &ScanRoot,
        base: Option<&Path>,
        excluded_paths: &[PathBuf],
    ) -> Vec<DiscoveredSourceFile> {
        let mut paths = Vec::new();
        if let Some(annotation) = Self::sibling_annotation_path(conversation_dir, base)
            && !path_is_excluded(&annotation, excluded_paths)
        {
            paths.push((annotation, DiscoveredSourceRole::MetadataSidecar));
        }
        if let Some(db) = Self::sibling_summaries_db_path(base) {
            let wal = db.with_extension("db-wal");
            if !path_is_excluded(&db, excluded_paths) && !path_is_excluded(&wal, excluded_paths) {
                paths.push((db, DiscoveredSourceRole::SqliteDatabase));
                if wal.is_file() {
                    paths.push((wal, DiscoveredSourceRole::MetadataSidecar));
                }
            }
        }
        paths
            .into_iter()
            .map(|(path, role)| {
                DiscoveredSourceFile::new(AGENT_SLUG, root, path, role, false).with_fs_metadata()
            })
            .collect()
    }

    fn source_roots(ctx: &ScanContext) -> Vec<AntigravitySourceRoot> {
        let roots = if ctx.use_default_detection() {
            // Mirror the explicit-root acceptance: a default-detection
            // data_dir that itself looks like antigravity storage (a base
            // with a `brain/` tree, or the `brain/` dir itself) scopes the
            // scan to it, so fixture/mirror scans stay hermetic; otherwise
            // probe the system bases (IDE and CLI). Roots that do not exist
            // are skipped by the scan. `CASS_ANTIGRAVITY_DATA_ROOT` keeps
            // precedence so CI redirection is unaffected.
            let d = &ctx.data_dir;
            let env_override = env_path_nonempty("CASS_ANTIGRAVITY_DATA_ROOT").is_some();
            let looks_like_base =
                d.join("brain").is_dir() || d.file_name().is_some_and(|n| n == "brain");
            if !env_override && looks_like_base {
                vec![ScanRoot::local(d.clone())]
            } else {
                Self::base_roots()
                    .into_iter()
                    .map(ScanRoot::local)
                    .collect()
            }
        } else {
            ctx.scan_roots.clone()
        };

        let mut resolved: Vec<_> = roots
            .into_iter()
            .flat_map(Self::resolve_source_root)
            .collect();

        resolved.sort_by(|a, b| a.root.path.cmp(&b.root.path));
        resolved.dedup_by(|a, b| a.root.path == b.root.path);
        resolved
    }

    fn resolve_source_root(root: ScanRoot) -> Vec<AntigravitySourceRoot> {
        if root.origin.is_local() || root.mirrored_source_path.is_none() {
            return vec![AntigravitySourceRoot {
                root,
                layout: None,
                conversation_uuid: None,
                metadata: AntigravityMetadataScope::Structural,
            }];
        }
        let source = root.mirrored_source_path.as_deref().unwrap_or_default();
        let Some(parts) = mirror_source_components(source) else {
            return Vec::new();
        };
        let mut resolved = Vec::new();
        for layout in [AntigravityLayout::Ide, AntigravityLayout::Cli] {
            if let Some(mirrored) =
                root.mirrored_store(&[".gemini", layout.base_dir_name(), "brain"])
            {
                // A shared `.gemini` mirror can own both products. Do not
                // let the first successful resolution hide the other store.
                let conversation_uuid = Self::is_conversation_dir(&mirrored)
                    .then(|| mirror_conversation_uuid(&parts, layout))
                    .flatten();
                let base = mirror_includes_product_base(&parts, layout)
                    .then(|| root.mirrored_store(&[".gemini", layout.base_dir_name()]))
                    .flatten();
                resolved.push(AntigravitySourceRoot {
                    root: root.with_path(mirrored),
                    layout: Some(layout),
                    conversation_uuid,
                    metadata: AntigravityMetadataScope::Mirrored(base),
                });
            }
        }
        if resolved.is_empty()
            && let Some(event) = Self::resolve_mirror_event(&root, &parts)
        {
            resolved.push(event);
        }
        if resolved.is_empty()
            && !parts.contains(&".gemini")
            && match fs::symlink_metadata(&root.path) {
                Ok(metadata) => metadata.is_dir() || metadata.is_file(),
                Err(error) => error.kind() == io::ErrorKind::NotFound,
            }
        {
            // Home/ancestor and unclassified mirrors retain bounded structural
            // discovery. A provider-qualified source must resolve safely above.
            resolved.push(AntigravitySourceRoot {
                root,
                layout: None,
                conversation_uuid: None,
                metadata: AntigravityMetadataScope::Structural,
            });
        }
        // A declared mirror that fails safe resolution must not widen to the
        // transport container and ingest unrelated sibling stores.
        resolved
    }

    fn resolve_mirror_event(root: &ScanRoot, parts: &[&str]) -> Option<AntigravitySourceRoot> {
        match fs::symlink_metadata(&root.path) {
            Ok(metadata) if metadata.is_file() => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => return None,
        }
        let name = root.path.file_name()?.to_str()?;
        let transcript_event = matches!(name, "transcript.jsonl" | "transcript_full.jsonl");
        let mut event_uuid = None;
        let base = match name {
            "transcript.jsonl" | "transcript_full.jsonl" => {
                let logs = root.path.parent()?;
                let generated = logs.parent()?;
                let conversation = generated.parent()?;
                if logs.file_name()? != "logs" || generated.file_name()? != ".system_generated" {
                    return None;
                }
                if ![logs, generated, conversation]
                    .into_iter()
                    .all(plain_directory)
                {
                    return None;
                }
                event_uuid = conversation
                    .file_name()
                    .and_then(|name| name.to_str())
                    .filter(|uuid| valid_conversation_uuid(uuid));
                Self::base_of_conversation_dir(conversation)
            }
            "conversation_summaries.db" | "conversation_summaries.db-wal" => root.path.parent(),
            _ if root
                .path
                .extension()
                .is_some_and(|extension| extension == "pbtxt") =>
            {
                let annotations = root.path.parent()?;
                (annotations.file_name()? == "annotations" && plain_directory(annotations))
                    .then(|| annotations.parent())
                    .flatten()
            }
            _ => return None,
        };
        if let Some(base) = base
            && (!plain_directory(base) || !plain_directory(&base.join("brain")))
        {
            return None;
        }
        let layout = [AntigravityLayout::Ide, AntigravityLayout::Cli]
            .into_iter()
            .find(|layout| {
                parts
                    .windows(2)
                    .any(|pair| pair == [".gemini", layout.base_dir_name()])
                    || (parts.ends_with(&[".gemini"])
                        && base.is_some_and(|base| {
                            base.file_name()
                                .is_some_and(|name| name == layout.base_dir_name())
                        }))
            })?;
        let owns_base = mirror_includes_product_base(parts, layout);
        let owns_brain = parts
            .windows(3)
            .any(|part| part == [".gemini", layout.base_dir_name(), "brain"]);
        if !owns_base && (!transcript_event || !owns_brain) {
            return None;
        }
        let conversation_uuid = mirror_conversation_uuid(parts, layout);
        if let (Some(selected), Some(event)) = (conversation_uuid.as_deref(), event_uuid)
            && !selected.eq_ignore_ascii_case(event)
        {
            return None;
        }
        // Exact watcher roots may retain original source identity. `with_path`
        // deliberately clears it: hosts must retain that context if the local
        // mirror path is opaque and cannot express the product identity itself.
        Some(AntigravitySourceRoot {
            root: root.clone(),
            layout: Some(layout),
            conversation_uuid,
            metadata: AntigravityMetadataScope::Mirrored(
                owns_base.then(|| base.map(Path::to_path_buf)).flatten(),
            ),
        })
    }

    /// Resolve every `brain/<uuid>` conversation directory reachable from a scan
    /// target. The target may be the conversation directory itself, the `brain/`
    /// directory, or a base directory (`antigravity` or `antigravity-cli`).
    fn conversation_dirs(scan_target: &Path) -> Vec<PathBuf> {
        // Hosts may target the exact path from a file-watcher event, including
        // a removed annotation or a WAL removed during a checkpoint. Resolve
        // known sidecars structurally, using directory scans' layout rules.
        if !scan_target.is_dir() {
            let name = scan_target.file_name().and_then(|name| name.to_str());
            let parent = scan_target.parent();
            let conversation = match name {
                Some("transcript.jsonl" | "transcript_full.jsonl") => parent
                    .filter(|logs| logs.file_name().is_some_and(|name| name == "logs"))
                    .and_then(Path::parent)
                    .filter(|dir| {
                        dir.file_name()
                            .is_some_and(|name| name == ".system_generated")
                    })
                    .and_then(Path::parent)
                    .map(Path::to_path_buf),
                Some("conversation_summaries.db" | "conversation_summaries.db-wal") => {
                    return parent.map_or_else(Vec::new, |base| {
                        Self::conversation_dirs(&base.join("brain"))
                    });
                }
                _ if scan_target.extension().is_some_and(|ext| ext == "pbtxt")
                    && parent.is_some_and(|dir| {
                        dir.file_name().is_some_and(|name| name == "annotations")
                    }) =>
                {
                    parent.and_then(Path::parent).and_then(|base| {
                        scan_target
                            .file_stem()
                            .map(|id| base.join("brain").join(id))
                    })
                }
                _ => None,
            };
            return conversation
                .filter(|dir| Self::is_conversation_dir(dir))
                .into_iter()
                .collect();
        }
        if Self::is_conversation_dir(scan_target) {
            return vec![scan_target.to_path_buf()];
        }

        let mut out = Vec::new();
        // A transcript sits at <conv>/.system_generated/logs/transcript*.jsonl,
        // so the conversation dir is three levels above the file. From the
        // base directory it is at depth 5; the cap is set higher so a scan
        // root one or two levels above (e.g. ~ or ~/.gemini, as remote mirrors
        // can produce) still finds it. The .system_generated/logs ancestry filter
        // below keeps correctness regardless of depth — the cap only bounds cost.
        for entry in WalkDir::new(scan_target)
            .min_depth(1)
            .max_depth(8)
            .into_iter()
            .flatten()
        {
            if !entry.file_type().is_file()
                || !matches!(
                    entry.file_name().to_str(),
                    Some("transcript.jsonl" | "transcript_full.jsonl")
                )
            {
                continue;
            }
            let path = entry.path();
            // Require the .system_generated/logs/ ancestry so we don't pick up an
            // unrelated transcript.jsonl somewhere else.
            let conv_dir = path
                .parent() // logs/
                .filter(|logs| logs.file_name().is_some_and(|n| n == "logs"))
                .and_then(Path::parent) // .system_generated/
                .filter(|sg| sg.file_name().is_some_and(|n| n == ".system_generated"))
                .and_then(Path::parent); // <uuid>/
            if let Some(dir) = conv_dir {
                out.push(dir.to_path_buf());
            }
        }

        out.sort();
        out.dedup();
        out
    }

    /// True when the conversation's transcript or metadata sidecars are newer
    /// than `since_ts`.
    fn conversation_modified_since(
        conversation_dir: &Path,
        transcript: &Path,
        since_ts: Option<i64>,
        sidecars: &[DiscoveredSourceFile],
        excluded_paths: &[PathBuf],
    ) -> bool {
        if since_ts.is_none() {
            return true;
        }
        let transcript_full = Self::transcript_full_path(conversation_dir);
        file_modified_since(transcript, since_ts)
            // Keep mirroring changes to an optional full sibling without
            // changing which transcript supplies the normalized conversation.
            || (transcript_full.as_path() != transcript
                && transcript_full.is_file()
                && !path_is_excluded(&transcript_full, excluded_paths)
                && file_modified_since(&transcript_full, since_ts))
            || sidecars
                .iter()
                .any(|source| file_modified_since(&source.source_path, since_ts))
    }

    /// Read a transcript file into per-step JSON records, tolerating blank lines
    /// and individual malformed/non-UTF-8 lines (skipped + logged, never fatal),
    /// while discarding incomplete transcripts on mid-stream I/O errors.
    fn read_transcript_records(transcript: &Path) -> Vec<Value> {
        // Transcripts accumulate; enforce the project's 100MB scan cap.
        if let Ok(meta) = fs::metadata(transcript)
            && meta.len() > 100 * 1024 * 1024
        {
            tracing::warn!(
                transcript = %transcript.display(),
                size_bytes = meta.len(),
                "antigravity: transcript exceeds the scan size cap; skipping"
            );
            return Vec::new();
        }
        let Ok(file) = fs::File::open(transcript) else {
            return Vec::new();
        };
        Self::read_transcript_records_from(transcript, BufReader::new(file)).unwrap_or_default()
    }

    fn read_transcript_records_from(
        transcript: &Path,
        reader: impl BufRead,
    ) -> io::Result<Vec<Value>> {
        let mut records = Vec::new();
        for (lineno, line_res) in JsonlLines::new(reader).enumerate() {
            let line = match line_res {
                Ok(line) => line,
                Err(err) => {
                    tracing::warn!(
                        transcript = %transcript.display(),
                        line = lineno + 1,
                        error = %err,
                        "antigravity: aborting transcript after mid-stream read error"
                    );
                    return Err(err);
                }
            };
            let trimmed = line.trim_start_matches('\u{feff}').trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(trimmed) {
                Ok(value) => records.push(value),
                Err(err) => tracing::warn!(
                    transcript = %transcript.display(),
                    line = lineno + 1,
                    error = %err,
                    "antigravity: skipping malformed transcript line"
                ),
            }
        }
        Ok(records)
    }
}

fn plain_directory(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir())
}

fn mirror_source_components(source: &str) -> Option<Vec<&str>> {
    if source.chars().any(char::is_control) {
        return None;
    }
    let parts: Vec<_> = source
        .split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .collect();
    (!parts.iter().any(|part| matches!(*part, "." | ".."))).then_some(parts)
}

fn mirror_includes_product_base(parts: &[&str], layout: AntigravityLayout) -> bool {
    // A provider-owned subtree can itself have an application-like basename.
    // It must never acquire the metadata scope of a complete product base.
    !parts
        .windows(3)
        .any(|part| part == [".gemini", layout.base_dir_name(), "brain"])
        && (parts.ends_with(&[".gemini"]) || parts.ends_with(&[".gemini", layout.base_dir_name()]))
}

fn mirror_conversation_uuid(parts: &[&str], layout: AntigravityLayout) -> Option<String> {
    let store = [".gemini", layout.base_dir_name(), "brain"];
    let index = parts.windows(store.len()).position(|part| part == store)?;
    parts
        .get(index + store.len())
        .filter(|uuid| valid_conversation_uuid(uuid))
        .map(|uuid| (*uuid).to_string())
}

/// Extract the inner text of every `<TAG>…</TAG>` block in `content`.
fn extract_tagged_blocks(content: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = content;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        out.push(after[..end].trim().to_string());
        rest = &after[end + close.len()..];
    }
    out
}

/// Split a wrapped `USER_INPUT` payload into (request body, settings-change text,
/// metadata text). agy wraps the real prompt as `<USER_REQUEST>` and may append
/// `<USER_SETTINGS_CHANGE>` and `<ADDITIONAL_METADATA>`. A single record can
/// carry several `<USER_REQUEST>` blocks; they are joined. If no wrapper is
/// present we fall back to the raw content.
fn extract_user_request(content: &str) -> (String, Option<String>, Option<String>) {
    let requests = extract_tagged_blocks(content, "USER_REQUEST");
    let settings = extract_tagged_blocks(content, "USER_SETTINGS_CHANGE")
        .into_iter()
        .next();
    let metadata = extract_tagged_blocks(content, "ADDITIONAL_METADATA")
        .into_iter()
        .next();
    let body = if requests.is_empty() {
        content.trim().to_string()
    } else {
        requests.join("\n\n")
    };
    (body, settings, metadata)
}

/// Pull the model name out of a `<USER_SETTINGS_CHANGE>` body such as
/// "The user changed setting `Model Selection` from None to Gemini 3.1 Pro
/// (High). No need to comment…" → `Some("Gemini 3.1 Pro (High)")`.
fn model_from_settings(settings: &str) -> Option<String> {
    // agy phrases this as "... from <old> to <model>. ...". Anchor on " from "
    // and take the FIRST " to " AFTER it, so a " to " appearing earlier (e.g. in
    // a setting name, or a non-None previous value containing " to ") cannot
    // hijack the parse. Fall back to the first " to " when no " from " is present.
    let from_marker = " from ";
    let to_marker = " to ";
    let search_from = settings
        .find(from_marker)
        .map_or(0, |i| i + from_marker.len());
    let rel = settings[search_from..].find(to_marker)?;
    let start = search_from + rel + to_marker.len();
    let tail = &settings[start..];
    let end = tail.find(". ").unwrap_or(tail.len());
    let model = tail[..end].trim().trim_end_matches('.').trim();
    if model.is_empty() || model.eq_ignore_ascii_case("none") {
        return None;
    }
    Some(model.to_string())
}

/// Pull the first model recorded in the transcript.
///
/// Newer Antigravity builds write the authoritative API model slug directly on
/// `PLANNER_RESPONSE` records (e.g. `"gemini-4-neon-high"`). Fall back to
/// `<USER_SETTINGS_CHANGE>` in `USER_INPUT` for older transcripts that omit
/// per-step model fields.
fn detect_model(records: &[&Value]) -> Option<String> {
    for rec in records {
        if let Some(model) = rec
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Some(model.to_string());
        }
    }
    for rec in records {
        if rec.get("type").and_then(Value::as_str) != Some("USER_INPUT") {
            continue;
        }
        let content = rec.get("content").and_then(Value::as_str).unwrap_or("");
        if let Some(settings) = extract_tagged_blocks(content, "USER_SETTINGS_CHANGE")
            .into_iter()
            .next()
        {
            if let Some(model) = model_from_settings(&settings) {
                return Some(model);
            }
        }
    }
    None
}

/// Copy per-step `model` and token usage fields from a raw transcript record
/// into `extra`. Returns `true` when at least one token count was attached.
fn attach_usage_and_model(rec: &Value, extra: &mut Map<String, Value>) -> bool {
    if let Some(model) = rec
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        extra.insert("model".to_string(), Value::String(model.to_string()));
    }

    let mut usage = Map::new();
    for key in [
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "reasoning_tokens",
    ] {
        if let Some(value) = rec.get(key).and_then(Value::as_i64).filter(|&v| v >= 0) {
            usage.insert(key.to_string(), Value::from(value));
        }
    }

    if usage.is_empty() {
        false
    } else {
        extra.insert("usage".to_string(), Value::Object(usage));
        true
    }
}

/// Parse structured `tool_calls` entries without synthesizing a fallback entry.
fn parse_explicit_tool_calls(
    tool_calls: Option<&Value>,
    fallback_name: Option<&str>,
) -> Vec<NormalizedInvocation> {
    let Some(arr) = tool_calls.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut seen_ids = HashSet::new();
    let mut invocations: Vec<_> = arr
        .iter()
        .filter_map(|tc| {
            // Malformed array elements are not additional invocations. A
            // legacy tool step with no usable entries gets one fallback below.
            tc.as_object()?;
            let call_id = antigravity_tool_call_id(tc);
            let name = antigravity_tool_name(tc).or_else(|| call_id.and(fallback_name))?;
            if let Some(id) = call_id
                && !seen_ids.insert(id)
            {
                return None;
            }
            let arguments = tc
                .get("arguments")
                .or_else(|| tc.get("args"))
                .or_else(|| tc.get("input"))
                .or_else(|| tc.pointer("/function/arguments"))
                .cloned()
                .map(|raw| match raw {
                    Value::String(s) => {
                        serde_json::from_str::<Value>(&s).unwrap_or(Value::String(s))
                    }
                    other => other,
                });
            Some(NormalizedInvocation {
                kind: "tool".to_string(),
                name: name.to_string(),
                raw_name: None,
                call_id: call_id.map(String::from),
                arguments,
            })
        })
        .collect();
    unwrap_skill_invocations(&mut invocations);
    invocations
}

/// Parse `tool_calls` into normalized invocations. When the array is absent we
/// still synthesize one invocation named after the step `type` (e.g.
/// `VIEW_FILE` → `view_file`) so the tool remains searchable.
fn parse_tool_calls(tool_calls: Option<&Value>, step_type: &str) -> Vec<NormalizedInvocation> {
    let synthesized_name = step_type.to_ascii_lowercase();
    let parsed = parse_explicit_tool_calls(tool_calls, Some(&synthesized_name));
    if parsed.is_empty() {
        vec![NormalizedInvocation {
            kind: "tool".to_string(),
            name: synthesized_name,
            raw_name: None,
            call_id: None,
            arguments: None,
        }]
    } else {
        parsed
    }
}

fn valid_conversation_uuid(candidate: &str) -> bool {
    candidate.len() == 36
        && candidate.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// Detect the parent conversation UUID of a spawned Antigravity subagent from
/// its step-0 `SYSTEM_MESSAGE` (`[Message] ... sender=<uuid> ...`).
fn detect_parent_from_records(ordered: &[&Value]) -> Option<String> {
    let first = ordered.first()?;
    if first.get("step_index").and_then(Value::as_i64) != Some(0)
        || first.get("type").and_then(Value::as_str) != Some("SYSTEM_MESSAGE")
        || first.get("source").and_then(Value::as_str) != Some("SYSTEM")
    {
        return None;
    }
    let content = first.get("content").and_then(Value::as_str)?;
    for line in content.lines() {
        let Some(header) = line.trim_start().strip_prefix("[Message]") else {
            continue;
        };
        // Only envelope fields identify the sender. Examples inside content
        // (including notsender=) must not create a relationship.
        for field in header.split_whitespace() {
            if field.starts_with("content=") {
                break;
            }
            if let Some(candidate) = field.strip_prefix("sender=") {
                if valid_conversation_uuid(candidate) {
                    return Some(candidate.to_string());
                }
            }
        }
    }
    None
}

/// Read the optional `title:"..."` field from `<base>/annotations/<uuid>.pbtxt`.
fn annotation_title(base: &Path, uuid: &str, excluded_paths: &[PathBuf]) -> Option<String> {
    let path = base.join("annotations").join(format!("{uuid}.pbtxt"));
    if path_is_excluded(&path, excluded_paths) {
        return None;
    }
    let text = read_capped(&path).ok()??;
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed
            .strip_prefix("title")
            .and_then(|rest| rest.trim_start().strip_prefix(':'))
        else {
            continue;
        };
        if let Some(title) = parse_pbtxt_string(rest.trim()) {
            let title = title.trim();
            if !title.is_empty() {
                return Some(title.to_string());
            }
        }
    }
    None
}

/// Parse a double-quoted protobuf text-format string literal, decoding octal
/// (`\ooo`) and hex (`\xHH`) byte escapes into UTF-8.
fn parse_pbtxt_string(input: &str) -> Option<String> {
    const fn hex_val(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = input.strip_prefix('"')?.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return String::from_utf8(out).ok(),
            b'\\' => {
                i += 1;
                let esc = *bytes.get(i)?;
                match esc {
                    b'\\' => out.push(b'\\'),
                    b'"' => out.push(b'"'),
                    b'\'' => out.push(b'\''),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'0'..=b'7' => {
                        let mut val: u16 = u16::from(esc - b'0');
                        for _ in 0..2 {
                            if let Some(&next) = bytes.get(i + 1)
                                && (b'0'..=b'7').contains(&next)
                            {
                                val = val * 8 + u16::from(next - b'0');
                                i += 1;
                            } else {
                                break;
                            }
                        }
                        out.push(u8::try_from(val).ok()?);
                    }
                    b'x' | b'X' => {
                        let hi = hex_val(*bytes.get(i + 1)?)?;
                        i += 1;
                        let val = bytes
                            .get(i + 1)
                            .copied()
                            .and_then(hex_val)
                            .map_or(hi, |lo| {
                                i += 1;
                                (hi << 4) | lo
                            });
                        out.push(val);
                    }
                    _ => return None,
                }
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    None
}

/// Minimal percent-decoding for `file://` URIs (no external dependency).
#[cfg(any(
    feature = "antigravity-sqlite",
    feature = "zcode",
    feature = "cursor",
    feature = "opencode",
    feature = "goose",
    feature = "hermes",
    feature = "crush",
    feature = "devin",
    feature = "shelley",
    feature = "openclaw-sqlite",
    feature = "copilot-vscdb",
    feature = "pi-sqlite",
    feature = "pi-durable"
))]
fn percent_decode(input: &str) -> Option<String> {
    const fn hex_val(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] == b'%' {
            let hi = hex_val(*bytes.get(pos + 1)?)?;
            let lo = hex_val(*bytes.get(pos + 2)?)?;
            out.push((hi << 4) | lo);
            pos += 3;
            continue;
        }
        out.push(bytes[pos]);
        pos += 1;
    }
    String::from_utf8(out)
        .ok()
        .filter(|path| !path.contains('\0'))
}

/// Parse a `file://` workspace URI (or plain path) into a local `PathBuf`.
#[cfg(any(
    feature = "antigravity-sqlite",
    feature = "zcode",
    feature = "cursor",
    feature = "opencode",
    feature = "goose",
    feature = "hermes",
    feature = "crush",
    feature = "devin",
    feature = "shelley",
    feature = "openclaw-sqlite",
    feature = "copilot-vscdb",
    feature = "pi-sqlite",
    feature = "pi-durable"
))]
fn parse_workspace_uri(uri: &str) -> Option<PathBuf> {
    let trimmed = uri.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return None;
    }
    let Some(rest) = trimmed.strip_prefix("file://") else {
        return Path::new(trimmed)
            .is_absolute()
            .then(|| PathBuf::from(trimmed));
    };
    // Split authority before decoding: file://server/share must retain the
    // server as a UNC path, rather than silently becoming local /share.
    let slash = rest.find(['/', '\\'])?;
    let authority = &rest[..slash];
    let decoded_path = percent_decode(&rest[slash..])?;
    let looks_like_drive = authority.len() == 2
        && authority.as_bytes()[0].is_ascii_alphabetic()
        && authority.as_bytes()[1] == b':';
    let decoded = if authority.is_empty() || authority.eq_ignore_ascii_case("localhost") {
        decoded_path
    } else if looks_like_drive {
        format!("{authority}{decoded_path}")
    } else {
        format!("//{authority}{decoded_path}")
    };
    let mut path = decoded.as_str();
    if cfg!(windows) && path.len() > 2 {
        let chars: Vec<char> = path.chars().take(3).collect();
        if chars[0] == '/' && chars[1].is_ascii_alphabetic() && chars[2] == ':' {
            path = &path[1..];
        }
    }
    (!path.is_empty()).then(|| PathBuf::from(path))
}

#[derive(Debug, Default)]
struct SummaryMetadata {
    workspace: Option<PathBuf>,
    title: Option<String>,
    parent_conversation_id: Option<String>,
}

/// Best-effort read of `workspace_uris`, `title`, and `parent_conversation_id`
/// from `<base>/conversation_summaries.db`.
#[cfg(any(
    feature = "antigravity-sqlite",
    feature = "zcode",
    feature = "cursor",
    feature = "opencode",
    feature = "goose",
    feature = "hermes",
    feature = "crush",
    feature = "devin",
    feature = "shelley",
    feature = "openclaw-sqlite",
    feature = "copilot-vscdb",
    feature = "pi-sqlite",
    feature = "pi-durable"
))]
fn summary_metadata(base: &Path, uuid: &str, excluded_paths: &[PathBuf]) -> SummaryMetadata {
    use super::sqlite_sync::{ConnectionExt, open_with_flags};
    use frankensqlite::compat::{OpenFlags, RowExt};

    let db_path = base.join("conversation_summaries.db");
    // Opening a SQLite database can also read its WAL. An excluded WAL must
    // therefore exclude the summary lookup, even when the main file is allowed.
    if !db_path.is_file()
        || path_is_excluded(&db_path, excluded_paths)
        || path_is_excluded(&db_path.with_extension("db-wal"), excluded_paths)
    {
        return SummaryMetadata::default();
    }
    let Some(db_str) = db_path.to_str() else {
        return SummaryMetadata::default();
    };
    let Ok(conn) = open_with_flags(db_str, OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return SummaryMetadata::default();
    };
    let row = conn.read_transaction(|conn| {
        // Inspect and read inside one snapshot: older schemas may omit an
        // optional field, and a concurrent schema change must not mix versions.
        let columns =
            conn.query_map_collect("PRAGMA table_info(conversation_summaries)", &[], |row| {
                row.get_typed::<String>(1)
            })?;
        let projection = ["workspace_uris", "title", "parent_conversation_id"]
            .map(|name| {
                if columns.iter().any(|column| column == name) {
                    name
                } else {
                    "NULL"
                }
            })
            .join(", ");
        // The projection uses only the fixed allowlist above. IDs are bound.
        conn.query_row_map(
            &format!("SELECT {projection} FROM conversation_summaries WHERE conversation_id = ?1"),
            frankensqlite::params![uuid],
            |row| {
                Ok((
                    row.get_typed::<String>(0).ok(),
                    row.get_typed::<String>(1).ok(),
                    row.get_typed::<String>(2).ok(),
                ))
            },
        )
    });
    let Ok((workspace_uris, title, parent_id)) = row else {
        return SummaryMetadata::default();
    };
    let workspace = workspace_uris
        .as_deref()
        .and_then(|uris| serde_json::from_str::<Value>(uris).ok())
        .and_then(|uris| {
            uris.as_array()?
                .iter()
                .find_map(|uri| uri.as_str().and_then(parse_workspace_uri))
        });
    let nonempty = |value: Option<String>| {
        value
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    SummaryMetadata {
        workspace,
        title: nonempty(title),
        parent_conversation_id: nonempty(parent_id),
    }
}

#[cfg(not(any(
    feature = "antigravity-sqlite",
    feature = "zcode",
    feature = "cursor",
    feature = "opencode",
    feature = "goose",
    feature = "hermes",
    feature = "crush",
    feature = "devin",
    feature = "shelley",
    feature = "openclaw-sqlite",
    feature = "copilot-vscdb",
    feature = "pi-sqlite",
    feature = "pi-durable"
)))]
fn summary_metadata(_base: &Path, _uuid: &str, _excluded_paths: &[PathBuf]) -> SummaryMetadata {
    SummaryMetadata::default()
}

/// Build a [`NormalizedMessage`] (idx assigned later by `reindex_messages`).
fn message(
    role: &str,
    author: Option<&str>,
    created_at: Option<i64>,
    content: String,
    extra: Map<String, Value>,
    invocations: Vec<NormalizedInvocation>,
) -> NormalizedMessage {
    NormalizedMessage {
        idx: 0,
        role: role.to_string(),
        author: author.map(String::from),
        created_at,
        content,
        extra: Value::Object(extra),
        invocations,
        snippets: Vec::new(),
    }
}

/// Map a single transcript record to a normalized message, or `None` for records
/// that carry no timeline content (e.g. `CONVERSATION_HISTORY` markers).
#[allow(clippy::too_many_lines)]
fn record_to_message(rec: &Value) -> Option<NormalizedMessage> {
    let source = rec.get("source").and_then(Value::as_str).unwrap_or("");
    let step_type = rec.get("type").and_then(Value::as_str).unwrap_or("");
    let created = rec.get("created_at").and_then(parse_timestamp);
    let content = rec
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let thinking = rec
        .get("thinking")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let tool_calls = rec.get("tool_calls").filter(|v| v.is_array());

    match step_type {
        "USER_INPUT" => {
            let (body, settings, metadata) = extract_user_request(&content);
            if body.trim().is_empty() {
                return None;
            }
            let mut extra = Map::new();
            if let Some(s) = settings {
                extra.insert("settings_change".to_string(), Value::String(s));
            }
            if let Some(m) = metadata {
                extra.insert("additional_metadata".to_string(), Value::String(m));
            }
            Some(message("user", None, created, body, extra, Vec::new()))
        }
        "PLANNER_RESPONSE" => {
            let invocations = parse_explicit_tool_calls(tool_calls, None);
            let mut extra = Map::new();
            if !invocations.is_empty() {
                extra.insert(
                    "cass".to_string(),
                    serde_json::json!({ "tool_call_count": invocations.len() }),
                );
            }
            if let Some(t) = thinking {
                extra.insert("thinking".to_string(), Value::String(t));
            }
            let has_usage = attach_usage_and_model(rec, &mut extra);
            if content.trim().is_empty()
                && !extra.contains_key("thinking")
                && invocations.is_empty()
                && !has_usage
            {
                return None;
            }
            Some(message(
                "assistant",
                None,
                created,
                content,
                extra,
                invocations,
            ))
        }
        "CONVERSATION_HISTORY" => None,
        "EPHEMERAL_MESSAGE" | "SYSTEM_MESSAGE" => {
            if content.trim().is_empty() {
                return None;
            }
            let mut extra = Map::new();
            extra.insert("agy_type".to_string(), Value::String(step_type.to_string()));
            let author = if step_type == "EPHEMERAL_MESSAGE" {
                "ephemeral"
            } else {
                "system"
            };
            Some(message(
                "system",
                Some(author),
                created,
                content,
                extra,
                Vec::new(),
            ))
        }
        _ => {
            // A MODEL step that is not a planner response is a tool action/result
            // (VIEW_FILE, EDIT_FILE, RUN_COMMAND, …, or an unknown future kind).
            if source == "MODEL" {
                let mut invocations = parse_tool_calls(tool_calls, step_type);
                // Older results identify the call on the record itself.
                if invocations.len() == 1 && invocations[0].call_id.is_none() {
                    invocations[0].call_id = ["tool_call_id", "call_id"]
                        .iter()
                        .find_map(|key| {
                            rec.get(key)
                                .and_then(Value::as_str)
                                .map(str::trim)
                                .filter(|id| !id.is_empty())
                        })
                        .map(String::from);
                }
                let mut extra = Map::new();
                extra.insert("agy_type".to_string(), Value::String(step_type.to_string()));
                if let Some(t) = thinking {
                    extra.insert("thinking".to_string(), Value::String(t));
                }
                if !invocations.is_empty() {
                    extra.insert(
                        "cass".to_string(),
                        serde_json::json!({ "tool_call_count": invocations.len() }),
                    );
                }
                let has_usage = attach_usage_and_model(rec, &mut extra);
                if content.trim().is_empty()
                    && !extra.contains_key("thinking")
                    && invocations.is_empty()
                    && !has_usage
                {
                    return None;
                }
                let author = step_type.to_ascii_lowercase();
                Some(message(
                    "tool",
                    Some(author.as_str()),
                    created,
                    content,
                    extra,
                    invocations,
                ))
            } else {
                // Unknown non-MODEL kind (including CHECKPOINT): preserve as a
                // system message rather than dropping it. Never crash on an
                // unrecognized schema.
                let mut extra = Map::new();
                let has_usage = attach_usage_and_model(rec, &mut extra);
                if content.trim().is_empty() && !has_usage {
                    return None;
                }
                extra.insert("agy_type".to_string(), Value::String(step_type.to_string()));
                if !source.is_empty() {
                    extra.insert("agy_source".to_string(), Value::String(source.to_string()));
                }
                Some(message("system", None, created, content, extra, Vec::new()))
            }
        }
    }
    .map(|mut msg| {
        // CASS persists extra even when its internal message type lacks an
        // invocations field. Explicit counts remain authoritative.
        if let Some(calls) = tool_calls {
            msg.extra["tool_calls"] = calls.clone();
            msg.extra["cass"]["tool_call_count"] = Value::from(msg.invocations.len());
        }
        if let Some(index) = rec.get("step_index").and_then(Value::as_i64) {
            msg.extra["step_index"] = Value::from(index);
        }
        for key in ["tool_call_id", "call_id"] {
            if let Some(id) = rec.get(key) {
                msg.extra[key] = id.clone();
            }
        }
        msg
    })
}

/// Results reference an earlier planner request without claiming another call.
/// Each planner step is a separate request, even if a provider reuses call IDs
/// after compaction. ID-less historical calls remain independent.
/// The caller resets ownership at raw turn/compaction boundaries, including
/// records that are filtered out of the normalized display messages.
fn reconcile_tool_invocations(msg: &mut NormalizedMessage, requested_ids: &mut HashSet<String>) {
    if msg.role == "assistant" {
        requested_ids.extend(
            msg.invocations
                .iter()
                .filter_map(|call| call.call_id.clone()),
        );
        return;
    }
    if msg.role != "tool" || msg.invocations.is_empty() {
        return;
    }
    let mut referenced = Vec::new();
    msg.invocations.retain(|invocation| {
        let Some(id) = &invocation.call_id else {
            return true;
        };
        if !requested_ids.contains(id) {
            return true;
        }
        referenced.push(Value::String(id.clone()));
        false
    });
    msg.extra["cass"]["tool_call_count"] = Value::from(msg.invocations.len());
    if !referenced.is_empty() {
        msg.extra["cass"]["referenced_tool_call_ids"] = Value::Array(referenced);
    }
}

fn conversation_metadata(
    model: Option<String>,
    parent_conversation_id: Option<String>,
    layout: Option<AntigravityLayout>,
    base: Option<&Path>,
) -> Value {
    let mut metadata = Map::new();
    metadata.insert("source".to_string(), Value::String(AGENT_SLUG.to_string()));
    if let Some(model) = model {
        metadata.insert("model".to_string(), Value::String(model));
    }
    if let Some(parent) = parent_conversation_id {
        metadata.insert(
            "parent_conversation_id".to_string(),
            Value::String(
                layout
                    .unwrap_or(AntigravityLayout::Cli)
                    .external_id(&parent),
            ),
        );
        metadata.insert(
            "raw_parent_conversation_id".to_string(),
            Value::String(parent),
        );
    }
    // Provenance: which store (IDE vs CLI) and which base directory this
    // conversation was read from, so identical uuids across stores stay
    // distinguishable downstream.
    if let Some(layout) = layout {
        metadata.insert(
            "layout".to_string(),
            Value::String(layout.metadata_value().to_string()),
        );
    }
    if let Some(base) = base {
        metadata.insert(
            "data_root".to_string(),
            Value::String(base.to_string_lossy().into_owned()),
        );
    }
    Value::Object(metadata)
}

fn parse_conversation(
    conversation_dir: &Path,
    transcript: &Path,
    excluded_paths: &[PathBuf],
    source: &AntigravitySourceRoot,
) -> Option<NormalizedConversation> {
    let records = AntigravityConnector::read_transcript_records(transcript);
    if records.is_empty() {
        return None;
    }

    // Sort by step_index (gaps are expected; ties keep input order via stable sort).
    let mut ordered: Vec<&Value> = records.iter().collect();
    ordered.sort_by_key(|r| {
        r.get("step_index")
            .and_then(Value::as_i64)
            .unwrap_or(i64::MAX)
    });

    let base = source.metadata_base(conversation_dir);
    let layout = source
        .layout
        .or_else(|| base.and_then(AntigravityLayout::from_base));
    let uuid = source
        .conversation_uuid
        .clone()
        .or_else(|| AntigravityConnector::conversation_uuid(conversation_dir));
    let external_id = uuid
        .as_deref()
        .map(|id| layout.unwrap_or(AntigravityLayout::Cli).external_id(id));
    let model = detect_model(&ordered);
    let ann_title = base.and_then(|b| {
        uuid.as_deref()
            .and_then(|id| annotation_title(b, id, excluded_paths))
    });
    let summary = base
        .filter(|_| source.root.origin.is_local())
        .and_then(|b| {
            uuid.as_deref()
                .map(|id| summary_metadata(b, id, excluded_paths))
        })
        .unwrap_or_default();
    let admissible_parent = |parent: &String| {
        valid_conversation_uuid(parent)
            && !uuid
                .as_deref()
                .is_some_and(|id| parent.eq_ignore_ascii_case(id))
    };
    let parent_conversation_id = summary
        .parent_conversation_id
        .filter(admissible_parent)
        .or_else(|| detect_parent_from_records(&ordered))
        .filter(admissible_parent);

    let mut messages: Vec<NormalizedMessage> = Vec::new();
    let mut requested_ids = HashSet::new();
    let mut started_at: Option<i64> = None;
    let mut ended_at: Option<i64> = None;

    for rec in ordered {
        // Empty checkpoints and settings-only user records still delimit call
        // identities even when record_to_message emits no display message.
        if matches!(
            rec.get("type").and_then(Value::as_str),
            Some("USER_INPUT" | "CHECKPOINT")
        ) {
            requested_ids.clear();
        }
        if let Some(ts) = rec.get("created_at").and_then(parse_timestamp) {
            started_at = Some(started_at.map_or(ts, |cur| cur.min(ts)));
            ended_at = Some(ended_at.map_or(ts, |cur| cur.max(ts)));
        }
        if let Some(mut msg) = record_to_message(rec) {
            reconcile_tool_invocations(&mut msg, &mut requested_ids);
            messages.push(msg);
        }
    }

    if messages.is_empty() {
        // read_transcript_records already returns [] for an empty/un-run
        // conversation, so reaching here means every record was a content-less
        // marker — or the transcript schema drifted out from under us. Surface
        // it loudly rather than letting the conversation silently vanish.
        tracing::warn!(
            transcript = %transcript.display(),
            records = records.len(),
            "antigravity: transcript produced no messages (possible agy schema drift)"
        );
        return None;
    }

    reindex_messages(&mut messages);

    let title = ann_title.or(summary.title).or_else(|| {
        messages
            .iter()
            .find(|m| m.role == "user")
            .or_else(|| messages.first())
            .and_then(|m| m.content.lines().find(|l| !l.trim().is_empty()))
            .map(|line| line.chars().take(100).collect::<String>())
    });

    Some(NormalizedConversation {
        agent_slug: AGENT_SLUG.to_string(),
        external_id,
        title,
        workspace: summary.workspace,
        source_path: transcript.to_path_buf(),
        started_at,
        ended_at,
        metadata: conversation_metadata(model, parent_conversation_id, layout, base),
        messages,
    })
}

fn scan_antigravity_with_callback(
    ctx: &ScanContext,
    on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
) -> Result<()> {
    let excluded_paths = excluded_scan_paths_from_env()?;
    let roots = AntigravityConnector::source_roots(ctx);
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for source in roots {
        let root = &source.root;
        if path_is_excluded(&root.path, &excluded_paths) {
            continue;
        }
        for conversation_dir in AntigravityConnector::conversation_dirs(&root.path) {
            let Some(transcript) =
                AntigravityConnector::selected_transcript_path(&conversation_dir, &excluded_paths)
            else {
                continue;
            };
            let sidecars = AntigravityConnector::metadata_sidecars(
                &conversation_dir,
                root,
                source.metadata_base(&conversation_dir),
                &excluded_paths,
            );
            // A selected removed sidecar is itself change evidence. Its mtime
            // no longer exists, so refresh the surviving transcript/metadata.
            if root.path.exists()
                && !AntigravityConnector::conversation_modified_since(
                    &conversation_dir,
                    &transcript,
                    ctx.since_ts,
                    &sidecars,
                    &excluded_paths,
                )
            {
                continue;
            }
            // An unchanged broad root must not hide a later explicit sidecar
            // deletion event for the same conversation.
            if !seen.insert(dedupe_path_key(&conversation_dir)) {
                continue;
            }
            ctx.tick();
            if let Some(mut conversation) =
                parse_conversation(&conversation_dir, &transcript, &excluded_paths, &source)
            {
                root.apply_workspace_rewrite(&mut conversation);
                on_conversation(conversation).with_context(|| {
                    format!(
                        "emit antigravity conversation {}",
                        conversation_dir.display()
                    )
                })?;
            }
        }
    }

    Ok(())
}

fn discover_sources(ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
    let excluded_paths = excluded_scan_paths_from_env()?;
    let roots = AntigravityConnector::source_roots(ctx);
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for source in roots {
        let root = &source.root;
        if path_is_excluded(&root.path, &excluded_paths) {
            continue;
        }
        for conversation_dir in AntigravityConnector::conversation_dirs(&root.path) {
            let Some(transcript) =
                AntigravityConnector::selected_transcript_path(&conversation_dir, &excluded_paths)
            else {
                continue;
            };
            let base = source.metadata_base(&conversation_dir);
            let sidecars = AntigravityConnector::metadata_sidecars(
                &conversation_dir,
                root,
                base,
                &excluded_paths,
            );
            if root.path.exists()
                && !AntigravityConnector::conversation_modified_since(
                    &conversation_dir,
                    &transcript,
                    ctx.since_ts,
                    &sidecars,
                    &excluded_paths,
                )
            {
                continue;
            }

            // The transcript we actually parse — required for reconstruction.
            if transcript.is_file()
                && !path_is_excluded(&transcript, &excluded_paths)
                && seen.insert(dedupe_path_key(&transcript))
            {
                out.push(
                    DiscoveredSourceFile::new(
                        AGENT_SLUG,
                        root,
                        transcript,
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );
            }

            // The fuller transcript variant, if present (optional).
            let transcript_full = AntigravityConnector::transcript_full_path(&conversation_dir);
            if transcript_full.is_file()
                && !path_is_excluded(&transcript_full, &excluded_paths)
                && seen.insert(dedupe_path_key(&transcript_full))
            {
                out.push(
                    DiscoveredSourceFile::new(
                        AGENT_SLUG,
                        root,
                        transcript_full,
                        DiscoveredSourceRole::PrimarySessionLog,
                        false,
                    )
                    .with_fs_metadata(),
                );
            }

            // The durable per-conversation SQLite database — the canonical source
            // of truth worth mirroring, though we read the transcript instead.
            if let Some(db) = AntigravityConnector::sibling_db_path(&conversation_dir, base) {
                if !path_is_excluded(&db, &excluded_paths) && seen.insert(dedupe_path_key(&db)) {
                    out.push(
                        DiscoveredSourceFile::new(
                            AGENT_SLUG,
                            root,
                            db,
                            DiscoveredSourceRole::SqliteDatabase,
                            false,
                        )
                        .with_fs_metadata(),
                    );
                }
            }

            // Shared summary sources are deduplicated across conversations.
            for sidecar in sidecars {
                if seen.insert(dedupe_path_key(&sidecar.source_path)) {
                    out.push(sidecar);
                }
            }
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// agy version-compatibility guard (bd-47kjh.2.5)
// ---------------------------------------------------------------------------

/// The `agy` versions whose transcript schema this reader has been validated against.
///
/// agy self-updates (`agy update`) and its on-disk formats are private and
/// undocumented, so bump this list whenever the reader is re-checked against a
/// newer agy. The connector itself never crashes on drift — unknown step types
/// are preserved (`extra.agy_type`) and a content-less transcript warns — but
/// this lets cass/ntm/CI proactively flag an untested agy so we re-validate.
pub const AGY_TESTED_VERSIONS: &[&str] = &["1.0.7"];

/// Best-effort `agy --version`, parsed to a bare dotted-numeric string (e.g.
/// `1.0.7`). Returns `None` if agy is absent or the output is unparseable.
#[must_use]
pub fn installed_agy_version() -> Option<String> {
    let output = std::process::Command::new("agy")
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_agy_version(&text)
}

/// Pull the first dotted-numeric version token out of `agy --version` text such
/// as `agy version 1.0.7` or `v1.0.7`.
fn parse_agy_version(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|tok| tok.trim_start_matches('v'))
        .find(|t| {
            let parts: Vec<&str> = t.split('.').collect();
            parts.len() >= 2
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(String::from)
}

/// Whether `version` is one this reader was validated against.
#[must_use]
pub fn agy_version_is_tested(version: &str) -> bool {
    let v = version.trim().trim_start_matches('v');
    AGY_TESTED_VERSIONS.contains(&v)
}

/// CI/diagnostic signal for agy version drift.
///
/// If agy is installed at a version this reader has NOT been validated against,
/// log a loud warning so the transcript reader gets re-checked after an
/// `agy update`. Returns the installed version (if any). Intended for a
/// startup/CI check — NOT the hot scan path.
pub fn warn_if_untested_agy_version() -> Option<String> {
    let version = installed_agy_version()?;
    if !agy_version_is_tested(&version) {
        tracing::warn!(
            installed = %version,
            tested = ?AGY_TESTED_VERSIONS,
            "antigravity: installed agy version is outside the tested-compatible set; \
             re-validate the transcript reader (bd-47kjh.2.5)"
        );
    }
    Some(version)
}

impl Connector for AntigravityConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector(AGENT_SLUG).unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        scan_antigravity_with_callback(ctx, &mut |conv| {
            convs.push(conv);
            Ok(())
        })?;
        Ok(convs)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        discover_sources(ctx)
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        scan_antigravity_with_callback(ctx, on_conversation)
    }

    fn supports_source_boundaries(&self) -> bool {
        // An annotation or shared summary/WAL may first appear outside the
        // transcript directory after a receipt was recorded. Existing-file
        // fingerprints cannot prove those dependencies are still absent.
        // Keep streaming and metadata-aware since_ts filtering, but use the
        // trait's conservative callback fallback rather than stale receipts.
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::assert_discovery_covers_scan_sources;
    use std::fs;
    use tempfile::TempDir;

    const FIXTURE_UUID: &str = "f1e2d3c4-b5a6-4789-9abc-def012345678";

    /// The base directory (`brain/` + `conversations/`) of the checked-in
    /// fixture. It is not under a `.gemini/` parent, so it is deliberately
    /// unclassified (neither IDE nor CLI).
    fn fixture_base() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("antigravity")
    }

    fn fixture_conversation_dir() -> PathBuf {
        fixture_base().join("brain").join(FIXTURE_UUID)
    }

    fn fixture_ctx() -> ScanContext {
        let base = fixture_base();
        ScanContext::with_roots(base.clone(), vec![ScanRoot::local(base)], None)
    }

    fn only_conversation() -> NormalizedConversation {
        let convs = AntigravityConnector::new().scan(&fixture_ctx()).unwrap();
        assert_eq!(convs.len(), 1, "fixture is a single conversation");
        convs.into_iter().next().unwrap()
    }

    #[test]
    fn default_detection_scopes_to_antigravity_base_data_dir() {
        // The checked-in fixture base has the `brain/<uuid>` shape; default
        // detection with this base as data_dir must scan HERE, not the
        // machine's real ~/.gemini/antigravity-cli.
        let ctx = ScanContext::local_default(fixture_base(), None);
        let convs = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(
            convs.len(),
            1,
            "default detection with an antigravity-base data_dir must scan that base"
        );
        assert_eq!(convs[0].external_id.as_deref(), Some(FIXTURE_UUID));
    }

    #[test]
    fn new_creates_connector() {
        let _ = AntigravityConnector::new();
        let _ = AntigravityConnector;
    }

    #[test]
    fn is_conversation_dir_requires_transcript() {
        let dir = TempDir::new().unwrap();
        assert!(!AntigravityConnector::is_conversation_dir(dir.path()));
        let logs = dir.path().join(".system_generated").join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("transcript.jsonl"), "{}\n").unwrap();
        assert!(AntigravityConnector::is_conversation_dir(dir.path()));
    }

    #[test]
    fn extract_tagged_blocks_handles_multiple_and_missing() {
        assert_eq!(
            extract_tagged_blocks("<A>one</A> mid <A>two</A>", "A"),
            vec!["one".to_string(), "two".to_string()]
        );
        assert!(extract_tagged_blocks("no tags here", "A").is_empty());
        // Unterminated open tag does not panic or loop forever.
        assert!(extract_tagged_blocks("<A>oops", "A").is_empty());
    }

    #[test]
    fn extract_user_request_unwraps_and_keeps_settings() {
        let raw = "<USER_REQUEST>\ndo the thing\n</USER_REQUEST>\n<ADDITIONAL_METADATA>\ntime\n</ADDITIONAL_METADATA>\n<USER_SETTINGS_CHANGE>\nchanged to Gemini 3.1 Pro (High). ok\n</USER_SETTINGS_CHANGE>";
        let (body, settings, metadata) = extract_user_request(raw);
        assert_eq!(body, "do the thing");
        assert!(settings.unwrap().contains("Gemini 3.1 Pro (High)"));
        assert_eq!(metadata.as_deref(), Some("time"));
    }

    #[test]
    fn extract_user_request_falls_back_to_raw_when_unwrapped() {
        let (body, settings, metadata) = extract_user_request("plain prompt with no tags");
        assert_eq!(body, "plain prompt with no tags");
        assert!(settings.is_none() && metadata.is_none());
    }

    #[test]
    fn model_from_settings_extracts_human_name() {
        assert_eq!(
            model_from_settings(
                "The user changed setting `Model Selection` from None to Gemini 3.1 Pro (High). No need to comment."
            )
            .as_deref(),
            Some("Gemini 3.1 Pro (High)")
        );
        assert_eq!(model_from_settings("changed from X to None. done"), None);
        // An earlier " to " (in a setting name / prior value) must NOT hijack the
        // parse: anchor on " from " then the next " to ".
        assert_eq!(
            model_from_settings(
                "changed setting `Auto to Stop` from None to Gemini 3.1 Pro (High). ok"
            )
            .as_deref(),
            Some("Gemini 3.1 Pro (High)")
        );
        // No " from " marker: fall back to the first " to ".
        assert_eq!(
            model_from_settings("set model to Gemini 3.1 Pro (High). thanks").as_deref(),
            Some("Gemini 3.1 Pro (High)")
        );
    }

    #[test]
    fn parse_tool_calls_synthesizes_name_from_type_when_absent() {
        let invs = parse_tool_calls(None, "VIEW_FILE");
        assert_eq!(invs.len(), 1);
        assert_eq!(invs[0].name, "view_file");
        assert_eq!(invs[0].kind, "tool");
        assert!(invs[0].arguments.is_none());
    }

    #[test]
    fn parse_tool_calls_reads_structured_object_args() {
        let tc = serde_json::json!([
            {"name":"run_command","id":"c1","arguments":{"command":"echo hi"}}
        ]);
        let invs = parse_tool_calls(Some(&tc), "RUN_COMMAND");
        assert_eq!(invs[0].name, "run_command");
        assert_eq!(invs[0].call_id.as_deref(), Some("c1"));
        assert_eq!(invs[0].arguments.as_ref().unwrap()["command"], "echo hi");
    }

    #[test]
    fn parse_tool_calls_parses_stringified_json_args() {
        let tc = serde_json::json!([
            {"tool_name":"edit_file","id":"c2","arguments":"{\"path\":\"out.txt\"}"}
        ]);
        let invs = parse_tool_calls(Some(&tc), "EDIT_FILE");
        assert_eq!(invs[0].name, "edit_file");
        assert_eq!(invs[0].arguments.as_ref().unwrap()["path"], "out.txt");
    }

    #[test]
    fn scan_parses_fixture_metadata_and_roles() {
        let conv = only_conversation();
        assert_eq!(conv.agent_slug, "antigravity");
        assert_eq!(conv.external_id.as_deref(), Some(FIXTURE_UUID));
        assert_eq!(conv.metadata["model"], "Gemini 3.1 Pro (High)");
        assert_eq!(conv.metadata["source"], "antigravity");
        assert!(conv.title.as_deref().unwrap().starts_with("Read data.txt"));
        assert!(conv.started_at.unwrap() <= conv.ended_at.unwrap());
        assert_eq!(
            conv.source_path,
            AntigravityConnector::transcript_path(&fixture_conversation_dir())
        );

        // CONVERSATION_HISTORY is dropped; every other record becomes a message.
        assert_eq!(conv.messages.len(), 9);
        for (i, m) in conv.messages.iter().enumerate() {
            assert_eq!(m.idx, i64::try_from(i).unwrap());
        }
        assert!(conv.messages.iter().any(|m| m.role == "user"));
        assert!(conv.messages.iter().any(|m| m.role == "assistant"));
        assert!(conv.messages.iter().any(|m| m.role == "tool"));
        assert!(conv.messages.iter().any(|m| m.role == "system"));
    }

    #[test]
    fn user_message_unwraps_request_and_keeps_settings_extra() {
        let conv = only_conversation();
        let user = conv.messages.iter().find(|m| m.role == "user").unwrap();
        assert!(user.content.starts_with("Read data.txt"));
        assert!(!user.content.contains("USER_REQUEST"));
        assert!(
            user.extra["settings_change"]
                .as_str()
                .unwrap()
                .contains("Gemini 3.1 Pro (High)")
        );
        assert!(user.extra.get("additional_metadata").is_some());
    }

    #[test]
    fn planner_response_preserves_thinking() {
        let conv = only_conversation();
        let planner = conv
            .messages
            .iter()
            .find(|m| m.role == "assistant" && m.extra.get("thinking").is_some())
            .expect("a planner response with thinking");
        assert!(planner.content.contains("data.txt"));
        assert!(
            planner.extra["thinking"]
                .as_str()
                .unwrap()
                .contains("Planning the steps")
        );
    }

    #[test]
    fn view_file_becomes_tool_message_with_synthesized_invocation() {
        let conv = only_conversation();
        let view = conv
            .messages
            .iter()
            .find(|m| m.extra.get("agy_type").and_then(Value::as_str) == Some("VIEW_FILE"))
            .expect("VIEW_FILE message");
        assert_eq!(view.role, "tool");
        assert!(view.content.contains("1234"));
        assert_eq!(view.invocations[0].name, "view_file");
        assert!(view.invocations[0].arguments.is_none());
    }

    #[test]
    fn run_command_invocation_carries_structured_args() {
        let conv = only_conversation();
        let run = conv
            .messages
            .iter()
            .find(|m| m.invocations.iter().any(|i| i.name == "run_command"))
            .expect("run_command message");
        assert_eq!(run.role, "tool");
        assert!(run.content.contains("HELLO_FROM_AGY"));
        let inv = &run.invocations[0];
        assert_eq!(inv.call_id.as_deref(), Some("call_run_0001"));
        assert_eq!(
            inv.arguments.as_ref().unwrap()["command"],
            "echo HELLO_FROM_AGY"
        );
    }

    #[test]
    fn edit_file_invocation_parses_stringified_args() {
        let conv = only_conversation();
        let edit = conv
            .messages
            .iter()
            .find(|m| m.invocations.iter().any(|i| i.name == "edit_file"))
            .expect("edit_file message");
        let inv = &edit.invocations[0];
        assert_eq!(inv.call_id.as_deref(), Some("call_edit_0002"));
        assert_eq!(inv.arguments.as_ref().unwrap()["path"], "out.txt");
        assert_eq!(inv.arguments.as_ref().unwrap()["content"], "DONE");
    }

    #[test]
    fn ephemeral_and_system_messages_preserved_as_system() {
        let conv = only_conversation();
        let ephemeral = conv
            .messages
            .iter()
            .find(|m| m.extra.get("agy_type").and_then(Value::as_str) == Some("EPHEMERAL_MESSAGE"))
            .expect("ephemeral message");
        assert_eq!(ephemeral.role, "system");
        assert_eq!(ephemeral.author.as_deref(), Some("ephemeral"));

        let system = conv
            .messages
            .iter()
            .find(|m| m.extra.get("agy_type").and_then(Value::as_str) == Some("SYSTEM_MESSAGE"))
            .expect("system message");
        assert_eq!(system.role, "system");
        assert_eq!(system.author.as_deref(), Some("system"));
    }

    #[test]
    fn unknown_model_step_type_is_preserved_not_dropped() {
        // BROWSER_PREVIEW is an unknown-to-us MODEL kind; the reader must never
        // crash or silently drop it (agy version-compat robustness).
        let conv = only_conversation();
        let unknown = conv
            .messages
            .iter()
            .find(|m| m.extra.get("agy_type").and_then(Value::as_str) == Some("BROWSER_PREVIEW"))
            .expect("unknown BROWSER_PREVIEW message preserved");
        assert_eq!(unknown.role, "tool");
        assert!(unknown.content.contains("preview"));
        assert_eq!(unknown.invocations[0].name, "browser_preview");
    }

    #[test]
    fn discovery_lists_transcript_full_and_db() {
        let connector = AntigravityConnector::new();
        let discovered = connector.discover_source_files(&fixture_ctx()).unwrap();

        assert!(discovered.iter().all(|d| d.provider_slug == "antigravity"));
        assert!(
            discovered
                .iter()
                .any(|d| d.source_path.ends_with("transcript.jsonl")
                    && d.role == DiscoveredSourceRole::PrimarySessionLog
                    && d.required_for_reconstruction),
            "transcript.jsonl must be a required primary source"
        );
        assert!(
            discovered
                .iter()
                .any(|d| d.source_path.ends_with("transcript_full.jsonl")),
            "transcript_full.jsonl should be discovered"
        );
        assert!(
            discovered
                .iter()
                .any(|d| d.role == DiscoveredSourceRole::SqliteDatabase
                    && d.source_path.extension().is_some_and(|e| e == "db")),
            "the conversations/<uuid>.db should be discovered as the sqlite source"
        );
    }

    #[test]
    fn discovery_covers_scan_sources_for_fixture() {
        assert_discovery_covers_scan_sources(&AntigravityConnector::new(), &fixture_ctx());
    }

    #[test]
    fn scan_with_callback_matches_scan() {
        let connector = AntigravityConnector::new();
        let scanned = connector.scan(&fixture_ctx()).unwrap();
        let mut streamed = Vec::new();
        connector
            .scan_with_callback(&fixture_ctx(), &mut |c| {
                streamed.push(c);
                Ok(())
            })
            .unwrap();
        assert_eq!(streamed.len(), scanned.len());
        assert_eq!(streamed[0].messages.len(), scanned[0].messages.len());
    }

    #[test]
    fn scan_resolves_conversation_from_direct_dir() {
        let dir = fixture_conversation_dir();
        let ctx = ScanContext::with_roots(dir.clone(), vec![ScanRoot::local(dir)], None);
        let convs = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn scan_returns_empty_for_missing_root() {
        let ctx = ScanContext::with_roots(
            PathBuf::from("/no/such/antigravity"),
            vec![ScanRoot::local(PathBuf::from("/no/such/antigravity"))],
            None,
        );
        assert!(AntigravityConnector::new().scan(&ctx).unwrap().is_empty());
    }

    #[test]
    fn since_ts_in_future_skips_conversation() {
        let base = fixture_base();
        let ctx =
            ScanContext::with_roots(base.clone(), vec![ScanRoot::local(base)], Some(i64::MAX));
        assert!(AntigravityConnector::new().scan(&ctx).unwrap().is_empty());
    }

    #[test]
    fn tested_versions_registry_and_version_check() {
        assert!(AGY_TESTED_VERSIONS.contains(&"1.0.7"));
        assert!(agy_version_is_tested("1.0.7"));
        assert!(agy_version_is_tested("v1.0.7"));
        assert!(!agy_version_is_tested("1.0.8"));
        assert!(!agy_version_is_tested("2.0.0"));
    }

    #[test]
    fn parse_agy_version_extracts_dotted_numeric_token() {
        assert_eq!(
            parse_agy_version("agy version 1.0.7").as_deref(),
            Some("1.0.7")
        );
        assert_eq!(parse_agy_version("v1.0.7\n").as_deref(), Some("1.0.7"));
        assert_eq!(
            parse_agy_version("Antigravity CLI 1.2.34 (build x)").as_deref(),
            Some("1.2.34")
        );
        assert_eq!(parse_agy_version("no version here").as_deref(), None);
    }

    #[test]
    fn transcript_with_only_markers_yields_no_conversation() {
        // A transcript whose only records carry no timeline content must not
        // panic and must not fabricate a conversation (it warns instead).
        let dir = TempDir::new().unwrap();
        let logs = dir.path().join(".system_generated").join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(
            logs.join("transcript.jsonl"),
            "{\"step_index\":0,\"source\":\"SYSTEM\",\"type\":\"CONVERSATION_HISTORY\",\"status\":\"DONE\",\"created_at\":\"2026-06-11T20:14:42Z\"}\n",
        )
        .unwrap();
        let ctx = ScanContext::with_roots(
            dir.path().to_path_buf(),
            vec![ScanRoot::local(dir.path().to_path_buf())],
            None,
        );
        assert!(AntigravityConnector::new().scan(&ctx).unwrap().is_empty());
    }

    #[test]
    fn malformed_transcript_lines_are_skipped_not_fatal() {
        let dir = TempDir::new().unwrap();
        let logs = dir.path().join(".system_generated").join("logs");
        fs::create_dir_all(&logs).unwrap();
        // A junk line between two valid records: junk is skipped, the rest parse.
        fs::write(
            logs.join("transcript.jsonl"),
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"status\":\"DONE\",\"created_at\":\"2026-06-11T20:14:42Z\",\"content\":\"<USER_REQUEST>\\nhi there\\n</USER_REQUEST>\"}\nthis is not json\n{\"step_index\":1,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"status\":\"DONE\",\"created_at\":\"2026-06-11T20:14:43Z\",\"content\":\"hello!\"}\n",
        )
        .unwrap();
        let ctx = ScanContext::with_roots(
            dir.path().to_path_buf(),
            vec![ScanRoot::local(dir.path().to_path_buf())],
            None,
        );
        let convs = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].messages.len(),
            2,
            "valid records survive a junk line"
        );
    }

    #[test]
    fn ignores_legacy_gemini_cli_layout_under_shared_dot_gemini() {
        // Both the legacy Gemini CLI (~/.gemini/tmp/<hash>/chats/session-*.json)
        // and agy (~/.gemini/antigravity-cli/...) live under ~/.gemini. The agy
        // connector must resolve ONLY the antigravity-cli transcript, never the
        // gemini session files. Root at the shared `.gemini` parent to prove it.
        let tmp = TempDir::new().unwrap();
        let dot_gemini = tmp.path().join(".gemini");

        // Legacy gemini-cli session (must be ignored).
        let chats = dot_gemini.join("tmp").join("deadbeef").join("chats");
        fs::create_dir_all(&chats).unwrap();
        fs::write(chats.join("session-1.json"), "{\"messages\":[]}").unwrap();

        // agy conversation transcript (must be found).
        let logs = dot_gemini
            .join("antigravity-cli")
            .join("brain")
            .join("11111111-2222-3333-4444-555555555555")
            .join(".system_generated")
            .join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(
            logs.join("transcript.jsonl"),
            "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"status\":\"DONE\",\"created_at\":\"2026-06-11T20:14:42Z\",\"content\":\"<USER_REQUEST>\\nhi\\n</USER_REQUEST>\"}\n",
        )
        .unwrap();

        let ctx =
            ScanContext::with_roots(dot_gemini.clone(), vec![ScanRoot::local(dot_gemini)], None);
        let convs = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1, "only the agy conversation should be found");
        assert_eq!(convs[0].agent_slug, "antigravity");
        assert_eq!(
            convs[0].external_id.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
    }
    // ---------------------------------------------------------------------
    // Dual-store layout (cass #454): IDE `~/.gemini/antigravity` + CLI
    // `~/.gemini/antigravity-cli`.
    // ---------------------------------------------------------------------

    const SHARED_UUID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    /// Write a minimal one-step transcript for `<base>/brain/<uuid>` whose user
    /// request is `marker`, returning the conversation directory.
    fn write_conversation(base: &Path, uuid: &str, marker: &str) -> PathBuf {
        let conv_dir = base.join("brain").join(uuid);
        let logs = conv_dir.join(".system_generated").join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(
            logs.join("transcript.jsonl"),
            format!(
                "{{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"status\":\"DONE\",\"created_at\":\"2026-06-11T20:14:42Z\",\"content\":\"<USER_REQUEST>\\n{marker}\\n</USER_REQUEST>\"}}\n"
            ),
        )
        .unwrap();
        conv_dir
    }

    #[test]
    fn default_base_roots_probe_ide_then_cli_under_dot_gemini() {
        let home = Path::new("/home/someone");
        assert_eq!(
            AntigravityConnector::default_base_roots(home),
            vec![
                PathBuf::from("/home/someone/.gemini/antigravity"),
                PathBuf::from("/home/someone/.gemini/antigravity-cli"),
            ]
        );
    }

    #[test]
    fn layout_is_classified_from_dot_gemini_location_shape_only() {
        assert_eq!(
            AntigravityLayout::from_base(Path::new("/h/.gemini/antigravity")),
            Some(AntigravityLayout::Ide)
        );
        assert_eq!(
            AntigravityLayout::from_base(Path::new("/h/.gemini/antigravity-cli")),
            Some(AntigravityLayout::Cli)
        );
        // A same-named directory outside `.gemini/` (fixture, relocated
        // mirror) is unclassified rather than guessed.
        assert_eq!(
            AntigravityLayout::from_base(Path::new("/mirror/antigravity")),
            None
        );
        assert_eq!(
            AntigravityLayout::from_base(Path::new("/h/.gemini/antigravity-ide")),
            None
        );
        assert_eq!(AntigravityLayout::from_base(&fixture_base()), None);
    }

    #[test]
    fn external_ids_qualify_ide_and_keep_cli_bare() {
        assert_eq!(AntigravityLayout::Ide.external_id("u-1"), "ide/u-1");
        assert_eq!(AntigravityLayout::Cli.external_id("u-1"), "u-1");
    }

    #[test]
    fn ide_and_cli_stores_are_both_scanned_and_same_uuid_never_collides() {
        let tmp = TempDir::new().unwrap();
        let dot_gemini = tmp.path().join(".gemini");
        let ide_base = dot_gemini.join("antigravity");
        let cli_base = dot_gemini.join("antigravity-cli");
        // The SAME uuid under both stores must surface as two distinct
        // conversations with different external ids.
        write_conversation(&ide_base, SHARED_UUID, "from the IDE");
        write_conversation(&cli_base, SHARED_UUID, "from the CLI");

        // The two default probe roots, exactly as `base_roots()` produces them.
        let ctx = ScanContext::with_roots(
            tmp.path().to_path_buf(),
            vec![
                ScanRoot::local(ide_base.clone()),
                ScanRoot::local(cli_base.clone()),
            ],
            None,
        );
        let mut convs = AntigravityConnector::new().scan(&ctx).unwrap();
        convs.sort_by(|a, b| a.external_id.cmp(&b.external_id));
        assert_eq!(convs.len(), 2, "one conversation per store");

        let cli = &convs[0];
        assert_eq!(cli.external_id.as_deref(), Some(SHARED_UUID));
        assert_eq!(cli.metadata["layout"], "cli");
        assert_eq!(
            cli.metadata["data_root"],
            cli_base.to_string_lossy().as_ref()
        );
        assert!(cli.source_path.starts_with(&cli_base));
        assert_eq!(cli.messages[0].content, "from the CLI");

        let ide = &convs[1];
        assert_eq!(
            ide.external_id.as_deref(),
            Some(format!("ide/{SHARED_UUID}").as_str())
        );
        assert_eq!(ide.metadata["layout"], "ide");
        assert_eq!(
            ide.metadata["data_root"],
            ide_base.to_string_lossy().as_ref()
        );
        assert!(ide.source_path.starts_with(&ide_base));
        assert_eq!(ide.messages[0].content, "from the IDE");

        // Discovery preserves per-root provenance for both stores.
        let discovered = AntigravityConnector::new()
            .discover_source_files(&ctx)
            .unwrap();
        let transcripts: Vec<&DiscoveredSourceFile> = discovered
            .iter()
            .filter(|d| d.required_for_reconstruction)
            .collect();
        assert_eq!(transcripts.len(), 2);
        assert!(
            transcripts
                .iter()
                .any(|d| d.scan_root == ide_base && d.source_path.starts_with(&ide_base))
        );
        assert!(
            transcripts
                .iter()
                .any(|d| d.scan_root == cli_base && d.source_path.starts_with(&cli_base))
        );
        assert_discovery_covers_scan_sources(&AntigravityConnector::new(), &ctx);
    }

    #[test]
    fn missing_ide_store_is_skipped_and_cli_store_still_indexed() {
        let tmp = TempDir::new().unwrap();
        let dot_gemini = tmp.path().join(".gemini");
        let ide_base = dot_gemini.join("antigravity"); // never created
        let cli_base = dot_gemini.join("antigravity-cli");
        write_conversation(&cli_base, SHARED_UUID, "cli only");

        let ctx = ScanContext::with_roots(
            tmp.path().to_path_buf(),
            vec![ScanRoot::local(ide_base), ScanRoot::local(cli_base)],
            None,
        );
        let convs = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some(SHARED_UUID));
        assert_eq!(convs[0].metadata["layout"], "cli");
    }

    #[test]
    fn scan_rooted_at_shared_dot_gemini_finds_both_stores_once() {
        // A remote mirror may root the scan one level up, at `.gemini` itself.
        // Both stores are found, each exactly once.
        let tmp = TempDir::new().unwrap();
        let dot_gemini = tmp.path().join(".gemini");
        write_conversation(
            &dot_gemini.join("antigravity"),
            "11111111-1111-4111-8111-111111111111",
            "ide",
        );
        write_conversation(
            &dot_gemini.join("antigravity-cli"),
            "22222222-2222-4222-8222-222222222222",
            "cli",
        );

        let ctx =
            ScanContext::with_roots(dot_gemini.clone(), vec![ScanRoot::local(dot_gemini)], None);
        let mut ids: Vec<String> = AntigravityConnector::new()
            .scan(&ctx)
            .unwrap()
            .into_iter()
            .filter_map(|c| c.external_id)
            .collect();
        ids.sort();
        assert_eq!(
            ids,
            vec![
                "22222222-2222-4222-8222-222222222222".to_string(),
                "ide/11111111-1111-4111-8111-111111111111".to_string(),
            ]
        );
    }

    #[test]
    fn unclassified_fixture_base_keeps_bare_uuid_and_records_data_root() {
        let conv = only_conversation();
        assert_eq!(conv.external_id.as_deref(), Some(FIXTURE_UUID));
        assert!(
            conv.metadata.get("layout").is_none(),
            "a base outside .gemini/ must not be guessed as IDE or CLI"
        );
        assert_eq!(
            conv.metadata["data_root"],
            fixture_base().to_string_lossy().as_ref()
        );
    }

    #[test]
    fn antigravity_mid_read_io_error_discards_incomplete_transcript_and_skips_corrupt_utf8() {
        use std::io::{self, BufReader, Cursor, Read};

        struct FailingReader(io::ErrorKind);
        impl Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(self.0, "simulated mid-read failure"))
            }
        }

        let prefix = "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"<USER_REQUEST>complete prefix</USER_REQUEST>\"}\n";
        for kind in [
            io::ErrorKind::Other,
            io::ErrorKind::InvalidData,
            io::ErrorKind::Interrupted,
        ] {
            let reader = BufReader::new(prefix.as_bytes().chain(FailingReader(kind)));
            assert!(
                AntigravityConnector::read_transcript_records_from(
                    Path::new("transcript.jsonl"),
                    reader
                )
                .is_err(),
                "mid-stream {kind:?} must discard incomplete Antigravity transcript"
            );
        }

        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            b"\xef\xbb\xbf{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"content\":\"<USER_REQUEST>first valid</USER_REQUEST>\"}\n",
        );
        bytes.extend_from_slice(b"{\"step_index\":1,\"content\":\"\xffcorrupt\"}\n");
        bytes.extend_from_slice(
            b"{\"step_index\":2,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"content\":\"second valid\"}\n",
        );
        let records = AntigravityConnector::read_transcript_records_from(
            Path::new("transcript.jsonl"),
            Cursor::new(bytes),
        )
        .expect("corrupt UTF-8 line should be skipped");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["step_index"], 0);
        assert_eq!(records[1]["step_index"], 2);
    }

    #[test]
    fn planner_response_keeps_usage_model_and_tool_calls_without_text() {
        let tmp = TempDir::new().unwrap();
        let uuid = "11111111-2222-4333-8444-555555555555";
        let conv_dir = tmp.path().join("brain").join(uuid);
        let logs = conv_dir.join(".system_generated").join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(
            logs.join("transcript.jsonl"),
            concat!(
                "{\"step_index\":0,\"source\":\"USER_EXPLICIT\",\"type\":\"USER_INPUT\",\"status\":\"DONE\",\"created_at\":\"2026-11-23T14:57:40Z\",\"content\":\"<USER_REQUEST>\\ncheck status\\n</USER_REQUEST>\\n<USER_SETTINGS_CHANGE>\\nThe user changed setting `Model Selection` from None to Gemini 4 Neon (High).\\n</USER_SETTINGS_CHANGE>\"}\n",
                "{\"step_index\":1,\"source\":\"MODEL\",\"type\":\"PLANNER_RESPONSE\",\"status\":\"DONE\",\"created_at\":\"2026-11-23T14:57:41Z\",\"model\":\"gemini-4-neon-high\",\"input_tokens\":2517,\"cache_read_tokens\":12725,\"output_tokens\":717,\"tool_calls\":[{\"name\":\"read_file\",\"args\":{\"Path\":\"/tmp/a.rs\"}}]}\n",
                "{\"step_index\":2,\"source\":\"SYSTEM\",\"type\":\"CHECKPOINT\",\"status\":\"DONE\",\"created_at\":\"2026-11-23T14:58:00Z\",\"input_tokens\":6982,\"cache_read_tokens\":508361,\"output_tokens\":5673,\"content\":\"compacted\"}\n"
            ),
        )
        .unwrap();

        let ctx = ScanContext::with_roots(
            tmp.path().to_path_buf(),
            vec![ScanRoot::local(tmp.path().to_path_buf())],
            None,
        );
        let convs = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        let conv = &convs[0];
        assert_eq!(conv.metadata["model"], "gemini-4-neon-high");
        assert_eq!(conv.messages.len(), 3);

        let planner = &conv.messages[1];
        assert_eq!(planner.role, "assistant");
        assert_eq!(planner.extra["model"], "gemini-4-neon-high");
        assert_eq!(planner.extra["usage"]["input_tokens"], 2517);
        assert_eq!(planner.extra["usage"]["cache_read_tokens"], 12725);
        assert_eq!(planner.extra["usage"]["output_tokens"], 717);
        assert_eq!(planner.invocations.len(), 1);
        assert_eq!(planner.invocations[0].name, "read_file");

        let checkpoint = &conv.messages[2];
        assert_eq!(checkpoint.role, "system");
        assert_eq!(checkpoint.extra["agy_type"], "CHECKPOINT");
        assert_eq!(checkpoint.extra["usage"]["input_tokens"], 6982);
        assert_eq!(checkpoint.extra["usage"]["cache_read_tokens"], 508_361);
        assert_eq!(checkpoint.extra["usage"]["output_tokens"], 5673);
    }

    #[test]
    fn annotation_pbtxt_sets_title_and_system_message_sets_parent() {
        let tmp = TempDir::new().unwrap();
        let uuid = "22222222-3333-4444-8555-666666666666";
        let parent_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let conv_dir = tmp.path().join("brain").join(uuid);
        let logs = conv_dir.join(".system_generated").join("logs");
        let annotations = tmp.path().join("annotations");
        fs::create_dir_all(&logs).unwrap();
        fs::create_dir_all(&annotations).unwrap();
        fs::write(
            annotations.join(format!("{uuid}.pbtxt")),
            "title:\"Fix \\\"Quoted\\\" Title\"\n",
        )
        .unwrap();
        fs::write(
            logs.join("transcript.jsonl"),
            format!(
                "{{\"step_index\":0,\"source\":\"SYSTEM\",\"type\":\"SYSTEM_MESSAGE\",\"status\":\"DONE\",\"created_at\":\"2026-11-23T11:40:54Z\",\"content\":\"The following is a <SYSTEM_MESSAGE>\\n\\n<SYSTEM_MESSAGE>\\n[Message] timestamp=2026-11-23T11:40:54Z sender={parent_uuid} priority=MESSAGE_PRIORITY_HIGH content=Do work\"}}\n"
            ),
        )
        .unwrap();

        let ctx = ScanContext::with_roots(
            tmp.path().to_path_buf(),
            vec![ScanRoot::local(tmp.path().to_path_buf())],
            None,
        );
        let convs = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].title.as_deref(), Some("Fix \"Quoted\" Title"));
        assert_eq!(
            convs[0].metadata["parent_conversation_id"].as_str(),
            Some(parent_uuid)
        );
    }

    #[cfg(any(
        feature = "antigravity-sqlite",
        feature = "zcode",
        feature = "cursor",
        feature = "opencode",
        feature = "goose",
        feature = "hermes",
        feature = "crush",
        feature = "devin",
        feature = "shelley",
        feature = "openclaw-sqlite",
        feature = "copilot-vscdb",
        feature = "pi-sqlite",
        feature = "pi-durable"
    ))]
    #[test]
    fn conversation_summaries_db_provides_workspace_title_and_parent() {
        let tmp = TempDir::new().unwrap();
        let uuid = "33333333-4444-4555-8666-777777777777";
        let parent_uuid = "99999999-8888-4777-8666-555555555555";
        write_conversation(tmp.path(), uuid, "hello");

        let db_path = tmp.path().join("conversation_summaries.db");
        use crate::connectors::sqlite_sync::{Connection, ConnectionExt};
        let conn = Connection::open(db_path.to_str().unwrap()).unwrap();
        conn.execute_batch(
            "CREATE TABLE conversation_summaries (
                conversation_id TEXT PRIMARY KEY,
                title TEXT NOT NULL DEFAULT '',
                workspace_uris TEXT NOT NULL,
                parent_conversation_id TEXT NOT NULL DEFAULT ''
            );",
        )
        .unwrap();
        conn.execute_compat(
            "INSERT INTO conversation_summaries (conversation_id, title, workspace_uris, parent_conversation_id) VALUES (?1, ?2, ?3, ?4)",
            frankensqlite::params![
                uuid,
                "Heatmap Investigation",
                "[\"file:///home/yeowool/my%20heatmap\"]",
                parent_uuid,
            ],
        )
        .unwrap();
        drop(conn);

        let ctx = ScanContext::with_roots(
            tmp.path().to_path_buf(),
            vec![ScanRoot::local(tmp.path().to_path_buf())],
            None,
        );
        let convs = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(
            convs[0].workspace.as_deref(),
            Some(Path::new("/home/yeowool/my heatmap"))
        );
        assert_eq!(convs[0].title.as_deref(), Some("Heatmap Investigation"));
        assert_eq!(
            convs[0].metadata["parent_conversation_id"].as_str(),
            Some(parent_uuid)
        );
    }

    #[test]
    fn discovery_includes_annotations_and_deduplicates_summaries_db() {
        let tmp = TempDir::new().unwrap();
        let uuid_a = "44444444-1111-4222-8333-555555555555";
        let uuid_b = "55555555-1111-4222-8333-666666666666";
        write_conversation(tmp.path(), uuid_a, "first");
        write_conversation(tmp.path(), uuid_b, "second");

        let annotations = tmp.path().join("annotations");
        fs::create_dir_all(&annotations).unwrap();
        let ann_a = annotations.join(format!("{uuid_a}.pbtxt"));
        fs::write(&ann_a, "title:\"First\"\n").unwrap();
        let summaries_db = tmp.path().join("conversation_summaries.db");
        fs::write(&summaries_db, b"").unwrap();
        let summaries_wal = tmp.path().join("conversation_summaries.db-wal");
        fs::write(&summaries_wal, b"").unwrap();

        let ctx = ScanContext::with_roots(
            tmp.path().to_path_buf(),
            vec![ScanRoot::local(tmp.path().to_path_buf())],
            None,
        );
        let discovered = AntigravityConnector::new()
            .discover_source_files(&ctx)
            .unwrap();
        assert!(discovered.iter().any(|d| {
            d.source_path == ann_a
                && d.role == DiscoveredSourceRole::MetadataSidecar
                && !d.required_for_reconstruction
        }));
        let summary_hits: Vec<_> = discovered
            .iter()
            .filter(|d| d.source_path == summaries_db)
            .collect();
        assert_eq!(summary_hits.len(), 1);
        assert_eq!(summary_hits[0].role, DiscoveredSourceRole::SqliteDatabase);
        assert!(!summary_hits[0].required_for_reconstruction);
        let wal_hits: Vec<_> = discovered
            .iter()
            .filter(|d| d.source_path == summaries_wal)
            .collect();
        assert_eq!(wal_hits.len(), 1);
        assert_eq!(wal_hits[0].role, DiscoveredSourceRole::MetadataSidecar);
        assert!(!wal_hits[0].required_for_reconstruction);
    }

    #[test]
    fn parse_pbtxt_string_decodes_octal_and_hex_utf8_and_rejects_unknown() {
        assert_eq!(
            parse_pbtxt_string(r#""caf\303\251""#).as_deref(),
            Some("café")
        );
        assert_eq!(
            parse_pbtxt_string(r#""caf\xc3\xa9""#).as_deref(),
            Some("café")
        );
        assert_eq!(parse_pbtxt_string(r#""bad\qescape""#), None);
        assert_eq!(parse_pbtxt_string(r#""bad\777""#), None);
    }

    #[test]
    fn modified_annotation_triggers_incremental_scan() {
        let tmp = TempDir::new().unwrap();
        let uuid = "66666666-1111-4222-8333-777777777777";
        let conv_dir = write_conversation(tmp.path(), uuid, "old prompt");
        let transcript = AntigravityConnector::transcript_path(&conv_dir);
        let transcript_mtime = fs::metadata(&transcript)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let since_ts = i64::try_from(transcript_mtime).unwrap() + 5_000;

        let ctx = ScanContext::with_roots(
            tmp.path().to_path_buf(),
            vec![ScanRoot::local(tmp.path().to_path_buf())],
            Some(since_ts),
        );
        assert!(AntigravityConnector::new().scan(&ctx).unwrap().is_empty());

        let annotations = tmp.path().join("annotations");
        fs::create_dir_all(&annotations).unwrap();
        let ann_path = annotations.join(format!("{uuid}.pbtxt"));
        fs::write(&ann_path, "title:\"Renamed\"\n").unwrap();
        let future = std::time::UNIX_EPOCH
            + std::time::Duration::from_millis(u64::try_from(since_ts + 5_000).unwrap());
        fs::OpenOptions::new()
            .write(true)
            .open(&ann_path)
            .unwrap()
            .set_modified(future)
            .unwrap();

        let convs = AntigravityConnector::new().scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].title.as_deref(), Some("Renamed"));
    }

    #[test]
    fn parent_fallback_requires_the_initial_system_step() {
        let mut record = serde_json::json!({
            "step_index": 0,
            "source": "SYSTEM",
            "type": "SYSTEM_MESSAGE",
            "content": "[Message] sender=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee content=Work"
        });
        assert_eq!(
            detect_parent_from_records(&[&record]).as_deref(),
            Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        );
        record["step_index"] = Value::from(12);
        assert_eq!(detect_parent_from_records(&[&record]), None);
    }

    #[test]
    fn planner_calls_keep_skill_normalization_and_tool_identity() {
        let message = record_to_message(&serde_json::json!({
            "type": "PLANNER_RESPONSE",
            "source": "MODEL",
            "tool_calls": [
                {"id": "skill-1", "name": "skill", "args": {"name": "code-review"}},
                {"call_id": "read-1", "function": {"name": "read_file", "arguments": "{\"path\":\"src/lib.rs\"}"}}
            ]
        }))
        .unwrap();
        assert_eq!(message.extra["cass"]["tool_call_count"], 2);
        let skill = &message.invocations[0];
        assert_eq!(skill.kind, "skill");
        assert_eq!(skill.name, "code-review");
        assert_eq!(skill.raw_name.as_deref(), Some("skill"));
        assert_eq!(skill.call_id.as_deref(), Some("skill-1"));
        let tool = &message.invocations[1];
        assert_eq!(tool.name, "read_file");
        assert_eq!(tool.call_id.as_deref(), Some("read-1"));
        assert_eq!(tool.arguments.as_ref().unwrap()["path"], "src/lib.rs");
    }

    #[cfg(any(
        feature = "antigravity-sqlite",
        feature = "zcode",
        feature = "cursor",
        feature = "opencode",
        feature = "goose",
        feature = "hermes",
        feature = "crush",
        feature = "devin",
        feature = "shelley",
        feature = "openclaw-sqlite",
        feature = "copilot-vscdb",
        feature = "pi-sqlite",
        feature = "pi-durable"
    ))]
    mod summaries {
        use super::*;
        use crate::connectors::sqlite_sync::{Connection, ConnectionExt};
        use frankensqlite::compat::RowExt;

        fn open_summary(base: &Path, wal: bool) -> Connection {
            let db_path = base.join("conversation_summaries.db");
            let conn = Connection::open(db_path.to_str().unwrap()).unwrap();
            if wal {
                let mode: String = conn
                    .query_row_map("PRAGMA journal_mode=wal;", &[], |row| row.get_typed(0))
                    .unwrap();
                assert_eq!(mode.to_ascii_lowercase(), "wal");
            }
            conn.execute(
                "CREATE TABLE conversation_summaries (
                    conversation_id TEXT PRIMARY KEY,
                    title TEXT,
                    workspace_uris TEXT,
                    parent_conversation_id TEXT
                )",
            )
            .unwrap();
            conn
        }

        #[test]
        fn nullable_fields_preserve_independent_summary_metadata() {
            let tmp = TempDir::new().unwrap();
            let conn = open_summary(tmp.path(), false);
            conn.execute_compat(
                "INSERT INTO conversation_summaries VALUES (?1, NULL, ?2, NULL)",
                frankensqlite::params!["workspace-only", "[\"file:///tmp/my%20project\"]"],
            )
            .unwrap();
            conn.execute_compat(
                "INSERT INTO conversation_summaries VALUES (?1, ?2, NULL, ?3)",
                frankensqlite::params!["title-parent", " Summary title ", " parent-id "],
            )
            .unwrap();
            drop(conn);

            let workspace = summary_metadata(tmp.path(), "workspace-only", &[]);
            assert_eq!(
                workspace.workspace.as_deref(),
                Some(Path::new("/tmp/my project"))
            );
            assert!(workspace.title.is_none());
            assert!(workspace.parent_conversation_id.is_none());
            let titled = summary_metadata(tmp.path(), "title-parent", &[]);
            assert!(titled.workspace.is_none());
            assert_eq!(titled.title.as_deref(), Some("Summary title"));
            assert_eq!(titled.parent_conversation_id.as_deref(), Some("parent-id"));
        }

        #[test]
        fn live_wal_metadata_is_read_without_changing_source_files() {
            let tmp = TempDir::new().unwrap();
            let uuid = "77777777-1111-4222-8333-888888888888";
            let conversation_dir = write_conversation(tmp.path(), uuid, "prompt title");
            let conn = open_summary(tmp.path(), true);
            conn.execute_compat(
                "INSERT INTO conversation_summaries VALUES (?1, 'Initial', ?2, NULL)",
                frankensqlite::params![uuid, "[\"file:///tmp/my%20project\"]"],
            )
            .unwrap();
            let db_path = tmp.path().join("conversation_summaries.db");
            let wal_path = db_path.with_extension("db-wal");
            let before_db = fs::read(&db_path).unwrap();
            conn.execute_compat(
                "UPDATE conversation_summaries SET title = 'Updated in WAL' WHERE conversation_id = ?1",
                frankensqlite::params![uuid],
            )
            .unwrap();
            assert_eq!(fs::read(&db_path).unwrap(), before_db);
            let before_wal = fs::read(&wal_path).unwrap();
            assert!(!before_wal.is_empty());

            // Only the WAL is newer than the incremental watermark.
            for path in [
                &db_path,
                &AntigravityConnector::transcript_path(&conversation_dir),
            ] {
                fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(100))
                    .unwrap();
            }
            let ctx = ScanContext::with_roots(
                tmp.path().to_path_buf(),
                vec![ScanRoot::local(tmp.path().to_path_buf())],
                Some(200_000),
            );
            let conversations = AntigravityConnector::new().scan(&ctx).unwrap();
            assert_eq!(conversations.len(), 1);
            assert_eq!(conversations[0].title.as_deref(), Some("Updated in WAL"));
            assert_eq!(
                conversations[0].workspace.as_deref(),
                Some(Path::new("/tmp/my project"))
            );
            assert_eq!(fs::read(&db_path).unwrap(), before_db);
            assert_eq!(fs::read(&wal_path).unwrap(), before_wal);
        }

        #[test]
        fn workspace_uris_preserve_authorities_and_validate_escapes() {
            for (uri, expected) in [
                ("file:///tmp/caf%C3%A9", "/tmp/café"),
                ("file://localhost/tmp/my%20project", "/tmp/my project"),
                (
                    "file://server/share/my%20project",
                    "//server/share/my project",
                ),
            ] {
                assert_eq!(
                    parse_workspace_uri(uri).as_deref(),
                    Some(Path::new(expected))
                );
            }
            for uri in [
                "",
                "relative/path",
                "file://relative",
                "file:///bad%",
                "file:///bad%ff",
                "file:///bad%00",
            ] {
                assert_eq!(parse_workspace_uri(uri), None, "{uri}");
            }
        }
    }
}
