use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::{excluded_scan_paths_from_env, path_is_excluded, read_capped};
use super::{
    Connector, extract_invocations_from_content_blocks, file_modified_since, flatten_content,
    franken_detection_for_connector, parse_timestamp, unwrap_skill_invocations,
    utils::dedupe_path_key,
};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct ClineConnector;
impl Default for ClineConnector {
    fn default() -> Self {
        Self::new()
    }
}

const CLINE_EXTENSIONS: [&str; 2] = ["saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline"];

const LEGACY_RESUME_WARNING: &str = "Warning: this is a legacy conversation, which means tool names may have changed. Please use the most up-to-date tools you are aware of.";

struct ClineSource {
    root: ScanRoot,
    primary: DiscoveredSourceFile,
    metadata: Option<DiscoveredSourceFile>,
    legacy: Option<Box<Self>>,
    sdk: bool,
    migrated: bool,
}

impl ClineSource {
    fn changed_since(&self, since: Option<i64>) -> bool {
        file_modified_since(&self.primary.source_path, since)
            || (self.sdk
                && self
                    .metadata
                    .as_ref()
                    .is_some_and(|metadata| file_modified_since(&metadata.source_path, since)))
            || self
                .legacy
                .as_ref()
                .is_some_and(|legacy| legacy.changed_since(since))
    }

    fn into_discovered(self, out: &mut Vec<DiscoveredSourceFile>) {
        out.push(self.primary);
        out.extend(self.metadata);
        if let Some(mut legacy) = self.legacy {
            // A migrated SDK history uses the original UI transcript before
            // its resume boundary. It must be mirrored even when unchanged.
            legacy.primary.role = DiscoveredSourceRole::MetadataSidecar;
            legacy.primary.required_for_reconstruction = true;
            legacy.into_discovered(out);
        }
    }
}

impl ClineConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn candidate_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        if let Some(sdk_root) = crate::cline_sdk_sessions_root() {
            roots.push(sdk_root);
        }
        let Some(base) = dirs::home_dir() else {
            return roots;
        };

        let code_roots = [
            base.join(".config/Code/User/globalStorage"),
            base.join(".config/Code - Insiders/User/globalStorage"),
            base.join(".config/VSCodium/User/globalStorage"),
            base.join("Library/Application Support/Code/User/globalStorage"),
            base.join("Library/Application Support/Code - Insiders/User/globalStorage"),
            base.join("Library/Application Support/VSCodium/User/globalStorage"),
            base.join("AppData/Roaming/Code/User/globalStorage"),
            base.join("AppData/Roaming/Code - Insiders/User/globalStorage"),
            base.join("AppData/Roaming/VSCodium/User/globalStorage"),
        ];
        let cursor_roots = [
            base.join(".config/Cursor/User/globalStorage"),
            base.join("Library/Application Support/Cursor/User/globalStorage"),
            base.join("AppData/Roaming/Cursor/User/globalStorage"),
        ];
        for root in code_roots.iter().chain(cursor_roots.iter()) {
            for ext in &CLINE_EXTENSIONS {
                roots.push(root.join(ext));
            }
        }

        roots
    }

    fn storage_roots() -> Vec<PathBuf> {
        Self::candidate_roots()
            .into_iter()
            .filter(|r| r.exists())
            .collect()
    }

    fn normalize_root_path(path: &std::path::Path) -> PathBuf {
        if path
            .file_name()
            .is_some_and(|n| n == "settings" || n == "settings.json")
        {
            path.parent().unwrap_or(path).to_path_buf()
        } else {
            path.to_path_buf()
        }
    }

    fn append_explicit_roots(roots: &mut Vec<PathBuf>, base: &Path) {
        let base = Self::normalize_root_path(base);
        if Self::is_sdk_scope(&base) || Self::looks_like_storage(&base) {
            // A provider store, tasks directory, task or exact transcript is
            // already a complete scope. Do not widen it to adjacent stores.
            roots.push(base);
            return;
        }
        // SDK stores are independent of the VS Code extension stores. A
        // supplied home can contain both generations; discover both without
        // consulting environment overrides outside the supplied scope.
        for candidate in [
            base.clone(),
            base.join("sessions"),
            base.join("data/sessions"),
            base.join(".cline/data/sessions"),
        ] {
            if Self::contains_sdk_sessions(&candidate) {
                roots.push(candidate);
            }
        }
        if base.join(".cline").is_dir() {
            roots.push(base.join(".cline/data/sessions"));
        }
        let file_name = base.file_name().and_then(|n| n.to_str());
        let is_config = file_name.is_some_and(|n| n == ".config");
        let is_app_support = file_name.is_some_and(|n| n == "Application Support");
        let is_appdata_roaming = file_name.is_some_and(|n| n == "Roaming")
            && base
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "AppData"));
        let is_code_variant = file_name
            .is_some_and(|n| matches!(n, "Code" | "Code - Insiders" | "VSCodium" | "Cursor"));
        let is_user = file_name.is_some_and(|n| n == "User");
        let is_global_storage = file_name.is_some_and(|n| n == "globalStorage");

        let mut storage_roots: Vec<PathBuf> = Vec::new();

        if is_global_storage {
            storage_roots.push(base.clone());
        }

        if is_config {
            storage_roots.push(base.join("Code/User/globalStorage"));
            storage_roots.push(base.join("Code - Insiders/User/globalStorage"));
            storage_roots.push(base.join("VSCodium/User/globalStorage"));
            storage_roots.push(base.join("Cursor/User/globalStorage"));
        }

        if is_app_support {
            storage_roots.push(base.join("Code/User/globalStorage"));
            storage_roots.push(base.join("Code - Insiders/User/globalStorage"));
            storage_roots.push(base.join("VSCodium/User/globalStorage"));
            storage_roots.push(base.join("Cursor/User/globalStorage"));
        }

        if is_appdata_roaming {
            storage_roots.push(base.join("Code/User/globalStorage"));
            storage_roots.push(base.join("Code - Insiders/User/globalStorage"));
            storage_roots.push(base.join("VSCodium/User/globalStorage"));
            storage_roots.push(base.join("Cursor/User/globalStorage"));
        }

        if is_code_variant {
            storage_roots.push(base.join("User/globalStorage"));
        }

        if is_user {
            storage_roots.push(base.join("globalStorage"));
        }

        if !(is_config
            || is_app_support
            || is_appdata_roaming
            || is_code_variant
            || is_user
            || is_global_storage)
        {
            storage_roots.push(base.join(".config/Code/User/globalStorage"));
            storage_roots.push(base.join(".config/Code - Insiders/User/globalStorage"));
            storage_roots.push(base.join(".config/VSCodium/User/globalStorage"));
            storage_roots.push(base.join(".config/Cursor/User/globalStorage"));
            storage_roots.push(base.join("Library/Application Support/Code/User/globalStorage"));
            storage_roots
                .push(base.join("Library/Application Support/Code - Insiders/User/globalStorage"));
            storage_roots
                .push(base.join("Library/Application Support/VSCodium/User/globalStorage"));
            storage_roots.push(base.join("Library/Application Support/Cursor/User/globalStorage"));
            storage_roots.push(base.join("AppData/Roaming/Code/User/globalStorage"));
            storage_roots.push(base.join("AppData/Roaming/Code - Insiders/User/globalStorage"));
            storage_roots.push(base.join("AppData/Roaming/VSCodium/User/globalStorage"));
            storage_roots.push(base.join("AppData/Roaming/Cursor/User/globalStorage"));
        }

        for root in storage_roots {
            for ext in &CLINE_EXTENSIONS {
                let candidate = root.join(ext);
                if candidate.exists() && Self::looks_like_storage(&candidate) {
                    roots.push(candidate);
                }
            }
        }
    }

    fn is_message_path(path: &Path) -> bool {
        path.file_name().is_some_and(|name| {
            name == "ui_messages.json" || name == "api_conversation_history.json"
        })
    }

    fn sdk_message_id(path: &Path) -> Option<&str> {
        path.file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".messages.json"))
            .filter(|id| !id.is_empty())
    }

    fn sdk_manifest_path(path: &Path) -> Option<PathBuf> {
        Self::sdk_message_id(path).map(|id| path.with_file_name(format!("{id}.json")))
    }

    fn sdk_task_source(directory: &Path) -> Option<PathBuf> {
        let id = directory.file_name()?.to_str()?;
        let file = directory.join(format!("{id}.messages.json"));
        (file.is_file() && directory.join(format!("{id}.json")).is_file()).then_some(file)
    }

    fn contains_sdk_sessions(path: &Path) -> bool {
        Self::sdk_task_source(path).is_some()
            || fs::read_dir(path).is_ok_and(|mut entries| {
                entries.any(|entry| {
                    entry.is_ok_and(|entry| Self::sdk_task_source(&entry.path()).is_some())
                })
            })
    }

    fn sdk_manifest_source(path: &Path) -> Option<PathBuf> {
        let id = path.file_name()?.to_str()?.strip_suffix(".json")?;
        let source = path.with_file_name(format!("{id}.messages.json"));
        (path.is_file() && source.is_file()).then_some(source)
    }

    fn is_sdk_scope(path: &Path) -> bool {
        let name = path.file_name().and_then(|name| name.to_str());
        let parent = path.parent().and_then(|parent| parent.file_name());
        Self::sdk_message_id(path).is_some()
            || Self::sdk_manifest_source(path).is_some()
            || Self::sdk_task_source(path).is_some()
            || name == Some(".cline")
            || (name == Some("data") && parent.is_some_and(|name| name == ".cline"))
            || (name == Some("sessions")
                && parent.is_some_and(|name| name == "data" || name == ".cline"))
            || parent.is_some_and(|name| name == "sessions")
            || path
                .parent()
                .and_then(Path::parent)
                .is_some_and(|parent| parent.file_name().is_some_and(|name| name == "sessions"))
            || (path
                .extension()
                .is_some_and(|extension| extension == "json")
                && path.file_stem().is_some_and(|stem| Some(stem) == parent))
    }

    fn sdk_source_files(root: &Path) -> Vec<PathBuf> {
        if Self::sdk_message_id(root).is_some() {
            return (root.is_file()
                && Self::sdk_manifest_path(root).is_some_and(|path| path.is_file()))
            .then(|| root.to_path_buf())
            .into_iter()
            .collect();
        }
        if let Some(source) = Self::sdk_manifest_source(root) {
            return vec![source];
        }
        if let Some(source) = Self::sdk_task_source(root) {
            return vec![source];
        }
        let mut files = Vec::new();
        for directory in [
            root.to_path_buf(),
            root.join("sessions"),
            root.join("data/sessions"),
        ] {
            let Ok(entries) = fs::read_dir(directory) else {
                continue;
            };
            for entry in entries.flatten() {
                if let Some(source) = Self::sdk_task_source(&entry.path()) {
                    files.push(source);
                }
            }
        }
        files.sort();
        files.dedup();
        files
    }

    fn task_source(task_dir: &Path) -> Option<PathBuf> {
        if task_dir
            .file_name()
            .is_some_and(|name| name == "taskHistory.json")
        {
            return None;
        }
        // UI history is the user-facing transcript. Keep API history as the
        // fallback only when that file is absent, as in the original adapter.
        ["ui_messages.json", "api_conversation_history.json"]
            .into_iter()
            .map(|name| task_dir.join(name))
            .find(|path| path.is_file())
    }

    fn looks_like_storage(path: &Path) -> bool {
        if Self::is_message_path(path)
            || path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                n.contains("claude-dev") || n.contains("roo-cline") || n == "tasks"
            })
            || path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "tasks"))
            || Self::task_source(path).is_some()
            || Self::contains_task_sources(&path.join("tasks"))
        {
            return true;
        }

        Self::contains_task_sources(path)
    }

    fn contains_task_sources(path: &Path) -> bool {
        fs::read_dir(path).is_ok_and(|mut entries| {
            entries.any(|entry| {
                entry.is_ok_and(|entry| {
                    let path = entry.path();
                    path.is_dir() && Self::task_source(&path).is_some()
                })
            })
        })
    }

    fn is_storage_container(path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                matches!(
                    name,
                    ".config"
                        | "Application Support"
                        | "Code"
                        | "Code - Insiders"
                        | "VSCodium"
                        | "Cursor"
                        | "User"
                        | "globalStorage"
                ) || (name == "Roaming"
                    && path
                        .parent()
                        .is_some_and(|parent| parent.file_name().is_some_and(|n| n == "AppData")))
            })
    }

    fn source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let override_root = Self::normalize_root_path(&ctx.data_dir);
        let mut roots: Vec<ScanRoot> = if ctx.use_default_detection() {
            // A data_dir that names an extension dir scopes directly; a
            // data_dir that is a VS Code base (globalStorage, User,
            // Code variant, platform root) derives its ext dirs via the
            // same expansion explicit roots get, so a mirrored base is
            // not silently ignored in favor of the live machine.
            let mut derived = Vec::new();
            Self::append_explicit_roots(&mut derived, &override_root);
            if !derived.is_empty() {
                derived.into_iter().map(ScanRoot::local).collect()
            } else if Self::is_storage_container(&override_root) {
                // A missing or empty selected VS Code store must not read
                // unrelated live histories from the current machine.
                Vec::new()
            } else {
                Self::storage_roots()
                    .into_iter()
                    .map(ScanRoot::local)
                    .collect()
            }
        } else {
            let mut explicit = Vec::new();
            for root in &ctx.scan_roots {
                let mut paths = Vec::new();
                for store in [
                    &[".cline", "data", "sessions"][..],
                    &[".config", "Code", "User", "globalStorage"][..],
                    &[".config", "Code - Insiders", "User", "globalStorage"][..],
                    &[".config", "VSCodium", "User", "globalStorage"][..],
                    &[".config", "Cursor", "User", "globalStorage"][..],
                    &[
                        "Library",
                        "Application Support",
                        "Code",
                        "User",
                        "globalStorage",
                    ][..],
                    &[
                        "Library",
                        "Application Support",
                        "Code - Insiders",
                        "User",
                        "globalStorage",
                    ][..],
                    &[
                        "Library",
                        "Application Support",
                        "VSCodium",
                        "User",
                        "globalStorage",
                    ][..],
                    &[
                        "Library",
                        "Application Support",
                        "Cursor",
                        "User",
                        "globalStorage",
                    ][..],
                    &["AppData", "Roaming", "Code", "User", "globalStorage"][..],
                    &[
                        "AppData",
                        "Roaming",
                        "Code - Insiders",
                        "User",
                        "globalStorage",
                    ][..],
                    &["AppData", "Roaming", "VSCodium", "User", "globalStorage"][..],
                    &["AppData", "Roaming", "Cursor", "User", "globalStorage"][..],
                ] {
                    if let Some(mirrored) = root.mirrored_store(store) {
                        Self::append_explicit_roots(&mut paths, &mirrored);
                    }
                }
                Self::append_explicit_roots(&mut paths, &root.path);
                explicit.extend(paths.into_iter().map(|path| root.with_path(path)));
            }
            explicit
        };

        roots.sort_by(|a, b| a.path.cmp(&b.path));
        roots.dedup_by(|a, b| a.path == b.path);
        roots
    }

    fn source_files(root: &Path) -> Vec<PathBuf> {
        // A copied task directory can itself have a transcript-like name.
        // Only a non-directory spelling selects an exact transcript file;
        // existing task directories still resolve their contained history.
        if Self::is_message_path(root) && !root.is_dir() {
            return root
                .is_file()
                .then(|| root.to_path_buf())
                .into_iter()
                .collect();
        }
        let mut files = Self::sdk_source_files(root);
        if Self::sdk_task_source(root).is_some() {
            return files;
        }
        if let Some(source) = Self::task_source(root) {
            return vec![source];
        }
        if Self::is_sdk_scope(root) {
            return files;
        }
        if root
            .parent()
            .is_some_and(|parent| parent.file_name().is_some_and(|name| name == "tasks"))
        {
            // A selected native task is terminal even if its transcript is
            // absent. Never replace it with a nested task or artifact.
            return Vec::new();
        }

        // Native Cline writes <globalStorage>/tasks/<id> (disk.ts,
        // ensureTaskDirectoryExists). Preserve direct <store>/<id> histories
        // too, without recursively reading arbitrary extension directories.
        for directory in [root.to_path_buf(), root.join("tasks")] {
            if !directory.is_dir() {
                continue;
            }
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(err) => {
                    tracing::debug!(path = %directory.display(), error = %err, "cline: skipping unreadable task directory");
                    continue;
                }
            };
            for entry in entries.flatten() {
                let task_dir = entry.path();
                if task_dir.is_dir()
                    && let Some(source) = Self::task_source(&task_dir)
                {
                    files.push(source);
                }
            }
        }
        files.sort();
        files.dedup();
        files
    }

    fn source_groups(ctx: &ScanContext) -> Result<Vec<ClineSource>> {
        let excluded_paths = excluded_scan_paths_from_env()?;
        let mut out = Vec::new();
        let mut seen_task_dirs = HashSet::new();
        for root in Self::source_roots(ctx) {
            if path_is_excluded(&root.path, &excluded_paths) {
                continue;
            }
            for file in Self::source_files(&root.path) {
                if path_is_excluded(&file, &excluded_paths) {
                    continue;
                }
                let Some(task_dir) = file.parent() else {
                    continue;
                };
                if path_is_excluded(task_dir, &excluded_paths) {
                    continue;
                }
                let sdk = Self::sdk_message_id(&file).is_some();
                // An ancestor of the selected store may be a symlink too.
                // Keep the original path/provenance in the source record,
                // but compare physical sources across overlapping roots. SDK
                // archives may hold several explicitly selected snapshots in
                // one directory; legacy UI/API files still represent one task.
                let identity = if sdk { file.as_path() } else { task_dir };
                let task_key =
                    fs::canonicalize(identity).unwrap_or_else(|_| dedupe_path_key(identity));
                if !seen_task_dirs.insert(task_key) {
                    continue;
                }
                let primary = DiscoveredSourceFile::new(
                    "cline",
                    &root,
                    file.clone(),
                    DiscoveredSourceRole::PrimarySessionLog,
                    true,
                )
                .with_fs_metadata();
                let meta_path = Self::sdk_manifest_path(&file)
                    .unwrap_or_else(|| task_dir.join("task_metadata.json"));
                if path_is_excluded(&meta_path, &excluded_paths) {
                    continue;
                }
                let migrated = sdk
                    && read_json(&meta_path).is_some_and(|manifest| {
                        manifest.get("version").and_then(Value::as_u64) == Some(1)
                            && manifest.get("session_id").and_then(Value::as_str)
                                == Self::sdk_message_id(&file)
                            && is_migrated_sdk(&manifest)
                    });
                let metadata = meta_path.is_file().then(|| {
                    DiscoveredSourceFile::new(
                        "cline",
                        &root,
                        meta_path,
                        DiscoveredSourceRole::MetadataSidecar,
                        sdk,
                    )
                    .with_fs_metadata()
                });
                out.push(ClineSource {
                    root: root.clone(),
                    primary,
                    metadata,
                    legacy: None,
                    sdk,
                    migrated,
                });
            }
        }
        Ok(Self::pair_migrated_sources(out)
            .into_iter()
            .filter(|source| source.changed_since(ctx.since_ts))
            .collect())
    }

    fn pair_migrated_sources(out: Vec<ClineSource>) -> Vec<ClineSource> {
        // Pair the two generations before applying incremental filtering.
        // Migration retains old cumulative usage in the SDK prefix and the
        // full historical UI in the old store; those are one conversation.
        let mut sources: Vec<Option<ClineSource>> = out.into_iter().map(Some).collect();
        for index in 0..sources.len() {
            let Some(sdk) = sources[index]
                .as_ref()
                .filter(|source| source.sdk && source.migrated)
            else {
                continue;
            };
            let id = Self::sdk_message_id(&sdk.primary.source_path);
            if sources
                .iter()
                .flatten()
                .filter(|candidate| {
                    candidate.sdk
                        && candidate.primary.origin == sdk.primary.origin
                        && Self::sdk_message_id(&candidate.primary.source_path) == id
                })
                .count()
                != 1
            {
                tracing::debug!(path = %sdk.primary.source_path.display(), "cline: ambiguous SDK migration roots; keeping independent sources");
                continue;
            }
            let matching: Vec<usize> = sources
                .iter()
                .enumerate()
                .filter_map(|(candidate_index, candidate)| {
                    let candidate = candidate.as_ref()?;
                    (!candidate.sdk
                        && candidate.primary.origin == sdk.primary.origin
                        && !candidate.primary.source_path.ancestors().any(|path| {
                            path.file_name()
                                .and_then(|name| name.to_str())
                                .is_some_and(|name| name.contains("roo-cline"))
                        })
                        && candidate
                            .primary
                            .source_path
                            .parent()
                            .and_then(|path| path.file_name())
                            .and_then(|name| name.to_str())
                            == id)
                        .then_some(candidate_index)
                })
                .collect();
            if let [legacy_index] = matching.as_slice() {
                let legacy = sources[*legacy_index].take().map(Box::new);
                if let Some(sdk) = sources[index].as_mut() {
                    sdk.legacy = legacy;
                }
            }
        }
        sources.into_iter().flatten().collect()
    }

    fn discover_sources(ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        let mut out = Vec::new();
        for source in Self::source_groups(ctx)? {
            source.into_discovered(&mut out);
        }
        Ok(out)
    }
}

impl Connector for ClineConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("cline").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        self.scan_with_callback(ctx, &mut |conv| {
            convs.push(conv);
            Ok(())
        })?;
        Ok(convs)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        for source in &Self::source_groups(ctx)? {
            ctx.tick();
            if let Some(mut conv) = parse_source_group(source) {
                source.root.apply_workspace_rewrite(&mut conv);
                on_conversation(conv)?;
            }
        }
        Ok(())
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Self::discover_sources(ctx)
    }
}

fn read_json(path: &Path) -> Option<Value> {
    let text = match read_capped(path) {
        Ok(Some(text)) => text,
        Ok(None) => {
            tracing::debug!(path = %path.display(), "cline: file exceeds the scan size cap; skipping");
            return None;
        }
        Err(error) => {
            tracing::debug!(path = %path.display(), %error, "cline: skipping unreadable file");
            return None;
        }
    };
    match serde_json::from_str(text.trim_start_matches('\u{feff}')) {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::debug!(path = %path.display(), %error, "cline: skipping malformed JSON");
            None
        }
    }
}

fn is_migrated_sdk(manifest: &Value) -> bool {
    manifest
        .pointer("/metadata/legacyTask")
        .and_then(Value::as_bool)
        == Some(true)
        || manifest
            .pointer("/metadata/migratedFromLegacyTask")
            .and_then(Value::as_bool)
            == Some(true)
}

fn parse_source_group(source: &ClineSource) -> Option<NormalizedConversation> {
    if !source.sdk {
        return parse_legacy_session(&source.primary.source_path);
    }
    let Some(mut sdk) = parse_sdk_session(&source.primary.source_path) else {
        // A partial/invalid SDK write must not hide the readable original.
        return source
            .legacy
            .as_ref()
            .and_then(|legacy| parse_legacy_session(&legacy.primary.source_path));
    };
    let Some(legacy_source) = source.legacy.as_ref() else {
        return Some(sdk);
    };
    if legacy_source
        .primary
        .source_path
        .file_name()
        .is_none_or(|name| name != "ui_messages.json")
    {
        // The SDK's migrated prefix already contains the API-history context
        // and cumulative legacy usage. Only the UI history supplies the full
        // transcript needed for Cline's own resume-boundary replacement.
        return Some(sdk);
    }
    let Some(legacy) = parse_legacy_session(&legacy_source.primary.source_path) else {
        return Some(sdk);
    };
    let Some(boundary) = sdk.messages.iter().position(|message| {
        message
            .extra
            .pointer("/cass/legacy_resume_marker")
            .and_then(Value::as_bool)
            == Some(true)
    }) else {
        tracing::debug!(path = %sdk.source_path.display(), "cline: migrated SDK snapshot lacks an unambiguous legacy resume boundary; keeping its saved snapshot");
        sdk.metadata["legacy_merge"] = Value::from("missing_resume_boundary");
        return Some(sdk);
    };
    let resumed = sdk.messages.split_off(boundary + 1);
    sdk.messages = legacy.messages;
    sdk.messages.extend(resumed);
    crate::types::reindex_messages(&mut sdk.messages);
    sdk.started_at = sdk
        .messages
        .iter()
        .filter_map(|message| message.created_at)
        .min();
    sdk.ended_at = sdk
        .messages
        .iter()
        .filter_map(|message| message.created_at)
        .max();
    sdk.metadata["legacy_merge"] = Value::from("ui_history");
    sdk.metadata["legacy_source_path"] =
        Value::from(legacy_source.primary.source_path.to_string_lossy().as_ref());
    Some(sdk)
}

fn nonblank_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
}

/// Read the canonical persisted SDK transcript, not its compacted model
/// context, database index, teammate output or runtime-generated projections.
/// Format: cline/cline c3a4057, core/services/session-{artifacts,data}.ts.
fn parse_sdk_session(file: &Path) -> Option<NormalizedConversation> {
    let session_id = ClineConnector::sdk_message_id(file)?;
    let manifest = read_json(&ClineConnector::sdk_manifest_path(file)?)?;
    let snapshot = read_json(file)?;
    let valid = manifest.get("version").and_then(Value::as_u64) == Some(1)
        && manifest.get("session_id").and_then(Value::as_str) == Some(session_id)
        && snapshot.get("version").and_then(Value::as_u64) == Some(1)
        && snapshot.get("agent").and_then(Value::as_str) == Some("lead")
        && snapshot.get("sessionId").and_then(Value::as_str) == Some(session_id)
        && snapshot
            .pointer("/origin/sessionId")
            .and_then(Value::as_str)
            == Some(session_id)
        && nonblank_string(snapshot.pointer("/origin/source")).is_some()
        && snapshot.pointer("/origin/source").and_then(Value::as_str)
            == manifest.get("source").and_then(Value::as_str);
    if !valid {
        tracing::debug!(path = %file.display(), "cline: skipping unsupported SDK version, agent kind or mismatched session identity");
        return None;
    }
    let records = snapshot.get("messages")?.as_array()?;
    let mut messages = Vec::new();
    for record in records {
        if let Some(message) = sdk_message(record, &manifest, session_id, messages.len()) {
            messages.push(message);
        }
    }
    if messages.is_empty() {
        return None;
    }
    // This is an ordered snapshot, not a stream of timestamped UI events.
    // Preserve its order even when missing/clock-skewed timestamps occur.
    let title = nonblank_string(manifest.pointer("/metadata/title"))
        .or_else(|| nonblank_string(manifest.get("prompt")))
        .map(String::from)
        .or_else(|| {
            messages
                .first()
                .and_then(|message| message.content.lines().next())
                .map(|line| line.chars().take(100).collect())
        });
    let workspace = nonblank_string(manifest.get("cwd"))
        .or_else(|| nonblank_string(manifest.get("workspace_root")))
        .map(PathBuf::from);
    Some(NormalizedConversation {
        agent_slug: "cline".into(),
        external_id: Some(session_id.into()),
        title,
        workspace,
        source_path: file.to_path_buf(),
        started_at: messages
            .iter()
            .filter_map(|message| message.created_at)
            .min()
            .or_else(|| manifest.get("started_at").and_then(parse_timestamp)),
        ended_at: messages
            .iter()
            .filter_map(|message| message.created_at)
            .max()
            .or_else(|| manifest.get("ended_at").and_then(parse_timestamp)),
        metadata: serde_json::json!({
            "source": "cline", "format": "cline_sdk_v1", "sdk_source": manifest["source"],
            "migrated_from_legacy": is_migrated_sdk(&manifest),
        }),
        messages,
    })
}

fn sdk_message(
    record: &Value,
    manifest: &Value,
    session_id: &str,
    index: usize,
) -> Option<NormalizedMessage> {
    let raw_role = record.get("role")?.as_str()?;
    if !matches!(raw_role, "user" | "assistant") {
        return None;
    }
    let blocks = record.get("content")?;
    if !(blocks.is_string() || blocks.is_array()) {
        return None;
    }
    let content = sdk_content(blocks);
    let has_metrics = record
        .get("metrics")
        .and_then(Value::as_object)
        .is_some_and(|metrics| {
            [
                "inputTokens",
                "outputTokens",
                "cacheReadTokens",
                "cacheWriteTokens",
            ]
            .iter()
            .any(|key| {
                metrics
                    .get(*key)
                    .and_then(Value::as_i64)
                    .is_some_and(|value| value >= 0)
            })
        });
    if content.trim().is_empty() && !(raw_role == "assistant" && has_metrics) {
        return None;
    }
    let role = if raw_role == "user"
        && blocks.as_array().is_some_and(|blocks| {
            !blocks.is_empty()
                && blocks
                    .iter()
                    .all(|block| block.get("type").and_then(Value::as_str) == Some("tool_result"))
        }) {
        "tool"
    } else {
        raw_role
    };
    let mut invocations = extract_invocations_from_content_blocks(blocks);
    unwrap_skill_invocations(&mut invocations);
    let mut extra = compact_sdk_extra(record, manifest, session_id, role, invocations.len());
    if raw_role == "user" && has_legacy_resume_warning(blocks) {
        extra["cass"]["legacy_resume_marker"] = Value::Bool(true);
    }
    Some(NormalizedMessage {
        idx: i64::try_from(index).unwrap_or(i64::MAX),
        role: role.into(),
        author: None,
        created_at: record.get("ts").and_then(parse_timestamp),
        content,
        extra,
        invocations,
        snippets: Vec::new(),
    })
}

fn has_legacy_resume_warning(content: &Value) -> bool {
    content
        .as_str()
        .is_some_and(|text| text.contains(LEGACY_RESUME_WARNING))
        || content.as_array().is_some_and(|blocks| {
            blocks.iter().any(|block| {
                block.get("type").and_then(Value::as_str) == Some("text")
                    && block
                        .get("text")
                        .and_then(Value::as_str)
                        .is_some_and(|text| text.contains(LEGACY_RESUME_WARNING))
            })
        })
}

fn compact_sdk_extra(
    record: &Value,
    manifest: &Value,
    session_id: &str,
    role: &str,
    tool_call_count: usize,
) -> Value {
    let mut cass = serde_json::json!({
        "cline_sdk": true, "role": role, "session_id": session_id,
        "tool_call_count": tool_call_count,
    });
    for (key, value) in [
        ("message_id", nonblank_string(record.get("id"))),
        ("session_id", nonblank_string(record.get("sessionId"))),
        ("agent", nonblank_string(record.get("agent"))),
        (
            "model",
            nonblank_string(record.pointer("/modelInfo/id"))
                .or_else(|| nonblank_string(manifest.get("model"))),
        ),
        (
            "provider",
            nonblank_string(record.pointer("/modelInfo/provider"))
                .or_else(|| nonblank_string(manifest.get("provider"))),
        ),
    ] {
        if let Some(value) = value {
            cass[key] = Value::from(value);
        }
    }
    if record
        .pointer("/metadata/displayOnly")
        .and_then(Value::as_bool)
        == Some(true)
    {
        cass["display_only"] = Value::Bool(true);
    }
    if let Some(metrics) = record.get("metrics") {
        let mut compact = serde_json::Map::new();
        for key in [
            "inputTokens",
            "outputTokens",
            "cacheReadTokens",
            "cacheWriteTokens",
        ] {
            if let Some(value) = metrics.get(key) {
                // Preserve invalid-present versus absent counters without
                // copying arbitrary strings, objects or provider payloads.
                compact.insert(
                    key.into(),
                    if value.is_number() {
                        value.clone()
                    } else {
                        Value::Null
                    },
                );
            }
        }
        cass["sdk_metrics"] = Value::Object(compact);
    }
    serde_json::json!({"cass": cass})
}

fn sdk_content(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_owned();
    }
    let Some(blocks) = value.as_array() else {
        return String::new();
    };
    let mut content = String::new();
    for block in blocks {
        let text = match block.get("type").and_then(Value::as_str) {
            Some("text") => block
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            Some("thinking") => block
                .get("thinking")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            Some("file") => block
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            Some("tool_use") => block
                .get("name")
                .and_then(Value::as_str)
                .map(|name| format!("[Tool: {name}]"))
                .unwrap_or_default(),
            Some("tool_result") => block.get("content").map(sdk_content).unwrap_or_default(),
            // Image/media/redacted-thinking bytes are not searchable text.
            _ => String::new(),
        };
        if !text.is_empty() {
            if !content.is_empty() {
                content.push('\n');
            }
            content.push_str(&text);
        }
    }
    content
}

#[allow(clippy::too_many_lines)]
fn parse_legacy_session(file: &Path) -> Option<NormalizedConversation> {
    let path = file.parent()?;
    let task_id = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(std::string::ToString::to_string);
    let meta_path = path.join("task_metadata.json");

    let val = read_json(file)?;

    let mut messages = Vec::new();
    if let Some(arr) = val.as_array() {
        let mut legacy_usage = if file
            .file_name()
            .is_some_and(|name| name == "ui_messages.json")
        {
            super::token_extraction::cline_legacy_usage_attachments(arr)
        } else {
            std::collections::BTreeMap::new()
        };
        for (index, item) in arr.iter().enumerate() {
            // Use parse_timestamp to handle both i64 milliseconds and ISO-8601 strings
            let created = item
                .get("timestamp")
                .or_else(|| item.get("created_at"))
                .or_else(|| item.get("ts"))
                .and_then(parse_timestamp);

            // NOTE: Do NOT filter individual messages by timestamp here!
            // The file-level check in file_modified_since() is sufficient.
            // Filtering messages would cause older messages to be lost when
            // the file is re-indexed after new messages are added.

            let role = normalized_role(item);

            let content_val = item
                .get("content")
                .or_else(|| item.get("text"))
                .or_else(|| item.get("message"));
            let content = content_val.map(flatten_content).unwrap_or_default();

            let attached_usage = legacy_usage.remove(&index);
            let has_attached_usage = attached_usage
                .as_ref()
                .and_then(Value::as_object)
                .is_some_and(|usage| !usage.is_empty());
            if content.trim().is_empty() && !has_attached_usage {
                continue;
            }
            let mut extra = item.clone();
            if let Some(usage) = attached_usage {
                // The original start/finish rows and their content stay
                // intact; only selected counters are copied to cass.
                if !extra.get("cass").is_some_and(Value::is_object) {
                    extra["cass"] = serde_json::json!({});
                }
                extra["cass"]["token_usage"] = usage;
            }

            let mut invocations =
                content_val.map_or_else(Vec::new, extract_invocations_from_content_blocks);
            unwrap_skill_invocations(&mut invocations);

            messages.push(NormalizedMessage {
                idx: i64::try_from(messages.len()).unwrap_or(i64::MAX), // preserve original order for stable sorting
                role: role.to_string(),
                author: None,
                created_at: created,
                content,
                extra,
                invocations,
                snippets: Vec::new(),
            });
        }
    }

    if messages.is_empty() {
        return None;
    }

    // Sort by timestamp (missing timestamps go last), preserving original order
    messages.sort_by(|a, b| {
        let a_ts = a.created_at.unwrap_or(i64::MAX);
        let b_ts = b.created_at.unwrap_or(i64::MAX);
        a_ts.cmp(&b_ts).then_with(|| a.idx.cmp(&b.idx))
    });

    // Re-index
    crate::types::reindex_messages(&mut messages);

    let (mut title, workspace) = if meta_path.exists()
        && let Some(v) = read_json(&meta_path)
    {
        let title = v
            .get("title")
            .and_then(|t| t.as_str())
            .map(std::string::ToString::to_string);
        // Try to find workspace path
        // Cline doesn't standardize this in metadata, but sometimes it's there or in state.
        // We check common keys.
        let workspace = v
            .get("rootPath")
            .or_else(|| v.get("cwd"))
            .or_else(|| v.get("workspace"))
            .and_then(|s| s.as_str())
            .map(PathBuf::from);
        (title, workspace)
    } else {
        (None, None)
    };

    // Fallback title from first message
    if title.is_none() {
        title = messages
            .first()
            .and_then(|m| m.content.lines().next())
            .map(|s| s.chars().take(100).collect());
    }

    Some(NormalizedConversation {
        agent_slug: "cline".to_string(),
        external_id: task_id,
        title,
        workspace,
        source_path: file.to_path_buf(),
        started_at: messages.iter().filter_map(|m| m.created_at).min(),
        ended_at: messages.iter().filter_map(|m| m.created_at).max(),
        metadata: serde_json::json!({"source": "cline"}),
        messages,
    })
}

fn normalized_role(item: &Value) -> &str {
    if let Some(role) = item.get("role").and_then(Value::as_str) {
        return role;
    }
    // Native Cline UI records use ask/say for their display type, not their
    // speaker. Keep the subtype in raw extra while exposing useful roles.
    // See cline/cline's ExtensionMessage.ts and sdk/message-translator.ts.
    match item.get("type").and_then(Value::as_str) {
        Some("say") => match item.get("say").and_then(Value::as_str) {
            Some("task" | "user_feedback" | "user_feedback_diff") => "user",
            Some("command_output" | "mcp_server_response" | "browser_action_result") => "tool",
            _ => "assistant",
        },
        Some("ask") => "assistant",
        Some(legacy_type) => legacy_type,
        None => "agent",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::scan::ScanRoot;
    use serde_json::json;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let connector = ClineConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = ClineConnector;
        let _ = connector;
    }

    // =====================================================
    // Helper: Create Cline storage structure
    // =====================================================

    fn create_cline_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join("claude-dev");
        fs::create_dir_all(&storage).unwrap();
        storage
    }

    fn create_task_dir(storage: &Path, task_id: &str) -> PathBuf {
        let task_dir = storage.join(task_id);
        fs::create_dir_all(&task_dir).unwrap();
        task_dir
    }

    // =====================================================
    // scan() Tests with ui_messages.json
    // =====================================================

    #[test]
    fn scan_parses_ui_messages_simple() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-001");

        let messages = json!([
            {"role": "user", "content": "Hello Cline!", "timestamp": 1_733_000_000},
            {"role": "assistant", "content": "Hello! How can I help?", "timestamp": 1_733_000_001}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello Cline!");
        assert_eq!(convs[0].messages[1].role, "assistant");
    }

    #[test]
    fn scan_with_explicit_roots_uses_scan_roots() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-explicit");

        let messages = json!([
            {"role": "user", "content": "Explicit root", "timestamp": 1_733_000_000}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().join("not-cline"),
            vec![ScanRoot::local(storage.clone())],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Explicit root");
    }

    #[test]
    fn scan_with_global_storage_scan_root() {
        let dir = TempDir::new().unwrap();
        let global_storage = dir.path().join("globalStorage");
        let storage = global_storage.join("saoudrizwan.claude-dev");
        let task_dir = create_task_dir(&storage, "task-global");

        let messages = json!([{"role": "user", "content": "From globalStorage"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().join("not-cline"),
            vec![ScanRoot::local(global_storage)],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "From globalStorage");
    }

    #[test]
    fn scan_with_explicit_config_root_finds_storage() {
        let dir = TempDir::new().unwrap();
        let config_root = dir.path().join(".config");
        let storage = config_root.join("Code/User/globalStorage/saoudrizwan.claude-dev");
        let task_dir = create_task_dir(&storage, "task-config");

        let messages = json!([{"role": "user", "content": "From .config"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().join("not-cline"),
            vec![ScanRoot::local(config_root)],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content, "From .config");
    }

    #[test]
    fn scan_prefers_ui_messages_over_api_history() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-prefer");

        // Both files exist
        let ui = json!([{"role": "user", "content": "From UI"}]);
        let api = json!([{"role": "user", "content": "From API"}]);
        fs::write(task_dir.join("ui_messages.json"), ui.to_string()).unwrap();
        fs::write(
            task_dir.join("api_conversation_history.json"),
            api.to_string(),
        )
        .unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].content, "From UI");
    }

    #[test]
    fn scan_falls_back_to_api_history() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-api");

        // Only API history exists
        let api = json!([{"role": "user", "content": "From API history"}]);
        fs::write(
            task_dir.join("api_conversation_history.json"),
            api.to_string(),
        )
        .unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].content, "From API history");
    }

    // =====================================================
    // scan() Tests with task_metadata.json
    // =====================================================

    #[test]
    fn scan_extracts_title_from_metadata() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-meta");

        let messages = json!([{"role": "user", "content": "Test"}]);
        let metadata = json!({"title": "My Cline Task"});
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        fs::write(task_dir.join("task_metadata.json"), metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("My Cline Task".to_string()));
    }

    #[test]
    fn discover_source_files_includes_primary_and_metadata_sidecar() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-discovery");

        let messages = json!([{"role": "user", "content": "Test"}]);
        let metadata = json!({"title": "Discovered Cline Task"});
        let primary = task_dir.join("ui_messages.json");
        let sidecar = task_dir.join("task_metadata.json");
        fs::write(&primary, messages.to_string()).unwrap();
        fs::write(&sidecar, metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage, None);
        let discovered = connector.discover_source_files(&ctx).unwrap();

        assert_eq!(discovered.len(), 2);
        assert!(discovered.iter().any(|source| {
            source.source_path == primary
                && source.role == DiscoveredSourceRole::PrimarySessionLog
                && source.required_for_reconstruction
        }));
        assert!(discovered.iter().any(|source| {
            source.source_path == sidecar
                && source.role == DiscoveredSourceRole::MetadataSidecar
                && !source.required_for_reconstruction
        }));
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_extracts_workspace_from_root_path() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-ws");

        let messages = json!([{"role": "user", "content": "Test"}]);
        let metadata = json!({"rootPath": "/home/user/project"});
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        fs::write(task_dir.join("task_metadata.json"), metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/project"))
        );
    }

    #[test]
    fn scan_extracts_workspace_from_cwd() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-cwd");

        let messages = json!([{"role": "user", "content": "Test"}]);
        let metadata = json!({"cwd": "/home/user/cwd-project"});
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        fs::write(task_dir.join("task_metadata.json"), metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/cwd-project"))
        );
    }

    #[test]
    fn scan_extracts_workspace_from_workspace_key() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-ws-key");

        let messages = json!([{"role": "user", "content": "Test"}]);
        let metadata = json!({"workspace": "/home/user/ws"});
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        fs::write(task_dir.join("task_metadata.json"), metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].workspace, Some(PathBuf::from("/home/user/ws")));
    }

    // =====================================================
    // Message Parsing Tests
    // =====================================================

    #[test]
    fn scan_parses_role_from_type_field() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-type");

        let messages = json!([{"type": "userMessage", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].role, "userMessage");
    }

    #[test]
    fn scan_parses_content_from_text_field() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-text");

        let messages = json!([{"role": "user", "text": "Content from text field"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].content, "Content from text field");
    }

    #[test]
    fn scan_parses_content_from_message_field() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-msg");

        let messages = json!([{"role": "user", "message": "Content from message field"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].content, "Content from message field");
    }

    #[test]
    fn scan_parses_timestamp() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-ts");

        let messages = json!([{"role": "user", "content": "Test", "timestamp": 1_733_000_000}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].created_at, Some(1_733_000_000_000));
    }

    #[test]
    fn scan_parses_created_at() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-created");

        let messages = json!([{"role": "user", "content": "Test", "created_at": 1_733_000_001}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].created_at, Some(1_733_000_001_000));
    }

    #[test]
    fn scan_parses_ts() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-ts-field");

        let messages = json!([{"role": "user", "content": "Test", "ts": 1_733_000_002}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].created_at, Some(1_733_000_002_000));
    }

    #[test]
    fn scan_skips_empty_content() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-empty");

        let messages = json!([
            {"role": "user", "content": "Valid"},
            {"role": "assistant", "content": ""},
            {"role": "assistant", "content": "   "}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages.len(), 1);
    }

    #[test]
    fn scan_sorts_messages_by_timestamp() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-sort");

        // Messages out of order
        let messages = json!([
            {"role": "assistant", "content": "Later", "timestamp": 1_733_000_100},
            {"role": "user", "content": "Earlier", "timestamp": 1_733_000_000}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].content, "Earlier");
        assert_eq!(convs[0].messages[1].content, "Later");
    }

    #[test]
    fn scan_assigns_sequential_indices() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-idx");

        let messages = json!([
            {"role": "user", "content": "First", "timestamp": 1},
            {"role": "assistant", "content": "Second", "timestamp": 2},
            {"role": "user", "content": "Third", "timestamp": 3}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].idx, 0);
        assert_eq!(convs[0].messages[1].idx, 1);
        assert_eq!(convs[0].messages[2].idx, 2);
    }

    #[test]
    fn scan_defaults_role_to_agent() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-no-role");

        let messages = json!([{"content": "No role field"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].role, "agent");
    }

    // =====================================================
    // Title Extraction Tests
    // =====================================================

    #[test]
    fn scan_extracts_title_from_first_message_if_no_metadata() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-no-meta");

        let messages = json!([
            {"role": "user", "content": "First line\nSecond line"},
            {"role": "assistant", "content": "Response"}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("First line".to_string()));
    }

    #[test]
    fn scan_truncates_long_titles() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-long-title");

        let long_content = "x".repeat(200);
        let messages = json!([{"role": "user", "content": long_content}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title.as_ref().unwrap().len(), 100);
    }

    // =====================================================
    // External ID and Agent Slug Tests
    // =====================================================

    #[test]
    fn scan_uses_task_dir_name_as_external_id() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "unique-task-id-123");

        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].external_id, Some("unique-task-id-123".to_string()));
    }

    #[test]
    fn scan_sets_agent_slug_to_cline() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-slug");

        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].agent_slug, "cline");
    }

    // =====================================================
    // Timestamp Tests
    // =====================================================

    #[test]
    fn scan_sets_started_at_from_first_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-start");

        let messages = json!([
            {"role": "user", "content": "First", "timestamp": 1_733_000_000},
            {"role": "assistant", "content": "Last", "timestamp": 1_733_000_100}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].started_at, Some(1_733_000_000_000));
        assert_eq!(convs[0].ended_at, Some(1_733_000_100_000));
    }

    // =====================================================
    // Edge Cases
    // =====================================================

    #[test]
    fn scan_handles_empty_storage() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_task_history_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);

        // This is a file, not a dir, but the code checks for dir name
        let task_history_dir = storage.join("taskHistory.json");
        fs::create_dir_all(&task_history_dir).unwrap();
        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(
            task_history_dir.join("ui_messages.json"),
            messages.to_string(),
        )
        .unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should be skipped
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_dir_without_message_files() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-no-files");
        // Don't create any message files

        // Create metadata only
        let metadata = json!({"title": "No messages"});
        fs::write(task_dir.join("task_metadata.json"), metadata.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_invalid_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-invalid");

        fs::write(task_dir.join("ui_messages.json"), "not valid json").unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_empty_messages_array() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-empty-arr");

        let messages = json!([]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_handles_multiple_tasks() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);

        for i in 1..=3 {
            let task_dir = create_task_dir(&storage, &format!("task-{i}"));
            let messages = json!([{"role": "user", "content": format!("Task {i}")}]);
            fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        }

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 3);
    }

    #[test]
    fn scan_skips_non_directory_entries() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);

        // Create a file instead of directory
        fs::write(storage.join("not-a-dir.json"), "{}").unwrap();

        // Create a real task
        let task_dir = create_task_dir(&storage, "real-task");
        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Only the real task should be processed
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn scan_sets_metadata_source() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-meta-src");

        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["source"], "cline");
    }

    // =====================================================
    // Edge case tests — malformed input robustness (br-2w98)
    // =====================================================

    #[test]
    fn scan_truncated_json_skips_task() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-trunc");

        // Write truncated JSON
        fs::write(
            task_dir.join("ui_messages.json"),
            r#"[{"role": "user", "content": "Hello"#,
        )
        .unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0, "truncated JSON should be skipped");
    }

    #[test]
    fn scan_json_object_instead_of_array_skips_task() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-obj");

        // JSON object instead of array
        let content = json!({"role": "user", "content": "Not an array"});
        fs::write(task_dir.join("ui_messages.json"), content.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // val.as_array() returns None for objects, so task is skipped
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_type_mismatch_in_messages_skips_bad_entries() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-mismatch");

        let messages = json!([
            // String instead of object
            "not a message object",
            // Number
            42,
            // Null
            null,
            // Object with wrong field types (content is a number)
            {"role": "user", "content": 12345},
            // Valid entry
            {"role": "user", "content": "Valid message"}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].content, "Valid message");
    }

    #[test]
    fn scan_deeply_nested_json_does_not_stack_overflow() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-deep");

        // Build deeply nested JSON (200 levels)
        let mut nested = String::new();
        for _ in 0..200 {
            nested.push_str("{\"a\":");
        }
        nested.push('1');
        for _ in 0..200 {
            nested.push('}');
        }
        fs::write(task_dir.join("ui_messages.json"), &nested).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        // Should not panic or stack overflow
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn scan_large_message_body_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-large");

        let large_content = "x".repeat(1_000_000);
        let messages = json!([{"role": "user", "content": large_content}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages[0].content.len(), 1_000_000);
    }

    #[test]
    fn scan_null_bytes_in_content_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-null");

        let messages = json!([
            {"role": "user", "content": "before\u{0000}after"},
            {"role": "user", "content": "Clean message"}
        ]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert!(
            !convs[0].messages.is_empty(),
            "should extract at least the clean message"
        );
    }

    #[test]
    fn scan_malformed_metadata_does_not_crash() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-bad-meta");

        let messages = json!([{"role": "user", "content": "Test"}]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();
        // Write malformed metadata
        fs::write(task_dir.join("task_metadata.json"), "not valid json {{{").unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should still extract the conversation even with bad metadata
        assert_eq!(convs.len(), 1);
        // Title should fallback to first message content
        assert_eq!(convs[0].title, Some("Test".to_string()));
    }

    #[test]
    fn scan_mixed_valid_and_invalid_tasks() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);

        // Invalid task: bad JSON
        let bad_dir = create_task_dir(&storage, "task-bad");
        fs::write(bad_dir.join("ui_messages.json"), "invalid json").unwrap();

        // Valid task
        let good_dir = create_task_dir(&storage, "task-good");
        let messages = json!([{"role": "user", "content": "Valid task"}]);
        fs::write(good_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        // Another invalid: empty array
        let empty_dir = create_task_dir(&storage, "task-empty-arr");
        fs::write(empty_dir.join("ui_messages.json"), "[]").unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1, "should only extract the valid task");
        assert_eq!(convs[0].messages[0].content, "Valid task");
    }

    #[test]
    fn scan_preserves_extra_fields_in_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_cline_storage(&dir);
        let task_dir = create_task_dir(&storage, "task-extra");

        let messages = json!([{
            "role": "user",
            "content": "Test",
            "customField": "customValue",
            "nestedData": {"key": "value"}
        }]);
        fs::write(task_dir.join("ui_messages.json"), messages.to_string()).unwrap();

        let connector = ClineConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].extra["customField"], "customValue");
        assert_eq!(convs[0].messages[0].extra["nestedData"]["key"], "value");
    }
}
