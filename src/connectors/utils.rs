//! Shared utility functions used by all connectors.

mod capped;

use anyhow::Context;
use std::path::{Path, PathBuf};

/// Read an environment variable, trimming whitespace and treating empty strings as unset.
pub(crate) fn env_var_nonempty(key: &str) -> Option<String> {
    dotenvy::var(key).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

/// Read an environment variable as a filesystem path, ignoring empty strings.
pub(crate) fn env_path_nonempty(key: &str) -> Option<PathBuf> {
    env_var_nonempty(key).map(PathBuf::from)
}

/// Read `CASS_EXCLUDE_PATHS` as a comma/newline-delimited list of exact files
/// or directory prefixes to skip during connector scans.
///
/// This is intentionally implemented in the connector crate rather than in CASS
/// so source discovery and parsing stay aligned: a path excluded here is neither
/// pre-mirrored nor parsed.
///
/// Each entry is kept as written and also as an absolute
/// path (a relative entry joins the working directory) and as the canonical
/// form of its nearest existing ancestor. A symlink alias, a `..` spelling, a
/// relative spelling or (on Windows) a differently-cased spelling of the same
/// directory therefore still excludes it. These are the semantics CASS applies
/// to raw-mirror capture (`connectors::codex::path_policy::ScanExclusions`), so
/// parsing and capture agree on what an exclusion covers.
///
/// Invalid policy input is an error, never an empty policy. Relative entries
/// require a usable working directory; absolute entries do not. Entries are
/// literal filesystem paths (no shell or tilde expansion).
pub(crate) fn excluded_scan_paths_from_env() -> anyhow::Result<Vec<PathBuf>> {
    let value = match dotenvy::var("CASS_EXCLUDE_PATHS") {
        Ok(value) => value,
        Err(dotenvy::Error::EnvVar(std::env::VarError::NotPresent)) => return Ok(Vec::new()),
        Err(dotenvy::Error::EnvVar(std::env::VarError::NotUnicode(_))) => {
            anyhow::bail!("CASS_EXCLUDE_PATHS must contain valid Unicode");
        }
        Err(error) => return Err(error).context("could not read CASS_EXCLUDE_PATHS"),
    };
    excluded_scan_paths_from(&value, std::env::current_dir().ok().as_deref())
}

fn excluded_scan_paths_from(value: &str, cwd: Option<&Path>) -> anyhow::Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |path: PathBuf| {
        if !out.contains(&path) {
            out.push(path);
        }
    };
    for written in value
        .split([',', '\n'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(PathBuf::from)
    {
        let absolute = absolute_path(&written, cwd).with_context(|| {
            format!(
                "cannot resolve CASS_EXCLUDE_PATHS entry '{}' without an absolute working directory",
                written.display()
            )
        })?;
        let resolved = resolve_existing_ancestor(&absolute).with_context(|| {
            format!(
                "cannot resolve CASS_EXCLUDE_PATHS entry '{}'",
                written.display()
            )
        })?;
        push(resolved);
        push(absolute);
        push(written);
    }
    Ok(out)
}

fn absolute_path(path: &Path, cwd: Option<&Path>) -> Option<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd?.join(path)
    };
    // On Windows a drive-relative path such as `C:foo` stays relative after
    // the join; do not guess another drive's working directory.
    absolute.is_absolute().then_some(absolute)
}

/// Canonicalize the nearest existing ancestor of `path` and re-append the
/// missing remainder, folding `.` and `..` only after the existing part is
/// resolved (a symlink followed by `..` names the target's parent).
fn resolve_existing_ancestor(path: &Path) -> std::io::Result<PathBuf> {
    use std::path::Component;
    for ancestor in path.ancestors() {
        match std::fs::canonicalize(ancestor) {
            Ok(resolved_ancestor) => {
                let remainder = path.strip_prefix(ancestor).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "exclusion path is not under its own ancestor",
                    )
                })?;
                let mut resolved = PathBuf::new();
                for component in resolved_ancestor.join(remainder).components() {
                    match component {
                        Component::CurDir => {}
                        Component::ParentDir => {
                            resolved.pop();
                        }
                        other => resolved.push(other.as_os_str()),
                    }
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "exclusion path has no existing ancestor",
    ))
}

/// Return true when `path` should be skipped because it equals or is under one
/// of the configured exclusions (see [`excluded_scan_paths_from_env`]).
///
/// The path as given is compared first, without touching the filesystem.
/// Otherwise the path is resolved the same way the entries were and compared
/// again. With exclusions configured, a source whose location cannot be
/// resolved is treated as excluded: failing to establish where it lives is no
/// evidence that it is outside every excluded directory.
#[must_use]
pub(crate) fn path_is_excluded(path: &Path, excluded_paths: &[PathBuf]) -> bool {
    if excluded_paths.is_empty() {
        return false;
    }
    if excluded_paths
        .iter()
        .any(|excluded| path.starts_with(excluded))
    {
        return true;
    }
    let cwd = if path.is_absolute() {
        None
    } else {
        std::env::current_dir().ok()
    };
    let Some(absolute) = absolute_path(path, cwd.as_deref()) else {
        return true;
    };
    resolve_existing_ancestor(&absolute).map_or(true, |resolved| {
        excluded_paths
            .iter()
            .any(|excluded| resolved.starts_with(excluded))
    })
}

/// Maximum session-store file size connectors will read into memory
/// (100 MiB), matching the chatgpt connector's policy.
pub(crate) const MAX_SCAN_FILE_BYTES: u64 = 100 * 1024 * 1024;

/// Read a session-store file to a string under the project's size cap.
///
/// Metadata on the opened file rejects known oversized sources cheaply. The
/// read itself consumes at most [`MAX_SCAN_FILE_BYTES`] plus one probe byte,
/// including when metadata fails or the source grows during the read. Returns
/// `Ok(None)` when the file exceeds the cap; callers decide how to log it.
pub(crate) fn read_capped(path: &Path) -> std::io::Result<Option<String>> {
    capped::read_capped(path)
}

/// True when a user message is harness-injected context rather than a
/// human-authored prompt (`# AGENTS.md instructions …`,
/// `<environment_context>`, `<session_context>`, `<user_instructions>`).
///
/// Used for TITLE selection only: the records stay in the timeline, but
/// letting them seed a conversation title yields boilerplate for a large
/// share of real sessions (3/12 recently-modified codex sessions sampled).
#[must_use]
pub(crate) fn is_injected_context_message(content: &str) -> bool {
    const PREFIXES: [&str; 4] = [
        "# AGENTS.md instructions",
        "<environment_context>",
        "<session_context>",
        "<user_instructions>",
    ];
    let trimmed = content.trim_start();
    PREFIXES.iter().any(|prefix| trimmed.starts_with(prefix))
}

/// Build a deduplication key for hot scan loops without paying the full
/// `canonicalize()` syscall cost on every ordinary file.
///
/// Most indexed session files are not symlinks. A full canonicalization on each
/// one walks every path component and triggers a storm of `readlink` probes that
/// dominate no-op incremental scans. We only resolve leaf symlinks here; callers
/// that need stronger root-level normalization should canonicalize the much
/// smaller root set separately.
#[must_use]
pub(crate) fn dedupe_path_key(path: &std::path::Path) -> PathBuf {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
        }
        _ => path.to_path_buf(),
    }
}

/// Minimal percent-decoding for URI path components (RFC 3986).
///
/// Decodes `%XX` byte escapes and leaves every other byte untouched;
/// malformed escapes (`%` not followed by two hex digits) pass through
/// verbatim. Invalid UTF-8 in decoded output is replaced per
/// [`String::from_utf8_lossy`], which is acceptable for workspace-path
/// best-effort inference.
#[must_use]
pub fn percent_decode_utf8(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] == b'%'
            && pos + 2 < bytes.len()
            && bytes[pos + 1].is_ascii_hexdigit()
            && bytes[pos + 2].is_ascii_hexdigit()
        {
            let hi = (bytes[pos + 1] as char).to_digit(16).unwrap_or(0);
            let lo = (bytes[pos + 2] as char).to_digit(16).unwrap_or(0);
            // Both digits passed `is_ascii_hexdigit`, so the value is at
            // most 0xFF; the fallback is unreachable.
            out.push(u8::try_from(hi * 16 + lo).unwrap_or_default());
            pos += 3;
        } else {
            out.push(bytes[pos]);
            pos += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Check if a file was modified since the given timestamp.
/// Returns true if the file should be processed (modified since timestamp or no timestamp given).
#[must_use]
pub fn file_modified_since(path: &std::path::Path, since_ts: Option<i64>) -> bool {
    since_ts.is_none_or(|ts| {
        let threshold = ts.saturating_sub(1_000);
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .map_or(true, |mt| {
                mt.duration_since(std::time::UNIX_EPOCH).map_or(true, |d| {
                    i64::try_from(d.as_millis()).unwrap_or(i64::MAX) >= threshold
                })
            })
    })
}

/// Parse a timestamp from either i64 milliseconds or ISO-8601 string.
/// Returns milliseconds since Unix epoch, or None if unparseable.
#[must_use]
pub fn parse_timestamp(val: &serde_json::Value) -> Option<i64> {
    if let Some(ts) = val.as_i64() {
        let ts = if (0..100_000_000_000).contains(&ts) {
            ts.saturating_mul(1000)
        } else if (100_000_000_000_000..=100_000_000_000_000_000).contains(&ts) {
            // Microsecond epoch: 1e14–1e17 µs spans 1973–5138. No
            // in-scope producer emits these today, but a µs value read as
            // milliseconds lands ~55 millennia out, so band it explicitly.
            ts / 1000
        } else {
            ts
        };
        return Some(ts);
    }
    // Handle JSON float numbers (e.g., 1700000000.5) — serde_json's as_i64()
    // returns None for numbers with fractional parts, so check as_f64() too.
    // Note: as_f64() also succeeds for integer Numbers, but those are already
    // handled by as_i64() above.
    if val.is_number() {
        if let Some(f) = val.as_f64() {
            if f.is_finite() && f > 0.0 {
                #[allow(clippy::cast_possible_truncation)]
                let ts = if f < 100_000_000_000.0 {
                    (f * 1000.0).round() as i64
                } else if (100_000_000_000_000.0..=100_000_000_000_000_000.0).contains(&f) {
                    // Microsecond epoch (see the as_i64 branch above).
                    (f / 1000.0).round() as i64
                } else {
                    f.round() as i64
                };
                return Some(ts);
            }
        }
    }
    if let Some(s) = val.as_str() {
        if let Ok(num) = s.parse::<i64>() {
            let ts = if (0..100_000_000_000).contains(&num) {
                num.saturating_mul(1000)
            } else if (100_000_000_000_000..=100_000_000_000_000_000).contains(&num) {
                // Microsecond epoch (see the as_i64 branch above).
                num / 1000
            } else {
                num
            };
            return Some(ts);
        }
        if let Ok(num) = s.parse::<f64>() {
            if !num.is_finite() {
                return None;
            }
            #[allow(clippy::cast_possible_truncation)]
            let ts = if (0.0..100_000_000_000.0).contains(&num) {
                (num * 1000.0).round() as i64
            } else if (100_000_000_000_000.0..=100_000_000_000_000_000.0).contains(&num) {
                // Microsecond epoch (see the as_i64 branch above).
                (num / 1000.0).round() as i64
            } else {
                num.round() as i64
            };
            return Some(ts);
        }
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
            return Some(dt.timestamp_millis());
        }
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ") {
            return Some(dt.and_utc().timestamp_millis());
        }
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ") {
            return Some(dt.and_utc().timestamp_millis());
        }
    }
    None
}

#[cfg(test)]
mod exclusion_tests {
    use super::{excluded_scan_paths_from, path_is_excluded};
    use std::path::Path;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        for file in [
            "projects/secret/a.jsonl",
            "projects/open/b.jsonl",
            "sessions/c.jsonl",
        ] {
            let path = dir.path().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "{}").unwrap();
        }
        dir
    }

    fn excludes(value: &str, cwd: &Path, source: &Path) -> bool {
        path_is_excluded(source, &excluded_scan_paths_from(value, Some(cwd)).unwrap())
    }

    #[test]
    fn no_exclusions_match_nothing() {
        assert!(
            excluded_scan_paths_from(" ,\n , ", None)
                .unwrap()
                .is_empty()
        );
        assert!(!path_is_excluded(Path::new("/nonexistent/a.jsonl"), &[]));
    }

    #[test]
    fn relative_policy_requires_an_absolute_working_directory() {
        for cwd in [None, Some(Path::new("relative-cwd"))] {
            let error = excluded_scan_paths_from("private", cwd).unwrap_err();
            assert!(error.to_string().contains("CASS_EXCLUDE_PATHS"));
            assert!(error.to_string().contains("working directory"));
        }
        let dir = tree();
        let mixed = format!("{},private", dir.path().display());
        assert!(excluded_scan_paths_from(&mixed, None).is_err());
    }

    #[test]
    fn absolute_policy_remains_effective_without_a_working_directory() {
        let dir = tree();
        let private = dir.path().join("projects/secret");
        let excluded = excluded_scan_paths_from(private.to_str().unwrap(), None).unwrap();
        assert!(path_is_excluded(&private.join("a.jsonl"), &excluded));
        assert!(!path_is_excluded(
            &dir.path().join("projects/open/b.jsonl"),
            &excluded
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unresolvable_policy_is_an_error_not_a_partial_policy() {
        let dir = tree();
        let alias = dir.path().join("loop");
        std::os::unix::fs::symlink(&alias, &alias).unwrap();
        let mixed = format!(
            "{},{}",
            dir.path().join("projects/secret").display(),
            alias.display()
        );
        assert!(excluded_scan_paths_from(&mixed, Some(dir.path())).is_err());
    }

    #[test]
    fn entries_match_whole_components_not_string_prefixes() {
        let dir = tree();
        let root = dir.path();
        let source = root.join("sessions/c.jsonl");
        assert!(!excludes(
            &root.join("sess").display().to_string(),
            root,
            &source
        ));
        assert!(excludes(
            &root.join("sessions").display().to_string(),
            root,
            &source
        ));
        assert!(excludes(&source.display().to_string(), root, &source));
    }

    #[test]
    fn a_missing_entry_still_matches_as_written() {
        let dir = tree();
        let gone = dir.path().join("gone/dir");
        assert!(excludes(
            &gone.display().to_string(),
            dir.path(),
            &gone.join("x.jsonl")
        ));
        assert!(!excludes(
            &gone.display().to_string(),
            dir.path(),
            &dir.path().join("projects/open/b.jsonl")
        ));
    }

    #[test]
    fn dotdot_and_relative_spellings_exclude_the_same_directory() {
        let dir = tree();
        let root = dir.path();
        let secret = root.join("projects/secret/a.jsonl");
        let open = root.join("projects/open/b.jsonl");
        let dotdot = root
            .join("projects/../projects/secret")
            .display()
            .to_string();
        for value in [
            dotdot.as_str(),
            "projects/secret",
            "./projects/open/../secret",
        ] {
            assert!(
                excludes(value, root, &secret),
                "{value} must exclude {secret:?}"
            );
            assert!(
                !excludes(value, root, &open),
                "{value} must not exclude {open:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_alias_on_either_side_excludes_the_target() {
        let dir = tree();
        let root = dir.path();
        std::os::unix::fs::symlink(root.join("projects/secret"), root.join("alias")).unwrap();
        let secret = root.join("projects/secret/a.jsonl");
        let open = root.join("projects/open/b.jsonl");
        let alias = root.join("alias").display().to_string();
        assert!(excludes(&alias, root, &secret));
        assert!(!excludes(&alias, root, &open));
        // A source reached through the alias is under the real directory.
        let real = root.join("projects/secret").display().to_string();
        assert!(excludes(&real, root, &root.join("alias/a.jsonl")));
    }
}

#[cfg(test)]
mod dedupe_tests {
    use super::dedupe_path_key;

    #[test]
    fn dedupe_path_key_keeps_regular_file_paths_stable() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("session.jsonl");
        std::fs::write(&file, "hello").unwrap();

        assert_eq!(dedupe_path_key(&file), file);
    }

    #[cfg(unix)]
    #[test]
    fn dedupe_path_key_canonicalizes_symlink_leaf() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("target.jsonl");
        let link = dir.path().join("link.jsonl");
        std::fs::write(&target, "hello").unwrap();
        symlink(&target, &link).unwrap();

        assert_eq!(
            dedupe_path_key(&link),
            std::fs::canonicalize(&target).unwrap()
        );
    }
}

/// Flatten content that may be a string or array of content blocks.
/// Extracts text from text blocks and tool names from `tool_use` blocks.
#[must_use]
pub fn flatten_content(val: &serde_json::Value) -> String {
    if let Some(s) = val.as_str() {
        return s.to_string();
    }

    if let Some(arr) = val.as_array() {
        let mut result = String::new();
        for item in arr {
            if let Some(text) = extract_content_part(item) {
                if text.is_empty() {
                    continue;
                }
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(&text);
            }
        }
        return result;
    }

    String::new()
}

/// Extract text content from a single content block item.
fn extract_content_part(item: &serde_json::Value) -> Option<String> {
    if let Some(text) = item.as_str() {
        return Some(text.to_string());
    }

    let item_type = item.get("type").and_then(|v| v.as_str());

    if let Some(text) = item.get("text").and_then(|v| v.as_str()) {
        // `output_text` is the modern Codex/Responses-API assistant text block;
        // `input_text` is the user/developer counterpart. Both, like a plain
        // `text` block, carry rendered text we want to surface.
        if item_type.is_none()
            || item_type == Some("text")
            || item_type == Some("input_text")
            || item_type == Some("output_text")
        {
            return Some(text.to_string());
        }
    }

    if item_type == Some("tool_use") {
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let desc = item
            .get("input")
            .and_then(|i| i.get("description"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                item.get("input")
                    .and_then(|i| i.get("file_path"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("");
        if desc.is_empty() {
            return Some(format!("[Tool: {name}]"));
        }
        return Some(format!("[Tool: {name} - {desc}]"));
    }

    None
}

/// Extract structured invocations from a Claude API-style content block array.
///
/// Emits every `tool_use` block as `kind: "tool"`. Connector-specific
/// unwrapping (e.g. Amp's skill wrapper) should be applied separately via
/// [`unwrap_skill_invocations`].
///
/// Works for any connector that stores content as an array of typed blocks:
/// amp, `claude_code`, codex, cline, factory.
#[must_use]
pub fn extract_invocations_from_content_blocks(
    val: &serde_json::Value,
) -> Vec<crate::types::NormalizedInvocation> {
    let Some(arr) = val.as_array() else {
        return Vec::new();
    };

    let mut invocations = Vec::new();
    for item in arr {
        let item_type = item.get("type").and_then(|v| v.as_str());
        if item_type != Some("tool_use") {
            continue;
        }

        let Some(raw_name) = item.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let call_id = item
            .get("id")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string);
        let input = item.get("input");

        invocations.push(crate::types::NormalizedInvocation {
            kind: "tool".to_string(),
            name: raw_name.to_string(),
            raw_name: None,
            call_id,
            arguments: input.cloned(),
        });
    }

    invocations
}

/// Amp-specific wrapper tools that should be unwrapped to their inner name.
const AMP_SKILL_WRAPPERS: &[(&str, &str)] = &[
    // (tool_name, input_key_for_real_name)
    ("skill", "name"),
    ("load_skill", "name"),
];

/// Unwrap Amp skill-wrapper invocations in place.
///
/// Tools like `skill` and `load_skill` are Amp-specific wrappers whose real
/// name lives inside the `input` object. This rewrites matching invocations
/// to `kind: "skill"` with the inner name, preserving `raw_name` for
/// traceability. Non-matching invocations are left unchanged.
pub fn unwrap_skill_invocations(invocations: &mut [crate::types::NormalizedInvocation]) {
    for inv in invocations.iter_mut() {
        if let Some((_, key)) = AMP_SKILL_WRAPPERS
            .iter()
            .find(|(name, _)| *name == inv.name)
        {
            if let Some(inner_name) = inv
                .arguments
                .as_ref()
                .and_then(|a| a.get(*key))
                .and_then(|v| v.as_str())
            {
                inv.raw_name = Some(inv.name.clone());
                inv.name = inner_name.to_string();
                inv.kind = "skill".to_string();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- parse_timestamp tests ---

    #[test]
    fn parse_timestamp_i64_milliseconds() {
        let val = json!(1_700_000_000_000_i64);
        assert_eq!(parse_timestamp(&val), Some(1_700_000_000_000));
    }

    #[test]
    fn parse_timestamp_i64_seconds() {
        let val = json!(1_700_000_000_i64);
        assert_eq!(parse_timestamp(&val), Some(1_700_000_000_000));
    }

    #[test]
    fn is_injected_context_message_detects_known_wrappers() {
        assert!(is_injected_context_message(
            "# AGENTS.md instructions for /data/projects/demo\nDo the thing"
        ));
        assert!(is_injected_context_message(
            "<environment_context>macos</environment_context>"
        ));
        assert!(is_injected_context_message("<session_context>\n…"));
        assert!(is_injected_context_message("  <user_instructions>…"));
    }

    #[test]
    fn is_injected_context_message_allows_real_prompts() {
        assert!(!is_injected_context_message("Fix the flaky test in it.rs"));
        // Wrapper text appearing mid-message is not an injection header.
        assert!(!is_injected_context_message(
            "please read the <session_context> block"
        ));
    }

    #[test]
    fn read_capped_enforces_size_cap() {
        let dir = tempfile::TempDir::new().unwrap();
        let small = dir.path().join("small.txt");
        std::fs::write(&small, "tiny").unwrap();
        assert_eq!(read_capped(&small).unwrap().as_deref(), Some("tiny"));

        // Sparse file: reports as over the cap without materializing 100MB.
        let big = dir.path().join("big.txt");
        let file = std::fs::File::create(&big).unwrap();
        file.set_len(MAX_SCAN_FILE_BYTES + 1).unwrap();
        drop(file);
        assert!(read_capped(&big).unwrap().is_none());
    }

    #[test]
    fn parse_timestamp_i64_microseconds() {
        // 1_700_000_000_000_000 µs == 1_700_000_000_000 ms.
        let val = json!(1_700_000_000_000_000_i64);
        assert_eq!(parse_timestamp(&val), Some(1_700_000_000_000));
    }

    #[test]
    fn parse_timestamp_float_microseconds() {
        let val = json!(1_700_000_000_500_000.0_f64);
        assert_eq!(parse_timestamp(&val), Some(1_700_000_000_500));
    }

    #[test]
    fn parse_timestamp_numeric_string_microseconds() {
        let val = json!("1700000000000000");
        assert_eq!(parse_timestamp(&val), Some(1_700_000_000_000));
    }

    #[test]
    fn parse_timestamp_numeric_string_seconds() {
        let val = json!("1700000000");
        assert_eq!(parse_timestamp(&val), Some(1_700_000_000_000));
    }

    #[test]
    fn parse_timestamp_numeric_string_millis() {
        let val = json!("1700000000000");
        assert_eq!(parse_timestamp(&val), Some(1_700_000_000_000));
    }

    #[test]
    fn parse_timestamp_iso8601_with_fractional() {
        let val = json!("2025-11-12T18:31:32.217Z");
        let ts = parse_timestamp(&val).unwrap();
        assert!(ts > 0);
        // Verify it round-trips correctly through chrono
        let expected = chrono::DateTime::parse_from_rfc3339("2025-11-12T18:31:32.217Z")
            .unwrap()
            .timestamp_millis();
        assert_eq!(ts, expected);
    }

    #[test]
    fn parse_timestamp_iso8601_without_fractional() {
        let val = json!("2025-11-12T18:31:32Z");
        let ts = parse_timestamp(&val).unwrap();
        assert!(ts > 0);
    }

    #[test]
    fn parse_timestamp_rfc3339_with_offset() {
        let val = json!("2025-11-12T18:31:32+00:00");
        assert!(parse_timestamp(&val).is_some());
    }

    #[test]
    fn parse_timestamp_null_returns_none() {
        let val = json!(null);
        assert_eq!(parse_timestamp(&val), None);
    }

    #[test]
    fn parse_timestamp_invalid_string_returns_none() {
        let val = json!("not-a-timestamp");
        assert_eq!(parse_timestamp(&val), None);
    }

    #[test]
    fn parse_timestamp_empty_string_returns_none() {
        let val = json!("");
        assert_eq!(parse_timestamp(&val), None);
    }

    #[test]
    fn parse_timestamp_object_returns_none() {
        let val = json!({"time": 123});
        assert_eq!(parse_timestamp(&val), None);
    }

    #[test]
    fn parse_timestamp_negative_i64() {
        let val = json!(-1000);
        assert_eq!(parse_timestamp(&val), Some(-1000));
    }

    #[test]
    fn parse_timestamp_zero() {
        let val = json!(0);
        assert_eq!(parse_timestamp(&val), Some(0));
    }

    // --- flatten_content tests ---

    #[test]
    fn flatten_content_plain_string() {
        let val = json!("Hello, world!");
        assert_eq!(flatten_content(&val), "Hello, world!");
    }

    #[test]
    fn flatten_content_text_block_array() {
        let val = json!([
            {"type": "text", "text": "Line 1"},
            {"type": "text", "text": "Line 2"}
        ]);
        assert_eq!(flatten_content(&val), "Line 1\nLine 2");
    }

    #[test]
    fn flatten_content_tool_use_block() {
        let val = json!([
            {"type": "tool_use", "name": "Read", "input": {"file_path": "/src/main.rs"}}
        ]);
        assert_eq!(flatten_content(&val), "[Tool: Read - /src/main.rs]");
    }

    #[test]
    fn flatten_content_mixed_blocks() {
        let val = json!([
            {"type": "text", "text": "Hello"},
            {"type": "tool_use", "name": "Write", "input": {"description": "writing file"}}
        ]);
        assert_eq!(flatten_content(&val), "Hello\n[Tool: Write - writing file]");
    }

    #[test]
    fn flatten_content_input_text_block() {
        let val = json!([{"type": "input_text", "text": "Codex input"}]);
        assert_eq!(flatten_content(&val), "Codex input");
    }

    #[test]
    fn flatten_content_output_text_block() {
        // Modern Codex assistant messages encode text as `output_text` blocks.
        let val = json!([{"type": "output_text", "text": "Codex assistant output"}]);
        assert_eq!(flatten_content(&val), "Codex assistant output");
    }

    #[test]
    fn flatten_content_null_returns_empty() {
        let val = json!(null);
        assert_eq!(flatten_content(&val), "");
    }

    #[test]
    fn flatten_content_empty_array() {
        let val = json!([]);
        assert_eq!(flatten_content(&val), "");
    }

    #[test]
    fn flatten_content_plain_string_array() {
        let val = json!(["Hello", "World"]);
        assert_eq!(flatten_content(&val), "Hello\nWorld");
    }

    #[test]
    fn flatten_content_empty_string() {
        let val = json!("");
        assert_eq!(flatten_content(&val), "");
    }

    #[test]
    fn flatten_content_number_returns_empty() {
        let val = json!(42);
        assert_eq!(flatten_content(&val), "");
    }

    #[test]
    fn flatten_content_whitespace_only() {
        let val = json!("   ");
        assert_eq!(flatten_content(&val), "   ");
    }

    // --- extract_invocations_from_content_blocks tests ---

    #[test]
    fn extract_invocations_plain_tool_use() {
        let val = json!([
            {"type": "text", "text": "Let me read that file."},
            {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {"path": "/src/main.rs"}}
        ]);
        let invocations = extract_invocations_from_content_blocks(&val);
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].kind, "tool");
        assert_eq!(invocations[0].name, "Read");
        assert!(invocations[0].raw_name.is_none());
        assert_eq!(invocations[0].call_id.as_deref(), Some("toolu_1"));
        assert_eq!(
            invocations[0].arguments.as_ref().unwrap()["path"],
            "/src/main.rs"
        );
    }

    #[test]
    fn extract_invocations_skill_not_unwrapped_by_shared_helper() {
        // The shared helper should NOT unwrap skill wrappers -- that's Amp-specific.
        let val = json!([
            {"type": "tool_use", "id": "toolu_2", "name": "skill", "input": {"name": "github-prs"}}
        ]);
        let invocations = extract_invocations_from_content_blocks(&val);
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].kind, "tool");
        assert_eq!(invocations[0].name, "skill");
        assert!(invocations[0].raw_name.is_none());
    }

    #[test]
    fn extract_invocations_multiple_tools() {
        let val = json!([
            {"type": "tool_use", "name": "Read", "input": {"path": "a.rs"}},
            {"type": "text", "text": "Now editing..."},
            {"type": "tool_use", "name": "edit_file", "input": {"path": "a.rs", "old_str": "x", "new_str": "y"}},
            {"type": "tool_use", "name": "skill", "input": {"name": "git"}}
        ]);
        let invocations = extract_invocations_from_content_blocks(&val);
        assert_eq!(invocations.len(), 3);
        assert_eq!(invocations[0].name, "Read");
        assert_eq!(invocations[1].name, "edit_file");
        assert_eq!(invocations[2].name, "skill");
    }

    #[test]
    fn extract_invocations_no_tool_use_blocks() {
        let val = json!([
            {"type": "text", "text": "Just plain text."}
        ]);
        assert!(extract_invocations_from_content_blocks(&val).is_empty());
    }

    #[test]
    fn extract_invocations_string_content_returns_empty() {
        let val = json!("plain string");
        assert!(extract_invocations_from_content_blocks(&val).is_empty());
    }

    #[test]
    fn extract_invocations_null_returns_empty() {
        let val = json!(null);
        assert!(extract_invocations_from_content_blocks(&val).is_empty());
    }

    #[test]
    fn extract_invocations_tool_use_missing_name_skipped() {
        let val = json!([
            {"type": "tool_use", "input": {"path": "a.rs"}}
        ]);
        assert!(extract_invocations_from_content_blocks(&val).is_empty());
    }

    // --- unwrap_skill_invocations tests ---

    #[test]
    fn unwrap_skill_invocations_rewrites_skill_wrapper() {
        let mut invocations = vec![crate::types::NormalizedInvocation {
            kind: "tool".to_string(),
            name: "skill".to_string(),
            raw_name: None,
            call_id: Some("toolu_1".to_string()),
            arguments: Some(json!({"name": "github-prs"})),
        }];
        unwrap_skill_invocations(&mut invocations);
        assert_eq!(invocations[0].kind, "skill");
        assert_eq!(invocations[0].name, "github-prs");
        assert_eq!(invocations[0].raw_name.as_deref(), Some("skill"));
    }

    #[test]
    fn unwrap_skill_invocations_rewrites_load_skill_wrapper() {
        let mut invocations = vec![crate::types::NormalizedInvocation {
            kind: "tool".to_string(),
            name: "load_skill".to_string(),
            raw_name: None,
            call_id: None,
            arguments: Some(json!({"name": "git"})),
        }];
        unwrap_skill_invocations(&mut invocations);
        assert_eq!(invocations[0].kind, "skill");
        assert_eq!(invocations[0].name, "git");
        assert_eq!(invocations[0].raw_name.as_deref(), Some("load_skill"));
    }

    #[test]
    fn unwrap_skill_invocations_leaves_non_wrappers_unchanged() {
        let mut invocations = vec![crate::types::NormalizedInvocation {
            kind: "tool".to_string(),
            name: "Read".to_string(),
            raw_name: None,
            call_id: None,
            arguments: Some(json!({"path": "/src/main.rs"})),
        }];
        unwrap_skill_invocations(&mut invocations);
        assert_eq!(invocations[0].kind, "tool");
        assert_eq!(invocations[0].name, "Read");
        assert!(invocations[0].raw_name.is_none());
    }

    #[test]
    fn unwrap_skill_invocations_no_inner_name_leaves_unchanged() {
        let mut invocations = vec![crate::types::NormalizedInvocation {
            kind: "tool".to_string(),
            name: "skill".to_string(),
            raw_name: None,
            call_id: None,
            arguments: Some(json!({"arguments": "something"})),
        }];
        unwrap_skill_invocations(&mut invocations);
        // No "name" key in arguments -- should remain as tool "skill"
        assert_eq!(invocations[0].kind, "tool");
        assert_eq!(invocations[0].name, "skill");
        assert!(invocations[0].raw_name.is_none());
    }
}
