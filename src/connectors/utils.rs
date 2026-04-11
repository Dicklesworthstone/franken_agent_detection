//! Shared utility functions used by all connectors.

use std::path::PathBuf;

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
        if item_type.is_none() || item_type == Some("text") || item_type == Some("input_text") {
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
