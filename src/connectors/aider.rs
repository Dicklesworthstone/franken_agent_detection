//! Connector for Aider session logs.
//!
//! Aider stores markdown chat history at:
//! - `<project>/.aider.chat.history.md`
//!
//! User messages are prefixed with `>` (blockquote style); everything else is
//! assistant or system output.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::json;
use walkdir::WalkDir;

use super::scan::ScanContext;
use super::{Connector, file_modified_since, franken_detection_for_connector};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct AiderConnector;

impl Default for AiderConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl AiderConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Find aider chat history files under the provided roots (limited depth to avoid wide scans).
    fn find_chat_files(roots: &[&Path]) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for root in roots {
            if !root.exists() {
                continue;
            }
            for entry in WalkDir::new(root)
                .max_depth(5)
                .into_iter()
                .flatten()
                .filter(|e| e.file_type().is_file())
            {
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n == ".aider.chat.history.md")
                {
                    files.push(entry.path().to_path_buf());
                }
            }
        }
        // Keep connector traversal deterministic across filesystems/runs.
        files.sort();
        files
    }

    #[allow(clippy::unused_self)]
    fn parse_chat_history(&self, path: &Path) -> Result<NormalizedConversation> {
        let content = fs::read_to_string(path)?;
        let mut messages = Vec::new();
        let mut current_role = "system";
        let mut current_content = String::new();
        let mut msg_idx: i64 = 0;

        for line in content.lines() {
            if line.trim().starts_with('>') {
                // Only push previous content if switching from non-user role
                if current_role != "user" && !current_content.trim().is_empty() {
                    messages.push(NormalizedMessage {
                        idx: msg_idx,
                        role: current_role.to_string(),
                        author: Some(current_role.to_string()),
                        created_at: None,
                        content: current_content.trim().to_string(),
                        extra: json!({}),
                        snippets: Vec::new(),
                    });
                    msg_idx += 1;
                    current_content.clear();
                }
                current_role = "user";

                // Only strip the prefix "> " (or ">") but preserve other whitespace
                // to maintain indentation (e.g. for code blocks in prompts).
                let trimmed_start = line.trim_start();
                let stripped = trimmed_start
                    .strip_prefix("> ")
                    .or_else(|| trimmed_start.strip_prefix('>'))
                    .unwrap_or(trimmed_start);
                current_content.push_str(stripped.trim_end());
            } else {
                if current_role == "user" && !line.trim().is_empty() && !line.starts_with('>') {
                    if !current_content.trim().is_empty() {
                        messages.push(NormalizedMessage {
                            idx: msg_idx,
                            role: "user".to_string(),
                            author: Some("user".to_string()),
                            created_at: None,
                            content: current_content.trim().to_string(),
                            extra: json!({}),
                            snippets: Vec::new(),
                        });
                        msg_idx += 1;
                        current_content.clear();
                    }
                    current_role = "assistant";
                }
                current_content.push_str(line);
            }
            current_content.push('\n');
        }

        if !current_content.trim().is_empty() {
            messages.push(NormalizedMessage {
                idx: msg_idx,
                role: current_role.to_string(),
                author: Some(current_role.to_string()),
                created_at: None,
                content: current_content.trim().to_string(),
                extra: json!({}),
                snippets: Vec::new(),
            });
        }

        let mtime = fs::metadata(path)?.modified()?;
        let ts = i64::try_from(
            mtime
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(i64::MAX);

        Ok(NormalizedConversation {
            agent_slug: "aider".to_string(),
            external_id: Some(path.to_string_lossy().to_string()),
            title: Some(format!(
                "Aider Chat: {}",
                path.parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
            )),
            workspace: path.parent().map(std::path::Path::to_path_buf),
            source_path: path.to_path_buf(),
            started_at: Some(ts),
            ended_at: Some(ts),
            metadata: json!({}),
            messages,
        })
    }
}

impl Connector for AiderConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("aider").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut roots: Vec<PathBuf> = Vec::new();

        let mut add_root = |root: PathBuf| {
            if !roots.contains(&root) {
                roots.push(root);
            }
        };

        if ctx.use_default_detection() {
            let data_root = if ctx
                .data_dir
                .file_name()
                .is_some_and(|n| n == ".aider.chat.history.md")
            {
                ctx.data_dir
                    .parent()
                    .map_or_else(|| ctx.data_dir.clone(), PathBuf::from)
            } else {
                ctx.data_dir.clone()
            };

            // Check if data_root is actually the CASS DB directory
            let is_cass_db_dir = data_root.join("agent_search.db").exists();

            // Check for override env var first
            if let Ok(override_root) = dotenvy::var("CASS_AIDER_DATA_ROOT")
                && !override_root.trim().is_empty()
            {
                add_root(PathBuf::from(override_root.trim()));
            } else if !is_cass_db_dir && data_root.exists() && data_root.is_dir() {
                // Use data_root for recursive search (will find history files in subdirs)
                // BUT skip if it looks like the CASS DB directory to avoid wasteful scanning
                add_root(data_root);
            } else {
                // Only fall back to CWD/home when data_root doesn't exist or is the DB dir
                if let Ok(cwd) = std::env::current_dir() {
                    add_root(cwd);
                }
                if let Some(home) = dirs::home_dir()
                    && home.join(".aider.chat.history.md").exists()
                {
                    add_root(home);
                }
            }
        } else {
            // Explicit roots provided (e.g. remote mirrors) - use them directly
            for root in &ctx.scan_roots {
                add_root(root.path.clone());
            }
        }

        if roots.is_empty() {
            return Ok(Vec::new());
        }

        let root_refs: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
        let files = Self::find_chat_files(&root_refs);

        let mut conversations = Vec::new();
        for path in files {
            if !file_modified_since(&path, ctx.since_ts) {
                continue;
            }
            match self.parse_chat_history(&path) {
                Ok(conv) => conversations.push(conv),
                Err(e) => {
                    tracing::warn!("failed to parse aider history {}: {}", path.display(), e);
                }
            }
        }
        Ok(conversations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let connector = AiderConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = AiderConnector;
        let _ = connector;
    }

    // =====================================================
    // find_chat_files() Tests
    // =====================================================

    #[test]
    fn find_chat_files_finds_aider_history() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        fs::write(&history_file, "# Chat\n> Hello").unwrap();

        let files = AiderConnector::find_chat_files(&[dir.path()]);
        assert_eq!(files.len(), 1);
        assert!(
            files[0]
                .to_str()
                .unwrap()
                .contains(".aider.chat.history.md")
        );
    }

    #[test]
    fn find_chat_files_finds_nested_history() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("project").join("subdir");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join(".aider.chat.history.md"), "# Chat").unwrap();

        let files = AiderConnector::find_chat_files(&[dir.path()]);
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn find_chat_files_ignores_other_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".aider.conf.yml"), "config").unwrap();
        fs::write(dir.path().join("chat.md"), "# Chat").unwrap();
        fs::write(dir.path().join("README.md"), "# README").unwrap();

        let files = AiderConnector::find_chat_files(&[dir.path()]);
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn find_chat_files_respects_max_depth() {
        let dir = TempDir::new().unwrap();
        // Create deeply nested structure (6 levels deep - beyond max_depth=5)
        let deep = dir
            .path()
            .join("a")
            .join("b")
            .join("c")
            .join("d")
            .join("e")
            .join("f");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join(".aider.chat.history.md"), "# Deep").unwrap();

        let files = AiderConnector::find_chat_files(&[dir.path()]);
        // Should not find file beyond max_depth=5
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn find_chat_files_returns_empty_for_nonexistent_root() {
        let nonexistent = PathBuf::from("/nonexistent/path/to/aider");
        let files = AiderConnector::find_chat_files(&[&nonexistent]);
        assert_eq!(files.len(), 0);
    }

    #[test]
    fn find_chat_files_searches_multiple_roots() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();

        fs::write(dir1.path().join(".aider.chat.history.md"), "# Chat 1").unwrap();
        fs::write(dir2.path().join(".aider.chat.history.md"), "# Chat 2").unwrap();

        let files = AiderConnector::find_chat_files(&[dir1.path(), dir2.path()]);
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn find_chat_files_returns_sorted_order() {
        let dir = TempDir::new().unwrap();
        let project = dir.path().join("project");
        fs::create_dir_all(project.join("z")).unwrap();
        fs::create_dir_all(project.join("a")).unwrap();
        fs::write(project.join("z").join(".aider.chat.history.md"), "# z").unwrap();
        fs::write(project.join("a").join(".aider.chat.history.md"), "# a").unwrap();

        let files = AiderConnector::find_chat_files(&[dir.path()]);
        assert_eq!(files.len(), 2);

        let parents: Vec<_> = files
            .iter()
            .map(|p| {
                p.parent()
                    .and_then(|x| x.file_name())
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        assert_eq!(parents, vec!["a", "z"]);
    }

    // =====================================================
    // parse_chat_history() Tests
    // =====================================================

    #[test]
    fn parse_chat_history_parses_user_messages() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        fs::write(&history_file, "> Hello, Aider!\n> How are you?").unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(conv.messages.len(), 1);
        assert_eq!(conv.messages[0].role, "user");
        assert!(conv.messages[0].content.contains("Hello, Aider!"));
        assert!(conv.messages[0].content.contains("How are you?"));
    }

    #[test]
    fn parse_chat_history_parses_assistant_messages() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        let content = "> User message\nAssistant response here.\nMore response.";
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(conv.messages.len(), 2);
        assert_eq!(conv.messages[0].role, "user");
        assert_eq!(conv.messages[1].role, "assistant");
        assert!(conv.messages[1].content.contains("Assistant response"));
    }

    #[test]
    fn parse_chat_history_handles_conversation_flow() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        let content = r#"> First user message
First assistant response

> Second user message
Second assistant response"#;
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(conv.messages.len(), 4);
        assert_eq!(conv.messages[0].role, "user");
        assert_eq!(conv.messages[1].role, "assistant");
        assert_eq!(conv.messages[2].role, "user");
        assert_eq!(conv.messages[3].role, "assistant");
    }

    #[test]
    fn parse_chat_history_sets_agent_slug() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        fs::write(&history_file, "> Hello").unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(conv.agent_slug, "aider");
    }

    #[test]
    fn parse_chat_history_sets_workspace_to_parent() {
        let dir = TempDir::new().unwrap();
        let project = dir.path().join("my-project");
        fs::create_dir_all(&project).unwrap();
        let history_file = project.join(".aider.chat.history.md");
        fs::write(&history_file, "> Hello").unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(conv.workspace, Some(project));
    }

    #[test]
    fn parse_chat_history_sets_title() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        fs::write(&history_file, "> Hello").unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert!(conv.title.is_some());
        assert!(conv.title.unwrap().contains("Aider Chat"));
    }

    #[test]
    fn parse_chat_history_sets_external_id() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        fs::write(&history_file, "> Hello").unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(
            conv.external_id,
            Some(history_file.to_string_lossy().to_string())
        );
    }

    #[test]
    fn parse_chat_history_assigns_sequential_indices() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        let content = "> First\nResponse 1\n> Second\nResponse 2";
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(conv.messages[0].idx, 0);
        assert_eq!(conv.messages[1].idx, 1);
        assert_eq!(conv.messages[2].idx, 2);
        assert_eq!(conv.messages[3].idx, 3);
    }

    #[test]
    fn parse_chat_history_sets_author_to_role() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        let content = "> User says\nAssistant says";
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(conv.messages[0].author, Some("user".to_string()));
        assert_eq!(conv.messages[1].author, Some("assistant".to_string()));
    }

    #[test]
    fn parse_chat_history_handles_empty_file() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        fs::write(&history_file, "").unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(conv.messages.len(), 0);
    }

    #[test]
    fn parse_chat_history_handles_only_whitespace() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        fs::write(&history_file, "   \n\n   \n").unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        // Should handle gracefully (system message with whitespace may be produced)
        // The important thing is it doesn't crash
        assert!(conv.messages.is_empty() || conv.messages[0].content.trim().is_empty());
    }

    #[test]
    fn parse_chat_history_strips_quote_prefix() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        fs::write(&history_file, "> Hello world").unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(conv.messages[0].content.trim(), "Hello world");
        assert!(!conv.messages[0].content.contains("> "));
    }

    #[test]
    fn parse_chat_history_uses_file_mtime_for_timestamp() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        fs::write(&history_file, "> Hello").unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert!(conv.started_at.is_some());
        assert!(conv.ended_at.is_some());
        // Timestamp should be recent (within last minute)
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap_or(i64::MAX);
        assert!(conv.started_at.unwrap() > now - 60000);
    }

    // =====================================================
    // scan() Tests
    // =====================================================

    #[test]
    fn scan_finds_and_parses_history_files() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        fs::write(&history_file, "> Hello Aider\nHello! How can I help?").unwrap();

        let connector = AiderConnector::new();
        let ctx = ScanContext::local_default(dir.path().to_path_buf(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].agent_slug, "aider");
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn scan_handles_empty_directory() {
        let dir = TempDir::new().unwrap();

        let connector = AiderConnector::new();
        let ctx = ScanContext::local_default(dir.path().to_path_buf(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_finds_multiple_history_files() {
        let dir = TempDir::new().unwrap();
        let proj1 = dir.path().join("project1");
        let proj2 = dir.path().join("project2");
        fs::create_dir_all(&proj1).unwrap();
        fs::create_dir_all(&proj2).unwrap();

        fs::write(proj1.join(".aider.chat.history.md"), "> Hello 1").unwrap();
        fs::write(proj2.join(".aider.chat.history.md"), "> Hello 2").unwrap();

        let connector = AiderConnector::new();
        let ctx = ScanContext::local_default(dir.path().to_path_buf(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn scan_sets_source_path() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        fs::write(&history_file, "> Hello").unwrap();

        let connector = AiderConnector::new();
        let ctx = ScanContext::local_default(dir.path().to_path_buf(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].source_path, history_file);
    }

    // =====================================================
    // Edge Cases
    // =====================================================

    #[test]
    fn parse_chat_history_handles_multiline_user_message() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        let content = "> Line 1\n> Line 2\n> Line 3\nAssistant response";
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        // User message should contain all three lines
        assert!(conv.messages[0].content.contains("Line 1"));
        assert!(conv.messages[0].content.contains("Line 2"));
        assert!(conv.messages[0].content.contains("Line 3"));
    }

    #[test]
    fn parse_chat_history_handles_code_blocks() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        let content = r#"> Add a function
Here's the code:
```python
def hello():
    print("Hello")
```
Done!"#;
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(conv.messages.len(), 2);
        assert!(conv.messages[1].content.contains("```python"));
        assert!(conv.messages[1].content.contains("def hello"));
    }

    #[test]
    fn parse_chat_history_handles_special_characters() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        let content = "> What does `foo()` do?\nThe function `foo()` returns \"bar\".";
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert!(conv.messages[0].content.contains("`foo()`"));
        assert!(conv.messages[1].content.contains("\"bar\""));
    }

    // =====================================================
    // Edge case tests — malformed input robustness (br-2w98)
    // =====================================================

    #[test]
    fn parse_chat_history_invalid_utf8_returns_error() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        // Write invalid UTF-8 bytes
        fs::write(&history_file, b"\xFF\xFE invalid utf8 bytes here").unwrap();

        let connector = AiderConnector::new();
        let result = connector.parse_chat_history(&history_file);
        // fs::read_to_string will fail on invalid UTF-8
        assert!(result.is_err(), "invalid UTF-8 file should return an error");
    }

    #[test]
    fn parse_chat_history_large_file_handled() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        // Create a 1MB file with repeated user/assistant exchanges
        let mut content = String::new();
        for i in 0..1000 {
            content.push_str(&format!("> User message number {i}\n"));
            content.push_str(&format!("Assistant response number {i}\n\n"));
        }
        fs::write(&history_file, &content).unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert!(
            conv.messages.len() >= 2000,
            "large file should produce many messages"
        );
    }

    #[test]
    fn parse_chat_history_bare_quote_marker_only() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        // Lines with just ">" and no content
        let content = ">\n>\n>\nAssistant response";
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let result = connector.parse_chat_history(&history_file);
        assert!(result.is_ok(), "bare quote markers should not cause errors");
    }

    #[test]
    fn parse_chat_history_only_user_messages_no_assistant() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        let content = "> First user message\n> Second user message\n> Third user message";
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        // All user messages should be in a single user message
        assert_eq!(conv.messages.len(), 1);
        assert_eq!(conv.messages[0].role, "user");
    }

    #[test]
    fn parse_chat_history_only_assistant_no_user() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        // No ">" prefix = not a user message; starts as system role
        let content = "Just some text without any quote markers\nMore text here";
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        // Should produce a system message
        assert!(!conv.messages.is_empty());
        assert_eq!(conv.messages[0].role, "system");
    }

    #[test]
    fn parse_chat_history_very_long_single_line() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        let long_line = format!("> {}", "x".repeat(1_000_000));
        fs::write(&history_file, &long_line).unwrap();

        let connector = AiderConnector::new();
        let conv = connector.parse_chat_history(&history_file).unwrap();

        assert_eq!(conv.messages.len(), 1);
        assert_eq!(conv.messages[0].content.len(), 1_000_000);
    }

    #[test]
    fn parse_chat_history_null_bytes_in_content() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        let content = "> Hello\0World\nResponse\0here";
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let result = connector.parse_chat_history(&history_file);
        assert!(result.is_ok(), "null bytes should not cause errors");
    }

    #[test]
    fn parse_chat_history_bom_marker_at_start() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        // UTF-8 BOM followed by valid content
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xEF\xBB\xBF> Hello after BOM\n");
        bytes.extend_from_slice(b"Assistant response\n");
        fs::write(&history_file, &bytes).unwrap();

        let connector = AiderConnector::new();
        let result = connector.parse_chat_history(&history_file);
        assert!(result.is_ok(), "BOM marker should not cause errors");
        let conv = result.unwrap();
        // BOM may affect first line parsing but shouldn't crash
        assert!(!conv.messages.is_empty());
    }

    #[test]
    fn parse_chat_history_nonexistent_file_returns_error() {
        let connector = AiderConnector::new();
        let result = connector.parse_chat_history(Path::new("/nonexistent/file.md"));
        assert!(result.is_err(), "nonexistent file should return error");
    }

    #[test]
    fn parse_chat_history_mixed_line_endings() {
        let dir = TempDir::new().unwrap();
        let history_file = dir.path().join(".aider.chat.history.md");
        // Mix of \r\n (Windows) and \n (Unix) line endings
        let content = "> Hello\r\n> World\r\nAssistant response\nMore response\r\n";
        fs::write(&history_file, content).unwrap();

        let connector = AiderConnector::new();
        let result = connector.parse_chat_history(&history_file);
        assert!(result.is_ok(), "mixed line endings should not cause errors");
        let conv = result.unwrap();
        assert!(
            conv.messages.len() >= 2,
            "should extract user and assistant messages"
        );
    }
}
