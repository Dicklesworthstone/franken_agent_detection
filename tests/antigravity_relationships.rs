//! Synthetic provider records exercise identity and invocation ownership at
//! the public connector boundary. All paths, IDs and content are invented.
#![cfg(feature = "connectors")]

use std::fs;
use std::path::{Path, PathBuf};

use franken_agent_detection::{
    AntigravityConnector, Connector, NormalizedConversation, ScanContext, ScanRoot,
    extract_tokens_for_agent,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const PARENT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const CHILD: &str = "11111111-2222-4333-8444-555555555555";
const CHILD_TRANSCRIPT: &str = include_str!("fixtures/antigravity/child_transcript.jsonl");

fn write_transcript(base: &Path, id: &str, transcript: &str) -> PathBuf {
    let path = base
        .join("brain")
        .join(id)
        .join(".system_generated/logs/transcript.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, transcript).unwrap();
    path
}

fn scan(base: &Path) -> Vec<NormalizedConversation> {
    let context = ScanContext::with_roots(
        base.join("unused-index"),
        vec![ScanRoot::local(base.to_path_buf())],
        None,
    );
    AntigravityConnector::new().scan(&context).unwrap()
}

#[test]
fn ide_and_cli_children_reference_their_own_parents_external_ids() {
    let directory = TempDir::new().unwrap();
    for store in ["antigravity", "antigravity-cli"] {
        let base = directory.path().join(".gemini").join(store);
        write_transcript(&base, CHILD, CHILD_TRANSCRIPT);
        write_transcript(
            &base,
            PARENT,
            &json!({
                "step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT",
                "content": "Review the synthetic parser fixture.",
            })
            .to_string(),
        );
    }

    let conversations = scan(directory.path());
    assert_eq!(conversations.len(), 4);
    for (prefix, layout) in [("ide/", "ide"), ("", "cli")] {
        let child_id = format!("{prefix}{CHILD}");
        let parent_id = format!("{prefix}{PARENT}");
        let child = conversations
            .iter()
            .find(|conversation| conversation.external_id.as_deref() == Some(&child_id))
            .unwrap();
        let parent = conversations
            .iter()
            .find(|conversation| conversation.external_id.as_deref() == Some(&parent_id))
            .unwrap();
        assert_eq!(child.metadata["layout"], layout);
        assert_eq!(child.metadata["parent_conversation_id"], parent_id);
        assert_eq!(child.metadata["raw_parent_conversation_id"], PARENT);
        assert_eq!(
            child.metadata["parent_conversation_id"].as_str(),
            parent.external_id.as_deref()
        );
        assert!(parent.metadata.get("parent_conversation_id").is_none());
    }
}

#[test]
fn relocated_store_keeps_historical_bare_parent_identity() {
    let directory = TempDir::new().unwrap();
    write_transcript(directory.path(), CHILD, CHILD_TRANSCRIPT);
    let conversations = scan(directory.path());
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0].external_id.as_deref(), Some(CHILD));
    assert_eq!(conversations[0].metadata["parent_conversation_id"], PARENT);
    assert_eq!(
        conversations[0].metadata["raw_parent_conversation_id"],
        PARENT
    );
}

#[test]
fn parent_is_only_taken_from_an_initial_system_envelope_header() {
    let directory = TempDir::new().unwrap();
    let cases = [
        (
            0,
            "SYSTEM",
            format!("[Message] content=Example sender={PARENT}"),
        ),
        (
            0,
            "SYSTEM",
            format!("Quoted example [Message] sender={PARENT} content=hello"),
        ),
        (
            0,
            "SYSTEM",
            format!("[Message] notsender={PARENT} content=hello"),
        ),
        (
            0,
            "MODEL",
            format!("[Message] sender={PARENT} content=hello"),
        ),
        (
            1,
            "SYSTEM",
            format!("[Message] sender={PARENT} content=hello"),
        ),
        (
            0,
            "SYSTEM",
            "[Message] sender=not-a-uuid content=hello".to_string(),
        ),
        (
            0,
            "SYSTEM",
            format!("[Message] sender={CHILD} content=hello"),
        ),
    ];
    for (step_index, source, content) in cases {
        write_transcript(
            directory.path(),
            CHILD,
            &json!({
                "step_index": step_index, "source": source, "type": "SYSTEM_MESSAGE",
                "content": content,
            })
            .to_string(),
        );
        let conversations = scan(directory.path());
        assert_eq!(conversations.len(), 1);
        assert!(
            conversations[0]
                .metadata
                .get("parent_conversation_id")
                .is_none(),
            "must not derive a parent from {step_index}/{source}: {content}"
        );
    }
}

#[test]
fn planner_owns_identified_calls_and_idless_repeats_remain_independent() {
    let directory = TempDir::new().unwrap();
    let path = write_transcript(directory.path(), CHILD, CHILD_TRANSCRIPT);
    let before = fs::metadata(&path).unwrap().modified().unwrap();
    let conversations = scan(directory.path());
    let conversation = &conversations[0];
    assert_eq!(conversation.messages.len(), 7);
    assert_eq!(conversation.messages[2].invocations.len(), 1);
    assert_eq!(
        conversation.messages[2].invocations[0].call_id.as_deref(),
        Some("fixture-read-1")
    );
    let result = &conversation.messages[3];
    assert_eq!(result.role, "tool");
    assert_eq!(result.content, "pub fn parse_fixture() -> bool { true }");
    assert!(
        result.invocations.is_empty(),
        "a result is not a second call"
    );
    assert_eq!(result.extra["cass"]["tool_call_count"], 0);
    // CASS persists `extra`, while its canonical Message has no dedicated
    // invocation field. Retain the provider payload on calls and results;
    // the explicit normalized count, including zero, controls analytics.
    let source_records: Vec<Value> = CHILD_TRANSCRIPT
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let archive_shape = serde_json::to_value(&conversation.messages).unwrap();
    for index in [2, 3, 4, 5] {
        assert_eq!(
            archive_shape[index]["extra"]["tool_calls"],
            source_records[index]["tool_calls"]
        );
    }
    for message in &conversation.messages[4..6] {
        assert!(message.content.is_empty(), "tool-only turns survive");
        assert_eq!(message.invocations.len(), 1);
        assert_eq!(message.invocations[0].call_id, None);
        assert_eq!(message.invocations[0].name, "run_command");
    }
    let invocation_count: usize = conversation
        .messages
        .iter()
        .map(|message| message.invocations.len())
        .sum();
    let analytics_count: u32 = conversation
        .messages
        .iter()
        .map(|message| {
            extract_tokens_for_agent(
                "antigravity",
                &message.extra,
                &message.content,
                &message.role,
            )
            .tool_call_count
        })
        .sum();
    assert_eq!(invocation_count, 3);
    assert_eq!(analytics_count, 3);

    let replay = scan(directory.path());
    assert_eq!(
        serde_json::to_value(&conversations).unwrap(),
        serde_json::to_value(&replay).unwrap()
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), CHILD_TRANSCRIPT);
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
}

#[test]
fn duplicate_call_ids_within_a_planner_are_counted_once_but_blank_ids_are_not_keys() {
    let directory = TempDir::new().unwrap();
    let calls: Vec<Value> = ["read-1", "read-1", "", "  "]
        .into_iter()
        .map(|id| json!({"id": id, "name": "read_file", "args": {"Path": "/synthetic/a.rs"}}))
        .collect();
    write_transcript(
        directory.path(),
        CHILD,
        &json!({
            "step_index": 0, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "tool_calls": calls,
        })
        .to_string(),
    );
    let conversations = scan(directory.path());
    let message = &conversations[0].messages[0];
    assert_eq!(message.invocations.len(), 3);
    assert_eq!(
        extract_tokens_for_agent(
            "antigravity",
            &message.extra,
            &message.content,
            &message.role
        )
        .tool_call_count,
        3
    );
}

#[test]
fn conversation_model_follows_step_order_while_messages_keep_their_own_models() {
    let directory = TempDir::new().unwrap();
    let records = [
        json!({
            "step_index": 20, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "model": "claude-sonnet-4-5", "content": "Later model response.",
        }),
        json!({
            "step_index": 0, "source": "USER_EXPLICIT", "type": "USER_INPUT",
            "content": "<USER_REQUEST>\nInspect the fixture.\n</USER_REQUEST>\n<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 4 Neon (High).\n</USER_SETTINGS_CHANGE>",
        }),
        json!({
            "step_index": 10, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "model": "gemini-4-neon-high", "content": "First model response.",
        }),
    ];
    let transcript = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    write_transcript(directory.path(), CHILD, &transcript);
    let conversations = scan(directory.path());
    let conversation = &conversations[0];
    assert_eq!(conversation.metadata["model"], "gemini-4-neon-high");
    assert_eq!(conversation.messages[0].role, "user");
    assert_eq!(
        conversation.messages[1].extra["model"],
        "gemini-4-neon-high"
    );
    assert_eq!(conversation.messages[2].extra["model"], "claude-sonnet-4-5");
    assert_eq!(conversation.messages[1].content, "First model response.");
    assert_eq!(conversation.messages[2].content, "Later model response.");
}

#[test]
fn reused_call_ids_on_distinct_planner_steps_count_each_request_once() {
    let directory = TempDir::new().unwrap();
    let records = [
        json!({
            "step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "tool_calls": [{"id": "turn-local-id", "name": "read_file", "args": {"Path": "/synthetic/first.rs"}}],
        }),
        json!({
            "step_index": 2, "source": "MODEL", "type": "READ_FILE",
            "tool_call_id": "turn-local-id", "content": "First file contents.",
        }),
        json!({
            "step_index": 3, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "tool_calls": [{"id": "turn-local-id", "name": "read_file", "args": {"Path": "/synthetic/second.rs"}}],
        }),
        json!({
            "step_index": 4, "source": "MODEL", "type": "READ_FILE",
            "tool_call_id": "turn-local-id", "content": "Second file contents.",
        }),
    ];
    let transcript = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    write_transcript(directory.path(), CHILD, &transcript);
    let conversations = scan(directory.path());
    let messages = &conversations[0].messages;
    assert_eq!(messages.len(), 4);
    for (index, expected) in [1, 0, 1, 0].into_iter().enumerate() {
        let message = &messages[index];
        assert_eq!(message.invocations.len(), expected, "message {index}");
        assert_eq!(
            usize::try_from(
                extract_tokens_for_agent(
                    "antigravity",
                    &message.extra,
                    &message.content,
                    &message.role,
                )
                .tool_call_count
            )
            .unwrap(),
            expected,
            "message {index}",
        );
    }
    assert_eq!(
        messages[0].invocations[0].arguments,
        Some(json!({"Path": "/synthetic/first.rs"}))
    );
    assert_eq!(
        messages[2].invocations[0].arguments,
        Some(json!({"Path": "/synthetic/second.rs"}))
    );
}

#[test]
fn compaction_and_user_boundaries_clear_previous_tool_request_correlations() {
    let directory = TempDir::new().unwrap();
    let records = [
        json!({
            "step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "tool_calls": [{"id": "recycled-id", "name": "read_file"}],
        }),
        json!({
            "step_index": 2, "source": "MODEL", "type": "READ_FILE",
            "call_id": "recycled-id", "content": "Result before compaction.",
        }),
        json!({
            "step_index": 3, "source": "SYSTEM", "type": "CHECKPOINT",
            "content": "Compacted context.", "input_tokens": 10, "output_tokens": 5,
        }),
        json!({
            "step_index": 4, "source": "MODEL", "type": "READ_FILE",
            "call_id": "recycled-id", "content": "Standalone historical tool step after compaction.",
        }),
        json!({
            "step_index": 5, "source": "MODEL", "type": "PLANNER_RESPONSE",
            "tool_calls": [{"id": "recycled-id", "name": "read_file"}],
        }),
        json!({
            "step_index": 6, "source": "USER_EXPLICIT", "type": "USER_INPUT",
            "content": "Start another task.",
        }),
        json!({
            "step_index": 7, "source": "MODEL", "type": "READ_FILE",
            "call_id": "recycled-id", "content": "Standalone historical tool step for the new task.",
        }),
    ];
    let transcript = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    write_transcript(directory.path(), CHILD, &transcript);
    let conversations = scan(directory.path());
    let messages = &conversations[0].messages;
    assert_eq!(messages.len(), 7);
    for (index, expected) in [1, 0, 0, 1, 1, 0, 1].into_iter().enumerate() {
        let message = &messages[index];
        assert_eq!(message.invocations.len(), expected, "message {index}");
        assert_eq!(
            usize::try_from(
                extract_tokens_for_agent(
                    "antigravity",
                    &message.extra,
                    &message.content,
                    &message.role,
                )
                .tool_call_count
            )
            .unwrap(),
            expected,
            "message {index}",
        );
    }
}
