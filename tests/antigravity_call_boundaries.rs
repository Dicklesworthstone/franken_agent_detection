//! Provider boundaries must survive filtering of empty display records.
#![cfg(feature = "connectors")]

use std::fs;

use franken_agent_detection::{
    AntigravityConnector, Connector, NormalizedConversation, ScanContext, ScanRoot,
    extract_tokens_for_agent,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn scan(records: &[Value]) -> NormalizedConversation {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join(
        "brain/11111111-2222-4333-8444-555555555555/.system_generated/logs/transcript.jsonl",
    );
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let context = ScanContext::with_roots(
        directory.path().join("unused-index"),
        vec![ScanRoot::local(directory.path().to_path_buf())],
        None,
    );
    let mut conversations = AntigravityConnector::new().scan(&context).unwrap();
    assert_eq!(conversations.len(), 1);
    conversations.pop().unwrap()
}

fn planner(step: i64) -> Value {
    json!({
        "step_index": step, "source": "MODEL", "type": "PLANNER_RESPONSE",
        "status": "DONE", "model": "gemini-4-neon-high",
        "tool_calls": [{
            "id": "turn-local-read", "name": "read_file",
            "args": {"Path": "/synthetic/example.rs"},
        }],
    })
}

fn result(step: i64) -> Value {
    json!({
        "step_index": step, "source": "MODEL", "type": "READ_FILE",
        "status": "DONE", "call_id": "turn-local-read",
        "content": format!("Synthetic file contents from step {step}."),
    })
}

fn assert_call_counts(conversation: &NormalizedConversation, expected: &[u32]) {
    assert_eq!(conversation.messages.len(), expected.len());
    for (index, (message, expected)) in conversation.messages.iter().zip(expected).enumerate() {
        assert_eq!(message.idx, i64::try_from(index).unwrap());
        assert_eq!(message.invocations.len(), usize::try_from(*expected).unwrap());
        let usage = extract_tokens_for_agent(
            "antigravity",
            &message.extra,
            &message.content,
            &message.role,
        );
        assert_eq!(usage.tool_call_count, *expected, "message {index}");
        assert_eq!(usage.has_tool_calls, *expected > 0, "message {index}");
    }
}

#[test]
fn empty_checkpoints_reset_call_ownership_without_creating_messages() {
    let checkpoint = json!({
        "step_index": 3, "source": "SYSTEM", "type": "CHECKPOINT",
        "status": "DONE", "content": null,
    });
    // Physical order is deliberately scrambled. Repeated empty checkpoint
    // markers remain harmless after ordering by the provider's step index.
    let conversation = scan(&[
        result(4),
        planner(1),
        checkpoint.clone(),
        result(2),
        checkpoint,
    ]);
    assert_call_counts(&conversation, &[1, 0, 1]);
    assert_eq!(
        conversation.messages[1].extra["cass"]["referenced_tool_call_ids"],
        json!(["turn-local-read"])
    );
    assert!(
        conversation.messages[2].extra["cass"]
            .get("referenced_tool_call_ids")
            .is_none()
    );
}

#[test]
fn settings_only_user_input_resets_call_ownership_without_creating_messages() {
    let conversation = scan(&[
        planner(1),
        result(2),
        json!({
            "step_index": 3, "source": "USER_EXPLICIT", "type": "USER_INPUT",
            "status": "DONE",
            "content": "<USER_REQUEST> \n </USER_REQUEST>\n<USER_SETTINGS_CHANGE>The user changed setting `Model Selection` from Gemini 4 Neon to Claude Sonnet.</USER_SETTINGS_CHANGE>",
        }),
        // A historical standalone tool after the new turn may recycle an ID.
        result(4),
        planner(5),
        result(6),
    ]);
    assert_call_counts(&conversation, &[1, 0, 1, 1, 0]);
    assert!(conversation.messages.iter().all(|message| message.role != "user"));
    assert_eq!(
        conversation.messages[4].extra["cass"]["referenced_tool_call_ids"],
        json!(["turn-local-read"])
    );
}

#[test]
fn unrelated_filtered_records_keep_same_turn_request_result_links() {
    let conversation = scan(&[
        planner(1),
        json!({
            "step_index": 2, "source": "SYSTEM", "type": "CONVERSATION_HISTORY",
            "content": null,
        }),
        json!({
            "step_index": 3, "source": "SYSTEM", "type": "SYSTEM_MESSAGE",
            "content": "  ",
        }),
        result(4),
    ]);
    assert_call_counts(&conversation, &[1, 0]);
    assert_eq!(
        conversation.messages[1].extra["cass"]["referenced_tool_call_ids"],
        json!(["turn-local-read"])
    );
}
