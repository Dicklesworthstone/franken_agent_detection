//! Placeholder aliases must not erase native Antigravity tool arguments.
#![cfg(feature = "connectors")]

use std::fs;

use franken_agent_detection::{
    AntigravityConnector, Connector, NormalizedConversation, ScanContext, ScanRoot,
};
use serde_json::{Value, json};
use tempfile::TempDir;

fn scan_call(call: Value) -> NormalizedConversation {
    let temp = TempDir::new().unwrap();
    let path = temp
        .path()
        .join("brain/11111111-2222-4333-8444-555555555555/.system_generated/logs/transcript.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let records = [
        json!({
            "step_index": 0,
            "type": "USER_INPUT",
            "source": "USER_EXPLICIT",
            "content": "Inspect the synthetic tool arguments"
        }),
        json!({
            "step_index": 1,
            "type": "PLANNER_RESPONSE",
            "source": "MODEL",
            "model": "gemini-test",
            "input_tokens": 5,
            "output_tokens": 2,
            "tool_calls": [call.clone()]
        }),
        json!({
            "step_index": 2,
            "type": "RUN_COMMAND",
            "source": "MODEL",
            "content": "Synthetic tool result",
            "tool_call_id": "call-1"
        }),
    ];
    let jsonl = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&path, jsonl).unwrap();
    let ctx = ScanContext::with_roots(
        temp.path().to_path_buf(),
        vec![ScanRoot::local(temp.path().to_path_buf())],
        None,
    );
    let mut conversations = AntigravityConnector::new().scan(&ctx).unwrap();
    assert_eq!(conversations.len(), 1);
    let conversation = conversations.pop().unwrap();
    assert_eq!(conversation.messages.len(), 3);
    let planner = &conversation.messages[1];
    assert!(planner.content.is_empty());
    assert_eq!(planner.invocations.len(), 1);
    assert_eq!(planner.invocations[0].call_id.as_deref(), Some("call-1"));
    assert_eq!(planner.extra["tool_calls"], json!([call]));
    assert_eq!(planner.extra["cass"]["tool_call_count"], 1);
    assert_eq!(planner.extra["usage"]["input_tokens"], 5);
    assert_eq!(planner.extra["usage"]["output_tokens"], 2);
    let result = &conversation.messages[2];
    assert!(result.invocations.is_empty());
    assert_eq!(result.extra["cass"]["tool_call_count"], 0);
    assert_eq!(
        result.extra["cass"]["referenced_tool_call_ids"],
        json!(["call-1"])
    );
    conversation
}

#[test]
fn null_and_blank_aliases_preserve_native_skill_arguments_and_call_ownership() {
    let arguments = json!({"name": "review", "args": {"path": "synthetic.rs"}});
    for placeholder in [
        Value::Null,
        json!(""),
        json!(" \t"),
        json!("null"),
        json!("\"\""),
    ] {
        for native in [arguments.clone(), json!(arguments.to_string())] {
            let conversation = scan_call(json!({
                "id": "call-1",
                "name": "skill",
                "arguments": placeholder.clone(),
                "args": native
            }));
            let invocation = &conversation.messages[1].invocations[0];
            assert_eq!(invocation.kind, "skill");
            assert_eq!(invocation.name, "review");
            assert_eq!(invocation.raw_name.as_deref(), Some("skill"));
            assert_eq!(invocation.arguments, Some(arguments.clone()));
        }
    }
}

#[test]
fn placeholder_aliases_fall_through_input_and_nested_function_arguments() {
    let expected = json!({"command": "printf synthetic"});
    for call in [
        json!({
            "id": "call-1",
            "name": "run_command",
            "arguments": null,
            "args": " ",
            "input": expected.clone()
        }),
        json!({
            "id": "call-1",
            "function": {
                "name": "run_command",
                "arguments": expected.to_string()
            },
            "arguments": null,
            "args": "null",
            "input": ""
        }),
    ] {
        let conversation = scan_call(call);
        let invocation = &conversation.messages[1].invocations[0];
        assert_eq!(invocation.name, "run_command");
        assert_eq!(invocation.arguments, Some(expected.clone()));
    }
}

#[test]
fn meaningful_higher_priority_arguments_keep_historical_precedence() {
    for expected in [
        json!({"command": "preferred"}),
        json!({}),
        json!([]),
        json!(0),
        json!(false),
        json!("opaque historical argument text"),
        json!("{incomplete JSON retained verbatim"),
    ] {
        let conversation = scan_call(json!({
            "id": "call-1",
            "name": "run_command",
            "arguments": expected.clone(),
            "args": {"command": "must not replace the first value"}
        }));
        assert_eq!(
            conversation.messages[1].invocations[0].arguments,
            Some(expected)
        );
    }

    let expected = json!({"command": "encoded preferred"});
    let conversation = scan_call(json!({
        "id": "call-1",
        "name": "run_command",
        "arguments": expected.to_string(),
        "args": {"command": "lower priority"}
    }));
    assert_eq!(
        conversation.messages[1].invocations[0].arguments,
        Some(expected)
    );
}

#[test]
fn missing_arguments_and_unresolved_placeholders_remain_lossless() {
    let conversation = scan_call(json!({"id": "call-1", "name": "run_command"}));
    assert!(conversation.messages[1].invocations[0].arguments.is_none());

    for (raw, decoded) in [
        (Value::Null, Value::Null),
        (json!(""), json!("")),
        (json!(" \t"), json!(" \t")),
        (json!("null"), Value::Null),
    ] {
        let conversation = scan_call(json!({
            "id": "call-1",
            "name": "run_command",
            "arguments": raw,
            "args": null,
            "input": ""
        }));
        assert_eq!(
            conversation.messages[1].invocations[0].arguments,
            Some(decoded)
        );
    }
}
