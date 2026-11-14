//! Line-oriented transcript reads and bounded recovery of complete records.

use serde_json::Value;
use std::io::{self, BufRead};
use std::iter::FusedIterator;

/// Largest malformed physical line inspected for a complete suffix (8 MiB).
pub const MAX_JSONL_RECOVERY_LINE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum total suffix bytes parsed while recovering one line (16 MiB).
pub const MAX_JSONL_RECOVERY_PARSE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum candidate record starts tried while recovering one line.
pub const MAX_JSONL_RECOVERY_ATTEMPTS: usize = 64;
/// Maximum complete records recovered from one physical line.
pub const MAX_JSONL_RECOVERY_RECORDS: usize = 1024;

/// Complete trailing records and the exact malformed prefix that precedes them.
///
/// Byte offsets refer to the supplied string, including any whitespace or BOM.
/// If recovery fails, `records` is empty and `discarded_bytes` is the whole
/// line length. The caller retains the original source and can quarantine just
/// `&line[..discarded_bytes]` without discarding successfully recovered records.
#[derive(Debug, Default)]
pub struct JsonlRecovery {
    pub records: Vec<Value>,
    pub discarded_bytes: usize,
    pub limited: bool,
}

/// Recognise session envelopes, never arbitrary nested text or tool blocks.
/// Intact JSONL records bypass this recovery-only restriction.
fn is_recoverable_record(value: &Value) -> bool {
    fn content(value: &Value) -> bool {
        value
            .get("content")
            .is_some_and(|content| content.is_string() || content.is_array())
    }

    fn message(value: &Value) -> bool {
        matches!(
            value.get("role").and_then(Value::as_str),
            Some(
                "user"
                    | "assistant"
                    | "system"
                    | "developer"
                    | "tool"
                    | "toolResult"
                    | "tool_result"
                    | "function"
            )
        ) && content(value)
    }

    fn has_id(value: &Value) -> bool {
        value
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
    }

    if message(value) {
        return true;
    }
    match value.get("type").and_then(Value::as_str) {
        Some("message") => has_id(value) && value.get("message").is_some_and(message),
        Some(role @ ("user" | "assistant")) => value.get("message").is_some_and(|inner| {
            message(inner) && inner.get("role").and_then(Value::as_str) == Some(role)
        }),
        Some("session") => has_id(value),
        // Pi control records can follow a complete message on the same torn
        // line. Retain their provenance instead of rejecting the whole suffix
        // merely because a later record contributes no searchable text.
        Some("model_change") => {
            has_id(value)
                && value
                    .get("modelId")
                    .or_else(|| value.get("model"))
                    .is_some_and(Value::is_string)
        }
        Some("thinking_level_change") => {
            has_id(value) && value.get("thinkingLevel").is_some_and(Value::is_string)
        }
        Some("session_info") => has_id(value) && value.get("name").is_some_and(Value::is_string),
        Some("label") => has_id(value) && value.get("targetId").is_some_and(Value::is_string),
        Some("custom") => has_id(value) && value.get("customType").is_some_and(Value::is_string),
        Some("custom_message") => has_id(value) && content(value),
        Some("compaction" | "branch_summary") => {
            has_id(value) && value.get("summary").is_some_and(Value::is_string)
        }
        Some("title" | "ai-title") => value.get("title").is_some_and(Value::is_string),
        Some("session_meta" | "response_item" | "event_msg" | "turn_context") => {
            let timestamp = value
                .get("timestamp")
                .is_some_and(|timestamp| timestamp.is_string() || timestamp.is_number());
            let Some(payload) = value.get("payload").filter(|payload| payload.is_object()) else {
                return false;
            };
            timestamp
                && match value.get("type").and_then(Value::as_str) {
                    Some("session_meta") => has_id(payload),
                    Some("turn_context") => true,
                    _ => payload
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| !kind.is_empty()),
                }
        }
        _ => false,
    }
}

/// Recover a complete suffix of session records after a torn JSONL prefix.
///
/// Only call this after the ordinary parser rejects a physical line. Search
/// from the start, not the error column: a tear inside a string can consume the
/// next record's opening brace before the parser notices the damage. Accept
/// the leftmost suffix of known object records with no trailing garbage.
///
/// Braces after ':', '[' or ',' (ignoring ASCII whitespace) are ambiguous
/// nested-value boundaries, so they are refused even if the suffix decodes.
/// Recovery never manufactures history from a nested message whose enclosing
/// record is unfinished. Work, input size and recovered record count are bounded.
#[must_use]
pub fn recover_jsonl_suffix(line: &str) -> JsonlRecovery {
    let mut unrecovered = JsonlRecovery {
        discarded_bytes: line.len(),
        ..JsonlRecovery::default()
    };
    if line.len() > MAX_JSONL_RECOVERY_LINE_BYTES {
        unrecovered.limited = true;
        return unrecovered;
    }

    let mut remaining_parse_bytes = MAX_JSONL_RECOVERY_PARSE_BYTES;
    let mut attempts = 0;
    let mut previous_non_whitespace = None;
    for (offset, byte) in line.bytes().enumerate() {
        let previous = previous_non_whitespace;
        if !byte.is_ascii_whitespace() {
            previous_non_whitespace = Some(byte);
        }
        if byte != b'{' || matches!(previous, Some(b':' | b'[' | b',')) {
            continue;
        }

        // An ASCII opening brace is always a UTF-8 character boundary.
        let suffix = &line[offset..];
        // A recognised object envelope starts with a quoted field name.
        if suffix[1..]
            .trim_start_matches(|ch: char| ch.is_ascii_whitespace())
            .as_bytes()
            .first()
            != Some(&b'"')
        {
            continue;
        }
        if attempts >= MAX_JSONL_RECOVERY_ATTEMPTS || suffix.len() > remaining_parse_bytes {
            unrecovered.limited = true;
            return unrecovered;
        }
        attempts += 1;
        remaining_parse_bytes -= suffix.len();

        let mut records = Vec::new();
        let mut complete = true;
        for parsed in serde_json::Deserializer::from_str(suffix).into_iter::<Value>() {
            let Ok(record) = parsed else {
                complete = false;
                break;
            };
            if !is_recoverable_record(&record) {
                complete = false;
                break;
            }
            if records.len() >= MAX_JSONL_RECOVERY_RECORDS {
                unrecovered.limited = true;
                return unrecovered;
            }
            records.push(record);
        }
        if complete && !records.is_empty() {
            return JsonlRecovery {
                records,
                discarded_bytes: offset,
                limited: false,
            };
        }
    }
    unrecovered
}

/// Parse an intact record or recover complete records from a torn JSONL line.
///
/// Ordinary JSON parsing is unchanged, including arbitrary intact values and
/// the providers' optional leading BOM. Pass the original physical line without
/// its LF/CRLF terminator: recovery counts its BOM and whitespace in the byte
/// budget, matching diagnostics and exact quarantine offsets.
/// Call [`recover_jsonl_suffix`] directly after a parse error when diagnostic
/// details about discarded bytes or recovery limits are needed.
pub fn parse_jsonl_line(line: &str) -> impl Iterator<Item = Value> + use<> {
    let (intact, recovered) = match serde_json::from_str(line.trim_start_matches('\u{feff}')) {
        Ok(value) => (Some(value), Vec::new()),
        Err(_) => (None, recover_jsonl_suffix(line).records),
    };
    intact.into_iter().chain(recovered)
}

/// Read UTF-8 lines, skipping corrupt records but stopping at reader failures.
///
/// UTF-8 is checked only after a complete physical line was read successfully.
/// An I/O error, including an underlying `InvalidData`, is returned unchanged
/// exactly once. Further iteration never reads again, so a failing source
/// cannot cause an unbounded error-and-retry loop. Callers must discard any
/// accumulated conversation when an error occurs.
#[derive(Debug)]
pub struct JsonlLines<R> {
    reader: R,
    done: bool,
}

impl<R: BufRead> JsonlLines<R> {
    pub const fn new(reader: R) -> Self {
        Self {
            reader,
            done: false,
        }
    }

    fn read_line_bytes(&mut self, bytes: &mut Vec<u8>) -> io::Result<usize> {
        loop {
            // Read bytes directly: read_line() conflates invalid UTF-8 with an
            // underlying InvalidData error. Do not retry an actual I/O error,
            // even Interrupted, without evidence that the source progressed.
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                self.done = true;
                return Ok(bytes.len());
            }
            let newline = available.iter().position(|&byte| byte == b'\n');
            let consumed = newline.map_or(available.len(), |index| index + 1);
            bytes.extend_from_slice(&available[..consumed]);
            self.reader.consume(consumed);
            if newline.is_some() {
                return Ok(bytes.len());
            }
        }
    }
}

impl<R: BufRead> Iterator for JsonlLines<R> {
    type Item = io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut bytes = Vec::new();
        loop {
            if self.done {
                return None;
            }
            match self.read_line_bytes(&mut bytes) {
                Ok(0) => {
                    self.done = true;
                    return None;
                }
                Ok(_) => {}
                Err(error) => {
                    self.done = true;
                    return Some(Err(error));
                }
            }

            // Match std::io::Lines: strip LF and its optional preceding CR,
            // but retain a standalone CR or a final line without a newline.
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
                if bytes.last() == Some(&b'\r') {
                    bytes.pop();
                }
            }
            match String::from_utf8(bytes) {
                Ok(line) => return Some(Ok(line)),
                Err(error) => {
                    bytes = error.into_bytes();
                    bytes.clear();
                }
            }
        }
    }
}

impl<R: BufRead> FusedIterator for JsonlLines<R> {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{Cursor, ErrorKind, Read};
    use std::rc::Rc;

    use super::*;

    #[test]
    fn recovery_finds_record_start_before_the_parse_error_and_keeps_exact_bytes() {
        let prefix = "\u{feff} \t{\"type\":\"message\",\"id\":\"torn\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"thinking\",\"thinkingSignature\":\"署名";
        let tool = serde_json::json!({
            "type": "message", "id": "tool",
            "message": {"role": "toolResult", "toolCallId": "call_1", "toolName": "bash",
                "content": [{"type": "text", "text": "bravo marker two"}]}
        });
        let line = format!("{prefix}{tool}\r\n");
        let error = serde_json::from_str::<Value>(line.trim_start_matches('\u{feff}')).unwrap_err();
        assert!(error.column() > prefix.len() - '\u{feff}'.len_utf8());
        let recovered = recover_jsonl_suffix(&line);
        assert_eq!(recovered.records, [tool]);
        assert_eq!(recovered.discarded_bytes, prefix.len());
        assert_eq!(&line[..recovered.discarded_bytes], prefix);
        assert!(!recovered.limited);
    }

    #[test]
    fn recovery_retains_order_and_known_pi_control_records() {
        let records = [
            serde_json::json!({"type":"message", "id":"u1", "message":{"role":"user", "content":"first"}}),
            serde_json::json!({"type":"model_change", "id":"m1", "modelId":"test-model", "provider":"test"}),
            serde_json::json!({"type":"thinking_level_change", "id":"t1", "thinkingLevel":"high"}),
            serde_json::json!({"type":"session_info", "id":"s1", "name":"Recovered session"}),
            serde_json::json!({"type":"label", "id":"l1", "targetId":"u1", "label":"keep"}),
            serde_json::json!({"type":"custom", "id":"c1", "customType":"test-state", "data":{}}),
            serde_json::json!({"type":"custom_message", "id":"x1", "content":"custom message"}),
            serde_json::json!({"type":"compaction", "id":"c2", "summary":"compressed context"}),
            serde_json::json!({"type":"branch_summary", "id":"b1", "summary":"branch context"}),
            serde_json::json!({"type":"title", "title":"OMP title"}),
        ];
        let suffix = records.iter().map(Value::to_string).collect::<String>();
        let recovered = recover_jsonl_suffix(&format!("torn{suffix}"));
        assert_eq!(recovered.records, records);
        assert_eq!(recovered.discarded_bytes, 4);
        assert!(!recovered.limited);
    }

    #[test]
    fn recovery_accepts_supported_provider_envelopes_with_arbitrary_field_order() {
        for record in [
            serde_json::json!({"type":"session", "id":"pi-session"}),
            serde_json::json!({"type":"assistant", "message":{"role":"assistant", "content":[{"type":"text", "text":"reply"}]}}),
            serde_json::json!({"type":"session_meta", "timestamp":1, "payload":{"id":"codex-session"}}),
            serde_json::json!({"type":"response_item", "timestamp":2, "payload":{"type":"function_call_output", "output":"result"}}),
            serde_json::json!({"type":"event_msg", "timestamp":3, "payload":{"type":"agent_message", "message":"reply"}}),
            serde_json::json!({"type":"turn_context", "timestamp":4, "payload":{}}),
            serde_json::json!({"role":"user", "content":"plain message"}),
        ] {
            let recovered = recover_jsonl_suffix(&format!("torn{record}"));
            assert_eq!(recovered.records, [record]);
            assert_eq!(recovered.discarded_bytes, 4);
        }
    }

    #[test]
    fn recovery_rejects_nested_values_unrecognised_objects_and_incomplete_suffixes() {
        for line in [
            r#"{"message":{"role":"user","content":"nested"}"#,
            r#"{"message":   {"role":"user","content":"nested"}"#,
            r#"[{"role":"user","content":"nested"}"#,
            r#"[null, {"role":"user","content":"nested"}"#,
            r#"torn{"type":"text","text":"not a session record"}"#,
            r#"torn{"type":"toolCall","id":"call-1","name":"bash","arguments":{}}"#,
            r#"torn{"role":"user","content":"complete"}trailing garbage"#,
            r#"torn{"role":"user","content":"complete"}42"#,
            r#"torn{"role":"user","content":"complete"}[]"#,
            r#"torn{"role":"user","content":"complete"}{"unknown":1}"#,
        ] {
            let recovered = recover_jsonl_suffix(line);
            assert!(recovered.records.is_empty(), "must refuse {line}");
            assert_eq!(recovered.discarded_bytes, line.len());
            assert!(!recovered.limited);
        }
    }

    #[test]
    fn intact_records_keep_the_original_json_parser_semantics() {
        for line in [
            r#"{"wrapper":{"role":"user","content":"nested"}}"#,
            r#"[1,2,3]"#,
            r#"null"#,
            r#"42"#,
            r#""string""#,
        ] {
            let expected: Value = serde_json::from_str(line).unwrap();
            assert_eq!(parse_jsonl_line(line).collect::<Vec<_>>(), [expected]);
        }
        assert!(parse_jsonl_line(" \t\r\n").next().is_none());
        assert_eq!(
            parse_jsonl_line("\u{feff}{\"intact\":true}").collect::<Vec<_>>(),
            [serde_json::json!({"intact":true})]
        );
    }

    #[test]
    fn parsing_keeps_the_bom_in_the_recovery_budget() {
        let record = r#"{"role":"user","content":"complete"}"#;
        let prefix = "x".repeat(MAX_JSONL_RECOVERY_LINE_BYTES - record.len());
        let line = format!("\u{feff}{prefix}{record}");
        assert!(recover_jsonl_suffix(&line).limited);
        assert!(parse_jsonl_line(&line).next().is_none());
    }

    #[test]
    fn recovery_bounds_line_size_attempts_and_total_parse_bytes() {
        let record = r#"{"role":"user","content":"complete"}"#;
        let oversized = format!("{}{record}", "x".repeat(MAX_JSONL_RECOVERY_LINE_BYTES));
        let recovered = recover_jsonl_suffix(&oversized);
        assert!(recovered.records.is_empty());
        assert!(recovered.limited);
        assert_eq!(recovered.discarded_bytes, oversized.len());

        let unknown = r#"{"unknown":true}"#;
        let within = format!(
            "{}{record}",
            unknown.repeat(MAX_JSONL_RECOVERY_ATTEMPTS - 1)
        );
        let recovered = recover_jsonl_suffix(&within);
        assert_eq!(recovered.records.len(), 1);
        assert!(!recovered.limited);
        let over = format!("{}{record}", unknown.repeat(MAX_JSONL_RECOVERY_ATTEMPTS));
        let recovered = recover_jsonl_suffix(&over);
        assert!(recovered.records.is_empty());
        assert!(recovered.limited);

        let parse_budget = format!("{}{}{record}", unknown.repeat(17), "x".repeat(1024 * 1024));
        assert!(parse_budget.len() < MAX_JSONL_RECOVERY_LINE_BYTES);
        let recovered = recover_jsonl_suffix(&parse_budget);
        assert!(recovered.records.is_empty());
        assert!(recovered.limited);
    }

    #[test]
    fn recovery_record_limit_does_not_silently_keep_only_the_last_records() {
        let record = r#"{"role":"user","content":"complete"}"#;
        let within = record.repeat(MAX_JSONL_RECOVERY_RECORDS);
        let recovered = recover_jsonl_suffix(&within);
        assert_eq!(recovered.records.len(), MAX_JSONL_RECOVERY_RECORDS);
        assert_eq!(recovered.discarded_bytes, 0);
        assert!(!recovered.limited);
        let over = record.repeat(MAX_JSONL_RECOVERY_RECORDS + 1);
        let recovered = recover_jsonl_suffix(&over);
        assert!(recovered.records.is_empty());
        assert!(recovered.limited);
        assert_eq!(recovered.discarded_bytes, over.len());
    }

    struct FailingReader {
        prefix: Cursor<Vec<u8>>,
        kind: ErrorKind,
        attempts: Rc<Cell<usize>>,
    }

    impl Read for FailingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let available = self.fill_buf()?;
            let len = available.len().min(buffer.len());
            buffer[..len].copy_from_slice(&available[..len]);
            self.consume(len);
            Ok(len)
        }
    }

    impl BufRead for FailingReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if usize::try_from(self.prefix.position()).unwrap() < self.prefix.get_ref().len() {
                return self.prefix.fill_buf();
            }
            self.attempts.set(self.attempts.get() + 1);
            Err(io::Error::new(self.kind, "persistent source failure"))
        }

        fn consume(&mut self, amount: usize) {
            self.prefix.consume(amount);
        }
    }

    #[test]
    fn matches_standard_line_endings_and_complete_final_line() {
        let input = b"first\r\n\nthird\ncarriage\rfinal\r";
        let expected = Cursor::new(input)
            .lines()
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        let actual = JsonlLines::new(Cursor::new(input))
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual, ["first", "", "third", "carriage\rfinal\r"]);
    }

    #[test]
    fn skips_only_corrupt_utf8_lines_and_keeps_following_records() {
        let input = b"before\n\xff\xfe broken\r\n\xef\xbb\xbfafter\n\xff";
        let lines = JsonlLines::new(Cursor::new(input))
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(lines, ["before", "\u{feff}after"]);
    }

    #[test]
    fn persistent_io_errors_are_preserved_and_terminal() {
        for kind in [
            ErrorKind::Other,
            ErrorKind::InvalidData,
            ErrorKind::Interrupted,
        ] {
            let attempts = Rc::new(Cell::new(0));
            let mut lines = JsonlLines::new(FailingReader {
                prefix: Cursor::new(Vec::new()),
                kind,
                attempts: Rc::clone(&attempts),
            });
            let error = lines.next().unwrap().unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), "persistent source failure");
            assert_eq!(attempts.get(), 1);
            for _ in 0..3 {
                assert!(lines.next().is_none());
            }
            assert_eq!(attempts.get(), 1, "a failed read must never be retried");
        }
    }

    #[test]
    fn io_error_after_valid_prefix_discards_incomplete_physical_line() {
        let attempts = Rc::new(Cell::new(0));
        let mut lines = JsonlLines::new(FailingReader {
            prefix: Cursor::new(b"complete\nunfinished".to_vec()),
            kind: ErrorKind::Other,
            attempts: Rc::clone(&attempts),
        });
        assert_eq!(lines.next().unwrap().unwrap(), "complete");
        assert_eq!(lines.next().unwrap().unwrap_err().kind(), ErrorKind::Other);
        assert!(lines.next().is_none());
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn eof_is_terminal_even_if_reader_could_later_return_data() {
        struct EofThenData {
            prefix: Cursor<&'static [u8]>,
            polls: Rc<Cell<usize>>,
            observed_eof: bool,
        }

        impl Read for EofThenData {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                unreachable!("the iterator uses BufRead directly")
            }
        }

        impl BufRead for EofThenData {
            fn fill_buf(&mut self) -> io::Result<&[u8]> {
                self.polls.set(self.polls.get() + 1);
                if usize::try_from(self.prefix.position()).unwrap() < self.prefix.get_ref().len() {
                    return self.prefix.fill_buf();
                }
                if self.observed_eof {
                    Ok(b"late\n")
                } else {
                    self.observed_eof = true;
                    Ok(b"")
                }
            }

            fn consume(&mut self, amount: usize) {
                self.prefix.consume(amount);
            }
        }

        for (prefix, expected) in [
            (b"".as_slice(), None),
            (b"final".as_slice(), Some("final")),
            (b"\xff".as_slice(), None),
        ] {
            let polls = Rc::new(Cell::new(0));
            let mut lines = JsonlLines::new(EofThenData {
                prefix: Cursor::new(prefix),
                polls: Rc::clone(&polls),
                observed_eof: false,
            });
            assert_eq!(lines.next().transpose().unwrap().as_deref(), expected);
            for _ in 0..3 {
                assert!(lines.next().is_none());
            }
            assert_eq!(polls.get(), if prefix.is_empty() { 1 } else { 2 });
        }
    }
}
