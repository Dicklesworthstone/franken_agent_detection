//! Pair duplicate Codex prompt records, never repeated prompt text globally.
//!
//! Old rollouts can write a prompt through both `event_msg/user_message` and
//! `response_item/user`. Text is not a session-wide identity: users routinely
//! repeat prompts such as "continue". Only neighboring physical records from
//! opposite streams may pair, and each record can participate in one pair.
//! Known timestamps and turn IDs must also be compatible. Ambiguous records
//! are retained rather than borrowing a match from another turn.

/// The existing dual-stream fixture has one-second timestamp precision.
/// Keep that compatibility without matching identical prompts minutes apart.
const MAX_PAIR_TIMESTAMP_DELTA_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stream {
    Event,
    Response,
}

struct PendingPrompt {
    stream: Stream,
    record_index: usize,
    message_index: usize,
    text: String,
    created_at: Option<i64>,
    turn_id: Option<String>,
}

#[derive(Default)]
pub(super) struct UserPrompts {
    pending: Option<PendingPrompt>,
    event_copies: Vec<usize>,
}

impl UserPrompts {
    /// Observe a user message immediately before it is appended to the private
    /// conversation. Physical record indices come from `RolloutReader`; skipped
    /// records and metadata therefore also separate possible pairs.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn observe(
        &mut self,
        stream: Stream,
        record_index: usize,
        message_index: usize,
        text: &str,
        created_at: Option<i64>,
        turn_id: Option<&str>,
    ) {
        let text = text.trim();
        let turn_id = turn_id.filter(|id| !id.is_empty());
        if let Some(previous) = self.pending.take() {
            let timestamps_match = match (previous.created_at, created_at) {
                (Some(left), Some(right)) => left.abs_diff(right) <= MAX_PAIR_TIMESTAMP_DELTA_MS,
                (None, None) => true,
                _ => false,
            };
            if previous.stream != stream
                && previous.record_index.checked_add(1) == Some(record_index)
                && previous.message_index.checked_add(1) == Some(message_index)
                && previous.text == text
                && timestamps_match
                && previous.turn_id.as_deref() == turn_id
            {
                self.event_copies.push(match stream {
                    Stream::Event => message_index,
                    Stream::Response => previous.message_index,
                });
                // Consume both sides. One response must never erase more than
                // one event, including runs of identical prompts at one time.
                return;
            }
        }
        self.pending = Some(PendingPrompt {
            stream,
            record_index,
            message_index,
            text: text.to_owned(),
            created_at,
            turn_id: turn_id.map(str::to_owned),
        });
    }

    /// Preserve message order and the response-side message with all of its
    /// original metadata. The caller performs its existing reindexing once.
    pub(super) fn finish<T>(self, messages: &mut Vec<T>) {
        if self.event_copies.is_empty() {
            return;
        }
        // Observations are in source order and a pair is consumed immediately,
        // so removal indices are strictly increasing without a sort or hash.
        let mut copies = self.event_copies.into_iter().peekable();
        let mut index = 0;
        messages.retain(|_| {
            let keep = copies.peek().copied() != Some(index);
            if !keep {
                copies.next();
            }
            index += 1;
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{Stream, UserPrompts};

    fn run(streams: &[Stream]) -> Vec<usize> {
        let mut prompts = UserPrompts::default();
        let mut messages = Vec::new();
        for (index, &stream) in streams.iter().enumerate() {
            prompts.observe(stream, index, index, "continue", Some(1_000), None);
            messages.push(index);
        }
        prompts.finish(&mut messages);
        messages
    }

    #[test]
    fn neighboring_pairs_keep_the_response_in_either_order() {
        assert_eq!(run(&[Stream::Event, Stream::Response]), [1]);
        assert_eq!(run(&[Stream::Response, Stream::Event]), [0]);
    }

    #[test]
    fn one_response_cannot_consume_multiple_identical_events() {
        assert_eq!(
            run(&[Stream::Event, Stream::Event, Stream::Response]),
            [0, 2]
        );
        assert_eq!(
            run(&[Stream::Event, Stream::Response, Stream::Event]),
            [1, 2]
        );
        assert_eq!(
            run(&[Stream::Response, Stream::Event, Stream::Event]),
            [0, 2]
        );
    }

    #[test]
    fn same_stream_repetition_and_repeated_pairs_are_preserved() {
        assert_eq!(run(&[Stream::Event, Stream::Event]), [0, 1]);
        assert_eq!(run(&[Stream::Response, Stream::Response]), [0, 1]);
        assert_eq!(
            run(&[
                Stream::Event,
                Stream::Response,
                Stream::Event,
                Stream::Response
            ]),
            [1, 3]
        );
    }

    #[test]
    fn discarded_raw_records_and_non_user_messages_separate_pairs() {
        for (record, message) in [(2, 1), (1, 2), (usize::MAX, 1)] {
            let mut prompts = UserPrompts::default();
            prompts.observe(Stream::Event, 0, 0, "continue", None, None);
            prompts.observe(Stream::Response, record, message, "continue", None, None);
            let mut messages = vec![0, 1, 2];
            prompts.finish(&mut messages);
            assert_eq!(messages, [0, 1, 2]);
        }
    }

    #[test]
    fn incompatible_timestamps_or_turn_ids_do_not_delete_history() {
        let cases = [
            (Some(0), Some(1_001), None, None),
            (Some(i64::MIN), Some(i64::MAX), None, None),
            (Some(1_000), None, None, None),
            (None, Some(1_000), None, None),
            (None, None, Some("turn-one"), Some("turn-two")),
            (None, None, Some("turn-one"), None),
        ];
        for (left_time, right_time, left_turn, right_turn) in cases {
            let mut prompts = UserPrompts::default();
            prompts.observe(Stream::Event, 0, 0, "continue", left_time, left_turn);
            prompts.observe(Stream::Response, 1, 1, "continue", right_time, right_turn);
            let mut messages = vec![0, 1];
            prompts.finish(&mut messages);
            assert_eq!(messages, [0, 1]);
        }
    }

    #[test]
    fn compatible_legacy_precision_trimmed_text_and_shared_turn_pair() {
        let mut prompts = UserPrompts::default();
        prompts.observe(Stream::Event, 0, 0, "  日本語\n", Some(1_000), Some("t"));
        prompts.observe(Stream::Response, 1, 1, "日本語", Some(2_000), Some("t"));
        let mut messages = vec![0, 1];
        prompts.finish(&mut messages);
        assert_eq!(messages, [1]);
    }

    #[test]
    fn exhaustive_small_streams_preserve_every_response_and_event_multiplicity() {
        for length in 0..=12 {
            for bits in 0..(1_usize << length) {
                let streams: Vec<_> = (0..length)
                    .map(|index| {
                        if bits & (1 << index) == 0 {
                            Stream::Event
                        } else {
                            Stream::Response
                        }
                    })
                    .collect();
                let retained = run(&streams);
                let responses = streams.iter().filter(|&&s| s == Stream::Response).count();
                let events = length - responses;
                assert!(retained.len() >= events.max(responses));
                assert!(retained.windows(2).all(|pair| pair[0] < pair[1]));
                for (index, stream) in streams.iter().enumerate() {
                    if *stream == Stream::Response {
                        assert!(retained.contains(&index));
                    }
                }
            }
        }
    }
}
