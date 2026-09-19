//! Read one bounded rollout snapshot without certifying incomplete input.

use std::fs::{self, File, Metadata};
use std::io::{self, BufRead, BufReader, Read, Take};
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

use super::super::utils::MAX_SCAN_FILE_BYTES;

const PROGRESS_LINE_STRIDE: usize = 1024;

pub(super) struct RolloutReader<'a> {
    path: &'a Path,
    before: Metadata,
    records: Records<'a, BufReader<Take<File>>>,
    finished: bool,
}

impl<'a> RolloutReader<'a> {
    pub(super) fn open(
        path: &'a Path,
        progress_tick: Option<&'a (dyn Fn() + Send + Sync)>,
    ) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("open Codex rollout {}", path.display()))?;
        let before = file.metadata().context("inspect opened Codex rollout")?;
        if !before.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Codex rollout is not a regular file",
            )
            .into());
        }
        if before.len() > MAX_SCAN_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Codex rollout exceeds the 100 MiB scan byte budget",
            )
            .into());
        }
        // Bound the underlying reader, not the result of read_line: even a
        // newline-free record or a concurrent appender cannot grow it forever.
        let input = BufReader::new(file.take(before.len()));
        Ok(Self {
            path,
            before,
            records: Records::new(input, progress_tick),
            finished: false,
        })
    }

    pub(super) fn next_record(&mut self) -> Result<Option<(usize, Value)>> {
        if self.finished {
            return Ok(None);
        }
        let record = self
            .records
            .next_record()
            .with_context(|| format!("read Codex rollout {}", self.path.display()))?;
        if record.is_none() {
            // The caller accumulates a source privately until this validated
            // EOF. Nothing from a failed source may reach its consumer sink.
            self.validate_snapshot()?;
            self.finished = true;
        }
        Ok(record)
    }

    fn validate_snapshot(&self) -> Result<()> {
        if self.records.bytes_read != self.before.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Codex rollout was truncated while reading; retry this source",
            )
            .into());
        }
        let after = self
            .records
            .input
            .get_ref()
            .get_ref()
            .metadata()
            .context("recheck opened Codex rollout")?;
        let named = fs::metadata(self.path).context("recheck Codex rollout path")?;
        if !same_snapshot(&self.before, &after)? || !same_snapshot(&self.before, &named)? {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Codex rollout changed while reading; retry this source",
            )
            .into());
        }
        Ok(())
    }
}

// Observable snapshot consistency, not protection against malicious edits
// that preserve metadata. Unix additionally checks the opened object's ID.
fn same_snapshot(before: &Metadata, after: &Metadata) -> io::Result<bool> {
    let same =
        after.is_file() && before.len() == after.len() && before.modified()? == after.modified()?;
    #[cfg(unix)]
    let same = {
        use std::os::unix::fs::MetadataExt;
        same && before.dev() == after.dev() && before.ino() == after.ino()
    };
    Ok(same)
}

struct Records<'a, R> {
    input: R,
    line: String,
    line_number: usize,
    bytes_read: u64,
    progress_tick: Option<&'a (dyn Fn() + Send + Sync)>,
}

impl<'a, R: BufRead> Records<'a, R> {
    const fn new(input: R, progress_tick: Option<&'a (dyn Fn() + Send + Sync)>) -> Self {
        Self {
            input,
            line: String::new(),
            line_number: 0,
            bytes_read: 0,
            progress_tick,
        }
    }

    fn next_record(&mut self) -> Result<Option<(usize, Value)>> {
        loop {
            if self.line_number % PROGRESS_LINE_STRIDE == 0 {
                if let Some(tick) = self.progress_tick {
                    tick();
                }
            }
            self.line.clear();
            let count = self
                .input
                .read_line(&mut self.line)
                .with_context(|| format!("read Codex JSONL line {}", self.line_number + 1))?;
            if count == 0 {
                return Ok(None);
            }
            self.bytes_read += count as u64;
            let index = self.line_number;
            self.line_number += 1;
            let terminated = self.line.ends_with('\n');
            let text = self.line.trim_start_matches('\u{feff}').trim();
            if text.is_empty() {
                continue;
            }
            match serde_json::from_str(text) {
                Ok(value) => return Ok(Some((index, value))),
                Err(error) if !terminated && error.is_eof() => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "unfinished Codex JSONL record at line {}; retry this source",
                            self.line_number
                        ),
                    )
                    .into());
                }
                // Keep the existing malformed-historical-record policy. Only
                // an unfinished final record or an actual read failure aborts.
                // Never include the record's potentially private text in errors.
                Err(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn records_keep_physical_indices_bom_crlf_and_complete_eof() {
        let bytes = "\u{feff}{\"first\":true}\r\n\nnot-json\n{\"last\":true}";
        let mut records = Records::new(Cursor::new(bytes), None);
        assert_eq!(
            records.next_record().unwrap(),
            Some((0, serde_json::json!({"first":true})))
        );
        assert_eq!(
            records.next_record().unwrap(),
            Some((3, serde_json::json!({"last":true})))
        );
        assert!(records.next_record().unwrap().is_none());
        assert_eq!(records.bytes_read, bytes.len() as u64);
    }

    #[test]
    fn unfinished_tail_is_not_successful_eof_or_a_content_disclosure() {
        let mut records = Records::new(Cursor::new("{}\n{\"private_marker\":"), None);
        assert!(records.next_record().unwrap().is_some());
        let error = records.next_record().unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(!error.to_string().contains("private_marker"));
    }

    #[test]
    fn invalid_utf8_propagates_instead_of_skipping_a_record() {
        let mut records = Records::new(Cursor::new(&b"{}\n\xff\n{}\n"[..]), None);
        assert!(records.next_record().unwrap().is_some());
        let error = records.next_record().unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn read_failure_after_a_valid_prefix_is_not_successful_eof() {
        struct Failing(Cursor<Vec<u8>>);
        impl Read for Failing {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.0.position() == self.0.get_ref().len() as u64 {
                    Err(io::Error::other("injected read failure"))
                } else {
                    self.0.read(buffer)
                }
            }
        }
        let mut records =
            Records::new(BufReader::new(Failing(Cursor::new(b"{}\n".to_vec()))), None);
        assert!(records.next_record().unwrap().is_some());
        let error = records.next_record().unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn liveness_ticks_include_skipped_lines_and_only_the_owning_scan() {
        let ticks = AtomicUsize::new(0);
        let tick = || {
            ticks.fetch_add(1, Ordering::Relaxed);
        };
        let bytes = "\n".repeat(PROGRESS_LINE_STRIDE * 2 + 1);
        let mut records = Records::new(Cursor::new(bytes), Some(&tick));
        assert!(records.next_record().unwrap().is_none());
        assert_eq!(ticks.load(Ordering::Relaxed), 3);
    }
}
