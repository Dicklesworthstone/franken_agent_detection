//! Read one bounded rollout snapshot without certifying incomplete input.

use std::fs::{self, File, Metadata};
use std::io::{self, BufRead, BufReader, Read, Take};
#[cfg(feature = "codex-zstd")]
use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use serde_json::Value;

use super::super::utils::MAX_SCAN_FILE_BYTES;

const PROGRESS_LINE_STRIDE: usize = 1024;

/// Largest Codex rollout the primary reader admits. The reader streams records
/// through a length-bounded handle, so this is an admission budget, not a
/// memory bound. It defaults to the shared 100 MiB scan budget; an embedder
/// that admits larger rollouts (cass: `CASS_CODEX_MAX_SOURCE_BYTES`) raises it.
static ROLLOUT_BYTE_BUDGET: AtomicU64 = AtomicU64::new(MAX_SCAN_FILE_BYTES);

/// Set the largest Codex rollout (bytes) the primary reader admits, process-wide.
/// Values below one byte are treated as one byte.
pub fn set_codex_rollout_byte_budget(bytes: u64) {
    ROLLOUT_BYTE_BUDGET.store(bytes.max(1), Ordering::Relaxed);
}

/// The current Codex rollout admission budget (bytes).
#[must_use]
pub fn codex_rollout_byte_budget() -> u64 {
    ROLLOUT_BYTE_BUDGET.load(Ordering::Relaxed)
}

fn admit_rollout_len(len: u64, budget: u64) -> io::Result<()> {
    if len > budget {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Codex rollout ({len} bytes) exceeds the {budget}-byte scan budget"),
        ));
    }
    Ok(())
}

pub(super) struct RolloutReader<'a> {
    path: &'a Path,
    /// The opened file, for the end-of-read snapshot check.
    file: File,
    before: Metadata,
    /// A compressed rollout's records are its decoded text, so the decoder's
    /// clean end, not the file length, says the whole file was read.
    compressed: bool,
    records: Records<'a, Box<dyn BufRead + 'a>>,
    finished: bool,
}

impl<'a> RolloutReader<'a> {
    pub(super) fn open(
        path: &'a Path,
        compressed: bool,
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
        let budget = codex_rollout_byte_budget();
        admit_rollout_len(before.len(), budget)?;
        // Bound the underlying reader, not the result of read_line: even a
        // newline-free record or a concurrent appender cannot grow it forever.
        let source = file
            .try_clone()
            .context("duplicate opened Codex rollout handle")?
            .take(before.len());
        let input: Box<dyn BufRead + 'a> = if compressed {
            Box::new(
                compressed_input(source, budget)
                    .context("start decoding compressed Codex rollout")?,
            )
        } else {
            Box::new(BufReader::new(source))
        };
        Ok(Self {
            path,
            file,
            before,
            compressed,
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
        // The decoder ends cleanly only after a complete frame with no input
        // left, so a compressed rollout cut short has already failed.
        if !self.compressed && self.records.bytes_read != self.before.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Codex rollout was truncated while reading; retry this source",
            )
            .into());
        }
        let after = self
            .file
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

/// The decoded text of a compressed rollout (`rollout-*.jsonl.zst`, which
/// Codex writes when its `local_thread_store_compression` feature compresses
/// a finished session), read from `compressed`.
///
/// Reading fails, instead of ending early, when the decoded text passes
/// `budget` bytes, when the stream is cut short mid-frame (an
/// [`io::ErrorKind::UnexpectedEof`]) and when the bytes are not zstd, so a
/// caller never takes part of a session for all of it. Past the budget the
/// error kind is [`io::ErrorKind::FileTooLarge`].
///
/// # Errors
///
/// Returns an error when the decoder cannot be created.
#[cfg(feature = "codex-zstd")]
pub fn decompressed_rollout<R: Read>(compressed: R, budget: u64) -> io::Result<impl BufRead> {
    Ok(BufReader::new(DecodedBudget {
        inner: zstd::stream::read::Decoder::new(compressed)?,
        decoded: 0,
        budget,
    }))
}

/// The decoded length a compressed rollout's first zstd frame header records.
///
/// It is read from the start of `source`, which is left where it was. Codex
/// pledges the whole length when it compresses a rollout, so for its files
/// this is the length of the session's text; another writer's first frame
/// may hold only part of it. `None` when the header records no length or is
/// not a zstd frame header.
///
/// # Errors
///
/// Returns an error when `source` cannot be read or repositioned.
#[cfg(feature = "codex-zstd")]
pub fn compressed_rollout_declared_len<R: Read + Seek>(source: &mut R) -> io::Result<Option<u64>> {
    // ZSTD_FRAMEHEADERSIZE_MAX: no frame header is longer.
    const FRAME_HEADER_MAX_BYTES: u64 = 18;
    let start = source.stream_position()?;
    let mut header = Vec::new();
    source
        .by_ref()
        .take(FRAME_HEADER_MAX_BYTES)
        .read_to_end(&mut header)?;
    source.seek(SeekFrom::Start(start))?;
    Ok(zstd::zstd_safe::get_frame_content_size(&header)
        .ok()
        .flatten())
}

/// A rollout's path without its format suffix (`.jsonl`, `.json` or
/// `.jsonl.zst`). It names the session in every form, so a session Codex
/// compresses after it was indexed keeps its id.
#[must_use]
pub fn rollout_session_path(path: &Path) -> std::path::PathBuf {
    let path = if is_compressed_rollout(path) {
        path.with_extension("")
    } else {
        path.to_path_buf()
    };
    path.with_extension("")
}

/// True for a rollout Codex compressed: `rollout-*.jsonl.zst`.
#[must_use]
pub fn is_compressed_rollout(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with("rollout-") && name.to_ascii_lowercase().ends_with(".jsonl.zst")
        })
}

#[cfg(feature = "codex-zstd")]
fn compressed_input(mut compressed: Take<File>, budget: u64) -> io::Result<impl BufRead> {
    // A length the header declares past the budget is refused before any
    // decoding, with the same error a plain rollout that long gets.
    if let Some(declared) = compressed_rollout_declared_len(compressed.get_mut())? {
        admit_rollout_len(declared, budget)?;
    }
    decompressed_rollout(compressed, budget)
}

#[cfg(not(feature = "codex-zstd"))]
fn compressed_input(_compressed: Take<File>, _budget: u64) -> io::Result<io::Empty> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "reading a compressed Codex rollout needs the `codex-zstd` feature",
    ))
}

/// Fails once the decoded text passes the budget: an early end would read
/// as a complete, shorter session.
#[cfg(feature = "codex-zstd")]
struct DecodedBudget<R> {
    inner: R,
    decoded: u64,
    budget: u64,
}

#[cfg(feature = "codex-zstd")]
impl<R: Read> Read for DecodedBudget<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.decoded = self.decoded.saturating_add(count as u64);
        if self.decoded > self.budget {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                format!(
                    "decompressed Codex rollout exceeds the {}-byte scan budget",
                    self.budget
                ),
            ));
        }
        Ok(count)
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
    fn rollout_admission_is_bounded_by_the_configured_budget() {
        assert_eq!(
            codex_rollout_byte_budget(),
            MAX_SCAN_FILE_BYTES,
            "the default budget is the shared scan budget"
        );
        assert!(admit_rollout_len(MAX_SCAN_FILE_BYTES, MAX_SCAN_FILE_BYTES).is_ok());
        let over = admit_rollout_len(MAX_SCAN_FILE_BYTES + 1, MAX_SCAN_FILE_BYTES)
            .expect_err("one byte over the budget is refused");
        assert_eq!(over.kind(), io::ErrorKind::InvalidData);
        // A raised budget admits a rollout the default refuses.
        assert!(admit_rollout_len(MAX_SCAN_FILE_BYTES + 1, 4 * MAX_SCAN_FILE_BYTES).is_ok());
    }

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
    fn every_rollout_form_names_the_same_session() {
        for name in [
            "d/rollout-x.jsonl",
            "d/rollout-x.json",
            "d/rollout-x.jsonl.zst",
            "d/rollout-x.JSONL.ZST",
        ] {
            assert_eq!(
                rollout_session_path(Path::new(name)),
                Path::new("d/rollout-x"),
                "{name}"
            );
        }
        // Only `.jsonl.zst` loses two suffixes.
        assert_eq!(
            rollout_session_path(Path::new("d/rollout-x.json.zst")),
            Path::new("d/rollout-x.json")
        );
    }

    #[cfg(feature = "codex-zstd")]
    mod compressed {
        use super::*;
        use std::io::{Seek, Write};

        const TEXT: &str = "\u{feff}{\"first\":true}\r\n\nnot-json\n{\"last\":true}\n";

        /// Compressed the way Codex compresses a rollout: one frame that
        /// records the decoded length.
        fn declared(text: &[u8]) -> Vec<u8> {
            zstd::bulk::compress(text, 3).unwrap()
        }

        /// One frame that does not record the decoded length.
        fn undeclared(text: &[u8]) -> Vec<u8> {
            let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
            encoder.include_contentsize(false).unwrap();
            encoder.write_all(text).unwrap();
            encoder.finish().unwrap()
        }

        fn records<R: BufRead>(input: R) -> Result<Vec<(usize, Value)>> {
            let mut records = Records::new(input, None);
            let mut out = Vec::new();
            while let Some(record) = records.next_record()? {
                out.push(record);
            }
            Ok(out)
        }

        fn read_file(path: &Path) -> Result<Vec<(usize, Value)>> {
            let mut reader = RolloutReader::open(path, true, None)?;
            let mut out = Vec::new();
            while let Some(record) = reader.next_record()? {
                out.push(record);
            }
            Ok(out)
        }

        fn io_kind(error: &anyhow::Error) -> Option<io::ErrorKind> {
            error.downcast_ref::<io::Error>().map(io::Error::kind)
        }

        #[test]
        fn a_compressed_rollout_reads_as_the_records_of_its_text() {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("rollout-x.jsonl.zst");
            fs::write(&path, declared(TEXT.as_bytes())).unwrap();
            let plain = records(Cursor::new(TEXT)).unwrap();
            assert_eq!(plain.len(), 2);
            assert_eq!(read_file(&path).unwrap(), plain);
            fs::write(&path, undeclared(TEXT.as_bytes())).unwrap();
            assert_eq!(read_file(&path).unwrap(), plain);
        }

        #[test]
        fn the_declared_length_is_read_without_moving_the_source() {
            let mut source = Cursor::new(declared(TEXT.as_bytes()));
            assert_eq!(
                compressed_rollout_declared_len(&mut source).unwrap(),
                Some(TEXT.len() as u64)
            );
            assert_eq!(source.stream_position().unwrap(), 0);
            let mut source = Cursor::new(undeclared(TEXT.as_bytes()));
            assert_eq!(compressed_rollout_declared_len(&mut source).unwrap(), None);
            let mut source = Cursor::new(TEXT.as_bytes().to_vec());
            assert_eq!(compressed_rollout_declared_len(&mut source).unwrap(), None);
        }

        #[test]
        fn a_cut_short_compressed_rollout_fails_as_unfinished() {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("rollout-x.jsonl.zst");
            let packed = declared("{\"a\":1}\n".repeat(20_000).as_bytes());
            fs::write(&path, &packed[..packed.len() / 2]).unwrap();
            let error = read_file(&path).unwrap_err();
            assert_eq!(
                io_kind(&error),
                Some(io::ErrorKind::UnexpectedEof),
                "{error:#}"
            );
            // An empty file is a compressed rollout not yet written.
            fs::write(&path, b"").unwrap();
            let error = read_file(&path).unwrap_err();
            assert_eq!(
                io_kind(&error),
                Some(io::ErrorKind::UnexpectedEof),
                "{error:#}"
            );
        }

        #[test]
        fn bytes_that_are_not_one_whole_zstd_stream_fail() {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("rollout-x.jsonl.zst");
            fs::write(&path, TEXT).unwrap();
            assert!(read_file(&path).is_err(), "plain text named .jsonl.zst");
            let mut trailing = declared(TEXT.as_bytes());
            trailing.extend_from_slice(b"not a frame");
            fs::write(&path, trailing).unwrap();
            assert!(read_file(&path).is_err(), "bytes after the frame");
        }

        #[test]
        fn decoded_text_is_held_to_the_budget() {
            let text = "{\"a\":1}\n".repeat(1_000);
            let len = text.len() as u64;
            let mut decoded = Vec::new();
            decompressed_rollout(Cursor::new(undeclared(text.as_bytes())), len)
                .unwrap()
                .read_to_end(&mut decoded)
                .expect("text exactly at the budget is admitted");
            assert_eq!(decoded, text.as_bytes());

            let error = decompressed_rollout(Cursor::new(undeclared(text.as_bytes())), len - 1)
                .unwrap()
                .read_to_end(&mut Vec::new())
                .expect_err("one byte past the budget fails, never a shorter text");
            assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
        }

        #[test]
        fn a_declared_length_past_the_budget_is_refused_before_decoding() {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("rollout-x.jsonl.zst");
            let text = "{\"a\":1}\n".repeat(1_000);
            fs::write(&path, declared(text.as_bytes())).unwrap();
            let file = File::open(&path).unwrap();
            let len = file.metadata().unwrap().len();
            let Err(error) = compressed_input(file.take(len), text.len() as u64 - 1) else {
                panic!("a declared length past the budget is refused");
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }

        #[test]
        fn only_rollout_jsonl_zst_names_are_compressed_rollouts() {
            for (name, expected) in [
                ("rollout-x.jsonl.zst", true),
                ("rollout-x.JSONL.ZST", true),
                ("rollout-x.jsonl", false),
                ("rollout-x.zst", false),
                ("rollout-x.json.zst", false),
                ("other-x.jsonl.zst", false),
            ] {
                assert_eq!(is_compressed_rollout(Path::new(name)), expected, "{name}");
            }
        }
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
