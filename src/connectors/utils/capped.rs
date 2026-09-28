//! Enforce the byte budget during I/O, not after an unbounded allocation.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use super::MAX_SCAN_FILE_BYTES;

pub(super) fn read_capped(path: &Path) -> io::Result<Option<String>> {
    let file = File::open(path)?;
    // Inspect the opened object, not a potentially replaced pathname. Metadata
    // is only an optimization: the reader below enforces the limit even when
    // metadata fails, underreports size, or the file grows after this check.
    if file
        .metadata()
        .is_ok_and(|metadata| metadata.len() > MAX_SCAN_FILE_BYTES)
    {
        return Ok(None);
    }
    read_limited(file, MAX_SCAN_FILE_BYTES)
}

fn read_limited(reader: impl Read, limit: u64) -> io::Result<Option<String>> {
    let probe_limit = limit
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "read limit overflow"))?;
    let mut bytes = Vec::new();
    reader.take(probe_limit).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Ok(None);
    }
    // Test the byte budget before UTF-8: a probe ending within a multibyte
    // character is an oversized source, not a corrupt accepted source.
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.utf8_error()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Seek, Write};

    #[derive(Default)]
    struct Endless {
        bytes_read: usize,
    }

    impl Read for Endless {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            buffer.fill(b'x');
            self.bytes_read += buffer.len();
            Ok(buffer.len())
        }
    }

    #[test]
    fn capped_read_stops_an_endless_source_after_one_probe_byte() {
        let mut source = Endless::default();
        assert!(read_limited(&mut source, 64).unwrap().is_none());
        assert_eq!(source.bytes_read, 65);
    }

    #[test]
    fn capped_read_accepts_exact_limit_and_preserves_utf8() {
        for text in ["", "plain text", "日本語\r\n", "\u{feff}hello"] {
            assert_eq!(
                read_limited(text.as_bytes(), text.len() as u64).unwrap(),
                Some(text.to_string())
            );
        }
        assert!(read_limited("é".as_bytes(), 1).unwrap().is_none());
        assert!(read_limited(&b"x"[..], 0).unwrap().is_none());
    }

    #[test]
    fn capped_read_rejects_invalid_utf8_only_when_within_budget() {
        let error = read_limited(&b"\xff"[..], 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(read_limited(&b"\xffx"[..], 1).unwrap().is_none());
    }

    #[test]
    fn capped_read_propagates_failure_after_a_valid_prefix() {
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
        let error = read_limited(Failing(Cursor::new(b"prefix".to_vec())), 64).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "injected read failure");
    }

    #[test]
    fn capped_read_retries_interrupted_reads() {
        struct Interrupted(bool);
        impl Read for Interrupted {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                if std::mem::replace(&mut self.0, false) {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(0)
                }
            }
        }
        let text = read_limited(Interrupted(true), 8).unwrap();
        assert_eq!(text, Some(String::new()));
    }

    #[test]
    fn capped_read_bounds_a_file_that_grew_after_metadata() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("growing-session.json");
        std::fs::write(&path, b"small")?;
        let mut file = File::open(&path)?;
        assert!(file.metadata()?.len() < 8);
        let mut writer = std::fs::OpenOptions::new().append(true).open(&path)?;
        writer.write_all(&[b'x'; 128])?;
        writer.flush()?;
        // Exercise the same backstop used after the optimistic metadata check.
        assert!(read_limited(&mut file, 8)?.is_none());
        assert_eq!(file.stream_position()?, 9);
        assert_eq!(std::fs::metadata(&path)?.len(), 133);
        Ok(())
    }

    #[test]
    fn capped_read_rejects_unrepresentable_probe_limit() {
        let error = read_limited(&b""[..], u64::MAX).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
