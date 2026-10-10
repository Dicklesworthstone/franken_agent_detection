//! Line-oriented transcript reads with record-local UTF-8 recovery.

use std::io::{self, BufRead};
use std::iter::FusedIterator;

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
