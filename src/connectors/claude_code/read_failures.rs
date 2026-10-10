use std::cell::Cell;
use std::io::{Cursor, Read};
use std::rc::Rc;

use super::*;

struct PrefixThenError {
    prefix: Cursor<Vec<u8>>,
    kind: io::ErrorKind,
    attempts: Rc<Cell<usize>>,
}

impl Read for PrefixThenError {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let len = available.len().min(buffer.len());
        buffer[..len].copy_from_slice(&available[..len]);
        self.consume(len);
        Ok(len)
    }
}

impl BufRead for PrefixThenError {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            return self.prefix.fill_buf();
        }
        self.attempts.set(self.attempts.get() + 1);
        Err(io::Error::new(self.kind, "injected source read failure"))
    }

    fn consume(&mut self, amount: usize) {
        self.prefix.consume(amount);
    }
}

#[test]
fn failed_jsonl_prefixes_are_discarded_and_healthy_sources_complete() {
    let dir = tempfile::TempDir::new().unwrap();
    let files: Vec<_> = ["a-bad.jsonl", "b-bad.jsonl", "c-healthy.jsonl"]
        .iter()
        .map(|name| dir.path().join(name))
        .collect();
    let record =
        b"{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"complete record\"}}\n";
    for path in &files {
        fs::write(path, record).unwrap();
    }
    let ctx = ScanContext::with_roots(
        dir.path().join("data"),
        files.iter().cloned().map(ScanRoot::local).collect(),
        None,
    );
    // The complete prefixes are genuine conversations at EOF; the failure
    // must invalidate them rather than accidentally succeeding with no data.
    let mut control = 0;
    scan_claude_with_callback_with_exclusions(
        &ctx,
        &mut |_| {
            control += 1;
            Ok(())
        },
        &[],
        &mut SourceScanHooks::default(),
    )
    .unwrap();
    assert_eq!(control, 3);

    let attempts = Rc::new(Cell::new(0));
    let mut emitted = Vec::new();
    let mut completed = Vec::new();
    let error = {
        let mut on_complete = |completion: &SourceCompletion| {
            completed.push(completion.source.source_path.clone());
            Ok(())
        };
        let mut open_jsonl = |path: &Path| -> io::Result<Box<dyn BufRead>> {
            if path == files[2] {
                return Ok(Box::new(BufReader::new(fs::File::open(path)?)));
            }
            let mut prefix = record.to_vec();
            prefix.extend_from_slice(b"{\"unfinished\":");
            Ok(Box::new(PrefixThenError {
                prefix: Cursor::new(prefix),
                kind: if path == files[0] {
                    io::ErrorKind::Other
                } else {
                    io::ErrorKind::InvalidData
                },
                attempts: Rc::clone(&attempts),
            }))
        };
        scan_claude_with_readers(
            &ctx,
            &mut |conversation| {
                assert_eq!(conversation.messages.len(), 1);
                assert_eq!(conversation.messages[0].idx, 0);
                emitted.push(conversation.source_path);
                Ok(())
            },
            &[],
            &mut SourceScanHooks {
                should_scan_source: None,
                on_source_complete: Some(&mut on_complete),
            },
            &mut open_jsonl,
            &mut |_| panic!("the JSONL fixture must not use the whole-JSON reader"),
        )
        .unwrap_err()
    };
    assert_eq!(attempts.get(), 2, "each failing source is attempted once");
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::Other
    );
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().to_string(),
        "injected source read failure"
    );
    assert!(format!("{error:#}").contains(files[0].to_str().unwrap()));
    assert!(error.to_string().contains("2 source(s)"));
    assert_eq!(emitted, [files[2].clone()]);
    assert_eq!(completed, emitted);
    for path in &files {
        assert_eq!(fs::read(path).unwrap(), record);
    }
}
