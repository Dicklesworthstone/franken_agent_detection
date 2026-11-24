"""Regenerate the synthetic committed-WAL fixture using Python's stock SQLite.

The database has a checkpointed original row and an updated row committed only
to the WAL. Copy both files while the writer is open; closing it may checkpoint.
WAL salts make the binary output nondeterministic, but its SQL contents are
deterministic. No real user transcripts, paths, or identifiers are used.
"""

import json
from pathlib import Path
import sqlite3
import tempfile

CHILD = "11111111-2222-4333-8444-555555555555"
PARENT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
DESTINATION = Path(__file__).parent

with tempfile.TemporaryDirectory(prefix="fad-synthetic-wal-") as temporary:
    source = Path(temporary) / "conversation_summaries.db"
    connection = sqlite3.connect(source)
    connection.execute("PRAGMA page_size=4096")
    assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute(
        "CREATE TABLE conversation_summaries (conversation_id TEXT PRIMARY KEY, "
        "title TEXT, workspace_uris TEXT, parent_conversation_id TEXT)"
    )
    connection.execute(
        "INSERT INTO conversation_summaries VALUES (?, ?, ?, NULL)",
        (CHILD, "Before WAL", '["file:///synthetic/old"]'),
    )
    connection.commit()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.execute(
        "UPDATE conversation_summaries SET title=?, workspace_uris=?, "
        "parent_conversation_id=? WHERE conversation_id=?",
        (
            "Committed in stock SQLite WAL",
            json.dumps([None, 17, "file:///bad%00", "file:///synthetic/work%20tree"]),
            PARENT,
            CHILD,
        ),
    )
    connection.commit()
    for suffix in ("", "-wal"):
        (DESTINATION / f"summary-wal.db{suffix}").write_bytes(
            Path(f"{source}{suffix}").read_bytes()
        )
    connection.close()
    print(f"Generated synthetic DB/WAL using SQLite {sqlite3.sqlite_version}")
