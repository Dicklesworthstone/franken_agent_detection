# ZCode storage fixtures

`schema.sql` reproduces the table DDL published in
[CASS #573](https://github.com/Dicklesworthstone/coding_agent_session_search/issues/573),
verified by the reporter against ZCode Desktop 3.18.2 and bundled CLI 0.17.1.
The identity table's columns were not provided; the fixture uses a synthetic
`id` column, and the connector requires only that table's existence.

The Rust tests build temporary databases from this schema using FrankenSQLite.
Their messages are synthetic examples of the persisted `real_user`, injected
`agent_runtime`, visible assistant, reasoning, tool and attachment shapes from
that issue. No private database, credentials or original user transcript is
included. Settings and session-entry prompt snapshots contain explicit sentinel
strings so accidental indexing or metadata retention fails the tests.
