-- ZCode CLI 0.17.1 / Desktop 3.18.2, verified DDL from CASS issue #573.
-- The reporter did not disclose zcode_database_identity's columns. Only its
-- existence is part of admission; this fixture gives it one synthetic key.
PRAGMA journal_mode = DELETE;
CREATE TABLE session (
  id text primary key,
  project_id text not null,
  workspace_id text,
  parent_id text,
  slug text not null,
  directory text not null,
  path text,
  title text not null,
  version text not null,
  share_url text,
  summary_additions integer,
  summary_deletions integer,
  summary_files integer,
  summary_diffs text,
  revert text,
  permission text,
  time_created integer not null,
  time_updated integer not null,
  time_compacting integer,
  time_archived integer,
  task_type text not null default 'interactive',
  title_source text not null default 'first_input'
    check(title_source in ('default', 'first_input', 'generated', 'custom')),
  title_message_id text,
  time_title_updated integer,
  trace_id text,
  time_deleted integer,
  last_outcome text
);
CREATE TABLE message (
  id text primary key,
  session_id text not null references session(id) on delete cascade,
  time_created integer not null,
  time_updated integer not null,
  data text not null,
  sequence integer
);
CREATE TABLE part (
  id text primary key,
  message_id text not null references message(id) on delete cascade,
  session_id text not null,
  time_created integer not null,
  time_updated integer not null,
  data text not null,
  sequence integer
);
CREATE TABLE session_entry (
  id text primary key,
  session_id text not null references session(id) on delete cascade,
  type text not null,
  time_created integer not null,
  time_updated integer not null,
  data text not null
);
CREATE TABLE turn_usage (
  session_id text not null references session(id) on delete cascade,
  turn_id text not null,
  trace_id text,
  user_message_id text,
  status text not null check(status in ('running', 'completed', 'error', 'cancelled')),
  started_at integer not null,
  first_model_start_at integer,
  first_token_at integer,
  completed_at integer,
  duration_ms integer,
  time_to_first_token_ms integer,
  model_request_count integer not null default 0,
  model_retry_count integer not null default 0,
  tool_call_count integer not null default 0,
  tool_error_count integer not null default 0,
  input_tokens integer not null default 0,
  output_tokens integer not null default 0,
  reasoning_tokens integer not null default 0,
  cache_creation_input_tokens integer not null default 0,
  cache_read_input_tokens integer not null default 0,
  computed_total_tokens integer not null default 0,
  retryable integer not null default 0,
  cancelled_by_user integer not null default 0,
  context_exceeded integer not null default 0,
  error_type text,
  error_code text,
  primary key(session_id, turn_id)
);
CREATE TABLE zcode_database_identity (id text primary key);
CREATE TABLE local_setting (key text primary key, value text);
