//! Synchronous bridge over the async `FrankenSQLite` 0.2 engine API.
//!
//! fsqlite 0.2 made every engine entry point `async` with `!Send` futures
//! (the engine is `Rc<RefCell<..>>` internally). The connectors are fully
//! synchronous, so this module drives each fsqlite future to completion on
//! the calling thread with a private current-thread `asupersync` runtime.
//!
//! Every future is created, polled, and dropped entirely within one bridge
//! call, so the engine's `Rc<RefCell<..>>` state never crosses a thread
//! boundary. `Runtime::block_on` has no `Send` bound and saves/restores the
//! ambient runtime handle, so nested use from inside a consumer's own
//! `block_on` is safe (proven by the sqlmodel-frankensqlite
//! `nested_block_on_*` probes for the same bridge pattern).
//!
//! The runtime is kept in a thread-local slot and *taken out* while a future
//! is being driven: a reentrant bridge call (e.g. from a row-mapping closure)
//! finds the slot empty and builds a fresh runtime instead of re-entering
//! `block_on` on the same runtime instance.

use std::cell::RefCell;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use asupersync::runtime::{Runtime, RuntimeBuilder};
use frankensqlite::FrankenError;
use frankensqlite::Row;
use frankensqlite::compat::ConnectionExt as AsyncConnectionExt;
use frankensqlite::compat::{OpenFlags, ParamValue};

thread_local! {
    static DRIVER: RefCell<Option<Runtime>> = const { RefCell::new(None) };
}

/// Drive a `!Send` fsqlite future to completion on the calling thread.
fn drive<T>(future: impl Future<Output = T>) -> Result<T, FrankenError> {
    let runtime = match DRIVER.with(|slot| slot.borrow_mut().take()) {
        Some(runtime) => runtime,
        None => RuntimeBuilder::current_thread().build().map_err(|error| {
            FrankenError::Internal(format!("failed to build SQLite connector runtime: {error}"))
        })?,
    };
    let output = runtime.block_on(future);
    DRIVER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(runtime);
        }
    });
    Ok(output)
}

/// Synchronous wrapper over [`frankensqlite::Connection`].
///
/// Exposes the subset of the engine surface the connectors use, with the
/// pre-0.2 blocking signatures.
pub struct Connection {
    inner: frankensqlite::Connection,
}

impl Connection {
    /// Open (or create) a database at `path`.
    pub fn open(path: &str) -> Result<Self, FrankenError> {
        Ok(Self {
            inner: drive(frankensqlite::Connection::open(path))??,
        })
    }

    /// Execute a single SQL statement, returning the affected row count.
    pub fn execute(&self, sql: &str) -> Result<usize, FrankenError> {
        drive(self.inner.execute(sql))?
    }

    /// Execute a string of semicolon-separated SQL statements.
    pub fn execute_batch(&self, sql: &str) -> Result<(), FrankenError> {
        drive(self.inner.execute_batch(sql))?
    }

    /// Run `f` inside one deferred read transaction so every query it issues
    /// observes a single coherent committed snapshot, then end the
    /// transaction promptly (a held read transaction blocks the writer's WAL
    /// checkpoint).
    ///
    /// On success the transaction is committed (a no-op for reads); if `f`
    /// or the commit fails, the transaction is rolled back best-effort.
    /// If `f` unwinds, rollback is attempted before resuming its original panic.
    pub fn read_transaction<T, E>(&self, f: impl FnOnce(&Self) -> Result<T, E>) -> Result<T, E>
    where
        E: From<FrankenError>,
    {
        self.execute("BEGIN DEFERRED;").map_err(E::from)?;
        // The callback is never resumed after an unwind. Keep its existing
        // unconstrained signature while releasing this transaction before the
        // caller can catch the panic and reuse the connection.
        let result = match catch_unwind(AssertUnwindSafe(|| f(self))) {
            Ok(result) => result,
            Err(payload) => {
                // A cleanup panic must not replace the callback's payload.
                let _ = catch_unwind(AssertUnwindSafe(|| self.execute("ROLLBACK;")));
                resume_unwind(payload);
            }
        };
        match result {
            Ok(value) => {
                if let Err(err) = self.execute("COMMIT;") {
                    let _ = self.execute("ROLLBACK;");
                    return Err(E::from(err));
                }
                Ok(value)
            }
            Err(err) => {
                let _ = self.execute("ROLLBACK;");
                Err(err)
            }
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // fsqlite 0.2 no longer checkpoints on drop, and read-only opens are
        // mutation-free (GH#294): they do not recover an unpublished WAL
        // sidecar. Closing in place on drop restores the pre-0.2 observable
        // contract that writes made through a dropped connection are visible
        // to a later read-only open.
        if let Err(error) = drive(self.inner.close_best_effort_in_place()) {
            tracing::warn!(%error, "could not drive SQLite connector close");
        }
    }
}

/// Open a database with rusqlite-style open flags (synchronous form of
/// [`frankensqlite::compat::open_with_flags`]).
pub fn open_with_flags(path: &str, flags: OpenFlags) -> Result<Connection, FrankenError> {
    Ok(Connection {
        inner: drive(frankensqlite::compat::open_with_flags(path, flags))??,
    })
}

/// Synchronous form of [`frankensqlite::compat::ConnectionExt`].
pub trait ConnectionExt {
    /// Execute a query that returns exactly one row, mapping it with `f`.
    fn query_row_map<T, F>(
        &self,
        sql: &str,
        params: &[ParamValue],
        f: F,
    ) -> Result<T, FrankenError>
    where
        F: FnOnce(&Row) -> Result<T, FrankenError>;

    /// Execute a query and collect all rows into a `Vec<T>` via mapping closure.
    fn query_map_collect<T, F>(
        &self,
        sql: &str,
        params: &[ParamValue],
        f: F,
    ) -> Result<Vec<T>, FrankenError>
    where
        F: FnMut(&Row) -> Result<T, FrankenError>;

    /// Execute a SQL statement with `ParamValue` parameters.
    fn execute_compat(&self, sql: &str, params: &[ParamValue]) -> Result<usize, FrankenError>;
}

impl ConnectionExt for Connection {
    fn query_row_map<T, F>(&self, sql: &str, params: &[ParamValue], f: F) -> Result<T, FrankenError>
    where
        F: FnOnce(&Row) -> Result<T, FrankenError>,
    {
        drive(AsyncConnectionExt::query_row_map(
            &self.inner,
            sql,
            params,
            f,
        ))?
    }

    fn query_map_collect<T, F>(
        &self,
        sql: &str,
        params: &[ParamValue],
        f: F,
    ) -> Result<Vec<T>, FrankenError>
    where
        F: FnMut(&Row) -> Result<T, FrankenError>,
    {
        drive(AsyncConnectionExt::query_map_collect(
            &self.inner,
            sql,
            params,
            f,
        ))?
    }

    fn execute_compat(&self, sql: &str, params: &[ParamValue]) -> Result<usize, FrankenError> {
        drive(AsyncConnectionExt::execute_compat(&self.inner, sql, params))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::{Cx, cx::CapMask};
    use frankensqlite::compat::RowExt;

    #[test]
    fn read_transaction_rolls_back_callback_and_row_mapper_panics() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            for restricted in [false, true] {
                let restriction = restricted.then(|| Cx::push_restriction(CapMask::none()));
                let caller = Cx::current().expect("caller context");
                for panic_in_mapper in [false, true] {
                    let connection = Connection::open(":memory:").unwrap();
                    connection
                        .execute_batch(
                            "CREATE TABLE values_seen (value INTEGER); \
                             INSERT INTO values_seen VALUES (1);",
                        )
                        .unwrap();
                    let panic = catch_unwind(AssertUnwindSafe(|| {
                        connection.read_transaction::<(), FrankenError>(|connection| {
                            connection.execute("INSERT INTO values_seen VALUES (2)")?;
                            if panic_in_mapper {
                                return connection.query_row_map("SELECT 1", &[], |_| {
                                    panic!("read-transaction callback panic"); // ubs:ignore[rust.ownership.panic-macro] — Inject mapper unwind to prove rollback and caller-context restoration.
                                });
                            }
                            panic!("read-transaction callback panic"); // ubs:ignore[rust.ownership.panic-macro] — catch_unwind verifies this original callback payload survives.
                        })
                    }))
                    .expect_err("callback must keep unwinding");
                    assert_eq!(
                        panic.downcast_ref::<&str>(),
                        Some(&"read-transaction callback panic")
                    );
                    let restored = Cx::current().expect("restored caller context");
                    assert_eq!(restored.task_id(), caller.task_id());
                    assert_eq!(restored.region_id(), caller.region_id());
                    assert_eq!(restored.capabilities(), caller.capabilities());

                    // The same connection must admit a new transaction, and
                    // work before the callback panic must not be committed.
                    let values: Vec<i64> = connection
                        .read_transaction(|connection| {
                            connection.query_map_collect(
                                "SELECT value FROM values_seen ORDER BY value",
                                &[],
                                |row| row.get_typed(0),
                            )
                        })
                        .unwrap();
                    assert_eq!(values, vec![1]);
                    drop(connection);
                    let restored = Cx::current().expect("caller context after close");
                    assert_eq!(restored.task_id(), caller.task_id());
                    assert_eq!(restored.capabilities(), caller.capabilities());
                }
                drop(restriction);
            }
        });
    }

    #[test]
    fn read_transaction_preserves_success_and_returned_error_behavior() {
        let connection = Connection::open(":memory:").unwrap();
        connection
            .execute("CREATE TABLE values_seen (value INTEGER)")
            .unwrap();
        let value = connection
            .read_transaction(|connection| {
                connection.execute("INSERT INTO values_seen VALUES (1)")?;
                Ok::<_, FrankenError>(42)
            })
            .unwrap();
        assert_eq!(value, 42);

        let error = connection
            .read_transaction::<(), FrankenError>(|connection| {
                connection.execute("INSERT INTO values_seen VALUES (2)")?;
                Err(FrankenError::Internal("callback error".to_owned()))
            })
            .unwrap_err();
        assert!(matches!(error, FrankenError::Internal(message) if message == "callback error"));
        let values: Vec<i64> = connection
            .read_transaction(|connection| {
                connection.query_map_collect(
                    "SELECT value FROM values_seen ORDER BY value",
                    &[],
                    |row| row.get_typed(0),
                )
            })
            .unwrap();
        assert_eq!(values, vec![1]);
    }

    #[test]
    fn read_transaction_preserves_panic_when_rollback_returns_an_error() {
        let connection = Connection::open(":memory:").unwrap();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            connection.read_transaction::<(), FrankenError>(|connection| {
                // End the transaction first so the unwind cleanup encounters
                // a real "no transaction is active" rollback error.
                connection.execute("ROLLBACK;")?;
                assert!(connection.execute("ROLLBACK;").is_err());
                panic!("original callback panic"); // ubs:ignore[rust.ownership.panic-macro] — This original unwind must survive a second rollback failure.
            })
        }))
        .expect_err("rollback error must not replace the callback panic");
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"original callback panic")
        );
        let value: i64 = connection
            .read_transaction(|connection| {
                connection.query_row_map("SELECT 42", &[], |row| row.get_typed(0))
            })
            .unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn read_transaction_failed_begin_keeps_existing_transaction() {
        let connection = Connection::open(":memory:").unwrap();
        connection
            .execute_batch(
                "CREATE TABLE values_seen (value INTEGER); \
                 BEGIN DEFERRED; INSERT INTO values_seen VALUES (1);",
            )
            .unwrap();
        let called = std::cell::Cell::new(false);
        let result = connection.read_transaction::<(), FrankenError>(|_| {
            called.set(true);
            Ok(())
        });
        assert!(result.is_err(), "nested BEGIN must fail");
        assert!(!called.get(), "failed BEGIN must not call the callback");
        connection.execute("COMMIT;").unwrap();
        let value: i64 = connection
            .query_row_map("SELECT value FROM values_seen", &[], |row| row.get_typed(0))
            .unwrap();
        assert_eq!(value, 1, "the pre-existing transaction must remain owned");
    }

    #[test]
    fn nested_sql_bridge_preserves_caller_context() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let parent = Cx::current().expect("outer runtime context");
            for restricted in [false, true] {
                let restriction = restricted.then(|| Cx::push_restriction(CapMask::none()));
                let caller = Cx::current().expect("caller context");
                let assert_caller = || {
                    let current = Cx::current().expect("restored caller context");
                    assert_eq!(current.task_id(), caller.task_id());
                    assert_eq!(current.region_id(), caller.region_id());
                    assert_eq!(current.capabilities(), caller.capabilities());
                };

                let connection = Connection::open(":memory:").unwrap();
                assert_caller();
                connection
                    .execute_batch("CREATE TABLE values_seen (value INTEGER); INSERT INTO values_seen VALUES (40);")
                    .unwrap();
                assert_caller();
                let value = connection
                    .query_row_map("SELECT value FROM values_seen", &[], |row| {
                        // Row mapping runs inside drive(). A nested bridge must
                        // use a separate runtime, then restore the mapping task.
                        let mapping = Cx::current().expect("mapping context");
                        let nested = Connection::open(":memory:")?;
                        let extra: i64 = nested.query_row_map("SELECT 2", &[], |row| {
                            row.get_typed(0)
                        })?;
                        drop(nested);
                        let restored = Cx::current().expect("restored mapping context");
                        assert_eq!(restored.task_id(), mapping.task_id());
                        assert_eq!(restored.capabilities(), mapping.capabilities());
                        Ok(row.get_typed::<i64>(0)? + extra)
                    })
                    .unwrap();
                assert_eq!(value, 42);
                assert_caller();
                drop(connection);
                assert_caller();
                drop(restriction);
                let restored = Cx::current().expect("restored outer runtime context");
                assert_eq!(restored.task_id(), parent.task_id());
                assert_eq!(restored.capabilities(), parent.capabilities());
            }
        });
    }
}
