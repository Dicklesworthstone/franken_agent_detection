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

use asupersync::runtime::{Runtime, RuntimeBuilder};
use frankensqlite::FrankenError;
use frankensqlite::Row;
use frankensqlite::compat::ConnectionExt as AsyncConnectionExt;
use frankensqlite::compat::{OpenFlags, ParamValue};

thread_local! {
    static DRIVER: RefCell<Option<Runtime>> = const { RefCell::new(None) };
}

/// Drive a `!Send` fsqlite future to completion on the calling thread.
fn drive<T>(future: impl Future<Output = T>) -> T {
    let runtime = DRIVER
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_else(|| {
            RuntimeBuilder::current_thread()
                .build()
                .expect("failed to build FrankenSQLite sync-bridge runtime")
        });
    let output = runtime.block_on(future);
    DRIVER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(runtime);
        }
    });
    output
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
            inner: drive(frankensqlite::Connection::open(path))?,
        })
    }

    /// Execute a single SQL statement, returning the affected row count.
    pub fn execute(&self, sql: &str) -> Result<usize, FrankenError> {
        drive(self.inner.execute(sql))
    }

    /// Execute a string of semicolon-separated SQL statements.
    pub fn execute_batch(&self, sql: &str) -> Result<(), FrankenError> {
        drive(self.inner.execute_batch(sql))
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // fsqlite 0.2 no longer checkpoints on drop, and read-only opens are
        // mutation-free (GH#294): they do not recover an unpublished WAL
        // sidecar. Closing in place on drop restores the pre-0.2 observable
        // contract that writes made through a dropped connection are visible
        // to a later read-only open.
        drive(self.inner.close_best_effort_in_place());
    }
}

/// Open a database with rusqlite-style open flags (synchronous form of
/// [`frankensqlite::compat::open_with_flags`]).
pub fn open_with_flags(path: &str, flags: OpenFlags) -> Result<Connection, FrankenError> {
    Ok(Connection {
        inner: drive(frankensqlite::compat::open_with_flags(path, flags))?,
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
        ))
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
        ))
    }

    fn execute_compat(&self, sql: &str, params: &[ParamValue]) -> Result<usize, FrankenError> {
        drive(AsyncConnectionExt::execute_compat(&self.inner, sql, params))
    }
}
