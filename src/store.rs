//! Correlation persistence. One row per (creator, bundle_id) — the invoice
//! identity the Lock Server polls with. State transitions are monotonic:
//! created -> paid -> confirmed, with reversed as a terminal branch reachable
//! from all three. A reversal of a confirmed row is recorded as
//! `reversed_after_confirm`: Locks has no un-complete transition, so an
//! entitlement the Lock Server already completed stays granted and the
//! reversal becomes a marketplace dispute matter (design §5), but this
//! gateway stops reporting `confirmed` for it from then on.

use std::time::Duration;

use async_trait::async_trait;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrelationState {
    Created,
    Paid,
    Confirmed,
    Reversed,
}

impl CorrelationState {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "created" => Some(Self::Created),
            "paid" => Some(Self::Paid),
            "confirmed" => Some(Self::Confirmed),
            "reversed" => Some(Self::Reversed),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Correlation {
    pub creator: String,
    pub bundle_id: String,
    pub lock_resource: String,
    pub reader: String,
    pub asset: String,
    pub amount_minor: i64,
    pub state: CorrelationState,
    /// Which processor the session/order belongs to (`stripe` | `paypal`).
    /// Bound when the session is minted and never rebound (fail-closed: a
    /// switch could leave a payable session on the abandoned processor).
    /// Rows minted before this column existed are Stripe rows.
    pub processor: Option<String>,
    pub session_id: Option<String>,
    pub checkout_url: Option<String>,
    pub checkout_expires_at: Option<i64>,
    /// Buyer return origin the session's redirect URLs were derived from
    /// (`None` = the static fallback URLs). Bound when the session is minted
    /// and never rebound, so a later callback or re-fetch cannot change it.
    pub return_origin: Option<String>,
    pub session_attempt: i32,
    /// Populated on the first verified-paid pull; the reversal path resolves
    /// charges back to correlations through it (SQL lookup in production).
    #[allow(dead_code)]
    pub payment_intent: Option<String>,
    pub amount_matched: bool,
    pub paid_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct NewCorrelation {
    pub creator: String,
    pub bundle_id: String,
    pub lock_resource: String,
    pub reader: String,
    pub asset: String,
    pub amount_minor: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted,
    /// Same (creator, bundle_id) with identical lock_resource + reader:
    /// idempotent replay, mirrors paykit-server's exact-replay acceptance.
    ExactReplay,
    /// Same identity bound to different terms: 409 upstream.
    Conflict,
}

/// What a verified reversal did to the row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReversalOutcome {
    /// created/paid -> reversed: promotion is suppressed.
    Reversed,
    /// confirmed -> reversed: the Lock Server may already have completed
    /// the task; the operator must handle it in the dispute flow.
    ReversedAfterConfirm,
    /// Already reversed, or no such row.
    Unchanged,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("correlation store error: {0}")]
    Failed(String),
    /// No pooled connection became free, and no new one opened, within the
    /// pool's acquire timeout; the statement never ran.
    #[error("correlation store busy: no pooled connection within the wait")]
    Busy,
}

#[async_trait]
pub trait CorrelationStore: Send + Sync {
    async fn insert_new(&self, new: NewCorrelation) -> Result<InsertOutcome, StoreError>;
    async fn get(&self, creator: &str, bundle_id: &str) -> Result<Option<Correlation>, StoreError>;
    /// Persists a freshly minted session only while the row is `created` and
    /// both bindings permit it. The stored `return_origin` must be unbound
    /// (NULL) or equal `return_origin`. The processor must be wholly unbound
    /// (NULL processor and session), or its effective value must equal the
    /// minted processor; a legacy row with a session and NULL processor is
    /// effectively Stripe. Thus the first persisted processor wins, while a
    /// same-processor re-mint remains valid. An attempt older than the
    /// stored `session_attempt` never applies, so a late persist cannot
    /// replace a newer session. At an equal attempt the write applies only
    /// when the row holds no session or the same `session_id`: two mints
    /// with different redirect URLs share an attempt under distinct keys,
    /// and the first to persist wins, so a session already served is never
    /// replaced by its concurrent sibling. A row whose attempt was skipped
    /// still holds its earlier session and refuses every other session at
    /// that attempt. Returns `false` when any guard
    /// rejects the write; the caller must not serve the session it minted.
    #[allow(clippy::too_many_arguments)]
    async fn set_session(
        &self,
        creator: &str,
        bundle_id: &str,
        processor: &str,
        session_id: &str,
        checkout_url: &str,
        checkout_expires_at: i64,
        session_attempt: i32,
        return_origin: Option<&str>,
    ) -> Result<bool, StoreError>;
    /// Records `session_attempt` as spent without a session, so the next
    /// mint starts after it. Forward-only and only while `created`; any
    /// other row is left as it is.
    async fn skip_session_attempt(
        &self,
        creator: &str,
        bundle_id: &str,
        session_attempt: i32,
    ) -> Result<(), StoreError>;
    /// Records a verified-paid observation (from the API pull, never from a
    /// webhook body). Forward-only: no-op unless current state is `created`.
    async fn mark_paid(
        &self,
        creator: &str,
        bundle_id: &str,
        amount_matched: bool,
        payment_intent: Option<&str>,
        paid_at: OffsetDateTime,
    ) -> Result<(), StoreError>;
    /// Promotes paid -> confirmed. No-op unless current state is `paid`.
    /// Promotion only follows a fresh pull, so it also counts as the first
    /// reversal check. Returns `true` only when this call moved the row; a
    /// row a concurrent writer already moved (for example to `reversed`)
    /// returns `false`.
    async fn mark_confirmed(
        &self,
        creator: &str,
        bundle_id: &str,
        confirmed_at: OffsetDateTime,
    ) -> Result<bool, StoreError>;
    /// Marks created/paid/confirmed -> reversed (verified reversal only).
    async fn mark_reversed(
        &self,
        creator: &str,
        bundle_id: &str,
        reversed_at: OffsetDateTime,
    ) -> Result<ReversalOutcome, StoreError>;
    async fn find_by_payment_intent(
        &self,
        payment_intent: &str,
    ) -> Result<Option<Correlation>, StoreError>;
    /// Returns true when the event id was new (i.e. should be processed).
    async fn record_webhook_event(
        &self,
        event_id: &str,
        event_type: &str,
    ) -> Result<bool, StoreError>;
    /// Drops a recorded event id after its processing failed transiently,
    /// so the processor's redelivery is processed instead of deduplicated.
    async fn forget_webhook_event(&self, event_id: &str) -> Result<(), StoreError>;
    /// Fiat correlations with a session that still need observation
    /// (state `created` or `paid`), for the slow-poll worker.
    async fn open_fiat_correlations(&self) -> Result<Vec<Correlation>, StoreError>;
    /// Confirmed correlations still inside the reversal watch window
    /// (`confirmed_at >= confirmed_after`) whose last reversal check is
    /// missing or older than `checked_before`, least recently checked first.
    async fn confirmed_due_for_reversal_check(
        &self,
        confirmed_after: OffsetDateTime,
        checked_before: OffsetDateTime,
    ) -> Result<Vec<Correlation>, StoreError>;
    async fn mark_reversal_checked(
        &self,
        creator: &str,
        bundle_id: &str,
        checked_at: OffsetDateTime,
    ) -> Result<(), StoreError>;
    async fn healthy(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Postgres implementation
// ---------------------------------------------------------------------------

pub struct PostgresStore {
    pool: sqlx::PgPool,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS correlations (
    creator TEXT NOT NULL,
    bundle_id TEXT NOT NULL,
    lock_resource TEXT NOT NULL,
    reader TEXT NOT NULL,
    asset TEXT NOT NULL,
    amount_minor BIGINT NOT NULL,
    state TEXT NOT NULL DEFAULT 'created',
    processor TEXT,
    session_id TEXT,
    checkout_url TEXT,
    checkout_expires_at BIGINT,
    return_origin TEXT,
    session_attempt INTEGER NOT NULL DEFAULT 0,
    payment_intent TEXT,
    amount_matched BOOLEAN NOT NULL DEFAULT FALSE,
    paid_at TIMESTAMPTZ,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (creator, bundle_id)
);
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS processor TEXT;
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS return_origin TEXT;
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS reversed_at TIMESTAMPTZ;
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS reversed_after_confirm BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS reversal_checked_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS correlations_payment_intent_idx
    ON correlations (payment_intent) WHERE payment_intent IS NOT NULL;
CREATE INDEX IF NOT EXISTS correlations_open_idx
    ON correlations (state) WHERE state IN ('created', 'paid');
CREATE INDEX IF NOT EXISTS correlations_reversal_watch_idx
    ON correlations (reversal_checked_at NULLS FIRST, confirmed_at) WHERE state = 'confirmed';
CREATE TABLE IF NOT EXISTS webhook_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"#;

/// Postgres connections one replica opens, split between the main pool and
/// the checkout pool. The checkout lookup concurrency is validated against
/// this value, so the main pool always keeps at least one connection.
pub const STORE_POOL_SIZE: u32 = 10;

/// The checkout pool's share of `STORE_POOL_SIZE`.
#[derive(Clone, Copy, Debug)]
pub struct CheckoutPool {
    pub connections: u32,
    /// How long a checkout statement waits for a connection before it fails
    /// with `StoreError::Busy` without running.
    pub acquire_timeout: Duration,
}

/// Two stores over one database. `/checkout-sessions` uses `checkout`;
/// everything else uses `main`. SQLx returns a dropped connection to its
/// pool in a spawned task that pings it first, and until then the
/// connection still counts against that pool's `max_connections`
/// (sqlx-core 0.8.6 `pool/connection.rs`). Separate pools therefore keep
/// checkout off the main pool's connections whatever the return timing.
pub struct PostgresStores {
    pub main: PostgresStore,
    pub checkout: PostgresStore,
}

impl PostgresStore {
    pub async fn connect(
        database_url: &str,
        checkout: CheckoutPool,
    ) -> Result<PostgresStores, StoreError> {
        if checkout.connections == 0 || checkout.connections >= STORE_POOL_SIZE {
            return Err(StoreError::Failed(format!(
                "checkout pool needs 1 to {} of the {STORE_POOL_SIZE} connections, got {}",
                STORE_POOL_SIZE - 1,
                checkout.connections
            )));
        }
        let main = sqlx::postgres::PgPoolOptions::new()
            .max_connections(STORE_POOL_SIZE - checkout.connections)
            .connect(database_url)
            .await
            .map_err(db_err)?;
        sqlx::raw_sql(SCHEMA).execute(&main).await.map_err(db_err)?;
        // Lazy so opening the pool does not run TCP/TLS under
        // `acquire_timeout`. The main pool already reached Postgres and
        // applied the schema; checkout connections open on first use, where
        // `acquire_timeout` bounds the wait as `FIAT_CHECKOUT_LOOKUP_WAIT_MS`.
        let checkout = sqlx::postgres::PgPoolOptions::new()
            .max_connections(checkout.connections)
            .acquire_timeout(checkout.acquire_timeout)
            .connect_lazy(database_url)
            .map_err(db_err)?;
        Ok(PostgresStores {
            main: Self { pool: main },
            checkout: Self { pool: checkout },
        })
    }

    #[cfg(test)]
    pub(crate) fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }
}

fn row_to_correlation(row: sqlx::postgres::PgRow) -> Result<Correlation, StoreError> {
    use sqlx::Row;
    let state: String = row.try_get("state").map_err(db_err)?;
    Ok(Correlation {
        creator: row.try_get("creator").map_err(db_err)?,
        bundle_id: row.try_get("bundle_id").map_err(db_err)?,
        lock_resource: row.try_get("lock_resource").map_err(db_err)?,
        reader: row.try_get("reader").map_err(db_err)?,
        asset: row.try_get("asset").map_err(db_err)?,
        amount_minor: row.try_get("amount_minor").map_err(db_err)?,
        state: CorrelationState::parse(&state)
            .ok_or_else(|| StoreError::Failed(format!("unknown state '{state}'")))?,
        processor: row.try_get("processor").map_err(db_err)?,
        session_id: row.try_get("session_id").map_err(db_err)?,
        checkout_url: row.try_get("checkout_url").map_err(db_err)?,
        checkout_expires_at: row.try_get("checkout_expires_at").map_err(db_err)?,
        return_origin: row.try_get("return_origin").map_err(db_err)?,
        session_attempt: row.try_get("session_attempt").map_err(db_err)?,
        payment_intent: row.try_get("payment_intent").map_err(db_err)?,
        amount_matched: row.try_get("amount_matched").map_err(db_err)?,
        paid_at: row.try_get("paid_at").map_err(db_err)?,
    })
}

fn db_err(error: sqlx::Error) -> StoreError {
    match error {
        sqlx::Error::PoolTimedOut => StoreError::Busy,
        error => StoreError::Failed(error.to_string()),
    }
}

const SELECT_COLUMNS: &str = "creator, bundle_id, lock_resource, reader, asset, amount_minor, \
     state, processor, session_id, checkout_url, checkout_expires_at, return_origin, \
     session_attempt, payment_intent, amount_matched, paid_at";

#[async_trait]
impl CorrelationStore for PostgresStore {
    async fn insert_new(&self, new: NewCorrelation) -> Result<InsertOutcome, StoreError> {
        let inserted = sqlx::query(
            "INSERT INTO correlations (creator, bundle_id, lock_resource, reader, asset, amount_minor) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (creator, bundle_id) DO NOTHING",
        )
        .bind(&new.creator)
        .bind(&new.bundle_id)
        .bind(&new.lock_resource)
        .bind(&new.reader)
        .bind(&new.asset)
        .bind(new.amount_minor)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        if inserted.rows_affected() == 1 {
            return Ok(InsertOutcome::Inserted);
        }
        let existing = self
            .get(&new.creator, &new.bundle_id)
            .await?
            .ok_or_else(|| StoreError::Failed("conflicting row vanished".to_owned()))?;
        if existing.lock_resource == new.lock_resource
            && existing.reader == new.reader
            && existing.asset == new.asset
            && existing.amount_minor == new.amount_minor
        {
            Ok(InsertOutcome::ExactReplay)
        } else {
            Ok(InsertOutcome::Conflict)
        }
    }

    async fn get(&self, creator: &str, bundle_id: &str) -> Result<Option<Correlation>, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM correlations WHERE creator = $1 AND bundle_id = $2"
        ))
        .bind(creator)
        .bind(bundle_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(row_to_correlation).transpose()
    }

    async fn set_session(
        &self,
        creator: &str,
        bundle_id: &str,
        processor: &str,
        session_id: &str,
        checkout_url: &str,
        checkout_expires_at: i64,
        session_attempt: i32,
        return_origin: Option<&str>,
    ) -> Result<bool, StoreError> {
        // One statement keeps the origin, processor, attempt, session, and
        // state guards atomic.
        // A legacy session with NULL processor is effectively Stripe.
        let updated = sqlx::query(
            "UPDATE correlations SET processor = $3, session_id = $4, checkout_url = $5, \
             checkout_expires_at = $6, session_attempt = $7, \
             return_origin = COALESCE($8, return_origin), updated_at = now() \
             WHERE creator = $1 AND bundle_id = $2 AND state = 'created' \
             AND (session_attempt < $7 \
                  OR (session_attempt = $7 AND (session_id IS NULL OR session_id = $4))) \
             AND (return_origin IS NULL OR return_origin = $8) \
             AND ((processor IS NULL AND session_id IS NULL) \
                  OR COALESCE(processor, CASE WHEN session_id IS NOT NULL THEN 'stripe' END) = $3)",
        )
        .bind(creator)
        .bind(bundle_id)
        .bind(processor)
        .bind(session_id)
        .bind(checkout_url)
        .bind(checkout_expires_at)
        .bind(session_attempt)
        .bind(return_origin)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(updated.rows_affected() == 1)
    }

    async fn skip_session_attempt(
        &self,
        creator: &str,
        bundle_id: &str,
        session_attempt: i32,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE correlations SET session_attempt = $3, updated_at = now() \
             WHERE creator = $1 AND bundle_id = $2 AND state = 'created' \
             AND session_attempt < $3",
        )
        .bind(creator)
        .bind(bundle_id)
        .bind(session_attempt)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn mark_paid(
        &self,
        creator: &str,
        bundle_id: &str,
        amount_matched: bool,
        payment_intent: Option<&str>,
        paid_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE correlations SET state = 'paid', amount_matched = $3, \
             payment_intent = COALESCE($4, payment_intent), paid_at = $5, updated_at = now() \
             WHERE creator = $1 AND bundle_id = $2 AND state = 'created'",
        )
        .bind(creator)
        .bind(bundle_id)
        .bind(amount_matched)
        .bind(payment_intent)
        .bind(paid_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn mark_confirmed(
        &self,
        creator: &str,
        bundle_id: &str,
        confirmed_at: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE correlations SET state = 'confirmed', confirmed_at = $3, \
             reversal_checked_at = $3, updated_at = now() \
             WHERE creator = $1 AND bundle_id = $2 AND state = 'paid'",
        )
        .bind(creator)
        .bind(bundle_id)
        .bind(confirmed_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn mark_reversed(
        &self,
        creator: &str,
        bundle_id: &str,
        reversed_at: OffsetDateTime,
    ) -> Result<ReversalOutcome, StoreError> {
        use sqlx::Row;
        // SET expressions read the pre-update row, so `state = 'confirmed'`
        // records whether this reversal landed after confirmation.
        let row = sqlx::query(
            "UPDATE correlations SET state = 'reversed', reversed_at = $3, \
             reversed_after_confirm = (state = 'confirmed'), updated_at = now() \
             WHERE creator = $1 AND bundle_id = $2 \
             AND state IN ('created', 'paid', 'confirmed') \
             RETURNING reversed_after_confirm",
        )
        .bind(creator)
        .bind(bundle_id)
        .bind(reversed_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(match row {
            None => ReversalOutcome::Unchanged,
            Some(row) => {
                if row
                    .try_get::<bool, _>("reversed_after_confirm")
                    .map_err(db_err)?
                {
                    ReversalOutcome::ReversedAfterConfirm
                } else {
                    ReversalOutcome::Reversed
                }
            }
        })
    }

    async fn find_by_payment_intent(
        &self,
        payment_intent: &str,
    ) -> Result<Option<Correlation>, StoreError> {
        let row = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM correlations WHERE payment_intent = $1 LIMIT 1"
        ))
        .bind(payment_intent)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(row_to_correlation).transpose()
    }

    async fn record_webhook_event(
        &self,
        event_id: &str,
        event_type: &str,
    ) -> Result<bool, StoreError> {
        let inserted = sqlx::query(
            "INSERT INTO webhook_events (event_id, event_type) VALUES ($1, $2) \
             ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(event_id)
        .bind(event_type)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(inserted.rows_affected() == 1)
    }

    async fn forget_webhook_event(&self, event_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM webhook_events WHERE event_id = $1")
            .bind(event_id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn open_fiat_correlations(&self) -> Result<Vec<Correlation>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM correlations \
             WHERE state IN ('created', 'paid') AND session_id IS NOT NULL \
             ORDER BY created_at ASC LIMIT 200"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(row_to_correlation).collect()
    }

    async fn confirmed_due_for_reversal_check(
        &self,
        confirmed_after: OffsetDateTime,
        checked_before: OffsetDateTime,
    ) -> Result<Vec<Correlation>, StoreError> {
        let rows = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM correlations \
             WHERE state = 'confirmed' AND session_id IS NOT NULL AND confirmed_at >= $1 \
             AND (reversal_checked_at IS NULL OR reversal_checked_at <= $2) \
             ORDER BY reversal_checked_at ASC NULLS FIRST, confirmed_at ASC LIMIT 200"
        ))
        .bind(confirmed_after)
        .bind(checked_before)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(row_to_correlation).collect()
    }

    async fn mark_reversal_checked(
        &self,
        creator: &str,
        bundle_id: &str,
        checked_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE correlations SET reversal_checked_at = $3 \
             WHERE creator = $1 AND bundle_id = $2 AND state = 'confirmed'",
        )
        .bind(creator)
        .bind(bundle_id)
        .bind(checked_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn healthy(&self) -> bool {
        sqlx::query("SELECT 1").execute(&self.pool).await.is_ok()
    }
}

// ---------------------------------------------------------------------------
// In-memory implementation (unit tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod memory {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use super::*;

    /// Columns the Postgres store keeps outside `Correlation`.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct RowMeta {
        pub confirmed_at: Option<OffsetDateTime>,
        pub reversed_at: Option<OffsetDateTime>,
        pub reversed_after_confirm: bool,
        pub reversal_checked_at: Option<OffsetDateTime>,
    }

    #[derive(Default)]
    pub struct MemoryStore {
        rows: Mutex<HashMap<(String, String), Correlation>>,
        meta: Mutex<HashMap<(String, String), RowMeta>>,
        events: Mutex<HashSet<String>>,
        gets: std::sync::atomic::AtomicUsize,
        set_session_pause: Mutex<Option<SetSessionPause>>,
    }

    /// Signals `reached` once the next `set_session` has been applied, then
    /// holds that call until `resume` fires.
    struct SetSessionPause {
        reached: tokio::sync::oneshot::Sender<()>,
        resume: tokio::sync::oneshot::Receiver<()>,
    }

    impl MemoryStore {
        /// Correlation reads served so far.
        pub fn get_calls(&self) -> usize {
            self.gets.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Pauses the next `set_session` after it is applied. Returns the
        /// receiver that fires when the call reaches the pause and the
        /// sender that lets it return.
        pub fn pause_next_set_session(
            &self,
        ) -> (
            tokio::sync::oneshot::Receiver<()>,
            tokio::sync::oneshot::Sender<()>,
        ) {
            let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
            let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
            *self.set_session_pause.lock().unwrap() = Some(SetSessionPause {
                reached: reached_tx,
                resume: resume_rx,
            });
            (reached_rx, resume_tx)
        }

        #[allow(clippy::too_many_arguments)]
        fn apply_session(
            &self,
            creator: &str,
            bundle_id: &str,
            processor: &str,
            session_id: &str,
            checkout_url: &str,
            checkout_expires_at: i64,
            session_attempt: i32,
            return_origin: Option<&str>,
        ) -> bool {
            let mut rows = self.rows.lock().unwrap();
            let Some(row) = rows.get_mut(&(creator.to_owned(), bundle_id.to_owned())) else {
                return false;
            };
            if row.state != CorrelationState::Created {
                return false;
            }
            if session_attempt < row.session_attempt {
                return false;
            }
            if session_attempt == row.session_attempt
                && row
                    .session_id
                    .as_deref()
                    .is_some_and(|held| held != session_id)
            {
                return false;
            }
            // Same origin guard as the SQL predicate: apply only while the
            // row is unbound or bound to exactly the minted origin. (When
            // `return_origin` is None this reduces to `is_none()`.)
            if row.return_origin.is_some() && row.return_origin.as_deref() != return_origin {
                return false;
            }
            let wholly_unbound = row.processor.is_none() && row.session_id.is_none();
            let effective_processor = crate::verification::bound_processor(row)
                .map(crate::verification::ProcessorKind::as_str);
            if !wholly_unbound && effective_processor != Some(processor) {
                return false;
            }
            row.processor = Some(processor.to_owned());
            row.session_id = Some(session_id.to_owned());
            row.checkout_url = Some(checkout_url.to_owned());
            row.checkout_expires_at = Some(checkout_expires_at);
            row.session_attempt = session_attempt;
            if let Some(origin) = return_origin {
                row.return_origin = Some(origin.to_owned());
            }
            true
        }

        pub fn meta(&self, creator: &str, bundle_id: &str) -> RowMeta {
            self.meta
                .lock()
                .unwrap()
                .get(&(creator.to_owned(), bundle_id.to_owned()))
                .copied()
                .unwrap_or_default()
        }
    }

    #[async_trait]
    impl CorrelationStore for MemoryStore {
        async fn insert_new(&self, new: NewCorrelation) -> Result<InsertOutcome, StoreError> {
            let mut rows = self.rows.lock().unwrap();
            let key = (new.creator.clone(), new.bundle_id.clone());
            if let Some(existing) = rows.get(&key) {
                return Ok(
                    if existing.lock_resource == new.lock_resource
                        && existing.reader == new.reader
                        && existing.asset == new.asset
                        && existing.amount_minor == new.amount_minor
                    {
                        InsertOutcome::ExactReplay
                    } else {
                        InsertOutcome::Conflict
                    },
                );
            }
            rows.insert(
                key,
                Correlation {
                    creator: new.creator,
                    bundle_id: new.bundle_id,
                    lock_resource: new.lock_resource,
                    reader: new.reader,
                    asset: new.asset,
                    amount_minor: new.amount_minor,
                    state: CorrelationState::Created,
                    processor: None,
                    session_id: None,
                    checkout_url: None,
                    checkout_expires_at: None,
                    return_origin: None,
                    session_attempt: 0,
                    payment_intent: None,
                    amount_matched: false,
                    paid_at: None,
                },
            );
            Ok(InsertOutcome::Inserted)
        }

        async fn get(
            &self,
            creator: &str,
            bundle_id: &str,
        ) -> Result<Option<Correlation>, StoreError> {
            self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self
                .rows
                .lock()
                .unwrap()
                .get(&(creator.to_owned(), bundle_id.to_owned()))
                .cloned())
        }

        async fn set_session(
            &self,
            creator: &str,
            bundle_id: &str,
            processor: &str,
            session_id: &str,
            checkout_url: &str,
            checkout_expires_at: i64,
            session_attempt: i32,
            return_origin: Option<&str>,
        ) -> Result<bool, StoreError> {
            let applied = self.apply_session(
                creator,
                bundle_id,
                processor,
                session_id,
                checkout_url,
                checkout_expires_at,
                session_attempt,
                return_origin,
            );
            let pause = self.set_session_pause.lock().unwrap().take();
            if let Some(pause) = pause {
                let _ = pause.reached.send(());
                let _ = pause.resume.await;
            }
            Ok(applied)
        }

        async fn skip_session_attempt(
            &self,
            creator: &str,
            bundle_id: &str,
            session_attempt: i32,
        ) -> Result<(), StoreError> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.get_mut(&(creator.to_owned(), bundle_id.to_owned())) {
                if row.state == CorrelationState::Created && row.session_attempt < session_attempt {
                    row.session_attempt = session_attempt;
                }
            }
            Ok(())
        }

        async fn mark_paid(
            &self,
            creator: &str,
            bundle_id: &str,
            amount_matched: bool,
            payment_intent: Option<&str>,
            paid_at: OffsetDateTime,
        ) -> Result<(), StoreError> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.get_mut(&(creator.to_owned(), bundle_id.to_owned())) {
                if row.state == CorrelationState::Created {
                    row.state = CorrelationState::Paid;
                    row.amount_matched = amount_matched;
                    if let Some(pi) = payment_intent {
                        row.payment_intent = Some(pi.to_owned());
                    }
                    row.paid_at = Some(paid_at);
                }
            }
            Ok(())
        }

        async fn mark_confirmed(
            &self,
            creator: &str,
            bundle_id: &str,
            confirmed_at: OffsetDateTime,
        ) -> Result<bool, StoreError> {
            let key = (creator.to_owned(), bundle_id.to_owned());
            let mut rows = self.rows.lock().unwrap();
            let Some(row) = rows.get_mut(&key) else {
                return Ok(false);
            };
            if row.state != CorrelationState::Paid {
                return Ok(false);
            }
            row.state = CorrelationState::Confirmed;
            let mut meta = self.meta.lock().unwrap();
            let meta = meta.entry(key).or_default();
            meta.confirmed_at = Some(confirmed_at);
            meta.reversal_checked_at = Some(confirmed_at);
            Ok(true)
        }

        async fn mark_reversed(
            &self,
            creator: &str,
            bundle_id: &str,
            reversed_at: OffsetDateTime,
        ) -> Result<ReversalOutcome, StoreError> {
            let key = (creator.to_owned(), bundle_id.to_owned());
            let mut rows = self.rows.lock().unwrap();
            let Some(row) = rows.get_mut(&key) else {
                return Ok(ReversalOutcome::Unchanged);
            };
            let after_confirm = match row.state {
                CorrelationState::Created | CorrelationState::Paid => false,
                CorrelationState::Confirmed => true,
                CorrelationState::Reversed => return Ok(ReversalOutcome::Unchanged),
            };
            row.state = CorrelationState::Reversed;
            let mut meta = self.meta.lock().unwrap();
            let meta = meta.entry(key).or_default();
            meta.reversed_at = Some(reversed_at);
            meta.reversed_after_confirm = after_confirm;
            Ok(if after_confirm {
                ReversalOutcome::ReversedAfterConfirm
            } else {
                ReversalOutcome::Reversed
            })
        }

        async fn find_by_payment_intent(
            &self,
            payment_intent: &str,
        ) -> Result<Option<Correlation>, StoreError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .values()
                .find(|row| row.payment_intent.as_deref() == Some(payment_intent))
                .cloned())
        }

        async fn record_webhook_event(
            &self,
            event_id: &str,
            _event_type: &str,
        ) -> Result<bool, StoreError> {
            Ok(self.events.lock().unwrap().insert(event_id.to_owned()))
        }

        async fn forget_webhook_event(&self, event_id: &str) -> Result<(), StoreError> {
            self.events.lock().unwrap().remove(event_id);
            Ok(())
        }

        async fn open_fiat_correlations(&self) -> Result<Vec<Correlation>, StoreError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .values()
                .filter(|row| {
                    matches!(
                        row.state,
                        CorrelationState::Created | CorrelationState::Paid
                    ) && row.session_id.is_some()
                })
                .cloned()
                .collect())
        }

        async fn confirmed_due_for_reversal_check(
            &self,
            confirmed_after: OffsetDateTime,
            checked_before: OffsetDateTime,
        ) -> Result<Vec<Correlation>, StoreError> {
            let rows = self.rows.lock().unwrap();
            let meta = self.meta.lock().unwrap();
            let mut due: Vec<(Option<OffsetDateTime>, OffsetDateTime, Correlation)> = rows
                .iter()
                .filter(|(_, row)| {
                    row.state == CorrelationState::Confirmed && row.session_id.is_some()
                })
                .filter_map(|(key, row)| {
                    let meta = meta.get(key).copied().unwrap_or_default();
                    let confirmed_at = meta.confirmed_at?;
                    let checked_ok = meta
                        .reversal_checked_at
                        .is_none_or(|checked| checked <= checked_before);
                    (confirmed_at >= confirmed_after && checked_ok)
                        .then(|| (meta.reversal_checked_at, confirmed_at, row.clone()))
                })
                .collect();
            due.sort_by_key(|entry| (entry.0, entry.1));
            Ok(due.into_iter().map(|(_, _, row)| row).take(200).collect())
        }

        async fn mark_reversal_checked(
            &self,
            creator: &str,
            bundle_id: &str,
            checked_at: OffsetDateTime,
        ) -> Result<(), StoreError> {
            let key = (creator.to_owned(), bundle_id.to_owned());
            let confirmed = self
                .rows
                .lock()
                .unwrap()
                .get(&key)
                .is_some_and(|row| row.state == CorrelationState::Confirmed);
            if confirmed {
                self.meta
                    .lock()
                    .unwrap()
                    .entry(key)
                    .or_default()
                    .reversal_checked_at = Some(checked_at);
            }
            Ok(())
        }

        async fn healthy(&self) -> bool {
            true
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const CREATOR: &str = "pubkycreator";

        fn new_row(bundle_id: &str) -> NewCorrelation {
            NewCorrelation {
                creator: CREATOR.to_owned(),
                bundle_id: bundle_id.to_owned(),
                lock_resource: format!("{CREATOR}/pub/locks.app/usd.json"),
                reader: "pubkyreader".to_owned(),
                asset: "USD".to_owned(),
                amount_minor: 1999,
            }
        }

        async fn insert(store: &MemoryStore, bundle_id: &str) {
            assert_eq!(
                store.insert_new(new_row(bundle_id)).await.unwrap(),
                InsertOutcome::Inserted
            );
        }

        async fn mint(
            store: &MemoryStore,
            bundle_id: &str,
            processor: &str,
            session_id: &str,
            attempt: i32,
        ) -> bool {
            store
                .set_session(
                    CREATOR,
                    bundle_id,
                    processor,
                    session_id,
                    "https://checkout.test/session",
                    1000,
                    attempt,
                    None,
                )
                .await
                .unwrap()
        }

        async fn row(store: &MemoryStore, bundle_id: &str) -> Correlation {
            store.get(CREATOR, bundle_id).await.unwrap().unwrap()
        }

        async fn row_id(store: &MemoryStore, bundle_id: &str) -> Option<String> {
            row(store, bundle_id).await.session_id
        }

        async fn mint_for_origin(
            store: &MemoryStore,
            bundle_id: &str,
            session_id: &str,
            attempt: i32,
            return_origin: Option<&str>,
        ) -> bool {
            store
                .set_session(
                    CREATOR,
                    bundle_id,
                    "stripe",
                    session_id,
                    "https://checkout.test/session",
                    1000,
                    attempt,
                    return_origin,
                )
                .await
                .unwrap()
        }

        #[tokio::test]
        async fn a_bound_origin_refuses_writes_for_no_origin_or_another_origin() {
            const ORIGIN_A: &str = "https://a.test";
            const ORIGIN_B: &str = "https://b.test";
            let store = MemoryStore::default();
            insert(&store, "ORIGIN").await;
            assert!(mint_for_origin(&store, "ORIGIN", "cs_a", 1, Some(ORIGIN_A)).await);
            for attempt in [1, 2] {
                assert!(
                    !mint_for_origin(&store, "ORIGIN", "cs_none", attempt, None).await,
                    "a write naming no origin applied at attempt {attempt}"
                );
                assert!(
                    !mint_for_origin(&store, "ORIGIN", "cs_b", attempt, Some(ORIGIN_B)).await,
                    "a write naming another origin applied at attempt {attempt}"
                );
            }
            let bound = row(&store, "ORIGIN").await;
            assert_eq!(bound.session_id.as_deref(), Some("cs_a"));
            assert_eq!(bound.session_attempt, 1);
            assert_eq!(bound.return_origin.as_deref(), Some(ORIGIN_A));

            assert!(mint_for_origin(&store, "ORIGIN", "cs_a2", 2, Some(ORIGIN_A)).await);
            let rebound = row(&store, "ORIGIN").await;
            assert_eq!(rebound.session_id.as_deref(), Some("cs_a2"));
            assert_eq!(rebound.session_attempt, 2);
            assert_eq!(rebound.return_origin.as_deref(), Some(ORIGIN_A));
        }

        #[tokio::test]
        async fn set_session_never_moves_the_attempt_backwards() {
            let store = MemoryStore::default();
            insert(&store, "BACK").await;
            assert!(mint(&store, "BACK", "stripe", "cs_new", 2).await);
            assert!(!mint(&store, "BACK", "stripe", "cs_old", 1).await);
            let row = row(&store, "BACK").await;
            assert_eq!(row.session_id.as_deref(), Some("cs_new"));
            assert_eq!(row.session_attempt, 2);
            assert!(mint(&store, "BACK", "stripe", "cs_new", 2).await);
            assert_eq!(row_id(&store, "BACK").await, Some("cs_new".to_owned()));
        }

        #[tokio::test]
        async fn an_equal_attempt_never_replaces_a_different_session() {
            let store = MemoryStore::default();
            insert(&store, "EQUAL").await;
            assert!(mint(&store, "EQUAL", "stripe", "cs_first", 2).await);
            assert!(
                !mint(&store, "EQUAL", "stripe", "cs_second", 2).await,
                "a second session at the same attempt applied"
            );
            assert!(
                !mint_for_origin(&store, "EQUAL", "cs_origin", 2, Some("https://a.test")).await,
                "an origin-bound session at the same attempt applied"
            );
            let held = row(&store, "EQUAL").await;
            assert_eq!(held.session_id.as_deref(), Some("cs_first"));
            assert_eq!(held.return_origin, None);
            assert!(mint(&store, "EQUAL", "stripe", "cs_first", 2).await);

            insert(&store, "SKIPPED").await;
            store
                .skip_session_attempt(CREATOR, "SKIPPED", 2)
                .await
                .unwrap();
            assert!(mint(&store, "SKIPPED", "stripe", "cs_after_skip", 2).await);

            insert(&store, "HELD").await;
            assert!(mint(&store, "HELD", "stripe", "cs_held", 1).await);
            store
                .skip_session_attempt(CREATOR, "HELD", 2)
                .await
                .unwrap();
            assert!(
                !mint(&store, "HELD", "stripe", "cs_skipped", 2).await,
                "a session at a skipped attempt replaced the held session"
            );
            assert_eq!(row_id(&store, "HELD").await, Some("cs_held".to_owned()));
            assert!(mint(&store, "HELD", "stripe", "cs_next", 3).await);
        }

        #[tokio::test]
        async fn a_skipped_session_attempt_only_moves_forward_on_created_rows() {
            let store = MemoryStore::default();
            insert(&store, "SKIP1").await;
            store
                .skip_session_attempt(CREATOR, "SKIP1", 2)
                .await
                .unwrap();
            assert_eq!(row(&store, "SKIP1").await.session_attempt, 2);
            store
                .skip_session_attempt(CREATOR, "SKIP1", 1)
                .await
                .unwrap();
            assert_eq!(row(&store, "SKIP1").await.session_attempt, 2);
            assert!(mint(&store, "SKIP1", "stripe", "cs_skip", 3).await);
            assert_eq!(row(&store, "SKIP1").await.session_attempt, 3);

            insert(&store, "SKIP2").await;
            assert!(mint(&store, "SKIP2", "stripe", "cs_paid", 1).await);
            store
                .mark_paid(
                    CREATOR,
                    "SKIP2",
                    true,
                    Some("pi_paid"),
                    OffsetDateTime::now_utc(),
                )
                .await
                .unwrap();
            store
                .skip_session_attempt(CREATOR, "SKIP2", 5)
                .await
                .unwrap();
            assert_eq!(row(&store, "SKIP2").await.session_attempt, 1);

            store
                .skip_session_attempt(CREATOR, "NOSUCHROW", 1)
                .await
                .unwrap();
        }

        fn make_legacy(store: &MemoryStore, bundle_id: &str) {
            store
                .rows
                .lock()
                .unwrap()
                .get_mut(&(CREATOR.to_owned(), bundle_id.to_owned()))
                .unwrap()
                .processor = None;
        }

        fn assert_unchanged(before: &Correlation, after: &Correlation) {
            assert_eq!(format!("{before:?}"), format!("{after:?}"));
        }

        #[tokio::test]
        async fn set_session_guards_processor_binding_and_created_state() {
            let store = MemoryStore::default();
            for bundle in ["BOUND", "LEGACYPAYPAL", "PAID", "REMINT", "LEGACYSTRIPE"] {
                insert(&store, bundle).await;
            }

            assert!(mint(&store, "BOUND", "stripe", "cs_1", 1).await);
            let before = row(&store, "BOUND").await;
            assert!(!mint(&store, "BOUND", "paypal", "pp_1", 2).await);
            assert_unchanged(&before, &row(&store, "BOUND").await);

            assert!(mint(&store, "LEGACYPAYPAL", "stripe", "cs_legacy", 1).await);
            make_legacy(&store, "LEGACYPAYPAL");
            let before = row(&store, "LEGACYPAYPAL").await;
            assert!(!mint(&store, "LEGACYPAYPAL", "paypal", "pp_legacy", 2).await);
            assert_unchanged(&before, &row(&store, "LEGACYPAYPAL").await);

            assert!(mint(&store, "PAID", "stripe", "cs_paid", 1).await);
            store
                .mark_paid(CREATOR, "PAID", true, None, OffsetDateTime::now_utc())
                .await
                .unwrap();
            let before = row(&store, "PAID").await;
            assert!(!mint(&store, "PAID", "stripe", "cs_replacement", 2).await);
            assert_unchanged(&before, &row(&store, "PAID").await);

            assert!(mint(&store, "REMINT", "stripe", "cs_old", 1).await);
            assert!(mint(&store, "REMINT", "stripe", "cs_new", 2).await);
            let reminted = row(&store, "REMINT").await;
            assert_eq!(reminted.processor.as_deref(), Some("stripe"));
            assert_eq!(reminted.session_id.as_deref(), Some("cs_new"));

            assert!(mint(&store, "LEGACYSTRIPE", "stripe", "cs_legacy", 1).await);
            make_legacy(&store, "LEGACYSTRIPE");
            assert!(mint(&store, "LEGACYSTRIPE", "stripe", "cs_new", 2).await);
            let rebound = row(&store, "LEGACYSTRIPE").await;
            assert_eq!(rebound.processor.as_deref(), Some("stripe"));
            assert_eq!(rebound.session_id.as_deref(), Some("cs_new"));
        }

        #[tokio::test]
        async fn mark_confirmed_reports_whether_the_row_moved() {
            let store = MemoryStore::default();
            let now = OffsetDateTime::now_utc();
            for bundle in ["PROMOTE", "REVERSED"] {
                insert(&store, bundle).await;
                assert!(mint(&store, bundle, "stripe", "cs_1", 1).await);
                store
                    .mark_paid(CREATOR, bundle, true, None, now)
                    .await
                    .unwrap();
            }

            assert!(store.mark_confirmed(CREATOR, "PROMOTE", now).await.unwrap());
            assert!(!store.mark_confirmed(CREATOR, "PROMOTE", now).await.unwrap());
            assert_eq!(
                row(&store, "PROMOTE").await.state,
                CorrelationState::Confirmed
            );

            store.mark_reversed(CREATOR, "REVERSED", now).await.unwrap();
            assert!(!store
                .mark_confirmed(CREATOR, "REVERSED", now)
                .await
                .unwrap());
            assert_eq!(
                row(&store, "REVERSED").await.state,
                CorrelationState::Reversed
            );
            assert!(store.meta(CREATOR, "REVERSED").confirmed_at.is_none());
            assert!(!store.mark_confirmed(CREATOR, "MISSING", now).await.unwrap());
        }
    }
}

/// The Postgres store against a real database. Runs when
/// `FIAT_TEST_DATABASE_URL` is set (CI provides a Postgres service); rows
/// use a per-run creator so runs never interfere.
#[cfg(test)]
pub(crate) mod postgres_tests {
    use std::time::Duration;

    use super::*;

    /// Concurrent `CREATE ... IF NOT EXISTS` on a fresh database can race in
    /// Postgres, so the tests bootstrap the schema one at a time.
    static BOOTSTRAP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// The acquire timeout bounds runtime pool acquisition on a loaded
    /// machine. Tests that assert a pool timeout use `stores_with`.
    pub(crate) const TEST_CHECKOUT_POOL: CheckoutPool = CheckoutPool {
        connections: 4,
        acquire_timeout: Duration::from_secs(10),
    };

    pub(crate) async fn store() -> Option<PostgresStore> {
        stores().await.map(|stores| stores.main)
    }

    pub(crate) async fn stores() -> Option<PostgresStores> {
        stores_with(TEST_CHECKOUT_POOL).await
    }

    pub(crate) async fn stores_with(checkout: CheckoutPool) -> Option<PostgresStores> {
        let Ok(url) = std::env::var("FIAT_TEST_DATABASE_URL") else {
            eprintln!("FIAT_TEST_DATABASE_URL unset: skipping the Postgres store test");
            return None;
        };
        let _bootstrap = BOOTSTRAP.lock().await;
        // Connecting twice proves the schema bootstrap is idempotent.
        PostgresStore::connect(&url, checkout)
            .await
            .expect("first connect");
        Some(
            PostgresStore::connect(&url, checkout)
                .await
                .expect("second connect"),
        )
    }

    fn new_row(creator: &str, bundle_id: &str) -> NewCorrelation {
        NewCorrelation {
            creator: creator.to_owned(),
            bundle_id: bundle_id.to_owned(),
            lock_resource: format!("{creator}/pub/locks.app/usd.json"),
            reader: "pubkyreader".to_owned(),
            asset: "USD".to_owned(),
            amount_minor: 1999,
        }
    }

    async fn paid_row(store: &PostgresStore, creator: &str, bundle_id: &str, at: OffsetDateTime) {
        assert_eq!(
            store.insert_new(new_row(creator, bundle_id)).await.unwrap(),
            InsertOutcome::Inserted
        );
        assert!(store
            .set_session(
                creator,
                bundle_id,
                "stripe",
                "cs_1",
                "https://x",
                0,
                1,
                None
            )
            .await
            .unwrap());
        store
            .mark_paid(
                creator,
                bundle_id,
                true,
                Some(&format!("pi_{creator}_{bundle_id}")),
                at,
            )
            .await
            .unwrap();
    }

    async fn mint(
        store: &PostgresStore,
        creator: &str,
        bundle_id: &str,
        processor: &str,
        session_id: &str,
        attempt: i32,
    ) -> bool {
        store
            .set_session(
                creator,
                bundle_id,
                processor,
                session_id,
                "https://checkout.test/session",
                1000,
                attempt,
                None,
            )
            .await
            .unwrap()
    }

    async fn make_legacy(store: &PostgresStore, creator: &str, bundle_id: &str) {
        sqlx::query(
            "UPDATE correlations SET processor = NULL WHERE creator = $1 AND bundle_id = $2",
        )
        .bind(creator)
        .bind(bundle_id)
        .execute(&store.pool)
        .await
        .unwrap();
    }

    fn assert_unchanged(before: &Correlation, after: &Correlation) {
        assert_eq!(format!("{before:?}"), format!("{after:?}"));
    }

    #[tokio::test]
    async fn checkout_pool_lazy_connect_survives_a_short_acquire_budget() {
        let Some(url) = std::env::var("FIAT_TEST_DATABASE_URL").ok() else {
            eprintln!("FIAT_TEST_DATABASE_URL unset: skipping the Postgres store test");
            return;
        };
        let _bootstrap = BOOTSTRAP.lock().await;
        let checkout = CheckoutPool {
            connections: 2,
            acquire_timeout: Duration::from_millis(1),
        };
        let stores = PostgresStore::connect(&url, checkout)
            .await
            .expect("lazy checkout pool must not open checkout TCP at boot");
        assert_eq!(stores.checkout.pool().size(), 0);
    }

    #[tokio::test]
    async fn checkout_pool_acquire_waits_then_times_out_at_runtime() {
        let Some(stores) = stores_with(CheckoutPool {
            connections: 1,
            acquire_timeout: Duration::from_millis(250),
        })
        .await
        else {
            return;
        };
        let held = stores
            .checkout
            .pool()
            .acquire()
            .await
            .expect("first checkout acquire succeeds");
        let started = std::time::Instant::now();
        let second =
            tokio::time::timeout(Duration::from_secs(2), stores.checkout.pool().acquire()).await;
        assert!(
            matches!(second, Ok(Err(sqlx::Error::PoolTimedOut)),),
            "second acquire must time out"
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(200),
            "waited only {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "acquire must not exceed the test harness timeout"
        );
        drop(held);
    }

    #[tokio::test]
    async fn the_pools_split_the_shared_connection_budget() {
        let Some(stores) = stores().await else {
            return;
        };
        assert_eq!(
            stores.main.pool().options().get_max_connections(),
            STORE_POOL_SIZE - TEST_CHECKOUT_POOL.connections
        );
        assert_eq!(
            stores.checkout.pool().options().get_max_connections(),
            TEST_CHECKOUT_POOL.connections
        );
        assert_eq!(
            stores.checkout.pool().options().get_acquire_timeout(),
            TEST_CHECKOUT_POOL.acquire_timeout
        );
        let url = std::env::var("FIAT_TEST_DATABASE_URL").unwrap();
        for connections in [0, STORE_POOL_SIZE] {
            let refused = PostgresStore::connect(
                &url,
                CheckoutPool {
                    connections,
                    ..TEST_CHECKOUT_POOL
                },
            )
            .await;
            assert!(
                matches!(refused, Err(StoreError::Failed(_))),
                "{connections}"
            );
        }
    }

    #[tokio::test]
    async fn a_skipped_session_attempt_only_moves_forward_on_created_rows() {
        let Some(store) = store().await else {
            return;
        };
        let creator = format!(
            "pubkytest{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        store.insert_new(new_row(&creator, "SKIP1")).await.unwrap();
        store
            .skip_session_attempt(&creator, "SKIP1", 2)
            .await
            .unwrap();
        assert_eq!(
            store
                .get(&creator, "SKIP1")
                .await
                .unwrap()
                .unwrap()
                .session_attempt,
            2
        );
        store
            .skip_session_attempt(&creator, "SKIP1", 1)
            .await
            .unwrap();
        assert_eq!(
            store
                .get(&creator, "SKIP1")
                .await
                .unwrap()
                .unwrap()
                .session_attempt,
            2,
            "never backwards"
        );
        assert!(mint(&store, &creator, "SKIP1", "stripe", "cs_skip", 3).await);
        assert_eq!(
            store
                .get(&creator, "SKIP1")
                .await
                .unwrap()
                .unwrap()
                .session_attempt,
            3
        );

        paid_row(&store, &creator, "SKIP2", OffsetDateTime::now_utc()).await;
        let before = store.get(&creator, "SKIP2").await.unwrap().unwrap();
        store
            .skip_session_attempt(&creator, "SKIP2", 5)
            .await
            .unwrap();
        assert_unchanged(
            &before,
            &store.get(&creator, "SKIP2").await.unwrap().unwrap(),
        );

        store
            .skip_session_attempt(&creator, "NOSUCHROW", 1)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reversal_columns_and_queries_round_trip() {
        let Some(store) = store().await else {
            return;
        };
        // Postgres keeps microseconds; truncate so round-trips compare equal.
        let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let creator = format!(
            "pubkytest{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let mine = |rows: Vec<Correlation>| -> Vec<String> {
            rows.into_iter()
                .filter(|row| row.creator == creator)
                .map(|row| row.bundle_id)
                .collect()
        };
        let hour = Duration::from_secs(3600);
        let day = Duration::from_secs(86_400);

        // Reversed before confirmation.
        paid_row(&store, &creator, "EARLY", now).await;
        assert_eq!(
            store.mark_reversed(&creator, "EARLY", now).await.unwrap(),
            ReversalOutcome::Reversed
        );
        assert_eq!(
            store.mark_reversed(&creator, "EARLY", now).await.unwrap(),
            ReversalOutcome::Unchanged
        );

        // Confirmed: the confirmation counts as the first check.
        paid_row(&store, &creator, "LATE", now).await;
        assert!(store.mark_confirmed(&creator, "LATE", now).await.unwrap());
        assert!(mine(
            store
                .confirmed_due_for_reversal_check(now - day, now - Duration::from_secs(1))
                .await
                .unwrap()
        )
        .is_empty());
        assert!(mine(
            store
                .confirmed_due_for_reversal_check(now - day, now - hour)
                .await
                .unwrap()
        )
        .is_empty());
        let later = now + hour;
        assert_eq!(
            mine(
                store
                    .confirmed_due_for_reversal_check(later - day, later - hour)
                    .await
                    .unwrap()
            ),
            vec!["LATE".to_owned()]
        );
        // Outside the watch window it is no longer listed.
        assert!(mine(
            store
                .confirmed_due_for_reversal_check(now + Duration::from_secs(1), later - hour)
                .await
                .unwrap()
        )
        .is_empty());

        store
            .mark_reversal_checked(&creator, "LATE", later)
            .await
            .unwrap();
        assert!(mine(
            store
                .confirmed_due_for_reversal_check(later - day, later - Duration::from_secs(1))
                .await
                .unwrap()
        )
        .is_empty());
        assert_eq!(
            mine(
                store
                    .confirmed_due_for_reversal_check(later - day, later + hour)
                    .await
                    .unwrap()
            ),
            vec!["LATE".to_owned()]
        );

        // Reversed after confirmation, recorded as such, and off the watch.
        assert_eq!(
            store.mark_reversed(&creator, "LATE", later).await.unwrap(),
            ReversalOutcome::ReversedAfterConfirm
        );
        assert_eq!(
            store.get(&creator, "LATE").await.unwrap().unwrap().state,
            CorrelationState::Reversed
        );
        assert!(mine(
            store
                .confirmed_due_for_reversal_check(later - day, later + day)
                .await
                .unwrap()
        )
        .is_empty());
        assert_eq!(
            store
                .find_by_payment_intent(&format!("pi_{creator}_LATE"))
                .await
                .unwrap()
                .unwrap()
                .bundle_id,
            "LATE"
        );
    }

    #[tokio::test]
    async fn set_session_guards_processor_binding_and_created_state() {
        let Some(store) = store().await else {
            return;
        };
        let creator = format!(
            "pubkytest{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        for bundle in ["BOUND", "LEGACYPAYPAL", "PAID", "REMINT", "LEGACYSTRIPE"] {
            assert_eq!(
                store.insert_new(new_row(&creator, bundle)).await.unwrap(),
                InsertOutcome::Inserted
            );
        }
        let row = |bundle| {
            let store = &store;
            let creator = &creator;
            async move { store.get(creator, bundle).await.unwrap().unwrap() }
        };

        assert!(mint(&store, &creator, "BOUND", "stripe", "cs_1", 1).await);
        let before = row("BOUND").await;
        assert!(!mint(&store, &creator, "BOUND", "paypal", "pp_1", 2).await);
        assert_unchanged(&before, &row("BOUND").await);

        assert!(mint(&store, &creator, "LEGACYPAYPAL", "stripe", "cs_legacy", 1).await);
        make_legacy(&store, &creator, "LEGACYPAYPAL").await;
        let before = row("LEGACYPAYPAL").await;
        assert!(!mint(&store, &creator, "LEGACYPAYPAL", "paypal", "pp_legacy", 2).await);
        assert_unchanged(&before, &row("LEGACYPAYPAL").await);

        assert!(mint(&store, &creator, "PAID", "stripe", "cs_paid", 1).await);
        store
            .mark_paid(&creator, "PAID", true, None, OffsetDateTime::now_utc())
            .await
            .unwrap();
        let before = row("PAID").await;
        assert!(!mint(&store, &creator, "PAID", "stripe", "cs_replacement", 2).await);
        assert_unchanged(&before, &row("PAID").await);

        assert!(mint(&store, &creator, "REMINT", "stripe", "cs_old", 1).await);
        assert!(mint(&store, &creator, "REMINT", "stripe", "cs_new", 2).await);
        let reminted = row("REMINT").await;
        assert_eq!(reminted.processor.as_deref(), Some("stripe"));
        assert_eq!(reminted.session_id.as_deref(), Some("cs_new"));

        assert!(mint(&store, &creator, "LEGACYSTRIPE", "stripe", "cs_legacy", 1).await);
        make_legacy(&store, &creator, "LEGACYSTRIPE").await;
        assert!(mint(&store, &creator, "LEGACYSTRIPE", "stripe", "cs_new", 2).await);
        let rebound = row("LEGACYSTRIPE").await;
        assert_eq!(rebound.processor.as_deref(), Some("stripe"));
        assert_eq!(rebound.session_id.as_deref(), Some("cs_new"));
    }

    #[tokio::test]
    async fn mark_confirmed_reports_whether_the_row_moved() {
        let Some(store) = store().await else {
            return;
        };
        let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let creator = format!(
            "pubkytest{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        paid_row(&store, &creator, "PROMOTE", now).await;
        paid_row(&store, &creator, "REVERSED", now).await;

        assert!(store
            .mark_confirmed(&creator, "PROMOTE", now)
            .await
            .unwrap());
        assert!(!store
            .mark_confirmed(&creator, "PROMOTE", now)
            .await
            .unwrap());
        assert_eq!(
            store.get(&creator, "PROMOTE").await.unwrap().unwrap().state,
            CorrelationState::Confirmed
        );

        store
            .mark_reversed(&creator, "REVERSED", now)
            .await
            .unwrap();
        assert!(!store
            .mark_confirmed(&creator, "REVERSED", now)
            .await
            .unwrap());
        assert_eq!(
            store
                .get(&creator, "REVERSED")
                .await
                .unwrap()
                .unwrap()
                .state,
            CorrelationState::Reversed
        );
        assert!(!store
            .mark_confirmed(&creator, "MISSING", now)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn forgotten_webhook_events_are_processed_again() {
        let Some(store) = store().await else {
            return;
        };
        let event_id = format!(
            "evt_test_{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        assert!(store
            .record_webhook_event(&event_id, "charge.refunded")
            .await
            .unwrap());
        assert!(!store
            .record_webhook_event(&event_id, "charge.refunded")
            .await
            .unwrap());
        store.forget_webhook_event(&event_id).await.unwrap();
        assert!(store
            .record_webhook_event(&event_id, "charge.refunded")
            .await
            .unwrap());
    }

    async fn mint_for_origin(
        store: &PostgresStore,
        creator: &str,
        session_id: &str,
        attempt: i32,
        return_origin: Option<&str>,
    ) -> bool {
        store
            .set_session(
                creator,
                "ORIGIN",
                "stripe",
                session_id,
                "https://checkout.test/session",
                1000,
                attempt,
                return_origin,
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_bound_origin_refuses_writes_for_no_origin_or_another_origin() {
        const ORIGIN_A: &str = "https://a.test";
        const ORIGIN_B: &str = "https://b.test";
        let Some(store) = store().await else {
            return;
        };
        let creator = format!(
            "pubkytest{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        store.insert_new(new_row(&creator, "ORIGIN")).await.unwrap();
        assert!(mint_for_origin(&store, &creator, "cs_a", 1, Some(ORIGIN_A)).await);
        for attempt in [1, 2] {
            assert!(
                !mint_for_origin(&store, &creator, "cs_none", attempt, None).await,
                "a write naming no origin applied at attempt {attempt}"
            );
            assert!(
                !mint_for_origin(&store, &creator, "cs_b", attempt, Some(ORIGIN_B)).await,
                "a write naming another origin applied at attempt {attempt}"
            );
        }
        let bound = store.get(&creator, "ORIGIN").await.unwrap().unwrap();
        assert_eq!(bound.session_id.as_deref(), Some("cs_a"));
        assert_eq!(bound.session_attempt, 1);
        assert_eq!(bound.return_origin.as_deref(), Some(ORIGIN_A));

        assert!(mint_for_origin(&store, &creator, "cs_a2", 2, Some(ORIGIN_A)).await);
        let rebound = store.get(&creator, "ORIGIN").await.unwrap().unwrap();
        assert_eq!(rebound.session_id.as_deref(), Some("cs_a2"));
        assert_eq!(rebound.session_attempt, 2);
        assert_eq!(rebound.return_origin.as_deref(), Some(ORIGIN_A));
    }

    #[tokio::test]
    async fn set_session_never_moves_the_attempt_backwards() {
        let Some(store) = store().await else {
            return;
        };
        let creator = format!(
            "pubkytest{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        store.insert_new(new_row(&creator, "BACK")).await.unwrap();
        assert!(mint(&store, &creator, "BACK", "stripe", "cs_new", 2).await);
        let older = mint(&store, &creator, "BACK", "stripe", "cs_old", 1).await;
        let row = store.get(&creator, "BACK").await.unwrap().unwrap();
        assert!(
            !older,
            "attempt 1 replaced attempt 2: row is {:?} at attempt {}",
            row.session_id, row.session_attempt
        );
        assert_eq!(row.session_id.as_deref(), Some("cs_new"));
        assert_eq!(row.session_attempt, 2);
        assert!(
            mint(&store, &creator, "BACK", "stripe", "cs_new", 2).await,
            "re-persisting the same attempt stays allowed"
        );
    }

    #[tokio::test]
    async fn an_equal_attempt_never_replaces_a_different_session() {
        let Some(store) = store().await else {
            return;
        };
        let creator = format!(
            "pubkytest{}",
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        for bundle in ["EQUAL", "SKIPPED", "HELD"] {
            store.insert_new(new_row(&creator, bundle)).await.unwrap();
        }
        assert!(mint(&store, &creator, "EQUAL", "stripe", "cs_first", 2).await);
        assert!(
            !mint(&store, &creator, "EQUAL", "stripe", "cs_second", 2).await,
            "a second session at the same attempt applied"
        );
        let origin_write = store
            .set_session(
                &creator,
                "EQUAL",
                "stripe",
                "cs_origin",
                "https://checkout.test/session",
                1000,
                2,
                Some("https://a.test"),
            )
            .await
            .unwrap();
        assert!(
            !origin_write,
            "an origin-bound session at the same attempt applied"
        );
        let held = store.get(&creator, "EQUAL").await.unwrap().unwrap();
        assert_eq!(held.session_id.as_deref(), Some("cs_first"));
        assert_eq!(held.return_origin, None);
        assert!(mint(&store, &creator, "EQUAL", "stripe", "cs_first", 2).await);

        store
            .skip_session_attempt(&creator, "SKIPPED", 2)
            .await
            .unwrap();
        assert!(mint(&store, &creator, "SKIPPED", "stripe", "cs_after_skip", 2).await);

        assert!(mint(&store, &creator, "HELD", "stripe", "cs_held", 1).await);
        store
            .skip_session_attempt(&creator, "HELD", 2)
            .await
            .unwrap();
        assert!(
            !mint(&store, &creator, "HELD", "stripe", "cs_skipped", 2).await,
            "a session at a skipped attempt replaced the held session"
        );
        assert_eq!(
            store
                .get(&creator, "HELD")
                .await
                .unwrap()
                .unwrap()
                .session_id
                .as_deref(),
            Some("cs_held")
        );
        assert!(mint(&store, &creator, "HELD", "stripe", "cs_next", 3).await);
    }
}
