//! Correlation persistence. One row per (creator, bundle_id) — the invoice
//! identity the Lock Server polls with. State transitions are monotonic:
//! created -> paid -> confirmed, with reversed as a terminal branch reachable
//! from all three. A reversal of a confirmed row is recorded as
//! `reversed_after_confirm`: Locks has no un-complete transition, so an
//! entitlement the Lock Server already completed stays granted and the
//! reversal becomes a marketplace dispute matter (design §5), but this
//! gateway stops reporting `confirmed` for it from then on.

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
#[error("correlation store error: {0}")]
pub struct StoreError(pub String);

#[async_trait]
pub trait CorrelationStore: Send + Sync {
    async fn insert_new(&self, new: NewCorrelation) -> Result<InsertOutcome, StoreError>;
    async fn get(&self, creator: &str, bundle_id: &str) -> Result<Option<Correlation>, StoreError>;
    /// Persists a freshly minted session. Conditional on the origin binding:
    /// the update applies only while the stored `return_origin` is still
    /// unbound (NULL — first binder wins) or already equals `return_origin`
    /// (the origin the session's redirect URLs were derived from). A mint
    /// against the static fallback URLs (`return_origin = None`) therefore
    /// can never overwrite an origin-bound row, and vice versa — this is
    /// what keeps "derived from the bound origin, never rebound" atomic
    /// across concurrent checkouts and across processes. Returns `false`
    /// when the guard rejected the write (a concurrent mint bound a
    /// different origin first); the caller must then not serve the session
    /// it just minted.
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
    /// reversal check.
    async fn mark_confirmed(
        &self,
        creator: &str,
        bundle_id: &str,
        confirmed_at: OffsetDateTime,
    ) -> Result<(), StoreError>;
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

impl PostgresStore {
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|error| StoreError(error.to_string()))?;
        sqlx::raw_sql(SCHEMA)
            .execute(&pool)
            .await
            .map_err(|error| StoreError(error.to_string()))?;
        Ok(Self { pool })
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
            .ok_or_else(|| StoreError(format!("unknown state '{state}'")))?,
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
    StoreError(error.to_string())
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
            .ok_or_else(|| StoreError("conflicting row vanished".to_owned()))?;
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
        // The origin guard: apply only while the row is unbound or bound to
        // exactly the origin this session was minted for. With $8 NULL the
        // second disjunct is never true, so a fallback-URL session can only
        // persist onto a still-NULL row — never over an origin binding.
        let updated = sqlx::query(
            "UPDATE correlations SET processor = $3, session_id = $4, checkout_url = $5, \
             checkout_expires_at = $6, session_attempt = $7, \
             return_origin = COALESCE($8, return_origin), updated_at = now() \
             WHERE creator = $1 AND bundle_id = $2 \
             AND (return_origin IS NULL OR return_origin = $8)",
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
    ) -> Result<(), StoreError> {
        sqlx::query(
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
        Ok(())
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
    }

    impl MemoryStore {
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
            let mut rows = self.rows.lock().unwrap();
            let Some(row) = rows.get_mut(&(creator.to_owned(), bundle_id.to_owned())) else {
                return Ok(false);
            };
            // Same origin guard as the SQL predicate: apply only while the
            // row is unbound or bound to exactly the minted origin. (When
            // `return_origin` is None this reduces to `is_none()`.)
            if row.return_origin.is_some() && row.return_origin.as_deref() != return_origin {
                return Ok(false);
            }
            row.processor = Some(processor.to_owned());
            row.session_id = Some(session_id.to_owned());
            row.checkout_url = Some(checkout_url.to_owned());
            row.checkout_expires_at = Some(checkout_expires_at);
            row.session_attempt = session_attempt;
            if let Some(origin) = return_origin {
                row.return_origin = Some(origin.to_owned());
            }
            Ok(true)
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
        ) -> Result<(), StoreError> {
            let key = (creator.to_owned(), bundle_id.to_owned());
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.get_mut(&key) {
                if row.state == CorrelationState::Paid {
                    row.state = CorrelationState::Confirmed;
                    let mut meta = self.meta.lock().unwrap();
                    let meta = meta.entry(key).or_default();
                    meta.confirmed_at = Some(confirmed_at);
                    meta.reversal_checked_at = Some(confirmed_at);
                }
            }
            Ok(())
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
            due.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
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
}

/// The Postgres store against a real database. Runs when
/// `FIAT_TEST_DATABASE_URL` is set (CI provides a Postgres service); rows
/// use a per-run creator so runs never interfere.
#[cfg(test)]
mod postgres_tests {
    use std::time::Duration;

    use super::*;

    /// Concurrent `CREATE ... IF NOT EXISTS` on a fresh database can race in
    /// Postgres, so the tests bootstrap the schema one at a time.
    static BOOTSTRAP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn store() -> Option<PostgresStore> {
        let Ok(url) = std::env::var("FIAT_TEST_DATABASE_URL") else {
            eprintln!("FIAT_TEST_DATABASE_URL unset: skipping the Postgres store test");
            return None;
        };
        let _bootstrap = BOOTSTRAP.lock().await;
        // Connecting twice proves the schema bootstrap is idempotent.
        PostgresStore::connect(&url).await.expect("first connect");
        Some(PostgresStore::connect(&url).await.expect("second connect"))
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
        store.mark_confirmed(&creator, "LATE", now).await.unwrap();
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
}
