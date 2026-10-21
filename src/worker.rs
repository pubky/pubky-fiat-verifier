//! Slow-poll fallback: a lost webhook delays a payment but never loses it
//! (design §3.3.3). Every open fiat correlation with a session gets pulled on
//! an interval; the same loop performs delay-elapsed promotion, in which case
//! the pull that just happened IS the fresh promotion-time re-pull.
//!
//! The same loop is the reversal watch: confirmed correlations are re-pulled
//! every `recheck_interval` for as long as the processors accept a refund or
//! a dispute (`window`), so a reversal whose webhook was lost, rejected or
//! never configured is still recorded.

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::store::{CorrelationState, CorrelationStore};
use crate::verification::{pull_and_apply, Processors, PullOutcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReversalWatch {
    /// How long after confirmation a reversal is still looked for.
    pub window: Duration,
    /// Minimum time between two reversal checks of the same correlation.
    pub recheck_interval: Duration,
}

pub async fn run(
    store: Arc<dyn CorrelationStore>,
    processors: Arc<Processors>,
    poll_interval: Duration,
    settlement_delay: Duration,
    reversal_watch: ReversalWatch,
) {
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        tick(
            &store,
            &processors,
            settlement_delay,
            reversal_watch,
            OffsetDateTime::now_utc(),
        )
        .await;
    }
}

/// One poll pass: open correlations first, then the reversal watch.
pub async fn tick(
    store: &Arc<dyn CorrelationStore>,
    processors: &Processors,
    settlement_delay: Duration,
    reversal_watch: ReversalWatch,
    now: OffsetDateTime,
) {
    poll_open(store, processors, settlement_delay, now).await;
    watch_confirmed(store, processors, reversal_watch, now).await;
}

async fn poll_open(
    store: &Arc<dyn CorrelationStore>,
    processors: &Processors,
    settlement_delay: Duration,
    now: OffsetDateTime,
) {
    let open = match store.open_fiat_correlations().await {
        Ok(open) => open,
        Err(error) => {
            tracing::error!(%error, "poll worker could not list open correlations");
            return;
        }
    };
    for correlation in open {
        let outcome = pull_and_apply(store, processors, &correlation, now).await;
        if !matches!(
            outcome,
            PullOutcome::Paid {
                amount_matched: true
            }
        ) {
            continue;
        }
        // Re-read: pull_and_apply may have just set paid_at.
        let refreshed = match store
            .get(&correlation.creator, &correlation.bundle_id)
            .await
        {
            Ok(Some(refreshed)) => refreshed,
            _ => continue,
        };
        if refreshed.state == CorrelationState::Paid {
            if let Some(paid_at) = refreshed.paid_at {
                if now >= paid_at + settlement_delay {
                    if let Err(error) = store
                        .mark_confirmed(&refreshed.creator, &refreshed.bundle_id, now)
                        .await
                    {
                        tracing::error!(%error, "poll worker failed to persist confirmation");
                    } else {
                        tracing::info!(
                            creator = %refreshed.creator,
                            bundle_id = %refreshed.bundle_id,
                            "fiat payment confirmed by poll worker (delay elapsed, pull verified)"
                        );
                    }
                }
            }
        }
    }
}

async fn watch_confirmed(
    store: &Arc<dyn CorrelationStore>,
    processors: &Processors,
    reversal_watch: ReversalWatch,
    now: OffsetDateTime,
) {
    let due = match store
        .confirmed_due_for_reversal_check(
            now - reversal_watch.window,
            now - reversal_watch.recheck_interval,
        )
        .await
    {
        Ok(due) => due,
        Err(error) => {
            tracing::error!(%error, "poll worker could not list confirmed correlations");
            return;
        }
    };
    for correlation in due {
        match pull_and_apply(store, processors, &correlation, now).await {
            // Not checked: the next tick retries this row first.
            PullOutcome::Unavailable => {}
            // The row left `confirmed`; nothing left to watch.
            PullOutcome::Reversed => {}
            PullOutcome::Paid { .. } | PullOutcome::Unpaid => {
                if let Err(error) = store
                    .mark_reversal_checked(&correlation.creator, &correlation.bundle_id, now)
                    .await
                {
                    tracing::error!(%error, "poll worker failed to record a reversal check");
                }
            }
        }
    }
}
