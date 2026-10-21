//! Pure fiat state → wire status mapping (design §3.4).
//!
//! | internal state                     | reported                                        |
//! | ---------------------------------- | ----------------------------------------------- |
//! | created                            | undetected, 0, false                            |
//! | paid, inside settlement delay      | detected, 0, amount_matched                     |
//! | paid, delay elapsed                | promotion due: fresh API re-pull decides        |
//! | confirmed                          | confirmed, synthesized confirmations, true      |
//! | reversed (before or after confirm) | undetected, 0, false (never promoted)           |
//!
//! The status handler serves `confirmed` only after a fresh pull still shows
//! the payment unrefunded and undisputed (see `http::transaction_status`);
//! this mapping is the stored-state half of that decision.

use std::time::Duration;

use time::OffsetDateTime;

use crate::store::{Correlation, CorrelationState};
use crate::wire::{StatusKind, TransactionStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    Immediate(TransactionStatus),
    /// Settlement delay has elapsed: the caller must do a fresh API pull and
    /// only report `confirmed` if the pull still says paid.
    PromotionDue {
        fallback: TransactionStatus,
    },
}

pub fn report(
    correlation: &Correlation,
    now: OffsetDateTime,
    settlement_delay: Duration,
    synthesized_confirmations: u32,
) -> Report {
    let undetected = TransactionStatus {
        status: StatusKind::Undetected,
        confirmations: 0,
        amount_matched: false,
    };
    match correlation.state {
        CorrelationState::Created | CorrelationState::Reversed => Report::Immediate(undetected),
        CorrelationState::Paid => {
            let detected = TransactionStatus {
                status: StatusKind::Detected,
                confirmations: 0,
                amount_matched: correlation.amount_matched,
            };
            match correlation.paid_at {
                Some(paid_at) if now >= paid_at + settlement_delay => {
                    if correlation.amount_matched {
                        Report::PromotionDue { fallback: detected }
                    } else {
                        // Paid but wrong amount/currency (processor/config
                        // drift): report honestly, never promote.
                        Report::Immediate(detected)
                    }
                }
                _ => Report::Immediate(detected),
            }
        }
        CorrelationState::Confirmed => Report::Immediate(TransactionStatus {
            status: StatusKind::Confirmed,
            confirmations: synthesized_confirmations,
            amount_matched: true,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn correlation(state: CorrelationState, paid_at: Option<OffsetDateTime>) -> Correlation {
        Correlation {
            creator: "pubkycreator".into(),
            bundle_id: "BUNDLE".into(),
            lock_resource: "pubkycreator/pub/locks.app/x.json".into(),
            reader: "pubkyreader".into(),
            asset: "USD".into(),
            amount_minor: 1999,
            state,
            processor: Some("stripe".into()),
            session_id: Some("cs_test_1".into()),
            checkout_url: Some("https://checkout.stripe.com/c/pay/x".into()),
            checkout_expires_at: None,
            return_origin: None,
            session_attempt: 1,
            payment_intent: None,
            amount_matched: matches!(state, CorrelationState::Paid | CorrelationState::Confirmed),
            paid_at,
        }
    }

    const DELAY: Duration = Duration::from_secs(300);
    const SYNTH: u32 = 1;

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    #[test]
    fn created_reports_undetected() {
        let report = report(
            &correlation(CorrelationState::Created, None),
            at(1_000_000),
            DELAY,
            SYNTH,
        );
        assert_eq!(
            report,
            Report::Immediate(TransactionStatus {
                status: StatusKind::Undetected,
                confirmations: 0,
                amount_matched: false
            })
        );
    }

    #[test]
    fn paid_inside_delay_reports_detected() {
        let outcome = report(
            &correlation(CorrelationState::Paid, Some(at(1_000_000))),
            at(1_000_000 + 299),
            DELAY,
            SYNTH,
        );
        assert_eq!(
            outcome,
            Report::Immediate(TransactionStatus {
                status: StatusKind::Detected,
                confirmations: 0,
                amount_matched: true
            })
        );
    }

    #[test]
    fn paid_after_delay_requires_promotion_pull() {
        let outcome = report(
            &correlation(CorrelationState::Paid, Some(at(1_000_000))),
            at(1_000_000 + 300),
            DELAY,
            SYNTH,
        );
        assert_eq!(
            outcome,
            Report::PromotionDue {
                fallback: TransactionStatus {
                    status: StatusKind::Detected,
                    confirmations: 0,
                    amount_matched: true
                }
            }
        );
    }

    #[test]
    fn paid_with_amount_mismatch_never_promotes() {
        let mut row = correlation(CorrelationState::Paid, Some(at(1_000_000)));
        row.amount_matched = false;
        let outcome = report(&row, at(2_000_000), DELAY, SYNTH);
        assert_eq!(
            outcome,
            Report::Immediate(TransactionStatus {
                status: StatusKind::Detected,
                confirmations: 0,
                amount_matched: false
            })
        );
    }

    #[test]
    fn confirmed_reports_synthesized_confirmations() {
        let outcome = report(
            &correlation(CorrelationState::Confirmed, Some(at(1_000_000))),
            at(2_000_000),
            DELAY,
            3,
        );
        assert_eq!(
            outcome,
            Report::Immediate(TransactionStatus {
                status: StatusKind::Confirmed,
                confirmations: 3,
                amount_matched: true
            })
        );
    }

    #[test]
    fn reversed_reports_undetected() {
        let outcome = report(
            &correlation(CorrelationState::Reversed, Some(at(1_000_000))),
            at(2_000_000),
            DELAY,
            SYNTH,
        );
        assert_eq!(
            outcome,
            Report::Immediate(TransactionStatus {
                status: StatusKind::Undetected,
                confirmations: 0,
                amount_matched: false
            })
        );
    }
}
