//! HTTP surface.
//!
//! Impersonated Paykit wire contract (Lock Server–facing, signed):
//!   POST /invoices              — dispatch by criterion asset
//!   POST /transactions/status   — BTC forwarded, fiat answered locally
//!
//! Gateway-native surface:
//!   POST /checkout-sessions     — buyer fetches the hosted checkout URL
//!                                 (and picks the processor when unbound)
//!   POST /webhooks/stripe       — processor hints (verified, deduped, then
//!   POST /webhooks/paypal         superseded by an API pull)
//!   GET  /health

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::auth::{parse_canonical_strict, verify_signature, SIGNATURE_HEADER};
use crate::error::ApiError;
use crate::lock_fetch::{CriterionSource, LockFetchError};
use crate::paypal::WebhookHeaders;
use crate::proxy::PaykitProxy;
use crate::rate_limit::TokenBucket;
use crate::state::{report, Report};
use crate::store::{
    Correlation, CorrelationState, CorrelationStore, InsertOutcome, NewCorrelation,
};
use crate::stripe::{client_reference, idempotency_key, StripeProcessor};
use crate::verification::{
    apply_reversal, bound_processor, promote_if_still_paid, pull_and_apply, ProcessorKind,
    Processors, PullOutcome,
};
use crate::wire::{
    parse_lock_resource, validate_id, CheckoutSessionRequest, CheckoutSessionResponse,
    InvoiceRequest, StatusRequest,
};

const MAX_BODY_BYTES: usize = 65_536;
const WEBHOOK_TOLERANCE: Duration = Duration::from_secs(300);
/// A checkout session this close to expiry is replaced rather than returned.
const SESSION_EXPIRY_SLACK_SECONDS: i64 = 60;
/// PayPal's create-order response carries no expiry; orders are approvable
/// for roughly three hours, so the recorded expiry mirrors that default.
const PAYPAL_ORDER_TTL_SECONDS: i64 = 3 * 3600;

pub struct AppState {
    pub trusted_key: VerifyingKey,
    pub store: Arc<dyn CorrelationStore>,
    pub processors: Arc<Processors>,
    /// Effective default for unbound checkout requests naming no processor:
    /// the sole configured processor, or `FIAT_DEFAULT_PROCESSOR` when both
    /// are configured.
    pub default_processor: ProcessorKind,
    pub criterion_source: Arc<dyn CriterionSource>,
    pub proxy: Arc<PaykitProxy>,
    pub settlement_delay: Duration,
    pub synthesized_confirmations: u32,
    pub allowed_assets: Vec<String>,
    /// Static fallback redirect targets (legacy single-shop mode), used when
    /// no return origin is bound to the correlation.
    pub checkout_success_url: String,
    pub checkout_cancel_url: String,
    /// Exact `https://` origins a checkout request may name as
    /// `return_origin` (canonical `url::Url` serializations).
    pub buyer_return_origins: Vec<String>,
    pub checkout_limiter: TokenBucket,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/invoices", post(create_invoice))
        .route("/transactions/status", post(transaction_status))
        .route("/checkout-sessions", post(checkout_session))
        .route("/webhooks/stripe", post(stripe_webhook))
        .route("/webhooks/paypal", post(paypal_webhook))
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Strips the optional `pubky` app-key prefix, leaving the bare z-base-32 key.
fn normalized_z32(key: &str) -> &str {
    key.strip_prefix("pubky").unwrap_or(key)
}

fn signature_string(headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get(SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or(ApiError::InvalidSignature)
}

async fn create_invoice(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    if let Err(error) = verify_signature(&state.trusted_key, &headers, &raw_body) {
        return error.into_response();
    }
    let request: InvoiceRequest = match parse_canonical_strict(&raw_body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if validate_id(&request.bundle_id).is_err() || request.reader.is_empty() {
        return ApiError::InvalidRequest.into_response();
    }
    let (creator, _path) = match parse_lock_resource(&request.lock_resource) {
        Ok(parts) => parts,
        Err(error) => return error.into_response(),
    };

    let criterion = match state
        .criterion_source
        .criterion(&request.lock_resource)
        .await
    {
        Ok(criterion) => criterion,
        Err(LockFetchError::NotFound) => return ApiError::LockNotFound.into_response(),
        Err(LockFetchError::Unavailable) => return ApiError::Unavailable.into_response(),
        Err(LockFetchError::Invalid) => return ApiError::InvalidRequest.into_response(),
    };

    if criterion.asset == "BTC" {
        tracing::info!(
            bundle_id = %request.bundle_id,
            lock_resource = %request.lock_resource,
            "dispatch: BTC criterion, proxying invoice to paykit-server"
        );
        let signature = match signature_string(&headers) {
            Ok(signature) => signature,
            Err(error) => return error.into_response(),
        };
        return state.proxy.forward("invoices", &signature, raw_body).await;
    }

    // Fiat path.
    if !state
        .allowed_assets
        .iter()
        .any(|asset| asset == &criterion.asset)
    {
        tracing::warn!(
            asset = %criterion.asset,
            bundle_id = %request.bundle_id,
            "criterion asset is not enabled on this gateway"
        );
        return ApiError::InvalidRequest.into_response();
    }
    // v1 policy: the payment recipient is the lock creator. Locks enforces
    // this at lock creation; re-checked here as processor-drift defense.
    // Stored locks may carry the recipient as bare z32 while the addressed
    // resource uses the pubky-prefixed app key, so compare normalized forms.
    if normalized_z32(&criterion.recipient_pubky) != normalized_z32(creator) {
        return ApiError::InvalidRequest.into_response();
    }
    let amount_minor: i64 = match criterion.amount.parse::<i64>() {
        Ok(amount) if amount > 0 => amount,
        _ => return ApiError::InvalidRequest.into_response(),
    };
    if !state.processors.any_configured() {
        tracing::error!(
            bundle_id = %request.bundle_id,
            "fiat invoice refused: no processor configured (fail-closed)"
        );
        return ApiError::Unavailable.into_response();
    }
    // Eager invoice-time minting only when the processor choice is forced
    // (exactly one configured). With both configured the mint waits for the
    // buyer's /checkout-sessions call, which carries the processor choice.
    let eager = state.processors.sole_configured();

    let outcome = match state
        .store
        .insert_new(NewCorrelation {
            creator: creator.to_owned(),
            bundle_id: request.bundle_id.clone(),
            lock_resource: request.lock_resource.clone(),
            reader: request.reader.clone(),
            asset: criterion.asset.clone(),
            amount_minor,
        })
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::error!(%error, "correlation insert failed");
            return ApiError::Unavailable.into_response();
        }
    };

    match outcome {
        InsertOutcome::Conflict => {
            tracing::warn!(
                creator,
                bundle_id = %request.bundle_id,
                "invoice conflict: identity already bound to different terms"
            );
            ApiError::InvoiceConflict.into_response()
        }
        InsertOutcome::ExactReplay => {
            let existing = match state.store.get(creator, &request.bundle_id).await {
                Ok(Some(existing)) => existing,
                _ => return ApiError::Unavailable.into_response(),
            };
            let Some(kind) = eager else {
                return StatusCode::NO_CONTENT.into_response();
            };
            if existing.session_id.is_some() {
                return StatusCode::NO_CONTENT.into_response();
            }
            // Earlier attempt persisted the row but died before the session
            // existed: idempotently create it now.
            match mint_session(
                &state,
                kind,
                creator,
                &request.bundle_id,
                &criterion.asset,
                amount_minor,
                existing.session_attempt + 1,
                None,
            )
            .await
            {
                Ok(_) => StatusCode::NO_CONTENT.into_response(),
                Err(response) => response,
            }
        }
        InsertOutcome::Inserted => {
            let Some(kind) = eager else {
                tracing::info!(
                    creator,
                    bundle_id = %request.bundle_id,
                    asset = %criterion.asset,
                    amount_minor,
                    "fiat invoice created; session mint deferred to checkout (both processors configured)"
                );
                return StatusCode::NO_CONTENT.into_response();
            };
            match mint_session(
                &state,
                kind,
                creator,
                &request.bundle_id,
                &criterion.asset,
                amount_minor,
                1,
                None,
            )
            .await
            {
                Ok(_) => {
                    tracing::info!(
                        creator,
                        bundle_id = %request.bundle_id,
                        asset = %criterion.asset,
                        amount_minor,
                        processor = kind.as_str(),
                        "fiat invoice created with checkout session"
                    );
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(response) => response,
            }
        }
    }
}

/// The redirect targets a session is minted with: derived server-side from
/// the bound buyer return origin, or the static fallback URLs (legacy
/// single-shop mode) when no origin is bound.
fn return_urls(state: &AppState, return_origin: Option<&str>) -> (String, String) {
    match return_origin {
        Some(origin) => (
            format!("{origin}/marketplace?checkout=return"),
            format!("{origin}/marketplace?checkout=cancel"),
        ),
        None => (
            state.checkout_success_url.clone(),
            state.checkout_cancel_url.clone(),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
async fn mint_session(
    state: &Arc<AppState>,
    kind: ProcessorKind,
    creator: &str,
    bundle_id: &str,
    asset: &str,
    amount_minor: i64,
    attempt: i32,
    return_origin: Option<&str>,
) -> Result<CheckoutSessionResponse, Response> {
    match kind {
        ProcessorKind::Stripe => {
            let Some(stripe) = state.processors.stripe.as_ref() else {
                return Err(ApiError::Unavailable.into_response());
            };
            mint_stripe_session(
                state,
                stripe,
                creator,
                bundle_id,
                asset,
                amount_minor,
                attempt,
                return_origin,
            )
            .await
        }
        ProcessorKind::Paypal => {
            let Some(paypal) = state.processors.paypal.as_ref() else {
                return Err(ApiError::Unavailable.into_response());
            };
            let (success_url, cancel_url) = return_urls(state, return_origin);
            let order = paypal
                .create_order(
                    &client_reference(creator, bundle_id),
                    &idempotency_key(creator, bundle_id, attempt),
                    amount_minor,
                    asset,
                    "Marketplace listing (Locks entitlement)",
                    &success_url,
                    &cancel_url,
                )
                .await
                .map_err(|error| {
                    tracing::error!(%error, creator, bundle_id, "paypal order creation failed");
                    ApiError::Unavailable.into_response()
                })?;
            let approval_url = order.approval_url().map(str::to_owned).ok_or_else(|| {
                tracing::error!(order_id = %order.id, "created paypal order has no approval link");
                ApiError::Unavailable.into_response()
            })?;
            let expires_at = OffsetDateTime::now_utc().unix_timestamp() + PAYPAL_ORDER_TTL_SECONDS;
            let persisted = state
                .store
                .set_session(
                    creator,
                    bundle_id,
                    ProcessorKind::Paypal.as_str(),
                    &order.id,
                    &approval_url,
                    expires_at,
                    attempt,
                    return_origin,
                )
                .await
                .map_err(|error| {
                    tracing::error!(%error, "failed to persist paypal order");
                    ApiError::Unavailable.into_response()
                })?;
            if !persisted {
                return persisted_session_after_lost_race(state, creator, bundle_id).await;
            }
            Ok(CheckoutSessionResponse {
                checkout_url: approval_url,
                processor: ProcessorKind::Paypal.as_str(),
                expires_at,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn mint_stripe_session(
    state: &Arc<AppState>,
    stripe: &Arc<StripeProcessor>,
    creator: &str,
    bundle_id: &str,
    asset: &str,
    amount_minor: i64,
    attempt: i32,
    return_origin: Option<&str>,
) -> Result<CheckoutSessionResponse, Response> {
    let (success_url, cancel_url) = return_urls(state, return_origin);
    let session = stripe
        .create_checkout_session(
            &client_reference(creator, bundle_id),
            &idempotency_key(creator, bundle_id, attempt),
            amount_minor,
            &asset.to_ascii_lowercase(),
            "Marketplace listing (Locks entitlement)",
            &success_url,
            &cancel_url,
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, creator, bundle_id, "stripe checkout session creation failed");
            ApiError::Unavailable.into_response()
        })?;
    let checkout_url = session.url.clone().ok_or_else(|| {
        tracing::error!(session_id = %session.id, "created checkout session has no url");
        ApiError::Unavailable.into_response()
    })?;
    let expires_at = session.expires_at.unwrap_or(0);
    let persisted = state
        .store
        .set_session(
            creator,
            bundle_id,
            ProcessorKind::Stripe.as_str(),
            &session.id,
            &checkout_url,
            expires_at,
            attempt,
            return_origin,
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to persist checkout session");
            ApiError::Unavailable.into_response()
        })?;
    if !persisted {
        return persisted_session_after_lost_race(state, creator, bundle_id).await;
    }
    Ok(CheckoutSessionResponse {
        checkout_url,
        processor: ProcessorKind::Stripe.as_str(),
        expires_at,
    })
}

/// The conditional persist of a just-minted session lost the race: between
/// the pre-mint read and the UPDATE, a concurrent mint bound the correlation
/// to a different return origin. The session we minted derives its redirect
/// URLs from an origin the correlation is NOT bound to, so it is never
/// served — re-read the winner instead. Choice (a) over (b): when the
/// winning session is still live it is served, because the store guard
/// makes it impossible for that session to carry URLs derived from anything
/// but the now-bound origin — there is nothing to conflict about. Only a
/// missing, expired, or no-longer-created row falls through to (b), a 409
/// `invoice_conflict`.
async fn persisted_session_after_lost_race(
    state: &Arc<AppState>,
    creator: &str,
    bundle_id: &str,
) -> Result<CheckoutSessionResponse, Response> {
    let correlation = match state.store.get(creator, bundle_id).await {
        Ok(Some(correlation)) => correlation,
        Ok(None) => return Err(ApiError::InvoiceConflict.into_response()),
        Err(error) => {
            tracing::error!(%error, "correlation re-read failed");
            return Err(ApiError::Unavailable.into_response());
        }
    };
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    if correlation.state == CorrelationState::Created {
        if let (Some(bound), Some(url), Some(expires_at)) = (
            bound_processor(&correlation),
            correlation.checkout_url.clone(),
            correlation.checkout_expires_at,
        ) {
            if expires_at > now_unix + SESSION_EXPIRY_SLACK_SECONDS {
                return Ok(CheckoutSessionResponse {
                    checkout_url: url,
                    processor: bound.as_str(),
                    expires_at,
                });
            }
        }
    }
    Err(ApiError::InvoiceConflict.into_response())
}

async fn transaction_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    if let Err(error) = verify_signature(&state.trusted_key, &headers, &raw_body) {
        return error.into_response();
    }
    let request: StatusRequest = match parse_canonical_strict(&raw_body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if validate_id(&request.bundle_id).is_err() || request.creator.is_empty() {
        return ApiError::InvalidRequest.into_response();
    }

    let correlation = match state.store.get(&request.creator, &request.bundle_id).await {
        Ok(correlation) => correlation,
        Err(error) => {
            tracing::error!(%error, "correlation lookup failed");
            return ApiError::Unavailable.into_response();
        }
    };

    let correlation = match correlation {
        // Unknown here => not a fiat correlation this gateway minted. All
        // BTC invoices (including every pre-cutover one) live in the real
        // Paykit Server, so forward and mirror its answer (404 included —
        // upstream treats it as retryable VerificationPending).
        None => {
            let signature = match signature_string(&headers) {
                Ok(signature) => signature,
                Err(error) => return error.into_response(),
            };
            return state
                .proxy
                .forward("transactions/status", &signature, raw_body)
                .await;
        }
        Some(correlation) if correlation.asset == "BTC" => {
            let signature = match signature_string(&headers) {
                Ok(signature) => signature,
                Err(error) => return error.into_response(),
            };
            return state
                .proxy
                .forward("transactions/status", &signature, raw_body)
                .await;
        }
        Some(correlation) => correlation,
    };

    let now = OffsetDateTime::now_utc();

    // Opportunistic pull while awaiting payment: the Lock Server polls this
    // endpoint ~every 30s, which doubles as the payment observation loop, so
    // fiat detection does not depend on webhook delivery at all.
    let correlation =
        if correlation.state == CorrelationState::Created && correlation.session_id.is_some() {
            pull_and_apply(&state.store, &state.processors, &correlation, now).await;
            match state.store.get(&request.creator, &request.bundle_id).await {
                Ok(Some(refreshed)) => refreshed,
                _ => correlation,
            }
        } else {
            correlation
        };

    let confirmed = crate::wire::TransactionStatus {
        status: crate::wire::StatusKind::Confirmed,
        confirmations: state.synthesized_confirmations,
        amount_matched: true,
    };
    let undetected = crate::wire::TransactionStatus {
        status: crate::wire::StatusKind::Undetected,
        confirmations: 0,
        amount_matched: false,
    };
    let status = if correlation.state == CorrelationState::Confirmed {
        // `confirmed` is what releases the good, so it is only ever served
        // on a fresh pull that still shows the payment unrefunded and
        // undisputed. An unreadable processor holds at `detected`.
        match pull_and_apply(&state.store, &state.processors, &correlation, now).await {
            PullOutcome::Paid {
                amount_matched: true,
            } => confirmed,
            PullOutcome::Reversed => undetected,
            PullOutcome::Paid { .. } | PullOutcome::Unpaid | PullOutcome::Unavailable => {
                crate::wire::TransactionStatus {
                    status: crate::wire::StatusKind::Detected,
                    confirmations: 0,
                    amount_matched: correlation.amount_matched,
                }
            }
        }
    } else {
        match report(
            &correlation,
            now,
            state.settlement_delay,
            state.synthesized_confirmations,
        ) {
            Report::Immediate(status) => status,
            Report::PromotionDue { fallback } => {
                if promote_if_still_paid(&state.store, &state.processors, &correlation, now).await {
                    confirmed
                } else {
                    match state.store.get(&request.creator, &request.bundle_id).await {
                        Ok(Some(refreshed)) if refreshed.state == CorrelationState::Reversed => {
                            undetected
                        }
                        _ => fallback,
                    }
                }
            }
        }
    };
    Json(status).into_response()
}

async fn checkout_session(
    State(state): State<Arc<AppState>>,
    body: Result<Json<CheckoutSessionRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !state.checkout_limiter.try_take() {
        return ApiError::RateLimited.into_response();
    }
    let Ok(Json(request)) = body else {
        return ApiError::InvalidRequest.into_response();
    };
    if validate_id(&request.bundle_id).is_err() || request.creator.is_empty() {
        return ApiError::InvalidRequest.into_response();
    }
    let requested = match request.processor.as_deref() {
        None => None,
        Some(value) => match ProcessorKind::parse(value) {
            Some(kind) => Some(kind),
            None => return ApiError::InvalidRequest.into_response(),
        },
    };
    // A return origin is accepted only as an exact allowlisted `https://`
    // origin (string equality after url parse-and-reserialize) — never a
    // full URL, so this cannot become an open redirect.
    let requested_origin = match request.return_origin.as_deref() {
        None => None,
        Some(value) => match crate::config::parse_return_origin(value) {
            Some(origin)
                if state
                    .buyer_return_origins
                    .iter()
                    .any(|allowed| allowed == &origin) =>
            {
                Some(origin)
            }
            _ => return ApiError::InvalidReturnOrigin.into_response(),
        },
    };
    if !state.processors.any_configured() {
        return ApiError::Unavailable.into_response();
    }
    let correlation = match state.store.get(&request.creator, &request.bundle_id).await {
        Ok(Some(correlation)) if correlation.asset != "BTC" => correlation,
        Ok(_) => return ApiError::NotFound.into_response(),
        Err(error) => {
            tracing::error!(%error, "correlation lookup failed");
            return ApiError::Unavailable.into_response();
        }
    };
    if correlation.state != CorrelationState::Created {
        // Paid/confirmed: nothing left to check out. Reversed: this bundle's
        // payment was reversed; the task will expire — a fresh purchase needs
        // a fresh proof bundle.
        return ApiError::InvoiceConflict.into_response();
    }
    // The return-origin binding is permanent, exactly like the processor
    // binding: a different origin than the bound one conflicts, and a
    // re-fetch without an origin keeps the bound one (never reverts to the
    // fallback, never follows a later request).
    if let (Some(bound), Some(requested)) = (&correlation.return_origin, &requested_origin) {
        if bound != requested {
            return ApiError::InvoiceConflict.into_response();
        }
    }
    let origin = correlation.return_origin.clone().or(requested_origin);
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    let kind = match bound_processor(&correlation) {
        Some(bound) => {
            // The binding is permanent: switching processors could leave a
            // still-payable session on the abandoned processor — a payment
            // this gateway would no longer observe (fail-closed).
            if requested.is_some_and(|requested| requested != bound) {
                return ApiError::InvoiceConflict.into_response();
            }
            // The live session is reused only when it was minted with the
            // effective origin; a newly named origin re-mints so the
            // processor-side redirect URLs really derive from it.
            if correlation.return_origin == origin {
                if let (Some(url), Some(expires_at)) = (
                    correlation.checkout_url.clone(),
                    correlation.checkout_expires_at,
                ) {
                    if expires_at > now_unix + SESSION_EXPIRY_SLACK_SECONDS {
                        return Json(CheckoutSessionResponse {
                            checkout_url: url,
                            processor: bound.as_str(),
                            expires_at,
                        })
                        .into_response();
                    }
                }
            }
            bound
        }
        None => requested.unwrap_or(state.default_processor),
    };
    if !state.processors.is_configured(kind) {
        return ApiError::Unavailable.into_response();
    }
    // Session expired (or was never minted / never fully persisted), or a
    // return origin is being bound for the first time: mint.
    match mint_session(
        &state,
        kind,
        &request.creator,
        &request.bundle_id,
        &correlation.asset,
        correlation.amount_minor,
        correlation.session_attempt + 1,
        origin.as_deref(),
    )
    .await
    {
        Ok(response) => Json(response).into_response(),
        Err(response) => response,
    }
}

async fn stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let Some(stripe) = state.processors.stripe.as_ref() else {
        return ApiError::Unavailable.into_response();
    };
    let Some(webhook_secret) = stripe.webhook_secret.as_deref() else {
        tracing::warn!("webhook received but STRIPE_WEBHOOK_SECRET is not configured");
        return ApiError::Unavailable.into_response();
    };
    let Some(signature) = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
    else {
        return ApiError::InvalidSignature.into_response();
    };
    let now_unix = OffsetDateTime::now_utc().unix_timestamp();
    if let Err(error) = StripeProcessor::verify_webhook(
        webhook_secret,
        signature,
        &raw_body,
        now_unix,
        WEBHOOK_TOLERANCE,
    ) {
        tracing::warn!(%error, "stripe webhook signature rejected");
        return ApiError::InvalidSignature.into_response();
    }

    let event: Value = match serde_json::from_slice(&raw_body) {
        Ok(event) => event,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    let (Some(event_id), Some(event_type)) = (
        event.get("id").and_then(Value::as_str),
        event.get("type").and_then(Value::as_str),
    ) else {
        return ApiError::InvalidRequest.into_response();
    };
    match state.store.record_webhook_event(event_id, event_type).await {
        Ok(true) => {}
        Ok(false) => return Json(json!({"received": true, "duplicate": true})).into_response(),
        Err(error) => {
            tracing::error!(%error, "webhook dedupe persistence failed");
            return ApiError::Unavailable.into_response();
        }
    }
    let object = event
        .pointer("/data/object")
        .cloned()
        .unwrap_or(Value::Null);
    tracing::info!(event_id, event_type, "stripe webhook accepted (hint only)");

    match handle_stripe_event(&state, stripe, event_id, event_type, &object).await {
        Ok(()) => Json(json!({"received": true})).into_response(),
        Err(Transient) => release_webhook_event(&state, event_id).await,
    }
}

/// A webhook whose processing failed for a reason a redelivery can fix
/// (processor or store unavailable).
struct Transient;

/// Forgets the event id and answers 503, so the processor's retry is
/// processed rather than deduplicated. The reversal watch in the poll
/// worker covers the case where the processor stops retrying.
async fn release_webhook_event(state: &Arc<AppState>, event_id: &str) -> Response {
    if let Err(error) = state.store.forget_webhook_event(event_id).await {
        tracing::error!(%error, event_id, "failed to release webhook event for redelivery");
    }
    ApiError::Unavailable.into_response()
}

async fn handle_stripe_event(
    state: &Arc<AppState>,
    stripe: &Arc<StripeProcessor>,
    event_id: &str,
    event_type: &str,
    object: &Value,
) -> Result<(), Transient> {
    let now = OffsetDateTime::now_utc();
    match event_type {
        "checkout.session.completed" | "checkout.session.async_payment_succeeded" => {
            let Some(reference) = object.get("client_reference_id").and_then(Value::as_str) else {
                tracing::warn!(event_id, "completed session carries no client_reference_id");
                return Ok(());
            };
            let Some((creator, bundle_id)) = reference.split_once('_') else {
                tracing::warn!(event_id, reference, "unparseable client_reference_id");
                return Ok(());
            };
            match state.store.get(creator, bundle_id).await {
                Ok(Some(correlation)) => {
                    // The webhook body is a hint. The pull is the fact.
                    let outcome =
                        pull_and_apply(&state.store, &state.processors, &correlation, now).await;
                    if outcome == PullOutcome::Unavailable {
                        return Err(Transient);
                    }
                }
                Ok(None) => {
                    tracing::warn!(event_id, reference, "webhook for unknown correlation");
                }
                Err(error) => {
                    tracing::error!(%error, "correlation lookup failed");
                    return Err(Transient);
                }
            }
        }
        "charge.refunded" | "charge.dispute.created" => {
            // A refund event's object is the charge; a dispute event's object
            // is the dispute, which names its charge.
            let charge_id = if event_type == "charge.refunded" {
                object.get("id")
            } else {
                object.get("charge")
            };
            let Some(charge_id) = charge_id.and_then(Value::as_str) else {
                tracing::warn!(event_id, event_type, "reversal event names no charge");
                return Ok(());
            };
            // Verify the reversal by pulling the charge before acting.
            let charge = match stripe.retrieve_charge(charge_id).await {
                Ok(charge) => charge,
                Err(error) => {
                    tracing::error!(%error, charge_id, "charge pull failed");
                    return Err(Transient);
                }
            };
            if !charge.is_reversed() {
                tracing::warn!(
                    charge_id,
                    "reversal webhook not corroborated by charge pull; ignored"
                );
                return Ok(());
            }
            let Some(payment_intent) = charge.payment_intent.as_deref() else {
                tracing::warn!(charge_id, "reversed charge carries no payment intent");
                return Ok(());
            };
            match state.store.find_by_payment_intent(payment_intent).await {
                Ok(Some(correlation)) => {
                    if let Err(error) = apply_reversal(
                        &state.store,
                        &correlation.creator,
                        &correlation.bundle_id,
                        ProcessorKind::Stripe.as_str(),
                        Some(payment_intent),
                        now,
                    )
                    .await
                    {
                        tracing::error!(%error, "failed to persist reversal");
                        return Err(Transient);
                    }
                }
                Ok(None) => {
                    tracing::warn!(charge_id, "reversal for a charge with no known correlation")
                }
                Err(error) => {
                    tracing::error!(%error, "lookup failed");
                    return Err(Transient);
                }
            }
        }
        other => {
            tracing::debug!(event_type = other, "ignoring unhandled webhook event type");
        }
    }
    Ok(())
}

/// Capture statuses that corroborate a reversal webhook: money returned to
/// the buyer, or a capture that never completed.
fn is_reversal_capture_status(status: Option<&str>) -> bool {
    crate::paypal::is_reversed_capture_status(status)
        || matches!(status, Some("DECLINED" | "FAILED"))
}

/// Extracts the capture id a reversal event refers to: the `up` link when
/// the resource is a refund, or the resource's own id when it is a capture.
fn reversal_capture_id(resource: &Value) -> Option<String> {
    if let Some(links) = resource.get("links").and_then(Value::as_array) {
        for link in links {
            if link.get("rel").and_then(Value::as_str) == Some("up") {
                if let Some(href) = link.get("href").and_then(Value::as_str) {
                    if let Some((_, id)) = href.rsplit_once("/captures/") {
                        if !id.is_empty() {
                            return Some(id.to_owned());
                        }
                    }
                }
            }
        }
    }
    resource
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Marks the correlation behind a verified-reversed PayPal capture, resolving
/// it by the capture's `custom_id` reference with the persisted payment
/// reference (capture id) as fallback.
async fn mark_paypal_capture_reversed(
    state: &Arc<AppState>,
    capture_id: &str,
    custom_id: Option<&str>,
) -> Result<(), Transient> {
    let correlation: Option<Correlation> = match custom_id.and_then(|id| id.split_once('_')) {
        Some((creator, bundle_id)) => match state.store.get(creator, bundle_id).await {
            Ok(correlation) => correlation,
            Err(error) => {
                tracing::error!(%error, "lookup failed");
                return Err(Transient);
            }
        },
        None => match state.store.find_by_payment_intent(capture_id).await {
            Ok(correlation) => correlation,
            Err(error) => {
                tracing::error!(%error, "lookup failed");
                return Err(Transient);
            }
        },
    };
    match correlation {
        Some(correlation) => {
            if let Err(error) = apply_reversal(
                &state.store,
                &correlation.creator,
                &correlation.bundle_id,
                ProcessorKind::Paypal.as_str(),
                Some(capture_id),
                OffsetDateTime::now_utc(),
            )
            .await
            {
                tracing::error!(%error, "failed to persist reversal");
                return Err(Transient);
            }
        }
        None => tracing::warn!(
            capture_id,
            "reversal for a capture with no known correlation"
        ),
    }
    Ok(())
}

async fn paypal_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let Some(paypal) = state.processors.paypal.as_ref() else {
        return ApiError::Unavailable.into_response();
    };
    let Some(webhook_id) = paypal.webhook_id.as_deref() else {
        tracing::warn!("webhook received but PAYPAL_WEBHOOK_ID is not configured");
        return ApiError::Unavailable.into_response();
    };
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    let (
        Some(transmission_id),
        Some(transmission_time),
        Some(transmission_sig),
        Some(cert_url),
        Some(auth_algo),
    ) = (
        header("paypal-transmission-id"),
        header("paypal-transmission-time"),
        header("paypal-transmission-sig"),
        header("paypal-cert-url"),
        header("paypal-auth-algo"),
    )
    else {
        return ApiError::InvalidSignature.into_response();
    };
    match paypal
        .verify_webhook(
            webhook_id,
            &WebhookHeaders {
                transmission_id,
                transmission_time,
                transmission_sig,
                cert_url,
                auth_algo,
            },
            &raw_body,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!("paypal webhook signature rejected by verification API");
            return ApiError::InvalidSignature.into_response();
        }
        Err(error) => {
            // Verification unreachable: fail closed, PayPal will retry.
            tracing::warn!(%error, "paypal webhook verification unavailable");
            return ApiError::Unavailable.into_response();
        }
    }

    let event: Value = match serde_json::from_slice(&raw_body) {
        Ok(event) => event,
        Err(_) => return ApiError::InvalidRequest.into_response(),
    };
    let (Some(event_id), Some(event_type)) = (
        event.get("id").and_then(Value::as_str),
        event.get("event_type").and_then(Value::as_str),
    ) else {
        return ApiError::InvalidRequest.into_response();
    };
    match state.store.record_webhook_event(event_id, event_type).await {
        Ok(true) => {}
        Ok(false) => return Json(json!({"received": true, "duplicate": true})).into_response(),
        Err(error) => {
            tracing::error!(%error, "webhook dedupe persistence failed");
            return ApiError::Unavailable.into_response();
        }
    }
    let resource = event.get("resource").cloned().unwrap_or(Value::Null);
    tracing::info!(event_id, event_type, "paypal webhook accepted (hint only)");

    match handle_paypal_event(&state, paypal, event_id, event_type, &resource).await {
        Ok(()) => Json(json!({"received": true})).into_response(),
        Err(Transient) => release_webhook_event(&state, event_id).await,
    }
}

async fn handle_paypal_event(
    state: &Arc<AppState>,
    paypal: &Arc<crate::paypal::PaypalProcessor>,
    event_id: &str,
    event_type: &str,
    resource: &Value,
) -> Result<(), Transient> {
    let now = OffsetDateTime::now_utc();
    match event_type {
        "CHECKOUT.ORDER.APPROVED"
        | "CHECKOUT.ORDER.COMPLETED"
        | "PAYMENT.CAPTURE.COMPLETED"
        | "PAYMENT.CAPTURE.PENDING" => {
            // Capture events carry the reference as `custom_id`; order events
            // carry it inside the first purchase unit.
            let reference = resource
                .get("custom_id")
                .and_then(Value::as_str)
                .or_else(|| {
                    resource
                        .pointer("/purchase_units/0/custom_id")
                        .and_then(Value::as_str)
                });
            let Some((creator, bundle_id)) = reference.and_then(|value| value.split_once('_'))
            else {
                tracing::warn!(event_id, "paypal event carries no parseable custom_id");
                return Ok(());
            };
            match state.store.get(creator, bundle_id).await {
                Ok(Some(correlation)) => {
                    // The webhook body is a hint. The pull is the fact.
                    let outcome =
                        pull_and_apply(&state.store, &state.processors, &correlation, now).await;
                    if outcome == PullOutcome::Unavailable {
                        return Err(Transient);
                    }
                }
                Ok(None) => {
                    tracing::warn!(event_id, "paypal webhook for unknown correlation");
                }
                Err(error) => {
                    tracing::error!(%error, "correlation lookup failed");
                    return Err(Transient);
                }
            }
        }
        "PAYMENT.CAPTURE.REFUNDED" | "PAYMENT.CAPTURE.REVERSED" | "PAYMENT.CAPTURE.DENIED" => {
            let Some(capture_id) = reversal_capture_id(resource) else {
                tracing::warn!(event_id, event_type, "reversal event names no capture");
                return Ok(());
            };
            // Verify the reversal by pulling the capture before acting.
            match paypal.retrieve_capture(&capture_id).await {
                Ok(capture) if is_reversal_capture_status(capture.status.as_deref()) => {
                    mark_paypal_capture_reversed(state, &capture.id, capture.custom_id.as_deref())
                        .await?;
                }
                Ok(_) => tracing::warn!(
                    capture_id,
                    "reversal webhook not corroborated by capture pull; ignored"
                ),
                Err(error) => {
                    tracing::error!(%error, capture_id, "capture pull failed");
                    return Err(Transient);
                }
            }
        }
        "CUSTOMER.DISPUTE.CREATED" => {
            let Some(dispute_id) = resource.get("dispute_id").and_then(Value::as_str) else {
                tracing::warn!(event_id, "dispute event names no dispute");
                return Ok(());
            };
            // Verify by pulling the dispute; its transactions map to
            // captures, which map to correlations via the persisted
            // payment reference.
            match paypal.retrieve_dispute(dispute_id).await {
                Ok(dispute) => {
                    for transaction in &dispute.disputed_transactions {
                        if let Some(capture_id) = transaction.seller_transaction_id.as_deref() {
                            mark_paypal_capture_reversed(state, capture_id, None).await?;
                        }
                    }
                }
                Err(error) => {
                    tracing::error!(%error, dispute_id, "dispute pull failed");
                    return Err(Transient);
                }
            }
        }
        other => {
            tracing::debug!(event_type = other, "ignoring unhandled webhook event type");
        }
    }
    Ok(())
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    let db_healthy = state.store.healthy().await;
    let body = json!({
        "status": if db_healthy { "ok" } else { "degraded" },
        "database": db_healthy,
        "stripe_enabled": state.processors.stripe.is_some(),
        "stripe_webhook_configured": state
            .processors
            .stripe
            .as_ref()
            .is_some_and(|stripe| stripe.webhook_secret.is_some()),
        "paypal_enabled": state.processors.paypal.is_some(),
        "paypal_webhook_configured": state
            .processors
            .paypal
            .as_ref()
            .is_some_and(|paypal| paypal.webhook_id.is_some()),
        "default_processor": state.default_processor.as_str(),
        "version": env!("CARGO_PKG_VERSION"),
    });
    let status = if db_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}
