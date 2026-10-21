//! Handler-level tests: the full router against an in-memory store, mock
//! Stripe and PayPal APIs, and a mock Paykit Server. Signatures are real
//! ed25519 over canonical JSON — exactly what the Lock Server sends. The
//! mock PayPal verification postback really verifies: it recomputes an HMAC
//! over the transmission fields plus a digest of the exact forwarded event
//! bytes, so a tampered body or a wrong signature yields FAILURE.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use time::OffsetDateTime;
use tokio::net::TcpListener;

use crate::http::{router, AppState};
use crate::lock_fetch::{CriterionSource, LockCriterion, LockFetchError};
use crate::paypal::PaypalProcessor;
use crate::proxy::PaykitProxy;
use crate::rate_limit::TokenBucket;
use crate::store::memory::MemoryStore;
use crate::store::{CorrelationState, CorrelationStore};
use crate::stripe::StripeProcessor;
use crate::verification::{ProcessorKind, Processors};
use crate::worker::ReversalWatch;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const READER: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";
const WEBHOOK_SECRET: &str = "whsec_unit_test";
const PAYPAL_WEBHOOK_ID: &str = "WH-UNIT-TEST";
/// Shared secret of the mock verification scheme (stands in for PayPal's
/// cert-based transmission signature, which only PayPal can produce).
const PAYPAL_MOCK_VERIFY_KEY: &str = "paypal_mock_transmission_key";
/// Allowlisted buyer return origins used by the harness.
const ORIGIN_A: &str = "https://shop.pubky.app";
const ORIGIN_B: &str = "https://staging-shop.vercel.app";

fn locks_key() -> SigningKey {
    SigningKey::from_bytes(&[9_u8; 32])
}

fn sign(key: &SigningKey, body: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(key.sign(body).to_bytes())
}

fn canonical(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).unwrap()
}

struct StaticCriteria(Mutex<std::collections::HashMap<String, LockCriterion>>);

#[async_trait]
impl CriterionSource for StaticCriteria {
    async fn criterion(&self, lock_resource: &str) -> Result<LockCriterion, LockFetchError> {
        self.0
            .lock()
            .unwrap()
            .get(lock_resource)
            .cloned()
            .ok_or(LockFetchError::NotFound)
    }
}

// -- mock Stripe -------------------------------------------------------------

#[derive(Clone, Default)]
struct MockStripe {
    /// (idempotency_key, form_body) per create call.
    creates: Arc<Mutex<Vec<(String, String)>>>,
    /// session id -> session object returned by retrieve.
    sessions: Arc<Mutex<std::collections::HashMap<String, Value>>>,
    charges: Arc<Mutex<std::collections::HashMap<String, Value>>>,
    /// When set, PaymentIntent reads answer 503 (processor outage).
    payment_intents_unavailable: Arc<Mutex<bool>>,
    counter: Arc<Mutex<u32>>,
    /// Incremented when a create call ARRIVES (before any gate), so tests
    /// can wait for an in-flight mint without sleeps.
    create_calls: Arc<std::sync::atomic::AtomicUsize>,
    /// One-shot gate: when armed, the next create call blocks until the
    /// test releases it (deterministic race windows, no sleeps).
    create_gate: Arc<Mutex<Option<tokio::sync::oneshot::Receiver<()>>>>,
}

impl MockStripe {
    /// Marking a session paid also creates its PaymentIntent (`pi_<session>`)
    /// and succeeded charge (`ch_<session>`), as Stripe does.
    fn set_payment_status(&self, session_id: &str, payment_status: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(session_id).unwrap();
        session["payment_status"] = json!(payment_status);
        if payment_status == "paid" {
            session["status"] = json!("complete");
            session["payment_intent"] = json!(format!("pi_{session_id}"));
            let charge_id = format!("ch_{session_id}");
            self.charges.lock().unwrap().insert(
                charge_id.clone(),
                json!({
                    "id": charge_id,
                    "object": "charge",
                    "status": "succeeded",
                    "amount": session["amount_total"].clone(),
                    "amount_refunded": 0,
                    "refunded": false,
                    "disputed": false,
                    "payment_intent": format!("pi_{session_id}"),
                }),
            );
        }
    }

    /// A refund of `amount` minor units against the session's charge. The
    /// session itself keeps `payment_status: paid`, exactly like Stripe.
    fn refund(&self, session_id: &str, amount: i64) {
        let mut charges = self.charges.lock().unwrap();
        let charge = charges.get_mut(&format!("ch_{session_id}")).unwrap();
        let refunded = charge["amount_refunded"].as_i64().unwrap() + amount;
        charge["amount_refunded"] = json!(refunded);
        charge["refunded"] = json!(Some(refunded) == charge["amount"].as_i64());
    }

    /// A dispute (chargeback) against the session's charge; returns the
    /// dispute object Stripe would put in a `charge.dispute.created` event.
    fn dispute(&self, session_id: &str) -> Value {
        let charge_id = format!("ch_{session_id}");
        self.charges.lock().unwrap().get_mut(&charge_id).unwrap()["disputed"] = json!(true);
        json!({
            "id": format!("dp_{session_id}"),
            "object": "dispute",
            "charge": charge_id,
            "payment_intent": format!("pi_{session_id}"),
            "status": "needs_response",
        })
    }

    fn fail_payment_intent_reads(&self, fail: bool) {
        *self.payment_intents_unavailable.lock().unwrap() = fail;
    }
}

async fn mock_create_session(
    State(mock): State<MockStripe>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    mock.create_calls
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let gate = mock.create_gate.lock().unwrap().take();
    if let Some(gate) = gate {
        let _ = gate.await;
    }
    let idempotency = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let form = String::from_utf8(body.to_vec()).unwrap();
    {
        let creates = mock.creates.lock().unwrap();
        // Stripe idempotency: same key returns the same session.
        for (index, (key, _)) in creates.iter().enumerate() {
            if *key == idempotency {
                let id = format!("cs_test_{}", index + 1);
                let session = mock.sessions.lock().unwrap().get(&id).cloned().unwrap();
                return Json(session);
            }
        }
    }
    let mut counter = mock.counter.lock().unwrap();
    *counter += 1;
    let id = format!("cs_test_{}", *counter);
    let amount: i64 = form
        .split('&')
        .find_map(|pair| pair.strip_prefix("line_items%5B0%5D%5Bprice_data%5D%5Bunit_amount%5D="))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let session = json!({
        "id": id,
        "object": "checkout.session",
        "url": format!("https://checkout.stripe.test/c/pay/{id}"),
        "status": "open",
        "payment_status": "unpaid",
        "amount_total": amount,
        "currency": "usd",
        "expires_at": OffsetDateTime::now_utc().unix_timestamp() + 86_400,
        "client_reference_id": format!("{CREATOR}_{BUNDLE}"),
        "livemode": false
    });
    mock.sessions
        .lock()
        .unwrap()
        .insert(id.clone(), session.clone());
    mock.creates.lock().unwrap().push((idempotency, form));
    Json(session)
}

async fn mock_get_session(
    State(mock): State<MockStripe>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match mock.sessions.lock().unwrap().get(&id) {
        Some(session) => Json(session.clone()).into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": {"type": "invalid_request_error"}})),
        )
            .into_response(),
    }
}

/// `GET /v1/payment_intents/:id`. Like Stripe, `latest_charge` is only the
/// charge id unless the request asks for `expand[]=latest_charge`.
async fn mock_get_payment_intent(
    State(mock): State<MockStripe>,
    Path(id): Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> axum::response::Response {
    if *mock.payment_intents_unavailable.lock().unwrap() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": {"type": "api_error"}})),
        )
            .into_response();
    }
    let Some(session_id) = id.strip_prefix("pi_") else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": {"type": "invalid_request_error"}})),
        )
            .into_response();
    };
    let charge_id = format!("ch_{session_id}");
    let Some(charge) = mock.charges.lock().unwrap().get(&charge_id).cloned() else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": {"type": "invalid_request_error"}})),
        )
            .into_response();
    };
    let expanded = query
        .unwrap_or_default()
        .split('&')
        .any(|pair| pair == "expand%5B%5D=latest_charge" || pair == "expand[]=latest_charge");
    Json(json!({
        "id": id,
        "object": "payment_intent",
        "status": "succeeded",
        "latest_charge": if expanded { charge } else { json!(charge_id) },
    }))
    .into_response()
}

async fn mock_get_charge(
    State(mock): State<MockStripe>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match mock.charges.lock().unwrap().get(&id) {
        Some(charge) => Json(charge.clone()).into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": {"type": "invalid_request_error"}})),
        )
            .into_response(),
    }
}

// -- mock PayPal ---------------------------------------------------------------

/// The mock transmission signature: HMAC-SHA256 over
/// `{transmission_id}|{transmission_time}|{webhook_id}|{sha256(event_bytes)}`.
/// The verify endpoint recomputes it from the postback's own fields and the
/// exact forwarded `webhook_event` bytes, so tampering is really detected.
fn paypal_mock_signature(
    transmission_id: &str,
    transmission_time: &str,
    webhook_id: &str,
    event_bytes: &[u8],
) -> String {
    use sha2::Digest;
    let digest = hex::encode(Sha256::digest(event_bytes));
    let mut mac = Hmac::<Sha256>::new_from_slice(PAYPAL_MOCK_VERIFY_KEY.as_bytes()).unwrap();
    mac.update(format!("{transmission_id}|{transmission_time}|{webhook_id}|{digest}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[derive(Clone, Default)]
struct MockPaypal {
    /// (paypal_request_id, body) per create-order call.
    creates: Arc<Mutex<Vec<(String, String)>>>,
    /// order id -> order object returned by retrieve.
    orders: Arc<Mutex<std::collections::HashMap<String, Value>>>,
    /// capture id -> capture object (GET /v2/payments/captures/:id).
    captures: Arc<Mutex<std::collections::HashMap<String, Value>>>,
    /// dispute id -> dispute object (GET /v1/customer/disputes/:id).
    disputes: Arc<Mutex<std::collections::HashMap<String, Value>>>,
    /// When set, the dispute list answers 503 (processor outage).
    disputes_unavailable: Arc<Mutex<bool>>,
    capture_calls: Arc<Mutex<u32>>,
    counter: Arc<Mutex<u32>>,
    /// Incremented when a create-order call ARRIVES (before any gate).
    create_calls: Arc<std::sync::atomic::AtomicUsize>,
    /// One-shot gate: when armed, the next create-order call blocks until
    /// the test releases it (deterministic race windows, no sleeps).
    create_gate: Arc<Mutex<Option<tokio::sync::oneshot::Receiver<()>>>>,
}

impl MockPaypal {
    fn approve(&self, order_id: &str) {
        let mut orders = self.orders.lock().unwrap();
        orders.get_mut(order_id).unwrap()["status"] = json!("APPROVED");
    }

    /// Simulates PayPal's auto-capture (ORDER_COMPLETE_ON_PAYMENT_APPROVAL):
    /// the order jumps straight to COMPLETED with a COMPLETED capture.
    fn complete(&self, order_id: &str) {
        let capture = {
            let mut orders = self.orders.lock().unwrap();
            let order = orders.get_mut(order_id).unwrap();
            order["status"] = json!("COMPLETED");
            let capture = json!({
                "id": format!("ppcap_{order_id}"),
                "status": "COMPLETED",
                "amount": order["purchase_units"][0]["amount"].clone(),
                "custom_id": order["purchase_units"][0]["custom_id"].clone(),
            });
            order["purchase_units"][0]["payments"] = json!({"captures": [capture.clone()]});
            capture
        };
        self.captures
            .lock()
            .unwrap()
            .insert(capture["id"].as_str().unwrap().to_owned(), capture);
    }

    fn set_capture_amount(&self, order_id: &str, value: &str) {
        let capture_id = format!("ppcap_{order_id}");
        {
            let mut orders = self.orders.lock().unwrap();
            let order = orders.get_mut(order_id).unwrap();
            order["purchase_units"][0]["payments"]["captures"][0]["amount"]["value"] = json!(value);
        }
        let mut captures = self.captures.lock().unwrap();
        captures.get_mut(&capture_id).unwrap()["amount"]["value"] = json!(value);
    }

    /// Changes the capture's status everywhere PayPal reports it: the
    /// standalone capture and the copy embedded in the order.
    fn set_capture_status(&self, order_id: &str, status: &str) {
        let capture_id = format!("ppcap_{order_id}");
        self.orders.lock().unwrap().get_mut(order_id).unwrap()["purchase_units"][0]["payments"]
            ["captures"][0]["status"] = json!(status);
        let mut captures = self.captures.lock().unwrap();
        captures.get_mut(&capture_id).unwrap()["status"] = json!(status);
    }

    fn set_dispute(&self, dispute_id: &str, capture_id: &str) {
        self.disputes.lock().unwrap().insert(
            dispute_id.to_owned(),
            json!({
                "dispute_id": dispute_id,
                "status": "OPEN",
                "disputed_transactions": [{"seller_transaction_id": capture_id}],
            }),
        );
    }
}

async fn mock_paypal_token() -> impl IntoResponse {
    Json(json!({
        "access_token": "mock_paypal_token",
        "token_type": "Bearer",
        "expires_in": 3600,
    }))
}

async fn mock_paypal_create_order(
    State(mock): State<MockPaypal>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    mock.create_calls
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let gate = mock.create_gate.lock().unwrap().take();
    if let Some(gate) = gate {
        let _ = gate.await;
    }
    let request_id = headers
        .get("paypal-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body_text = String::from_utf8(body.to_vec()).unwrap();
    {
        let creates = mock.creates.lock().unwrap();
        // PayPal-Request-Id idempotency: same id returns the same order.
        for (index, (key, _)) in creates.iter().enumerate() {
            if *key == request_id {
                let id = format!("pporder_{}", index + 1);
                let order = mock.orders.lock().unwrap().get(&id).cloned().unwrap();
                return Json(order);
            }
        }
    }
    let parsed: Value = serde_json::from_str(&body_text).unwrap();
    let mut counter = mock.counter.lock().unwrap();
    *counter += 1;
    let id = format!("pporder_{}", *counter);
    let order = json!({
        "id": id,
        "status": "CREATED",
        "intent": parsed["intent"],
        "processing_instruction": parsed["processing_instruction"],
        "purchase_units": [{
            "custom_id": parsed["purchase_units"][0]["custom_id"],
            "amount": parsed["purchase_units"][0]["amount"],
        }],
        "links": [
            {"rel": "self",
             "href": format!("https://api.sandbox.paypal.test/v2/checkout/orders/{id}")},
            {"rel": "payer-action",
             "href": format!("https://sandbox.paypal.test/checkoutnow?token={id}")}
        ]
    });
    mock.orders
        .lock()
        .unwrap()
        .insert(id.clone(), order.clone());
    mock.creates.lock().unwrap().push((request_id, body_text));
    Json(order)
}

async fn mock_paypal_get_order(
    State(mock): State<MockPaypal>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match mock.orders.lock().unwrap().get(&id) {
        Some(order) => Json(order.clone()).into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"name": "RESOURCE_NOT_FOUND"})),
        )
            .into_response(),
    }
}

async fn mock_paypal_capture_order(
    State(mock): State<MockPaypal>,
    Path(id): Path<String>,
) -> axum::response::Response {
    let capture = {
        let mut orders = mock.orders.lock().unwrap();
        let Some(order) = orders.get_mut(&id) else {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(json!({"name": "RESOURCE_NOT_FOUND"})),
            )
                .into_response();
        };
        if order["status"] != json!("APPROVED") {
            return (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"name": "UNPROCESSABLE_ENTITY",
                            "details": [{"issue": "ORDER_NOT_APPROVED"}]})),
            )
                .into_response();
        }
        *mock.capture_calls.lock().unwrap() += 1;
        order["status"] = json!("COMPLETED");
        let capture = json!({
            "id": format!("ppcap_{id}"),
            "status": "COMPLETED",
            "amount": order["purchase_units"][0]["amount"].clone(),
            "custom_id": order["purchase_units"][0]["custom_id"].clone(),
        });
        order["purchase_units"][0]["payments"] = json!({"captures": [capture.clone()]});
        let response = order.clone();
        mock.captures
            .lock()
            .unwrap()
            .insert(capture["id"].as_str().unwrap().to_owned(), capture);
        response
    };
    Json(capture).into_response()
}

async fn mock_paypal_get_capture(
    State(mock): State<MockPaypal>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match mock.captures.lock().unwrap().get(&id) {
        Some(capture) => Json(capture.clone()).into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"name": "RESOURCE_NOT_FOUND"})),
        )
            .into_response(),
    }
}

async fn mock_paypal_get_dispute(
    State(mock): State<MockPaypal>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match mock.disputes.lock().unwrap().get(&id) {
        Some(dispute) => Json(dispute.clone()).into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"name": "RESOURCE_NOT_FOUND"})),
        )
            .into_response(),
    }
}

/// `GET /v1/customer/disputes?disputed_transaction_id=...`: summaries of
/// the disputes naming that capture.
async fn mock_paypal_list_disputes(
    State(mock): State<MockPaypal>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    if *mock.disputes_unavailable.lock().unwrap() {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"name": "INTERNAL_SERVICE_ERROR"})),
        )
            .into_response();
    }
    let Some(capture_id) = query.get("disputed_transaction_id") else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"name": "INVALID_REQUEST"})),
        )
            .into_response();
    };
    let items: Vec<Value> = mock
        .disputes
        .lock()
        .unwrap()
        .values()
        .filter(|dispute| {
            dispute["disputed_transactions"]
                .as_array()
                .is_some_and(|transactions| {
                    transactions
                        .iter()
                        .any(|t| t["seller_transaction_id"] == json!(capture_id))
                })
        })
        .map(|dispute| json!({"dispute_id": dispute["dispute_id"], "status": dispute["status"]}))
        .collect();
    Json(json!({"items": items, "links": []})).into_response()
}

/// Really verifies: recomputes the mock transmission signature from the
/// postback's own fields and the exact bytes of the forwarded event.
async fn mock_paypal_verify_webhook(body: Bytes) -> axum::response::Response {
    #[derive(serde::Deserialize)]
    struct Postback {
        transmission_id: String,
        transmission_sig: String,
        transmission_time: String,
        webhook_id: String,
        webhook_event: Box<serde_json::value::RawValue>,
    }
    let Ok(postback) = serde_json::from_slice::<Postback>(&body) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"name": "INVALID_REQUEST"})),
        )
            .into_response();
    };
    let expected = paypal_mock_signature(
        &postback.transmission_id,
        &postback.transmission_time,
        &postback.webhook_id,
        postback.webhook_event.get().as_bytes(),
    );
    let status =
        if postback.webhook_id == PAYPAL_WEBHOOK_ID && postback.transmission_sig == expected {
            "SUCCESS"
        } else {
            "FAILURE"
        };
    Json(json!({"verification_status": status})).into_response()
}

// -- mock Paykit Server -------------------------------------------------------

/// (path, forwarded signature header, forwarded raw body)
type CapturedForward = (String, Option<String>, Vec<u8>);

#[derive(Clone, Default)]
struct MockPaykit {
    requests: Arc<Mutex<Vec<CapturedForward>>>,
}

async fn mock_paykit_invoices(
    State(mock): State<MockPaykit>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    mock.requests.lock().unwrap().push((
        "/invoices".into(),
        headers
            .get("x-paykit-signature")
            .map(|value| value.to_str().unwrap().to_owned()),
        body.to_vec(),
    ));
    axum::http::StatusCode::NO_CONTENT
}

async fn mock_paykit_status(
    State(mock): State<MockPaykit>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    mock.requests.lock().unwrap().push((
        "/transactions/status".into(),
        headers
            .get("x-paykit-signature")
            .map(|value| value.to_str().unwrap().to_owned()),
        body.to_vec(),
    ));
    Json(json!({"status": "detected", "confirmations": 0, "amount_matched": true}))
}

// -- harness -------------------------------------------------------------------

struct Harness {
    base: String,
    store: Arc<dyn CorrelationStore>,
    memory: Arc<MemoryStore>,
    processors: Arc<Processors>,
    stripe_mock: MockStripe,
    paypal_mock: MockPaypal,
    paykit_mock: MockPaykit,
    http: reqwest::Client,
    settlement_delay: Duration,
}

#[derive(Clone, Copy)]
struct HarnessOptions {
    settlement_delay: Duration,
    with_stripe: bool,
    with_paypal: bool,
    paypal_webhook_id: bool,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            settlement_delay: Duration::from_secs(300),
            with_stripe: true,
            with_paypal: false,
            paypal_webhook_id: true,
        }
    }
}

async fn spawn(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn build_harness(options: HarnessOptions) -> Harness {
    let stripe_mock = MockStripe::default();
    let stripe_url = spawn(
        Router::new()
            .route("/v1/checkout/sessions", post(mock_create_session))
            .route("/v1/checkout/sessions/{id}", get(mock_get_session))
            .route("/v1/charges/{id}", get(mock_get_charge))
            .route("/v1/payment_intents/{id}", get(mock_get_payment_intent))
            .with_state(stripe_mock.clone()),
    )
    .await;

    let paypal_mock = MockPaypal::default();
    let paypal_url = spawn(
        Router::new()
            .route("/v1/oauth2/token", post(mock_paypal_token))
            .route("/v2/checkout/orders", post(mock_paypal_create_order))
            .route("/v2/checkout/orders/{id}", get(mock_paypal_get_order))
            .route(
                "/v2/checkout/orders/{id}/capture",
                post(mock_paypal_capture_order),
            )
            .route("/v2/payments/captures/{id}", get(mock_paypal_get_capture))
            .route("/v1/customer/disputes", get(mock_paypal_list_disputes))
            .route("/v1/customer/disputes/{id}", get(mock_paypal_get_dispute))
            .route(
                "/v1/notifications/verify-webhook-signature",
                post(mock_paypal_verify_webhook),
            )
            .with_state(paypal_mock.clone()),
    )
    .await;

    let paykit_mock = MockPaykit::default();
    let paykit_url = spawn(
        Router::new()
            .route("/invoices", post(mock_paykit_invoices))
            .route("/transactions/status", post(mock_paykit_status))
            .with_state(paykit_mock.clone()),
    )
    .await;

    let mut criteria = std::collections::HashMap::new();
    criteria.insert(
        format!("{CREATOR}/pub/locks.app/usd.json"),
        LockCriterion {
            asset: "USD".into(),
            amount: "1999".into(),
            recipient_pubky: CREATOR.into(),
        },
    );
    criteria.insert(
        format!("{CREATOR}/pub/locks.app/btc.json"),
        LockCriterion {
            asset: "BTC".into(),
            amount: "15000".into(),
            recipient_pubky: CREATOR.into(),
        },
    );
    criteria.insert(
        format!("{CREATOR}/pub/locks.app/eur.json"),
        LockCriterion {
            asset: "EUR".into(),
            amount: "500".into(),
            recipient_pubky: CREATOR.into(),
        },
    );
    // Lock Server-stored locks carry the recipient as bare z32 (no `pubky`
    // prefix), while the addressed resource uses the prefixed app key.
    criteria.insert(
        format!("{CREATOR}/pub/locks.app/usdbare.json"),
        LockCriterion {
            asset: "USD".into(),
            amount: "1999".into(),
            recipient_pubky: CREATOR.strip_prefix("pubky").unwrap().into(),
        },
    );

    let memory = Arc::new(MemoryStore::default());
    let store: Arc<dyn CorrelationStore> = memory.clone();
    let processors = Arc::new(Processors {
        stripe: options.with_stripe.then(|| {
            Arc::new(StripeProcessor::new(
                url::Url::parse(&stripe_url).unwrap(),
                "sk_test_unit".into(),
                Some(WEBHOOK_SECRET.into()),
            ))
        }),
        paypal: options.with_paypal.then(|| {
            Arc::new(PaypalProcessor::new(
                url::Url::parse(&paypal_url).unwrap(),
                "paypal_client_unit".into(),
                "paypal_secret_unit".into(),
                options
                    .paypal_webhook_id
                    .then(|| PAYPAL_WEBHOOK_ID.to_owned()),
            ))
        }),
    });
    let default_processor = processors
        .sole_configured()
        .unwrap_or(ProcessorKind::Stripe);
    let state = Arc::new(AppState {
        trusted_key: locks_key().verifying_key(),
        store: store.clone(),
        processors: processors.clone(),
        default_processor,
        criterion_source: Arc::new(StaticCriteria(Mutex::new(criteria))),
        proxy: Arc::new(PaykitProxy::new(url::Url::parse(&paykit_url).unwrap())),
        settlement_delay: options.settlement_delay,
        synthesized_confirmations: 1,
        allowed_assets: vec!["USD".into()],
        checkout_success_url: "https://app.test/success".into(),
        checkout_cancel_url: "https://app.test/cancel".into(),
        buyer_return_origins: vec![ORIGIN_A.into(), ORIGIN_B.into()],
        checkout_limiter: TokenBucket::new(100, 100),
    });
    let base = spawn(router(state)).await;
    Harness {
        base,
        store,
        memory,
        processors,
        stripe_mock,
        paypal_mock,
        paykit_mock,
        http: reqwest::Client::new(),
        settlement_delay: options.settlement_delay,
    }
}

async fn harness_with_delay(settlement_delay: Duration) -> Harness {
    build_harness(HarnessOptions {
        settlement_delay,
        ..HarnessOptions::default()
    })
    .await
}

async fn harness() -> Harness {
    build_harness(HarnessOptions::default()).await
}

async fn harness_paypal_only(settlement_delay: Duration) -> Harness {
    build_harness(HarnessOptions {
        settlement_delay,
        with_stripe: false,
        with_paypal: true,
        ..HarnessOptions::default()
    })
    .await
}

async fn harness_dual(settlement_delay: Duration) -> Harness {
    build_harness(HarnessOptions {
        settlement_delay,
        with_stripe: true,
        with_paypal: true,
        ..HarnessOptions::default()
    })
    .await
}

/// The reversal watch the worker tests run with.
const WATCH: ReversalWatch = ReversalWatch {
    window: Duration::from_secs(180 * 86_400),
    recheck_interval: Duration::from_secs(3600),
};

impl Harness {
    /// One poll-worker pass at `now`.
    async fn tick(&self, now: OffsetDateTime) {
        crate::worker::tick(
            &self.store,
            &self.processors,
            self.settlement_delay,
            WATCH,
            now,
        )
        .await;
    }

    async fn state(&self, bundle: &str) -> CorrelationState {
        self.store
            .get(CREATOR, bundle)
            .await
            .unwrap()
            .unwrap()
            .state
    }

    async fn signed_post(&self, path: &str, body: &[u8]) -> reqwest::Response {
        self.http
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/json")
            .header("x-paykit-signature", sign(&locks_key(), body))
            .body(body.to_vec())
            .send()
            .await
            .unwrap()
    }

    async fn invoice(&self, lock: &str, bundle: &str) -> reqwest::Response {
        let body = canonical(&json!({
            "bundle_id": bundle,
            "lock_resource": format!("{CREATOR}/pub/locks.app/{lock}.json"),
            "reader": READER,
        }));
        self.signed_post("/invoices", &body).await
    }

    async fn status(&self, bundle: &str) -> Value {
        let body = canonical(&json!({"bundle_id": bundle, "creator": CREATOR}));
        self.signed_post("/transactions/status", &body)
            .await
            .json()
            .await
            .unwrap()
    }

    fn webhook_signature(&self, timestamp: i64, payload: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(WEBHOOK_SECRET.as_bytes()).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        )
    }

    async fn send_webhook(&self, event: &Value) -> reqwest::Response {
        let payload = serde_json::to_vec(event).unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.http
            .post(format!("{}/webhooks/stripe", self.base))
            .header("stripe-signature", self.webhook_signature(now, &payload))
            .body(payload)
            .send()
            .await
            .unwrap()
    }

    /// Delivers a PayPal webhook whose transmission signature covers
    /// `signed_over` — pass the payload itself for a valid delivery, or
    /// different bytes to simulate tampering.
    async fn send_paypal_webhook_signed_over(
        &self,
        payload: Vec<u8>,
        signed_over: &[u8],
    ) -> reqwest::Response {
        use sha2::Digest;
        let transmission_id = format!("tx-{}", hex::encode(&Sha256::digest(&payload)[..6]));
        let transmission_time = "2026-08-22T00:00:00Z";
        let signature = paypal_mock_signature(
            &transmission_id,
            transmission_time,
            PAYPAL_WEBHOOK_ID,
            signed_over,
        );
        self.http
            .post(format!("{}/webhooks/paypal", self.base))
            .header("paypal-transmission-id", transmission_id)
            .header("paypal-transmission-time", transmission_time)
            .header("paypal-transmission-sig", signature)
            .header(
                "paypal-cert-url",
                "https://api.sandbox.paypal.test/cert.pem",
            )
            .header("paypal-auth-algo", "SHA256withRSA")
            .body(payload)
            .send()
            .await
            .unwrap()
    }

    async fn send_paypal_webhook(&self, event: &Value) -> reqwest::Response {
        let payload = serde_json::to_vec(event).unwrap();
        let signed_over = payload.clone();
        self.send_paypal_webhook_signed_over(payload, &signed_over)
            .await
    }

    async fn checkout(&self, bundle: &str, processor: Option<&str>) -> reqwest::Response {
        self.checkout_with_origin(bundle, processor, None).await
    }

    async fn checkout_with_origin(
        &self,
        bundle: &str,
        processor: Option<&str>,
        return_origin: Option<&str>,
    ) -> reqwest::Response {
        let mut body = json!({"creator": CREATOR, "bundle_id": bundle});
        if let Some(processor) = processor {
            body["processor"] = json!(processor);
        }
        if let Some(origin) = return_origin {
            body["return_origin"] = json!(origin);
        }
        self.http
            .post(format!("{}/checkout-sessions", self.base))
            .json(&body)
            .send()
            .await
            .unwrap()
    }
}

// -- tests ----------------------------------------------------------------------

#[tokio::test]
async fn btc_invoice_is_proxied_verbatim_with_original_signature() {
    let harness = harness().await;
    let body = canonical(&json!({
        "bundle_id": BUNDLE,
        "lock_resource": format!("{CREATOR}/pub/locks.app/btc.json"),
        "reader": READER,
    }));
    let signature = sign(&locks_key(), &body);
    let response = harness.signed_post("/invoices", &body).await;
    assert_eq!(response.status().as_u16(), 204);

    let requests = harness.paykit_mock.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let (path, forwarded_signature, forwarded_body) = &requests[0];
    assert_eq!(path, "/invoices");
    assert_eq!(forwarded_signature.as_deref(), Some(signature.as_str()));
    assert_eq!(forwarded_body, &body);
}

#[tokio::test]
async fn unknown_status_is_proxied_to_paykit() {
    let harness = harness().await;
    let status = harness.status("UNKNOWNBUNDLE1").await;
    assert_eq!(status["status"], "detected");
    let requests = harness.paykit_mock.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "/transactions/status");
}

#[tokio::test]
async fn unsigned_and_garbage_signed_requests_are_rejected() {
    let harness = harness().await;
    let body = canonical(&json!({
        "bundle_id": BUNDLE,
        "lock_resource": format!("{CREATOR}/pub/locks.app/usd.json"),
        "reader": READER,
    }));
    let unsigned = harness
        .http
        .post(format!("{}/invoices", harness.base))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(unsigned.status().as_u16(), 401);

    let garbage = harness
        .http
        .post(format!("{}/invoices", harness.base))
        .header("x-paykit-signature", URL_SAFE_NO_PAD.encode([0_u8; 64]))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(garbage.status().as_u16(), 401);
    assert!(harness.paykit_mock.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn usd_invoice_creates_idempotent_checkout_session() {
    let harness = harness().await;
    let first = harness.invoice("usd", BUNDLE).await;
    assert_eq!(first.status().as_u16(), 204);

    // Exact replay: same identity, same terms -> 204, no second session.
    let replay = harness.invoice("usd", BUNDLE).await;
    assert_eq!(replay.status().as_u16(), 204);
    assert_eq!(harness.stripe_mock.creates.lock().unwrap().len(), 1);

    let (idempotency_key, form) = harness.stripe_mock.creates.lock().unwrap()[0].clone();
    assert!(idempotency_key.starts_with("fiatv1-"));
    assert!(form.contains("mode=payment"));
    assert!(form.contains("unit_amount%5D=1999"));
    assert!(form.contains("currency%5D=usd"));

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Created);
    assert_eq!(row.session_id.as_deref(), Some("cs_test_1"));
    assert_eq!(row.amount_minor, 1999);
    // Nothing was proxied to the Paykit Server on the fiat path.
    assert!(harness.paykit_mock.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn same_bundle_with_different_terms_conflicts() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    // Same (creator, bundle_id) bound to a different reader -> 409, mirroring
    // paykit-server's invoice-binding conflict semantics.
    let conflicting = canonical(&json!({
        "bundle_id": BUNDLE,
        "lock_resource": format!("{CREATOR}/pub/locks.app/usd.json"),
        "reader": CREATOR,
    }));
    let response = harness.signed_post("/invoices", &conflicting).await;
    assert_eq!(response.status().as_u16(), 409);
}

#[tokio::test]
async fn bare_z32_recipient_matches_prefixed_creator() {
    let harness = harness().await;
    let response = harness.invoice("usdbare", BUNDLE).await;
    assert_eq!(response.status().as_u16(), 204);
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Created);
}

#[tokio::test]
async fn disallowed_fiat_asset_fails_the_submission() {
    let harness = harness().await;
    let response = harness.invoice("eur", BUNDLE).await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn fiat_status_reports_undetected_until_the_pull_says_paid() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    let status = harness.status(BUNDLE).await;
    assert_eq!(
        status,
        json!({"status": "undetected", "confirmations": 0, "amount_matched": false})
    );
}

#[tokio::test]
async fn webhook_hint_is_overruled_by_unpaid_pull() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    // A webhook claims completion, but the API still says unpaid.
    // The pull wins: nothing moves.
    let event = json!({
        "id": "evt_lying_1",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_test_1",
            "client_reference_id": format!("{CREATOR}_{BUNDLE}"),
            "payment_status": "paid"
        }}
    });
    let response = harness.send_webhook(&event).await;
    assert_eq!(response.status().as_u16(), 200);

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Created);
    let status = harness.status(BUNDLE).await;
    assert_eq!(status["status"], "undetected");
}

#[tokio::test]
async fn paid_pull_detects_then_settlement_delay_confirms() {
    let harness = harness_with_delay(Duration::from_secs(2)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    // Payment happens at the processor; webhook arrives; the pull verifies.
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    let event = json!({
        "id": "evt_real_1",
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_test_1",
            "client_reference_id": format!("{CREATOR}_{BUNDLE}")
        }}
    });
    assert_eq!(harness.send_webhook(&event).await.status().as_u16(), 200);

    // Inside the settlement delay: detected, never confirmed.
    let status = harness.status(BUNDLE).await;
    assert_eq!(
        status,
        json!({"status": "detected", "confirmations": 0, "amount_matched": true})
    );

    // After the delay: the status call re-pulls and promotes.
    tokio::time::sleep(harness.settlement_delay + Duration::from_millis(200)).await;
    let status = harness.status(BUNDLE).await;
    assert_eq!(
        status,
        json!({"status": "confirmed", "confirmations": 1, "amount_matched": true})
    );
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Confirmed);
}

#[tokio::test]
async fn duplicate_webhook_events_are_deduplicated() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    let event = json!({
        "id": "evt_dup",
        "type": "checkout.session.completed",
        "data": {"object": {"id": "cs_test_1",
            "client_reference_id": format!("{CREATOR}_{BUNDLE}")}}
    });
    let first: Value = harness.send_webhook(&event).await.json().await.unwrap();
    assert_eq!(first, json!({"received": true}));
    let second: Value = harness.send_webhook(&event).await.json().await.unwrap();
    assert_eq!(second, json!({"received": true, "duplicate": true}));
}

#[tokio::test]
async fn webhook_with_bad_signature_is_rejected() {
    let harness = harness().await;
    let payload = serde_json::to_vec(&json!({"id": "evt_x", "type": "t"})).unwrap();
    let response = harness
        .http
        .post(format!("{}/webhooks/stripe", harness.base))
        .header("stripe-signature", "t=1,v1=deadbeef")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn detection_works_without_webhooks_via_status_poll() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    // No webhook at all: the Lock Server's own status poll triggers the pull.
    let status = harness.status(BUNDLE).await;
    assert_eq!(status["status"], "detected");
    assert_eq!(status["amount_matched"], true);
}

#[tokio::test]
async fn amount_mismatch_is_reported_and_never_promotes() {
    let harness = harness_with_delay(Duration::from_secs(0)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    {
        let mut sessions = harness.stripe_mock.sessions.lock().unwrap();
        let session = sessions.get_mut("cs_test_1").unwrap();
        session["amount_total"] = json!(1); // paid the wrong amount
    }
    let status = harness.status(BUNDLE).await;
    assert_eq!(
        status,
        json!({"status": "detected", "confirmations": 0, "amount_matched": false})
    );
    // Even with a zero delay it must not confirm.
    let status = harness.status(BUNDLE).await;
    assert_eq!(status["status"], "detected");
    assert_eq!(status["amount_matched"], false);
}

#[tokio::test]
async fn checkout_sessions_returns_url_and_reminting_only_after_expiry() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    let fetch = || async {
        harness
            .http
            .post(format!("{}/checkout-sessions", harness.base))
            .json(&json!({"creator": CREATOR, "bundle_id": BUNDLE}))
            .send()
            .await
            .unwrap()
    };
    let first: Value = fetch().await.json().await.unwrap();
    assert_eq!(
        first["checkout_url"],
        "https://checkout.stripe.test/c/pay/cs_test_1"
    );
    assert_eq!(first["processor"], "stripe");

    // Same live session on repeat.
    let repeat: Value = fetch().await.json().await.unwrap();
    assert_eq!(repeat["checkout_url"], first["checkout_url"]);
    assert_eq!(harness.stripe_mock.creates.lock().unwrap().len(), 1);

    // Force expiry -> replacement is minted with a new idempotency key.
    harness
        .store
        .set_session(
            CREATOR,
            BUNDLE,
            "stripe",
            "cs_test_1",
            first["checkout_url"].as_str().unwrap(),
            1,
            1,
            None,
        )
        .await
        .unwrap();
    let reminted: Value = fetch().await.json().await.unwrap();
    assert_eq!(
        reminted["checkout_url"],
        "https://checkout.stripe.test/c/pay/cs_test_2"
    );
    assert_eq!(harness.stripe_mock.creates.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn checkout_sessions_unknown_bundle_is_404_and_paid_conflicts() {
    let harness = harness_with_delay(Duration::from_secs(600)).await;
    let unknown = harness
        .http
        .post(format!("{}/checkout-sessions", harness.base))
        .json(&json!({"creator": CREATOR, "bundle_id": "NOPE1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status().as_u16(), 404);

    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    let _ = harness.status(BUNDLE).await; // detection pull
    let paid = harness
        .http
        .post(format!("{}/checkout-sessions", harness.base))
        .json(&json!({"creator": CREATOR, "bundle_id": BUNDLE}))
        .send()
        .await
        .unwrap();
    assert_eq!(paid.status().as_u16(), 409);
}

#[tokio::test]
async fn verified_reversal_blocks_promotion() {
    let harness = harness_with_delay(Duration::from_secs(0)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    let status = harness.status(BUNDLE).await; // detect + record payment_intent
                                               // Zero delay: this status call would normally promote on its next poll.
    assert!(status["status"] == "confirmed" || status["status"] == "detected");

    // Reset to a paid-but-not-yet-confirmed shape for the reversal test.
    let harness = harness_with_delay(Duration::from_secs(600)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    let _ = harness.status(BUNDLE).await; // detected; payment_intent = pi_cs_test_1
    harness.stripe_mock.charges.lock().unwrap().insert(
        "ch_reversed".into(),
        json!({"id": "ch_reversed", "refunded": true, "disputed": false,
               "payment_intent": "pi_cs_test_1"}),
    );
    let event = json!({
        "id": "evt_reversal",
        "type": "charge.refunded",
        "data": {"object": {"id": "ch_reversed"}}
    });
    assert_eq!(harness.send_webhook(&event).await.status().as_u16(), 200);

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Reversed);
    let status = harness.status(BUNDLE).await;
    assert_eq!(status["status"], "undetected");
}

#[tokio::test]
async fn health_reports_ok() {
    let harness = harness().await;
    let health: Value = harness
        .http
        .get(format!("{}/health", harness.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["stripe_enabled"], true);
    assert_eq!(health["paypal_enabled"], false);
    assert_eq!(health["paypal_webhook_configured"], false);
    assert_eq!(health["default_processor"], "stripe");
}

// -- PayPal leg -------------------------------------------------------------------

#[tokio::test]
async fn paypal_only_invoice_mints_order_eagerly_and_idempotently() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    // Exact replay: same identity, same terms -> 204, no second order.
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    assert_eq!(harness.paypal_mock.creates.lock().unwrap().len(), 1);

    let (request_id, body) = harness.paypal_mock.creates.lock().unwrap()[0].clone();
    assert!(request_id.starts_with("fiatv1-"));
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["intent"], "CAPTURE");
    assert_eq!(
        body["processing_instruction"],
        "ORDER_COMPLETE_ON_PAYMENT_APPROVAL"
    );
    assert_eq!(
        body["purchase_units"][0]["custom_id"],
        format!("{CREATOR}_{BUNDLE}")
    );
    assert_eq!(body["purchase_units"][0]["amount"]["currency_code"], "USD");
    assert_eq!(body["purchase_units"][0]["amount"]["value"], "19.99");

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Created);
    assert_eq!(row.processor.as_deref(), Some("paypal"));
    assert_eq!(row.session_id.as_deref(), Some("pporder_1"));

    let checkout: Value = harness.checkout(BUNDLE, None).await.json().await.unwrap();
    assert_eq!(checkout["processor"], "paypal");
    assert_eq!(
        checkout["checkout_url"],
        "https://sandbox.paypal.test/checkoutnow?token=pporder_1"
    );
}

#[tokio::test]
async fn dual_processor_invoice_defers_mint_and_checkout_binds_default() {
    let harness = harness_dual(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    // Both processors configured: no session yet, the buyer chooses.
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert!(row.session_id.is_none());
    assert!(row.processor.is_none());
    assert!(harness.stripe_mock.creates.lock().unwrap().is_empty());
    assert!(harness.paypal_mock.creates.lock().unwrap().is_empty());

    // No processor named -> deployment default (stripe).
    let checkout: Value = harness.checkout(BUNDLE, None).await.json().await.unwrap();
    assert_eq!(checkout["processor"], "stripe");
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.processor.as_deref(), Some("stripe"));

    // The binding is permanent: asking for paypal afterwards conflicts.
    let switched = harness.checkout(BUNDLE, Some("paypal")).await;
    assert_eq!(switched.status().as_u16(), 409);

    // Asking for the bound processor returns the same live session.
    let repeat: Value = harness
        .checkout(BUNDLE, Some("stripe"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(repeat["checkout_url"], checkout["checkout_url"]);
}

#[tokio::test]
async fn dual_processor_checkout_can_choose_paypal() {
    let harness = harness_dual(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    let checkout: Value = harness
        .checkout(BUNDLE, Some("paypal"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(checkout["processor"], "paypal");
    assert_eq!(
        checkout["checkout_url"],
        "https://sandbox.paypal.test/checkoutnow?token=pporder_1"
    );
    assert!(harness.stripe_mock.creates.lock().unwrap().is_empty());

    // Idempotent repeat, and stripe is now a conflicting choice.
    let repeat: Value = harness
        .checkout(BUNDLE, Some("paypal"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(repeat["checkout_url"], checkout["checkout_url"]);
    assert_eq!(harness.paypal_mock.creates.lock().unwrap().len(), 1);
    assert_eq!(
        harness
            .checkout(BUNDLE, Some("stripe"))
            .await
            .status()
            .as_u16(),
        409
    );
}

#[tokio::test]
async fn checkout_rejects_unknown_processor_value() {
    let harness = harness_dual(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    let response = harness.checkout(BUNDLE, Some("venmo")).await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn paypal_full_lifecycle_approval_webhook_capture_then_settlement() {
    let harness = harness_paypal_only(Duration::from_secs(2)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    // Buyer approves at PayPal; the auto-capture has not landed yet, so the
    // pull observes APPROVED and captures explicitly (capture-on-approval).
    harness.paypal_mock.approve("pporder_1");
    let event = json!({
        "id": "WH-EVT-APPROVED-1",
        "event_type": "CHECKOUT.ORDER.APPROVED",
        "resource": {
            "id": "pporder_1",
            "status": "APPROVED",
            "purchase_units": [{"custom_id": format!("{CREATOR}_{BUNDLE}")}]
        }
    });
    assert_eq!(
        harness.send_paypal_webhook(&event).await.status().as_u16(),
        200
    );
    assert_eq!(*harness.paypal_mock.capture_calls.lock().unwrap(), 1);

    // Inside the settlement delay: detected, never confirmed.
    let status = harness.status(BUNDLE).await;
    assert_eq!(
        status,
        json!({"status": "detected", "confirmations": 0, "amount_matched": true})
    );
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Paid);
    assert_eq!(row.payment_intent.as_deref(), Some("ppcap_pporder_1"));

    // After the delay: the status call re-pulls and promotes.
    tokio::time::sleep(harness.settlement_delay + Duration::from_millis(200)).await;
    let status = harness.status(BUNDLE).await;
    assert_eq!(
        status,
        json!({"status": "confirmed", "confirmations": 1, "amount_matched": true})
    );
}

#[tokio::test]
async fn paypal_detection_works_without_webhooks_via_status_poll() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    // PayPal auto-captured on approval; no webhook at all: the Lock Server's
    // own status poll triggers the pull.
    harness.paypal_mock.complete("pporder_1");
    let status = harness.status(BUNDLE).await;
    assert_eq!(status["status"], "detected");
    assert_eq!(status["amount_matched"], true);
}

#[tokio::test]
async fn paypal_webhook_hint_is_overruled_by_unpaid_pull() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    // A webhook claims a completed capture, but the order pull still says
    // CREATED. The pull wins: nothing moves.
    let event = json!({
        "id": "WH-EVT-LIE-1",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {
            "id": "ppcap_pporder_1",
            "status": "COMPLETED",
            "custom_id": format!("{CREATOR}_{BUNDLE}")
        }
    });
    assert_eq!(
        harness.send_paypal_webhook(&event).await.status().as_u16(),
        200
    );
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Created);
    assert_eq!(harness.status(BUNDLE).await["status"], "undetected");
}

#[tokio::test]
async fn paypal_webhook_with_wrong_signature_is_rejected() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.paypal_mock.complete("pporder_1");

    let payload = serde_json::to_vec(&json!({
        "id": "WH-EVT-BADSIG",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {"custom_id": format!("{CREATOR}_{BUNDLE}")}
    }))
    .unwrap();
    let response = harness
        .http
        .post(format!("{}/webhooks/paypal", harness.base))
        .header("paypal-transmission-id", "tx-forged")
        .header("paypal-transmission-time", "2026-08-22T00:00:00Z")
        .header("paypal-transmission-sig", "deadbeef")
        .header(
            "paypal-cert-url",
            "https://api.sandbox.paypal.test/cert.pem",
        )
        .header("paypal-auth-algo", "SHA256withRSA")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
    // A rejected webhook schedules nothing: state is untouched even though
    // the order is genuinely paid (the next verified pull will catch it).
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Created);
}

#[tokio::test]
async fn paypal_webhook_with_tampered_body_fails_postback_verification() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    let genuine = serde_json::to_vec(&json!({
        "id": "WH-EVT-TAMPER",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {"custom_id": format!("{CREATOR}_{BUNDLE}")}
    }))
    .unwrap();
    let tampered = serde_json::to_vec(&json!({
        "id": "WH-EVT-TAMPER",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {"custom_id": format!("{CREATOR}_OTHERBUNDLE1")}
    }))
    .unwrap();
    // Signature covers the genuine bytes; the delivered body differs.
    let response = harness
        .send_paypal_webhook_signed_over(tampered, &genuine)
        .await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn paypal_webhook_fails_closed_without_configuration() {
    // Stripe-only deployment: the PayPal webhook path answers 503.
    let harness = harness().await;
    let response = harness
        .http
        .post(format!("{}/webhooks/paypal", harness.base))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 503);

    // PayPal configured but no webhook id: also 503 (poll-only detection).
    let harness = build_harness(HarnessOptions {
        with_stripe: false,
        with_paypal: true,
        paypal_webhook_id: false,
        ..HarnessOptions::default()
    })
    .await;
    let response = harness
        .http
        .post(format!("{}/webhooks/paypal", harness.base))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 503);
}

#[tokio::test]
async fn paypal_amount_mismatch_is_reported_and_never_promotes() {
    let harness = harness_paypal_only(Duration::from_secs(0)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.paypal_mock.complete("pporder_1");
    harness.paypal_mock.set_capture_amount("pporder_1", "0.01");

    let status = harness.status(BUNDLE).await;
    assert_eq!(
        status,
        json!({"status": "detected", "confirmations": 0, "amount_matched": false})
    );
    // Even with a zero delay it must not confirm.
    let status = harness.status(BUNDLE).await;
    assert_eq!(status["status"], "detected");
    assert_eq!(status["amount_matched"], false);
}

#[tokio::test]
async fn paypal_refund_reversal_blocks_promotion() {
    let harness = harness_paypal_only(Duration::from_secs(600)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.paypal_mock.complete("pporder_1");
    let _ = harness.status(BUNDLE).await; // detected; payment ref = ppcap_pporder_1
    harness
        .paypal_mock
        .set_capture_status("pporder_1", "REFUNDED");

    // The refund event's resource is the refund, linking up to the capture.
    let event = json!({
        "id": "WH-EVT-REFUND-1",
        "event_type": "PAYMENT.CAPTURE.REFUNDED",
        "resource": {
            "id": "pprefund_1",
            "status": "COMPLETED",
            "links": [
                {"rel": "up",
                 "href": "https://api.sandbox.paypal.test/v2/payments/captures/ppcap_pporder_1"}
            ]
        }
    });
    assert_eq!(
        harness.send_paypal_webhook(&event).await.status().as_u16(),
        200
    );

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Reversed);
    assert_eq!(harness.status(BUNDLE).await["status"], "undetected");
}

#[tokio::test]
async fn paypal_reversal_webhook_not_corroborated_by_pull_is_ignored() {
    let harness = harness_paypal_only(Duration::from_secs(600)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.paypal_mock.complete("pporder_1");
    let _ = harness.status(BUNDLE).await; // detected

    // Refund webhook, but the capture pull still says COMPLETED: ignored.
    let event = json!({
        "id": "WH-EVT-REFUND-FAKE",
        "event_type": "PAYMENT.CAPTURE.REFUNDED",
        "resource": {
            "id": "pprefund_x",
            "links": [
                {"rel": "up",
                 "href": "https://api.sandbox.paypal.test/v2/payments/captures/ppcap_pporder_1"}
            ]
        }
    });
    assert_eq!(
        harness.send_paypal_webhook(&event).await.status().as_u16(),
        200
    );
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Paid);
}

#[tokio::test]
async fn paypal_dispute_marks_correlation_reversed() {
    let harness = harness_paypal_only(Duration::from_secs(600)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.paypal_mock.complete("pporder_1");
    let _ = harness.status(BUNDLE).await; // detected; payment ref persisted
    harness.paypal_mock.set_dispute("PP-D-1", "ppcap_pporder_1");

    let event = json!({
        "id": "WH-EVT-DISPUTE-1",
        "event_type": "CUSTOMER.DISPUTE.CREATED",
        "resource": {
            "dispute_id": "PP-D-1",
            "disputed_transactions": [{"seller_transaction_id": "ppcap_pporder_1"}]
        }
    });
    assert_eq!(
        harness.send_paypal_webhook(&event).await.status().as_u16(),
        200
    );

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.state, CorrelationState::Reversed);
    assert_eq!(harness.status(BUNDLE).await["status"], "undetected");
}

#[tokio::test]
async fn paypal_duplicate_webhook_events_are_deduplicated() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    let event = json!({
        "id": "WH-EVT-DUP",
        "event_type": "CHECKOUT.ORDER.APPROVED",
        "resource": {"purchase_units": [{"custom_id": format!("{CREATOR}_{BUNDLE}")}]}
    });
    let first: Value = harness
        .send_paypal_webhook(&event)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(first, json!({"received": true}));
    let second: Value = harness
        .send_paypal_webhook(&event)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(second, json!({"received": true, "duplicate": true}));
}

#[tokio::test]
async fn paypal_checkout_remints_on_the_same_processor_after_expiry() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    let first: Value = harness.checkout(BUNDLE, None).await.json().await.unwrap();

    // Force expiry -> replacement is minted, still on paypal.
    harness
        .store
        .set_session(
            CREATOR,
            BUNDLE,
            "paypal",
            "pporder_1",
            first["checkout_url"].as_str().unwrap(),
            1,
            1,
            None,
        )
        .await
        .unwrap();
    let reminted: Value = harness.checkout(BUNDLE, None).await.json().await.unwrap();
    assert_eq!(reminted["processor"], "paypal");
    assert_eq!(
        reminted["checkout_url"],
        "https://sandbox.paypal.test/checkoutnow?token=pporder_2"
    );
    assert_eq!(harness.paypal_mock.creates.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn paypal_health_reports_processor_flags() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    let health: Value = harness
        .http
        .get(format!("{}/health", harness.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["stripe_enabled"], false);
    assert_eq!(health["paypal_enabled"], true);
    assert_eq!(health["paypal_webhook_configured"], true);
    assert_eq!(health["default_processor"], "paypal");
}

// -- buyer return origins -----------------------------------------------------

#[tokio::test]
async fn stripe_checkout_with_allowlisted_origin_derives_return_urls() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    let checkout = harness
        .checkout_with_origin(BUNDLE, None, Some(ORIGIN_A))
        .await;
    assert_eq!(checkout.status().as_u16(), 200);

    // Stripe received the server-side derived URLs (form-encoded).
    // [0] is the eager fallback mint at invoice time.
    let form = harness.stripe_mock.creates.lock().unwrap()[1].1.clone();
    assert!(
        form.contains("success_url=https%3A%2F%2Fshop.pubky.app%2Fmarketplace%3Fcheckout%3Dreturn"),
        "form was: {form}"
    );
    assert!(
        form.contains("cancel_url=https%3A%2F%2Fshop.pubky.app%2Fmarketplace%3Fcheckout%3Dcancel"),
        "form was: {form}"
    );

    // The origin is persisted alongside the session.
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.return_origin.as_deref(), Some(ORIGIN_A));
}

#[tokio::test]
async fn paypal_checkout_with_allowlisted_origin_derives_return_urls() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    let checkout = harness
        .checkout_with_origin(BUNDLE, None, Some(ORIGIN_B))
        .await;
    assert_eq!(checkout.status().as_u16(), 200);

    let creates = harness.paypal_mock.creates.lock().unwrap();
    let (_, body) = &creates[1]; // [0] is the eager fallback mint
    let body: Value = serde_json::from_str(body).unwrap();
    let context = &body["payment_source"]["paypal"]["experience_context"];
    assert_eq!(
        context["return_url"],
        format!("{ORIGIN_B}/marketplace?checkout=return")
    );
    assert_eq!(
        context["cancel_url"],
        format!("{ORIGIN_B}/marketplace?checkout=cancel")
    );
}

#[tokio::test]
async fn checkout_rejects_origins_off_the_allowlist() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    for origin in [
        "https://unknown-shop.example.com", // unknown origin
        "https://shop.pubky.app.evil.com",  // lookalike host
        "http://shop.pubky.app",            // not https
        "https://shop.pubky.app/marketplace?checkout=return", // full URL, not an origin
        "https://shop.pubky.app/",          // trailing slash is not exact
    ] {
        let response = harness
            .checkout_with_origin(BUNDLE, None, Some(origin))
            .await;
        assert_eq!(response.status().as_u16(), 400, "origin: {origin}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["error"]["code"], "invalid_return_origin");
    }
    // Nothing was minted or bound by the rejected requests.
    assert_eq!(harness.stripe_mock.creates.lock().unwrap().len(), 1);
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.return_origin, None);
}

#[tokio::test]
async fn checkout_without_origin_uses_the_static_fallback_urls() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    let checkout = harness.checkout(BUNDLE, None).await;
    assert_eq!(checkout.status().as_u16(), 200);

    let creates = harness.stripe_mock.creates.lock().unwrap();
    assert_eq!(creates.len(), 1); // the eager mint, no re-mint
    let (_, form) = &creates[0];
    assert!(form.contains("success_url=https%3A%2F%2Fapp.test%2Fsuccess"));
    assert!(form.contains("cancel_url=https%3A%2F%2Fapp.test%2Fcancel"));
}

#[tokio::test]
async fn bound_origin_is_persistent_and_immutable() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    // Bind ORIGIN_A.
    let first: Value = harness
        .checkout_with_origin(BUNDLE, None, Some(ORIGIN_A))
        .await
        .json()
        .await
        .unwrap();
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.return_origin.as_deref(), Some(ORIGIN_A));

    // A different origin conflicts; the same origin returns the live session.
    let switched = harness
        .checkout_with_origin(BUNDLE, None, Some(ORIGIN_B))
        .await;
    assert_eq!(switched.status().as_u16(), 409);
    let repeat: Value = harness
        .checkout_with_origin(BUNDLE, None, Some(ORIGIN_A))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(repeat["checkout_url"], first["checkout_url"]);

    // Force expiry, then re-fetch WITHOUT an origin: the re-mint keeps the
    // bound origin — a later request can never change it back. (The direct
    // write must name the bound origin: the conditional persist rejects an
    // origin-less write over an origin-bound row.)
    harness
        .store
        .set_session(
            CREATOR,
            BUNDLE,
            "stripe",
            "cs_test_2",
            first["checkout_url"].as_str().unwrap(),
            1,
            2,
            Some(ORIGIN_A),
        )
        .await
        .unwrap();
    let reminted: Value = harness.checkout(BUNDLE, None).await.json().await.unwrap();
    assert_eq!(
        reminted["checkout_url"],
        "https://checkout.stripe.test/c/pay/cs_test_3"
    );
    let form = harness
        .stripe_mock
        .creates
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .1
        .clone();
    assert!(
        form.contains("success_url=https%3A%2F%2Fshop.pubky.app%2Fmarketplace%3Fcheckout%3Dreturn"),
        "form was: {form}"
    );
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.return_origin.as_deref(), Some(ORIGIN_A));
}

/// Polls until `expected` create calls have ARRIVED at the mock (they may
/// still be parked on the one-shot gate) — no fixed sleeps in race tests.
async fn wait_for_create_calls(calls: &std::sync::atomic::AtomicUsize, expected: usize) {
    for _ in 0..1000 {
        if calls.load(std::sync::atomic::Ordering::SeqCst) >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("timed out waiting for {expected} create calls");
}

/// Fires a bare (no processor, no origin) checkout request in the
/// background: the race loser in the concurrent-binding tests below.
fn spawn_plain_checkout(base: &str) -> tokio::task::JoinHandle<reqwest::Response> {
    let url = format!("{base}/checkout-sessions");
    tokio::spawn(async move {
        reqwest::Client::new()
            .post(url)
            .json(&json!({"creator": CREATOR, "bundle_id": BUNDLE}))
            .send()
            .await
            .unwrap()
    })
}

// F1 regression: a no-origin mint that read the row before a concurrent
// origin-A mint persisted must never clobber the A binding with its
// static-fallback session. The gate parks the no-origin mint inside the
// mock create, guaranteeing the audit's interleaving: loser read +
// mint in flight -> winner mints and persists (binds A) -> loser's
// fallback-URL mint persists last and is rejected by the conditional
// UPDATE, so the loser is served the bound A session instead.
#[tokio::test]
async fn stripe_concurrent_fallback_mint_cannot_clobber_an_origin_binding() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    // Force expiry so both racers decide to mint (row still origin-less).
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert!(
        harness
            .store
            .set_session(
                CREATOR,
                BUNDLE,
                "stripe",
                row.session_id.as_deref().unwrap(),
                row.checkout_url.as_deref().unwrap(),
                1,
                1,
                None,
            )
            .await
            .unwrap(),
        "origin-less write onto an unbound row must apply"
    );

    let (release, gate) = tokio::sync::oneshot::channel();
    *harness.stripe_mock.create_gate.lock().unwrap() = Some(gate);
    let loser = spawn_plain_checkout(&harness.base);
    wait_for_create_calls(&harness.stripe_mock.create_calls, 2).await;

    // Bump the stored attempt so the winner's mint carries a distinct
    // idempotency key — with identical keys Stripe would replay one create
    // onto the other, collapsing the two mints into one session and hiding
    // the exact persist race under test.
    harness
        .store
        .set_session(
            CREATOR,
            BUNDLE,
            "stripe",
            row.session_id.as_deref().unwrap(),
            row.checkout_url.as_deref().unwrap(),
            1,
            2,
            None,
        )
        .await
        .unwrap();

    // The winner mints with ORIGIN_A and persists first, binding A.
    let winner: Value = harness
        .checkout_with_origin(BUNDLE, None, Some(ORIGIN_A))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        winner["checkout_url"],
        "https://checkout.stripe.test/c/pay/cs_test_2"
    );
    let winner_form = harness.stripe_mock.creates.lock().unwrap()[1].1.clone();
    assert!(
        winner_form
            .contains("success_url=https%3A%2F%2Fshop.pubky.app%2Fmarketplace%3Fcheckout%3Dreturn"),
        "form was: {winner_form}"
    );

    // The loser's fallback-URL mint now persists last — and must lose.
    release.send(()).unwrap();
    let loser_response = loser.await.unwrap();
    assert_eq!(loser_response.status().as_u16(), 200);
    let loser_body: Value = loser_response.json().await.unwrap();
    assert_eq!(loser_body["checkout_url"], winner["checkout_url"]);

    // The loser's mint really carried the static fallback URLs — it was
    // minted against them, yet never persisted and never served.
    let loser_form = harness.stripe_mock.creates.lock().unwrap()[2].1.clone();
    assert!(
        loser_form.contains("success_url=https%3A%2F%2Fapp.test%2Fsuccess"),
        "form was: {loser_form}"
    );

    // Invariant: return_origin=A can only ever coexist with A-derived URLs.
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.return_origin.as_deref(), Some(ORIGIN_A));
    assert_eq!(
        row.checkout_url.as_deref(),
        Some("https://checkout.stripe.test/c/pay/cs_test_2")
    );
    assert_eq!(row.session_id.as_deref(), Some("cs_test_2"));
}

// Same interleaving, but the winning session has already expired when the
// loser re-reads: nothing valid to serve, so the loser gets (b), a 409
// `invoice_conflict` — never its own fallback-URL session.
#[tokio::test]
async fn stripe_concurrent_fallback_mint_over_expired_binding_conflicts() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    harness
        .store
        .set_session(
            CREATOR,
            BUNDLE,
            "stripe",
            row.session_id.as_deref().unwrap(),
            row.checkout_url.as_deref().unwrap(),
            1,
            1,
            None,
        )
        .await
        .unwrap();

    let (release, gate) = tokio::sync::oneshot::channel();
    *harness.stripe_mock.create_gate.lock().unwrap() = Some(gate);
    let loser = spawn_plain_checkout(&harness.base);
    wait_for_create_calls(&harness.stripe_mock.create_calls, 2).await;

    // Distinct idempotency key for the winner's mint (see the serve-bound
    // race test above).
    harness
        .store
        .set_session(
            CREATOR,
            BUNDLE,
            "stripe",
            row.session_id.as_deref().unwrap(),
            row.checkout_url.as_deref().unwrap(),
            1,
            2,
            None,
        )
        .await
        .unwrap();

    let winner: Value = harness
        .checkout_with_origin(BUNDLE, None, Some(ORIGIN_A))
        .await
        .json()
        .await
        .unwrap();

    // Expire the just-bound session before the loser's persist lands.
    assert!(
        harness
            .store
            .set_session(
                CREATOR,
                BUNDLE,
                "stripe",
                "cs_test_2",
                winner["checkout_url"].as_str().unwrap(),
                1,
                2,
                Some(ORIGIN_A),
            )
            .await
            .unwrap(),
        "a write naming the bound origin must apply"
    );

    release.send(()).unwrap();
    let loser_response = loser.await.unwrap();
    assert_eq!(loser_response.status().as_u16(), 409);
    let body: Value = loser_response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invoice_conflict");

    // The row is untouched by the loser: still A-bound with A-derived URLs.
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.return_origin.as_deref(), Some(ORIGIN_A));
    assert_eq!(
        row.checkout_url.as_deref(),
        Some("https://checkout.stripe.test/c/pay/cs_test_2")
    );
}

// Same race on the PayPal leg: the gated loser's fallback-URL order mints
// last, loses the conditional persist, and is served the bound A order.
#[tokio::test]
async fn paypal_concurrent_fallback_mint_cannot_clobber_an_origin_binding() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    harness
        .store
        .set_session(
            CREATOR,
            BUNDLE,
            "paypal",
            row.session_id.as_deref().unwrap(),
            row.checkout_url.as_deref().unwrap(),
            1,
            1,
            None,
        )
        .await
        .unwrap();

    let (release, gate) = tokio::sync::oneshot::channel();
    *harness.paypal_mock.create_gate.lock().unwrap() = Some(gate);
    let loser = spawn_plain_checkout(&harness.base);
    wait_for_create_calls(&harness.paypal_mock.create_calls, 2).await;

    // Distinct idempotency key for the winner's mint (see the Stripe race
    // test above).
    harness
        .store
        .set_session(
            CREATOR,
            BUNDLE,
            "paypal",
            row.session_id.as_deref().unwrap(),
            row.checkout_url.as_deref().unwrap(),
            1,
            2,
            None,
        )
        .await
        .unwrap();

    let winner: Value = harness
        .checkout_with_origin(BUNDLE, None, Some(ORIGIN_A))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        winner["checkout_url"],
        "https://sandbox.paypal.test/checkoutnow?token=pporder_2"
    );
    let winner_body: Value =
        serde_json::from_str(&harness.paypal_mock.creates.lock().unwrap()[1].1).unwrap();
    assert_eq!(
        winner_body["payment_source"]["paypal"]["experience_context"]["return_url"],
        format!("{ORIGIN_A}/marketplace?checkout=return")
    );

    release.send(()).unwrap();
    let loser_response = loser.await.unwrap();
    assert_eq!(loser_response.status().as_u16(), 200);
    let loser_body: Value = loser_response.json().await.unwrap();
    assert_eq!(loser_body["checkout_url"], winner["checkout_url"]);

    // The loser's minted order carried the static fallback URLs.
    let loser_mint: Value =
        serde_json::from_str(&harness.paypal_mock.creates.lock().unwrap()[2].1).unwrap();
    assert_eq!(
        loser_mint["payment_source"]["paypal"]["experience_context"]["return_url"],
        "https://app.test/success"
    );

    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.return_origin.as_deref(), Some(ORIGIN_A));
    assert_eq!(
        row.checkout_url.as_deref(),
        Some("https://sandbox.paypal.test/checkoutnow?token=pporder_2")
    );
    assert_eq!(row.session_id.as_deref(), Some("pporder_2"));
}

// Regression guard: a plain sequential no-origin re-fetch on an A-bound
// correlation keeps returning the A session (never reverts to fallback).
#[tokio::test]
async fn no_origin_refetch_on_bound_correlation_returns_the_bound_session() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);

    let first: Value = harness
        .checkout_with_origin(BUNDLE, None, Some(ORIGIN_A))
        .await
        .json()
        .await
        .unwrap();
    let refetch = harness.checkout(BUNDLE, None).await;
    assert_eq!(refetch.status().as_u16(), 200);
    let refetch: Value = refetch.json().await.unwrap();
    assert_eq!(refetch["checkout_url"], first["checkout_url"]);

    // No re-mint: eager + A-binding mint only.
    assert_eq!(harness.stripe_mock.creates.lock().unwrap().len(), 2);
    let row = harness.store.get(CREATOR, BUNDLE).await.unwrap().unwrap();
    assert_eq!(row.return_origin.as_deref(), Some(ORIGIN_A));
}

// -- reversal hardening ---------------------------------------------------------

/// Invoice, pay, detect and confirm a Stripe purchase through the poll
/// worker alone (no webhooks); returns the confirmation time.
async fn confirm_stripe_purchase(harness: &Harness) -> OffsetDateTime {
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    let paid_at = OffsetDateTime::now_utc();
    harness.tick(paid_at).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Paid);
    let confirmed_at = paid_at + harness.settlement_delay;
    harness.tick(confirmed_at).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Confirmed);
    confirmed_at
}

/// Same through PayPal.
async fn confirm_paypal_purchase(harness: &Harness) -> OffsetDateTime {
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.paypal_mock.complete("pporder_1");
    let paid_at = OffsetDateTime::now_utc();
    harness.tick(paid_at).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Paid);
    let confirmed_at = paid_at + harness.settlement_delay;
    harness.tick(confirmed_at).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Confirmed);
    confirmed_at
}

#[tokio::test]
async fn refund_inside_settlement_delay_blocks_confirmation_without_a_webhook() {
    let harness = harness_with_delay(Duration::from_secs(1)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    assert_eq!(harness.status(BUNDLE).await["status"], "detected");

    // Full refund; the session still says `paid` and no webhook arrives.
    harness.stripe_mock.refund("cs_test_1", 1999);
    tokio::time::sleep(harness.settlement_delay + Duration::from_millis(200)).await;
    assert_eq!(
        harness.status(BUNDLE).await,
        json!({"status": "undetected", "confirmations": 0, "amount_matched": false})
    );
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);
    assert!(!harness.memory.meta(CREATOR, BUNDLE).reversed_after_confirm);
}

#[tokio::test]
async fn partial_refund_blocks_worker_promotion() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    let paid_at = OffsetDateTime::now_utc();
    harness.tick(paid_at).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Paid);

    harness.stripe_mock.refund("cs_test_1", 500);
    harness.tick(paid_at + harness.settlement_delay).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);
}

#[tokio::test]
async fn dispute_before_detection_never_marks_paid() {
    let harness = harness().await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    harness.stripe_mock.dispute("cs_test_1");
    assert_eq!(harness.status(BUNDLE).await["status"], "undetected");
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);
}

#[tokio::test]
async fn confirmed_status_is_rechecked_and_a_later_refund_withdraws_it() {
    let harness = harness().await;
    confirm_stripe_purchase(&harness).await;
    assert_eq!(
        harness.status(BUNDLE).await,
        json!({"status": "confirmed", "confirmations": 1, "amount_matched": true})
    );

    harness.stripe_mock.refund("cs_test_1", 1999);
    assert_eq!(
        harness.status(BUNDLE).await,
        json!({"status": "undetected", "confirmations": 0, "amount_matched": false})
    );
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);
    let meta = harness.memory.meta(CREATOR, BUNDLE);
    assert!(meta.reversed_after_confirm);
    assert!(meta.reversed_at.is_some());
}

#[tokio::test]
async fn confirmed_status_holds_at_detected_while_stripe_is_unreadable() {
    let harness = harness().await;
    confirm_stripe_purchase(&harness).await;
    harness.stripe_mock.fail_payment_intent_reads(true);
    assert_eq!(
        harness.status(BUNDLE).await,
        json!({"status": "detected", "confirmations": 0, "amount_matched": true})
    );
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Confirmed);
    harness.stripe_mock.fail_payment_intent_reads(false);
    assert_eq!(harness.status(BUNDLE).await["status"], "confirmed");
}

#[tokio::test]
async fn worker_reconciles_a_dispute_after_confirm_whose_webhook_was_lost() {
    let harness = harness().await;
    let confirmed_at = confirm_stripe_purchase(&harness).await;
    harness.stripe_mock.dispute("cs_test_1");

    // The confirming pull counts as the first check; the next one is due a
    // recheck interval later.
    harness.tick(confirmed_at + WATCH.recheck_interval).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);
    assert!(harness.memory.meta(CREATOR, BUNDLE).reversed_after_confirm);
}

#[tokio::test]
async fn reversal_watch_respects_the_recheck_interval() {
    let harness = harness().await;
    let confirmed_at = confirm_stripe_purchase(&harness).await;
    let checked_at = harness.memory.meta(CREATOR, BUNDLE).reversal_checked_at;
    assert_eq!(checked_at, Some(confirmed_at));

    // Refunded later; a pass inside the recheck interval leaves the row.
    harness.stripe_mock.refund("cs_test_1", 1999);
    harness.tick(confirmed_at + Duration::from_secs(60)).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Confirmed);

    // The next pass after the interval finds the refund.
    harness.tick(confirmed_at + WATCH.recheck_interval).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);
    assert!(harness.memory.meta(CREATOR, BUNDLE).reversed_after_confirm);
}

#[tokio::test]
async fn reversal_watch_stops_after_the_window() {
    let harness = harness().await;
    let confirmed_at = confirm_stripe_purchase(&harness).await;
    harness.stripe_mock.refund("cs_test_1", 1999);
    harness
        .tick(confirmed_at + WATCH.window + Duration::from_secs(1))
        .await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Confirmed);
    assert_eq!(
        harness.memory.meta(CREATOR, BUNDLE).reversal_checked_at,
        Some(confirmed_at)
    );
}

#[tokio::test]
async fn reversal_watch_retries_a_row_the_processor_could_not_answer() {
    let harness = harness().await;
    let confirmed_at = confirm_stripe_purchase(&harness).await;
    harness.stripe_mock.fail_payment_intent_reads(true);
    let due = confirmed_at + WATCH.recheck_interval;
    harness.tick(due).await;
    assert_eq!(
        harness.memory.meta(CREATOR, BUNDLE).reversal_checked_at,
        Some(confirmed_at),
        "an unanswered check is not recorded"
    );

    // The very next pass retries, without waiting another interval.
    harness.stripe_mock.fail_payment_intent_reads(false);
    harness.stripe_mock.dispute("cs_test_1");
    harness.tick(due + Duration::from_secs(60)).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);
}

#[tokio::test]
async fn refund_webhook_after_confirm_reverses_the_row() {
    let harness = harness().await;
    confirm_stripe_purchase(&harness).await;
    harness.stripe_mock.refund("cs_test_1", 1999);
    let event = json!({
        "id": "evt_refund_after_confirm",
        "type": "charge.refunded",
        "data": {"object": {"id": "ch_cs_test_1", "object": "charge"}}
    });
    assert_eq!(harness.send_webhook(&event).await.status().as_u16(), 200);
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);
    assert!(harness.memory.meta(CREATOR, BUNDLE).reversed_after_confirm);
}

#[tokio::test]
async fn dispute_webhook_resolves_the_charge_from_the_dispute_object() {
    let harness = harness_with_delay(Duration::from_secs(600)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    assert_eq!(harness.status(BUNDLE).await["status"], "detected");

    let dispute = harness.stripe_mock.dispute("cs_test_1");
    let event = json!({
        "id": "evt_dispute_1",
        "type": "charge.dispute.created",
        "data": {"object": dispute}
    });
    assert_eq!(harness.send_webhook(&event).await.status().as_u16(), 200);
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);
    assert!(!harness.memory.meta(CREATOR, BUNDLE).reversed_after_confirm);
}

#[tokio::test]
async fn reversal_webhook_that_fails_transiently_is_processed_on_redelivery() {
    let harness = harness_with_delay(Duration::from_secs(600)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.stripe_mock.set_payment_status("cs_test_1", "paid");
    assert_eq!(harness.status(BUNDLE).await["status"], "detected");

    // The charge pull fails (Stripe answers 404 for a charge it has not
    // propagated yet): 503, and the event id is released.
    let event = json!({
        "id": "evt_refund_retry",
        "type": "charge.refunded",
        "data": {"object": {"id": "ch_late", "object": "charge"}}
    });
    assert_eq!(harness.send_webhook(&event).await.status().as_u16(), 503);
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Paid);

    harness.stripe_mock.charges.lock().unwrap().insert(
        "ch_late".into(),
        json!({"id": "ch_late", "status": "succeeded", "refunded": true,
               "amount_refunded": 1999, "disputed": false,
               "payment_intent": "pi_cs_test_1"}),
    );
    let redelivery = harness.send_webhook(&event).await;
    assert_eq!(redelivery.status().as_u16(), 200);
    let body: Value = redelivery.json().await.unwrap();
    assert_eq!(body, json!({"received": true}));
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);

    // Once processed, the id deduplicates as before.
    let again: Value = harness.send_webhook(&event).await.json().await.unwrap();
    assert_eq!(again, json!({"received": true, "duplicate": true}));
}

#[tokio::test]
async fn paypal_refund_after_confirm_is_reconciled_without_a_webhook() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    let confirmed_at = confirm_paypal_purchase(&harness).await;
    assert_eq!(harness.status(BUNDLE).await["status"], "confirmed");

    harness
        .paypal_mock
        .set_capture_status("pporder_1", "PARTIALLY_REFUNDED");
    harness.tick(confirmed_at + WATCH.recheck_interval).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);
    assert!(harness.memory.meta(CREATOR, BUNDLE).reversed_after_confirm);
    assert_eq!(harness.status(BUNDLE).await["status"], "undetected");
}

#[tokio::test]
async fn paypal_dispute_is_found_by_the_pull_before_confirmation() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.paypal_mock.complete("pporder_1");
    let paid_at = OffsetDateTime::now_utc();
    harness.tick(paid_at).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Paid);

    // An open dispute leaves the capture COMPLETED; no webhook arrives.
    harness.paypal_mock.set_dispute("PP-D-9", "ppcap_pporder_1");
    harness.tick(paid_at + harness.settlement_delay).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Reversed);
}

#[tokio::test]
async fn paypal_dispute_lookup_outage_holds_confirmation() {
    let harness = harness_paypal_only(Duration::from_secs(300)).await;
    assert_eq!(harness.invoice("usd", BUNDLE).await.status().as_u16(), 204);
    harness.paypal_mock.complete("pporder_1");
    let paid_at = OffsetDateTime::now_utc();
    harness.tick(paid_at).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Paid);

    *harness.paypal_mock.disputes_unavailable.lock().unwrap() = true;
    harness.tick(paid_at + harness.settlement_delay).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Paid);

    *harness.paypal_mock.disputes_unavailable.lock().unwrap() = false;
    harness.tick(paid_at + harness.settlement_delay).await;
    assert_eq!(harness.state(BUNDLE).await, CorrelationState::Confirmed);
}
