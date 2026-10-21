//! PayPal processor plugin (sandbox). Mirrors the Stripe plugin's three
//! responsibilities (design §3.3):
//!
//! 1. `create_order` — Orders v2 `intent=CAPTURE` with the verification
//!    task's reference as `custom_id` and a `PayPal-Request-Id` derived from
//!    the same idempotency key Stripe uses, so replays mint no duplicates.
//!    `processing_instruction=ORDER_COMPLETE_ON_PAYMENT_APPROVAL` asks PayPal
//!    to capture on approval; the pull additionally captures explicitly if it
//!    ever observes a still-`APPROVED` order (belt and braces).
//! 2. `retrieve_*` — the API pull. Pulled state is the ONLY thing that
//!    advances a correlation; webhooks merely schedule pulls.
//! 3. `verify_webhook` — PayPal's postback verification API
//!    (`POST /v1/notifications/verify-webhook-signature`) over the exact raw
//!    body. Unlike Stripe there is no local HMAC: PayPal itself attests the
//!    transmission, which requires `PAYPAL_WEBHOOK_ID` to be configured.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use time::OffsetDateTime;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum PaypalError {
    #[error("paypal request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("paypal returned status {status}: {body}")]
    Api { status: u16, body: String },
    #[error("paypal response was not the expected shape: {0}")]
    Shape(String),
    #[error("webhook body is not valid JSON")]
    InvalidWebhookBody,
}

#[derive(Clone, Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Link {
    pub rel: String,
    pub href: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Amount {
    pub currency_code: String,
    pub value: String,
}

/// A capture inside `purchase_units[].payments.captures[]`, or the standalone
/// object from `GET /v2/payments/captures/:id`.
#[derive(Clone, Debug, Deserialize)]
pub struct Capture {
    pub id: String,
    pub status: Option<String>,
    pub amount: Option<Amount>,
    pub custom_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Payments {
    #[serde(default)]
    pub captures: Vec<Capture>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PurchaseUnit {
    pub payments: Option<Payments>,
}

/// The Orders v2 fields the verifier consumes
/// (<https://developer.paypal.com/docs/api/orders/v2/>).
#[derive(Clone, Debug, Deserialize)]
pub struct Order {
    pub id: String,
    /// `CREATED` | `SAVED` | `APPROVED` | `VOIDED` | `COMPLETED` |
    /// `PAYER_ACTION_REQUIRED`. `COMPLETED` alone is not payment — the
    /// capture object's own status must also be `COMPLETED`.
    pub status: Option<String>,
    #[serde(default)]
    pub links: Vec<Link>,
    #[serde(default)]
    pub purchase_units: Vec<PurchaseUnit>,
}

impl Order {
    /// The buyer's hosted approval URL: `payer-action` (payment_source
    /// integrations) with `approve` as the legacy fallback.
    pub fn approval_url(&self) -> Option<&str> {
        self.links
            .iter()
            .find(|link| link.rel == "payer-action")
            .or_else(|| self.links.iter().find(|link| link.rel == "approve"))
            .map(|link| link.href.as_str())
    }

    /// The first capture whose own status is `COMPLETED`.
    pub fn completed_capture(&self) -> Option<&Capture> {
        self.purchase_units
            .iter()
            .filter_map(|unit| unit.payments.as_ref())
            .flat_map(|payments| payments.captures.iter())
            .find(|capture| capture.status.as_deref() == Some("COMPLETED"))
    }

    /// The first capture PayPal reports as refunded (fully or partially) or
    /// reversed. A refund moves the capture out of `COMPLETED`, so without
    /// this check a refunded order would simply read as "not paid".
    pub fn reversed_capture(&self) -> Option<&Capture> {
        self.purchase_units
            .iter()
            .filter_map(|unit| unit.payments.as_ref())
            .flat_map(|payments| payments.captures.iter())
            .find(|capture| is_reversed_capture_status(capture.status.as_deref()))
    }
}

/// Capture statuses that mean the money went back to the buyer.
pub fn is_reversed_capture_status(status: Option<&str>) -> bool {
    matches!(status, Some("REFUNDED" | "PARTIALLY_REFUNDED" | "REVERSED"))
}

/// `GET /v1/customer/disputes?disputed_transaction_id=...` — summary items;
/// only their existence matters.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct DisputeList {
    #[serde(default)]
    pub items: Vec<DisputeSummary>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DisputeSummary {
    pub dispute_id: String,
}

/// `GET /v1/customer/disputes/:id` — only the transaction linkage is needed.
#[derive(Clone, Debug, Deserialize)]
pub struct Dispute {
    #[serde(default)]
    pub disputed_transactions: Vec<DisputedTransaction>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DisputedTransaction {
    /// The seller-side transaction id, i.e. the capture id.
    pub seller_transaction_id: Option<String>,
}

/// The five headers PayPal sends with every webhook delivery.
pub struct WebhookHeaders<'a> {
    pub transmission_id: &'a str,
    pub transmission_time: &'a str,
    pub transmission_sig: &'a str,
    pub cert_url: &'a str,
    pub auth_algo: &'a str,
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    auth_algo: &'a str,
    cert_url: &'a str,
    transmission_id: &'a str,
    transmission_sig: &'a str,
    transmission_time: &'a str,
    webhook_id: &'a str,
    webhook_event: &'a RawValue,
}

#[derive(Deserialize)]
struct VerifyResponse {
    verification_status: String,
}

pub struct PaypalProcessor {
    http: reqwest::Client,
    api_base: Url,
    client_id: String,
    client_secret: String,
    /// Webhook id from the PayPal developer dashboard. Optional: without it
    /// the webhook endpoint fails closed and payment observation relies on
    /// the API poll — exactly like Stripe without its webhook secret.
    pub webhook_id: Option<String>,
    token: tokio::sync::Mutex<Option<(String, i64)>>,
}

/// Access tokens are refreshed this many seconds before their expiry.
const TOKEN_REFRESH_SLACK_SECONDS: i64 = 60;

impl PaypalProcessor {
    pub fn new(
        api_base: Url,
        client_id: String,
        client_secret: String,
        webhook_id: Option<String>,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(20))
                .build()
                .expect("static reqwest client configuration"),
            api_base,
            client_id,
            client_secret,
            webhook_id,
            token: tokio::sync::Mutex::new(None),
        }
    }

    fn endpoint(&self, path: &str) -> Url {
        let mut url = self.api_base.clone();
        url.set_path(path);
        url
    }

    /// Client-credentials OAuth2 token, cached until shortly before expiry.
    async fn access_token(&self) -> Result<String, PaypalError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut cache = self.token.lock().await;
        if let Some((token, expires_at)) = cache.as_ref() {
            if *expires_at > now + TOKEN_REFRESH_SLACK_SECONDS {
                return Ok(token.clone());
            }
        }
        let response = self
            .http
            .post(self.endpoint("/v1/oauth2/token"))
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("grant_type", "client_credentials")])
            .send()
            .await?;
        let token: TokenResponse = Self::parse(response).await?;
        *cache = Some((token.access_token.clone(), now + token.expires_in));
        Ok(token.access_token)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_order(
        &self,
        reference: &str,
        request_id: &str,
        amount_minor: i64,
        asset: &str,
        description: &str,
        return_url: &str,
        cancel_url: &str,
    ) -> Result<Order, PaypalError> {
        let token = self.access_token().await?;
        let body = serde_json::json!({
            "intent": "CAPTURE",
            "processing_instruction": "ORDER_COMPLETE_ON_PAYMENT_APPROVAL",
            "purchase_units": [{
                "custom_id": reference,
                "description": description,
                "amount": {
                    "currency_code": asset,
                    "value": minor_to_decimal(asset, amount_minor),
                },
            }],
            "payment_source": {
                "paypal": {
                    "experience_context": {
                        "return_url": return_url,
                        "cancel_url": cancel_url,
                        "user_action": "PAY_NOW",
                        "shipping_preference": "NO_SHIPPING",
                    },
                },
            },
        });
        let response = self
            .http
            .post(self.endpoint("/v2/checkout/orders"))
            .bearer_auth(token)
            .header("PayPal-Request-Id", request_id)
            .header("Prefer", "return=representation")
            .json(&body)
            .send()
            .await?;
        Self::parse(response).await
    }

    pub async fn retrieve_order(&self, order_id: &str) -> Result<Order, PaypalError> {
        let token = self.access_token().await?;
        let response = self
            .http
            .get(self.endpoint(&format!("/v2/checkout/orders/{order_id}")))
            .bearer_auth(token)
            .send()
            .await?;
        Self::parse(response).await
    }

    /// Explicit capture of an approved order. Normally redundant (the order
    /// carries `ORDER_COMPLETE_ON_PAYMENT_APPROVAL`), kept as the fallback
    /// when a pull observes an order stuck in `APPROVED`.
    pub async fn capture_order(
        &self,
        order_id: &str,
        request_id: &str,
    ) -> Result<Order, PaypalError> {
        let token = self.access_token().await?;
        let response = self
            .http
            .post(self.endpoint(&format!("/v2/checkout/orders/{order_id}/capture")))
            .bearer_auth(token)
            .header("PayPal-Request-Id", request_id)
            .header("Prefer", "return=representation")
            .json(&serde_json::json!({}))
            .send()
            .await?;
        Self::parse(response).await
    }

    pub async fn retrieve_capture(&self, capture_id: &str) -> Result<Capture, PaypalError> {
        let token = self.access_token().await?;
        let response = self
            .http
            .get(self.endpoint(&format!("/v2/payments/captures/{capture_id}")))
            .bearer_auth(token)
            .send()
            .await?;
        Self::parse(response).await
    }

    pub async fn retrieve_dispute(&self, dispute_id: &str) -> Result<Dispute, PaypalError> {
        let token = self.access_token().await?;
        let response = self
            .http
            .get(self.endpoint(&format!("/v1/customer/disputes/{dispute_id}")))
            .bearer_auth(token)
            .send()
            .await?;
        Self::parse(response).await
    }

    /// Disputes PayPal holds against one capture, in any state.
    pub async fn disputes_for_capture(&self, capture_id: &str) -> Result<DisputeList, PaypalError> {
        let token = self.access_token().await?;
        let response = self
            .http
            .get(self.endpoint("/v1/customer/disputes"))
            .query(&[("disputed_transaction_id", capture_id)])
            .bearer_auth(token)
            .send()
            .await?;
        Self::parse(response).await
    }

    /// Verifies a webhook delivery via PayPal's postback API. The exact raw
    /// body is forwarded byte-for-byte (`RawValue`), because the signature
    /// covers the transmitted bytes, not a re-serialization.
    pub async fn verify_webhook(
        &self,
        webhook_id: &str,
        headers: &WebhookHeaders<'_>,
        raw_body: &[u8],
    ) -> Result<bool, PaypalError> {
        let raw_event = std::str::from_utf8(raw_body)
            .ok()
            .and_then(|body| RawValue::from_string(body.to_owned()).ok())
            .ok_or(PaypalError::InvalidWebhookBody)?;
        let token = self.access_token().await?;
        let response = self
            .http
            .post(self.endpoint("/v1/notifications/verify-webhook-signature"))
            .bearer_auth(token)
            .json(&VerifyRequest {
                auth_algo: headers.auth_algo,
                cert_url: headers.cert_url,
                transmission_id: headers.transmission_id,
                transmission_sig: headers.transmission_sig,
                transmission_time: headers.transmission_time,
                webhook_id,
                webhook_event: &raw_event,
            })
            .send()
            .await?;
        let verdict: VerifyResponse = Self::parse(response).await?;
        Ok(verdict.verification_status == "SUCCESS")
    }

    async fn parse<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, PaypalError> {
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(PaypalError::Api {
                status: status.as_u16(),
                body: body.chars().take(2000).collect(),
            });
        }
        serde_json::from_str(&body).map_err(|error| PaypalError::Shape(error.to_string()))
    }
}

/// ISO 4217 currencies without a minor unit (the Stripe zero-decimal list);
/// everything else is treated as exponent-2, which covers every currency in
/// `FIAT_ALLOWED_ASSETS`' expected range.
const ZERO_DECIMAL_ASSETS: &[&str] = &[
    "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG", "RWF", "UGX", "VND", "VUV",
    "XAF", "XOF", "XPF",
];

/// Criterion minor units → PayPal decimal string (`1999` USD → `"19.99"`).
pub fn minor_to_decimal(asset: &str, minor: i64) -> String {
    if ZERO_DECIMAL_ASSETS.contains(&asset) {
        minor.to_string()
    } else {
        format!("{}.{:02}", minor / 100, minor % 100)
    }
}

/// PayPal decimal string → minor units, strict: rejects malformed values and
/// fractional amounts of zero-decimal currencies rather than rounding.
pub fn decimal_to_minor(asset: &str, value: &str) -> Option<i64> {
    let (whole, frac) = match value.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (value, ""),
    };
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: i64 = whole.parse().ok()?;
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if ZERO_DECIMAL_ASSETS.contains(&asset) {
        if frac.bytes().any(|b| b != b'0') {
            return None;
        }
        return Some(whole);
    }
    if frac.len() > 2 {
        return None;
    }
    let frac_value: i64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<2}").parse().ok()?
    };
    whole.checked_mul(100)?.checked_add(frac_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_minor_units_to_paypal_decimal() {
        assert_eq!(minor_to_decimal("USD", 1999), "19.99");
        assert_eq!(minor_to_decimal("USD", 100), "1.00");
        assert_eq!(minor_to_decimal("USD", 5), "0.05");
        assert_eq!(minor_to_decimal("JPY", 500), "500");
    }

    #[test]
    fn converts_paypal_decimal_to_minor_units() {
        assert_eq!(decimal_to_minor("USD", "19.99"), Some(1999));
        assert_eq!(decimal_to_minor("USD", "19.9"), Some(1990));
        assert_eq!(decimal_to_minor("USD", "19"), Some(1900));
        assert_eq!(decimal_to_minor("USD", "0.05"), Some(5));
        assert_eq!(decimal_to_minor("JPY", "500"), Some(500));
        assert_eq!(decimal_to_minor("JPY", "500.00"), Some(500));
    }

    #[test]
    fn rejects_malformed_decimal_amounts() {
        assert_eq!(decimal_to_minor("USD", ""), None);
        assert_eq!(decimal_to_minor("USD", "19.999"), None);
        assert_eq!(decimal_to_minor("USD", "-1.00"), None);
        assert_eq!(decimal_to_minor("USD", "1,00"), None);
        assert_eq!(decimal_to_minor("USD", ".99"), None);
        assert_eq!(decimal_to_minor("JPY", "500.50"), None);
    }

    #[test]
    fn round_trip_matches_the_criterion() {
        for minor in [1, 99, 100, 1999, 123_456_789] {
            assert_eq!(
                decimal_to_minor("USD", &minor_to_decimal("USD", minor)),
                Some(minor)
            );
        }
    }

    #[test]
    fn approval_url_prefers_payer_action() {
        let order: Order = serde_json::from_value(serde_json::json!({
            "id": "ORD1",
            "status": "CREATED",
            "links": [
                {"rel": "self", "href": "https://api.sandbox.paypal.com/v2/checkout/orders/ORD1"},
                {"rel": "approve", "href": "https://sandbox.paypal.com/approve"},
                {"rel": "payer-action", "href": "https://sandbox.paypal.com/payer-action"}
            ]
        }))
        .unwrap();
        assert_eq!(
            order.approval_url(),
            Some("https://sandbox.paypal.com/payer-action")
        );
    }

    #[test]
    fn completed_capture_requires_capture_level_completed() {
        let order: Order = serde_json::from_value(serde_json::json!({
            "id": "ORD1",
            "status": "COMPLETED",
            "purchase_units": [{
                "custom_id": "creator_bundle",
                "payments": {"captures": [
                    {"id": "CAP1", "status": "PENDING"},
                    {"id": "CAP2", "status": "COMPLETED",
                     "amount": {"currency_code": "USD", "value": "19.99"}}
                ]}
            }]
        }))
        .unwrap();
        assert_eq!(order.completed_capture().unwrap().id, "CAP2");
    }

    #[test]
    fn refunded_capture_is_a_reversal_not_a_payment() {
        for status in ["REFUNDED", "PARTIALLY_REFUNDED", "REVERSED"] {
            let order: Order = serde_json::from_value(serde_json::json!({
                "id": "ORD1",
                "status": "COMPLETED",
                "purchase_units": [{
                    "payments": {"captures": [
                        {"id": "CAP1", "status": status,
                         "amount": {"currency_code": "USD", "value": "19.99"}}
                    ]}
                }]
            }))
            .unwrap();
            assert!(order.completed_capture().is_none(), "{status}");
            assert_eq!(order.reversed_capture().unwrap().id, "CAP1", "{status}");
        }
    }

    #[test]
    fn pending_or_completed_capture_is_not_a_reversal() {
        for status in ["COMPLETED", "PENDING", "DECLINED", "FAILED"] {
            assert!(!is_reversed_capture_status(Some(status)), "{status}");
        }
        assert!(!is_reversed_capture_status(None));
    }
}
