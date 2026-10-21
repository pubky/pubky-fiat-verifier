//! Environment-driven configuration, following the Railway service precedent
//! (pubky-payment-rails entrypoints, marketplace-service): everything comes
//! from env vars, secrets never touch disk, live mode is fail-closed.

use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use pubky::PublicKey;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("{0} is invalid: {1}")]
    Invalid(&'static str, String),
    #[error(
        "STRIPE_SECRET_KEY looks like a LIVE key; refusing to start without FIAT_LIVE_MODE=true \
         (staging is test-mode only by design)"
    )]
    LiveKeyWithoutLiveMode,
    #[error(
        "PAYPAL_API_BASE is not the PayPal sandbox; refusing to start without \
         FIAT_LIVE_MODE=true (staging is sandbox-only by design)"
    )]
    LivePaypalWithoutLiveMode,
}

#[derive(Clone, Debug)]
pub struct StripeConfig {
    pub secret_key: String,
    /// Webhook signing secret (`whsec_...`). Optional: without it the webhook
    /// endpoint fails closed and payment observation relies on the API poll.
    pub webhook_secret: Option<String>,
    pub api_base: Url,
}

#[derive(Clone, Debug)]
pub struct PaypalConfig {
    pub client_id: String,
    pub client_secret: String,
    /// Webhook id from the PayPal developer dashboard (`WH-...`). Optional:
    /// without it the webhook endpoint fails closed and payment observation
    /// relies on the API poll.
    pub webhook_id: Option<String>,
    pub api_base: Url,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: String,
    /// The one Lock Server identity whose ed25519 signature authenticates the
    /// signed wire endpoints. Canonical pubky-prefixed public key.
    pub trusted_locks_public_key: VerifyingKey,
    /// The real Paykit Server: BTC criteria are proxied here verbatim.
    pub paykit_server_url: Url,
    pub database_url: String,
    /// None => Stripe disabled. With no processor configured at all, fiat
    /// invoices fail closed with 503.
    pub stripe: Option<StripeConfig>,
    /// None => PayPal disabled; the PayPal path fails closed with 503.
    pub paypal: Option<PaypalConfig>,
    /// Processor used when a checkout request names none and both are
    /// configured (`stripe` | `paypal`).
    pub default_processor: String,
    /// Fiat analogue of block confirmations: how long a paid checkout must
    /// rest before the verifier reports `confirmed` (design §3.4, §5.1).
    pub settlement_delay: Duration,
    /// Reported as `confirmations` once the settlement delay has elapsed, so
    /// the Lock Server's `confirmations >= minimum_confirmations` rule passes.
    /// Must be >= the Lock Server's configured minimum_confirmations.
    pub synthesized_confirmations: u32,
    /// Slow-poll interval for open fiat correlations (lost-webhook recovery).
    pub poll_interval: Duration,
    /// How long after confirmation the poll worker keeps re-checking for a
    /// refund or dispute. Defaults to 180 days, PayPal's dispute window
    /// (Stripe's card dispute window is up to 120 days).
    pub reversal_watch_window: Duration,
    /// Minimum time between two reversal checks of one confirmed payment.
    pub reversal_recheck_interval: Duration,
    /// Criterion assets accepted on the fiat path (uppercase ISO 4217).
    pub allowed_assets: Vec<String>,
    /// Legacy single-shop redirect targets, used for checkout requests that
    /// carry no `return_origin`.
    pub checkout_success_url: String,
    pub checkout_cancel_url: String,
    /// Exact `https://` origins (`BUYER_RETURN_ORIGINS`, comma-separated) a
    /// buyer checkout request may name as its return origin. Canonical
    /// `url::Url` origin serializations; matching is string equality. Empty
    /// disables per-request origins (single-shop fallback mode).
    pub buyer_return_origins: Vec<String>,
    /// Max content-lock document size fetched from a homeserver.
    pub lock_resource_max_bytes: u64,
    pub lock_fetch_timeout: Duration,
    /// Requests-per-second budget for the buyer-facing /checkout-sessions.
    pub checkout_rate_per_second: u64,
    pub checkout_rate_burst: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = match std::env::var("FIAT_LISTEN_ADDR") {
            Ok(addr) => addr,
            Err(_) => match std::env::var("PORT") {
                Ok(port) => format!("[::]:{port}"),
                Err(_) => "[::]:3002".to_owned(),
            },
        };

        let trusted = required("FIAT_TRUSTED_LOCKS_PUBLIC_KEY")?;
        let trusted_locks_public_key = parse_trusted_key(&trusted)?;

        let paykit_server_url = Url::parse(
            &std::env::var("FIAT_PAYKIT_SERVER_URL")
                .unwrap_or_else(|_| "http://paykit-server.railway.internal:3001".to_owned()),
        )
        .map_err(|error| ConfigError::Invalid("FIAT_PAYKIT_SERVER_URL", error.to_string()))?;
        if !matches!(paykit_server_url.scheme(), "http" | "https") {
            return Err(ConfigError::Invalid(
                "FIAT_PAYKIT_SERVER_URL",
                "must be http(s)".to_owned(),
            ));
        }

        let database_url = required("FIAT_DATABASE_URL")?;

        let stripe = match std::env::var("STRIPE_SECRET_KEY") {
            Ok(secret_key) if !secret_key.trim().is_empty() => {
                let secret_key = secret_key.trim().to_owned();
                let live_mode = std::env::var("FIAT_LIVE_MODE").is_ok_and(|v| v == "true");
                let looks_live =
                    secret_key.starts_with("sk_live") || secret_key.starts_with("rk_live");
                if looks_live && !live_mode {
                    return Err(ConfigError::LiveKeyWithoutLiveMode);
                }
                let api_base = Url::parse(
                    &std::env::var("STRIPE_API_BASE")
                        .unwrap_or_else(|_| "https://api.stripe.com".to_owned()),
                )
                .map_err(|error| ConfigError::Invalid("STRIPE_API_BASE", error.to_string()))?;
                let webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET")
                    .ok()
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty());
                Some(StripeConfig {
                    secret_key,
                    webhook_secret,
                    api_base,
                })
            }
            _ => None,
        };

        let optional = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let paypal = match (
            optional("PAYPAL_CLIENT_ID"),
            optional("PAYPAL_CLIENT_SECRET"),
        ) {
            (Some(client_id), Some(client_secret)) => {
                let live_mode = std::env::var("FIAT_LIVE_MODE").is_ok_and(|v| v == "true");
                let api_base = Url::parse(
                    &std::env::var("PAYPAL_API_BASE")
                        .unwrap_or_else(|_| "https://api-m.sandbox.paypal.com".to_owned()),
                )
                .map_err(|error| ConfigError::Invalid("PAYPAL_API_BASE", error.to_string()))?;
                let looks_sandbox = api_base
                    .host_str()
                    .is_some_and(|host| host.contains("sandbox"));
                if !looks_sandbox && !live_mode {
                    return Err(ConfigError::LivePaypalWithoutLiveMode);
                }
                let webhook_id = std::env::var("PAYPAL_WEBHOOK_ID")
                    .ok()
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty());
                Some(PaypalConfig {
                    client_id,
                    client_secret,
                    webhook_id,
                    api_base,
                })
            }
            (None, None) => None,
            _ => {
                return Err(ConfigError::Invalid(
                    "PAYPAL_CLIENT_ID",
                    "PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET must be set together".to_owned(),
                ))
            }
        };

        let default_processor = std::env::var("FIAT_DEFAULT_PROCESSOR")
            .unwrap_or_else(|_| "stripe".to_owned())
            .trim()
            .to_ascii_lowercase();
        if default_processor != "stripe" && default_processor != "paypal" {
            return Err(ConfigError::Invalid(
                "FIAT_DEFAULT_PROCESSOR",
                "must be 'stripe' or 'paypal'".to_owned(),
            ));
        }

        let settlement_delay =
            Duration::from_secs(parse_u64("FIAT_SETTLEMENT_DELAY_SECONDS", 300)?);
        let synthesized_confirmations =
            u32::try_from(parse_u64("FIAT_SYNTHESIZED_CONFIRMATIONS", 1)?).map_err(|_| {
                ConfigError::Invalid("FIAT_SYNTHESIZED_CONFIRMATIONS", "too large".into())
            })?;
        let poll_interval = Duration::from_secs(parse_u64("FIAT_POLL_INTERVAL_SECONDS", 60)?);
        let reversal_watch_days = parse_u64("FIAT_REVERSAL_WATCH_DAYS", 180)?;
        if reversal_watch_days == 0 || reversal_watch_days > 3650 {
            return Err(ConfigError::Invalid(
                "FIAT_REVERSAL_WATCH_DAYS",
                "must be between 1 and 3650".to_owned(),
            ));
        }
        let reversal_recheck_seconds = parse_u64("FIAT_REVERSAL_RECHECK_SECONDS", 3600)?;
        if reversal_recheck_seconds == 0 {
            return Err(ConfigError::Invalid(
                "FIAT_REVERSAL_RECHECK_SECONDS",
                "must be positive".to_owned(),
            ));
        }

        let allowed_assets = std::env::var("FIAT_ALLOWED_ASSETS")
            .unwrap_or_else(|_| "USD".to_owned())
            .split(',')
            .map(|asset| asset.trim().to_owned())
            .filter(|asset| !asset.is_empty())
            .collect::<Vec<_>>();
        if allowed_assets.iter().any(|asset| {
            asset.len() != 3 || !asset.bytes().all(|b| b.is_ascii_uppercase()) || asset == "BTC"
        }) {
            return Err(ConfigError::Invalid(
                "FIAT_ALLOWED_ASSETS",
                "must be comma-separated uppercase 3-letter fiat codes (never BTC)".to_owned(),
            ));
        }

        let checkout_success_url = std::env::var("FIAT_CHECKOUT_SUCCESS_URL")
            .unwrap_or_else(|_| "https://staging.pubky.app/marketplace?checkout=return".to_owned());
        let checkout_cancel_url = std::env::var("FIAT_CHECKOUT_CANCEL_URL")
            .unwrap_or_else(|_| "https://staging.pubky.app/marketplace?checkout=cancel".to_owned());

        let buyer_return_origins =
            parse_origin_list(&std::env::var("BUYER_RETURN_ORIGINS").unwrap_or_default())?;

        Ok(Self {
            bind_addr,
            trusted_locks_public_key,
            paykit_server_url,
            database_url,
            stripe,
            paypal,
            default_processor,
            settlement_delay,
            synthesized_confirmations,
            poll_interval,
            reversal_watch_window: Duration::from_secs(reversal_watch_days * 86_400),
            reversal_recheck_interval: Duration::from_secs(reversal_recheck_seconds),
            allowed_assets,
            checkout_success_url,
            checkout_cancel_url,
            buyer_return_origins,
            lock_resource_max_bytes: parse_u64("FIAT_LOCK_RESOURCE_MAX_BYTES", 10_000_000)?,
            lock_fetch_timeout: Duration::from_secs(parse_u64(
                "FIAT_LOCK_FETCH_TIMEOUT_SECONDS",
                10,
            )?),
            checkout_rate_per_second: parse_u64("FIAT_CHECKOUT_RATE_PER_SECOND", 5)?,
            checkout_rate_burst: parse_u64("FIAT_CHECKOUT_RATE_BURST", 20)?,
        })
    }
}

/// Parses a canonical pubky-prefixed public key (mirrors paykit-server's
/// `TrustedLocksPublicKey::parse`: canonical round-trip + valid curve point).
pub fn parse_trusted_key(value: &str) -> Result<VerifyingKey, ConfigError> {
    let public_key = PublicKey::try_from(value).map_err(|error| {
        ConfigError::Invalid("FIAT_TRUSTED_LOCKS_PUBLIC_KEY", error.to_string())
    })?;
    if public_key.to_string() != value {
        return Err(ConfigError::Invalid(
            "FIAT_TRUSTED_LOCKS_PUBLIC_KEY",
            "must be the canonical pubky-prefixed spelling".to_owned(),
        ));
    }
    VerifyingKey::from_bytes(&public_key.to_bytes())
        .map_err(|error| ConfigError::Invalid("FIAT_TRUSTED_LOCKS_PUBLIC_KEY", error.to_string()))
}

/// Parses one exact buyer return origin: `https://host[:port]` and nothing
/// else — no path, query, fragment, or userinfo, no trailing slash, no
/// default-port or case spelling that the parse would normalize away (the
/// same strictness as the Lock Server's origin allowlists). Returns the
/// canonical `url::Url` origin serialization, which doubles as the allowlist
/// comparison key: matching is string equality after parse-and-reserialize.
pub fn parse_return_origin(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    (origin == value).then_some(origin)
}

/// Parses the `BUYER_RETURN_ORIGINS` comma-separated allowlist; any invalid
/// entry fails startup.
fn parse_origin_list(value: &str) -> Result<Vec<String>, ConfigError> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            parse_return_origin(entry).ok_or_else(|| {
                ConfigError::Invalid(
                    "BUYER_RETURN_ORIGINS",
                    format!("'{entry}' is not an exact https:// origin (scheme+host[+port] only)"),
                )
            })
        })
        .collect()
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn parse_u64(name: &'static str, default: u64) -> Result<u64, ConfigError> {
    match std::env::var(name) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|error| ConfigError::Invalid(name, error.to_string())),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_list_accepts_exact_https_origins() {
        let origins = parse_origin_list(
            "https://shop.pubky.app, https://pubky-marketplace-staging.vercel.app , https://shop.example.com:8443",
        )
        .unwrap();
        assert_eq!(
            origins,
            vec![
                "https://shop.pubky.app",
                "https://pubky-marketplace-staging.vercel.app",
                "https://shop.example.com:8443",
            ]
        );
        // Empty list (unset var) is allowed: single-shop fallback mode.
        assert_eq!(parse_origin_list("").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn origin_list_rejects_invalid_entries() {
        for entry in [
            "http://shop.pubky.app",              // not https
            "https://shop.pubky.app/",            // trailing slash
            "https://shop.pubky.app/marketplace", // path
            "https://shop.pubky.app?x=1",         // query
            "https://shop.pubky.app#frag",        // fragment
            "https://user@shop.pubky.app",        // userinfo
            "https://shop.pubky.app:443",         // normalized default port
            "HTTPS://shop.pubky.app",             // normalized scheme case
            "shop.pubky.app",                     // no scheme
            "not a url",
        ] {
            assert!(
                parse_origin_list(entry).is_err(),
                "entry should be rejected: {entry}"
            );
        }
    }

    #[test]
    fn parse_return_origin_is_the_canonical_comparison_key() {
        assert_eq!(
            parse_return_origin("https://shop.pubky.app").as_deref(),
            Some("https://shop.pubky.app")
        );
        // A lookalike parses as a valid origin of its own; allowlist
        // membership (string equality) is what rejects it.
        assert_eq!(
            parse_return_origin("https://shop.pubky.app.evil.com").as_deref(),
            Some("https://shop.pubky.app.evil.com")
        );
    }
}
