mod auth;
mod config;
mod error;
mod http;
#[cfg(test)]
mod http_tests;
mod lock_fetch;
mod paypal;
mod proxy;
mod rate_limit;
mod state;
mod store;
mod stripe;
mod verification;
mod wire;
mod worker;

use std::sync::Arc;

use crate::config::Config;
use crate::http::{AppState, CheckoutDbGate, RefusalLog, StatusPullCache};
use crate::lock_fetch::PubkyCriterionSource;
use crate::paypal::PaypalProcessor;
use crate::proxy::PaykitProxy;
use crate::rate_limit::TokenBucket;
use crate::store::{CheckoutPool, CorrelationStore, PostgresStore};
use crate::stripe::StripeProcessor;
use crate::verification::{ProcessorKind, Processors};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration error: {error}");
            std::process::exit(1);
        }
    };

    let checkout_pool = CheckoutPool {
        connections: u32::try_from(config.checkout_lookup_concurrency)
            .expect("validated below STORE_POOL_SIZE by Config::from_env"),
        acquire_timeout: config.checkout_lookup_wait,
    };
    let (store, checkout_store): (Arc<dyn CorrelationStore>, Arc<dyn CorrelationStore>) =
        match PostgresStore::connect(&config.database_url, checkout_pool).await {
            Ok(stores) => (Arc::new(stores.main), Arc::new(stores.checkout)),
            Err(error) => {
                eprintln!("database error: {error}");
                std::process::exit(1);
            }
        };

    let stripe = config.stripe.as_ref().map(|stripe_config| {
        Arc::new(StripeProcessor::new(
            stripe_config.api_base.clone(),
            stripe_config.secret_key.clone(),
            stripe_config.webhook_secret.clone(),
        ))
    });
    let paypal = config.paypal.as_ref().map(|paypal_config| {
        Arc::new(PaypalProcessor::new(
            paypal_config.api_base.clone(),
            paypal_config.client_id.clone(),
            paypal_config.client_secret.clone(),
            paypal_config.webhook_id.clone(),
        ))
    });
    let processors = Arc::new(Processors {
        stripe: stripe.clone(),
        paypal: paypal.clone(),
    });
    let default_processor = processors.sole_configured().unwrap_or_else(|| {
        ProcessorKind::parse(&config.default_processor).expect("validated by Config::from_env")
    });

    if processors.any_configured() {
        tokio::spawn(worker::run(
            store.clone(),
            processors.clone(),
            config.poll_interval,
            config.settlement_delay,
            worker::ReversalWatch {
                window: config.reversal_watch_window,
                recheck_interval: config.reversal_recheck_interval,
            },
        ));
    }

    let state = Arc::new(AppState {
        trusted_key: config.trusted_locks_public_key,
        store,
        checkout_store,
        processors: processors.clone(),
        default_processor,
        criterion_source: Arc::new(
            match PubkyCriterionSource::new(
                config.lock_resource_max_bytes,
                config.lock_fetch_timeout,
            ) {
                Ok(source) => source,
                Err(error) => {
                    eprintln!("pubky client error: {error}");
                    std::process::exit(1);
                }
            },
        ),
        proxy: Arc::new(PaykitProxy::new(config.paykit_server_url.clone())),
        settlement_delay: config.settlement_delay,
        synthesized_confirmations: config.synthesized_confirmations,
        allowed_assets: config.allowed_assets.clone(),
        checkout_success_url: config.checkout_success_url.clone(),
        checkout_cancel_url: config.checkout_cancel_url.clone(),
        buyer_return_origins: config.buyer_return_origins.clone(),
        checkout_db_gate: CheckoutDbGate::new(
            config.checkout_lookup_concurrency,
            config.checkout_lookup_wait,
        ),
        checkout_limiter: TokenBucket::new(
            config.checkout_rate_per_second,
            config.checkout_rate_burst,
        ),
        status_pull_cache: StatusPullCache::default(),
        status_pull_freshness: config.status_pull_freshness,
        status_pull_limiter: TokenBucket::new(
            config.status_pull_rate_per_second,
            config.status_pull_rate_burst,
        ),
        settlement_pull_limiter: TokenBucket::new(
            config.settlement_pull_rate_per_second,
            config.settlement_pull_rate_burst,
        ),
        pull_budget_refusals: RefusalLog::default(),
    });

    tracing::info!(
        bind_addr = %config.bind_addr,
        paykit_server_url = %config.paykit_server_url,
        stripe_enabled = stripe.is_some(),
        paypal_enabled = paypal.is_some(),
        default_processor = default_processor.as_str(),
        settlement_delay_seconds = config.settlement_delay.as_secs(),
        synthesized_confirmations = config.synthesized_confirmations,
        reversal_watch_days = config.reversal_watch_window.as_secs() / 86_400,
        reversal_recheck_seconds = config.reversal_recheck_interval.as_secs(),
        allowed_assets = ?config.allowed_assets,
        buyer_return_origins = config.buyer_return_origins.len(),
        "starting pubky-fiat-verifier"
    );

    let listener = match tokio::net::TcpListener::bind(&config.bind_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("failed to bind {}: {error}", config.bind_addr);
            std::process::exit(1);
        }
    };

    axum::serve(listener, http::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("http server run");
}
