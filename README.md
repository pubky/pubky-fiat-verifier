# pubky-fiat-verifier

A payment **verifier gateway** for the [Locks](https://github.com/pubky/locks) entitlement
layer. It speaks the exact signed wire contract the Lock Server already uses to talk to a
Paykit Server (`POST /invoices`, `POST /transactions/status`, ed25519 over canonical JSON
in `X-Paykit-Signature`), and dispatches on the content lock's payment criterion `asset`:

- **`BTC`** → the signed call is forwarded **verbatim** (original body + original
  signature) to the real Paykit Server. The gateway holds no signing key of its own on
  this path; the Paykit Server keeps trusting the Lock Server's pinned key, and the
  signature covers only the canonical body, so pass-through is contract-exact.
- **`USD`** (fiat) → a hosted checkout is created on a processor plugin, idempotently
  keyed to the verification task: a Stripe Checkout Session (**test mode**) or a
  PayPal Orders v2 order (**sandbox**). Both settle through the same correlation
  state machine.

This proves the design claim in the marketplace's `fiat-rails-design.md`: Locks is a
payment-agnostic entitlement layer, and a fiat rail plugs into the same verifier
contract, the same lifecycle, and the same marketplace verification loop with **zero
upstream changes** to Locks, Paykit Server, or marketplace-service.

## Topology

```
                                  ┌──────────────────────────┐
Lock Server ──[paykit].server_url─►      fiat-verifier       │
 (signed HTTP, ed25519 pinned)    │  dispatch on criterion   │
                                  │          asset           │
                                  │   BTC ──────────────────────► paykit-server (unchanged,
                                  │   (verbatim body + sig)  │     private networking)
                                  │                          │
                                  │   USD → Stripe processor ────► api.stripe.com (TEST mode)
                                  │     · Checkout Session   │
                                  │     · webhook = hint     ◄──── Stripe webhooks (public domain)
                                  │     · API pull = truth   │
                                  │     · settlement delay   │
                                  │   USD → PayPal processor ────► api-m.sandbox.paypal.com
                                  │     · Orders v2 order    │
                                  │     · webhook = hint     ◄──── PayPal webhooks (verified via
                                  │     · API pull = truth   │     PayPal's postback API)
                                  │     · same delay/machine │
                                  └──────────┬───────────────┘
                                             │
Buyer ── POST /checkout-sessions ────────────┘   (fetches the hosted checkout URL;
         {creator, bundle_id}                     bundle id is bearer material)
```

The Lock Server has exactly one payment backend URL, which is why this is a gateway and
not a second backend: one URL, all rails. Cutover is an operator env change
(`LOCKS_PAYKIT_SERVER_URL` on the Lock Server) — no code changes anywhere upstream.

## Wire surface

| Endpoint | Auth | Behavior |
| --- | --- | --- |
| `POST /invoices` | `X-Paykit-Signature` (pinned Lock Server key; canonical-JSON strict body) | Fetch the content lock from the creator's homeserver (public Pubky read), parse the `paykit-payment` criterion, dispatch by `asset`. BTC → proxy. Fiat → persist correlation, `204`; a hosted checkout is minted eagerly when exactly one processor is configured (see processor selection below). Exact replay → `204` (idempotent). Same identity, different binding → `409`. |
| `POST /transactions/status` | same | Unknown or BTC correlation → proxy (the real Paykit Server owns every BTC invoice, including all pre-cutover ones). Fiat → answered from local state, advanced **only** by verified API pulls. |
| `POST /checkout-sessions` | possession of `{creator, bundle_id}` (bearer material), rate-limited | Body `{creator, bundle_id, processor?, return_origin?}`. Returns `{checkout_url, processor, expires_at}`. Idempotent; re-mints on the **same** processor if the session expired. `404` unknown/BTC, `409` once paid, when `processor` names a different processor than the correlation is bound to, or when `return_origin` differs from the bound origin, `400` unknown processor value (`invalid_request`) or an origin off the allowlist (`invalid_return_origin`), `503` when the named processor is not configured. |
| `POST /webhooks/stripe` | `Stripe-Signature` (HMAC over raw body, ±300s tolerance, deduped by event id) | A **hint, never a fact**: schedules an API pull. `checkout.session.completed` / `async_payment_succeeded` → pull the session. `charge.refunded` (object = the charge) / `charge.dispute.created` (object = the dispute, whose `charge` is pulled) → pull the charge, and only a corroborating pull marks the correlation reversed, in any state including `confirmed`. A transient failure (processor or database unavailable) answers `503` and releases the event id, so Stripe's retry is processed instead of deduplicated. |
| `POST /webhooks/paypal` | PayPal transmission headers, verified via `POST /v1/notifications/verify-webhook-signature` over the exact raw body (requires `PAYPAL_WEBHOOK_ID`); deduped by event id | Same hint-only and transient-failure rules. `CHECKOUT.ORDER.APPROVED` / `CHECKOUT.ORDER.COMPLETED` / `PAYMENT.CAPTURE.COMPLETED` / `PENDING` → pull the order. `PAYMENT.CAPTURE.REFUNDED` / `REVERSED` / `DENIED` → pull the capture; `CUSTOMER.DISPUTE.CREATED` → pull the dispute (`GET /v1/customer/disputes/{id}`); only a corroborating pull marks the correlation reversed. |
| `GET /health` | none | DB + processor wiring status (`stripe_enabled`, `stripe_webhook_configured`, `paypal_enabled`, `paypal_webhook_configured`, `default_processor`). |

### Processor selection

- **One processor configured** (staging today: Stripe): `/invoices` mints the hosted
  checkout eagerly on that processor — the proven Stripe behavior, unchanged.
- **Both configured**: `/invoices` only persists the correlation; the mint waits for
  the buyer's `/checkout-sessions` call, whose optional `processor` field
  (`stripe` | `paypal`) picks the rail, defaulting to `FIAT_DEFAULT_PROCESSOR`
  (default `stripe`).
- **The binding is permanent.** Once a session/order is minted, the correlation's
  processor never changes — a later `/checkout-sessions` naming the other processor
  gets `409`. Reason, stated honestly: switching would leave a still-payable
  session on the abandoned processor whose payment this gateway would no longer
  observe; refusing the switch is the fail-closed option. Expired sessions re-mint
  on the same processor.

### The PayPal order lifecycle

Orders are created with `intent=CAPTURE`, the verification task's reference as
`custom_id`, a `PayPal-Request-Id` idempotency key, and
`processing_instruction=ORDER_COMPLETE_ON_PAYMENT_APPROVAL` (PayPal captures on
buyer approval). If a pull ever observes an order still `APPROVED` (auto-capture
not landed), the verifier captures explicitly — capture-on-approval either way.
Payment is only ever recognized from a pull showing order `COMPLETED` **and** a
capture whose own status is `COMPLETED` with the criterion's exact amount and
currency. The recorded session expiry is 3 hours (PayPal's default order
validity; the create response carries no expiry field).

### Fiat state mapping (settlement delay = fiat confirmations)

| Internal state | Reported to the Lock Server |
| --- | --- |
| created (no completed checkout) | `undetected, 0, false` |
| paid (API pull verified), inside settlement delay | `detected, 0, amount_matched` |
| paid, delay elapsed, fresh re-pull still paid and not refunded or disputed | `confirmed, FIAT_SYNTHESIZED_CONFIRMATIONS, true` |
| confirmed, fresh re-pull on every status read still clean | `confirmed, FIAT_SYNTHESIZED_CONFIRMATIONS, true` |
| confirmed, processor unreadable on that read | `detected, 0, true` (held, never served blind) |
| reversed — refunded (fully or partially) or disputed, pull-verified, before or after confirmation | `undetected, 0, false` |

**What "paid" means.** A Stripe Checkout Session keeps `payment_status: paid` after a
refund or a dispute, so every Stripe pull also reads the session's PaymentIntent with
`expand[]=latest_charge` and treats `refunded`, `amount_refunded > 0` or `disputed` as a
reversal. A paid session whose charge cannot be read holds its state. On PayPal, a
`REFUNDED` / `PARTIALLY_REFUNDED` / `REVERSED` capture is a reversal, and an open dispute
(found through `GET /v1/customer/disputes?disputed_transaction_id=<capture>`, since it
leaves the capture `COMPLETED`) is one too. Any dispute counts, whatever its outcome:
the rule is deliberately fail-closed.

**Reversal watch (missed webhooks).** Webhooks only speed reversal detection up. The poll
worker re-pulls every confirmed correlation every `FIAT_REVERSAL_RECHECK_SECONDS` for
`FIAT_REVERSAL_WATCH_DAYS` after confirmation, so a reversal whose webhook was lost,
rejected or never configured is still recorded. A pull the processor could not answer is
retried on the next poll tick.

**Reversal after confirmation.** The row moves to `reversed` with
`reversed_after_confirm = true` and the service logs an `ALERT fiat payment reversed
after confirmation` error line. From then on the status endpoint stops reporting
`confirmed`, so a Lock Server that has not completed the task yet never releases the good.
Locks has no un-complete transition, so an entitlement the Lock Server already completed
stays granted: that case goes to the marketplace dispute flow, and the alert is the
operator's signal.

There is no early-failure transition in the Locks contract: an abandoned checkout leaves
the task pending until the marketplace payment window and task expiry lapse, exactly as
an unpaid Bitcoin invoice does.

The buyer's payment instruction cannot ride the invoice response (the Lock Server
discards the response body), which is why `/checkout-sessions` exists: after proof-bundle
submission the client fetches the checkout URL with the same `{creator, bundle_id}` pair
it already holds and opens it. That client work is Phase 2; the data flows today.

## Trust model, stated bluntly

| Property | Bitcoin via Paykit (proxied) | Card via Stripe (this service) | PayPal (this service) |
| --- | --- | --- | --- |
| Who attests payment | Paykit Server operator reading its own Electrum view of the chain | fiat-verifier operator reading Stripe's API | fiat-verifier operator reading PayPal's API |
| Can the attestor lie? | Yes — but anyone can independently verify on-chain | Yes — and only Stripe + the seller's dashboard can contradict it | Yes — and only PayPal + the seller's dashboard can contradict it |
| Reversible after Locks `completed`? | No (N confirmations) | **Yes** — chargebacks up to ~120 days; lands in the marketplace dispute flow, not in Locks | **Yes** — disputes up to 180 days; same dispute flow |
| Who sees the buyer | Paykit operator sees reader pubky ↔ invoice | Stripe sees the buyer's card identity; this service sees pubky ↔ session linkage | PayPal sees the buyer's account identity; this service sees pubky ↔ order linkage |
| Settlement finality signal | Block confirmations (objective) | A settlement-delay timer this service imposes (policy, not physics) | Same |
| What Locks itself trusts | Identical in every case: the Lock Server operator and its configured backend URL |

The operator of this service can see who paid for what and could falsely report payment
status in either direction. Mitigation is operational (structured logs, the seller's own
processor dashboard as a cross-check), not cryptographic — the same trust class as the
Paykit Server operator, with larger identity exposure because Stripe/PayPal know the
buyer's legal identity. Privacy-conscious buyers should use the Bitcoin rail.

## Configuration

All configuration is environment variables. No secret ever lives in this repo.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `FIAT_TRUSTED_LOCKS_PUBLIC_KEY` | yes | — | The Lock Server's canonical pubky-prefixed public key (same value as the Paykit Server's `[locks] trusted_public_key`). |
| `FIAT_DATABASE_URL` | yes | — | Postgres URL (correlations + webhook dedupe). |
| `FIAT_PAYKIT_SERVER_URL` | no | `http://paykit-server.railway.internal:3001` | The real Paykit Server for BTC pass-through. |
| `FIAT_LISTEN_ADDR` / `PORT` | no | `[::]:3002` | Bind address (Railway injects `PORT`). |
| `STRIPE_SECRET_KEY` | no | — | **Test-mode** secret key (`sk_test_...`). Absent ⇒ the Stripe path fails closed with 503; BTC proxying is unaffected. |
| `STRIPE_WEBHOOK_SECRET` | no | — | Webhook signing secret (`whsec_...`). Absent ⇒ webhooks answer 503 and detection relies purely on API polling (the Lock Server's ~30s status poll and the slow poll both pull). |
| `PAYPAL_CLIENT_ID` / `PAYPAL_CLIENT_SECRET` | no | — | **Sandbox** REST app credentials, set together. Absent ⇒ the PayPal path fails closed with 503. |
| `PAYPAL_WEBHOOK_ID` | no | — | Webhook id (`WH-...`) from the PayPal developer dashboard, required by the verification postback. Absent ⇒ PayPal webhooks answer 503 and detection relies purely on API polling. |
| `PAYPAL_API_BASE` | no | `https://api-m.sandbox.paypal.com` | A non-sandbox host refuses to boot without `FIAT_LIVE_MODE=true`. |
| `FIAT_DEFAULT_PROCESSOR` | no | `stripe` | Processor used when a checkout request names none and both are configured. |
| `FIAT_LIVE_MODE` | no | unset | A live-looking Stripe key or a non-sandbox PayPal base refuses to boot unless this is exactly `true`. Staging = test keys only, forever. |
| `FIAT_SETTLEMENT_DELAY_SECONDS` | no | `300` | Anti-chargeback rest period between `detected` and `confirmed`. |
| `FIAT_SYNTHESIZED_CONFIRMATIONS` | no | `1` | Reported once confirmed; must be ≥ the Lock Server's `[paykit] minimum_confirmations`. |
| `FIAT_ALLOWED_ASSETS` | no | `USD` | Comma-separated uppercase fiat codes accepted on the fiat path (never BTC). |
| `BUYER_RETURN_ORIGINS` | no | empty | Comma-separated exact `https://` origins (scheme+host[+port] only — no path/query/fragment/userinfo; any invalid entry refuses to boot). Multi-shop mode: a `/checkout-sessions` request may name one as `return_origin`, and the success/cancel redirect URLs are then derived server-side as `{origin}/marketplace?checkout=return` and `{origin}/marketplace?checkout=cancel`. The origin is bound to the correlation at mint and never changes. |
| `FIAT_CHECKOUT_SUCCESS_URL` / `FIAT_CHECKOUT_CANCEL_URL` | no | staging app URLs | **Legacy single-shop mode**: static redirect targets used when a checkout request carries no `return_origin` (or the allowlist is empty). Redirects are buyer-attested and carry no state; the Locks lifecycle is the only truth. |
| `FIAT_POLL_INTERVAL_SECONDS` | no | `60` | Slow-poll interval over open fiat correlations (lost-webhook recovery). |
| `FIAT_REVERSAL_WATCH_DAYS` | no | `180` | How long after confirmation the poll worker keeps re-checking for a refund or dispute (1–3650). The default covers PayPal's 180-day dispute window; Stripe card disputes arrive within 120 days. |
| `FIAT_REVERSAL_RECHECK_SECONDS` | no | `3600` | Minimum time between two reversal checks of one confirmed payment. Each Stripe check costs two API reads (session and PaymentIntent), each PayPal check two (order and disputes). |
| `FIAT_CHECKOUT_RATE_PER_SECOND` / `FIAT_CHECKOUT_RATE_BURST` | no | `5` / `20` | Token bucket for `/checkout-sessions`. |
| `STRIPE_API_BASE` | no | `https://api.stripe.com` | Overridable for tests only. |

## Runbook

### Deploy (Railway, project `pubky-marketplace-staging`)

```bash
railway add --service fiat-verifier            # once
railway add --database postgres                # once (deployed instance: "Postgres-sa-c")
# set variables per the table above, plus PORT=3002 so Railway's healthcheck,
# the public domain, and private networking all agree on the port; then:
railway up --service fiat-verifier --detach
railway domain --service fiat-verifier         # public domain (Stripe webhooks need one)
```

Deployed staging values: public `https://fiat-verifier-production.up.railway.app`,
private `http://fiat-verifier.railway.internal:3002`,
`FIAT_DATABASE_URL=${{Postgres-sa-c.DATABASE_URL}}`.

### Enable Stripe test mode

1. Set `STRIPE_SECRET_KEY` to a **test-mode** secret key.
2. Create the webhook endpoint against the public domain and capture its secret:

```bash
curl -s https://api.stripe.com/v1/webhook_endpoints \
  -u "$STRIPE_SECRET_KEY:" \
  -d "url=https://<fiat-verifier-domain>/webhooks/stripe" \
  -d "enabled_events[]=checkout.session.completed" \
  -d "enabled_events[]=checkout.session.async_payment_succeeded" \
  -d "enabled_events[]=charge.refunded" \
  -d "enabled_events[]=charge.dispute.created"
# → response field "secret" is STRIPE_WEBHOOK_SECRET
```

3. Redeploy. `/health` reports `stripe_enabled` and `stripe_webhook_configured`.

### Enable PayPal sandbox

1. In the [PayPal developer dashboard](https://developer.paypal.com/dashboard/), create
   a REST app (sandbox) and set `PAYPAL_CLIENT_ID` + `PAYPAL_CLIENT_SECRET`.
2. Create the webhook against the public domain and capture its id (dashboard, or):

```bash
TOKEN=$(curl -s https://api-m.sandbox.paypal.com/v1/oauth2/token \
  -u "$PAYPAL_CLIENT_ID:$PAYPAL_CLIENT_SECRET" \
  -d grant_type=client_credentials | jq -r .access_token)
curl -s https://api-m.sandbox.paypal.com/v1/notifications/webhooks \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"url": "https://<fiat-verifier-domain>/webhooks/paypal",
       "event_types": [
         {"name": "CHECKOUT.ORDER.APPROVED"},
         {"name": "PAYMENT.CAPTURE.COMPLETED"},
         {"name": "PAYMENT.CAPTURE.PENDING"},
         {"name": "PAYMENT.CAPTURE.DENIED"},
         {"name": "PAYMENT.CAPTURE.REFUNDED"},
         {"name": "PAYMENT.CAPTURE.REVERSED"},
         {"name": "CUSTOMER.DISPUTE.CREATED"}]}'
# → response field "id" is PAYPAL_WEBHOOK_ID
```

3. Redeploy. `/health` reports `paypal_enabled` and `paypal_webhook_configured`.
   Detection works without the webhook (poll-only), just slower.

### Cutover / rollback

Point the Lock Server at the gateway (this is the only change anywhere):

```bash
railway variables --service locks-server \
  --set "LOCKS_PAYKIT_SERVER_URL=http://fiat-verifier.railway.internal:<port>"
# redeploy locks-server, then re-run the BTC live purchase proof
```

Rollback is the same variable set back to `http://paykit-server.railway.internal:3001`.

### Observing a fiat purchase

Structured JSON logs carry the full lifecycle: `dispatch:` lines on invoices,
`fiat payment detected (verified by API pull)`, and
`fiat payment confirmed (settlement delay elapsed, re-pull verified)`. Nothing moves
state except a pull: grep for those two messages when auditing an entitlement.

## Development

```bash
cargo test        # signature verification, dispatch, idempotency,
                  # webhook-vs-pull disagreement (pull wins), delay window,
                  # re-mint, refund/dispute detection before and after
                  # confirmation, reversal watch, webhook redelivery,
                  # processor selection and binding, PayPal lifecycle +
                  # capture-on-approval, buyer return-origin allowlist + binding
FIAT_TEST_DATABASE_URL=postgres://user:pass@localhost/db cargo test
                  # additionally runs the Postgres store tests against a real
                  # database (they print a skip notice without it)
cargo build --release
```

CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`, `cargo clippy --all-targets
-- -D warnings` and `cargo test` against a Postgres service on every push and pull
request, on the same Rust version as the Dockerfile.

Unit tests run against an in-memory store, mock Stripe and PayPal APIs, and a mock
Paykit Server; Lock Server signatures in tests are real ed25519 over canonical JSON,
and the mock PayPal verification postback really verifies (an HMAC over the
transmission fields plus a digest of the exact forwarded event bytes, standing in for
PayPal's cert-based signature, which only PayPal can produce). The live staging proof
uses a real Stripe test-mode payment — never a mock; the equivalent PayPal sandbox
proof is pending sandbox credentials.

## Known limitations (recorded, not hidden)

- On the wire, a Stripe-settled entitlement still says `verifier_type: "paykit-payment"`
  — a semantic misnomer, not a trust change (the label was never a trust statement).
  The upstream proposal for a generic `external-payment` verifier type removes it.
- `confirmations` for fiat is synthesized to satisfy the existing satisfaction rule; the
  mechanism (the delay really elapsed) is honest, the unit is not.
- Post-completion chargebacks land in the marketplace dispute flow (operator-manual in
  this phase); Locks has no un-complete transition, deliberately. This service detects
  them (webhook or reversal watch), records `reversed_after_confirm` and logs an
  `ALERT` line, but cannot revoke an entitlement the Lock Server already completed.
- Seller onboarding (Stripe Connect / PayPal Commerce Platform) is a later phase: this
  deployment settles into the operator-configured Stripe test / PayPal sandbox account,
  marked staging-only.
- PayPal's create-order response carries no expiry; the recorded 3-hour session expiry
  mirrors PayPal's documented default order validity rather than a processor-attested
  timestamp. An early-expired order simply re-mints on the next checkout call.
- The PayPal leg has not yet had a live sandbox end-to-end proof (no sandbox
  credentials configured); its lifecycle is proven against a mocked PayPal API with
  verified mock webhooks. Fail-closed behavior without credentials IS deployed
  behavior.
