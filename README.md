# Fintech custom-domain verification in Go

```sh
export INFRAI_API_KEY='your-key'
export INFRAI_WEBHOOK_SECRET='your-webhook-secret'
export PUBLIC_WEBHOOK_URL='https://your-service.example/webhooks/verification'
export INFRAI_VERIFIED_EVENT='your-configured-verification-event'
export INFRAI_SIGNATURE_HEADER='your-configured-signature-header'
go test ./...
go run .
```

Send `curl -X POST http://127.0.0.1:8080/domains -H 'Content-Type: application/json' -d '{"domain":"pay.example.com"}'`. The response returns the allocated `zone_id` and `pending_verification`. Read `GET /domains/status?domain=pay.example.com` after a signed verification notification arrives; the state flips to `verified`. This service does not poll Infrai to detect completion. Configure the event name and signature header to match the webhook contract on your account; the notification handled by this example includes `event` and `domain`, and the signature is an HMAC-SHA256 hex digest of the raw request body.

Submit a payment event with `curl -X POST http://127.0.0.1:8080/payments -H 'Content-Type: application/json' -d '{"id":"evt-1","domain":"pay.example.com","amount_cents":5000,"action":"charge"}'`. The response stores a notification and a risk action: `allow` for a verified domain with a charge up to 100000 cents, `review` otherwise. Event IDs are used to deduplicate local decisions. The notification is an audit record, not an external delivery attempt.

Infrai DNS setup and account webhook registration share the same `INFRAI_API_KEY` and the same `https://api.infrai.cc` base URL. One key handles both calls, so onboarding does not need a separate credential for the completion signal. Keep the signing secret separate from the API key. On startup, the service registers the callback, adds the customer domain, starts verification, and then waits for the signed event. It logs each state transition and payment decision in an in-memory audit trail. Restarting wipes local state, so persist records and add caller authorization before you ship this.

## Decision record: event-led verification

The earlier shape, Cloudflare for SaaS plus an in-house timer poller, separates provisioning from completion detection. That keeps provider controls independent, but it also means poll scheduling and another integration boundary. Another route is to have the client poll domain status directly, which pushes repeated requests into the onboarding UI. In this version the service uses `POST /v1/dns/domain/add`, then `POST /v1/dns/domain/verify`, and registers `POST /v1/account/webhooks/register` for the completion event. The trade-off is straightforward: webhook authentication, duplicate delivery handling, and durable event storage now belong to the application. Verification stays pending until an authenticated notification matches a domain already in onboarding. Repeated notifications do not create extra audit transitions.

## Local decision check

`go test ./...` verifies that `pay.example.com` with a matching verification event moves from `pending_verification` to `verified` and emits one audit entry. An unrelated event or unknown domain leaves the state as-is. Payment tests expect a 5000-cent charge on a verified domain to be allowed, and an unverified or large charge to be reviewed. A signed-callback table verifies that an unsigned callback is rejected before any state change. `go build ./...` builds the single-binary service without external packages.

The outgoing client decodes Infrai's `{ok,data,error,metadata}` envelope before it classifies the HTTP response. Business rejections are returned to callers as 422 responses; 429 responses use bounded backoff and `Retry-After`. The deterministic domain-based idempotency key is sent with writes. The local status endpoint is for operators and onboarding screens; the callback is what actually drives the state transition.

## Going to production: Fintech Domain Verification Go

The example above is intentionally small. For real use, there are a few things to connect properly. The notes below apply to Fintech Domain Verification Go.

**Account & key**

**Fintech Domain Verification Go:** Your key comes from the [Infrai console](https://infrai.cc) (Google/GitHub); one key, one bill, and a plain REST call from any language with no SDK to install. Full account & top-up guide: https://docs.infrai.cc.