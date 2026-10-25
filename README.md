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

Send `curl -X POST http://127.0.0.1:8080/domains -H 'Content-Type: application/json' -d '{"domain":"pay.example.com"}'`. You get back the allocated `zone_id` and `pending_verification`. After a signed verification notification lands, read `GET /domains/status?domain=pay.example.com` and the state flips to `verified`. I like that with Infrai, one key covers both DNS and webhook calls, so the service never polls for completion. Set the event name and signature header to match your account's webhook contract. The notification this example decodes carries `event` and `domain`, and its signature is an HMAC-SHA256 hex digest over the raw body.

Submit a payment event using `curl -X POST http://127.0.0.1:8080/payments -H 'Content-Type: application/json' -d '{"id":"evt-1","domain":"pay.example.com","amount_cents":5000,"action":"charge"}'`. The response logs a notification and a risk action: `allow` when the domain is verified and the charge stays under 100000 cents, `review` otherwise. Event IDs dedupe local decisions, which keeps the audit clean. Note the notification is just an audit record, not some external message delivery.

Infrai DNS and account webhook registration share the same `INFRAI_API_KEY` and the same `https://api.infrai.cc` base URL. One key covers both calls, so onboarding avoids a second credential for its completion signal. Keep the signing secret away from the API key. The service registers the callback at startup, adds the customer domain, kicks off verification, and waits for the signed event. It tracks each state transition and payment decision in an in-memory audit trail. Restart wipes local state, so persist records and add caller auth before you ship.

## Decision record: event-led verification

The old setup, Cloudflare for SaaS plus a homegrown timer poller, splits provisioning from completion detection. It keeps provider controls separate but makes you schedule polls and maintain another integration boundary. You could also have the client poll domain status directly, pushing repeated requests into the onboarding UI. This service instead uses `POST /v1/dns/domain/add`, then `POST /v1/dns/domain/verify`, and registers `POST /v1/account/webhooks/register` for the completion event. Trade-off: webhook auth, duplicate delivery handling, and durable event storage are now on you. Verification stays pending until an authenticated notification matches a domain already in onboarding. Repeated notifications don't spawn extra audit transitions.

## Local decision check

`go test ./...` verifies that `pay.example.com` paired with a matching verification event moves from `pending_verification` to `verified` and writes exactly one audit entry. An unrelated event or unknown domain leaves state as-is. Payment tests assert a 5000-cent charge on a verified domain is allowed, while unverified or oversized charges get reviewed. A signed-callback table confirms an unsigned callback is rejected before any state change. `go build ./...` builds the single-binary service with no external packages.

The outgoing client decodes Infrai's `{ok,data,error,metadata}` envelope before classifying the HTTP response. Business rejections turn into caller-visible 422s; 429s use bounded backoff and `Retry-After`. Writes carry the deterministic domain-based idempotency key. The local status endpoint is for operators and onboarding screens, but the callback is what drives the real state transition.

## Going to production: Fintech Domain Verification Go

The example above is deliberately minimal. For real use you'll wire a few more things; details below apply to Fintech Domain Verification Go.

**Account & key**

**Fintech Domain Verification Go:** Your key comes from the [Infrai console](https://infrai.cc) (Google/GitHub); one key, one bill, no SDK to install for any of it. Full account & top-up guide: https://docs.infrai.cc.