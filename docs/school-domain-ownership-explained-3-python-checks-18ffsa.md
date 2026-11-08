# School Domain Ownership Explained — 3 Python Checks for TXT Verification and Email

Require a fresh TXT challenge before a school administrator can activate a domain in your SaaS console. Use email confirmation for the administrator's contact address, then evaluate message authentication separately before enabling school-branded notifications. Each step answers a different question.

TL;DR: A matching TXT challenge can support a narrowly scoped claim of DNS control. An email confirmation supports a claim about access to that mailbox. Neither establishes inbox placement. For an edtech admin console, keep domain proof and deliverability evidence in separate fields, and require both before marking a sending configuration ready.

RFC 7489 supplies the critical distinction: DMARC evaluates alignment between the visible author domain and an authenticated identifier from SPF or DKIM. Its policy and reporting mechanisms concern message handling. They are not an onboarding protocol for assigning a domain to a SaaS tenant. That boundary makes a useful starting point for a notebook-to-prod implementation: define exactly what each observation permits the application to conclude.

## Follow the evidence through the school console

The proposed flow starts when an authorized school administrator requests a domain binding. The backend issues a tenant-bound, expiring token and displays the exact TXT owner name and value; a verifier reads that name and records its observation against the challenge. Email confirmation records contact access independently. A later message test contributes authentication evidence from a trusted receiving system, and the console derives readiness from those distinct results.

Keep the observations separate.

For a fictional school using `academy.example`, the console might show a verified DNS challenge alongside an untested sending configuration. That is a useful intermediate state. The school can finish proving control while the messaging team prepares its authentication setup, without a green ownership badge making an unsupported promise about lesson reminders reaching parents. In this design, the UI reports what was observed, when it was observed, and what action it enables.

## A runnable Python boundary with 3 checks

This standard-library example models the decision boundary after DNS lookup. It accepts complete logical TXT values from an adapter; it does not perform DNS resolution, validate email authentication, or send a confirmation message. The fixture uses a reserved example domain and synthetic observations. Its three checks cover the challenge context, the TXT match, and the presence of a separate aligned-authentication observation.

```python
from dataclasses import dataclass, replace
from secrets import compare_digest, token_urlsafe


@dataclass(frozen=True)
class Challenge:
    tenant: str
    domain: str
    owner: str
    value: str
    expires_at: int


def issue(tenant: str, domain: str, now: int) -> Challenge:
    # Accept a domain already validated and normalized by the backend.
    return Challenge(
        tenant=tenant,
        domain=domain,
        owner=f"_school-proof.{domain}",
        value=f"school-proof={token_urlsafe(32)}",
        expires_at=now + 900,
    )


def evaluate(
    challenge: Challenge,
    tenant: str,
    domain: str,
    queried_owner: str,
    txt_values: tuple[str, ...],
    aligned_auth_observed: bool,
    now: int,
) -> dict[str, bool]:
    context_ok = (
        tenant == challenge.tenant
        and domain == challenge.domain
        and queried_owner == challenge.owner
        and now < challenge.expires_at
    )
    txt_matches = any(
        compare_digest(value.encode("utf-8"), challenge.value.encode("utf-8"))
        for value in txt_values
    )
    dns_control = context_ok and txt_matches
    return {
        "dns_control_observed": dns_control,
        "aligned_auth_observed": aligned_auth_observed,
        "sending_setup_ready": dns_control and aligned_auth_observed,
    }


challenge = issue("school-17", "academy.example", now=0)
inputs = dict(
    challenge=challenge,
    tenant="school-17",
    domain="academy.example",
    queried_owner=challenge.owner,
    txt_values=(challenge.value,),
    aligned_auth_observed=False,
    now=1,
)
assert evaluate(**inputs)["dns_control_observed"]
assert not evaluate(**inputs)["sending_setup_ready"]
assert not evaluate(**(inputs | {"tenant": "school-18"}))["dns_control_observed"]
assert not evaluate(**(inputs | {"txt_values": ()}))["dns_control_observed"]
assert not evaluate(**(inputs | {"now": 900}))["dns_control_observed"]
rotated = replace(challenge, value="school-proof=another-token")
assert not evaluate(**(inputs | {"challenge": rotated}))["dns_control_observed"]
assert evaluate(**(inputs | {"aligned_auth_observed": True}))["sending_setup_ready"]
```

The example expires a challenge after 900 seconds. That's an illustrative application policy, not a DNS requirement or a propagation promise.

Likewise, `sending_setup_ready` means this example's two prerequisites passed. It does not mean a recipient accepted the message, placed it in an inbox, or read it. Those outcomes need their own evidence.

There is a deliberate omission: confirming a contact email cannot turn `dns_control_observed` true. Keep that contact result in the account workflow. Feeding it into the domain predicate would silently change the permission being granted.

## What does TXT verification prove that an email link cannot?

Under this proposed policy, the TXT test demonstrates that the expected token appeared at the requested DNS name during verification. The email link demonstrates access to the destination mailbox during confirmation. These are operational observations with different scopes; neither identifies a school's legal owner. Choose the proof according to the permission the console is about to grant.

For managing DNS records, require the DNS challenge. For confirming where to send an administrator's notices, use email confirmation. If the school delegates DNS management to another team, keep the request pending until that team publishes the challenge. The trade-off is slower onboarding in exchange for evidence tied to the requested permission. Email confirmation alone is not suitable for granting domain-wide control: a contact mailbox is insufficient evidence for permission to activate an entire domain in the admin console.

One easy trap is the word "verified." A single Boolean invites downstream code to reuse the result for contact access, tenant ownership, sending readiness, and delivery. Give these observations explicit names and timestamps instead. The console should say "DNS control observed" when that is all the verifier knows.

Ownership itself needs careful wording.

A limitation of this challenge is its scope: it proves the ability to publish the token at the checked name, subject to the verifier's DNS trust assumptions. It does not prove exclusive control, permanent control, or authorization over every subdomain. Store the precise domain binding, and define separately whether a proof for one name permits actions on child names.

## Deliverability evidence needs a message

RFC 7489 describes a DMARC pass in terms of an aligned SPF-authenticated identifier or an aligned DKIM-authenticated identifier. The visible From domain is central to that alignment. A custom onboarding token does not test either mechanism, and finding a DMARC TXT record is not evidence that a particular school notification authenticated successfully.

Test a message.

For this console, retain the test's sender domain, receiving-system identity, observation time, and authentication result. Treat `aligned_auth_observed` as a trusted backend input derived from that evidence, never as a checkbox submitted by the browser. RFC 7489's discussion of extracted authentication results warns that Authentication-Results headers require a trust boundary; accepting arbitrary uploaded headers would weaken this check.

Even then, keep the claim narrow. DMARC policy gives receivers domain-owner preferences, and receivers retain local handling discretion. A published rejection policy is not a receipt. Aggregate reports can help evaluate authentication across traffic, but they cannot establish inbox placement for an individual parent notification. If the release decision requires actual delivery evidence, collect the corresponding receiving-system observation and label it separately.

For an AI-assisted admin console, this distinction is also prompt-cost aware. Deterministic code should decide challenge equality, expiry, and readiness. An assistant can explain a pending state or summarize test evidence, but asking a model to infer ownership from free-form DNS text adds inference work without supplying the missing observation. The useful eval target is whether the explanation preserves the backend's permission boundary.

## Take the verifier from notebook to production

Start the eval harness with the failures already represented above: a token presented for another tenant, an absent value, an expired challenge, and a stale token after rotation. Add resolver-adapter fixtures for unrelated TXT records, lookup errors, and TXT values composed of multiple character strings. RFC 1035 defines TXT data as one or more character strings; the adapter must preserve record boundaries while assembling each logical value. Flattening every returned string together can create a value that no individual record contained. Keep a lookup error distinct from a successful lookup with no matching value. Neither authorizes activation. The distinction still matters to the administrator: one result calls for another observation, while the other calls for checking the published name and value. DNS caching also makes an unsuccessful observation time-bound; RFC 2308 describes negative caching, so immediate repeated requests cannot be treated as independent proof that a newly added record is absent everywhere.

Treat retries as new observations, not new permissions.

The minimal example intentionally has no durable state. Before deployment, store challenges server-side, authorize issuance against the tenant, and make acceptance and token consumption atomic. Define how competing requests to bind the same domain are resolved. Decide when an existing binding needs renewed proof, particularly before a sensitive permission change; a historical observation cannot establish current control indefinitely.

Finish the operational checklist in the release review: confirm that domain normalization and record assembly have fixtures, that expired or superseded challenges cannot activate bindings, and that retries preserve the distinction between resolver failure and token mismatch. Record enough timestamps and outcomes to investigate pending school requests without putting raw challenge tokens into logs. Then verify that the console and its generated explanations reserve each badge for the evidence actually collected.

That is the release criterion: DNS control for domain activation, mailbox access for contact confirmation, and message-level evidence for claims about sending. A school administrator should be able to tell which step is complete and which observation is still missing.

## References

- RFC 7489: DMARC alignment, authentication results, receiver policy, and reporting. https://datatracker.ietf.org/doc/html/rfc7489
- RFC 1035, section 3.3.14: TXT record character strings. https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14
- RFC 2308: negative caching of DNS answers. https://datatracker.ietf.org/doc/html/rfc2308
