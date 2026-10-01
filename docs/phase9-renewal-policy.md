# Phase 9.2 — Renewal Policy

Phase 9.2 adds a persistent renewal policy and a read-only renewal decision for each managed domain certificate instance.

The policy layer answers one question:

```text
Should this domain be renewed now?
```

It does **not** execute a renewal yet. Execution/scheduling belongs to the next phase.

## Model

```text
Domain Certificate Instance
          |
          v
Renewal Policy
├── auto_renew
└── renew_before_days
          |
          v
Renewal Decision
├── should_renew
├── reason
├── days_remaining
└── current_certificate
```

The default policy is intentionally conservative:

```json
{
  "auto_renew": false,
  "renew_before_days": 30
}
```

Automatic renewal must be explicitly enabled.

## APIs

Read the policy:

```bash
curl -s \
  http://127.0.0.1:8080/domains/hello2.test/renewal-policy \
  | jq
```

Configure the policy:

```bash
curl -s -X PUT \
  http://127.0.0.1:8080/domains/hello2.test/renewal-policy \
  -H 'Content-Type: application/json' \
  -d '{
    "auto_renew": true,
    "renew_before_days": 30
  }' \
  | jq
```

Evaluate the decision:

```bash
curl -s \
  http://127.0.0.1:8080/domains/hello2.test/renewal-decision \
  | jq
```

## Decision rules

```text
auto_renew = false
    -> should_renew = false
    -> reason = auto_renew_disabled

no current usable certificate
    -> should_renew = true
    -> reason = no_active_certificate

current certificate expires inside renew_before_days
    -> should_renew = true
    -> reason = within_renewal_window

current certificate expires after renew_before_days
    -> should_renew = false
    -> reason = outside_renewal_window
```

The decision always uses the platform-level `current_certificate` selected in Phase 9.1, so revoked, expired, and not-yet-valid certificates are never treated as the active renewal target.

## Persistence

Policies are stored under:

```text
data/renewal-policies/
```

Each domain is stored in an individual JSON file. The filename is a SHA-256 hash of the normalized domain so wildcard and future identifier formats do not need to be encoded directly into filesystem paths.

Restart the API server after configuring a policy and query it again. The policy should remain configured.

## Useful manual test

With a certificate that still has roughly 90 days remaining, first configure a 30-day window:

```bash
curl -s -X PUT \
  http://127.0.0.1:8080/domains/hello2.test/renewal-policy \
  -H 'Content-Type: application/json' \
  -d '{"auto_renew":true,"renew_before_days":30}' \
  | jq

curl -s \
  http://127.0.0.1:8080/domains/hello2.test/renewal-decision \
  | jq
```

Expected:

```text
should_renew = false
reason = outside_renewal_window
```

Then widen the window to 120 days:

```bash
curl -s -X PUT \
  http://127.0.0.1:8080/domains/hello2.test/renewal-policy \
  -H 'Content-Type: application/json' \
  -d '{"auto_renew":true,"renew_before_days":120}' \
  | jq
```

Query the decision again. Expected:

```text
should_renew = true
reason = within_renewal_window
```

## Boundary of this phase

Phase 9.2 makes renewal a policy decision but intentionally does not create a new ACME Order automatically.

The next layer can consume `RenewalDecision` from a scheduler/executor:

```text
Scheduler
   |
   v
RenewalDecision
   |
   +-- false -> no action
   |
   +-- true  -> Renewal Executor
                  |
                  v
              new ACME Order
```
