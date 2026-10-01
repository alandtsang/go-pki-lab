# Phase 8.7 — Certificate history and lifecycle queries

Phase 8.7 adds a protocol-neutral history view across both the original platform Orders and ACME-issued certificates.

## API

```text
GET /certificates?domain=<dns-name>
```

Example:

```bash
curl -s \
  'http://127.0.0.1:8080/certificates?domain=hello2.test' \
  | jq
```

The response is sorted newest-first by certificate `NotBefore`:

```json
{
  "domain": "hello2.test",
  "count": 2,
  "certificates": [
    {
      "serial_number": "CB92A3DEDE6EE156943AB566AB5B56E2",
      "domain": "hello2.test",
      "order_id": "<new-order-id>",
      "status": "good",
      "not_before": "...",
      "not_after": "..."
    },
    {
      "serial_number": "0F7CA3B7472D4604F62D1CA36A578F10",
      "domain": "hello2.test",
      "order_id": "<old-order-id>",
      "status": "revoked",
      "not_before": "...",
      "not_after": "...",
      "revoked_at": "...",
      "revocation_reason": 1
    }
  ]
}
```

## Status calculation

Each certificate generation is evaluated independently:

```text
revoked_at != nil      -> revoked
now > NotAfter         -> expired
now < NotBefore        -> not_yet_valid
otherwise              -> good
```

Renewing a domain therefore does not overwrite the old certificate:

```text
Domain hello2.test
  |
  +-- Order A -> Certificate A -> Serial A -> revoked
  |
  `-- Order B -> Certificate B -> Serial B -> good
```

## Why the query is protocol-neutral

`platform.Service` owns the history API and aggregates `CertificateState` objects from:

```text
platform Orders
      +
ACME Issuance state
      |
      v
CertificateHistory(domain)
      |
      v
GET /certificates?domain=...
```

This means callers do not need to know whether a certificate was created through the legacy platform API or through ACME.

## Validation

Run:

```bash
gofmt -w ./internal/platform/*.go ./internal/acme/*.go ./internal/api/*.go
go test ./internal/acme -run TestACMERenewalKeepsCertificateHistoryIndependent -v
go test ./...
```

Then query the domain used in the real acme.sh renewal test:

```bash
curl -s \
  'http://127.0.0.1:8080/certificates?domain=hello2.test' \
  | jq
```

The old and renewed serial numbers should both be present.

Known serials from the Phase 8.6 manual test were:

```text
OLD=0F7CA3B7472D4604F62D1CA36A578F10
NEW=CB92A3DEDE6EE156943AB566AB5B56E2
```

The API should preserve both generations rather than collapsing them into one domain record.
