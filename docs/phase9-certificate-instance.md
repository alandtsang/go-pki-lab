# Phase 9.1 — Domain certificate instance

Phase 9 moves go-pki-lab from an ACME/CA protocol lab toward a certificate-management platform.

The first platform abstraction is:

```text
Domain
  |
  v
Certificate Instance
  |
  +--> Current Certificate
  |
  `--> Certificate History
```

## Why this layer exists

ACME operates on Accounts, Orders, Authorizations, Challenges, and Certificates. A certificate platform needs a higher-level object that answers a different question:

```text
Which certificate should this domain be using now?
```

A domain can have many Orders and many historical certificate generations. The platform must not blindly use the newest Order because that Order may be pending or failed. It must also not blindly use the newest issued certificate because that certificate may be revoked, expired, or not yet valid.

Phase 9.1 therefore introduces `DomainCertificateInstance`.

## Current-certificate selection

For one domain, go-pki-lab first loads all issued certificate generations and calculates their lifecycle status:

```text
revoked_at != nil       -> revoked
now > NotAfter          -> expired
now < NotBefore         -> not_yet_valid
otherwise               -> good
```

History is sorted by `NotBefore`, newest first.

The current certificate is the first certificate whose status is `good`.

Conceptually:

```text
hello2.test
  |
  +-- Certificate A  revoked
  |
  +-- Certificate B  good       <--- current
  |
  `-- Certificate C  expired
```

If no certificate is currently usable:

```text
status = no_active_certificate
current_certificate = null
```

Otherwise:

```text
status = active
```

## API

```text
GET /domains/{domain}/certificate-instance
```

Example:

```bash
curl -s \
  http://127.0.0.1:8080/domains/hello2.test/certificate-instance \
  | jq
```

Example response:

```json
{
  "domain": "hello2.test",
  "status": "active",
  "current_certificate": {
    "serial_number": "CB92A3DEDE6EE156943AB566AB5B56E2",
    "domain": "hello2.test",
    "order_id": "272071a40630a5e48729c39a",
    "status": "good",
    "not_before": "2026-10-01T09:35:04Z",
    "not_after": "2026-12-30T09:40:04Z"
  },
  "history_count": 2,
  "history": [
    {
      "serial_number": "CB92A3DEDE6EE156943AB566AB5B56E2",
      "status": "good"
    },
    {
      "serial_number": "0F7CA3B7472D4604F62D1CA36A578F10",
      "status": "good"
    }
  ]
}
```

The actual history items include the complete fields returned by the certificate-history API.

## Architecture boundary

The instance view is protocol-neutral:

```text
platform Orders -----+
                     |
                     +--> CertificateState
                     |        |
ACME Issuance -------+        v
                       CertificateHistory
                              |
                              v
                    DomainCertificateInstance
```

This lets future platform features depend on one stable certificate model instead of knowing whether a certificate came from ACME or the original platform API.

## Tests

```bash
go test ./internal/acme \
  -run TestACMERenewalKeepsCertificateHistoryIndependent \
  -v

go test ./...
```

The renewal regression test now also verifies:

```text
old certificate revoked
new certificate good
        |
        v
current_certificate = new certificate

old certificate revoked
new certificate revoked
        |
        v
status = no_active_certificate
current_certificate = null
```

## Next platform capability

The next natural layer is a renewal policy attached to the certificate instance, for example:

```text
renew_before_days = 30
auto_renew = true
```

That policy can answer:

```text
Does this certificate instance need renewal now?
```

and later drive automated renewal, deployment, and expiry monitoring.
