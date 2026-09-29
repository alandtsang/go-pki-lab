# Phase 7 — Certificate lifecycle: renewal, revocation and CRL

Phase 7 adds a minimal certificate lifecycle loop on top of the persistent CA platform.

Implemented:

- certificate serial number exposed in Order responses
- certificate status lookup by serial number
- certificate revocation with a reason code
- revocation metadata persisted across API-server restarts
- an X.509 CRL signed by the persistent Intermediate CA
- renewal creates a fresh Order and fresh DNS-01 challenge
- renewal reuses the existing CSR/public key for this lab stage

> The status endpoint is an OCSP-style status API for experimentation. It is **not yet** an RFC 6960 DER OCSP responder. A standards-compatible OCSP responder can be added separately.

## API endpoints

```text
POST /orders/{id}/renew
POST /orders/{id}/revoke
GET  /certificates/{serial}/status
GET  /ca/crl
```

## 1. Find the issued certificate serial number

After an Order is issued:

```bash
curl -s http://127.0.0.1:8080/orders/<order-id> | jq
```

The response includes:

```json
{
  "serial_number": "<hex-serial>",
  "not_after": "..."
}
```

You can also inspect the local certificate:

```bash
openssl x509 \
  -in ./client/hello.test.crt \
  -serial \
  -enddate \
  -noout
```

## 2. Query certificate status

```bash
curl -s \
  http://127.0.0.1:8080/certificates/<hex-serial>/status \
  | jq
```

Before revocation:

```json
{
  "status": "good"
}
```

Possible lab statuses are:

```text
good
revoked
expired
```

## 3. Revoke an issued certificate

Reason code `1` means `keyCompromise` in the X.509 CRL reason-code convention.

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<order-id>/revoke \
  -H 'Content-Type: application/json' \
  -d '{"reason":1}' \
  | jq
```

The Order response now contains:

```json
{
  "revoked_at": "...",
  "revocation_reason": 1
}
```

Query the serial again:

```bash
curl -s \
  http://127.0.0.1:8080/certificates/<hex-serial>/status \
  | jq
```

Expected:

```json
{
  "status": "revoked"
}
```

Revocation metadata is persisted in `data/orders/<order-id>.json` and survives API-server restarts.

## 4. Download and inspect the CRL

```bash
curl -s http://127.0.0.1:8080/ca/crl \
  -o ./client/intermediate.crl.pem
```

Inspect it:

```bash
openssl crl \
  -in ./client/intermediate.crl.pem \
  -text \
  -noout
```

The revoked certificate serial should appear under `Revoked Certificates`.

Verify that the CRL was signed by the Intermediate CA. The Intermediate certificate is stored by the lab server at:

```text
data/ca/intermediate-ca.crt
```

For local experimentation:

```bash
openssl crl \
  -in ./client/intermediate.crl.pem \
  -CAfile ./data/ca/intermediate-ca.crt \
  -noout
```

The CRL is generated dynamically from persisted revocation records. `This Update` is the current time and `Next Update` is 24 hours later.

## 5. Renew a certificate

Renewal does **not** silently replace the existing certificate. It creates a new Order with a new ID and a new DNS-01 challenge:

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<old-order-id>/renew \
  | jq
```

Example:

```json
{
  "id": "<new-order-id>",
  "status": "pending",
  "renewed_from": "<old-order-id>",
  "challenge": {
    "type": "dns-01",
    "name": "_acme-challenge.hello.test",
    "value": "<new-random-token>"
  }
}
```

Publish the **new** TXT token, validate, then issue as usual:

```bash
curl -s -X POST http://127.0.0.1:8080/dns/txt \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"_acme-challenge.hello.test",
    "values":["<new-random-token>"]
  }'

curl -s -X POST \
  http://127.0.0.1:8080/orders/<new-order-id>/validate

curl -s -X POST \
  http://127.0.0.1:8080/orders/<new-order-id>/issue \
  | jq
```

The renewed certificate gets a new serial number and validity window.

## Lifecycle model

```text
Initial Order
    |
    | DNS-01 + issue
    v
Certificate A (good)
    |                  \
    | revoke            \ renew
    v                    v
Certificate A          New Order
(revoked)                 |
    |                     | DNS-01 + issue
    v                     v
CRL entry             Certificate B (good)
```

## Current limitations

- renewal currently reuses the original CSR/public key; a production client would often generate a fresh key/CSR according to key-rotation policy
- the CRL number is generated when the CRL endpoint is called rather than stored as a monotonically increasing CA counter
- no delta CRL
- no CRL Distribution Point extension is embedded in leaf certificates yet
- the status API is not yet a standards-compatible RFC 6960 OCSP responder
- no authentication/authorization around revocation operations

These are good follow-up experiments before or alongside the ACME phase.
