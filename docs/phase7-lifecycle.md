# Phase 7 — Certificate lifecycle: renewal, revocation, CRL and OCSP

Phase 7 adds a minimal certificate lifecycle loop on top of the persistent CA platform.

Implemented:

- certificate serial number exposed in Order responses
- certificate status lookup by serial number
- certificate revocation with a reason code
- revocation metadata persisted across API-server restarts
- an X.509 CRL signed by the persistent Intermediate CA
- an RFC 6960-compatible OCSP responder at `POST /ocsp`
- renewal creates a fresh Order and fresh DNS-01 challenge
- renewal reuses the existing CSR/public key for this lab stage

## API endpoints

```text
POST /orders/{id}/renew
POST /orders/{id}/revoke
GET  /certificates/{serial}/status
GET  /ca/crl
POST /ocsp
```

`GET /certificates/{serial}/status` is still useful as a human-readable JSON API. `POST /ocsp` is the binary OCSP protocol endpoint.

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

## 2. Query certificate status through the JSON API

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

## 3. Query the real OCSP responder

The Intermediate CA is the issuer of the leaf certificate, so OpenSSL needs:

```text
issuer = data/ca/intermediate-ca.crt
cert   = client/hello.test.crt
OCSP   = http://127.0.0.1:8080/ocsp
```

Run:

```bash
openssl ocsp \
  -issuer ./data/ca/intermediate-ca.crt \
  -cert ./client/hello.test.crt \
  -url http://127.0.0.1:8080/ocsp \
  -CAfile ./data/ca/root-ca.crt \
  -no_nonce \
  -resp_text
```

Before revocation you should see a successful OCSP response whose certificate status is:

```text
good
```

The responder flow is:

```text
OpenSSL / TLS client
        |
        | DER OCSPRequest
        v
POST /ocsp
        |
        | parse issuer hashes + serial
        v
Persistent certificate state
        |
        | good / revoked / unknown
        v
Intermediate CA private key
        |
        | sign DER OCSPResponse
        v
OpenSSL / TLS client
```

The lab uses the Intermediate CA itself as the OCSP response signer. A production CA often uses a delegated responder certificate with the `OCSPSigning` EKU.

## 4. Revoke an issued certificate

Reason code `1` means `keyCompromise` in the X.509/OCSP reason-code convention.

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

Query the JSON status again:

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

Now repeat the same OpenSSL OCSP command:

```bash
openssl ocsp \
  -issuer ./data/ca/intermediate-ca.crt \
  -cert ./client/hello.test.crt \
  -url http://127.0.0.1:8080/ocsp \
  -CAfile ./data/ca/root-ca.crt \
  -no_nonce \
  -resp_text
```

The OCSP certificate status should now be:

```text
revoked
```

and the response should contain the stored revocation time and reason.

Revocation metadata is persisted in `data/orders/<order-id>.json` and survives API-server restarts.

## 5. Download and inspect the CRL

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

Verify the CRL signature with the Intermediate CA:

```bash
openssl crl \
  -in ./client/intermediate.crl.pem \
  -CAfile ./data/ca/intermediate-ca.crt \
  -noout
```

The CRL is generated dynamically from persisted revocation records. `This Update` is the current time and `Next Update` is 24 hours later.

## 6. Renew a certificate

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
    |                     v
    +--> CRL          Certificate B (good)
    |
    +--> OCSP = revoked
```

## Current limitations

- renewal currently reuses the original CSR/public key; a production client would often generate a fresh key/CSR according to key-rotation policy
- the CRL number is generated when the CRL endpoint is called rather than stored as a monotonically increasing CA counter
- no delta CRL
- no CRL Distribution Point extension is embedded in leaf certificates yet
- no OCSP URL (Authority Information Access) is embedded in leaf certificates yet
- the OCSP responder uses the Intermediate CA directly instead of a delegated responder certificate
- OCSP nonce handling is not implemented, so the OpenSSL demo uses `-no_nonce`
- no authentication/authorization around revocation operations

These are good follow-up experiments before the ACME phase.
