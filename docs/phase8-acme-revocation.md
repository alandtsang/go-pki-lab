# Phase 8.5 — ACME revocation and unified lifecycle

Phase 8.5 adds the RFC 8555 `revokeCert` resource and connects ACME-issued certificates to the same status, CRL, and OCSP lifecycle used by the original platform API.

## ACME Directory

The directory now advertises:

```json
{
  "newNonce": "http://127.0.0.1:8080/acme/new-nonce",
  "newAccount": "http://127.0.0.1:8080/acme/new-account",
  "newOrder": "http://127.0.0.1:8080/acme/new-order",
  "revokeCert": "http://127.0.0.1:8080/acme/revoke-cert"
}
```

## Endpoint

```text
POST /acme/revoke-cert
```

The request is a normal ACME JWS request. The certificate payload contains a base64url-encoded DER certificate and an optional RFC 5280 reason code.

Supported authentication modes:

```text
ACME account key -> protected header uses kid
certificate key  -> protected header uses jwk
```

The server verifies ownership before recording revocation.

## Persistent revocation state

ACME revocation state is stored in:

```text
data/acme/state.json
```

Each issued record can now contain:

```json
{
  "revoked_at": "...",
  "revocation_reason": 1
}
```

The ACME Order remains `valid`; revocation is certificate lifecycle state, not Order state.

## Shared lifecycle source

The platform lifecycle layer now accepts protocol-neutral certificate state sources:

```text
platform Order certificates ----+
                                |
ACME-issued certificates --------+--> CertificateStatus
                                +--> CRL
                                `--> OCSP
```

This means an ACME-issued certificate revoked through RFC 8555 is visible through all three existing mechanisms.

## Test with acme.sh

Assume `hello.test` was issued successfully with the ECC flow used in previous phases.

```bash
~/.acme.sh/acme.sh --revoke \
  --server http://127.0.0.1:8080/acme/directory \
  -d hello.test \
  --ecc \
  --debug 2
```

A successful ACME revocation should complete without an ACME error.

## Verify JSON status

Get the certificate serial:

```bash
SERIAL=$(openssl x509 \
  -in ~/.acme.sh/hello.test_ecc/hello.test.cer \
  -noout -serial | cut -d= -f2)

echo "$SERIAL"
```

Then query the platform status API:

```bash
curl -s \
  "http://127.0.0.1:8080/certificates/${SERIAL}/status" \
  | jq
```

Expected status:

```json
{
  "status": "revoked"
}
```

## Verify CRL

```bash
curl -s http://127.0.0.1:8080/ca/crl \
  -o /tmp/go-pki-lab.crl.pem

openssl crl \
  -in /tmp/go-pki-lab.crl.pem \
  -text \
  -noout
```

The ACME certificate serial should be listed in the revoked certificate entries.

## Verify OCSP

```bash
openssl ocsp \
  -issuer ./data/ca/intermediate-ca.crt \
  -cert ~/.acme.sh/hello.test_ecc/hello.test.cer \
  -url http://127.0.0.1:8080/ocsp \
  -CAfile ./data/ca/root-ca.crt \
  -no_nonce \
  -resp_text
```

Expected certificate status:

```text
revoked
```

## Automated regression

```bash
go test ./internal/acme -v
go test ./...
```

The Phase 8.5 regression covers:

```text
ACME revokeCert
  -> persistent revoked_at/reason
  -> CertificateStatus = revoked
  -> serial appears in CRL
  -> OCSP = revoked
```
