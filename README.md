# go-pki-lab

A Go-based local PKI and certificate authority lab for learning certificate chains, DNS-01 validation, CSR signing, TLS, persistence, renewal, revocation, CRL, OCSP, ACME, and certificate-platform workflows.

> Local research only. Do not use generated CA keys in production.

## Progress

```text
Phase 1  [done] Root CA -> Intermediate CA -> Leaf -> x509.Verify
Phase 2  [done] Local DNS server + TXT records + DNS-01 challenge
Phase 3  [done] Certificate Order HTTP API
Phase 4  [done] Trusted local HTTPS
Phase 5  [done] Client-owned private key + CSR signing
Phase 6  [done] Persistent CA/order/certificate storage
Phase 7  [done] Renewal + revocation + CRL + RFC 6960 OCSP
Phase 8  [in progress] ACME protocol
         8.1 [done] Directory + Nonce + JWS + Account + Order
         8.2 [done] DNS-01 + Finalize CSR + Certificate download
         8.3 [done] acme.sh end-to-end compatibility + local DNS hook
         8.4 [done] Persistent ACME Account/Order/issuance state
```

## Architecture

```text
                         go-pki-lab :8080
                               |
        +----------------------+----------------------+
        |                                             |
        v                                             v
 Certificate Platform API                       ACME RFC 8555 API
        |                                             |
        +----------------------+----------------------+
                               |
                        Persistent CA
                  data/ca/root-ca.{crt,key}
            data/ca/intermediate-ca.{crt,key}
                               |
                     +---------+---------+
                     |                   |
                     v                   v
              platform Orders       ACME state
              data/orders/*      data/acme/state.json
                     |                   |
                     +---------+---------+
                               |
                               v
                     Local DNS :1053/udp
                               |
                               v
                           DNS-01
                               |
                               v
                     Intermediate CA signs CSR
                               |
                               v
                    Leaf + Intermediate chain
```

The leaf private key and ACME account private key stay on the client side.

## Requirements

- Go 1.24+

```bash
go mod tidy
go test ./...
```

## Start the platform

```bash
go run ./cmd/api-server
```

Defaults:

```text
HTTP API        : http://127.0.0.1:8080
ACME directory  : http://127.0.0.1:8080/acme/directory
DNS             : 127.0.0.1:1053/udp
Persistent data : ./data
ACME state      : ./data/acme/state.json
```

The first startup creates the Root and Intermediate CA. Later startups load the same CA and ACME protocol state from disk.

## Persistent server data

```text
data/
├── ca/
│   ├── root-ca.crt
│   ├── root-ca.key
│   ├── intermediate-ca.crt
│   └── intermediate-ca.key
├── orders/
│   └── <platform-order-id>.json
└── acme/
    └── state.json
```

`data/` is ignored by Git. Never commit or distribute CA private keys.

The canonical trust anchor is:

```text
data/ca/root-ca.crt
```

Clients can obtain a copy through:

```bash
curl -s http://127.0.0.1:8080/ca/root -o ./client/root-ca.crt
```

`root-ca.crt` is not generated automatically into `client/`.

## ACME endpoints

```text
GET  /acme/directory
HEAD /acme/new-nonce
GET  /acme/new-nonce
POST /acme/new-account
POST /acme/acct/{id}
POST /acme/new-order
POST /acme/order/{id}
POST /acme/authz/{id}
POST /acme/challenge/{id}
POST /acme/finalize/{id}
POST /acme/cert/{id}
```

The implementation validates flattened JSON JWS, one-time `Replay-Nonce`, `url`, `jwk`/`kid`, ES256 signatures, and RS256 signatures for lab compatibility.

## ACME end-to-end flow

```text
Directory
   -> Nonce
   -> newAccount
   -> newOrder
   -> Authorization + dns-01 token
   -> local TXT publication
   -> POST challenge
   -> Order ready
   -> Finalize CSR
   -> Persistent Intermediate CA signs CSR
   -> Order valid
   -> POST-as-GET certificate URL
   -> Leaf + Intermediate PEM chain
```

ACME DNS-01 uses the standard value:

```text
keyAuthorization = token + "." + accountJWKThumbprint
TXT value        = base64url(SHA256(keyAuthorization))
```

Certificate download returns a PEM chain containing Leaf + Intermediate. The Root CA is intentionally not included.

## Test with acme.sh

A custom DNS hook is included at:

```text
scripts/acme.sh/dns_go_pki_lab.sh
```

Install it:

```bash
cp ./scripts/acme.sh/dns_go_pki_lab.sh \
  ~/.acme.sh/dnsapi/dns_go_pki_lab.sh
```

Then issue a local certificate:

```bash
export GO_PKI_LAB_API=http://127.0.0.1:8080

~/.acme.sh/acme.sh --issue \
  --server http://127.0.0.1:8080/acme/directory \
  --dns dns_go_pki_lab \
  --dnssleep 1 \
  -d hello.test \
  --keylength ec-256 \
  --accountkeylength ec-256 \
  --force \
  --debug 2
```

`--dnssleep 1` is important because the lab TXT record exists only on the local authoritative DNS server, not on public DNS/DoH resolvers.

The hook automatically performs:

```text
dns_go_pki_lab_add -> POST /dns/txt
ACME validation     -> local DNS :1053
dns_go_pki_lab_rm  -> DELETE /dns/txt
```

Detailed acme.sh instructions:

```text
docs/phase8-acmesh.md
```

## ACME persistence and restart recovery

ACME protocol state is stored in:

```text
data/acme/state.json
```

Persisted:

```text
Account ID
Account status/contact
Account public JWK + thumbprint
ACME Orders
challenge token + DNS-01 value
Order status
Challenge status
Authorization status
validation timestamp
ACME-issued PEM certificate chain
```

Not persisted:

```text
Replay-Nonce values
Local DNS TXT records
```

Nonces are intentionally short-lived and single-use. A pending DNS-01 challenge may need its TXT record republished after restart.

The ACME state file is written atomically and uses file mode `0600`. It contains only the account public JWK; the account private key remains with the ACME client.

Important migration note: Accounts created before Phase 8.4 were never stored server-side, so they cannot be restored retroactively. After one fresh registration on this version, future restarts reuse the same account.

Restart test and details:

```text
docs/phase8-acme-persistence.md
```

## ACME tests

```bash
go test ./internal/acme -v
go test ./...
```

The ACME tests cover real cryptographic operations and persistence:

```text
P-256 account key
-> ES256 JWS
-> Account
-> Order
-> Authorization
-> DNS TXT publication
-> UDP DNS-01 validation
-> client-generated CSR
-> CA signing
-> certificate download
-> X.509 chain verification
-> state save/load
-> JWK public-key reconstruction
-> order/lifecycle/certificate restoration
```

## Non-ACME certificate API

The original platform flow remains available for learning and comparison:

```text
POST   /orders
GET    /orders/{id}
POST   /orders/{id}/validate
POST   /orders/{id}/issue
POST   /dns/txt
GET    /dns/txt
DELETE /dns/txt
```

## Local HTTPS

Map:

```text
127.0.0.1 hello.test
```

Start HTTPS with a client-owned key and issued full chain:

```bash
go run ./cmd/https-server \
  -domain hello.test \
  -addr 127.0.0.1:8443 \
  -cert ./client/fullchain.pem \
  -key ./client/hello.test.key
```

Test:

```bash
curl --cacert ./data/ca/root-ca.crt https://hello.test:8443/
```

## Certificate lifecycle APIs

```text
POST /orders/{id}/renew
POST /orders/{id}/revoke
GET  /certificates/{serial}/status
GET  /ca/crl
POST /ocsp
```

Detailed lifecycle walkthrough:

```text
docs/phase7-lifecycle.md
```

### RFC 6960 OCSP

```bash
openssl ocsp \
  -issuer ./data/ca/intermediate-ca.crt \
  -cert ./client/hello.test.crt \
  -url http://127.0.0.1:8080/ocsp \
  -CAfile ./data/ca/root-ca.crt \
  -no_nonce \
  -resp_text
```

Before revocation the status should be `good`; after revocation it should be `revoked`.

## Current limitations

- one DNS identifier per ACME Order
- DNS-01 only
- no wildcard-specific ACME behavior yet
- local DNS TXT records are not persistent
- ACME challenge validation is synchronous
- persisted ACME resource URLs assume the same externally visible ACME base URL after restart
- no account key rollover
- no ACME revocation endpoint yet
- no External Account Binding
- renewal in the non-ACME API currently reuses the original CSR/public key
- CRL number is not yet a persisted monotonic counter
- no delta CRL
- leaf certificates do not yet contain CRL Distribution Point or OCSP AIA URLs
- OCSP nonce handling is not implemented
- OCSP responses are signed directly by the Intermediate CA rather than a delegated responder certificate
- no KMS/HSM integration or production-grade CA key protection

## Legacy all-in-one CLI

```bash
go run ./cmd/pki-server -domain hello.test -out ./out
```

This creates an isolated CA and certificate chain under `out/`; it does not use the persistent CA under `data/ca/`.
