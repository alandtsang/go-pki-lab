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
         8.3 [in progress] acme.sh compatibility + local DNS hook
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

The leaf private key stays on the client side.

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
```

The first startup creates the Root and Intermediate CA. Later startups load the same CA from disk.

## Persistent server data

```text
data/
├── ca/
│   ├── root-ca.crt
│   ├── root-ca.key
│   ├── intermediate-ca.crt
│   └── intermediate-ca.key
└── orders/
    └── <platform-order-id>.json
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

Discover the server:

```bash
curl -s http://127.0.0.1:8080/acme/directory | jq
```

Get a nonce:

```bash
curl -i -X HEAD http://127.0.0.1:8080/acme/new-nonce
```

The implementation validates flattened JSON JWS, `Replay-Nonce`, `url`, `jwk`/`kid`, ES256 signatures, and RS256 signatures for lab compatibility.

## ACME end-to-end flow

```text
Directory
   |
   v
Nonce
   |
   v
newAccount
   |
   v
newOrder(hello.test)
   |
   v
Authorization + dns-01 token
   |
   v
_acme-challenge.hello.test TXT
   |
   v
POST challenge
   |
   v
DNS lookup through local DNS :1053
   |
   v
Authorization = valid
Order = ready
   |
   v
POST finalize { csr }
   |
   v
CSR signature + SAN validation
   |
   v
Persistent Intermediate CA signs CSR
   |
   v
Order = valid
   |
   v
POST-as-GET certificate URL
   |
   v
Leaf + Intermediate PEM chain
```

ACME DNS-01 uses the standard value:

```text
keyAuthorization = token + "." + accountJWKThumbprint
TXT value        = base64url(SHA256(keyAuthorization))
```

Certificate download returns:

```text
Content-Type: application/pem-certificate-chain

-----BEGIN CERTIFICATE-----
<leaf>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<intermediate>
-----END CERTIFICATE-----
```

The Root CA is intentionally not included in the served chain.

## Phase 8.3: test with acme.sh

A custom DNS API hook is included at:

```text
scripts/acme.sh/dns_go_pki_lab.sh
```

Install it into a normal acme.sh installation:

```bash
cp ./scripts/acme.sh/dns_go_pki_lab.sh \
  ~/.acme.sh/dnsapi/dns_go_pki_lab.sh
```

Then issue one local certificate:

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

`--dnssleep 1` is important for this lab because acme.sh normally checks DNS propagation through public DNS/DoH, while go-pki-lab intentionally exposes the challenge only on the local authoritative server at `127.0.0.1:1053`.

The hook automatically performs:

```text
acme.sh
   |
   +--> dns_go_pki_lab_add
   |       |
   |       `--> POST /dns/txt
   |
   +--> ACME challenge validation
   |       |
   |       `--> local DNS :1053
   |
   `--> dns_go_pki_lab_rm
           |
           `--> DELETE /dns/txt
```

Detailed instructions and troubleshooting:

```text
docs/phase8-acmesh.md
```

## ACME tests

Run:

```bash
go test ./internal/acme -v
```

The end-to-end test covers real cryptographic operations:

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
```

Run all tests:

```bash
go test ./...
```

See the protocol details in:

```text
docs/phase8-acme.md
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

Client-side artifacts typically look like:

```text
client/
├── hello.test.key
├── hello.test.csr
├── hello.test.crt
├── fullchain.pem
└── issue-response.json
```

Verify a certificate against the persistent Root CA:

```bash
openssl verify \
  -CAfile ./data/ca/root-ca.crt \
  -untrusted ./client/fullchain.pem \
  ./client/hello.test.crt
```

## Local HTTPS

Map:

```text
127.0.0.1 hello.test
```

Start HTTPS:

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

## Persistence behavior

Persistent today:

```text
Root CA
Intermediate CA
non-ACME platform Orders
issued platform certificates
revocation state
renewal relationships
```

Still in memory:

```text
Local DNS TXT records
ACME nonces
ACME accounts
ACME protocol Orders
ACME-issued certificate response state
```

Therefore restarting `api-server` preserves the CA trust anchor, but currently discards active ACME protocol sessions and ACME account/order state.

## Current limitations

- one DNS identifier per ACME Order
- DNS-01 only
- no wildcard-specific ACME behavior yet
- ACME account/order state is not persistent yet
- challenge validation is synchronous
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
