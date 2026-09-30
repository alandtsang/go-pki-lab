# go-pki-lab

A Go-based local PKI and certificate authority lab for learning certificate chains, DNS-01 validation, CSR signing, TLS, persistence, renewal, revocation, CRL, OCSP, and certificate-platform workflows.

> Local research only. Do not use generated CA keys in production.

## Implemented

```text
Phase 1  [done] Root CA -> Intermediate CA -> Leaf -> x509.Verify
Phase 2  [done] Local DNS server + TXT records + DNS-01 challenge
Phase 3  [done] Certificate Order HTTP API
Phase 4  [done] Trusted local HTTPS
Phase 5  [done] Client-owned private key + CSR signing
Phase 6  [done] Persistent CA/order/certificate storage
Phase 7  [done] Renewal + revocation + CRL + RFC 6960 OCSP
Phase 8         ACME-compatible workflow experiments
```

## Current architecture

```text
Client
  |
  | generate private key + CSR
  v
Certificate Platform API :8080
  |
  +---- persistent CA
  |       data/ca/root-ca.crt
  |       data/ca/root-ca.key
  |       data/ca/intermediate-ca.crt
  |       data/ca/intermediate-ca.key
  |
  +---- persistent orders
  |       data/orders/<order-id>.json
  |
  +---- DNS-01 validator -> local DNS :1053/udp
  |
  +---- Intermediate CA signs CSR public key
  |
  +---- lifecycle
          |-- renewal
          |-- revocation
          |-- CRL
          `-- OCSP
```

The leaf private key never enters the CA platform.

## Requirements

- Go 1.24+

After pulling a version that adds or changes dependencies, run:

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
DNS             : 127.0.0.1:1053/udp
Persistent data : ./data
```

First startup creates the Root and Intermediate CA. Later startups load the same persistent CA.

Use another data directory if needed:

```bash
go run ./cmd/api-server -data-dir ./lab-data
```

## Persistent server data

The canonical CA files live under `data/ca/`:

```text
data/
├── ca/
│   ├── root-ca.crt
│   ├── root-ca.key
│   ├── intermediate-ca.crt
│   └── intermediate-ca.key
└── orders/
    └── <order-id>.json
```

`data/` is ignored by Git. Never commit or distribute the CA private keys.

## Client working directory

The client directory contains client-owned or downloaded artifacts:

```text
client/
├── hello.test.key
├── hello.test.csr
├── hello.test.crt
├── fullchain.pem
└── issue-response.json
```

`root-ca.crt` is **not automatically generated into `client/`**.

The authoritative persisted Root CA is:

```text
data/ca/root-ca.crt
```

An external-style client can explicitly download a copy:

```bash
curl -s http://127.0.0.1:8080/ca/root \
  -o ./client/root-ca.crt
```

## Certificate issuance flow

Generate the client key and CSR:

```bash
mkdir -p ./client

go run ./cmd/csr-client \
  -domain hello.test \
  -out ./client
```

Create an Order:

```bash
jq -n \
  --arg domain "hello.test" \
  --rawfile csr ./client/hello.test.csr \
  '{domain:$domain, csr_pem:$csr}' \
| curl -s -X POST http://127.0.0.1:8080/orders \
    -H 'Content-Type: application/json' \
    -d @-
```

Publish the returned DNS-01 challenge:

```bash
curl -s -X POST http://127.0.0.1:8080/dns/txt \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"_acme-challenge.hello.test",
    "values":["<challenge-value>"]
  }'
```

Validate and issue:

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<order-id>/validate

curl -s -X POST \
  http://127.0.0.1:8080/orders/<order-id>/issue \
  -o ./client/issue-response.json
```

Extract the certificate files:

```bash
jq -r '.certificate.certificate_pem' \
  ./client/issue-response.json > ./client/hello.test.crt

jq -r '.certificate.fullchain_pem' \
  ./client/issue-response.json > ./client/fullchain.pem
```

Verify the chain directly against the persistent CA:

```bash
openssl verify \
  -CAfile ./data/ca/root-ca.crt \
  -untrusted ./client/fullchain.pem \
  ./client/hello.test.crt
```

Expected:

```text
./client/hello.test.crt: OK
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
curl --cacert ./data/ca/root-ca.crt \
  https://hello.test:8443/
```

## Certificate lifecycle APIs

```text
POST /orders/{id}/renew
POST /orders/{id}/revoke
GET  /certificates/{serial}/status
GET  /ca/crl
POST /ocsp
```

### Human-readable status API

```bash
curl -s \
  http://127.0.0.1:8080/certificates/<serial>/status \
  | jq
```

Statuses include:

```text
good
revoked
expired
```

### Revoke

Reason `1` is `keyCompromise`:

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<order-id>/revoke \
  -H 'Content-Type: application/json' \
  -d '{"reason":1}' \
  | jq
```

### CRL

```bash
curl -s http://127.0.0.1:8080/ca/crl \
  -o ./client/intermediate.crl.pem

openssl crl \
  -in ./client/intermediate.crl.pem \
  -text \
  -noout
```

### RFC 6960 OCSP

The binary OCSP endpoint is:

```text
POST /ocsp
Content-Type: application/ocsp-request
Response: application/ocsp-response
```

Query an issued certificate with OpenSSL:

```bash
openssl ocsp \
  -issuer ./data/ca/intermediate-ca.crt \
  -cert ./client/hello.test.crt \
  -url http://127.0.0.1:8080/ocsp \
  -CAfile ./data/ca/root-ca.crt \
  -no_nonce \
  -resp_text
```

Before revocation, the certificate status should be:

```text
good
```

After calling the revoke API, repeat the same command. The OCSP status should be:

```text
revoked
```

The OCSP response is signed by the persistent Intermediate CA. For this lab stage, the Intermediate CA itself is the responder; a production design often uses a delegated OCSP signing certificate.

### Renewal

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<old-order-id>/renew \
  | jq
```

Renewal creates a new pending Order with a new DNS-01 challenge. The old certificate is not overwritten.

For the complete lifecycle walkthrough, see:

```text
docs/phase7-lifecycle.md
```

## Persistence behavior

Persistent:

```text
Root CA
Intermediate CA
Order ID
Domain
CSR
DNS challenge metadata
Order status
Issued certificate and full chain
Revocation time/reason
Renewal relationship
```

Still in memory:

```text
Local DNS TXT records
```

After restart, a pending Order may require its TXT record to be published again.

## Current limitations

- renewal currently reuses the original CSR/public key
- CRL number is generated dynamically instead of using a persisted monotonic counter
- no delta CRL
- leaf certificates do not yet contain CRL Distribution Point URLs
- leaf certificates do not yet contain an OCSP Authority Information Access URL
- OCSP nonce handling is not implemented; the OpenSSL demo uses `-no_nonce`
- OCSP responses are signed directly by the Intermediate CA rather than a delegated responder certificate
- no authentication/authorization around certificate issuance or revocation
- no KMS/HSM integration or production-grade CA key protection

## Legacy all-in-one CLI

```bash
go run ./cmd/pki-server -domain hello.test -out ./out
```

This command creates an isolated CA and certificate chain under `out/`. It does not use the persistent CA under `data/ca/`.
