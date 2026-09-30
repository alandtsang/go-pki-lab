# go-pki-lab

A Go-based local PKI and certificate authority lab for learning certificate chains, DNS-01 validation, CSR signing, TLS, persistence, renewal, revocation, and certificate lifecycle workflows.

> Local research only. Do not use generated CA keys in production.

## Implemented

### Phase 1: local certificate chain
- Self-signed Root CA
- Intermediate CA signed by Root CA
- TLS leaf certificate
- SAN validation
- `fullchain.pem`
- Go `crypto/x509` chain verification

### Phase 2: local DNS-01
- Local authoritative UDP DNS server
- In-memory TXT store
- DNS-01 challenge token
- Real TXT lookup through `github.com/miekg/dns`
- Order states: `pending -> ready -> valid`

### Phase 3: certificate platform API
- `POST /orders`
- `GET /orders/{id}`
- `POST /dns/txt`
- `GET /dns/txt`
- `POST /orders/{id}/validate`
- `POST /orders/{id}/issue`
- `GET /ca/root`

### Phase 4: trusted local HTTPS
- Local HTTPS server
- `fullchain.pem + leaf private key`
- hosts mapping walkthrough
- Root CA trust-store walkthrough
- Browser-valid HTTPS testing

### Phase 5: client-generated private key + CSR
- Client generates its own RSA private key
- Client generates CSR with DNS SAN
- `POST /orders` requires `csr_pem`
- CA validates CSR signature and SAN
- DNS-01 authorization is required
- CA signs the public key from the CSR
- Leaf private key never enters the CA platform

### Phase 6: persistent CA and order storage
- Root CA is generated only on first startup
- Intermediate CA is generated only on first startup
- Root/Intermediate certificates and private keys are loaded from disk after restart
- Persisted CA certificate/key pairs are validated when loaded
- Intermediate CA signature is checked against the Root CA
- Orders, CSR, challenge, status and issued certificates are persisted as JSON files
- Persisted orders are restored when the API server restarts
- Previously issued certificates remain verifiable after server restart

### Phase 7: certificate lifecycle
- `POST /orders/{id}/renew` creates a new renewal order
- `POST /orders/{id}/revoke` revokes an issued certificate
- Revocation time and reason are persisted
- `GET /certificates/{serial}/status` returns `good`, `revoked`, or `expired`
- `GET /ca/crl` returns a real X.509 CRL signed by the Intermediate CA
- Renewed certificates use a new order and new DNS-01 challenge

## Architecture

```text
Client
  |
  | generate key + CSR
  v
Certificate Platform API
  |
  +---- persistent CA -------------------------+
  |       data/ca/root-ca.{crt,key}            |
  |       data/ca/intermediate-ca.{crt,key}    |
  |                                             |
  +---- persistent orders ---------------------+
  |       data/orders/<order-id>.json           |
  |                                             |
  +---- DNS-01 -> Local DNS :1053               |
  |                                             |
  +---- Intermediate CA signs CSR public key    |
  |                                             |
  +---- revoke -> persistent status -> CRL      |
  |                                             |
  +---- renew -> new order -> DNS-01 -> issue   |
  v
certificate + fullchain
```

## Requirements

- Go 1.24+

```bash
go mod tidy
go test ./...
```

## Start the certificate platform

```bash
go run ./cmd/api-server
```

Defaults:

```text
HTTP API        : http://127.0.0.1:8080
DNS             : 127.0.0.1:1053/udp
Persistent data : ./data
```

On first startup:

```text
CA state: initialized new persistent CA
```

On later startups using the same data directory:

```text
CA state: loaded existing persistent CA
```

Use another storage directory if needed:

```bash
go run ./cmd/api-server -data-dir ./lab-data
```

## Persistent data layout

The persistent CA lives under `data/ca`, not under `client/`:

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

`data/` is ignored by Git.

The CA private keys are sensitive. Never commit or distribute:

```text
data/ca/root-ca.key
data/ca/intermediate-ca.key
```

## Client working directory

The `client/` directory is only for client-owned or client-downloaded artifacts:

```text
client/
├── hello.test.key          <- generated locally by csr-client
├── hello.test.csr          <- generated locally by csr-client
├── hello.test.crt          <- extracted from issuance response
├── fullchain.pem           <- extracted from issuance response
└── issue-response.json     <- optional saved API response
```

`root-ca.crt` is **not generated into `client/` automatically**.

The authoritative persisted Root CA is:

```text
data/ca/root-ca.crt
```

Clients should normally obtain a copy through the API:

```text
GET /ca/root
```

If you want a client-side copy for `curl`, OpenSSL, or trust-store installation, download it explicitly:

```bash
curl -s http://127.0.0.1:8080/ca/root \
  -o ./client/root-ca.crt
```

After that explicit download, `client/root-ca.crt` is just a copy of the persistent CA certificate; the canonical persisted file remains `data/ca/root-ca.crt`.

## End-to-end certificate issuance

### 1. Start the API server

```bash
go run ./cmd/api-server
```

### 2. Generate client private key and CSR

```bash
mkdir -p ./client

go run ./cmd/csr-client \
  -domain hello.test \
  -out ./client
```

At this point:

```text
client/
├── hello.test.key
└── hello.test.csr
```

Inspect the CSR:

```bash
openssl req \
  -in ./client/hello.test.csr \
  -text \
  -noout \
  -verify
```

### 3. Create an order

```bash
jq -n \
  --arg domain "hello.test" \
  --rawfile csr ./client/hello.test.csr \
  '{domain:$domain, csr_pem:$csr}' \
| curl -s -X POST http://127.0.0.1:8080/orders \
    -H 'Content-Type: application/json' \
    -d @-
```

Save the returned:

```text
id
challenge.name
challenge.value
```

### 4. Publish DNS TXT

```bash
curl -s -X POST http://127.0.0.1:8080/dns/txt \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"_acme-challenge.hello.test",
    "values":["<random-token>"]
  }'
```

Verify:

```bash
dig @127.0.0.1 -p 1053 TXT _acme-challenge.hello.test
```

### 5. Validate the order

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<order-id>/validate
```

Expected status:

```text
ready
```

### 6. Issue the certificate

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<order-id>/issue \
  -o ./client/issue-response.json
```

Extract the leaf certificate and chain:

```bash
jq -r '.certificate.certificate_pem' \
  ./client/issue-response.json > ./client/hello.test.crt

jq -r '.certificate.fullchain_pem' \
  ./client/issue-response.json > ./client/fullchain.pem
```

Now:

```text
client/
├── hello.test.key
├── hello.test.csr
├── hello.test.crt
├── fullchain.pem
└── issue-response.json
```

### 7. Verify the certificate chain

You can verify directly against the persistent Root CA:

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

Or, if you specifically want to behave like an external client, first download the Root CA:

```bash
curl -s http://127.0.0.1:8080/ca/root \
  -o ./client/root-ca.crt
```

Then verify with:

```bash
openssl verify \
  -CAfile ./client/root-ca.crt \
  -untrusted ./client/fullchain.pem \
  ./client/hello.test.crt
```

## Verify CA persistence across restart

Record the persisted Root CA fingerprint:

```bash
openssl x509 \
  -in ./data/ca/root-ca.crt \
  -fingerprint \
  -sha256 \
  -noout
```

Stop and restart:

```bash
go run ./cmd/api-server
```

Run the same command again. The fingerprint must be identical.

You can also verify that an old issued certificate still chains to the same Root CA:

```bash
openssl verify \
  -CAfile ./data/ca/root-ca.crt \
  -untrusted ./client/fullchain.pem \
  ./client/hello.test.crt
```

## Run local HTTPS

Map the test domain:

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

Test directly with the persisted Root CA:

```bash
curl --cacert ./data/ca/root-ca.crt \
  https://hello.test:8443/
```

Or download a client copy first:

```bash
curl -s http://127.0.0.1:8080/ca/root \
  -o ./client/root-ca.crt

curl --cacert ./client/root-ca.crt \
  https://hello.test:8443/
```

## Phase 7 lifecycle demo

### Query certificate status

Get the serial number from the order response or certificate:

```bash
openssl x509 \
  -in ./client/hello.test.crt \
  -serial \
  -noout
```

Then:

```bash
curl -s \
  http://127.0.0.1:8080/certificates/<serial>/status \
  | jq
```

Typical status before revocation:

```json
{
  "status": "good"
}
```

### Revoke the certificate

Example using reason code `1` (`keyCompromise`):

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<order-id>/revoke \
  -H 'Content-Type: application/json' \
  -d '{"reason":1}' \
  | jq
```

Query status again:

```bash
curl -s \
  http://127.0.0.1:8080/certificates/<serial>/status \
  | jq
```

Expected:

```json
{
  "status": "revoked"
}
```

### Download and inspect the CRL

```bash
curl -s http://127.0.0.1:8080/ca/crl \
  -o ./client/intermediate.crl.pem
```

Inspect:

```bash
openssl crl \
  -in ./client/intermediate.crl.pem \
  -text \
  -noout
```

The revoked certificate serial number should appear in the CRL.

### Renew a certificate

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<order-id>/renew \
  | jq
```

Renewal creates a new order:

```text
old certificate/order
        |
        v
POST /renew
        |
        v
new pending order
        |
        v
new DNS-01 challenge
        |
        v
validate
        |
        v
issue new certificate
```

The old certificate is not overwritten.

For the complete lifecycle walkthrough, see:

```text
docs/phase7-lifecycle.md
```

## Persistence behavior and current limitations

Persistent state:

```text
Root CA
Intermediate CA
Order ID
Domain
CSR
DNS challenge data
Order status
Issued leaf certificate
Full certificate chain
Revocation state
Revocation reason
Revocation time
Renewal relationship
```

Still in memory:

```text
Local DNS TXT records
```

After restarting the API server, a pending order that still needs DNS validation may require its TXT record to be published again.

The current certificate status endpoint is an application-level JSON status API. It is useful for lifecycle experiments but is not yet a complete RFC 6960 binary OCSP responder.

The API is still an educational local service. It does not yet include authentication, authorization, rate limiting, audit logging, KMS/HSM integration, or production-grade CA key protection.

## Legacy Phase 1/2 CLI

```bash
go run ./cmd/pki-server -domain hello.test -out ./out
```

This legacy command creates an isolated CA and certificate chain under `out/`. It does not use the persistent CA under `data/ca/`.

## Roadmap

```text
Phase 1  [done] Root CA -> Intermediate CA -> Leaf -> x509.Verify
Phase 2  [done] Local DNS server + TXT records + DNS-01 challenge
Phase 3  [done] Certificate Order HTTP API
Phase 4  [done] Trusted local HTTPS
Phase 5  [done] Client private key + CSR signing workflow
Phase 6  [done] Persistent CA/order/certificate storage
Phase 7  [done] Renewal + revocation + CRL + certificate status API
Phase 8  RFC 6960 OCSP responder + ACME-compatible workflow experiments
```