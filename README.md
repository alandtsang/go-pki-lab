# go-pki-lab

A Go-based local PKI and certificate authority lab for learning certificate chains, DNS-01 validation, CSR signing, TLS, persistence, and certificate-platform workflows.

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
  v
certificate + fullchain
```

## Requirements

- Go 1.24+

```bash
go mod tidy
go test ./...
```

## Start the persistent certificate platform

```bash
go run ./cmd/api-server
```

Defaults:

```text
HTTP API       : http://127.0.0.1:8080
DNS            : 127.0.0.1:1053/udp
Persistent data: ./data
```

On the first startup you should see:

```text
CA state: initialized new persistent CA
```

On later startups using the same `data` directory:

```text
CA state: loaded existing persistent CA
```

You can choose another storage directory:

```bash
go run ./cmd/api-server -data-dir ./lab-data
```

## Persistent data layout

After the first startup:

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

The CA private key files are sensitive even though this project is only a lab. Do not commit or distribute them.

## Where `root-ca.crt` comes from

The API exposes the persistent Root CA certificate at:

```text
GET /ca/root
```

Download it with:

```bash
mkdir -p ./client
curl -s http://127.0.0.1:8080/ca/root \
  -o ./client/root-ca.crt
```

You may also inspect the persisted copy directly at:

```text
data/ca/root-ca.crt
```

The API route is preferred because clients should not need direct access to CA storage.

## Phase 5/6 end-to-end demo

### 1. Start the API server

```bash
go run ./cmd/api-server
```

### 2. Download the Root CA

```bash
mkdir -p ./client
curl -s http://127.0.0.1:8080/ca/root \
  -o ./client/root-ca.crt
```

Record its fingerprint:

```bash
openssl x509 \
  -in ./client/root-ca.crt \
  -fingerprint \
  -sha256 \
  -noout
```

### 3. Generate client private key and CSR

```bash
go run ./cmd/csr-client \
  -domain hello.test \
  -out ./client
```

Generated locally:

```text
client/
├── root-ca.crt
├── hello.test.key
└── hello.test.csr
```

### 4. Create an order

```bash
jq -n \
  --arg domain "hello.test" \
  --rawfile csr ./client/hello.test.csr \
  '{domain:$domain, csr_pem:$csr}' \
| curl -s -X POST http://127.0.0.1:8080/orders \
    -H 'Content-Type: application/json' \
    -d @-
```

Save the returned `id`, challenge `name`, and challenge `value`.

### 5. Publish DNS TXT

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

### 6. Validate the order

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<order-id>/validate
```

Expected status:

```text
ready
```

### 7. Issue the certificate

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<order-id>/issue \
  -o ./client/issue-response.json
```

Extract:

```bash
jq -r '.certificate.certificate_pem' \
  ./client/issue-response.json > ./client/hello.test.crt

jq -r '.certificate.fullchain_pem' \
  ./client/issue-response.json > ./client/fullchain.pem
```

### 8. Verify the chain

```bash
openssl verify \
  -CAfile ./client/root-ca.crt \
  -untrusted ./client/fullchain.pem \
  ./client/hello.test.crt
```

Expected:

```text
./client/hello.test.crt: OK
```

## Phase 6 restart persistence test

This verifies that the Root CA and issued order survive a process restart.

### 1. Record the current Root CA fingerprint

```bash
curl -s http://127.0.0.1:8080/ca/root \
  -o /tmp/root-before.crt

openssl x509 \
  -in /tmp/root-before.crt \
  -fingerprint -sha256 -noout
```

Also confirm an existing issued order can be read:

```bash
curl -s http://127.0.0.1:8080/orders/<order-id>
```

### 2. Stop and restart the API server

Stop it with `Ctrl+C`, then run again:

```bash
go run ./cmd/api-server
```

The startup log should say:

```text
CA state: loaded existing persistent CA
```

### 3. Compare the Root CA after restart

```bash
curl -s http://127.0.0.1:8080/ca/root \
  -o /tmp/root-after.crt

openssl x509 \
  -in /tmp/root-after.crt \
  -fingerprint -sha256 -noout

cmp /tmp/root-before.crt /tmp/root-after.crt
```

`cmp` should produce no output. The SHA-256 fingerprints should also be identical.

### 4. Confirm the order still exists

```bash
curl -s http://127.0.0.1:8080/orders/<order-id>
```

The same order ID and status should be returned.

For a previously issued order, calling issue again should return its persisted certificate rather than generating a new certificate:

```bash
curl -s -X POST \
  http://127.0.0.1:8080/orders/<order-id>/issue
```

### 5. Verify the old certificate against the Root CA after restart

```bash
curl -s http://127.0.0.1:8080/ca/root \
  -o ./client/root-ca-after-restart.crt

openssl verify \
  -CAfile ./client/root-ca-after-restart.crt \
  -untrusted ./client/fullchain.pem \
  ./client/hello.test.crt
```

Expected:

```text
./client/hello.test.crt: OK
```

This is the key Phase 6 result: restarting the certificate platform no longer changes its trust anchor.

## Run local HTTPS

Add this to your hosts file:

```text
127.0.0.1 hello.test
```

Then:

```bash
go run ./cmd/https-server \
  -domain hello.test \
  -addr 127.0.0.1:8443 \
  -cert ./client/fullchain.pem \
  -key ./client/hello.test.key
```

Test:

```bash
curl --cacert ./client/root-ca.crt \
  https://hello.test:8443/
```

## Persistence behavior and current limitations

The following state is persistent:

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
```

The local DNS TXT store is still in memory. After restarting the API server, TXT records must be published again if a `pending` or failed order still needs DNS validation.

This stage uses a file-backed repository intentionally so the persistence model stays easy to inspect. A future version can replace it with SQLite/PostgreSQL without changing the core certificate workflow.

The API is still an educational local service. It does not yet include authentication, authorization, rate limiting, audit logging, KMS/HSM integration, or production-grade CA key protection.

## Legacy Phase 1/2 CLI

```bash
go run ./cmd/pki-server -domain hello.test -out ./out
```

This legacy command still generates an isolated CA and certificate chain inside one process. It does not use the persistent API-server CA state.

## Roadmap

```text
Phase 1  [done] Root CA -> Intermediate CA -> Leaf -> x509.Verify
Phase 2  [done] Local DNS server + TXT records + DNS-01 challenge
Phase 3  [done] Certificate Order HTTP API
Phase 4  [done] Trusted local HTTPS
Phase 5  [done] Client private key + CSR signing workflow
Phase 6  [done] Persistent CA/order/certificate storage
Phase 7  Renewal, revocation, CRL and OCSP experiments
Phase 8  ACME-compatible workflow experiments
```
