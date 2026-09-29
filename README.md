# go-pki-lab

A Go-based local PKI and certificate authority lab for learning and testing certificate issuance, DNS-01 validation, certificate chains, TLS, and certificate-platform workflows.

> This repository is for local research and testing. Do not use generated CA private keys in production.

## Implemented

### Phase 1: local certificate chain

- Self-signed Root CA
- Intermediate CA signed by the Root CA
- TLS leaf certificate signed by the Intermediate CA
- SAN (`DNSNames`) for the requested domain
- `fullchain.pem` containing leaf + intermediate certificates
- Local chain verification with Go `crypto/x509`

### Phase 2: local DNS-01 validation

- Certificate Order with `pending -> ready -> valid` states
- Random DNS-01 challenge token generation
- Local authoritative UDP DNS server
- In-memory TXT record store
- Real DNS TXT lookup through `github.com/miekg/dns`
- Certificate issuance only after DNS-01 validation succeeds

### Phase 3: certificate platform HTTP API

- In-memory Order store with random Order IDs
- `POST /orders` creates a certificate order and DNS-01 challenge
- `POST /dns/txt` explicitly publishes local TXT records
- `POST /orders/{id}/validate` performs a real DNS TXT lookup
- `POST /orders/{id}/issue` issues only a `ready` order
- `GET /orders/{id}` returns order state
- `GET /ca/root` exposes the local Root CA certificate for later browser-trust experiments
- End-to-end API test covering create -> TXT -> validate -> issue

Phase 3 is still a lab workflow: the CA currently generates the leaf private key and returns it in the issuance response. A later CSR phase will move private-key generation to the client, matching real-world CA behavior more closely.

## Architecture

```text
                   HTTP API :8080
                        |
          +-------------+-------------+
          |                           |
          v                           v
   Certificate Orders            DNS Record API
          |                           |
          |                           v
          |                    TXT Record Store
          |                           |
          |                           v
          |                  Local UDP DNS :1053
          |                           ^
          v                           |
      DNS-01 Validator ---------------+
          |
          v
     status = ready
          |
          v
   Intermediate CA
          |
          v
   Leaf Certificate
          |
          v
     status = valid
```

## Certificate chain

```text
Go PKI Lab Root CA
        |
        v
Go PKI Lab Intermediate CA
        |
        v
hello.test
```

## Requirements

- Go 1.24+

```bash
go mod tidy
go test ./...
```

## Phase 2 CLI demo

```bash
go run ./cmd/pki-server -domain hello.test -out ./out
```

The CLI automatically publishes its generated TXT record so the complete DNS-01 flow can be demonstrated in one process.

## Phase 3 API demo

Start the platform:

```bash
go run ./cmd/api-server
```

Default endpoints:

```text
HTTP API : http://127.0.0.1:8080
DNS      : 127.0.0.1:1053/udp
```

### 1. Create an order

```bash
curl -s -X POST http://127.0.0.1:8080/orders \
  -H 'Content-Type: application/json' \
  -d '{"domain":"hello.test"}'
```

Example response:

```json
{
  "id": "<order-id>",
  "domain": "hello.test",
  "status": "pending",
  "challenge": {
    "type": "dns-01",
    "name": "_acme-challenge.hello.test",
    "value": "<random-token>"
  }
}
```

Save the returned `id`, challenge `name`, and challenge `value` for the next steps.

### 2. Publish the TXT record

```bash
curl -s -X POST http://127.0.0.1:8080/dns/txt \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"_acme-challenge.hello.test",
    "values":["<random-token>"]
  }'
```

You can inspect the record through the API:

```bash
curl -s 'http://127.0.0.1:8080/dns/txt?name=_acme-challenge.hello.test'
```

Or query the real local DNS server directly:

```bash
dig @127.0.0.1 -p 1053 TXT _acme-challenge.hello.test
```

### 3. Validate DNS-01

```bash
curl -s -X POST http://127.0.0.1:8080/orders/<order-id>/validate
```

The order should become:

```json
{
  "status": "ready"
}
```

If the TXT record is missing or incorrect, validation returns HTTP `422` and the certificate is not issued.

### 4. Issue the certificate

```bash
curl -s -X POST http://127.0.0.1:8080/orders/<order-id>/issue
```

The response contains:

```json
{
  "status": "valid",
  "certificate": {
    "certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "private_key_pem": "-----BEGIN PRIVATE KEY-----...",
    "fullchain_pem": "-----BEGIN CERTIFICATE-----..."
  }
}
```

Issuance before successful DNS validation returns HTTP `409`.

### 5. Inspect the order

```bash
curl -s http://127.0.0.1:8080/orders/<order-id>
```

### 6. Download the Root CA

```bash
curl -s http://127.0.0.1:8080/ca/root -o root-ca.crt
```

This certificate will be used in Phase 4 to make the local browser trust certificates issued by the lab CA.

## Phase 2 generated files

Running `cmd/pki-server` generates:

```text
out/
├── root-ca.crt
├── root-ca.key
├── intermediate-ca.crt
├── intermediate-ca.key
├── hello.test.crt
├── hello.test.key
└── fullchain.pem
```

`fullchain.pem` contains the leaf certificate followed by the intermediate CA certificate. The Root CA is intentionally not included in the TLS full chain; it is installed separately into the local trust store.

## Verify with OpenSSL

```bash
openssl verify \
  -CAfile out/root-ca.crt \
  -untrusted out/intermediate-ca.crt \
  out/hello.test.crt
```

## Security notes

Generated PKI material is ignored by Git. Never commit Root CA, Intermediate CA, or leaf private keys.

The API implementation is intentionally local and educational. It currently has no authentication, authorization, persistent database, rate limiting, audit log, HSM/KMS integration, or production-grade key protection.

## Roadmap

```text
Phase 1  [done] Root CA -> Intermediate CA -> Leaf -> x509.Verify
Phase 2  [done] Local DNS server + TXT records + DNS-01 challenge
Phase 3  [done] Certificate Order HTTP API + explicit challenge publication
Phase 4  Local HTTPS server + hosts mapping + browser trust walkthrough
Phase 5  CSR workflow: client-generated private keys and CSRs
Phase 6  Persistent CA/order storage and certificate lifecycle
Phase 7  Renewal, revocation, CRL and OCSP experiments
Phase 8  ACME-compatible workflow experiments
```
