# go-pki-lab

A Go-based local PKI and certificate authority lab for learning certificate chains, DNS-01 validation, CSR signing, TLS, and certificate-platform workflows.

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
- CA validates CSR signature
- CA requires CSR SAN to match requested domain
- DNS-01 authorization is still required
- CA signs the public key from the CSR
- Issuance response no longer contains a private key
- The leaf private key never enters the CA platform

## Architecture

```text
Client
  |
  | generate private key locally
  v
hello.test.key
  |
  | create CSR
  v
hello.test.csr
  |
  | POST /orders { domain, csr_pem }
  v
Certificate Platform
  |
  +--> validate CSR signature + SAN
  |
  +--> create DNS-01 challenge
  |
  v
pending
  |
  | publish TXT
  v
Local DNS Server :1053
  |
  | validate DNS-01
  v
ready
  |
  | Intermediate CA signs CSR public key
  v
certificate + fullchain
  |
  v
valid

The private key stays on the client side for the entire flow.
```

## Requirements

- Go 1.24+

```bash
go mod tidy
go test ./...
```

## Important: where `root-ca.crt` comes from

`cmd/csr-client` does **not** generate `root-ca.crt`.

The Root CA is created by the certificate platform process when `cmd/api-server` starts. The API exposes the corresponding Root CA certificate at:

```text
GET /ca/root
```

Download it with:

```bash
curl -s http://127.0.0.1:8080/ca/root \
  -o ./client/root-ca.crt
```

So the Phase 5 files come from different places:

```text
client/
├── hello.test.key       <- generated locally by csr-client
├── hello.test.csr       <- generated locally by csr-client
├── hello.test.crt       <- returned by POST /orders/{id}/issue
├── fullchain.pem        <- returned by POST /orders/{id}/issue
├── root-ca.crt          <- downloaded from GET /ca/root
└── issue-response.json  <- saved issuance API response
```

### Current limitation: Root CA is not persistent yet

At the current stage, `cmd/api-server` generates a new Root CA and Intermediate CA every time the process starts.

That means:

```text
start api-server
    |
    +--> Root CA A
    |
    +--> issue hello.test certificate signed by Root CA A

restart api-server
    |
    +--> Root CA B
```

A certificate issued under **Root CA A** will not validate against **Root CA B**.

Therefore, for the current Phase 5 demo:

1. Start `cmd/api-server`.
2. Keep that same process running while creating the order, validating DNS-01 and issuing the certificate.
3. Download `root-ca.crt` from that same running process.
4. Use that downloaded Root CA to verify the issued certificate.
5. If you restart `cmd/api-server`, previously issued certificates belong to the old CA instance.

Persistent Root/Intermediate CA storage is planned for Phase 6.

## Phase 5 end-to-end demo

### 1. Start the certificate platform

```bash
go run ./cmd/api-server
```

Defaults:

```text
HTTP API : http://127.0.0.1:8080
DNS      : 127.0.0.1:1053/udp
```

Keep this process running for the entire demo. Do not restart it between certificate issuance and Root CA download.

### 2. Download the Root CA for this CA instance

In another terminal:

```bash
mkdir -p ./client

curl -s http://127.0.0.1:8080/ca/root \
  -o ./client/root-ca.crt
```

You can inspect it with:

```bash
openssl x509 \
  -in ./client/root-ca.crt \
  -subject \
  -issuer \
  -fingerprint \
  -sha256 \
  -noout
```

Because the Root CA is currently generated in memory when `api-server` starts, this file must come from the same server instance that will issue your certificate.

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

Inspect the CSR:

```bash
openssl req \
  -in ./client/hello.test.csr \
  -text \
  -noout \
  -verify
```

You should see `DNS:hello.test` in Subject Alternative Name.

### 4. Create an order with the CSR

Using `jq` to safely JSON-encode the PEM:

```bash
jq -n \
  --arg domain "hello.test" \
  --rawfile csr ./client/hello.test.csr \
  '{domain:$domain, csr_pem:$csr}' \
| curl -s -X POST http://127.0.0.1:8080/orders \
    -H 'Content-Type: application/json' \
    -d @-
```

Example response:

```json
{
  "id": "<order-id>",
  "domain": "hello.test",
  "status": "pending",
  "csr_submitted": true,
  "challenge": {
    "type": "dns-01",
    "name": "_acme-challenge.hello.test",
    "value": "<random-token>"
  }
}
```

A CSR for another domain is rejected with HTTP `400`.

### 5. Publish the DNS TXT challenge

```bash
curl -s -X POST http://127.0.0.1:8080/dns/txt \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"_acme-challenge.hello.test",
    "values":["<random-token>"]
  }'
```

Verify it through real DNS:

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

The response contains only:

```text
certificate_pem
fullchain_pem
```

It does **not** contain `private_key_pem`.

Extract the files:

```bash
jq -r '.certificate.certificate_pem' \
  ./client/issue-response.json > ./client/hello.test.crt

jq -r '.certificate.fullchain_pem' \
  ./client/issue-response.json > ./client/fullchain.pem
```

The client directory is now:

```text
client/
├── root-ca.crt          <- downloaded from the CA API
├── hello.test.key       <- generated locally, never sent to CA
├── hello.test.csr       <- sent to CA
├── hello.test.crt       <- returned by CA
├── fullchain.pem        <- returned by CA
└── issue-response.json
```

### 8. Verify the certificate chain

Because `fullchain.pem` contains the leaf certificate followed by the Intermediate CA certificate, you can verify it with:

```bash
openssl verify \
  -CAfile ./client/root-ca.crt \
  -untrusted ./client/fullchain.pem \
  ./client/hello.test.crt
```

Expected result:

```text
./client/hello.test.crt: OK
```

If this fails after restarting `api-server`, make sure the `root-ca.crt` and the leaf certificate were produced by the same CA server instance.

### 9. Prove the issued certificate matches the client private key

Compare the public keys:

```bash
openssl pkey \
  -in ./client/hello.test.key \
  -pubout \
  -outform pem > /tmp/key.pub

openssl x509 \
  -in ./client/hello.test.crt \
  -pubkey \
  -noout > /tmp/cert.pub

diff /tmp/key.pub /tmp/cert.pub
```

No output from `diff` means the certificate was issued for the public key in the client's private key.

### 10. Run HTTPS with the client-owned private key

Add:

```text
127.0.0.1 hello.test
```

to your hosts file, then run:

```bash
go run ./cmd/https-server \
  -domain hello.test \
  -addr 127.0.0.1:8443 \
  -cert ./client/fullchain.pem \
  -key ./client/hello.test.key
```

Test without modifying the system trust store:

```bash
curl --cacert ./client/root-ca.crt \
  https://hello.test:8443/
```

Or:

```bash
openssl s_client \
  -connect hello.test:8443 \
  -servername hello.test \
  -CAfile ./client/root-ca.crt \
  -verify_return_error
```

Expected result:

```text
Verify return code: 0 (ok)
```

After installing the lab Root CA into your local trust store, the browser should open `https://hello.test:8443/` without a certificate warning.

## Legacy Phase 1/2 CLI

The original all-in-one lab command still exists:

```bash
go run ./cmd/pki-server -domain hello.test -out ./out
```

That command intentionally generates the Root CA, Intermediate CA and leaf private key inside one process so the earliest PKI experiments remain easy to reproduce.

In that legacy path, `out/root-ca.crt` is generated directly by `cmd/pki-server`. This is different from the Phase 5 API path, where `root-ca.crt` should be downloaded from `GET /ca/root`.

## Security notes

Generated keys, CSRs and certificates are ignored by Git.

Never commit:
- Root CA private keys
- Intermediate CA private keys
- leaf private keys
- runtime certificate material

The HTTP API is still an educational local service. It has no authentication, persistent database, authorization policy, rate limiting, audit log, KMS/HSM integration, or production-grade CA key protection.

Installing the lab Root CA into an operating-system trust store gives that CA broad trust on the local machine. Remove it after experiments if you no longer need it.

## Roadmap

```text
Phase 1  [done] Root CA -> Intermediate CA -> Leaf -> x509.Verify
Phase 2  [done] Local DNS server + TXT records + DNS-01 challenge
Phase 3  [done] Certificate Order HTTP API
Phase 4  [done] Trusted local HTTPS
Phase 5  [done] Client private key + CSR signing workflow
Phase 6  Persistent CA/order/certificate storage and lifecycle model
Phase 7  Renewal, revocation, CRL and OCSP experiments
Phase 8  ACME-compatible workflow experiments
```
