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
- `GET /ca/root` exposes the local Root CA certificate
- End-to-end API test covering create -> TXT -> validate -> issue

Phase 3 is still a lab workflow: the CA currently generates the leaf private key and returns it in the issuance response. A later CSR phase will move private-key generation to the client, matching real-world CA behavior more closely.

### Phase 4: local trusted HTTPS

- Local HTTPS server using the issued `fullchain.pem` and leaf private key
- TLS 1.2+ configuration
- Browser-test page and `/healthz` endpoint
- Test proving Go TLS loads leaf + intermediate from `fullchain.pem`
- Local hosts mapping walkthrough
- Root CA trust-store walkthrough for macOS, Linux and Windows

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
   Leaf Certificate + Full Chain
          |
          v
     Local HTTPS Server :8443
          |
          v
      Browser / TLS Client
```

## Certificate chain

```text
Go PKI Lab Root CA              <- installed in local trust store
        |
        v
Go PKI Lab Intermediate CA      <- sent by HTTPS server
        |
        v
hello.test                      <- sent by HTTPS server
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

### 2. Publish the TXT record

```bash
curl -s -X POST http://127.0.0.1:8080/dns/txt \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"_acme-challenge.hello.test",
    "values":["<random-token>"]
  }'
```

Inspect the record through the API:

```bash
curl -s 'http://127.0.0.1:8080/dns/txt?name=_acme-challenge.hello.test'
```

Or query the local DNS server directly:

```bash
dig @127.0.0.1 -p 1053 TXT _acme-challenge.hello.test
```

### 3. Validate DNS-01

```bash
curl -s -X POST http://127.0.0.1:8080/orders/<order-id>/validate
```

The order should become `ready`. If the TXT record is missing or incorrect, validation returns HTTP `422` and the certificate is not issued.

### 4. Issue the certificate

```bash
curl -s -X POST http://127.0.0.1:8080/orders/<order-id>/issue
```

The response contains `certificate_pem`, `private_key_pem`, and `fullchain_pem`. Issuance before successful DNS validation returns HTTP `409`.

### 5. Download the Root CA

```bash
curl -s http://127.0.0.1:8080/ca/root -o root-ca.crt
```

## Phase 4: trusted browser HTTPS demo

The simplest Phase 4 path is to use the files produced by `cmd/pki-server`.

### 1. Generate the certificate chain

```bash
go run ./cmd/pki-server -domain hello.test -out ./out
```

Generated files:

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

`fullchain.pem` contains the leaf certificate followed by the intermediate CA certificate. The Root CA is intentionally not included in the TLS full chain because it belongs in the client's trust store.

### 2. Map the test domain to localhost

Add this line to your hosts file:

```text
127.0.0.1 hello.test
```

macOS / Linux:

```bash
sudo sh -c 'echo "127.0.0.1 hello.test" >> /etc/hosts'
```

Windows: edit `C:\Windows\System32\drivers\etc\hosts` as Administrator and add the same line.

Confirm:

```bash
ping hello.test
```

It should resolve to `127.0.0.1`.

### 3. Start the HTTPS server

```bash
go run ./cmd/https-server \
  -domain hello.test \
  -addr 127.0.0.1:8443 \
  -cert ./out/fullchain.pem \
  -key ./out/hello.test.key
```

Then test the TLS endpoint before trusting the Root CA:

```bash
curl --cacert ./out/root-ca.crt https://hello.test:8443/
```

You can also inspect the chain sent by the server:

```bash
openssl s_client \
  -connect hello.test:8443 \
  -servername hello.test \
  -CAfile ./out/root-ca.crt \
  -verify_return_error
```

The verification result should be `Verify return code: 0 (ok)`.

### 4. Trust the lab Root CA

Only trust this CA on a development machine. The holder of `root-ca.key` can issue certificates your machine will trust.

#### macOS

Install the Root CA into the System keychain as a trusted root:

```bash
sudo security add-trusted-cert \
  -d \
  -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ./out/root-ca.crt
```

You can also import `out/root-ca.crt` with Keychain Access and set **Trust -> When using this certificate -> Always Trust**.

To remove the test Root CA later:

```bash
sudo security delete-certificate \
  -c "Go PKI Lab Root CA" \
  /Library/Keychains/System.keychain
```

#### Debian / Ubuntu Linux

```bash
sudo cp ./out/root-ca.crt /usr/local/share/ca-certificates/go-pki-lab-root.crt
sudo update-ca-certificates
```

To remove it:

```bash
sudo rm /usr/local/share/ca-certificates/go-pki-lab-root.crt
sudo update-ca-certificates --fresh
```

#### Windows

Run an Administrator terminal:

```powershell
certutil -addstore -f Root .\out\root-ca.crt
```

Remove it later with the Certificates MMC (`certmgr.msc` / `certlm.msc`) or `certutil`.

### 5. Open the browser

Open:

```text
https://hello.test:8443/
```

The page should load without a certificate warning once all of the following are true:

```text
hello.test -> 127.0.0.1
       +
Leaf SAN contains hello.test
       +
HTTPS server sends leaf + intermediate
       +
Local trust store trusts Go PKI Lab Root CA
       =
Trusted HTTPS connection
```

Modern browsers do not necessarily display a green lock icon anymore; browser UI has changed over time. The important result is that the page opens normally with no certificate/privacy warning and the certificate viewer shows a valid chain to `Go PKI Lab Root CA`.

### Optional: use the standard HTTPS port

Port `8443` avoids privileged-port requirements. If you specifically want `https://hello.test/` without a port number, run the server on port `443` using an appropriate local privilege/port-forwarding setup:

```bash
go run ./cmd/https-server \
  -domain hello.test \
  -addr 127.0.0.1:443 \
  -cert ./out/fullchain.pem \
  -key ./out/hello.test.key
```

Avoid running more of your development environment as root than necessary.

## Verify certificate files with OpenSSL

```bash
openssl verify \
  -CAfile out/root-ca.crt \
  -untrusted out/intermediate-ca.crt \
  out/hello.test.crt
```

## Security notes

Generated PKI material is ignored by Git. Never commit Root CA, Intermediate CA, or leaf private keys.

The API implementation is intentionally local and educational. It currently has no authentication, authorization, persistent database, rate limiting, audit log, HSM/KMS integration, or production-grade key protection.

Installing the lab Root CA into an operating-system trust store gives that CA broad trust on the local machine. Remove it after experiments if you no longer need it, and never distribute `root-ca.key`.

## Roadmap

```text
Phase 1  [done] Root CA -> Intermediate CA -> Leaf -> x509.Verify
Phase 2  [done] Local DNS server + TXT records + DNS-01 challenge
Phase 3  [done] Certificate Order HTTP API + explicit challenge publication
Phase 4  [done] Local HTTPS server + hosts mapping + browser trust walkthrough
Phase 5  CSR workflow: client-generated private keys and CSRs
Phase 6  Persistent CA/order storage and certificate lifecycle
Phase 7  Renewal, revocation, CRL and OCSP experiments
Phase 8  ACME-compatible workflow experiments
```
