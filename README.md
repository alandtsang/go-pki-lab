# go-pki-lab

A Go-based local PKI and certificate authority lab for learning and testing certificate issuance, DNS-01 validation, certificate chains, and TLS.

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
- Tests proving validation fails without the TXT record and succeeds after publication

The Phase 2 CLI automatically publishes the generated TXT record into the local DNS store so the complete flow can be demonstrated in one command. A later API phase will separate the CA from the DNS client so the user explicitly publishes the challenge.

## Flow

```text
Certificate Order
      |
      v
status = pending
      |
      v
Generate DNS-01 Challenge
      |
      v
_acme-challenge.hello.test TXT <token>
      |
      v
Local UDP DNS Server :1053
      |
      v
DNS TXT Query / Validation
      |
      v
status = ready
      |
      v
Intermediate CA issues leaf certificate
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

## Run

Requirements: Go 1.23+.

```bash
go mod tidy
go test ./...
go run ./cmd/pki-server -domain hello.test -out ./out
```

The local DNS server listens on `127.0.0.1:1053` by default. Override it with:

```bash
go run ./cmd/pki-server \
  -domain hello.test \
  -dns-addr 127.0.0.1:2053 \
  -out ./out
```

Expected flow:

```text
certificate order created
domain: hello.test
order status: pending
DNS-01 record: _acme-challenge.hello.test TXT "<random-token>"
local DNS server: 127.0.0.1:1053
DNS-01 validation: OK
order status: ready
certificate issued successfully
order status: valid
output: ./out
chain verification: OK
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

`fullchain.pem` contains the leaf certificate followed by the intermediate CA certificate. The Root CA is intentionally not included in the TLS full chain; it is installed separately into the local trust store when testing browser trust.

## Verify with OpenSSL

```bash
openssl verify \
  -CAfile out/root-ca.crt \
  -untrusted out/intermediate-ca.crt \
  out/hello.test.crt
```

## Security

Generated PKI material is ignored by Git. Never commit Root CA, Intermediate CA, or leaf private keys.

## Roadmap

```text
Phase 1  [done] Root CA -> Intermediate CA -> Leaf -> x509.Verify
Phase 2  [done] Local DNS server + TXT records + DNS-01 challenge
Phase 3  Certificate Order HTTP API + explicit challenge publication
Phase 4  Local HTTPS server + hosts mapping + browser trust walkthrough
Phase 5  Persistent CA/order storage and certificate lifecycle
Phase 6  Renewal, revocation, CRL and OCSP experiments
Phase 7  ACME-compatible workflow experiments
```
