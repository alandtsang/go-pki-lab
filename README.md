# go-pki-lab

A Go-based local PKI and certificate authority lab for learning and testing certificate issuance, DNS-01 validation, certificate chains, and TLS.

> This repository is for local research and testing. Do not use generated CA private keys in production.

## Milestone 1: local certificate chain

The current version implements:

- Self-signed Root CA
- Intermediate CA signed by the Root CA
- TLS leaf certificate signed by the Intermediate CA
- SAN (`DNSNames`) for the requested domain
- `fullchain.pem` containing leaf + intermediate certificates
- Local chain verification with Go `crypto/x509`
- Private keys written with restrictive file permissions

The next milestone will add a local DNS server and DNS-01 style TXT challenge before certificate issuance.

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
go run ./cmd/pki-server -domain hello.test -out ./out
```

Expected output:

```text
certificate issued successfully
domain: hello.test
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

`fullchain.pem` contains:

```text
hello.test certificate
        +
intermediate CA certificate
```

The Root CA is intentionally not included in the TLS full chain; it is installed separately into the local trust store when testing browser trust.

## Inspect the certificates

```bash
openssl x509 -in out/root-ca.crt -text -noout
openssl x509 -in out/intermediate-ca.crt -text -noout
openssl x509 -in out/hello.test.crt -text -noout
```

Verify with OpenSSL:

```bash
openssl verify \
  -CAfile out/root-ca.crt \
  -untrusted out/intermediate-ca.crt \
  out/hello.test.crt
```

## Security

Generated PKI material is ignored by Git. In particular, never commit:

- Root CA private keys
- Intermediate CA private keys
- Leaf private keys
- Runtime certificate output directories

## Roadmap

```text
Phase 1  Root CA -> Intermediate CA -> Leaf -> x509.Verify
Phase 2  Local DNS server + TXT records + DNS-01 challenge
Phase 3  Certificate Order API and issuance state machine
Phase 4  Local HTTPS server and browser trust walkthrough
Phase 5  Renewal, revocation, CRL and OCSP experiments
Phase 6  ACME-compatible workflow experiments
```
