# Phase 8 — ACME protocol and certificate issuance

This phase adds an RFC 8555-style ACME surface on top of the existing persistent lab CA.

## Implemented

### Phase 8.1 protocol foundation

- ACME Directory
- fresh one-time Replay-Nonce values
- flattened JSON JWS parsing
- protected-header validation
- ES256 signature verification
- RS256 signature verification for lab compatibility
- JWK parsing for P-256 EC and RSA account keys
- RFC 7638-style JWK thumbprints
- account creation and lookup
- account `kid` authentication
- new Order creation for one DNS identifier
- Authorization resource with DNS-01 challenge token
- replayed nonce rejection

### Phase 8.2 issuance flow

- `POST /acme/challenge/{id}` performs a real TXT lookup through the local DNS server
- DNS-01 uses the standard value:

```text
keyAuthorization = token + "." + accountJWKThumbprint
TXT value        = base64url(SHA256(keyAuthorization))
```

- successful DNS-01 changes Authorization to `valid` and Order to `ready`
- `POST /acme/finalize/{id}` accepts a base64url DER CSR
- CSR signature and DNS SAN are validated
- CSR SAN must exactly match the ACME Order identifier
- the persistent Intermediate CA signs the CSR public key
- successful finalize changes the Order to `valid`
- the final Order response includes a certificate URL
- `POST /acme/cert/{id}` implements POST-as-GET certificate download
- certificate download returns `application/pem-certificate-chain` containing leaf + intermediate
- the leaf private key remains entirely client-owned

## Endpoints

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

The API server prints the directory URL at startup:

```text
ACME directory: http://127.0.0.1:8080/acme/directory
```

## Directory discovery

```bash
curl -s http://127.0.0.1:8080/acme/directory | jq
```

Expected shape:

```json
{
  "newNonce": "http://127.0.0.1:8080/acme/new-nonce",
  "newAccount": "http://127.0.0.1:8080/acme/new-account",
  "newOrder": "http://127.0.0.1:8080/acme/new-order"
}
```

## Replay nonce

```bash
curl -i -X HEAD http://127.0.0.1:8080/acme/new-nonce
```

The response includes:

```text
Replay-Nonce: <base64url-value>
Cache-Control: no-store
```

A nonce is single-use. Replaying the same signed request returns an ACME `badNonce` problem document and a fresh `Replay-Nonce` response header.

## JWS authentication model

ACME POST bodies use flattened JSON JWS:

```json
{
  "protected": "<base64url protected header>",
  "payload": "<base64url payload>",
  "signature": "<base64url signature>"
}
```

For `newAccount`, the protected header contains `jwk`. After account creation, the server returns the account URL in `Location`; later requests use that URL as `kid`.

## New Order and DNS-01

The lab currently supports exactly one DNS identifier per Order:

```json
{
  "identifiers": [
    { "type": "dns", "value": "hello.test" }
  ]
}
```

The Order starts as `pending` and exposes Authorization and Finalize URLs.

The Authorization resource exposes a DNS-01 token. A standard ACME client computes:

```text
keyAuthorization = token + "." + accountJWKThumbprint
TXT value        = base64url(SHA256(keyAuthorization))
```

Publish that value at:

```text
_acme-challenge.hello.test
```

For this lab, the TXT record can be written to the local authoritative DNS store through the existing helper API:

```bash
curl -s -X POST http://127.0.0.1:8080/dns/txt \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"_acme-challenge.hello.test",
    "values":["<computed-acme-dns-value>"]
  }'
```

When the client POSTs to the challenge URL, the ACME server queries the local DNS server at `127.0.0.1:1053` (or the configured DNS address). If the value matches, the challenge and Authorization become `valid`, and the Order becomes `ready`.

## Finalize and certificate download

The Finalize request carries a DER CSR encoded with base64url without padding:

```json
{
  "csr": "<base64url DER CSR>"
}
```

The server checks:

```text
CSR parses successfully
        +
CSR signature is valid
        +
CSR has exactly one DNS SAN
        +
DNS SAN == ACME Order domain
```

The persistent Intermediate CA then signs the CSR public key. The Order becomes `valid` and contains:

```json
{
  "status": "valid",
  "certificate": "http://127.0.0.1:8080/acme/cert/<id>"
}
```

A POST-as-GET to that URL returns:

```text
-----BEGIN CERTIFICATE-----
<leaf>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<intermediate>
-----END CERTIFICATE-----
```

The Root CA is not included in the served chain; it remains the trust anchor under:

```text
data/ca/root-ca.crt
```

## Automated protocol test

Run:

```bash
go test ./internal/acme -v
```

`TestACMEEndToEndIssuance` uses real cryptographic material and exercises:

```text
P-256 account key
   -> Replay-Nonce
   -> ES256 newAccount JWS
   -> newOrder
   -> Authorization
   -> publish DNS TXT
   -> challenge validation through UDP DNS
   -> Order ready
   -> client-generated CSR
   -> finalize
   -> persistent CA signing
   -> certificate POST-as-GET
   -> x509 chain verification
```

The separate nonce test proves that replaying an already-consumed nonce is rejected.

## Current state and limitations

The ACME issuance path is now end-to-end functional inside the lab, but several production-grade features remain intentionally out of scope:

- ACME accounts and ACME protocol Orders are currently in memory and disappear on API-server restart
- only one DNS identifier per Order is supported
- wildcard identifiers are not yet handled specially
- only DNS-01 is implemented
- challenge validation is synchronous rather than queued/background processing
- no account key rollover endpoint
- no ACME certificate revocation endpoint yet
- no External Account Binding
- no persistent nonce/account/order ACME repository
- no rate limits or authorization policy

The next practical compatibility test is to point a standard ACME client such as `acme.sh` at:

```text
http://127.0.0.1:8080/acme/directory
```

and observe which RFC 8555 compatibility gaps remain in a real client flow.
