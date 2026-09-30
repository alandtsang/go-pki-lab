# Phase 8.1 — ACME protocol foundation

This phase introduces the RFC 8555 protocol surface without replacing the existing certificate-platform API.

Implemented:

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
- Authorization resource with a DNS-01 challenge token
- replayed nonce rejection

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

For `newAccount`, the protected header contains `jwk`:

```json
{
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "nonce": "...",
  "url": "http://127.0.0.1:8080/acme/new-account"
}
```

After account creation, the server returns the account URL in `Location`. Later requests use that URL as `kid` instead of embedding `jwk`.

## New Order

The current lab supports exactly one DNS identifier per Order:

```json
{
  "identifiers": [
    { "type": "dns", "value": "hello.test" }
  ]
}
```

The response contains an Authorization URL and Finalize URL:

```json
{
  "status": "pending",
  "identifiers": [
    { "type": "dns", "value": "hello.test" }
  ],
  "authorizations": [
    "http://127.0.0.1:8080/acme/authz/<id>"
  ],
  "finalize": "http://127.0.0.1:8080/acme/finalize/<id>"
}
```

The Authorization resource exposes a DNS-01 token. Internally, the server also computes the standard DNS-01 TXT value:

```text
keyAuthorization = token + "." + accountJWKThumbprint
TXT value        = base64url(SHA256(keyAuthorization))
```

## Automated tests

```bash
go test ./internal/acme -v
```

The tests use a real P-256 account key and ES256 JWS signatures to cover:

```text
Directory
   -> Nonce
   -> newAccount
   -> account Location/kid
   -> newOrder
   -> Authorization
```

A separate test proves that replaying an already-consumed nonce is rejected.

## Current boundary

Phase 8.1 intentionally stops before certificate issuance through ACME.

Not wired yet:

```text
POST /acme/challenge/{id}
POST /acme/finalize/{id}
POST /acme/cert/{id}
```

The next step is to connect those resources to the existing platform:

```text
ACME DNS-01 challenge
        |
        v
local DNS :1053 validation
        |
        v
ACME Order ready
        |
        v
Finalize CSR
        |
        v
platform.Service
        |
        v
persistent Intermediate CA
        |
        v
certificate chain
```

Until that wiring is complete, standard ACME clients can discover the server and exercise account/order protocol behavior, but they cannot yet complete issuance.
