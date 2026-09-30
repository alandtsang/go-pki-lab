# Phase 8.4 — ACME persistence and restart recovery

Phase 8.4 persists ACME protocol state under the same `data` directory as the CA.

Persisted:

```text
ACME accounts
ACME account JWK + thumbprint
ACME orders
challenge token + DNS-01 value
order status
challenge status
authorization status
validation timestamp
ACME-issued PEM certificate chain
```

Intentionally not persisted:

```text
Replay-Nonce values
local DNS TXT records
```

Nonces are short-lived, single-use protocol values and should be regenerated after restart. Local TXT records remain ephemeral lab DNS state.

## Storage layout

```text
data/
├── ca/
│   ├── root-ca.crt
│   ├── root-ca.key
│   ├── intermediate-ca.crt
│   └── intermediate-ca.key
├── orders/
│   └── <platform-order-id>.json
└── acme/
    └── state.json
```

`state.json` is written atomically through a temporary file and rename. The file permission is `0600`.

The ACME server stores only the account **public JWK**. The ACME account private key remains in the client, such as acme.sh.

## Important migration note

Accounts created before Phase 8.4 were never persisted by the server, so they cannot be restored retroactively.

If acme.sh still has an old `kid` from a pre-8.4 run, the first request after upgrading may fail with:

```text
urn:ietf:params:acme:error:accountDoesNotExist
```

Do not delete the CA or previously issued certificates. Re-register the existing acme.sh account key against the same local ACME directory:

```bash
~/.acme.sh/acme.sh --register-account \
  --server http://127.0.0.1:8080/acme/directory \
  --accountkeylength ec-256 \
  --debug 2
```

This sends `newAccount` using the existing account public JWK. The server creates/persists a new Account and acme.sh replaces its cached account URL (`kid`) with the newly returned `Location` value.

Verify the persisted account exists:

```bash
jq '{
  accounts: (.accounts | length),
  account_ids: (.accounts | keys)
}' ./data/acme/state.json
```

After this one-time migration, normal `--issue` calls should reuse the persisted account across server restarts.

## Automated tests

```bash
go test ./internal/acme -v
go test ./...
```

Persistence tests cover:

```text
FileStateStore round trip
Account JWK/public-key reconstruction
Order status restoration
Issuance lifecycle restoration
Certificate-chain restoration
Replay-Nonce remains non-persistent
```

## Manual restart test with acme.sh

Start from a running server:

```bash
go run ./cmd/api-server
```

For a fresh Phase 8.4 installation, or after performing the migration step above, issue a certificate through the existing local DNS hook:

```bash
export GO_PKI_LAB_API=http://127.0.0.1:8080

~/.acme.sh/acme.sh --issue \
  --server http://127.0.0.1:8080/acme/directory \
  --dns dns_go_pki_lab \
  --dnssleep 1 \
  -d hello.test \
  --keylength ec-256 \
  --accountkeylength ec-256 \
  --force \
  --debug 2
```

After a successful issue, inspect persisted state:

```bash
jq '{
  accounts: (.accounts | length),
  orders: (.orders | length),
  issuance: (.issuance | length)
}' ./data/acme/state.json
```

You should see at least one account and one order.

Stop the API server and restart it using the same data directory:

```bash
go run ./cmd/api-server
```

The startup output includes:

```text
ACME state: data/acme/state.json
```

Now use the same acme.sh installation/account to issue another domain:

```bash
~/.acme.sh/acme.sh --issue \
  --server http://127.0.0.1:8080/acme/directory \
  --dns dns_go_pki_lab \
  --dnssleep 1 \
  -d hello2.test \
  --keylength ec-256 \
  --accountkeylength ec-256 \
  --force \
  --debug 2
```

The important result is that the existing account `kid` remains accepted after restart. The account count should remain stable while the order count increases:

```bash
jq '{
  accounts: (.accounts | length),
  orders: (.orders | length),
  issuance: (.issuance | length)
}' ./data/acme/state.json
```

Conceptually:

```text
acme.sh account key
       |
       | kid
       v
ACME Account A
       |
       v
 data/acme/state.json
       |
   server restart
       |
       v
restore JWK -> parse public key
       |
       v
verify new JWS signed by same account key
       |
       v
create new Order without re-registering Account A
```

## Current persistence boundary

This phase persists protocol state but does not yet persist every operational subsystem. In particular, local DNS TXT records disappear on restart. A pending DNS-01 challenge therefore needs its TXT record to be published again after restart.

For an already issued ACME Order, the certificate chain is persisted and remains available to the ACME certificate resource after restart, as long as the service is restarted at the same externally visible ACME base URL.
