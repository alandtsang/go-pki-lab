# Phase 8.6 — ACME renewal and certificate rotation

ACME does not define a dedicated renewal endpoint. A renewal is a normal new Order for the same identifier, followed by a new authorization/finalize/certificate flow.

For go-pki-lab that means:

```text
existing certificate A for hello2.test
        |
        | acme.sh --renew
        v
new ACME Order
        |
        v
DNS-01
        |
        v
new CSR
        |
        v
new certificate B
```

Certificate B must have a different serial number from certificate A. Certificate A remains part of the historical certificate state and is not overwritten.

## Automated test

Run:

```bash
go test ./internal/acme -run TestACMERenewalKeepsCertificateHistoryIndependent -v
go test ./...
```

The test verifies:

```text
same account
same domain
certificate A serial != certificate B serial
certificate A revoked
certificate B remains good
server restart
both certificate states are still recoverable
```

## Real acme.sh renewal

Use a domain that currently has a valid acme.sh certificate, for example `hello2.test`.

Capture the current serial first:

```bash
OLD_SERIAL=$(openssl x509 \
  -in ~/.acme.sh/hello2.test_ecc/hello2.test.cer \
  -noout -serial | cut -d= -f2)

echo "$OLD_SERIAL"
```

Renew through the same local ACME server:

```bash
export GO_PKI_LAB_API=http://127.0.0.1:8080

~/.acme.sh/acme.sh --renew \
  --server http://127.0.0.1:8080/acme/directory \
  -d hello2.test \
  --ecc \
  --force \
  --debug 2
```

The DNS API configuration stored by acme.sh for the existing domain should be reused. The local API server and `dns_go_pki_lab` hook must still be available.

After renewal, capture the new serial:

```bash
NEW_SERIAL=$(openssl x509 \
  -in ~/.acme.sh/hello2.test_ecc/hello2.test.cer \
  -noout -serial | cut -d= -f2)

echo "$NEW_SERIAL"
```

Verify rotation:

```bash
test "$OLD_SERIAL" != "$NEW_SERIAL" \
  && echo "certificate rotated" \
  || echo "serial did not change"
```

Expected:

```text
certificate rotated
```

## Persisted history

The ACME state file should now contain more than one Order/issuance record for the same domain:

```bash
jq '[
  .orders as $orders
  | .issuance
  | to_entries[]
  | select($orders[.key].domain == "hello2.test")
  | {
      order_id: .key,
      order_status: $orders[.key].status,
      revoked_at: .value.revoked_at,
      revocation_reason: .value.revocation_reason
    }
]' ./data/acme/state.json
```

A renewal does not automatically revoke the previous certificate. Both certificates may remain valid until the older one expires or is explicitly revoked.

This is intentional and matches the separation between:

```text
ACME Order lifecycle
certificate lifecycle
```

If the old certificate is explicitly revoked later, the new certificate must remain good and keep a different serial.

## Restart behavior

After renewal, restart the API server with the same `data` directory:

```bash
go run ./cmd/api-server
```

The ACME Account count should remain stable while Order/issuance history increases:

```bash
jq '{
  accounts: (.accounts | length),
  orders: (.orders | length),
  issuance: (.issuance | length)
}' ./data/acme/state.json
```

The important properties are:

```text
same ACME Account survives restart
new renewal Order is persisted
new certificate serial is distinct
old certificate history is retained
revocation state is isolated per certificate
```
