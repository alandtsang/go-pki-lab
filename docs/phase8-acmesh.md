# Phase 8.3 — acme.sh compatibility

This phase validates the ACME server with a real external ACME client instead of only the Go protocol tests.

The target client is `acme.sh` using the local ACME directory:

```text
http://127.0.0.1:8080/acme/directory
```

## What this phase adds

- a custom `acme.sh` DNS API hook: `dns_go_pki_lab`
- automatic TXT publication through the local `/dns/txt` API
- automatic TXT cleanup through `DELETE /dns/txt`
- a repeatable single-domain `acme.sh` issuance command
- local-DNS-specific `--dnssleep` guidance

The current ACME server supports one DNS identifier per Order.

## 1. Start go-pki-lab

```bash
go run ./cmd/api-server
```

Expected endpoints:

```text
ACME directory : http://127.0.0.1:8080/acme/directory
HTTP API       : http://127.0.0.1:8080
Local DNS      : 127.0.0.1:1053
```

Check the directory:

```bash
curl -s http://127.0.0.1:8080/acme/directory | jq
```

## 2. Install the local DNS hook into acme.sh

Assuming the normal acme.sh installation directory is `~/.acme.sh`:

```bash
cp ./scripts/acme.sh/dns_go_pki_lab.sh \
  ~/.acme.sh/dnsapi/dns_go_pki_lab.sh
```

The hook calls:

```text
POST   http://127.0.0.1:8080/dns/txt
DELETE http://127.0.0.1:8080/dns/txt
```

You can override the API base URL:

```bash
export GO_PKI_LAB_API=http://127.0.0.1:8080
```

## 3. Issue a certificate with acme.sh

Use exactly one domain for the current lab stage:

```bash
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

Why `--dnssleep 1` matters here:

```text
acme.sh default DNS API mode
        |
        +--> publish TXT through hook
        |
        `--> verify TXT using public DNS/DoH
```

But go-pki-lab serves TXT only from:

```text
127.0.0.1:1053
```

so public resolvers cannot see the record. Supplying `--dnssleep` makes acme.sh wait instead of performing its normal public DNS propagation checks. The go-pki-lab ACME server itself then validates the TXT record against the local DNS server.

## 4. Observe the TXT lifecycle

During issuance, the hook sends approximately:

```json
{
  "name": "_acme-challenge.hello.test",
  "values": ["<dns-01-value>"]
}
```

You can inspect the record while issuance is running:

```bash
curl -s \
  'http://127.0.0.1:8080/dns/txt?name=_acme-challenge.hello.test' \
  | jq
```

Or query the local DNS server directly:

```bash
dig @127.0.0.1 -p 1053 TXT _acme-challenge.hello.test
```

After successful issuance, `acme.sh` calls `dns_go_pki_lab_rm`, which removes the local TXT entry through:

```text
DELETE /dns/txt
```

## 5. Verify the issued certificate

`acme.sh` prints the generated certificate/key paths at the end of a successful run.

The issued chain should terminate at the persistent go-pki-lab Root CA:

```text
data/ca/root-ca.crt
```

If the full chain produced by acme.sh is stored in `<fullchain-file>`, inspect it with:

```bash
openssl crl2pkcs7 \
  -nocrl \
  -certfile <fullchain-file> \
| openssl pkcs7 -print_certs -noout
```

For direct leaf verification, use the persistent Root CA and Intermediate CA:

```bash
openssl verify \
  -CAfile ./data/ca/root-ca.crt \
  -untrusted ./data/ca/intermediate-ca.crt \
  <leaf-cert-file>
```

Expected result:

```text
<leaf-cert-file>: OK
```

## Troubleshooting

### `Cannot find DNS API hook`

Confirm:

```bash
ls ~/.acme.sh/dnsapi/dns_go_pki_lab.sh
```

and use:

```text
--dns dns_go_pki_lab
```

### acme.sh waits for public DNS propagation

Make sure the command includes:

```text
--dnssleep 1
```

The local authoritative DNS server is intentionally not published to the Internet.

### ACME `badNonce`

The server uses one-time Replay-Nonce values. A replayed signed request is rejected and the error response returns a fresh nonce. Run with:

```text
--debug 2
```

to inspect the retry behavior.

### Challenge becomes `invalid`

Check the exact TXT value seen by the local server:

```bash
dig @127.0.0.1 -p 1053 TXT _acme-challenge.hello.test
```

The value must equal:

```text
base64url(SHA256(token + "." + accountJWKThumbprint))
```

## Current compatibility boundary

Phase 8.3 intentionally focuses on the common single-domain DNS-01 issuance path.

Still to improve:

- ACME Account persistence
- ACME Order/Authorization persistence
- multi-SAN Orders
- wildcard identifiers
- ACME certificate revocation endpoint
- account key rollover (`keyChange`)
- retry/polling behavior for asynchronous validation and issuance
- richer RFC 8555 interoperability tests
