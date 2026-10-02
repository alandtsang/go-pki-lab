# Phase 9.6: Certificate monitoring and drift detection

The API server probes each enabled Deployment Target on startup and every minute.
Each scan uses a fresh TLS connection to the target's `address` (`host:port`),
with SNI and hostname checks using its managed `domain`. The expected serial is
resolved from the domain's Certificate Instance Current Certificate after the
handshake, including certificates supplied by the ACME state source.

Monitoring only observes: it does not write certificate/key files, create jobs,
change job completion state, or alter Phase 9.5 TLS hot reload behavior.

## Configuration

```sh
go run ./cmd/api-server -data-dir ./data \
  -monitor-interval 1m \
  -monitor-timeout 5s \
  -monitor-expiring-before-days 30
```

`-monitor-expiring-before-days` is the preferred expiry-warning setting. It uses
an integer number of days, so `30` means 30 days. Zero disables advance expiry
warnings.

The older duration flag is still accepted for compatibility:

```sh
-monitor-expiring-before 720h
```

Go's `time.Duration` parser does not support a `d` suffix, so values such as
`30d` are invalid. If the legacy duration flag is explicitly set to a positive
value, it overrides `-monitor-expiring-before-days`.

A non-positive interval disables background scans; manual probes remain available.
Timeout must be positive; the expiry window must be non-negative. Scans run
sequentially without overlapping within the background worker. Each target has a
bounded connection/handshake timeout. Shutdown cancels pending background probes.
Disabled targets are skipped and retain their previous observation. A failed probe
does not prevent probing subsequent targets.

## APIs

```sh
curl http://127.0.0.1:8080/deployment-targets/TARGET_ID/monitoring
curl -X POST http://127.0.0.1:8080/deployment-targets/TARGET_ID/probe
curl -X POST http://127.0.0.1:8080/certificate-monitor/run
```

Target GET/list responses also include `monitoring`. The state contains `status`,
`expected_serial`, `online_serial`, `checked_at`, `not_before`, `not_after`, and
`last_error` when applicable. Before the first probe, status is empty and timestamps
are zero. Read `checked_at` to assess freshness; stored observations are snapshots,
not a guarantee of present health. A scan returns states/errors keyed by target ID
and a list of skipped targets. A probe returns 404 for an unknown target, 409 for
a disabled target, and 500 on internal/persistence failure. Network failure is a
successful observation with status `tls_unreachable`, returned as HTTP 200.

## Status precedence

When multiple faults coexist, the first applicable status wins:

| Status | Meaning |
| --- | --- |
| `tls_unreachable` | Connection/handshake failed, timed out, or no peer certificate |
| `certificate_expired` | Online leaf's expiry has been reached |
| `hostname_mismatch` | Online leaf does not cover the target domain |
| `serial_mismatch` | Online serial differs from Current Serial, no active Current Certificate exists, or online certificate is not yet valid |
| `certificate_expiring` | Matching certificate expires within the configured window |
| `healthy` | Matching serial, hostname, and validity outside the warning window |

For a renewal smoke test, observe `healthy`, issue a newer Current Certificate
while leaving the old certificate online, and manually probe to see
`serial_mismatch`. Complete the existing deployment executor flow and probe again:
expect `healthy` (or `certificate_expiring` for short-lived lab certificates).

The probe deliberately inspects the peer certificate even when expired or issued
by the private lab CA. It checks identity and validity explicitly; `healthy` does
not assert chain trust, revocation, or matching certificate public keys. Monitoring
uses the existing address and domain rather than accepting arbitrary probe URLs.
Like the existing API, these endpoints are intended for the local lab; keep access
restricted to trusted operators.

The latest state is stored atomically in the existing
`data/deployment-targets/<id>.json`. Old target files load with an empty state;
no migration is required. Save failures leave the previous in-memory observation
intact. Concurrent probes cannot replace a newer recorded observation with an
older one. History/alert delivery and automatic remediation are outside this phase.

## Verification

```sh
gofmt -w internal/platform/monitoring*.go internal/platform/deployment.go \
  internal/api/deployment.go internal/api/monitoring_test.go \
  internal/persistence/deployment_repository_test.go \
  internal/tlsserver/server_test.go cmd/api-server/main.go
go test ./...
```

Tests cover all six statuses over real TLS handshakes, serial normalization,
renewal drift/recovery, persistence round trip and failure, disabled targets,
handshake timeout, cancellation, periodic scans, API responses, and Phase 9.5
fullchain and certificate reload on a new handshake. Go remains `1.24.0`.
