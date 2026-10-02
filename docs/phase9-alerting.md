# Phase 9.7: Alerting and incident/event model

Phase 9.7 converts certificate-monitoring state changes into durable events and alert lifecycles.

## Model

```text
Deployment Target
      |
      v
Monitoring Probe
      |
      v
old status -> new status
      |
      +--> Event (immutable audit record)
      |
      `--> Alert lifecycle
             firing
               |
               v
             resolved
```

A repeated probe with the same status does not create another Event or another Alert. This prevents a short monitoring interval from creating notification storms.

Examples:

```text
healthy -> serial_mismatch
  Event: healthy -> serial_mismatch
  Alert: serial_mismatch / firing

serial_mismatch -> serial_mismatch
  no new Event
  existing firing Alert is reused

serial_mismatch -> healthy
  Event: serial_mismatch -> healthy
  Alert: serial_mismatch / resolved

serial_mismatch -> tls_unreachable
  Event: serial_mismatch -> tls_unreachable
  serial_mismatch Alert -> resolved
  tls_unreachable Alert -> firing
```

When upgrading from Phase 9.6, an abnormal MonitoringState may already be persisted without an Alert. The first same-status probe bootstraps one firing Alert without manufacturing a duplicate state-change Event.

## Persistence

```text
data/events/<event-id>.json
data/alerts/<alert-id>.json
```

Events are append-only audit records. Alerts are mutable lifecycle records and are updated in place when resolved.

## Event fields

```text
id
target_id
domain
previous_status
current_status
occurred_at
message
```

## Alert fields

```text
id
target_id
domain
type
status                firing | resolved
first_seen_at
last_seen_at
resolved_at
occurrences
last_message
```

The current phase uses one Alert per abnormal incident. `occurrences` starts at 1; repeated identical probes are deliberately not counted as new incidents.

## APIs

List all events:

```sh
curl -s http://127.0.0.1:8080/events | jq
```

Filter events by target:

```sh
curl -s 'http://127.0.0.1:8080/events?target_id=TARGET_ID' | jq
```

List all alerts:

```sh
curl -s http://127.0.0.1:8080/alerts | jq
```

Only active alerts:

```sh
curl -s 'http://127.0.0.1:8080/alerts?status=firing' | jq
```

Resolved alerts:

```sh
curl -s 'http://127.0.0.1:8080/alerts?status=resolved' | jq
```

Filter by target:

```sh
curl -s 'http://127.0.0.1:8080/alerts?target_id=TARGET_ID' | jq
```

Read one alert:

```sh
curl -s http://127.0.0.1:8080/alerts/ALERT_ID | jq
```

## Runtime validation

Start the HTTPS target and API server as in Phase 9.6. Confirm the target is healthy, then replace the online certificate with the drift certificate used in the Phase 9.6 manual test.

Probe:

```sh
curl -s -X POST \
  http://127.0.0.1:8080/deployment-targets/TARGET_ID/probe | jq
```

Expected monitoring state:

```text
serial_mismatch
```

Now query firing alerts:

```sh
curl -s 'http://127.0.0.1:8080/alerts?status=firing' | jq
```

Expected:

```text
type   = serial_mismatch
status = firing
```

Probe repeatedly while the same drift remains. The event and firing-alert counts must remain stable.

Restore the correct certificate and probe again. The existing serial-mismatch Alert should become `resolved`, with `resolved_at` populated, and a recovery Event should be appended.

## Verification

```sh
gofmt -w \
  internal/platform/service.go \
  internal/platform/monitoring.go \
  internal/platform/incident.go \
  internal/platform/incident_test.go \
  internal/persistence/incident_repository.go \
  internal/persistence/incident_repository_test.go \
  internal/api/incident.go \
  cmd/api-server/main.go

go test ./...
```

Phase 9.7 intentionally stops at durable incident state and query APIs. Notification delivery (Feishu, Slack, webhook, email), retry/backoff, silencing, acknowledgement, escalation, and alert routing belong to later phases.
