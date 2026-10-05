# Phase 9.8: Notification and Alert Sink

Phase 9.8 turns the Phase 9.7 alert lifecycle into durable notification deliveries.
Monitoring remains independent of external notification systems: alert transitions enqueue
persistent delivery records, and a separate dispatcher sends them asynchronously.

## Architecture

```text
Monitoring State Change
        |
        v
      Alert
 firing / resolved
        |
        v
NotificationDelivery
 pending / delivering / failed / delivered
        |
        v
 AlertSink
   |-- log
   `-- webhook
```

The idempotency key is logically `(alert_id, event, sink)`. Repeated probes that keep the
same alert state do not create duplicate deliveries. A firing alert creates one `firing`
delivery per configured sink. When the alert resolves, one `resolved` delivery per sink is
created.

Delivery contains an immutable message snapshot so a delayed firing notification cannot
accidentally use the later resolved message.

## Persistence

Delivery state is stored under:

```text
data/notification-deliveries/<delivery-id>.json
```

Each delivery records:

```text
id
alert_id
target_id
domain
alert_type
event
message
sink
status
attempts
last_error
created_at
updated_at
delivered_at
```

A delivery left in `delivering` by an interrupted process is loaded as retryable `failed`
on restart.

## Sinks

The log sink is enabled by default and writes alert notifications to the API server log.

A generic JSON webhook sink can be enabled with:

```sh
-notification-webhook-url http://127.0.0.1:9090/alerts
```

Webhook requests use `POST` with `Content-Type: application/json`. Any 2xx response is
accepted as success.

Example payload:

```json
{
  "alert_id": "...",
  "target_id": "...",
  "domain": "hello2.test",
  "alert_type": "serial_mismatch",
  "event": "firing",
  "message": "target ... monitoring status changed from healthy to serial_mismatch",
  "created_at": "..."
}
```

## Dispatcher

The dispatcher runs every 10 seconds by default:

```text
-notification-interval 10s
```

Failed deliveries remain retryable and are attempted again on the next dispatcher run.
A delivery is claimed as `delivering` before external I/O so concurrent manual/background
dispatchers do not send the same record at the same time.

Disable the background dispatcher with a non-positive interval and invoke it manually:

```sh
curl -s -X POST http://127.0.0.1:8080/notification-dispatcher/run | jq
```

## APIs

```sh
curl -s 'http://127.0.0.1:8080/notification-deliveries' | jq
curl -s 'http://127.0.0.1:8080/notification-deliveries?status=failed' | jq
curl -s 'http://127.0.0.1:8080/notification-deliveries?alert_id=ALERT_ID' | jq
curl -s http://127.0.0.1:8080/notification-deliveries/DELIVERY_ID | jq
curl -s -X POST http://127.0.0.1:8080/notification-dispatcher/run | jq
```

## Local webhook smoke test

Start the included receiver:

```sh
go run ./cmd/webhook-receiver -addr 127.0.0.1:9090
```

Start the platform:

```sh
go run ./cmd/api-server \
  -data-dir ./data \
  -monitor-interval 5s \
  -monitor-timeout 2s \
  -monitor-expiring-before-days 30 \
  -notification-interval 2s \
  -notification-webhook-url http://127.0.0.1:9090/alerts
```

Create a monitoring drift as in Phase 9.6. The receiver should log a JSON payload with:

```text
event = firing
alert_type = serial_mismatch
```

After restoring the correct online certificate, it should receive a second payload:

```text
event = resolved
alert_type = serial_mismatch
```

Verify delivery state:

```sh
curl -s 'http://127.0.0.1:8080/notification-deliveries' | jq
```

Expected successful records have:

```text
status = delivered
attempts >= 1
delivered_at != null
```

## Failure and retry smoke test

Stop `webhook-receiver`, create a new alert transition, then run the dispatcher. The webhook
delivery becomes `failed` and records `last_error`. Restart the receiver and invoke the
dispatcher again; the same delivery record is retried and becomes `delivered` with an
incremented attempt count.

## Verification

```sh
gofmt -w \
  internal/platform/service.go \
  internal/platform/incident.go \
  internal/platform/notification.go \
  internal/platform/notification_test.go \
  internal/persistence/notification_repository.go \
  internal/persistence/notification_repository_test.go \
  internal/api/notification.go \
  cmd/api-server/main.go \
  cmd/webhook-receiver/main.go

go test ./...
```

Go remains `1.24.0`.
