# Phase 9.9: Job lease, heartbeat, and stale recovery

Phase 9.9 makes renewal and deployment jobs recoverable when an executor crashes after claiming work.

## State model

```text
waiting_for_client
       |
       | claim
       v
    running
       |
       | heartbeat extends lease
       |
       +----------> completed
       |
       +----------> failed
       |
       | lease expires
       v
job recovery
   |        |
   |        +--> attempts >= max_attempts -> failed
   |
   +--> waiting_for_client
```

Both RenewalJob and DeploymentJob now persist:

```text
claimed_at
claimed_by
heartbeat_at
lease_expires_at
attempts
max_attempts
```

Old persisted running jobs from earlier phases have no lease. They are intentionally treated as stale and recovered on the first recovery scan.

## Server configuration

Defaults:

```text
job lease duration   30s
job max attempts     3
job recovery scan    10s
```

Example:

```sh
go run ./cmd/api-server \
  -job-lease-duration 30s \
  -job-max-attempts 3 \
  -job-recovery-interval 10s
```

A non-positive recovery interval disables the background recovery worker. Manual recovery remains available.

## Heartbeat APIs

```text
POST /renewal-jobs/{id}/heartbeat
POST /deployment-jobs/{id}/heartbeat
```

Body:

```json
{"client_id":"executor-a"}
```

The heartbeat is accepted only while the job is running, the client owns the job, and the existing lease has not already expired.

The renewal and deployment executors send heartbeats every 10 seconds by default:

```sh
go run ./cmd/renewal-executor -heartbeat-interval 10s
go run ./cmd/deployment-executor -heartbeat-interval 10s
```

The heartbeat interval should remain comfortably shorter than the server lease duration.

## Recovery API

```sh
curl -s -X POST http://127.0.0.1:8080/job-recovery/run | jq
```

Example result:

```json
{
  "recovered_renewal_jobs": ["..."],
  "failed_renewal_jobs": [],
  "recovered_deployment_jobs": ["..."],
  "failed_deployment_jobs": []
}
```

A stale job below max attempts is requeued:

```text
running
-> waiting_for_client
claimed_by = ""
heartbeat_at = null
lease_expires_at = null
last_error = "lease expired; job requeued"
```

The next claim increments attempts.

When attempts reaches max_attempts and that lease expires:

```text
running
-> failed
last_error = "lease expired after N attempt(s)"
```

Explicit executor failures remain terminal failures. Phase 9.9 retries executor loss, not deterministic business errors. A job that exhausts max_attempts also blocks automatic recreation of the same renewal work or deployment target+serial; operator intervention is required before trying again.

## Manual crash test

For a fast test, start the API server with a short lease:

```sh
go run ./cmd/api-server \
  -job-lease-duration 10s \
  -job-max-attempts 3 \
  -job-recovery-interval 2s
```

Claim a waiting job manually and do not heartbeat:

```sh
curl -s -X POST \
  http://127.0.0.1:8080/renewal-jobs/JOB_ID/claim \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"crash-test"}' | jq
```

Observe:

```sh
curl -s http://127.0.0.1:8080/renewal-jobs/JOB_ID | jq
```

After lease expiry plus a recovery scan the job should return to `waiting_for_client`. Claim it again and verify `attempts` increments.

## Verification

```sh
gofmt -w \
  internal/platform/service.go \
  internal/platform/renewal_job.go \
  internal/platform/deployment.go \
  internal/platform/job_lease.go \
  internal/platform/job_lease_test.go \
  internal/api/renewal_job.go \
  internal/api/deployment.go \
  internal/api/job_recovery.go \
  cmd/api-server/main.go \
  cmd/renewal-executor/main.go \
  cmd/deployment-executor/main.go

go test ./...
```

Phase 9.9 intentionally does not implement distributed fencing tokens. Client ID is an ownership check for this local lab; a production multi-worker system should add a unique lease/fencing token to every claim and mutation.
