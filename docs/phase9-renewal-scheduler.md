# Phase 9.3 - Renewal Scheduler and Jobs

Phase 9.3 turns the renewal policy from a passive decision into a persistent scheduling workflow.

## Why the server does not renew the certificate by itself yet

The ACME leaf private key remains on the ACME client. The server therefore cannot create the final CSR or complete ACME finalize without either taking ownership of the private key or delegating execution to a client-side agent.

Phase 9.3 keeps that security boundary intact:

```text
Renewal Policy
      |
      v
Renewal Decision
      |
      v
Scheduler Scan
      |
      v
Renewal Job
status = waiting_for_client
      |
      v
Client-side executor (next phase)
```

## Persistent state

Renewal jobs are stored under:

```text
data/renewal-jobs/<job-id>.json
```

Each job records:

```text
id
domain
status
reason
source_serial
renew_before_days
created_at
updated_at
```

The current Phase 9.3 job status is:

```text
waiting_for_client
```

`completed` and `failed` are reserved for the client-executor phase.

## Duplicate prevention

Only one `waiting_for_client` job may exist for a domain at a time. Repeated scheduler scans reuse the existing job instead of creating duplicates.

This is important because the scheduler may run every minute while a client has not yet processed the renewal.

## Background scheduler

The API server starts the scheduler automatically.

Default interval:

```text
1m
```

Override it with:

```bash
go run ./cmd/api-server -renewal-scan-interval 5s
```

Disable background scans while keeping manual scans available:

```bash
go run ./cmd/api-server -renewal-scan-interval 0
```

The scheduler performs one scan immediately at startup and then scans at the configured interval.

## Manual scan

```bash
curl -s -X POST \
  http://127.0.0.1:8080/renewal-scheduler/run \
  | jq
```

Example result:

```json
{
  "scanned_policies": 1,
  "due_domains": 1,
  "created_jobs": [
    {
      "id": "...",
      "domain": "hello2.test",
      "status": "waiting_for_client",
      "reason": "within_renewal_window",
      "source_serial": "CB92A3DEDE6EE156943AB566AB5B56E2",
      "renew_before_days": 120
    }
  ],
  "existing_jobs": []
}
```

Running it again should return the same job under `existing_jobs` and an empty `created_jobs` array.

## Query jobs

All jobs:

```bash
curl -s http://127.0.0.1:8080/renewal-jobs | jq
```

Jobs for one domain:

```bash
curl -s \
  'http://127.0.0.1:8080/renewal-jobs?domain=hello2.test' \
  | jq
```

One job:

```bash
curl -s \
  http://127.0.0.1:8080/renewal-jobs/<job-id> \
  | jq
```

## Validation for hello2.test

If the Phase 9.2 policy is still:

```json
{
  "auto_renew": true,
  "renew_before_days": 120
}
```

then the existing `hello2.test` certificate should be inside the renewal window.

Start the server:

```bash
go run ./cmd/api-server -renewal-scan-interval 5s
```

Then query:

```bash
curl -s \
  'http://127.0.0.1:8080/renewal-jobs?domain=hello2.test' \
  | jq
```

Expected invariant:

```text
count = 1
status = waiting_for_client
source_serial = current hello2.test certificate serial
```

Wait for multiple scheduler intervals and query again. The job count should remain `1`.

Restart the API server and query again. The same job ID should still be present.
