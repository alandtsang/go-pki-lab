# Phase 9.4 - Client Renewal Executor

Phase 9.4 closes the renewal loop without moving the leaf private key into the platform server.

## Flow

```text
Renewal Scheduler
  -> waiting_for_client
  -> executor claims job
  -> running
  -> acme.sh --renew
  -> platform ACME issues a new certificate
  -> executor reads Domain Certificate Instance
  -> verifies current serial changed
  -> executor reports result serial
  -> completed
```

On failure the executor reports the error and the job becomes `failed`.

## Run

```bash
go run ./cmd/renewal-executor \
  -api http://127.0.0.1:8080 \
  -acme-server http://127.0.0.1:8080/acme/directory \
  -domain hello2.test
```

The executor defaults to `~/.acme.sh/acme.sh` and passes `--ecc`. Use `-ecc=false` for an RSA acme.sh certificate.

## Job APIs

```text
POST /renewal-jobs/{id}/claim
POST /renewal-jobs/{id}/complete
POST /renewal-jobs/{id}/fail
```

`complete` validates that the reported serial is different from `source_serial` and is the domain's current certificate in the platform state.

## Security boundary

The platform never receives the leaf private key. `acme.sh` remains responsible for the private key and CSR on the client machine.
