# Phase 9.5 - Deployment Target and Certificate Deployment

Phase 9.5 extends the certificate lifecycle from renewal into verified deployment.

```text
Current Certificate
        |
        v
Deployment Reconciler
        |
        v
Deployment Job (waiting_for_client)
        |
        v
Deployment Executor
        |
        +--> validate source cert/key
        +--> atomically replace target files
        +--> TLS handshake target
        +--> verify online serial
        |
        v
Deployment Job (completed)
```

The API server never receives the leaf private key. File paths in a `local_https` target refer to the filesystem of the machine running the deployment executor.

## 1. Format and test

```bash
gofmt -w \
  ./internal/platform/*.go \
  ./internal/persistence/*.go \
  ./internal/api/*.go \
  ./internal/tlsserver/*.go \
  ./cmd/api-server/main.go \
  ./cmd/https-server/main.go \
  ./cmd/deployment-executor/main.go

go test ./...
```

## 2. Seed the local HTTPS target

The HTTPS server needs an initial certificate before it can listen. For the existing ECC `hello2.test` certificate:

```bash
mkdir -p ./deploy/hello2.test

cp ~/.acme.sh/hello2.test_ecc/fullchain.cer \
  ./deploy/hello2.test/fullchain.pem

cp ~/.acme.sh/hello2.test_ecc/hello2.test.key \
  ./deploy/hello2.test/hello2.test.key

chmod 600 ./deploy/hello2.test/hello2.test.key
```

Start the HTTPS target:

```bash
go run ./cmd/https-server \
  -domain hello2.test \
  -addr 127.0.0.1:8443 \
  -cert ./deploy/hello2.test/fullchain.pem \
  -key ./deploy/hello2.test/hello2.test.key
```

The HTTPS server validates the pair during startup and reloads the files for each new TLS handshake. No arbitrary reload command is executed.

## 3. Start the platform

```bash
go run ./cmd/api-server \
  -renewal-scan-interval 5s \
  -deployment-scan-interval 5s
```

Deployment state is persisted under:

```text
data/deployment-targets/
data/deployment-jobs/
```

## 4. Register a deployment target

```bash
curl -s -X POST \
  http://127.0.0.1:8080/deployment-targets \
  -H 'Content-Type: application/json' \
  -d '{
    "domain":"hello2.test",
    "type":"local_https",
    "address":"127.0.0.1:8443",
    "cert_path":"./deploy/hello2.test/fullchain.pem",
    "key_path":"./deploy/hello2.test/hello2.test.key",
    "enabled":true
  }' | jq
```

Save the returned `id` as the target ID.

The deployment reconciler immediately or periodically compares the target with the domain's current certificate and creates an idempotent deployment job for the current serial.

Manual reconcile:

```bash
curl -s -X POST \
  http://127.0.0.1:8080/deployment-reconciler/run | jq
```

Inspect jobs:

```bash
curl -s \
  'http://127.0.0.1:8080/deployment-jobs?domain=hello2.test' | jq
```

## 5. Run the deployment executor

```bash
go run ./cmd/deployment-executor \
  -api http://127.0.0.1:8080 \
  -domain hello2.test \
  -ecc=true
```

The executor:

1. finds a `waiting_for_client` job;
2. claims the job;
3. loads `~/.acme.sh/hello2.test_ecc/fullchain.cer` and `hello2.test.key`;
4. validates that the certificate and key match;
5. validates the certificate hostname and expected serial;
6. atomically replaces the target cert/key files;
7. opens a new TLS connection to `127.0.0.1:8443` using SNI `hello2.test`;
8. reads the peer leaf serial;
9. completes the job only if the online serial equals the expected serial.

Custom source paths can be supplied with:

```text
-source-cert
-source-key
```

## 6. Verify the online certificate manually

```bash
echo | openssl s_client \
  -connect 127.0.0.1:8443 \
  -servername hello2.test \
  2>/dev/null \
  | openssl x509 -noout -serial -subject -dates
```

Compare the online serial with the platform current certificate:

```bash
curl -s \
  http://127.0.0.1:8080/domains/hello2.test/certificate-instance \
  | jq -r '.current_certificate.serial_number'
```

They must match.

## 7. Verify the full renewal-to-deployment loop

After a later renewal rotates the certificate serial:

```text
Renewal Executor
  -> new ACME certificate
  -> Certificate Instance switches current serial
  -> Deployment Reconciler creates a new job
  -> Deployment Executor installs cert/key
  -> HTTPS server hot-loads them
  -> TLS peer serial matches current serial
  -> Deployment Job completed
```

A completed job is retained for audit. The reconciler does not create another job for the same target and certificate serial.

## Current scope

Phase 9.5 supports only `local_https`. Future target adapters can model Nginx, Kubernetes Secrets, cloud load balancers, CDN edges, and other certificate consumers without changing the certificate/renewal model.
