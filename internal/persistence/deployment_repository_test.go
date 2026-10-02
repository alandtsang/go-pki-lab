package persistence

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

func TestDeploymentRepositoriesRoundTrip(t *testing.T) {
	root := t.TempDir()
	targetRepo, err := NewDeploymentTargetRepository(filepath.Join(root, "targets"))
	if err != nil {
		t.Fatal(err)
	}
	jobRepo, err := NewDeploymentJobRepository(filepath.Join(root, "jobs"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	target := platform.DeploymentTarget{ID: "target-1", Domain: "hello.test", Type: platform.DeploymentTargetTypeLocalHTTPS, Address: "127.0.0.1:8443", CertPath: "deploy/fullchain.pem", KeyPath: "deploy/key.pem", Enabled: true, CreatedAt: now, UpdatedAt: now}
	target.Monitoring = platform.MonitoringState{Status: platform.MonitoringSerialMismatch, ExpectedSerial: "ABCD", OnlineSerial: "1234", CheckedAt: now, NotAfter: now.Add(time.Hour)}
	if err := targetRepo.Save(target); err != nil {
		t.Fatal(err)
	}
	job := platform.DeploymentJob{ID: "job-1", TargetID: target.ID, Domain: target.Domain, CertificateSerial: "ABCD", Status: platform.DeploymentJobStatusWaitingForClient, CreatedAt: now, UpdatedAt: now}
	if err := jobRepo.Save(job); err != nil {
		t.Fatal(err)
	}
	targets, err := targetRepo.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := jobRepo.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].ID != target.ID || targets[0].CertPath != target.CertPath || targets[0].Monitoring != target.Monitoring {
		t.Fatalf("unexpected deployment targets: %#v", targets)
	}
	if len(jobs) != 1 || jobs[0].ID != job.ID || jobs[0].CertificateSerial != job.CertificateSerial {
		t.Fatalf("unexpected deployment jobs: %#v", jobs)
	}
}
