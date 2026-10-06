package platform

import (
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
)

type leaseRenewalRepository struct {
	jobs map[string]RenewalJob
}

func (r *leaseRenewalRepository) LoadAll() ([]RenewalJob, error) {
	result := make([]RenewalJob, 0, len(r.jobs))
	for _, job := range r.jobs {
		result = append(result, job)
	}
	return result, nil
}

func (r *leaseRenewalRepository) Save(job RenewalJob) error {
	r.jobs[job.ID] = job
	return nil
}

type leaseDeploymentRepository struct {
	jobs map[string]DeploymentJob
}

func (r *leaseDeploymentRepository) LoadAll() ([]DeploymentJob, error) {
	result := make([]DeploymentJob, 0, len(r.jobs))
	for _, job := range r.jobs {
		result = append(result, job)
	}
	return result, nil
}

func (r *leaseDeploymentRepository) Save(job DeploymentJob) error {
	r.jobs[job.ID] = job
	return nil
}

func newLeaseTestService(t *testing.T) *Service {
	t.Helper()
	root, err := ca.NewRoot("Lease Root", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "Lease Intermediate", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(root, intermediate, "127.0.0.1:1053")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetJobLeaseOptions(time.Minute, 2); err != nil {
		t.Fatal(err)
	}
	return service
}

func TestRenewalJobLeaseHeartbeatAndRecovery(t *testing.T) {
	service := newLeaseTestService(t)
	repository := &leaseRenewalRepository{jobs: map[string]RenewalJob{
		"renew-1": {
			ID:          "renew-1",
			Domain:      "hello.test",
			Status:      RenewalJobStatusWaitingForClient,
			MaxAttempts: 2,
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		},
	}}
	if err := service.SetRenewalJobRepository(repository); err != nil {
		t.Fatal(err)
	}

	job, err := service.ClaimRenewalJob("renew-1", "executor-a")
	if err != nil {
		t.Fatal(err)
	}
	if job.Attempts != 1 || job.LeaseExpiresAt == nil || job.HeartbeatAt == nil {
		t.Fatalf("unexpected claimed job: %+v", job)
	}
	if _, err := service.HeartbeatRenewalJob(job.ID, "executor-b"); err == nil {
		t.Fatal("expected heartbeat from wrong executor to fail")
	}
	heartbeat, err := service.HeartbeatRenewalJob(job.ID, "executor-a")
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.LeaseExpiresAt == nil || heartbeat.HeartbeatAt == nil {
		t.Fatal("heartbeat did not renew lease")
	}

	service.mu.Lock()
	expired := time.Now().UTC().Add(-time.Second)
	job = service.renewalJobs[job.ID]
	job.LeaseExpiresAt = &expired
	service.renewalJobs[job.ID] = job
	service.mu.Unlock()

	result, err := service.RecoverStaleJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RecoveredRenewalJobs) != 1 {
		t.Fatalf("expected renewal job recovery, got %+v", result)
	}
	job, _ = service.GetRenewalJob(job.ID)
	if job.Status != RenewalJobStatusWaitingForClient || job.ClaimedBy != "" {
		t.Fatalf("expected requeued job, got %+v", job)
	}

	job, err = service.ClaimRenewalJob(job.ID, "executor-b")
	if err != nil {
		t.Fatal(err)
	}
	if job.Attempts != 2 {
		t.Fatalf("expected second attempt, got %d", job.Attempts)
	}

	service.mu.Lock()
	expired = time.Now().UTC().Add(-time.Second)
	job = service.renewalJobs[job.ID]
	job.LeaseExpiresAt = &expired
	service.renewalJobs[job.ID] = job
	service.mu.Unlock()

	result, err = service.RecoverStaleJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.FailedRenewalJobs) != 1 {
		t.Fatalf("expected permanent renewal failure, got %+v", result)
	}
	job, _ = service.GetRenewalJob(job.ID)
	if job.Status != RenewalJobStatusFailed {
		t.Fatalf("expected failed job, got %+v", job)
	}
}

func TestDeploymentJobLeaseRecovery(t *testing.T) {
	service := newLeaseTestService(t)
	renewalRepository := &leaseRenewalRepository{jobs: map[string]RenewalJob{}}
	if err := service.SetRenewalJobRepository(renewalRepository); err != nil {
		t.Fatal(err)
	}
	repository := &leaseDeploymentRepository{jobs: map[string]DeploymentJob{
		"deploy-1": {
			ID:                "deploy-1",
			TargetID:          "target-1",
			Domain:            "hello.test",
			CertificateSerial: "ABCD",
			Status:            DeploymentJobStatusWaitingForClient,
			MaxAttempts:       2,
			CreatedAt:         time.Now().UTC(),
			UpdatedAt:         time.Now().UTC(),
		},
	}}
	if err := service.SetDeploymentJobRepository(repository); err != nil {
		t.Fatal(err)
	}

	job, err := service.ClaimDeploymentJob("deploy-1", "executor-a")
	if err != nil {
		t.Fatal(err)
	}
	if job.Attempts != 1 || job.LeaseExpiresAt == nil {
		t.Fatalf("unexpected claimed deployment job: %+v", job)
	}

	service.mu.Lock()
	expired := time.Now().UTC().Add(-time.Second)
	job = service.deploymentJobs[job.ID]
	job.LeaseExpiresAt = &expired
	service.deploymentJobs[job.ID] = job
	service.mu.Unlock()

	result, err := service.RecoverStaleJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RecoveredDeploymentJobs) != 1 {
		t.Fatalf("expected deployment recovery, got %+v", result)
	}
	job, _ = service.GetDeploymentJob(job.ID)
	if job.Status != DeploymentJobStatusWaitingForClient {
		t.Fatalf("expected deployment job requeued, got %+v", job)
	}
}
