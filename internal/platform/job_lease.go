package platform

import (
	"context"
	"fmt"
	"time"
)

type JobRecoveryResult struct {
	RecoveredRenewalJobs    []string `json:"recovered_renewal_jobs"`
	FailedRenewalJobs       []string `json:"failed_renewal_jobs"`
	RecoveredDeploymentJobs []string `json:"recovered_deployment_jobs"`
	FailedDeploymentJobs    []string `json:"failed_deployment_jobs"`
}

func (s *Service) SetJobLeaseOptions(leaseDuration time.Duration, maxAttempts int) error {
	if leaseDuration <= 0 {
		return fmt.Errorf("job lease duration must be positive")
	}
	if maxAttempts <= 0 {
		return fmt.Errorf("job max attempts must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobLeaseDuration = leaseDuration
	s.jobMaxAttempts = maxAttempts
	return nil
}

func (s *Service) HeartbeatRenewalJob(id, clientID string) (RenewalJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, ok := s.renewalJobs[id]
	if !ok {
		return RenewalJob{}, fmt.Errorf("renewal job %q not found", id)
	}
	if job.Status != RenewalJobStatusRunning {
		return RenewalJob{}, fmt.Errorf("renewal job %q is not running", id)
	}
	if job.ClaimedBy != clientID {
		return RenewalJob{}, fmt.Errorf("renewal job %q is claimed by %q", id, job.ClaimedBy)
	}
	now := time.Now().UTC()
	if job.LeaseExpiresAt != nil && !now.Before(*job.LeaseExpiresAt) {
		return RenewalJob{}, fmt.Errorf("renewal job %q lease has expired", id)
	}
	if s.renewalJobRepository == nil {
		return RenewalJob{}, fmt.Errorf("renewal job repository is not configured")
	}
	leaseExpiresAt := now.Add(s.jobLeaseDuration)
	job.HeartbeatAt = &now
	job.LeaseExpiresAt = &leaseExpiresAt
	job.UpdatedAt = now
	if err := s.renewalJobRepository.Save(job); err != nil {
		return RenewalJob{}, err
	}
	s.renewalJobs[id] = job
	return job, nil
}

func (s *Service) HeartbeatDeploymentJob(id, clientID string) (DeploymentJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, ok := s.deploymentJobs[id]
	if !ok {
		return DeploymentJob{}, fmt.Errorf("deployment job %q not found", id)
	}
	if job.Status != DeploymentJobStatusRunning {
		return DeploymentJob{}, fmt.Errorf("deployment job %q is not running", id)
	}
	if job.ClaimedBy != clientID {
		return DeploymentJob{}, fmt.Errorf("deployment job %q is claimed by %q", id, job.ClaimedBy)
	}
	now := time.Now().UTC()
	if job.LeaseExpiresAt != nil && !now.Before(*job.LeaseExpiresAt) {
		return DeploymentJob{}, fmt.Errorf("deployment job %q lease has expired", id)
	}
	if s.deploymentJobRepository == nil {
		return DeploymentJob{}, fmt.Errorf("deployment job repository is not configured")
	}
	leaseExpiresAt := now.Add(s.jobLeaseDuration)
	job.HeartbeatAt = &now
	job.LeaseExpiresAt = &leaseExpiresAt
	job.UpdatedAt = now
	if err := s.deploymentJobRepository.Save(job); err != nil {
		return DeploymentJob{}, err
	}
	s.deploymentJobs[id] = job
	return job, nil
}

func (s *Service) RecoverStaleJobs() (JobRecoveryResult, error) {
	now := time.Now().UTC()
	result := JobRecoveryResult{}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.renewalJobRepository == nil || s.deploymentJobRepository == nil {
		return result, fmt.Errorf("job repositories are not configured")
	}

	for id, job := range s.renewalJobs {
		if job.Status != RenewalJobStatusRunning || !leaseExpired(job.LeaseExpiresAt, now) {
			continue
		}
		if job.MaxAttempts <= 0 {
			job.MaxAttempts = s.jobMaxAttempts
		}
		if job.Attempts >= job.MaxAttempts {
			job.Status = RenewalJobStatusFailed
			job.LastError = fmt.Sprintf("lease expired after %d attempt(s)", job.Attempts)
			result.FailedRenewalJobs = append(result.FailedRenewalJobs, id)
		} else {
			job.Status = RenewalJobStatusWaitingForClient
			job.LastError = "lease expired; job requeued"
			job.ClaimedBy = ""
			job.ClaimedAt = nil
			job.HeartbeatAt = nil
			job.LeaseExpiresAt = nil
			result.RecoveredRenewalJobs = append(result.RecoveredRenewalJobs, id)
		}
		job.UpdatedAt = now
		if err := s.renewalJobRepository.Save(job); err != nil {
			return result, err
		}
		s.renewalJobs[id] = job
	}

	for id, job := range s.deploymentJobs {
		if job.Status != DeploymentJobStatusRunning || !leaseExpired(job.LeaseExpiresAt, now) {
			continue
		}
		if job.MaxAttempts <= 0 {
			job.MaxAttempts = s.jobMaxAttempts
		}
		if job.Attempts >= job.MaxAttempts {
			job.Status = DeploymentJobStatusFailed
			job.LastError = fmt.Sprintf("lease expired after %d attempt(s)", job.Attempts)
			result.FailedDeploymentJobs = append(result.FailedDeploymentJobs, id)
		} else {
			job.Status = DeploymentJobStatusWaitingForClient
			job.LastError = "lease expired; job requeued"
			job.ClaimedBy = ""
			job.ClaimedAt = nil
			job.HeartbeatAt = nil
			job.LeaseExpiresAt = nil
			result.RecoveredDeploymentJobs = append(result.RecoveredDeploymentJobs, id)
		}
		job.UpdatedAt = now
		if err := s.deploymentJobRepository.Save(job); err != nil {
			return result, err
		}
		s.deploymentJobs[id] = job
	}

	return result, nil
}

func leaseExpired(expiresAt *time.Time, now time.Time) bool {
	return expiresAt == nil || !now.Before(*expiresAt)
}

func (s *Service) RunJobRecovery(ctx context.Context, interval time.Duration, report func(error)) {
	if interval <= 0 {
		return
	}
	run := func() {
		if _, err := s.RecoverStaleJobs(); err != nil && report != nil {
			report(err)
		}
	}
	run()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
