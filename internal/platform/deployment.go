package platform

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	DeploymentTargetTypeLocalHTTPS = "local_https"

	DeploymentJobStatusWaitingForClient = "waiting_for_client"
	DeploymentJobStatusRunning          = "running"
	DeploymentJobStatusCompleted        = "completed"
	DeploymentJobStatusFailed           = "failed"
)

type DeploymentTarget struct {
	Monitoring MonitoringState `json:"monitoring"`
	ID         string          `json:"id"`
	Domain     string          `json:"domain"`
	Type       string          `json:"type"`
	Address    string          `json:"address"`
	CertPath   string          `json:"cert_path"`
	KeyPath    string          `json:"key_path"`
	Enabled    bool            `json:"enabled"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

type DeploymentJob struct {
	ID                string     `json:"id"`
	TargetID          string     `json:"target_id"`
	Domain            string     `json:"domain"`
	CertificateSerial string     `json:"certificate_serial"`
	Status            string     `json:"status"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	ClaimedAt         *time.Time `json:"claimed_at,omitempty"`
	ClaimedBy         string     `json:"claimed_by,omitempty"`
	HeartbeatAt       *time.Time `json:"heartbeat_at,omitempty"`
	LeaseExpiresAt    *time.Time `json:"lease_expires_at,omitempty"`
	Attempts          int        `json:"attempts"`
	MaxAttempts       int        `json:"max_attempts"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	VerifiedSerial    string     `json:"verified_serial,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
}

type DeploymentTargetRepository interface {
	LoadAll() ([]DeploymentTarget, error)
	Save(DeploymentTarget) error
}

type DeploymentJobRepository interface {
	LoadAll() ([]DeploymentJob, error)
	Save(DeploymentJob) error
}

func (s *Service) SetDeploymentTargetRepository(repository DeploymentTargetRepository) error {
	if repository == nil {
		return fmt.Errorf("deployment target repository is required")
	}
	targets, err := repository.LoadAll()
	if err != nil {
		return fmt.Errorf("load deployment targets: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deploymentTargetRepository = repository
	if s.deploymentTargets == nil {
		s.deploymentTargets = make(map[string]DeploymentTarget)
	}
	for _, target := range targets {
		if target.ID == "" || normalizeDomain(target.Domain) == "" {
			continue
		}
		target.Domain = normalizeDomain(target.Domain)
		s.deploymentTargets[target.ID] = target
	}
	return nil
}

func (s *Service) SetDeploymentJobRepository(repository DeploymentJobRepository) error {
	if repository == nil {
		return fmt.Errorf("deployment job repository is required")
	}
	jobs, err := repository.LoadAll()
	if err != nil {
		return fmt.Errorf("load deployment jobs: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deploymentJobRepository = repository
	if s.deploymentJobs == nil {
		s.deploymentJobs = make(map[string]DeploymentJob)
	}
	for _, job := range jobs {
		if job.ID == "" || job.TargetID == "" {
			continue
		}
		job.Domain = normalizeDomain(job.Domain)
		s.deploymentJobs[job.ID] = job
	}
	return nil
}

func (s *Service) CreateDeploymentTarget(domain, targetType, address, certPath, keyPath string, enabled bool) (DeploymentTarget, error) {
	domain = normalizeDomain(domain)
	targetType = strings.TrimSpace(targetType)
	address = strings.TrimSpace(address)
	certPath = strings.TrimSpace(certPath)
	keyPath = strings.TrimSpace(keyPath)
	if domain == "" {
		return DeploymentTarget{}, fmt.Errorf("domain is required")
	}
	if targetType == "" {
		targetType = DeploymentTargetTypeLocalHTTPS
	}
	if targetType != DeploymentTargetTypeLocalHTTPS {
		return DeploymentTarget{}, fmt.Errorf("unsupported deployment target type %q", targetType)
	}
	if address == "" || certPath == "" || keyPath == "" {
		return DeploymentTarget{}, fmt.Errorf("address, cert_path, and key_path are required")
	}
	id, err := randomID()
	if err != nil {
		return DeploymentTarget{}, err
	}
	now := time.Now().UTC()
	target := DeploymentTarget{ID: id, Domain: domain, Type: targetType, Address: address, CertPath: certPath, KeyPath: keyPath, Enabled: enabled, CreatedAt: now, UpdatedAt: now}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deploymentTargetRepository == nil {
		return DeploymentTarget{}, fmt.Errorf("deployment target repository is not configured")
	}
	if err := s.deploymentTargetRepository.Save(target); err != nil {
		return DeploymentTarget{}, err
	}
	s.deploymentTargets[target.ID] = target
	return target, nil
}

func (s *Service) DeploymentTargets(domain string) []DeploymentTarget {
	domain = normalizeDomain(domain)
	s.mu.RLock()
	targets := make([]DeploymentTarget, 0, len(s.deploymentTargets))
	for _, target := range s.deploymentTargets {
		if domain != "" && target.Domain != domain {
			continue
		}
		targets = append(targets, target)
	}
	s.mu.RUnlock()
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].CreatedAt.Equal(targets[j].CreatedAt) {
			return targets[i].ID < targets[j].ID
		}
		return targets[i].CreatedAt.Before(targets[j].CreatedAt)
	})
	return targets
}

func (s *Service) GetDeploymentTarget(id string) (DeploymentTarget, error) {
	s.mu.RLock()
	target, ok := s.deploymentTargets[id]
	s.mu.RUnlock()
	if !ok {
		return DeploymentTarget{}, fmt.Errorf("deployment target %q not found", id)
	}
	return target, nil
}

func (s *Service) DeploymentJobs(domain string) []DeploymentJob {
	domain = normalizeDomain(domain)
	s.mu.RLock()
	jobs := make([]DeploymentJob, 0, len(s.deploymentJobs))
	for _, job := range s.deploymentJobs {
		if domain != "" && job.Domain != domain {
			continue
		}
		jobs = append(jobs, job)
	}
	s.mu.RUnlock()
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].CreatedAt.Equal(jobs[j].CreatedAt) {
			return jobs[i].ID > jobs[j].ID
		}
		return jobs[i].CreatedAt.After(jobs[j].CreatedAt)
	})
	return jobs
}

func (s *Service) GetDeploymentJob(id string) (DeploymentJob, error) {
	s.mu.RLock()
	job, ok := s.deploymentJobs[id]
	s.mu.RUnlock()
	if !ok {
		return DeploymentJob{}, fmt.Errorf("deployment job %q not found", id)
	}
	return job, nil
}

func (s *Service) CreateDeploymentJobForTarget(targetID, serial string) (DeploymentJob, bool, error) {
	serial = strings.ToUpper(strings.TrimSpace(serial))
	if serial == "" {
		return DeploymentJob{}, false, fmt.Errorf("certificate serial is required")
	}
	target, err := s.GetDeploymentTarget(targetID)
	if err != nil {
		return DeploymentJob{}, false, err
	}
	if !target.Enabled {
		return DeploymentJob{}, false, fmt.Errorf("deployment target %q is disabled", targetID)
	}
	return s.ensureDeploymentJob(target, serial)
}

func (s *Service) CreateDeploymentJobsForDomain(domain, serial string) ([]DeploymentJob, error) {
	domain = normalizeDomain(domain)
	serial = strings.ToUpper(strings.TrimSpace(serial))
	if domain == "" || serial == "" {
		return nil, fmt.Errorf("domain and certificate serial are required")
	}
	targets := s.DeploymentTargets(domain)
	created := make([]DeploymentJob, 0, len(targets))
	for _, target := range targets {
		if !target.Enabled {
			continue
		}
		job, wasCreated, err := s.ensureDeploymentJob(target, serial)
		if err != nil {
			return created, err
		}
		if wasCreated {
			created = append(created, job)
		}
	}
	return created, nil
}

func (s *Service) ensureDeploymentJob(target DeploymentTarget, serial string) (DeploymentJob, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deploymentJobRepository == nil {
		return DeploymentJob{}, false, fmt.Errorf("deployment job repository is not configured")
	}
	for _, job := range s.deploymentJobs {
		if job.TargetID == target.ID && strings.EqualFold(job.CertificateSerial, serial) && (job.Status == DeploymentJobStatusWaitingForClient || job.Status == DeploymentJobStatusRunning || job.Status == DeploymentJobStatusCompleted || (job.Status == DeploymentJobStatusFailed && job.MaxAttempts > 0 && job.Attempts >= job.MaxAttempts)) {
			return job, false, nil
		}
	}
	id, err := randomID()
	if err != nil {
		return DeploymentJob{}, false, err
	}
	now := time.Now().UTC()
	job := DeploymentJob{ID: id, TargetID: target.ID, Domain: target.Domain, CertificateSerial: strings.ToUpper(serial), Status: DeploymentJobStatusWaitingForClient, MaxAttempts: s.jobMaxAttempts, CreatedAt: now, UpdatedAt: now}
	if err := s.deploymentJobRepository.Save(job); err != nil {
		return DeploymentJob{}, false, err
	}
	s.deploymentJobs[job.ID] = job
	return job, true, nil
}

func (s *Service) ClaimDeploymentJob(id, clientID string) (DeploymentJob, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return DeploymentJob{}, fmt.Errorf("client_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.deploymentJobs[id]
	if !ok {
		return DeploymentJob{}, fmt.Errorf("deployment job %q not found", id)
	}
	if job.Status == DeploymentJobStatusRunning && job.ClaimedBy == clientID {
		now := time.Now().UTC()
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
	if job.Status != DeploymentJobStatusWaitingForClient {
		return DeploymentJob{}, fmt.Errorf("deployment job %q cannot be claimed from status %q", id, job.Status)
	}
	now := time.Now().UTC()
	leaseExpiresAt := now.Add(s.jobLeaseDuration)
	job.Status = DeploymentJobStatusRunning
	job.ClaimedBy = clientID
	job.ClaimedAt = &now
	job.HeartbeatAt = &now
	job.LeaseExpiresAt = &leaseExpiresAt
	job.Attempts++
	if job.MaxAttempts <= 0 {
		job.MaxAttempts = s.jobMaxAttempts
	}
	job.UpdatedAt = now
	job.LastError = ""
	if err := s.deploymentJobRepository.Save(job); err != nil {
		return DeploymentJob{}, err
	}
	s.deploymentJobs[id] = job
	return job, nil
}

func (s *Service) CompleteDeploymentJob(id, verifiedSerial string) (DeploymentJob, error) {
	verifiedSerial = strings.ToUpper(strings.TrimSpace(verifiedSerial))
	if verifiedSerial == "" {
		return DeploymentJob{}, fmt.Errorf("verified_serial is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.deploymentJobs[id]
	if !ok {
		return DeploymentJob{}, fmt.Errorf("deployment job %q not found", id)
	}
	if job.Status == DeploymentJobStatusCompleted && strings.EqualFold(job.VerifiedSerial, verifiedSerial) {
		return job, nil
	}
	if job.Status != DeploymentJobStatusRunning {
		return DeploymentJob{}, fmt.Errorf("deployment job %q cannot complete from status %q", id, job.Status)
	}
	if !strings.EqualFold(job.CertificateSerial, verifiedSerial) {
		return DeploymentJob{}, fmt.Errorf("verified serial %q does not match deployment certificate %q", verifiedSerial, job.CertificateSerial)
	}
	now := time.Now().UTC()
	job.Status = DeploymentJobStatusCompleted
	job.VerifiedSerial = verifiedSerial
	job.CompletedAt = &now
	job.UpdatedAt = now
	job.LastError = ""
	if err := s.deploymentJobRepository.Save(job); err != nil {
		return DeploymentJob{}, err
	}
	s.deploymentJobs[id] = job
	return job, nil
}

func (s *Service) FailDeploymentJob(id, message string) (DeploymentJob, error) {
	message = strings.TrimSpace(message)
	if message == "" {
		return DeploymentJob{}, fmt.Errorf("error is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.deploymentJobs[id]
	if !ok {
		return DeploymentJob{}, fmt.Errorf("deployment job %q not found", id)
	}
	if job.Status != DeploymentJobStatusRunning {
		return DeploymentJob{}, fmt.Errorf("deployment job %q cannot fail from status %q", id, job.Status)
	}
	now := time.Now().UTC()
	job.Status = DeploymentJobStatusFailed
	job.LastError = message
	job.UpdatedAt = now
	if err := s.deploymentJobRepository.Save(job); err != nil {
		return DeploymentJob{}, err
	}
	s.deploymentJobs[id] = job
	return job, nil
}
