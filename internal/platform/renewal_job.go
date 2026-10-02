package platform

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	RenewalJobStatusWaitingForClient = "waiting_for_client"
	RenewalJobStatusRunning          = "running"
	RenewalJobStatusCompleted        = "completed"
	RenewalJobStatusFailed           = "failed"
)

type RenewalJob struct {
	ID                  string     `json:"id"`
	Domain              string     `json:"domain"`
	Status              string     `json:"status"`
	Reason              string     `json:"reason"`
	SourceSerial        string     `json:"source_serial,omitempty"`
	RenewBeforeDays     int        `json:"renew_before_days"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	ClaimedAt           *time.Time `json:"claimed_at,omitempty"`
	ClaimedBy           string     `json:"claimed_by,omitempty"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
	ResultSerial        string     `json:"result_serial,omitempty"`
	LastError           string     `json:"last_error,omitempty"`
}

type RenewalScanResult struct {
	ScannedPolicies int          `json:"scanned_policies"`
	DueDomains      int          `json:"due_domains"`
	CreatedJobs     []RenewalJob `json:"created_jobs"`
	ExistingJobs    []RenewalJob `json:"existing_jobs"`
}

type RenewalJobRepository interface {
	LoadAll() ([]RenewalJob, error)
	Save(RenewalJob) error
}

func (s *Service) SetRenewalJobRepository(repository RenewalJobRepository) error {
	if repository == nil {
		return fmt.Errorf("renewal job repository is required")
	}
	jobs, err := repository.LoadAll()
	if err != nil {
		return fmt.Errorf("load renewal jobs: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewalJobRepository = repository
	if s.renewalJobs == nil {
		s.renewalJobs = make(map[string]RenewalJob)
	}
	for _, job := range jobs {
		if job.ID == "" || normalizeDomain(job.Domain) == "" {
			continue
		}
		job.Domain = normalizeDomain(job.Domain)
		s.renewalJobs[job.ID] = job
	}
	return nil
}

func (s *Service) RenewalJobs(domain string) []RenewalJob {
	domain = normalizeDomain(domain)
	s.mu.RLock()
	jobs := make([]RenewalJob, 0, len(s.renewalJobs))
	for _, job := range s.renewalJobs {
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

func (s *Service) GetRenewalJob(id string) (RenewalJob, error) {
	s.mu.RLock()
	job, ok := s.renewalJobs[id]
	s.mu.RUnlock()
	if !ok {
		return RenewalJob{}, fmt.Errorf("renewal job %q not found", id)
	}
	return job, nil
}

func (s *Service) ClaimRenewalJob(id, clientID string) (RenewalJob, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return RenewalJob{}, fmt.Errorf("client_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.renewalJobs[id]
	if !ok {
		return RenewalJob{}, fmt.Errorf("renewal job %q not found", id)
	}
	if job.Status == RenewalJobStatusRunning && job.ClaimedBy == clientID {
		return job, nil
	}
	if job.Status != RenewalJobStatusWaitingForClient {
		return RenewalJob{}, fmt.Errorf("renewal job %q cannot be claimed from status %q", id, job.Status)
	}
	if s.renewalJobRepository == nil {
		return RenewalJob{}, fmt.Errorf("renewal job repository is not configured")
	}

	now := time.Now().UTC()
	job.Status = RenewalJobStatusRunning
	job.ClaimedBy = clientID
	job.ClaimedAt = &now
	job.UpdatedAt = now
	job.LastError = ""
	if err := s.renewalJobRepository.Save(job); err != nil {
		return RenewalJob{}, err
	}
	s.renewalJobs[id] = job
	return job, nil
}

func (s *Service) CompleteRenewalJob(id, resultSerial string) (RenewalJob, error) {
	resultSerial = strings.ToUpper(strings.TrimSpace(resultSerial))
	if resultSerial == "" {
		return RenewalJob{}, fmt.Errorf("result_serial is required")
	}

	job, err := s.GetRenewalJob(id)
	if err != nil {
		return RenewalJob{}, err
	}
	if job.Status == RenewalJobStatusCompleted && job.ResultSerial == resultSerial {
		return job, nil
	}
	if job.Status != RenewalJobStatusRunning {
		return RenewalJob{}, fmt.Errorf("renewal job %q cannot complete from status %q", id, job.Status)
	}
	if strings.EqualFold(job.SourceSerial, resultSerial) {
		return RenewalJob{}, fmt.Errorf("renewal result serial must differ from source serial")
	}

	instance, err := s.DomainCertificateInstance(job.Domain)
	if err != nil {
		return RenewalJob{}, err
	}
	if instance.CurrentCertificate == nil {
		return RenewalJob{}, fmt.Errorf("domain %q has no active certificate after renewal", job.Domain)
	}
	if !strings.EqualFold(instance.CurrentCertificate.SerialNumber, resultSerial) {
		return RenewalJob{}, fmt.Errorf("result serial %q is not the current certificate for %q", resultSerial, job.Domain)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	job = s.renewalJobs[id]
	if job.Status != RenewalJobStatusRunning {
		return RenewalJob{}, fmt.Errorf("renewal job %q cannot complete from status %q", id, job.Status)
	}
	if s.renewalJobRepository == nil {
		return RenewalJob{}, fmt.Errorf("renewal job repository is not configured")
	}
	now := time.Now().UTC()
	job.Status = RenewalJobStatusCompleted
	job.ResultSerial = resultSerial
	job.CompletedAt = &now
	job.UpdatedAt = now
	job.LastError = ""
	if err := s.renewalJobRepository.Save(job); err != nil {
		return RenewalJob{}, err
	}
	s.renewalJobs[id] = job
	return job, nil
}

func (s *Service) FailRenewalJob(id, message string) (RenewalJob, error) {
	message = strings.TrimSpace(message)
	if message == "" {
		return RenewalJob{}, fmt.Errorf("error is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.renewalJobs[id]
	if !ok {
		return RenewalJob{}, fmt.Errorf("renewal job %q not found", id)
	}
	if job.Status != RenewalJobStatusRunning {
		return RenewalJob{}, fmt.Errorf("renewal job %q cannot fail from status %q", id, job.Status)
	}
	if s.renewalJobRepository == nil {
		return RenewalJob{}, fmt.Errorf("renewal job repository is not configured")
	}
	now := time.Now().UTC()
	job.Status = RenewalJobStatusFailed
	job.LastError = message
	job.UpdatedAt = now
	if err := s.renewalJobRepository.Save(job); err != nil {
		return RenewalJob{}, err
	}
	s.renewalJobs[id] = job
	return job, nil
}

func (s *Service) RunRenewalScan() (RenewalScanResult, error) {
	policies := s.configuredRenewalPolicies()
	result := RenewalScanResult{ScannedPolicies: len(policies)}
	for _, policy := range policies {
		if !policy.AutoRenew {
			continue
		}
		decision, err := s.RenewalDecision(policy.Domain)
		if err != nil {
			return result, err
		}
		if !decision.ShouldRenew {
			continue
		}
		result.DueDomains++
		job, created, err := s.ensureRenewalJob(decision)
		if err != nil {
			return result, err
		}
		if created {
			result.CreatedJobs = append(result.CreatedJobs, job)
		} else {
			result.ExistingJobs = append(result.ExistingJobs, job)
		}
	}
	return result, nil
}

func (s *Service) configuredRenewalPolicies() []RenewalPolicy {
	s.mu.RLock()
	policies := make([]RenewalPolicy, 0, len(s.renewalPolicies))
	for _, policy := range s.renewalPolicies {
		policies = append(policies, policy)
	}
	s.mu.RUnlock()
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Domain < policies[j].Domain
	})
	return policies
}

func (s *Service) ensureRenewalJob(decision RenewalDecision) (RenewalJob, bool, error) {
	domain := normalizeDomain(decision.Domain)
	if domain == "" {
		return RenewalJob{}, false, fmt.Errorf("renewal decision domain is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.renewalJobRepository == nil {
		return RenewalJob{}, false, fmt.Errorf("renewal job repository is not configured")
	}
	for _, job := range s.renewalJobs {
		if job.Domain == domain && (job.Status == RenewalJobStatusWaitingForClient || job.Status == RenewalJobStatusRunning) {
			return job, false, nil
		}
	}

	id, err := randomID()
	if err != nil {
		return RenewalJob{}, false, err
	}
	now := time.Now().UTC()
	job := RenewalJob{
		ID:              id,
		Domain:          domain,
		Status:          RenewalJobStatusWaitingForClient,
		Reason:          decision.Reason,
		RenewBeforeDays: decision.Policy.RenewBeforeDays,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if decision.CurrentCertificate != nil {
		job.SourceSerial = decision.CurrentCertificate.SerialNumber
	}
	if err := s.renewalJobRepository.Save(job); err != nil {
		return RenewalJob{}, false, err
	}
	s.renewalJobs[job.ID] = job
	return job, true, nil
}
