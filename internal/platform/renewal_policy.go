package platform

import (
	"fmt"
	"strings"
	"time"
)

const DefaultRenewBeforeDays = 30

type RenewalPolicy struct {
	Domain          string    `json:"domain"`
	AutoRenew       bool      `json:"auto_renew"`
	RenewBeforeDays int       `json:"renew_before_days"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type RenewalDecision struct {
	Domain             string                  `json:"domain"`
	ShouldRenew        bool                    `json:"should_renew"`
	Reason             string                  `json:"reason"`
	DaysRemaining      *int                    `json:"days_remaining,omitempty"`
	Policy             RenewalPolicy           `json:"policy"`
	CurrentCertificate *CertificateHistoryItem `json:"current_certificate,omitempty"`
}

type RenewalPolicyRepository interface {
	LoadAll() ([]RenewalPolicy, error)
	Save(RenewalPolicy) error
}

func (s *Service) SetRenewalPolicyRepository(repository RenewalPolicyRepository) error {
	if repository == nil {
		return fmt.Errorf("renewal policy repository is required")
	}
	policies, err := repository.LoadAll()
	if err != nil {
		return fmt.Errorf("load renewal policies: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewalPolicyRepository = repository
	if s.renewalPolicies == nil {
		s.renewalPolicies = make(map[string]RenewalPolicy)
	}
	for _, policy := range policies {
		domain := normalizeDomain(policy.Domain)
		if domain == "" {
			continue
		}
		policy.Domain = domain
		s.renewalPolicies[domain] = policy
	}
	return nil
}

func (s *Service) SetRenewalPolicy(domain string, autoRenew bool, renewBeforeDays int) (RenewalPolicy, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return RenewalPolicy{}, fmt.Errorf("domain is required")
	}
	if renewBeforeDays <= 0 || renewBeforeDays > 365 {
		return RenewalPolicy{}, fmt.Errorf("renew_before_days must be between 1 and 365")
	}

	policy := RenewalPolicy{
		Domain:          domain,
		AutoRenew:       autoRenew,
		RenewBeforeDays: renewBeforeDays,
		UpdatedAt:       time.Now().UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.renewalPolicyRepository == nil {
		return RenewalPolicy{}, fmt.Errorf("renewal policy repository is not configured")
	}
	if err := s.renewalPolicyRepository.Save(policy); err != nil {
		return RenewalPolicy{}, err
	}
	if s.renewalPolicies == nil {
		s.renewalPolicies = make(map[string]RenewalPolicy)
	}
	s.renewalPolicies[domain] = policy
	return policy, nil
}

func (s *Service) RenewalPolicy(domain string) RenewalPolicy {
	domain = normalizeDomain(domain)
	s.mu.RLock()
	policy, ok := s.renewalPolicies[domain]
	s.mu.RUnlock()
	if ok {
		return policy
	}
	return RenewalPolicy{
		Domain:          domain,
		AutoRenew:       false,
		RenewBeforeDays: DefaultRenewBeforeDays,
	}
}

func (s *Service) RenewalDecision(domain string) (RenewalDecision, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return RenewalDecision{}, fmt.Errorf("domain is required")
	}
	policy := s.RenewalPolicy(domain)
	instance, err := s.DomainCertificateInstance(domain)
	if err != nil {
		return RenewalDecision{}, err
	}

	decision := RenewalDecision{
		Domain:             domain,
		Policy:             policy,
		CurrentCertificate: instance.CurrentCertificate,
	}
	if !policy.AutoRenew {
		decision.Reason = "auto_renew_disabled"
		return decision, nil
	}
	if instance.CurrentCertificate == nil {
		decision.ShouldRenew = true
		decision.Reason = "no_active_certificate"
		return decision, nil
	}

	remaining := time.Until(instance.CurrentCertificate.NotAfter)
	days := int(remaining.Hours() / 24)
	if remaining > 0 && remaining% (24*time.Hour) != 0 {
		days++
	}
	decision.DaysRemaining = &days
	if remaining <= time.Duration(policy.RenewBeforeDays)*24*time.Hour {
		decision.ShouldRenew = true
		decision.Reason = "within_renewal_window"
		return decision, nil
	}
	decision.Reason = "outside_renewal_window"
	return decision, nil
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}
