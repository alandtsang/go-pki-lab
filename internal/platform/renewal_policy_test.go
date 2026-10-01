package platform

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
)

type testRenewalPolicyRepository struct {
	policies map[string]RenewalPolicy
}

func (r *testRenewalPolicyRepository) LoadAll() ([]RenewalPolicy, error) {
	result := make([]RenewalPolicy, 0, len(r.policies))
	for _, policy := range r.policies {
		result = append(result, policy)
	}
	return result, nil
}

func (r *testRenewalPolicyRepository) Save(policy RenewalPolicy) error {
	if r.policies == nil {
		r.policies = make(map[string]RenewalPolicy)
	}
	r.policies[policy.Domain] = policy
	return nil
}

type testCertificateStateSource struct {
	states []CertificateState
}

func (s *testCertificateStateSource) FindCertificateBySerial(serial *big.Int) (*CertificateState, bool, error) {
	for _, state := range s.states {
		if state.Certificate != nil && state.Certificate.SerialNumber.Cmp(serial) == 0 {
			copyState := state
			return &copyState, true, nil
		}
	}
	return nil, false, nil
}

func (s *testCertificateStateSource) RevokedCertificates() ([]CertificateState, error) {
	return nil, nil
}

func (s *testCertificateStateSource) CertificatesByDomain(domain string) ([]CertificateState, error) {
	result := make([]CertificateState, 0)
	for _, state := range s.states {
		if normalizeDomain(state.Domain) == normalizeDomain(domain) {
			result = append(result, state)
		}
	}
	return result, nil
}

func TestRenewalDecision(t *testing.T) {
	root, err := ca.NewRoot("Renewal Policy Root", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "Renewal Policy Intermediate", 180*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(root, intermediate, "127.0.0.1:1053")
	if err != nil {
		t.Fatal(err)
	}
	repository := &testRenewalPolicyRepository{policies: make(map[string]RenewalPolicy)}
	if err := service.SetRenewalPolicyRepository(repository); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	service.AddCertificateStateSource(&testCertificateStateSource{states: []CertificateState{{
		Certificate: &x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(45 * 24 * time.Hour),
		},
		Domain:   "hello.test",
		SourceID: "order-current",
	}}})

	decision, err := service.RenewalDecision("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	if decision.ShouldRenew || decision.Reason != "auto_renew_disabled" {
		t.Fatalf("unexpected default decision: %#v", decision)
	}

	if _, err := service.SetRenewalPolicy("hello.test", true, 30); err != nil {
		t.Fatal(err)
	}
	decision, err = service.RenewalDecision("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	if decision.ShouldRenew || decision.Reason != "outside_renewal_window" {
		t.Fatalf("unexpected outside-window decision: %#v", decision)
	}

	if _, err := service.SetRenewalPolicy("hello.test", true, 60); err != nil {
		t.Fatal(err)
	}
	decision, err = service.RenewalDecision("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	if !decision.ShouldRenew || decision.Reason != "within_renewal_window" {
		t.Fatalf("unexpected inside-window decision: %#v", decision)
	}
	if decision.DaysRemaining == nil || *decision.DaysRemaining < 44 || *decision.DaysRemaining > 46 {
		t.Fatalf("unexpected days remaining: %#v", decision.DaysRemaining)
	}

	if _, err := service.SetRenewalPolicy("missing.test", true, 30); err != nil {
		t.Fatal(err)
	}
	decision, err = service.RenewalDecision("missing.test")
	if err != nil {
		t.Fatal(err)
	}
	if !decision.ShouldRenew || decision.Reason != "no_active_certificate" {
		t.Fatalf("unexpected missing-certificate decision: %#v", decision)
	}
}
