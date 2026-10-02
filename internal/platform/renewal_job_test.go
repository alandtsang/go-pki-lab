package platform

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
)

type memoryRenewalPolicyRepository struct {
	policies map[string]RenewalPolicy
}

func (r *memoryRenewalPolicyRepository) LoadAll() ([]RenewalPolicy, error) {
	policies := make([]RenewalPolicy, 0, len(r.policies))
	for _, policy := range r.policies {
		policies = append(policies, policy)
	}
	return policies, nil
}

func (r *memoryRenewalPolicyRepository) Save(policy RenewalPolicy) error {
	if r.policies == nil {
		r.policies = make(map[string]RenewalPolicy)
	}
	r.policies[policy.Domain] = policy
	return nil
}

type memoryRenewalJobRepository struct {
	jobs map[string]RenewalJob
}

func (r *memoryRenewalJobRepository) LoadAll() ([]RenewalJob, error) {
	jobs := make([]RenewalJob, 0, len(r.jobs))
	for _, job := range r.jobs {
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (r *memoryRenewalJobRepository) Save(job RenewalJob) error {
	if r.jobs == nil {
		r.jobs = make(map[string]RenewalJob)
	}
	r.jobs[job.ID] = job
	return nil
}

type renewalCertificateSource struct {
	domain string
	cert   *x509.Certificate
}

func (s renewalCertificateSource) FindCertificateBySerial(serial *big.Int) (*CertificateState, bool, error) {
	if serial == nil || s.cert == nil || s.cert.SerialNumber.Cmp(serial) != 0 {
		return nil, false, nil
	}
	return &CertificateState{Certificate: s.cert, Domain: s.domain, SourceID: "source-order"}, true, nil
}

func (s renewalCertificateSource) RevokedCertificates() ([]CertificateState, error) {
	return nil, nil
}

func (s renewalCertificateSource) CertificatesByDomain(domain string) ([]CertificateState, error) {
	if normalizeDomain(domain) != normalizeDomain(s.domain) {
		return nil, nil
	}
	return []CertificateState{{Certificate: s.cert, Domain: s.domain, SourceID: "source-order"}}, nil
}

func TestRunRenewalScanCreatesOnePersistentJob(t *testing.T) {
	root, err := ca.NewRoot("Renewal Scheduler Root", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "Renewal Scheduler Intermediate", 180*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	policyRepository := &memoryRenewalPolicyRepository{}
	jobRepository := &memoryRenewalJobRepository{}
	service, err := NewService(root, intermediate, "127.0.0.1:1053")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetRenewalPolicyRepository(policyRepository); err != nil {
		t.Fatal(err)
	}
	if err := service.SetRenewalJobRepository(jobRepository); err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234),
		NotBefore:    time.Now().UTC().Add(-time.Hour),
		NotAfter:     time.Now().UTC().Add(20 * 24 * time.Hour),
	}
	service.AddCertificateStateSource(renewalCertificateSource{domain: "hello.test", cert: cert})
	if _, err := service.SetRenewalPolicy("hello.test", true, 30); err != nil {
		t.Fatal(err)
	}

	first, err := service.RunRenewalScan()
	if err != nil {
		t.Fatal(err)
	}
	if first.DueDomains != 1 || len(first.CreatedJobs) != 1 || len(first.ExistingJobs) != 0 {
		t.Fatalf("unexpected first scan result: %#v", first)
	}
	job := first.CreatedJobs[0]
	if job.Status != RenewalJobStatusWaitingForClient {
		t.Fatalf("job status = %q", job.Status)
	}
	if job.SourceSerial != CertificateSerialHex(cert) {
		t.Fatalf("job source serial = %q", job.SourceSerial)
	}

	second, err := service.RunRenewalScan()
	if err != nil {
		t.Fatal(err)
	}
	if len(second.CreatedJobs) != 0 || len(second.ExistingJobs) != 1 || second.ExistingJobs[0].ID != job.ID {
		t.Fatalf("scheduler created a duplicate job: %#v", second)
	}

	reloaded, err := NewService(root, intermediate, "127.0.0.1:1053")
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.SetRenewalPolicyRepository(policyRepository); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.SetRenewalJobRepository(jobRepository); err != nil {
		t.Fatal(err)
	}
	reloaded.AddCertificateStateSource(renewalCertificateSource{domain: "hello.test", cert: cert})

	third, err := reloaded.RunRenewalScan()
	if err != nil {
		t.Fatal(err)
	}
	if len(third.CreatedJobs) != 0 || len(third.ExistingJobs) != 1 || third.ExistingJobs[0].ID != job.ID {
		t.Fatalf("persistent job was not reused after restart: %#v", third)
	}
}
