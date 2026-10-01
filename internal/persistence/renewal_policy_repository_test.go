package persistence

import (
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

func TestRenewalPolicyRepositoryRoundTrip(t *testing.T) {
	repository, err := NewRenewalPolicyRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policy := platform.RenewalPolicy{
		Domain:          "hello.test",
		AutoRenew:       true,
		RenewBeforeDays: 30,
		UpdatedAt:       time.Now().UTC().Truncate(time.Second),
	}
	if err := repository.Save(policy); err != nil {
		t.Fatal(err)
	}
	policies, err := repository.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected one policy, got %#v", policies)
	}
	got := policies[0]
	if got.Domain != policy.Domain || got.AutoRenew != policy.AutoRenew || got.RenewBeforeDays != policy.RenewBeforeDays || !got.UpdatedAt.Equal(policy.UpdatedAt) {
		t.Fatalf("unexpected policy: %#v", got)
	}
}
