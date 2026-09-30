package persistence

import (
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/challenge"
	"github.com/alandtsang/go-pki-lab/internal/csr"
	"github.com/alandtsang/go-pki-lab/internal/order"
	"github.com/alandtsang/go-pki-lab/internal/platform"
)

func TestFileRepositoryRoundTrip(t *testing.T) {
	req, err := csr.Generate("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	entry := &platform.Entry{
		ID: "order-1",
		Order: &order.Order{
			Domain:    "hello.test",
			Status:    order.StatusPending,
			Challenge: &challenge.DNS01{Domain: "hello.test", Name: "_acme-challenge.hello.test", Token: "token"},
		},
		CSR: req.CSR, CSRPEM: req.CSRPEM, CreatedAt: now, UpdatedAt: now,
	}
	repo, err := NewFileRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Save(entry); err != nil {
		t.Fatal(err)
	}
	entries, err := repo.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	got := entries[0]
	if got.ID != entry.ID || got.Order.Domain != "hello.test" || got.Order.Challenge.Token != "token" {
		t.Fatalf("unexpected restored entry: %+v", got)
	}
	if got.CSR == nil || len(got.CSR.DNSNames) != 1 || got.CSR.DNSNames[0] != "hello.test" {
		t.Fatal("CSR was not restored correctly")
	}
}
