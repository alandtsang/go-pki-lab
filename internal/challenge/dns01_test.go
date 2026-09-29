package challenge_test

import (
	"testing"

	"github.com/alandtsang/go-pki-lab/internal/challenge"
	localdns "github.com/alandtsang/go-pki-lab/internal/dns"
)

func TestDNS01Verify(t *testing.T) {
	store := localdns.NewStore()
	server, err := localdns.StartLocalServer("127.0.0.1:0", store)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()

	ch, err := challenge.NewDNS01("hello.test")
	if err != nil {
		t.Fatal(err)
	}

	if err := ch.Verify(server.Addr()); err == nil {
		t.Fatal("expected validation to fail before TXT record is published")
	}

	store.SetTXT(ch.Name, ch.Token)
	if err := ch.Verify(server.Addr()); err != nil {
		t.Fatalf("expected validation to succeed: %v", err)
	}
}
