package ca

import (
	"testing"
	"time"
)

func TestIssueAndVerifyServerCertificate(t *testing.T) {
	root, err := NewRoot("Test Root CA", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("NewRoot() error = %v", err)
	}

	intermediate, err := NewIntermediate(root, "Test Intermediate CA", 180*24*time.Hour)
	if err != nil {
		t.Fatalf("NewIntermediate() error = %v", err)
	}

	leaf, err := IssueServerCertificate(intermediate, "hello.test", 24*time.Hour)
	if err != nil {
		t.Fatalf("IssueServerCertificate() error = %v", err)
	}

	if err := VerifyServerCertificate(leaf.Certificate, root, intermediate, "hello.test"); err != nil {
		t.Fatalf("VerifyServerCertificate() error = %v", err)
	}

	if err := leaf.Certificate.VerifyHostname("wrong.test"); err == nil {
		t.Fatal("VerifyHostname(wrong.test) unexpectedly succeeded")
	}
}
