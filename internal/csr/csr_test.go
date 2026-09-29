package csr

import "testing"

func TestParseAndValidate(t *testing.T) {
	req, err := Generate("hello.test")
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseAndValidate(req.CSRPEM, "hello.test")
	if err != nil {
		t.Fatalf("expected valid CSR: %v", err)
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "hello.test" {
		t.Fatalf("unexpected SANs: %#v", parsed.DNSNames)
	}

	if _, err := ParseAndValidate(req.CSRPEM, "other.test"); err == nil {
		t.Fatal("expected domain mismatch to fail")
	}
}
