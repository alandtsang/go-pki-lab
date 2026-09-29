package tlsserver

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
)

func TestNewTLSConfigWithFullChain(t *testing.T) {
	root, err := ca.NewRoot("Test Root CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "Test Intermediate CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.IssueServerCertificate(intermediate, "hello.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "hello.test.key")
	if err := os.WriteFile(certFile, leaf.FullChainPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, leaf.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := NewTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.Certificates); got != 1 {
		t.Fatalf("expected one TLS certificate pair, got %d", got)
	}
	if got := len(cfg.Certificates[0].Certificate); got != 2 {
		t.Fatalf("expected leaf + intermediate in chain, got %d certificates", got)
	}
}

func TestHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "https://hello.test/", nil)
	req.Host = "hello.test:8443"
	rec := httptest.NewRecorder()

	NewHandler("hello.test").ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Go PKI Lab HTTPS is working") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}
