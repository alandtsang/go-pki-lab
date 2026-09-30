package platform

import (
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	"github.com/alandtsang/go-pki-lab/internal/csr"
	"github.com/alandtsang/go-pki-lab/internal/order"
	"golang.org/x/crypto/ocsp"
)

func TestOCSPResponseGoodAndRevoked(t *testing.T) {
	root, err := ca.NewRoot("Test Root CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "Test Intermediate CA", 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request, err := csr.Generate("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.IssueServerCertificateFromCSR(intermediate, request.CSR, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	service, err := NewService(root, intermediate, "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	service.orders["issued"] = &Entry{
		ID: "issued",
		Order: &order.Order{Domain: "hello.test", Status: order.StatusValid},
		CSR: request.CSR,
		CSRPEM: request.CSRPEM,
		Certificate: leaf,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	requestDER, err := ocsp.CreateRequest(leaf.Certificate, intermediate.Certificate, nil)
	if err != nil {
		t.Fatal(err)
	}

	responseDER, err := service.OCSPResponse(requestDER)
	if err != nil {
		t.Fatal(err)
	}
	response, err := ocsp.ParseResponseForCert(responseDER, leaf.Certificate, intermediate.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != ocsp.Good {
		t.Fatalf("status = %d, want good", response.Status)
	}

	revokedAt := time.Now().UTC().Add(-time.Minute)
	service.orders["issued"].RevokedAt = &revokedAt
	service.orders["issued"].RevocationReason = ocsp.KeyCompromise

	responseDER, err = service.OCSPResponse(requestDER)
	if err != nil {
		t.Fatal(err)
	}
	response, err = ocsp.ParseResponseForCert(responseDER, leaf.Certificate, intermediate.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != ocsp.Revoked {
		t.Fatalf("status = %d, want revoked", response.Status)
	}
	if response.RevocationReason != ocsp.KeyCompromise {
		t.Fatalf("revocation reason = %d, want %d", response.RevocationReason, ocsp.KeyCompromise)
	}
}
