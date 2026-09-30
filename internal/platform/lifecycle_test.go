package platform

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	"github.com/alandtsang/go-pki-lab/internal/csr"
	localdns "github.com/alandtsang/go-pki-lab/internal/dns"
)

func TestLifecycleRevokeCRLAndRenew(t *testing.T) {
	root, err := ca.NewRoot("Test Root", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "Test Intermediate", 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store := localdns.NewStore()
	dnsServer, err := localdns.StartLocalServer("127.0.0.1:0", store)
	if err != nil {
		t.Fatal(err)
	}
	defer dnsServer.Shutdown()

	svc, err := NewService(root, intermediate, dnsServer.Addr())
	if err != nil {
		t.Fatal(err)
	}
	req, err := csr.Generate("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	entry, err := svc.CreateOrder("hello.test", req.CSRPEM)
	if err != nil {
		t.Fatal(err)
	}
	store.SetTXT(entry.Order.Challenge.Name, entry.Order.Challenge.Token)
	if _, err := svc.ValidateOrder(entry.ID); err != nil {
		t.Fatal(err)
	}
	issued, err := svc.IssueOrder(entry.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serial := issued.Certificate.Certificate.SerialNumber.Text(16)

	status, err := svc.CertificateStatus(serial)
	if err != nil {
		t.Fatal(err)
	}
	if status["status"] != "good" {
		t.Fatalf("status = %v", status["status"])
	}

	if _, err := svc.RevokeOrder(entry.ID, 1); err != nil {
		t.Fatal(err)
	}
	status, err = svc.CertificateStatus(serial)
	if err != nil {
		t.Fatal(err)
	}
	if status["status"] != "revoked" {
		t.Fatalf("status = %v", status["status"])
	}

	crlPEM, err := svc.CRLPEM()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("CRL PEM decode failed")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(intermediate.Certificate); err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(issued.Certificate.Certificate.SerialNumber) != 0 {
		t.Fatal("revoked certificate not found in CRL")
	}

	renewed, err := svc.RenewOrder(entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.RenewedFrom != entry.ID || renewed.ID == entry.ID || renewed.Order.Status != "pending" {
		t.Fatalf("unexpected renewed order: %+v", renewed)
	}
}
