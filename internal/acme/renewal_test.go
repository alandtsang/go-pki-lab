package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	"github.com/alandtsang/go-pki-lab/internal/csr"
	localdns "github.com/alandtsang/go-pki-lab/internal/dns"
	"github.com/alandtsang/go-pki-lab/internal/platform"
)

func TestACMERenewalKeepsCertificateHistoryIndependent(t *testing.T) {
	root, err := ca.NewRoot("ACME Renewal Root", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "ACME Renewal Intermediate", 180*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	dnsStore := localdns.NewStore()
	dnsServer, err := localdns.StartLocalServer("127.0.0.1:0", dnsStore)
	if err != nil {
		t.Fatal(err)
	}
	defer dnsServer.Shutdown()

	stateStore, err := NewFileStateStore(filepath.Join(t.TempDir(), "acme", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerWithStore(stateStore)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := NewIssuanceWithStore(server, root, intermediate, dnsServer.Addr(), stateStore)
	if err != nil {
		t.Fatal(err)
	}
	service, err := platform.NewService(root, intermediate, dnsServer.Addr())
	if err != nil {
		t.Fatal(err)
	}
	service.AddCertificateStateSource(issuance)

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkValue := ecJWK(accountKey)
	thumbprint, err := jwkThumbprint(jwkValue)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := parseJWK(jwkValue)
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{ID: "acct-renew", Status: "valid", JWK: jwkValue, Thumbprint: thumbprint, PublicKey: publicKey}
	server.accounts[account.ID] = account
	if err := server.persistAccount(account); err != nil {
		t.Fatal(err)
	}

	oldCSR, err := csr.Generate("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	oldCert, err := ca.IssueServerCertificateFromCSR(intermediate, oldCSR.CSR, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCSR, err := csr.Generate("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	newCert, err := ca.IssueServerCertificateFromCSR(intermediate, newCSR.CSR, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if oldCert.Certificate.SerialNumber.Cmp(newCert.Certificate.SerialNumber) == 0 {
		t.Fatal("renewal must produce a new certificate serial")
	}

	oldOrder := &Order{ID: "order-old", AccountID: account.ID, Status: "valid", Domain: "hello.test"}
	newOrder := &Order{ID: "order-new", AccountID: account.ID, Status: "valid", Domain: "hello.test"}
	server.orders[oldOrder.ID] = oldOrder
	server.orders[newOrder.ID] = newOrder
	if err := server.persistOrder(oldOrder); err != nil {
		t.Fatal(err)
	}
	if err := server.persistOrder(newOrder); err != nil {
		t.Fatal(err)
	}

	issuance.certificates[oldOrder.ID] = append([]byte(nil), oldCert.FullChainPEM...)
	issuance.certificates[newOrder.ID] = append([]byte(nil), newCert.FullChainPEM...)
	revokedAt := time.Now().UTC().Truncate(time.Second)
	issuance.revokedAt[oldOrder.ID] = revokedAt
	issuance.revocationReason[oldOrder.ID] = 1
	if err := issuance.persistIssuance(oldOrder.ID); err != nil {
		t.Fatal(err)
	}
	if err := issuance.persistIssuance(newOrder.ID); err != nil {
		t.Fatal(err)
	}

	oldState, found, err := issuance.FindCertificateBySerial(oldCert.Certificate.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	if !found || oldState.RevokedAt == nil || oldState.RevocationReason != 1 {
		t.Fatalf("old certificate revocation state was lost: %#v", oldState)
	}

	newState, found, err := issuance.FindCertificateBySerial(newCert.Certificate.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("renewed certificate not found")
	}
	if newState.RevokedAt != nil {
		t.Fatalf("renewed certificate must remain good when old certificate is revoked: %#v", newState)
	}

	history, err := service.CertificateHistory("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("expected two certificate generations, got %#v", history)
	}
	statuses := map[string]string{}
	for _, item := range history {
		statuses[item.SerialNumber] = item.Status
	}
	oldSerial := platform.CertificateSerialHex(oldCert.Certificate)
	newSerial := platform.CertificateSerialHex(newCert.Certificate)
	if statuses[oldSerial] != "revoked" {
		t.Fatalf("old certificate history status = %q", statuses[oldSerial])
	}
	if statuses[newSerial] != "good" {
		t.Fatalf("new certificate history status = %q", statuses[newSerial])
	}

	instance, err := service.DomainCertificateInstance("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	if instance.Status != "active" {
		t.Fatalf("certificate instance status = %q", instance.Status)
	}
	if instance.HistoryCount != 2 || len(instance.History) != 2 {
		t.Fatalf("certificate instance history mismatch: %#v", instance)
	}
	if instance.CurrentCertificate == nil {
		t.Fatal("current certificate must be selected")
	}
	if instance.CurrentCertificate.SerialNumber != newSerial {
		t.Fatalf("current certificate serial = %q, want %q", instance.CurrentCertificate.SerialNumber, newSerial)
	}
	if instance.CurrentCertificate.Status != "good" {
		t.Fatalf("current certificate status = %q", instance.CurrentCertificate.Status)
	}

	newRevokedAt := time.Now().UTC().Truncate(time.Second)
	issuance.revokedAt[newOrder.ID] = newRevokedAt
	issuance.revocationReason[newOrder.ID] = 1
	if err := issuance.persistIssuance(newOrder.ID); err != nil {
		t.Fatal(err)
	}
	instance, err = service.DomainCertificateInstance("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	if instance.Status != "no_active_certificate" || instance.CurrentCertificate != nil {
		t.Fatalf("all revoked certificates must leave no active certificate: %#v", instance)
	}

	delete(issuance.revokedAt, newOrder.ID)
	delete(issuance.revocationReason, newOrder.ID)
	if err := issuance.persistIssuance(newOrder.ID); err != nil {
		t.Fatal(err)
	}

	reloadedServer, err := NewServerWithStore(stateStore)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewIssuanceWithStore(reloadedServer, root, intermediate, dnsServer.Addr(), stateStore)
	if err != nil {
		t.Fatal(err)
	}
	oldState, found, err = reloaded.FindCertificateBySerial(oldCert.Certificate.SerialNumber)
	if err != nil || !found || oldState.RevokedAt == nil {
		t.Fatalf("old certificate state did not survive restart: state=%#v found=%v err=%v", oldState, found, err)
	}
	newState, found, err = reloaded.FindCertificateBySerial(newCert.Certificate.SerialNumber)
	if err != nil || !found || newState.RevokedAt != nil {
		t.Fatalf("renewed certificate state did not survive restart: state=%#v found=%v err=%v", newState, found, err)
	}
}
