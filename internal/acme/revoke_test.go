package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	"github.com/alandtsang/go-pki-lab/internal/csr"
	localdns "github.com/alandtsang/go-pki-lab/internal/dns"
	"github.com/alandtsang/go-pki-lab/internal/platform"
	"golang.org/x/crypto/ocsp"
)

func TestACMERevokeCertificateFeedsStatusCRLAndOCSP(t *testing.T) {
	root, err := ca.NewRoot("ACME Revoke Root", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "ACME Revoke Intermediate", 180*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store := localdns.NewStore()
	dnsServer, err := localdns.StartLocalServer("127.0.0.1:0", store)
	if err != nil {
		t.Fatal(err)
	}
	defer dnsServer.Shutdown()

	stateStore, err := NewFileStateStore(filepath.Join(t.TempDir(), "state.json"))
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
	account := &Account{ID: "acct-1", Status: "valid", JWK: jwkValue, Thumbprint: thumbprint, PublicKey: publicKey}
	server.accounts[account.ID] = account
	if err := server.persistAccount(account); err != nil {
		t.Fatal(err)
	}

	request, err := csr.Generate("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ca.IssueServerCertificateFromCSR(intermediate, request.CSR, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	order := &Order{ID: "order-1", AccountID: account.ID, Status: "valid", Domain: "hello.test"}
	server.orders[order.ID] = order
	if err := server.persistOrder(order); err != nil {
		t.Fatal(err)
	}
	issuance.certificates[order.ID] = append([]byte(nil), issued.FullChainPEM...)
	if err := issuance.persistIssuance(order.ID); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /acme/directory", server.HandleDirectory)
	mux.HandleFunc("POST /acme/revoke-cert", issuance.HandleRevokeCertificate)
	mux.Handle("/acme/", server.Handler())
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	nonce := fetchNonce(t, httpServer.URL)
	revokeURL := httpServer.URL + "/acme/revoke-cert"
	payload, err := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(issued.Certificate.Raw),
		"reason":      1,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := signES256JWS(t, accountKey, revokeURL, nonce, httpServer.URL+"/acme/acct/"+account.ID, nil, payload)
	resp := doPOST(t, revokeURL, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d, body = %s", resp.StatusCode, resp.Body)
	}

	status, err := service.CertificateStatus(issued.Certificate.SerialNumber.Text(16))
	if err != nil {
		t.Fatal(err)
	}
	if status["status"] != "revoked" || status["revocation_reason"] != 1 {
		t.Fatalf("unexpected certificate status: %#v", status)
	}

	crlPEM, err := service.CRLPEM()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("CRL response is not PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(issued.Certificate.SerialNumber) == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("ACME certificate serial not found in CRL")
	}

	requestDER, err := ocsp.CreateRequest(issued.Certificate, intermediate.Certificate, nil)
	if err != nil {
		t.Fatal(err)
	}
	responseDER, err := service.OCSPResponse(requestDER)
	if err != nil {
		t.Fatal(err)
	}
	ocspResponse, err := ocsp.ParseResponseForCert(responseDER, issued.Certificate, intermediate.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if ocspResponse.Status != ocsp.Revoked || ocspResponse.RevocationReason != 1 {
		t.Fatalf("unexpected OCSP response: status=%d reason=%d", ocspResponse.Status, ocspResponse.RevocationReason)
	}
}

func signCertificateKeyJWS(t *testing.T, key *ecdsa.PrivateKey, url, nonce string, payload []byte) []byte {
	t.Helper()
	jwkValue := ecJWK(key)
	protected := map[string]any{"alg": "ES256", "nonce": nonce, "url": url}
	var jwkObject any
	if err := json.Unmarshal(jwkValue, &jwkObject); err != nil {
		t.Fatal(err)
	}
	protected["jwk"] = jwkObject
	protectedJSON, err := json.Marshal(protected)
	if err != nil {
		t.Fatal(err)
	}
	protected64 := base64.RawURLEncoding.EncodeToString(protectedJSON)
	payload64 := base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(protected64 + "." + payload64))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	envelope, err := json.Marshal(map[string]string{
		"protected": protected64,
		"payload":   payload64,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
