package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	"github.com/alandtsang/go-pki-lab/internal/csr"
	localdns "github.com/alandtsang/go-pki-lab/internal/dns"
)

func TestACMEEndToEndIssuance(t *testing.T) {
	root, err := ca.NewRoot("ACME Test Root", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "ACME Test Intermediate", 180*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	store := localdns.NewStore()
	dnsServer, err := localdns.StartLocalServer("127.0.0.1:0", store)
	if err != nil {
		t.Fatal(err)
	}
	defer dnsServer.Shutdown()

	protocol := NewServer()
	issuance, err := NewIssuance(protocol, root, intermediate, dnsServer.Addr())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /acme/challenge/{id}", issuance.HandleChallenge)
	mux.HandleFunc("POST /acme/authz/{id}", issuance.HandleAuthorization)
	mux.HandleFunc("POST /acme/order/{id}", issuance.HandleOrder)
	mux.HandleFunc("POST /acme/finalize/{id}", issuance.HandleFinalize)
	mux.HandleFunc("POST /acme/cert/{id}", issuance.HandleCertificate)
	mux.Handle("/acme/", protocol.Handler())
	server := httptest.NewServer(mux)
	defer server.Close()

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkValue := ecJWK(accountKey)
	thumbprint, err := jwkThumbprint(jwkValue)
	if err != nil {
		t.Fatal(err)
	}

	nonce := fetchNonce(t, server.URL)
	accountURL := server.URL + "/acme/new-account"
	accountBody := signES256JWS(t, accountKey, accountURL, nonce, "", jwkValue, []byte("{}"))
	accountResp := doPOST(t, accountURL, accountBody)
	if accountResp.StatusCode != http.StatusCreated {
		t.Fatalf("newAccount status = %d, body = %s", accountResp.StatusCode, accountResp.Body)
	}
	kid := accountResp.Header.Get("Location")
	nonce = accountResp.Header.Get("Replay-Nonce")

	orderURL := server.URL + "/acme/new-order"
	orderPayload := []byte("{\"identifiers\":[{\"type\":\"dns\",\"value\":\"hello.test\"}]}")
	orderBody := signES256JWS(t, accountKey, orderURL, nonce, kid, nil, orderPayload)
	orderResp := doPOST(t, orderURL, orderBody)
	if orderResp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d, body = %s", orderResp.StatusCode, orderResp.Body)
	}
	var order struct {
		Status         string   `json:"status"`
		Authorizations []string `json:"authorizations"`
		Finalize       string   `json:"finalize"`
	}
	if err := json.Unmarshal(orderResp.Body, &order); err != nil {
		t.Fatal(err)
	}

	nonce = orderResp.Header.Get("Replay-Nonce")
	authzBody := signES256JWS(t, accountKey, order.Authorizations[0], nonce, kid, nil, nil)
	authzResp := doPOST(t, order.Authorizations[0], authzBody)
	if authzResp.StatusCode != http.StatusOK {
		t.Fatalf("authorization status = %d, body = %s", authzResp.StatusCode, authzResp.Body)
	}
	var authorization struct {
		Challenges []struct {
			URL   string `json:"url"`
			Token string `json:"token"`
		} `json:"challenges"`
	}
	if err := json.Unmarshal(authzResp.Body, &authorization); err != nil {
		t.Fatal(err)
	}
	if len(authorization.Challenges) != 1 {
		t.Fatalf("unexpected authorization: %s", authzResp.Body)
	}

	keyAuthorization := authorization.Challenges[0].Token + "." + thumbprint
	digest := sha256Bytes([]byte(keyAuthorization))
	store.SetTXT("_acme-challenge.hello.test", base64.RawURLEncoding.EncodeToString(digest))

	nonce = authzResp.Header.Get("Replay-Nonce")
	challengeURL := authorization.Challenges[0].URL
	challengeBody := signES256JWS(t, accountKey, challengeURL, nonce, kid, nil, []byte("{}"))
	challengeResp := doPOST(t, challengeURL, challengeBody)
	if challengeResp.StatusCode != http.StatusOK || !bytes.Contains(challengeResp.Body, []byte("\"status\":\"valid\"")) {
		t.Fatalf("challenge status = %d, body = %s", challengeResp.StatusCode, challengeResp.Body)
	}

	request, err := csr.Generate("hello.test")
	if err != nil {
		t.Fatal(err)
	}
	finalizePayload, err := json.Marshal(map[string]string{
		"csr": base64.RawURLEncoding.EncodeToString(request.CSR.Raw),
	})
	if err != nil {
		t.Fatal(err)
	}
	nonce = challengeResp.Header.Get("Replay-Nonce")
	finalizeBody := signES256JWS(t, accountKey, order.Finalize, nonce, kid, nil, finalizePayload)
	finalizeResp := doPOST(t, order.Finalize, finalizeBody)
	if finalizeResp.StatusCode != http.StatusOK {
		t.Fatalf("finalize status = %d, body = %s", finalizeResp.StatusCode, finalizeResp.Body)
	}
	var finalized struct {
		Status      string `json:"status"`
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(finalizeResp.Body, &finalized); err != nil {
		t.Fatal(err)
	}
	if finalized.Status != "valid" || finalized.Certificate == "" {
		t.Fatalf("unexpected finalize response: %s", finalizeResp.Body)
	}

	nonce = finalizeResp.Header.Get("Replay-Nonce")
	certificateBody := signES256JWS(t, accountKey, finalized.Certificate, nonce, kid, nil, nil)
	certificateResp := doPOST(t, finalized.Certificate, certificateBody)
	if certificateResp.StatusCode != http.StatusOK {
		t.Fatalf("certificate status = %d, body = %s", certificateResp.StatusCode, certificateResp.Body)
	}
	block, _ := pem.Decode(certificateResp.Body)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("certificate response is not PEM: %s", certificateResp.Body)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.VerifyServerCertificate(leaf, root, intermediate, "hello.test"); err != nil {
		t.Fatal(err)
	}
}

func sha256Bytes(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}
