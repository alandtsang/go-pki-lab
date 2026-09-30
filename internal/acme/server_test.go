package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestACMEAccountAndOrderFlow(t *testing.T) {
	server := httptest.NewServer(NewServer().Handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/acme/directory")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("directory status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkValue := ecJWK(key)

	nonce := fetchNonce(t, server.URL)
	accountURL := server.URL + "/acme/new-account"
	accountBody := signES256JWS(t, key, accountURL, nonce, "", jwkValue, []byte(`{"termsOfServiceAgreed":true}`))
	accountResp := doPOST(t, accountURL, accountBody)
	if accountResp.StatusCode != http.StatusCreated {
		t.Fatalf("newAccount status = %d, body = %s", accountResp.StatusCode, accountResp.Body)
	}
	kid := accountResp.Header.Get("Location")
	if kid == "" {
		t.Fatal("newAccount response missing Location")
	}
	nonce = accountResp.Header.Get("Replay-Nonce")
	if nonce == "" {
		t.Fatal("newAccount response missing Replay-Nonce")
	}

	orderURL := server.URL + "/acme/new-order"
	orderPayload := []byte(`{"identifiers":[{"type":"dns","value":"hello.test"}]}`)
	orderBody := signES256JWS(t, key, orderURL, nonce, kid, nil, orderPayload)
	orderResp := doPOST(t, orderURL, orderBody)
	if orderResp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d, body = %s", orderResp.StatusCode, orderResp.Body)
	}
	if orderResp.Header.Get("Location") == "" {
		t.Fatal("newOrder response missing Location")
	}
	var order struct {
		Status         string   `json:"status"`
		Authorizations []string `json:"authorizations"`
		Finalize       string   `json:"finalize"`
	}
	if err := json.Unmarshal(orderResp.Body, &order); err != nil {
		t.Fatal(err)
	}
	if order.Status != "pending" || len(order.Authorizations) != 1 || order.Finalize == "" {
		t.Fatalf("unexpected order response: %s", orderResp.Body)
	}

	nonce = orderResp.Header.Get("Replay-Nonce")
	authzBody := signES256JWS(t, key, order.Authorizations[0], nonce, kid, nil, nil)
	authzResp := doPOST(t, order.Authorizations[0], authzBody)
	if authzResp.StatusCode != http.StatusOK {
		t.Fatalf("authorization status = %d, body = %s", authzResp.StatusCode, authzResp.Body)
	}
	if !bytes.Contains(authzResp.Body, []byte(`"type":"dns-01"`)) || !bytes.Contains(authzResp.Body, []byte(`"token":`)) {
		t.Fatalf("unexpected authorization response: %s", authzResp.Body)
	}
}

func TestACMENonceCannotBeReused(t *testing.T) {
	server := httptest.NewServer(NewServer().Handler())
	defer server.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkValue := ecJWK(key)
	nonce := fetchNonce(t, server.URL)
	url := server.URL + "/acme/new-account"
	body := signES256JWS(t, key, url, nonce, "", jwkValue, []byte(`{}`))

	first := doPOST(t, url, body)
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first request status = %d, body = %s", first.StatusCode, first.Body)
	}
	second := doPOST(t, url, body)
	if second.StatusCode != http.StatusBadRequest || !bytes.Contains(second.Body, []byte("badNonce")) {
		t.Fatalf("replayed nonce status = %d, body = %s", second.StatusCode, second.Body)
	}
}

func fetchNonce(t *testing.T, baseURL string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodHead, baseURL+"/acme/new-nonce", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("newNonce status = %d", resp.StatusCode)
	}
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		t.Fatal("newNonce response missing Replay-Nonce")
	}
	return nonce
}

type httpResult struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func doPOST(t *testing.T, url string, body []byte) httpResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return httpResult{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: []byte(strings.TrimSpace(buf.String()))}
}

func ecJWK(key *ecdsa.PrivateKey) json.RawMessage {
	size := (key.Curve.Params().BitSize + 7) / 8
	x := key.X.FillBytes(make([]byte, size))
	y := key.Y.FillBytes(make([]byte, size))
	data, _ := json.Marshal(map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	})
	return data
}

func signES256JWS(t *testing.T, key *ecdsa.PrivateKey, url, nonce, kid string, jwkValue json.RawMessage, payload []byte) []byte {
	t.Helper()
	protected := map[string]any{"alg": "ES256", "nonce": nonce, "url": url}
	if kid != "" {
		protected["kid"] = kid
	} else {
		var jwkObject any
		if err := json.Unmarshal(jwkValue, &jwkObject); err != nil {
			t.Fatal(err)
		}
		protected["jwk"] = jwkObject
	}
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
	sig := append(intBytes(r, 32), intBytes(s, 32)...)
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

func intBytes(value *big.Int, size int) []byte {
	return value.FillBytes(make([]byte, size))
}
