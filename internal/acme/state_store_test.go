package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestFileStateStoreRoundTrip(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "acme", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.Update(func(state *PersistentState) error {
		state.Accounts["acct-1"] = AccountRecord{
			ID:         "acct-1",
			Status:     "valid",
			JWK:        json.RawMessage(`{"kty":"EC","crv":"P-256","x":"AQ","y":"Ag"}`),
			Thumbprint: "thumb",
		}
		state.Orders["order-1"] = Order{ID: "order-1", AccountID: "acct-1", Status: "valid", Domain: "hello.test"}
		state.Issuance["order-1"] = IssuanceRecord{
			ChallengeStatus:     "valid",
			AuthorizationStatus: "valid",
			ValidatedAt:         &now,
			CertificatePEM:      []byte("certificate-chain"),
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Accounts["acct-1"].Thumbprint != "thumb" {
		t.Fatalf("account not restored: %#v", state.Accounts["acct-1"])
	}
	if state.Orders["order-1"].Status != "valid" {
		t.Fatalf("order not restored: %#v", state.Orders["order-1"])
	}
	if string(state.Issuance["order-1"].CertificatePEM) != "certificate-chain" {
		t.Fatalf("certificate state not restored")
	}
}

func TestServerRestoresAccountAndOrder(t *testing.T) {
	store, err := NewFileStateStore(filepath.Join(t.TempDir(), "acme", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkValue := ecJWK(key)
	thumbprint, err := jwkThumbprint(jwkValue)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := parseJWK(jwkValue)
	if err != nil {
		t.Fatal(err)
	}

	first, err := NewServerWithStore(store)
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{
		ID:         "acct-1",
		Status:     "valid",
		JWK:        jwkValue,
		Thumbprint: thumbprint,
		PublicKey:  publicKey,
	}
	first.accounts[account.ID] = account
	if err := first.persistAccount(account); err != nil {
		t.Fatal(err)
	}
	order := &Order{
		ID:        "order-1",
		AccountID: account.ID,
		Status:    "ready",
		Domain:    "hello.test",
		Token:     "token",
		DNSValue:  "dns-value",
	}
	first.orders[order.ID] = order
	if err := first.persistOrder(order); err != nil {
		t.Fatal(err)
	}

	second, err := NewServerWithStore(store)
	if err != nil {
		t.Fatal(err)
	}
	restoredAccount := second.accounts[account.ID]
	if restoredAccount == nil || restoredAccount.PublicKey == nil || restoredAccount.Thumbprint != thumbprint {
		t.Fatalf("account was not fully restored: %#v", restoredAccount)
	}
	restoredOrder := second.getOrder(order.ID)
	if restoredOrder == nil || restoredOrder.Status != "ready" || restoredOrder.Domain != "hello.test" {
		t.Fatalf("order was not restored: %#v", restoredOrder)
	}
	if len(second.nonces) != 0 {
		t.Fatalf("nonces must not be persisted")
	}
}
