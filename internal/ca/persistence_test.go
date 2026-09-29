package ca

import (
	"bytes"
	"testing"
	"time"
)

func TestAuthorityPersistenceRoundTrip(t *testing.T) {
	root, err := NewRoot("Persistent Root", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := SaveAuthority(dir, "root", root); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAuthority(dir, "root")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root.Certificate.Raw, loaded.Certificate.Raw) {
		t.Fatal("loaded certificate differs from saved certificate")
	}
	if root.PrivateKey.PublicKey.N.Cmp(loaded.PrivateKey.PublicKey.N) != 0 {
		t.Fatal("loaded private key differs from saved private key")
	}
}
