package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateRSAKey creates an RSA private key suitable for test PKI usage.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("rsa key size must be at least 2048 bits")
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// PrivateKeyPEM encodes an RSA private key as PKCS#8 PEM.
func PrivateKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
