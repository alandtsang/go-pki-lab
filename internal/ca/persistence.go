package ca

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alandtsang/go-pki-lab/internal/certificate"
)

func SaveAuthority(dir, name string, authority *Authority) error {
	if authority == nil || authority.Certificate == nil || authority.PrivateKey == nil {
		return fmt.Errorf("authority is incomplete")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create CA directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".crt"), authority.CertPEM, 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".key"), authority.KeyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA private key: %w", err)
	}
	return nil
}

func LoadAuthority(dir, name string) (*Authority, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, name+".crt"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, name+".key"))
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM for %s", name)
	}
	cert, err := certificate.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key PEM for %s", name)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key for %s: %w", name, err)
	}
	key, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key for %s is not RSA", name)
	}
	certKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key for %s is not RSA", name)
	}
	if key.PublicKey.N.Cmp(certKey.N) != 0 || key.PublicKey.E != certKey.E {
		return nil, fmt.Errorf("certificate and private key mismatch for %s", name)
	}
	return &Authority{Certificate: cert, PrivateKey: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}
