package csr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/alandtsang/go-pki-lab/internal/certificate"
)

// Request bundles a client-generated private key and CSR for local lab use.
type Request struct {
	PrivateKey *rsa.PrivateKey
	CSR        *x509.CertificateRequest
	KeyPEM     []byte
	CSRPEM     []byte
}

// Generate creates a client-side RSA private key and a CSR containing the domain in SAN.
func Generate(domain string) (*Request, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain must not be empty")
	}

	key, err := certificate.GenerateRSAKey(2048)
	if err != nil {
		return nil, err
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated CSR: %w", err)
	}
	keyPEM, err := certificate.PrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	return &Request{PrivateKey: key, CSR: parsed, KeyPEM: keyPEM, CSRPEM: csrPEM}, nil
}

// ParseAndValidate parses a PEM CSR, checks its signature, and requires exactly the requested DNS SAN.
func ParseAndValidate(csrPEM []byte, domain string) (*x509.CertificateRequest, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain must not be empty")
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("CSR PEM must contain exactly one request")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := req.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify CSR signature: %w", err)
	}
	if len(req.DNSNames) != 1 || !strings.EqualFold(strings.TrimSuffix(req.DNSNames[0], "."), strings.TrimSuffix(domain, ".")) {
		return nil, fmt.Errorf("CSR SAN must contain exactly requested domain %q", domain)
	}
	return req, nil
}
