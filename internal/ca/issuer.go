package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/certificate"
)

type IssuedCertificate struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
	FullChainPEM []byte
}

// IssueServerCertificate issues a TLS server certificate for domain.
func IssueServerCertificate(intermediate *Authority, domain string, validity time.Duration) (*IssuedCertificate, error) {
	if intermediate == nil || intermediate.Certificate == nil || intermediate.PrivateKey == nil {
		return nil, fmt.Errorf("intermediate CA is incomplete")
	}
	if domain == "" {
		return nil, fmt.Errorf("domain must not be empty")
	}

	key, err := certificate.GenerateRSAKey(2048)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		intermediate.Certificate,
		&key.PublicKey,
		intermediate.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("issue server certificate: %w", err)
	}
	cert, err := certificate.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyPEM, err := certificate.PrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	certPEM := certificate.CertificatePEM(der)
	fullChain := append(append([]byte{}, certPEM...), intermediate.CertPEM...)

	return &IssuedCertificate{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		FullChainPEM: fullChain,
	}, nil
}

// VerifyServerCertificate verifies the leaf against the provided root and intermediate CAs.
func VerifyServerCertificate(leaf *x509.Certificate, root, intermediate *Authority, domain string) error {
	if leaf == nil || root == nil || intermediate == nil {
		return fmt.Errorf("leaf, root and intermediate certificates are required")
	}

	roots := x509.NewCertPool()
	roots.AddCert(root.Certificate)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate.Certificate)

	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       domain,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("verify certificate chain: %w", err)
	}
	return nil
}
