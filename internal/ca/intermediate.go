package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/certificate"
)

// NewIntermediate creates an intermediate CA signed by the supplied root CA.
func NewIntermediate(root *Authority, commonName string, validity time.Duration) (*Authority, error) {
	if root == nil || root.Certificate == nil || root.PrivateKey == nil {
		return nil, fmt.Errorf("root CA is incomplete")
	}

	key, err := certificate.GenerateRSAKey(4096)
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
			CommonName:   commonName,
			Organization: []string{"Go PKI Lab"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		root.Certificate,
		&key.PublicKey,
		root.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("create intermediate certificate: %w", err)
	}
	cert, err := certificate.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyPEM, err := certificate.PrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}

	return &Authority{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM:     certificate.CertificatePEM(der),
		KeyPEM:      keyPEM,
	}, nil
}
