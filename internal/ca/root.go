package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/certificate"
)

type Authority struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}

// NewRoot creates a self-signed root certificate authority.
func NewRoot(commonName string, validity time.Duration) (*Authority, error) {
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
		MaxPathLen:            1,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageDigitalSignature,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create root certificate: %w", err)
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
