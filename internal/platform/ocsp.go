package platform

import (
	"bytes"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPResponse parses an RFC 6960 OCSP request and returns a signed response
// from the persistent Intermediate CA.
func (s *Service) OCSPResponse(requestDER []byte) ([]byte, error) {
	req, err := ocsp.ParseRequest(requestDER)
	if err != nil {
		return nil, fmt.Errorf("parse OCSP request: %w", err)
	}

	now := time.Now().UTC()
	template := ocsp.Response{
		Status:       ocsp.Unknown,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
		ProducedAt:   now,
	}

	s.mu.RLock()
	for _, entry := range s.orders {
		if entry == nil || entry.Certificate == nil || entry.Certificate.Certificate == nil {
			continue
		}
		cert := entry.Certificate.Certificate
		if cert.SerialNumber.Cmp(req.SerialNumber) != 0 {
			continue
		}

		expectedDER, err := ocsp.CreateRequest(cert, s.intermediate.Certificate, &ocsp.RequestOptions{Hash: req.HashAlgorithm})
		if err != nil {
			s.mu.RUnlock()
			return nil, fmt.Errorf("build expected OCSP request: %w", err)
		}
		expected, err := ocsp.ParseRequest(expectedDER)
		if err != nil {
			s.mu.RUnlock()
			return nil, fmt.Errorf("parse expected OCSP request: %w", err)
		}
		if !bytes.Equal(req.IssuerNameHash, expected.IssuerNameHash) || !bytes.Equal(req.IssuerKeyHash, expected.IssuerKeyHash) {
			s.mu.RUnlock()
			return nil, fmt.Errorf("OCSP request issuer does not match Intermediate CA")
		}

		template.Status = ocsp.Good
		if entry.RevokedAt != nil {
			template.Status = ocsp.Revoked
			template.RevokedAt = *entry.RevokedAt
			template.RevocationReason = entry.RevocationReason
		}
		break
	}
	s.mu.RUnlock()

	responseDER, err := ocsp.CreateResponse(
		s.intermediate.Certificate,
		s.intermediate.Certificate,
		template,
		s.intermediate.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("create OCSP response: %w", err)
	}
	return responseDER, nil
}
