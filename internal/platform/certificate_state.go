package platform

import (
	"crypto/x509"
	"math/big"
	"time"
)

// CertificateState is a protocol-neutral certificate lifecycle view used by
// status, CRL, and OCSP code. External issuers such as the ACME layer can
// register a source without the platform package depending on them directly.
type CertificateState struct {
	Certificate      *x509.Certificate
	Domain           string
	SourceID         string
	RevokedAt        *time.Time
	RevocationReason int
}

// CertificateStateSource exposes certificates issued outside platform Orders.
type CertificateStateSource interface {
	FindCertificateBySerial(serial *big.Int) (*CertificateState, bool, error)
	RevokedCertificates() ([]CertificateState, error)
}

func (s *Service) AddCertificateStateSource(source CertificateStateSource) {
	if source == nil {
		return
	}
	s.mu.Lock()
	s.certificateSources = append(s.certificateSources, source)
	s.mu.Unlock()
}

func (s *Service) findCertificateStateBySerial(serial *big.Int) (*CertificateState, bool, error) {
	if serial == nil {
		return nil, false, nil
	}

	s.mu.RLock()
	for _, entry := range s.orders {
		if entry == nil || entry.Certificate == nil || entry.Certificate.Certificate == nil {
			continue
		}
		cert := entry.Certificate.Certificate
		if cert.SerialNumber.Cmp(serial) != 0 {
			continue
		}
		state := &CertificateState{
			Certificate:      cert,
			SourceID:         entry.ID,
			RevokedAt:        entry.RevokedAt,
			RevocationReason: entry.RevocationReason,
		}
		if entry.Order != nil {
			state.Domain = entry.Order.Domain
		}
		s.mu.RUnlock()
		return state, true, nil
	}
	sources := append([]CertificateStateSource(nil), s.certificateSources...)
	s.mu.RUnlock()

	for _, source := range sources {
		state, found, err := source.FindCertificateBySerial(serial)
		if err != nil {
			return nil, false, err
		}
		if found {
			return state, true, nil
		}
	}
	return nil, false, nil
}

func (s *Service) revokedCertificateStates() ([]CertificateState, error) {
	states := make([]CertificateState, 0)

	s.mu.RLock()
	for _, entry := range s.orders {
		if entry == nil || entry.Certificate == nil || entry.Certificate.Certificate == nil || entry.RevokedAt == nil {
			continue
		}
		state := CertificateState{
			Certificate:      entry.Certificate.Certificate,
			SourceID:         entry.ID,
			RevokedAt:        entry.RevokedAt,
			RevocationReason: entry.RevocationReason,
		}
		if entry.Order != nil {
			state.Domain = entry.Order.Domain
		}
		states = append(states, state)
	}
	sources := append([]CertificateStateSource(nil), s.certificateSources...)
	s.mu.RUnlock()

	for _, source := range sources {
		external, err := source.RevokedCertificates()
		if err != nil {
			return nil, err
		}
		states = append(states, external...)
	}
	return states, nil
}
