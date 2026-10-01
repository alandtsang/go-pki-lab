package platform

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

// CertificateState is a protocol-neutral certificate lifecycle view used by
// status, CRL, OCSP, history-query, and certificate-instance code. External
// issuers such as the ACME layer can register a source without the platform
// package depending on them directly.
type CertificateState struct {
	Certificate      *x509.Certificate
	Domain           string
	SourceID         string
	RevokedAt        *time.Time
	RevocationReason int
}

// CertificateHistoryItem is the stable API view for one certificate generation.
type CertificateHistoryItem struct {
	SerialNumber     string     `json:"serial_number"`
	Domain           string     `json:"domain"`
	OrderID          string     `json:"order_id"`
	Status           string     `json:"status"`
	NotBefore        time.Time  `json:"not_before"`
	NotAfter         time.Time  `json:"not_after"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason int        `json:"revocation_reason,omitempty"`
}

// DomainCertificateInstance is the platform-level view of one managed domain.
// CurrentCertificate is the newest currently usable certificate, while History
// retains every issued generation for audit and lifecycle decisions.
type DomainCertificateInstance struct {
	Domain             string                    `json:"domain"`
	Status             string                    `json:"status"`
	CurrentCertificate *CertificateHistoryItem   `json:"current_certificate"`
	HistoryCount       int                       `json:"history_count"`
	History            []CertificateHistoryItem  `json:"history"`
}

// CertificateStateSource exposes certificates issued outside platform Orders.
type CertificateStateSource interface {
	FindCertificateBySerial(serial *big.Int) (*CertificateState, bool, error)
	RevokedCertificates() ([]CertificateState, error)
	CertificatesByDomain(domain string) ([]CertificateState, error)
}

func (s *Service) AddCertificateStateSource(source CertificateStateSource) {
	if source == nil {
		return
	}
	s.mu.Lock()
	s.certificateSources = append(s.certificateSources, source)
	s.mu.Unlock()
}

// CertificateSerialHex returns the certificate serial in byte-preserving,
// uppercase hexadecimal form. Unlike big.Int.Text(16), this preserves a
// leading zero nibble inside the first serial byte, matching openssl -serial.
func CertificateSerialHex(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes()))
}

// DomainCertificateInstance returns the managed-certificate view for a domain.
// The current certificate is the newest certificate whose lifecycle state is
// good. Revoked, expired, not-yet-valid, failed, and pending generations are
// never selected as current.
func (s *Service) DomainCertificateInstance(domain string) (*DomainCertificateInstance, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	history, err := s.CertificateHistory(domain)
	if err != nil {
		return nil, err
	}
	instance := &DomainCertificateInstance{
		Domain:       domain,
		Status:       "no_active_certificate",
		HistoryCount: len(history),
		History:      history,
	}
	for idx := range history {
		if history[idx].Status != "good" {
			continue
		}
		current := history[idx]
		instance.CurrentCertificate = &current
		instance.Status = "active"
		break
	}
	return instance, nil
}

// CertificateHistory returns every issued certificate generation for a domain,
// newest first. Pending/failed Orders are intentionally excluded because they
// have no certificate identity yet.
func (s *Service) CertificateHistory(domain string) ([]CertificateHistoryItem, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	states := make([]CertificateState, 0)
	s.mu.RLock()
	for _, entry := range s.orders {
		if entry == nil || entry.Order == nil || entry.Certificate == nil || entry.Certificate.Certificate == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSuffix(entry.Order.Domain, "."), domain) {
			continue
		}
		states = append(states, CertificateState{
			Certificate:      entry.Certificate.Certificate,
			Domain:           entry.Order.Domain,
			SourceID:         entry.ID,
			RevokedAt:        entry.RevokedAt,
			RevocationReason: entry.RevocationReason,
		})
	}
	sources := append([]CertificateStateSource(nil), s.certificateSources...)
	s.mu.RUnlock()

	for _, source := range sources {
		external, err := source.CertificatesByDomain(domain)
		if err != nil {
			return nil, err
		}
		states = append(states, external...)
	}

	now := time.Now().UTC()
	items := make([]CertificateHistoryItem, 0, len(states))
	seen := make(map[string]struct{}, len(states))
	for _, state := range states {
		if state.Certificate == nil || state.Certificate.SerialNumber == nil {
			continue
		}
		serial := CertificateSerialHex(state.Certificate)
		if _, ok := seen[serial]; ok {
			continue
		}
		seen[serial] = struct{}{}

		status := "good"
		if state.RevokedAt != nil {
			status = "revoked"
		} else if now.After(state.Certificate.NotAfter) {
			status = "expired"
		} else if now.Before(state.Certificate.NotBefore) {
			status = "not_yet_valid"
		}
		items = append(items, CertificateHistoryItem{
			SerialNumber:     serial,
			Domain:           state.Domain,
			OrderID:          state.SourceID,
			Status:           status,
			NotBefore:        state.Certificate.NotBefore,
			NotAfter:         state.Certificate.NotAfter,
			RevokedAt:        state.RevokedAt,
			RevocationReason: state.RevocationReason,
		})
	}

	sort.Slice(items, func(a, b int) bool {
		if items[a].NotBefore.Equal(items[b].NotBefore) {
			return items[a].SerialNumber > items[b].SerialNumber
		}
		return items[a].NotBefore.After(items[b].NotBefore)
	})
	return items, nil
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
