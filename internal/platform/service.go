package platform

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	"github.com/alandtsang/go-pki-lab/internal/csr"
	"github.com/alandtsang/go-pki-lab/internal/order"
)

type Entry struct {
	ID               string
	Order            *order.Order
	CSR              *x509.CertificateRequest
	CSRPEM           []byte
	Certificate      *ca.IssuedCertificate
	CreatedAt        time.Time
	UpdatedAt        time.Time
	RevokedAt        *time.Time
	RevocationReason int
	RenewedFrom      string
}

type Repository interface {
	LoadAll() ([]*Entry, error)
	Save(*Entry) error
}

type Service struct {
	mu           sync.RWMutex
	orders       map[string]*Entry
	root         *ca.Authority
	intermediate *ca.Authority
	dnsServer    string
	repository   Repository
}

func NewService(root, intermediate *ca.Authority, dnsServer string, repositories ...Repository) (*Service, error) {
	if root == nil || root.Certificate == nil {
		return nil, fmt.Errorf("root CA is required")
	}
	if intermediate == nil || intermediate.Certificate == nil || intermediate.PrivateKey == nil {
		return nil, fmt.Errorf("intermediate CA is required")
	}
	if dnsServer == "" {
		return nil, fmt.Errorf("DNS server address is required")
	}
	s := &Service{orders: make(map[string]*Entry), root: root, intermediate: intermediate, dnsServer: dnsServer}
	if len(repositories) > 0 && repositories[0] != nil {
		s.repository = repositories[0]
		entries, err := s.repository.LoadAll()
		if err != nil {
			return nil, fmt.Errorf("load persisted orders: %w", err)
		}
		for _, entry := range entries {
			if entry != nil {
				s.orders[entry.ID] = entry
			}
		}
	}
	return s, nil
}

func (s *Service) persist(entry *Entry) error {
	if s.repository == nil {
		return nil
	}
	return s.repository.Save(entry)
}

func (s *Service) CreateOrder(domain string, csrPEM []byte) (*Entry, error) {
	return s.createOrder(domain, csrPEM, "")
}

func (s *Service) createOrder(domain string, csrPEM []byte, renewedFrom string) (*Entry, error) {
	req, err := csr.ParseAndValidate(csrPEM, domain)
	if err != nil {
		return nil, err
	}
	o, err := order.New(domain)
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	entry := &Entry{ID: id, Order: o, CSR: req, CSRPEM: append([]byte(nil), csrPEM...), CreatedAt: now, UpdatedAt: now, RenewedFrom: renewedFrom}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.persist(entry); err != nil {
		return nil, err
	}
	s.orders[id] = entry
	return cloneEntry(entry), nil
}

func (s *Service) GetOrder(id string) (*Entry, error) {
	s.mu.RLock()
	entry, ok := s.orders[id]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("order %q not found", id)
	}
	return cloneEntry(entry), nil
}

func (s *Service) ValidateOrder(id string) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.orders[id]
	if !ok {
		return nil, fmt.Errorf("order %q not found", id)
	}
	if entry.Order.Status == order.StatusValid {
		return cloneEntry(entry), nil
	}
	if err := entry.Order.ValidateDNS01(s.dnsServer); err != nil {
		entry.UpdatedAt = time.Now().UTC()
		_ = s.persist(entry)
		return cloneEntry(entry), err
	}
	entry.UpdatedAt = time.Now().UTC()
	if err := s.persist(entry); err != nil {
		return cloneEntry(entry), err
	}
	return cloneEntry(entry), nil
}

func (s *Service) IssueOrder(id string, validity time.Duration) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.orders[id]
	if !ok {
		return nil, fmt.Errorf("order %q not found", id)
	}
	if entry.Certificate != nil && entry.Order.Status == order.StatusValid {
		return cloneEntry(entry), nil
	}
	if entry.Order.Status != order.StatusReady {
		return cloneEntry(entry), fmt.Errorf("order must be ready before issuance, current status: %s", entry.Order.Status)
	}
	if entry.CSR == nil {
		return cloneEntry(entry), fmt.Errorf("order CSR is missing")
	}

	leaf, err := ca.IssueServerCertificateFromCSR(s.intermediate, entry.CSR, validity)
	if err != nil {
		return cloneEntry(entry), err
	}
	if err := ca.VerifyServerCertificate(leaf.Certificate, s.root, s.intermediate, entry.Order.Domain); err != nil {
		return cloneEntry(entry), err
	}
	if err := entry.Order.MarkIssued(); err != nil {
		return cloneEntry(entry), err
	}
	entry.Certificate = leaf
	entry.UpdatedAt = time.Now().UTC()
	if err := s.persist(entry); err != nil {
		return cloneEntry(entry), err
	}
	return cloneEntry(entry), nil
}

func (s *Service) RenewOrder(id string) (*Entry, error) {
	s.mu.RLock()
	entry, ok := s.orders[id]
	if !ok {
		s.mu.RUnlock()
		return nil, fmt.Errorf("order %q not found", id)
	}
	if entry.Certificate == nil || entry.Order.Status != order.StatusValid {
		s.mu.RUnlock()
		return nil, fmt.Errorf("only an issued certificate can be renewed")
	}
	domain := entry.Order.Domain
	csrPEM := append([]byte(nil), entry.CSRPEM...)
	s.mu.RUnlock()
	return s.createOrder(domain, csrPEM, id)
}

func (s *Service) RevokeOrder(id string, reason int) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.orders[id]
	if !ok {
		return nil, fmt.Errorf("order %q not found", id)
	}
	if entry.Certificate == nil || entry.Order.Status != order.StatusValid {
		return cloneEntry(entry), fmt.Errorf("only an issued certificate can be revoked")
	}
	if entry.RevokedAt != nil {
		return cloneEntry(entry), nil
	}
	now := time.Now().UTC()
	entry.RevokedAt = &now
	entry.RevocationReason = reason
	entry.UpdatedAt = now
	if err := s.persist(entry); err != nil {
		return cloneEntry(entry), err
	}
	return cloneEntry(entry), nil
}

func (s *Service) CertificateStatus(serial string) (map[string]any, error) {
	serial = strings.TrimSpace(strings.ToLower(serial))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.orders {
		if entry.Certificate == nil || entry.Certificate.Certificate == nil {
			continue
		}
		cert := entry.Certificate.Certificate
		if strings.ToLower(cert.SerialNumber.Text(16)) != serial {
			continue
		}
		status := "good"
		if entry.RevokedAt != nil {
			status = "revoked"
		} else if time.Now().After(cert.NotAfter) {
			status = "expired"
		}
		return map[string]any{
			"serial_number":     cert.SerialNumber.Text(16),
			"order_id":          entry.ID,
			"domain":            entry.Order.Domain,
			"status":            status,
			"not_before":        cert.NotBefore,
			"not_after":         cert.NotAfter,
			"revoked_at":        entry.RevokedAt,
			"revocation_reason": entry.RevocationReason,
		}, nil
	}
	return nil, fmt.Errorf("certificate serial %q not found", serial)
}

func (s *Service) CRLPEM() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := make([]x509.RevocationListEntry, 0)
	for _, entry := range s.orders {
		if entry.Certificate == nil || entry.Certificate.Certificate == nil || entry.RevokedAt == nil {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   entry.Certificate.Certificate.SerialNumber,
			RevocationTime: *entry.RevokedAt,
			ReasonCode:     entry.RevocationReason,
		})
	}
	now := time.Now().UTC()
	number, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CRL number: %w", err)
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:        s.intermediate.Certificate.SignatureAlgorithm,
		RevokedCertificateEntries: entries,
		Number:                    number,
		ThisUpdate:                now,
		NextUpdate:                now.Add(24 * time.Hour),
	}, s.intermediate.Certificate, s.intermediate.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create CRL: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

func randomID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate order id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func cloneEntry(entry *Entry) *Entry {
	if entry == nil {
		return nil
	}
	copyEntry := *entry
	copyEntry.CSRPEM = append([]byte(nil), entry.CSRPEM...)
	if entry.RevokedAt != nil {
		t := *entry.RevokedAt
		copyEntry.RevokedAt = &t
	}
	if entry.Order != nil {
		copyOrder := *entry.Order
		if entry.Order.Challenge != nil {
			copyChallenge := *entry.Order.Challenge
			copyOrder.Challenge = &copyChallenge
		}
		copyEntry.Order = &copyOrder
	}
	return &copyEntry
}
