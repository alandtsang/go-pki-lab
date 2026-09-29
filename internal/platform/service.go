package platform

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	"github.com/alandtsang/go-pki-lab/internal/order"
)

// Entry is the platform representation of a certificate order.
type Entry struct {
	ID          string
	Order       *order.Order
	Certificate *ca.IssuedCertificate
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Service coordinates certificate orders, DNS-01 validation and issuance.
type Service struct {
	mu           sync.RWMutex
	orders       map[string]*Entry
	root         *ca.Authority
	intermediate *ca.Authority
	dnsServer    string
}

func NewService(root, intermediate *ca.Authority, dnsServer string) (*Service, error) {
	if root == nil || root.Certificate == nil {
		return nil, fmt.Errorf("root CA is required")
	}
	if intermediate == nil || intermediate.Certificate == nil || intermediate.PrivateKey == nil {
		return nil, fmt.Errorf("intermediate CA is required")
	}
	if dnsServer == "" {
		return nil, fmt.Errorf("DNS server address is required")
	}
	return &Service{
		orders:       make(map[string]*Entry),
		root:         root,
		intermediate: intermediate,
		dnsServer:    dnsServer,
	}, nil
}

func (s *Service) CreateOrder(domain string) (*Entry, error) {
	o, err := order.New(domain)
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	entry := &Entry{ID: id, Order: o, CreatedAt: now, UpdatedAt: now}

	s.mu.Lock()
	s.orders[id] = entry
	s.mu.Unlock()
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
		return cloneEntry(entry), err
	}
	entry.UpdatedAt = time.Now().UTC()
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

	leaf, err := ca.IssueServerCertificate(s.intermediate, entry.Order.Domain, validity)
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
	return cloneEntry(entry), nil
}

func randomID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate order id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// cloneEntry returns a shallow immutable snapshot suitable for API responses.
// The certificate and challenge objects are treated as read-only after publication.
func cloneEntry(entry *Entry) *Entry {
	if entry == nil {
		return nil
	}
	copyEntry := *entry
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
