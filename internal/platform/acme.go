package platform

import (
	"time"

	"github.com/alandtsang/go-pki-lab/internal/csr"
	"github.com/alandtsang/go-pki-lab/internal/order"
)

// CreateAuthorizedOrder imports an order whose domain authorization was
// already completed by an external protocol adapter such as ACME.
// The CSR is still validated by the platform before the order is marked ready.
func (s *Service) CreateAuthorizedOrder(domain string, csrPEM []byte) (*Entry, error) {
	req, err := csr.ParseAndValidate(csrPEM, domain)
	if err != nil {
		return nil, err
	}
	o, err := order.New(domain)
	if err != nil {
		return nil, err
	}
	o.Status = order.StatusReady
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	entry := &Entry{
		ID:        id,
		Order:     o,
		CSR:       req,
		CSRPEM:    append([]byte(nil), csrPEM...),
		CreatedAt: now,
		UpdatedAt: now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.persist(entry); err != nil {
		return nil, err
	}
	s.orders[id] = entry
	return cloneEntry(entry), nil
}
