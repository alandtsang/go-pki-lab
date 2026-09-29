package order

import (
	"fmt"

	"github.com/alandtsang/go-pki-lab/internal/challenge"
)

type Status string

const (
	StatusPending Status = "pending"
	StatusReady   Status = "ready"
	StatusValid   Status = "valid"
	StatusInvalid Status = "invalid"
)

type Order struct {
	Domain    string
	Status    Status
	Challenge *challenge.DNS01
}

func New(domain string) (*Order, error) {
	ch, err := challenge.NewDNS01(domain)
	if err != nil {
		return nil, err
	}
	return &Order{Domain: domain, Status: StatusPending, Challenge: ch}, nil
}

func (o *Order) ValidateDNS01(serverAddr string) error {
	if o == nil || o.Challenge == nil {
		return fmt.Errorf("order challenge is missing")
	}
	if err := o.Challenge.Verify(serverAddr); err != nil {
		o.Status = StatusInvalid
		return err
	}
	o.Status = StatusReady
	return nil
}

func (o *Order) MarkIssued() error {
	if o == nil {
		return fmt.Errorf("order is required")
	}
	if o.Status != StatusReady {
		return fmt.Errorf("order must be ready before issuance, current status: %s", o.Status)
	}
	o.Status = StatusValid
	return nil
}
