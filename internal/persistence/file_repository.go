package persistence

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	"github.com/alandtsang/go-pki-lab/internal/challenge"
	"github.com/alandtsang/go-pki-lab/internal/csr"
	"github.com/alandtsang/go-pki-lab/internal/order"
	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type FileRepository struct {
	dir string
}

func NewFileRepository(dir string) (*FileRepository, error) {
	if dir == "" {
		return nil, fmt.Errorf("repository directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create repository directory: %w", err)
	}
	return &FileRepository{dir: dir}, nil
}

type record struct {
	ID               string       `json:"id"`
	Domain           string       `json:"domain"`
	Status           order.Status `json:"status"`
	ChallengeName    string       `json:"challenge_name"`
	ChallengeToken   string       `json:"challenge_token"`
	CSRPEM           string       `json:"csr_pem"`
	CertificatePEM   string       `json:"certificate_pem,omitempty"`
	FullChainPEM     string       `json:"fullchain_pem,omitempty"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
	RevokedAt        *time.Time   `json:"revoked_at,omitempty"`
	RevocationReason int          `json:"revocation_reason,omitempty"`
	RenewedFrom      string       `json:"renewed_from,omitempty"`
}

func (r *FileRepository) Save(entry *platform.Entry) error {
	if entry == nil || entry.Order == nil || entry.Order.Challenge == nil {
		return fmt.Errorf("entry is incomplete")
	}
	rec := record{
		ID: entry.ID, Domain: entry.Order.Domain, Status: entry.Order.Status,
		ChallengeName: entry.Order.Challenge.Name, ChallengeToken: entry.Order.Challenge.Token,
		CSRPEM: string(entry.CSRPEM), CreatedAt: entry.CreatedAt, UpdatedAt: entry.UpdatedAt,
		RevokedAt: entry.RevokedAt, RevocationReason: entry.RevocationReason, RenewedFrom: entry.RenewedFrom,
	}
	if entry.Certificate != nil {
		rec.CertificatePEM = string(entry.Certificate.CertPEM)
		rec.FullChainPEM = string(entry.Certificate.FullChainPEM)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal order: %w", err)
	}
	path := filepath.Join(r.dir, entry.ID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write order: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit order: %w", err)
	}
	return nil
}

func (r *FileRepository) LoadAll() ([]*platform.Entry, error) {
	matches, err := filepath.Glob(filepath.Join(r.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	entries := make([]*platform.Entry, 0, len(matches))
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var rec record
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		req, err := csr.ParseAndValidate([]byte(rec.CSRPEM), rec.Domain)
		if err != nil {
			return nil, fmt.Errorf("restore order %s CSR: %w", rec.ID, err)
		}
		entry := &platform.Entry{
			ID: rec.ID,
			Order: &order.Order{Domain: rec.Domain, Status: rec.Status, Challenge: &challenge.DNS01{Domain: rec.Domain, Name: rec.ChallengeName, Token: rec.ChallengeToken}},
			CSR: req, CSRPEM: []byte(rec.CSRPEM), CreatedAt: rec.CreatedAt, UpdatedAt: rec.UpdatedAt,
			RevokedAt: rec.RevokedAt, RevocationReason: rec.RevocationReason, RenewedFrom: rec.RenewedFrom,
		}
		if rec.CertificatePEM != "" {
			block, _ := pem.Decode([]byte(rec.CertificatePEM))
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("restore order %s: invalid certificate PEM", rec.ID)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("restore order %s certificate: %w", rec.ID, err)
			}
			entry.Certificate = &ca.IssuedCertificate{Certificate: cert, CertPEM: []byte(rec.CertificatePEM), FullChainPEM: []byte(rec.FullChainPEM)}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
