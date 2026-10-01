package acme

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AccountRecord struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	Contact    []string        `json:"contact,omitempty"`
	JWK        json.RawMessage `json:"jwk"`
	Thumbprint string          `json:"thumbprint"`
}

type IssuanceRecord struct {
	ChallengeStatus     string     `json:"challenge_status,omitempty"`
	AuthorizationStatus string     `json:"authorization_status,omitempty"`
	ValidatedAt         *time.Time `json:"validated_at,omitempty"`
	CertificatePEM      []byte     `json:"certificate_pem,omitempty"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	RevocationReason    int        `json:"revocation_reason,omitempty"`
}

type PersistentState struct {
	Accounts map[string]AccountRecord  `json:"accounts"`
	Orders   map[string]Order          `json:"orders"`
	Issuance map[string]IssuanceRecord `json:"issuance"`
}

type StateStore interface {
	Load() (*PersistentState, error)
	Update(func(*PersistentState) error) error
}

type FileStateStore struct {
	mu   sync.Mutex
	path string
}

func NewFileStateStore(path string) (*FileStateStore, error) {
	if path == "" {
		return nil, fmt.Errorf("ACME state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create ACME state directory: %w", err)
	}
	return &FileStateStore{path: path}, nil
}

func (s *FileStateStore) Load() (*PersistentState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *FileStateStore) Update(update func(*PersistentState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.loadLocked()
	if err != nil {
		return err
	}
	if err := update(state); err != nil {
		return err
	}
	return s.saveLocked(state)
}

func (s *FileStateStore) loadLocked() (*PersistentState, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return newPersistentState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read ACME state: %w", err)
	}
	var state PersistentState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode ACME state: %w", err)
	}
	normalizePersistentState(&state)
	return &state, nil
}

func (s *FileStateStore) saveLocked(state *PersistentState) error {
	normalizePersistentState(state)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode ACME state: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".acme-state-*")
	if err != nil {
		return fmt.Errorf("create ACME state temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod ACME state temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write ACME state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync ACME state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close ACME state: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace ACME state: %w", err)
	}
	return nil
}

func newPersistentState() *PersistentState {
	return &PersistentState{
		Accounts: make(map[string]AccountRecord),
		Orders:   make(map[string]Order),
		Issuance: make(map[string]IssuanceRecord),
	}
}

func normalizePersistentState(state *PersistentState) {
	if state.Accounts == nil {
		state.Accounts = make(map[string]AccountRecord)
	}
	if state.Orders == nil {
		state.Orders = make(map[string]Order)
	}
	if state.Issuance == nil {
		state.Issuance = make(map[string]IssuanceRecord)
	}
}
