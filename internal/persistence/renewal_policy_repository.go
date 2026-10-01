package persistence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type RenewalPolicyRepository struct {
	dir string
}

func NewRenewalPolicyRepository(dir string) (*RenewalPolicyRepository, error) {
	if dir == "" {
		return nil, fmt.Errorf("renewal policy directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create renewal policy directory: %w", err)
	}
	return &RenewalPolicyRepository{dir: dir}, nil
}

func (r *RenewalPolicyRepository) Save(policy platform.RenewalPolicy) error {
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal renewal policy: %w", err)
	}
	path := filepath.Join(r.dir, renewalPolicyFilename(policy.Domain))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write renewal policy: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit renewal policy: %w", err)
	}
	return nil
}

func (r *RenewalPolicyRepository) LoadAll() ([]platform.RenewalPolicy, error) {
	matches, err := filepath.Glob(filepath.Join(r.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	policies := make([]platform.RenewalPolicy, 0, len(matches))
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var policy platform.RenewalPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

func renewalPolicyFilename(domain string) string {
	sum := sha256.Sum256([]byte(domain))
	return hex.EncodeToString(sum[:]) + ".json"
}
