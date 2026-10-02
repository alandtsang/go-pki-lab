package persistence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type RenewalJobRepository struct {
	dir string
}

func NewRenewalJobRepository(dir string) (*RenewalJobRepository, error) {
	if dir == "" {
		return nil, fmt.Errorf("renewal job directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create renewal job directory: %w", err)
	}
	return &RenewalJobRepository{dir: dir}, nil
}

func (r *RenewalJobRepository) LoadAll() ([]platform.RenewalJob, error) {
	matches, err := filepath.Glob(filepath.Join(r.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	jobs := make([]platform.RenewalJob, 0, len(matches))
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read renewal job %s: %w", path, err)
		}
		var job platform.RenewalJob
		if err := json.Unmarshal(data, &job); err != nil {
			return nil, fmt.Errorf("decode renewal job %s: %w", path, err)
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (r *RenewalJobRepository) Save(job platform.RenewalJob) error {
	if job.ID == "" {
		return fmt.Errorf("renewal job id is required")
	}
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return fmt.Errorf("encode renewal job: %w", err)
	}
	path := filepath.Join(r.dir, job.ID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write renewal job: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit renewal job: %w", err)
	}
	return nil
}
