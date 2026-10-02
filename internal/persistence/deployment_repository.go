package persistence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type DeploymentTargetRepository struct {
	dir string
}

func NewDeploymentTargetRepository(dir string) (*DeploymentTargetRepository, error) {
	if dir == "" {
		return nil, fmt.Errorf("deployment target repository directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create deployment target repository: %w", err)
	}
	return &DeploymentTargetRepository{dir: dir}, nil
}

func (r *DeploymentTargetRepository) Save(target platform.DeploymentTarget) error {
	return writeJSONFile(filepath.Join(r.dir, target.ID+".json"), target)
}

func (r *DeploymentTargetRepository) LoadAll() ([]platform.DeploymentTarget, error) {
	matches, err := filepath.Glob(filepath.Join(r.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	targets := make([]platform.DeploymentTarget, 0, len(matches))
	for _, path := range matches {
		var target platform.DeploymentTarget
		if err := readJSONFile(path, &target); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, nil
}

type DeploymentJobRepository struct {
	dir string
}

func NewDeploymentJobRepository(dir string) (*DeploymentJobRepository, error) {
	if dir == "" {
		return nil, fmt.Errorf("deployment job repository directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create deployment job repository: %w", err)
	}
	return &DeploymentJobRepository{dir: dir}, nil
}

func (r *DeploymentJobRepository) Save(job platform.DeploymentJob) error {
	return writeJSONFile(filepath.Join(r.dir, job.ID+".json"), job)
}

func (r *DeploymentJobRepository) LoadAll() ([]platform.DeploymentJob, error) {
	matches, err := filepath.Glob(filepath.Join(r.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	jobs := make([]platform.DeploymentJob, 0, len(matches))
	for _, path := range matches {
		var job platform.DeploymentJob
		if err := readJSONFile(path, &job); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func writeJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit %s: %w", path, err)
	}
	return nil
}

func readJSONFile(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
