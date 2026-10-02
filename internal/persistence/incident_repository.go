package persistence

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type EventRepository struct {
	dir string
}

func NewEventRepository(dir string) (*EventRepository, error) {
	if dir == "" {
		return nil, fmt.Errorf("event repository directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create event repository: %w", err)
	}
	return &EventRepository{dir: dir}, nil
}

func (r *EventRepository) Save(event platform.Event) error {
	return writeJSONFile(filepath.Join(r.dir, event.ID+".json"), event)
}

func (r *EventRepository) LoadAll() ([]platform.Event, error) {
	matches, err := filepath.Glob(filepath.Join(r.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	events := make([]platform.Event, 0, len(matches))
	for _, path := range matches {
		var event platform.Event
		if err := readJSONFile(path, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

type AlertRepository struct {
	dir string
}

func NewAlertRepository(dir string) (*AlertRepository, error) {
	if dir == "" {
		return nil, fmt.Errorf("alert repository directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create alert repository: %w", err)
	}
	return &AlertRepository{dir: dir}, nil
}

func (r *AlertRepository) Save(alert platform.Alert) error {
	return writeJSONFile(filepath.Join(r.dir, alert.ID+".json"), alert)
}

func (r *AlertRepository) LoadAll() ([]platform.Alert, error) {
	matches, err := filepath.Glob(filepath.Join(r.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	alerts := make([]platform.Alert, 0, len(matches))
	for _, path := range matches {
		var alert platform.Alert
		if err := readJSONFile(path, &alert); err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	return alerts, nil
}
