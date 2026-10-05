package persistence

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type NotificationDeliveryRepository struct {
	dir string
}

func NewNotificationDeliveryRepository(dir string) (*NotificationDeliveryRepository, error) {
	if dir == "" {
		return nil, fmt.Errorf("notification delivery repository directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create notification delivery repository: %w", err)
	}
	return &NotificationDeliveryRepository{dir: dir}, nil
}

func (r *NotificationDeliveryRepository) Save(delivery platform.NotificationDelivery) error {
	return writeJSONFile(filepath.Join(r.dir, delivery.ID+".json"), delivery)
}

func (r *NotificationDeliveryRepository) LoadAll() ([]platform.NotificationDelivery, error) {
	matches, err := filepath.Glob(filepath.Join(r.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	deliveries := make([]platform.NotificationDelivery, 0, len(matches))
	for _, path := range matches {
		var delivery platform.NotificationDelivery
		if err := readJSONFile(path, &delivery); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, nil
}
