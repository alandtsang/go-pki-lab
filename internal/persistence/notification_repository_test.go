package persistence

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

func TestNotificationDeliveryRepositoryRoundTrip(t *testing.T) {
	repository, err := NewNotificationDeliveryRepository(filepath.Join(t.TempDir(), "deliveries"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	delivery := platform.NotificationDelivery{
		ID:        "delivery-1",
		AlertID:   "alert-1",
		TargetID:  "target-1",
		Domain:    "hello.test",
		AlertType: platform.MonitoringSerialMismatch,
		Event:     platform.NotificationEventFiring,
		Message:   "certificate drift detected",
		Sink:      "webhook",
		Status:    platform.NotificationStatusFailed,
		Attempts:  2,
		LastError: "temporary failure",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := repository.Save(delivery); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(loaded))
	}
	if loaded[0].ID != delivery.ID || loaded[0].Status != delivery.Status || loaded[0].Attempts != 2 || loaded[0].Message != delivery.Message {
		t.Fatalf("unexpected loaded delivery: %#v", loaded[0])
	}
}
