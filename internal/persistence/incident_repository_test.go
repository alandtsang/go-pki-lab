package persistence

import (
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

func TestIncidentRepositoriesRoundTrip(t *testing.T) {
	base := t.TempDir()
	eventRepo, err := NewEventRepository(base + "/events")
	if err != nil {
		t.Fatal(err)
	}
	alertRepo, err := NewAlertRepository(base + "/alerts")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	event := platform.Event{
		ID:             "event-1",
		TargetID:       "target-1",
		Domain:         "hello.test",
		PreviousStatus: platform.MonitoringHealthy,
		CurrentStatus:  platform.MonitoringSerialMismatch,
		OccurredAt:     now,
		Message:        "changed",
	}
	alert := platform.Alert{
		ID:          "alert-1",
		TargetID:    "target-1",
		Domain:      "hello.test",
		Type:        platform.MonitoringSerialMismatch,
		Status:      platform.AlertStatusFiring,
		FirstSeenAt: now,
		LastSeenAt:  now,
		Occurrences: 1,
	}
	if err := eventRepo.Save(event); err != nil {
		t.Fatal(err)
	}
	if err := alertRepo.Save(alert); err != nil {
		t.Fatal(err)
	}

	events, err := eventRepo.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != event.ID || events[0].CurrentStatus != event.CurrentStatus {
		t.Fatalf("unexpected events: %#v", events)
	}
	alerts, err := alertRepo.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].ID != alert.ID || alerts[0].Status != alert.Status {
		t.Fatalf("unexpected alerts: %#v", alerts)
	}
}
