package platform

import (
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
)

type memoryEventRepository struct {
	events map[string]Event
}

func (r *memoryEventRepository) LoadAll() ([]Event, error) {
	result := make([]Event, 0, len(r.events))
	for _, event := range r.events {
		result = append(result, event)
	}
	return result, nil
}

func (r *memoryEventRepository) Save(event Event) error {
	if r.events == nil {
		r.events = make(map[string]Event)
	}
	r.events[event.ID] = event
	return nil
}

type memoryAlertRepository struct {
	alerts map[string]Alert
}

func (r *memoryAlertRepository) LoadAll() ([]Alert, error) {
	result := make([]Alert, 0, len(r.alerts))
	for _, alert := range r.alerts {
		result = append(result, alert)
	}
	return result, nil
}

func (r *memoryAlertRepository) Save(alert Alert) error {
	if r.alerts == nil {
		r.alerts = make(map[string]Alert)
	}
	r.alerts[alert.ID] = alert
	return nil
}

func newIncidentTestService(t *testing.T) *Service {
	t.Helper()
	root, err := ca.NewRoot("Test Root", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "Test Intermediate", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(root, intermediate, "127.0.0.1:1053")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetEventRepository(&memoryEventRepository{events: make(map[string]Event)}); err != nil {
		t.Fatal(err)
	}
	if err := service.SetAlertRepository(&memoryAlertRepository{alerts: make(map[string]Alert)}); err != nil {
		t.Fatal(err)
	}
	return service
}

func TestMonitoringTransitionAlertLifecycle(t *testing.T) {
	service := newIncidentTestService(t)
	target := DeploymentTarget{ID: "target-1", Domain: "hello.test"}
	t0 := time.Now().UTC()
	healthy := MonitoringState{Status: MonitoringHealthy, CheckedAt: t0}
	mismatch := MonitoringState{Status: MonitoringSerialMismatch, CheckedAt: t0.Add(time.Second)}
	recovered := MonitoringState{Status: MonitoringHealthy, CheckedAt: t0.Add(2 * time.Second)}

	if err := service.RecordMonitoringTransition(target, healthy, mismatch); err != nil {
		t.Fatal(err)
	}
	if got := len(service.Events(target.ID)); got != 1 {
		t.Fatalf("expected 1 event, got %d", got)
	}
	firing := service.Alerts(AlertStatusFiring, target.ID)
	if len(firing) != 1 {
		t.Fatalf("expected 1 firing alert, got %d", len(firing))
	}
	if firing[0].Type != MonitoringSerialMismatch {
		t.Fatalf("expected serial_mismatch alert, got %q", firing[0].Type)
	}

	if err := service.RecordMonitoringTransition(target, mismatch, mismatch); err != nil {
		t.Fatal(err)
	}
	if got := len(service.Events(target.ID)); got != 1 {
		t.Fatalf("same state must not create another event, got %d", got)
	}
	if got := len(service.Alerts(AlertStatusFiring, target.ID)); got != 1 {
		t.Fatalf("same state must not create another alert, got %d", got)
	}

	if err := service.RecordMonitoringTransition(target, mismatch, recovered); err != nil {
		t.Fatal(err)
	}
	if got := len(service.Events(target.ID)); got != 2 {
		t.Fatalf("expected recovery event, got %d total events", got)
	}
	if got := len(service.Alerts(AlertStatusFiring, target.ID)); got != 0 {
		t.Fatalf("expected no firing alerts after recovery, got %d", got)
	}
	resolved := service.Alerts(AlertStatusResolved, target.ID)
	if len(resolved) != 1 {
		t.Fatalf("expected 1 resolved alert, got %d", len(resolved))
	}
	if resolved[0].ResolvedAt == nil {
		t.Fatal("expected resolved_at to be set")
	}
}

func TestMonitoringSameAbnormalStateBootstrapsAlertWithoutEvent(t *testing.T) {
	service := newIncidentTestService(t)
	target := DeploymentTarget{ID: "target-2", Domain: "hello.test"}
	state := MonitoringState{Status: MonitoringTLSUnreachable, CheckedAt: time.Now().UTC()}

	if err := service.RecordMonitoringTransition(target, state, state); err != nil {
		t.Fatal(err)
	}
	if got := len(service.Events(target.ID)); got != 0 {
		t.Fatalf("expected no synthetic event, got %d", got)
	}
	firing := service.Alerts(AlertStatusFiring, target.ID)
	if len(firing) != 1 || firing[0].Type != MonitoringTLSUnreachable {
		t.Fatalf("expected one bootstrapped tls_unreachable alert, got %#v", firing)
	}

	if err := service.RecordMonitoringTransition(target, state, state); err != nil {
		t.Fatal(err)
	}
	if got := len(service.Alerts(AlertStatusFiring, target.ID)); got != 1 {
		t.Fatalf("expected alert deduplication, got %d", got)
	}
}
