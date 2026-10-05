package platform

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
)

type memoryNotificationDeliveryRepository struct {
	deliveries map[string]NotificationDelivery
}

func (r *memoryNotificationDeliveryRepository) LoadAll() ([]NotificationDelivery, error) {
	result := make([]NotificationDelivery, 0, len(r.deliveries))
	for _, delivery := range r.deliveries {
		result = append(result, delivery)
	}
	return result, nil
}

func (r *memoryNotificationDeliveryRepository) Save(delivery NotificationDelivery) error {
	if r.deliveries == nil {
		r.deliveries = make(map[string]NotificationDelivery)
	}
	r.deliveries[delivery.ID] = delivery
	return nil
}

type recordingAlertSink struct {
	name      string
	failCount int
	received  []Notification
}

func (s *recordingAlertSink) Name() string { return s.name }

func (s *recordingAlertSink) Deliver(_ context.Context, notification Notification) error {
	if s.failCount > 0 {
		s.failCount--
		return fmt.Errorf("temporary failure")
	}
	s.received = append(s.received, notification)
	return nil
}

func newNotificationTestService(t *testing.T) *Service {
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
	if err := service.SetNotificationDeliveryRepository(&memoryNotificationDeliveryRepository{deliveries: make(map[string]NotificationDelivery)}); err != nil {
		t.Fatal(err)
	}
	return service
}

func TestNotificationDeliveryFiringAndResolved(t *testing.T) {
	service := newNotificationTestService(t)
	sink := &recordingAlertSink{name: "test"}
	if err := service.AddAlertSink(sink); err != nil {
		t.Fatal(err)
	}

	target := DeploymentTarget{ID: "target-1", Domain: "hello.test"}
	now := time.Now().UTC()
	healthy := MonitoringState{Status: MonitoringHealthy, CheckedAt: now}
	mismatch := MonitoringState{Status: MonitoringSerialMismatch, CheckedAt: now.Add(time.Second)}
	recovered := MonitoringState{Status: MonitoringHealthy, CheckedAt: now.Add(2 * time.Second)}

	if err := service.RecordMonitoringTransition(target, healthy, mismatch); err != nil {
		t.Fatal(err)
	}
	deliveries := service.NotificationDeliveries(NotificationStatusPending, "")
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 pending firing delivery, got %d", len(deliveries))
	}
	if deliveries[0].Event != NotificationEventFiring {
		t.Fatalf("expected firing event, got %q", deliveries[0].Event)
	}

	if err := service.RecordMonitoringTransition(target, mismatch, mismatch); err != nil {
		t.Fatal(err)
	}
	if got := len(service.NotificationDeliveries("", "")); got != 1 {
		t.Fatalf("same alert state must not duplicate delivery, got %d", got)
	}

	if err := service.DispatchNotifications(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.received) != 1 || sink.received[0].Event != NotificationEventFiring {
		t.Fatalf("expected one firing notification, got %#v", sink.received)
	}

	if err := service.RecordMonitoringTransition(target, mismatch, recovered); err != nil {
		t.Fatal(err)
	}
	if err := service.DispatchNotifications(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.received) != 2 || sink.received[1].Event != NotificationEventResolved {
		t.Fatalf("expected resolved notification, got %#v", sink.received)
	}
	if got := len(service.NotificationDeliveries(NotificationStatusDelivered, "")); got != 2 {
		t.Fatalf("expected 2 delivered notifications, got %d", got)
	}
}

func TestNotificationDeliveryRetriesFailure(t *testing.T) {
	service := newNotificationTestService(t)
	sink := &recordingAlertSink{name: "test", failCount: 1}
	if err := service.AddAlertSink(sink); err != nil {
		t.Fatal(err)
	}

	target := DeploymentTarget{ID: "target-1", Domain: "hello.test"}
	now := time.Now().UTC()
	if err := service.RecordMonitoringTransition(
		target,
		MonitoringState{Status: MonitoringHealthy, CheckedAt: now},
		MonitoringState{Status: MonitoringTLSUnreachable, CheckedAt: now.Add(time.Second)},
	); err != nil {
		t.Fatal(err)
	}

	if err := service.DispatchNotifications(context.Background()); err == nil {
		t.Fatal("expected first delivery attempt to fail")
	}
	failed := service.NotificationDeliveries(NotificationStatusFailed, "")
	if len(failed) != 1 || failed[0].Attempts != 1 {
		t.Fatalf("expected one failed attempt, got %#v", failed)
	}

	if err := service.DispatchNotifications(context.Background()); err != nil {
		t.Fatal(err)
	}
	delivered := service.NotificationDeliveries(NotificationStatusDelivered, "")
	if len(delivered) != 1 || delivered[0].Attempts != 2 {
		t.Fatalf("expected retry to deliver on attempt 2, got %#v", delivered)
	}
	if len(sink.received) != 1 {
		t.Fatalf("expected exactly one successful sink delivery, got %d", len(sink.received))
	}
}
