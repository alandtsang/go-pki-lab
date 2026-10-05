package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	NotificationEventFiring   = "firing"
	NotificationEventResolved = "resolved"

	NotificationStatusPending   = "pending"
	NotificationStatusDelivered = "delivered"
	NotificationStatusFailed    = "failed"
)

type Notification struct {
	AlertID   string    `json:"alert_id"`
	TargetID  string    `json:"target_id"`
	Domain    string    `json:"domain"`
	AlertType string    `json:"alert_type"`
	Event     string    `json:"event"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type NotificationDelivery struct {
	ID          string     `json:"id"`
	AlertID     string     `json:"alert_id"`
	TargetID    string     `json:"target_id"`
	Domain      string     `json:"domain"`
	AlertType   string     `json:"alert_type"`
	Event       string     `json:"event"`
	Sink        string     `json:"sink"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
}

type NotificationDeliveryRepository interface {
	LoadAll() ([]NotificationDelivery, error)
	Save(NotificationDelivery) error
}

type AlertSink interface {
	Name() string
	Deliver(context.Context, Notification) error
}

type LogAlertSink struct{}

func (LogAlertSink) Name() string { return "log" }

func (LogAlertSink) Deliver(_ context.Context, notification Notification) error {
	log.Printf("alert notification: event=%s alert_id=%s target_id=%s domain=%s type=%s message=%q", notification.Event, notification.AlertID, notification.TargetID, notification.Domain, notification.AlertType, notification.Message)
	return nil
}

type WebhookAlertSink struct {
	name   string
	url    string
	client *http.Client
}

func NewWebhookAlertSink(name, url string, timeout time.Duration) (*WebhookAlertSink, error) {
	name = strings.TrimSpace(name)
	url = strings.TrimSpace(url)
	if name == "" {
		name = "webhook"
	}
	if url == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("webhook timeout must be positive")
	}
	return &WebhookAlertSink{name: name, url: url, client: &http.Client{Timeout: timeout}}, nil
}

func (s *WebhookAlertSink) Name() string { return s.name }

func (s *WebhookAlertSink) Deliver(ctx context.Context, notification Notification) error {
	body, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("marshal webhook notification: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver webhook notification: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) SetNotificationDeliveryRepository(repository NotificationDeliveryRepository) error {
	if repository == nil {
		return fmt.Errorf("notification delivery repository is required")
	}
	deliveries, err := repository.LoadAll()
	if err != nil {
		return fmt.Errorf("load notification deliveries: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notificationDeliveryRepository = repository
	if s.notificationDeliveries == nil {
		s.notificationDeliveries = make(map[string]NotificationDelivery)
	}
	for _, delivery := range deliveries {
		if delivery.ID == "" || delivery.AlertID == "" || delivery.Sink == "" {
			continue
		}
		s.notificationDeliveries[delivery.ID] = delivery
	}
	return nil
}

func (s *Service) AddAlertSink(sink AlertSink) error {
	if sink == nil || strings.TrimSpace(sink.Name()) == "" {
		return fmt.Errorf("alert sink with a name is required")
	}
	name := strings.TrimSpace(sink.Name())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.alertSinks == nil {
		s.alertSinks = make(map[string]AlertSink)
	}
	if _, exists := s.alertSinks[name]; exists {
		return fmt.Errorf("alert sink %q already exists", name)
	}
	s.alertSinks[name] = sink
	return nil
}

func (s *Service) NotificationDeliveries(status, alertID string) []NotificationDelivery {
	status = strings.TrimSpace(status)
	alertID = strings.TrimSpace(alertID)
	s.mu.RLock()
	deliveries := make([]NotificationDelivery, 0, len(s.notificationDeliveries))
	for _, delivery := range s.notificationDeliveries {
		if status != "" && delivery.Status != status {
			continue
		}
		if alertID != "" && delivery.AlertID != alertID {
			continue
		}
		deliveries = append(deliveries, delivery)
	}
	s.mu.RUnlock()
	sort.Slice(deliveries, func(i, j int) bool {
		if deliveries[i].CreatedAt.Equal(deliveries[j].CreatedAt) {
			return deliveries[i].ID > deliveries[j].ID
		}
		return deliveries[i].CreatedAt.After(deliveries[j].CreatedAt)
	})
	return deliveries
}

func (s *Service) GetNotificationDelivery(id string) (NotificationDelivery, error) {
	s.mu.RLock()
	delivery, ok := s.notificationDeliveries[id]
	s.mu.RUnlock()
	if !ok {
		return NotificationDelivery{}, fmt.Errorf("notification delivery %q not found", id)
	}
	return delivery, nil
}

func (s *Service) enqueueAlertNotificationsLocked(alert Alert, event string, now time.Time) error {
	if s.notificationDeliveryRepository == nil || len(s.alertSinks) == 0 {
		return nil
	}
	for sinkName := range s.alertSinks {
		duplicate := false
		for _, delivery := range s.notificationDeliveries {
			if delivery.AlertID == alert.ID && delivery.Event == event && delivery.Sink == sinkName {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		delivery := NotificationDelivery{
			ID:        id,
			AlertID:   alert.ID,
			TargetID:  alert.TargetID,
			Domain:    alert.Domain,
			AlertType: alert.Type,
			Event:     event,
			Sink:      sinkName,
			Status:    NotificationStatusPending,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := s.notificationDeliveryRepository.Save(delivery); err != nil {
			return err
		}
		s.notificationDeliveries[delivery.ID] = delivery
	}
	return nil
}

func (s *Service) DispatchNotifications(ctx context.Context) error {
	type workItem struct {
		delivery NotificationDelivery
		sink     AlertSink
		alert    Alert
	}

	s.mu.RLock()
	items := make([]workItem, 0)
	for _, delivery := range s.notificationDeliveries {
		if delivery.Status == NotificationStatusDelivered {
			continue
		}
		sink, ok := s.alertSinks[delivery.Sink]
		if !ok {
			continue
		}
		alert, ok := s.alerts[delivery.AlertID]
		if !ok {
			continue
		}
		items = append(items, workItem{delivery: delivery, sink: sink, alert: alert})
	}
	s.mu.RUnlock()

	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		notification := Notification{
			AlertID:   item.alert.ID,
			TargetID:  item.alert.TargetID,
			Domain:    item.alert.Domain,
			AlertType: item.alert.Type,
			Event:     item.delivery.Event,
			Message:   item.alert.LastMessage,
			CreatedAt: item.delivery.CreatedAt,
		}
		deliveryErr := item.sink.Deliver(ctx, notification)
		now := time.Now().UTC()

		s.mu.Lock()
		delivery, ok := s.notificationDeliveries[item.delivery.ID]
		if !ok || delivery.Status == NotificationStatusDelivered {
			s.mu.Unlock()
			continue
		}
		delivery.Attempts++
		delivery.UpdatedAt = now
		if deliveryErr != nil {
			delivery.Status = NotificationStatusFailed
			delivery.LastError = deliveryErr.Error()
		} else {
			delivery.Status = NotificationStatusDelivered
			delivery.LastError = ""
			deliveredAt := now
			delivery.DeliveredAt = &deliveredAt
		}
		if s.notificationDeliveryRepository == nil {
			s.mu.Unlock()
			return fmt.Errorf("notification delivery repository is not configured")
		}
		if err := s.notificationDeliveryRepository.Save(delivery); err != nil {
			s.mu.Unlock()
			return err
		}
		s.notificationDeliveries[delivery.ID] = delivery
		s.mu.Unlock()
	}
	return nil
}

func (s *Service) RunNotificationDispatcher(ctx context.Context, interval time.Duration, report func(error)) {
	if interval <= 0 {
		return
	}
	run := func() {
		if err := s.DispatchNotifications(ctx); err != nil && report != nil {
			report(err)
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
