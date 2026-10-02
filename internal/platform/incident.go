package platform

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	AlertStatusFiring   = "firing"
	AlertStatusResolved = "resolved"
)

type Event struct {
	ID             string    `json:"id"`
	TargetID       string    `json:"target_id"`
	Domain         string    `json:"domain"`
	PreviousStatus string    `json:"previous_status,omitempty"`
	CurrentStatus  string    `json:"current_status"`
	OccurredAt     time.Time `json:"occurred_at"`
	Message        string    `json:"message"`
}

type Alert struct {
	ID           string     `json:"id"`
	TargetID     string     `json:"target_id"`
	Domain       string     `json:"domain"`
	Type         string     `json:"type"`
	Status       string     `json:"status"`
	FirstSeenAt  time.Time  `json:"first_seen_at"`
	LastSeenAt   time.Time  `json:"last_seen_at"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
	Occurrences  int        `json:"occurrences"`
	LastMessage  string     `json:"last_message,omitempty"`
}

type EventRepository interface {
	LoadAll() ([]Event, error)
	Save(Event) error
}

type AlertRepository interface {
	LoadAll() ([]Alert, error)
	Save(Alert) error
}

func (s *Service) SetEventRepository(repository EventRepository) error {
	if repository == nil {
		return fmt.Errorf("event repository is required")
	}
	events, err := repository.LoadAll()
	if err != nil {
		return fmt.Errorf("load events: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventRepository = repository
	if s.events == nil {
		s.events = make(map[string]Event)
	}
	for _, event := range events {
		if event.ID == "" || event.TargetID == "" {
			continue
		}
		event.Domain = normalizeDomain(event.Domain)
		s.events[event.ID] = event
	}
	return nil
}

func (s *Service) SetAlertRepository(repository AlertRepository) error {
	if repository == nil {
		return fmt.Errorf("alert repository is required")
	}
	alerts, err := repository.LoadAll()
	if err != nil {
		return fmt.Errorf("load alerts: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertRepository = repository
	if s.alerts == nil {
		s.alerts = make(map[string]Alert)
	}
	for _, alert := range alerts {
		if alert.ID == "" || alert.TargetID == "" {
			continue
		}
		alert.Domain = normalizeDomain(alert.Domain)
		s.alerts[alert.ID] = alert
	}
	return nil
}

func (s *Service) Events(targetID string) []Event {
	targetID = strings.TrimSpace(targetID)
	s.mu.RLock()
	events := make([]Event, 0, len(s.events))
	for _, event := range s.events {
		if targetID != "" && event.TargetID != targetID {
			continue
		}
		events = append(events, event)
	}
	s.mu.RUnlock()
	sort.Slice(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].ID > events[j].ID
		}
		return events[i].OccurredAt.After(events[j].OccurredAt)
	})
	return events
}

func (s *Service) Alerts(status, targetID string) []Alert {
	status = strings.TrimSpace(status)
	targetID = strings.TrimSpace(targetID)
	s.mu.RLock()
	alerts := make([]Alert, 0, len(s.alerts))
	for _, alert := range s.alerts {
		if status != "" && alert.Status != status {
			continue
		}
		if targetID != "" && alert.TargetID != targetID {
			continue
		}
		alerts = append(alerts, alert)
	}
	s.mu.RUnlock()
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].LastSeenAt.Equal(alerts[j].LastSeenAt) {
			return alerts[i].ID > alerts[j].ID
		}
		return alerts[i].LastSeenAt.After(alerts[j].LastSeenAt)
	})
	return alerts
}

func (s *Service) GetAlert(id string) (Alert, error) {
	s.mu.RLock()
	alert, ok := s.alerts[id]
	s.mu.RUnlock()
	if !ok {
		return Alert{}, fmt.Errorf("alert %q not found", id)
	}
	return alert, nil
}

func isHealthyMonitoringStatus(status string) bool {
	return status == MonitoringHealthy
}

func isAbnormalMonitoringStatus(status string) bool {
	return status != "" && !isHealthyMonitoringStatus(status)
}

func monitoringTransitionMessage(target DeploymentTarget, previous, current MonitoringState) string {
	if previous.Status == "" {
		return fmt.Sprintf("target %s initial monitoring status is %s", target.ID, current.Status)
	}
	return fmt.Sprintf("target %s monitoring status changed from %s to %s", target.ID, previous.Status, current.Status)
}

func (s *Service) RecordMonitoringTransition(target DeploymentTarget, previous, current MonitoringState) error {
	if current.Status == "" || previous.Status == current.Status {
		return nil
	}
	if s.eventRepository == nil || s.alertRepository == nil {
		return nil
	}

	now := current.CheckedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	eventID, err := randomID()
	if err != nil {
		return err
	}
	event := Event{
		ID:             eventID,
		TargetID:       target.ID,
		Domain:         target.Domain,
		PreviousStatus: previous.Status,
		CurrentStatus:  current.Status,
		OccurredAt:     now,
		Message:        monitoringTransitionMessage(target, previous, current),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.eventRepository.Save(event); err != nil {
		return err
	}
	s.events[event.ID] = event

	if isAbnormalMonitoringStatus(previous.Status) {
		for id, alert := range s.alerts {
			if alert.TargetID != target.ID || alert.Type != previous.Status || alert.Status != AlertStatusFiring {
				continue
			}
			resolvedAt := now
			alert.Status = AlertStatusResolved
			alert.ResolvedAt = &resolvedAt
			alert.LastSeenAt = now
			alert.LastMessage = event.Message
			if err := s.alertRepository.Save(alert); err != nil {
				return err
			}
			s.alerts[id] = alert
		}
	}

	if !isAbnormalMonitoringStatus(current.Status) {
		return nil
	}
	for _, alert := range s.alerts {
		if alert.TargetID == target.ID && alert.Type == current.Status && alert.Status == AlertStatusFiring {
			return nil
		}
	}
	alertID, err := randomID()
	if err != nil {
		return err
	}
	alert := Alert{
		ID:          alertID,
		TargetID:    target.ID,
		Domain:      target.Domain,
		Type:        current.Status,
		Status:      AlertStatusFiring,
		FirstSeenAt: now,
		LastSeenAt:  now,
		Occurrences: 1,
		LastMessage: event.Message,
	}
	if err := s.alertRepository.Save(alert); err != nil {
		return err
	}
	s.alerts[alert.ID] = alert
	return nil
}
