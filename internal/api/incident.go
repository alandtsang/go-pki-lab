package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type IncidentAPI struct {
	service *platform.Service
	mux     *http.ServeMux
}

func NewIncidentAPI(service *platform.Service) (*IncidentAPI, error) {
	if service == nil {
		return nil, fmt.Errorf("platform service is required")
	}
	api := &IncidentAPI{service: service, mux: http.NewServeMux()}
	api.mux.HandleFunc("GET /events", api.handleListEvents)
	api.mux.HandleFunc("GET /alerts", api.handleListAlerts)
	api.mux.HandleFunc("GET /alerts/{id}", api.handleGetAlert)
	return api, nil
}

func (a *IncidentAPI) Handler() http.Handler {
	return a.mux
}

func (a *IncidentAPI) handleListEvents(w http.ResponseWriter, r *http.Request) {
	targetID := strings.TrimSpace(r.URL.Query().Get("target_id"))
	events := a.service.Events(targetID)
	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(events),
		"events": events,
	})
}

func (a *IncidentAPI) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && status != platform.AlertStatusFiring && status != platform.AlertStatusResolved {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid alert status %q", status))
		return
	}
	targetID := strings.TrimSpace(r.URL.Query().Get("target_id"))
	alerts := a.service.Alerts(status, targetID)
	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(alerts),
		"alerts": alerts,
	})
}

func (a *IncidentAPI) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	alert, err := a.service.GetAlert(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, alert)
}
