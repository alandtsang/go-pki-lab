package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type NotificationAPI struct {
	service *platform.Service
	mux     *http.ServeMux
}

func NewNotificationAPI(service *platform.Service) (*NotificationAPI, error) {
	if service == nil {
		return nil, fmt.Errorf("platform service is required")
	}
	api := &NotificationAPI{service: service, mux: http.NewServeMux()}
	api.mux.HandleFunc("GET /notification-deliveries", api.handleListDeliveries)
	api.mux.HandleFunc("GET /notification-deliveries/{id}", api.handleGetDelivery)
	api.mux.HandleFunc("POST /notification-dispatcher/run", api.handleRunDispatcher)
	return api, nil
}

func (a *NotificationAPI) Handler() http.Handler {
	return a.mux
}

func (a *NotificationAPI) handleListDeliveries(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	alertID := strings.TrimSpace(r.URL.Query().Get("alert_id"))
	deliveries := a.service.NotificationDeliveries(status, alertID)
	writeJSON(w, http.StatusOK, map[string]any{"count": len(deliveries), "deliveries": deliveries})
}

func (a *NotificationAPI) handleGetDelivery(w http.ResponseWriter, r *http.Request) {
	delivery, err := a.service.GetNotificationDelivery(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, delivery)
}

func (a *NotificationAPI) handleRunDispatcher(w http.ResponseWriter, r *http.Request) {
	if err := a.service.DispatchNotifications(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}
