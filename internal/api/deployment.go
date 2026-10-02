package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type DeploymentAPI struct {
	service           *platform.Service
	mux               *http.ServeMux
	monitoringOptions platform.MonitoringOptions
}

func NewDeploymentAPI(service *platform.Service) (*DeploymentAPI, error) {
	return NewDeploymentAPIWithMonitoring(service, platform.MonitoringOptions{Timeout: 5 * time.Second, ExpiringBefore: 30 * 24 * time.Hour})
}

func NewDeploymentAPIWithMonitoring(service *platform.Service, options platform.MonitoringOptions) (*DeploymentAPI, error) {
	if options.Timeout <= 0 || options.ExpiringBefore < 0 {
		return nil, fmt.Errorf("invalid monitoring options")
	}
	if service == nil {
		return nil, fmt.Errorf("platform service is required")
	}
	api := &DeploymentAPI{service: service, mux: http.NewServeMux(), monitoringOptions: options}
	api.mux.HandleFunc("GET /deployment-targets/{id}/monitoring", api.handleGetMonitoring)
	api.mux.HandleFunc("POST /deployment-targets/{id}/probe", api.handleProbe)
	api.mux.HandleFunc("POST /certificate-monitor/run", api.handleMonitoringScan)
	api.mux.HandleFunc("POST /deployment-targets", api.handleCreateTarget)
	api.mux.HandleFunc("GET /deployment-targets", api.handleListTargets)
	api.mux.HandleFunc("GET /deployment-targets/{id}", api.handleGetTarget)
	api.mux.HandleFunc("POST /deployment-targets/{id}/deploy", api.handleDeployTarget)
	api.mux.HandleFunc("POST /deployment-reconciler/run", api.handleRunReconciler)
	api.mux.HandleFunc("GET /deployment-jobs", api.handleListJobs)
	api.mux.HandleFunc("GET /deployment-jobs/{id}", api.handleGetJob)
	api.mux.HandleFunc("POST /deployment-jobs/{id}/claim", api.handleClaimJob)
	api.mux.HandleFunc("POST /deployment-jobs/{id}/complete", api.handleCompleteJob)
	api.mux.HandleFunc("POST /deployment-jobs/{id}/fail", api.handleFailJob)
	return api, nil
}

func (a *DeploymentAPI) Handler() http.Handler {
	return a.mux
}

func (a *DeploymentAPI) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain   string `json:"domain"`
		Type     string `json:"type"`
		Address  string `json:"address"`
		CertPath string `json:"cert_path"`
		KeyPath  string `json:"key_path"`
		Enabled  bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	target, err := a.service.CreateDeploymentTarget(req.Domain, req.Type, req.Address, req.CertPath, req.KeyPath, req.Enabled)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, target)
}

func (a *DeploymentAPI) handleListTargets(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	targets := a.service.DeploymentTargets(domain)
	writeJSON(w, http.StatusOK, map[string]any{"count": len(targets), "targets": targets})
}

func (a *DeploymentAPI) handleGetTarget(w http.ResponseWriter, r *http.Request) {
	target, err := a.service.GetDeploymentTarget(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, target)
}

func (a *DeploymentAPI) handleDeployTarget(w http.ResponseWriter, r *http.Request) {
	target, err := a.service.GetDeploymentTarget(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	instance, err := a.service.DomainCertificateInstance(target.Domain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if instance.CurrentCertificate == nil {
		writeError(w, http.StatusConflict, fmt.Errorf("domain %q has no active certificate", target.Domain))
		return
	}
	job, _, err := a.service.CreateDeploymentJobForTarget(target.ID, instance.CurrentCertificate.SerialNumber)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusCreated, job)
}

func (a *DeploymentAPI) handleRunReconciler(w http.ResponseWriter, _ *http.Request) {
	result, err := a.service.RunDeploymentReconcile()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *DeploymentAPI) handleListJobs(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	jobs := a.service.DeploymentJobs(domain)
	writeJSON(w, http.StatusOK, map[string]any{"count": len(jobs), "jobs": jobs})
}

func (a *DeploymentAPI) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job, err := a.service.GetDeploymentJob(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (a *DeploymentAPI) handleClaimJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	job, err := a.service.ClaimDeploymentJob(r.PathValue("id"), req.ClientID)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (a *DeploymentAPI) handleCompleteJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VerifiedSerial string `json:"verified_serial"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	job, err := a.service.CompleteDeploymentJob(r.PathValue("id"), req.VerifiedSerial)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (a *DeploymentAPI) handleFailJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Error string `json:"error"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	job, err := a.service.FailDeploymentJob(r.PathValue("id"), req.Error)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (a *DeploymentAPI) handleGetMonitoring(w http.ResponseWriter, r *http.Request) {
	target, err := a.service.GetDeploymentTarget(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, target.Monitoring)
}
func (a *DeploymentAPI) handleProbe(w http.ResponseWriter, r *http.Request) {
	target, err := a.service.GetDeploymentTarget(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if !target.Enabled {
		writeError(w, http.StatusConflict, fmt.Errorf("target is disabled"))
		return
	}
	state, err := a.service.ProbeDeploymentTarget(r.Context(), target.ID, a.monitoringOptions)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}
func (a *DeploymentAPI) handleMonitoringScan(w http.ResponseWriter, r *http.Request) {
	result, err := a.service.RunMonitoringScan(r.Context(), a.monitoringOptions)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
