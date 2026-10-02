package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type RenewalJobAPI struct {
	service *platform.Service
	mux     *http.ServeMux
}

func NewRenewalJobAPI(service *platform.Service) (*RenewalJobAPI, error) {
	if service == nil {
		return nil, fmt.Errorf("platform service is required")
	}
	api := &RenewalJobAPI{service: service, mux: http.NewServeMux()}
	api.mux.HandleFunc("POST /renewal-scheduler/run", api.handleRunScheduler)
	api.mux.HandleFunc("GET /renewal-jobs", api.handleListJobs)
	api.mux.HandleFunc("GET /renewal-jobs/{id}", api.handleGetJob)
	return api, nil
}

func (a *RenewalJobAPI) Handler() http.Handler {
	return a.mux
}

func (a *RenewalJobAPI) handleRunScheduler(w http.ResponseWriter, _ *http.Request) {
	result, err := a.service.RunRenewalScan()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *RenewalJobAPI) handleListJobs(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	jobs := a.service.RenewalJobs(domain)
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(jobs),
		"jobs":  jobs,
	})
}

func (a *RenewalJobAPI) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job, err := a.service.GetRenewalJob(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}
