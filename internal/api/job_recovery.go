package api

import (
	"fmt"
	"net/http"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type JobRecoveryAPI struct {
	service *platform.Service
	mux     *http.ServeMux
}

func NewJobRecoveryAPI(service *platform.Service) (*JobRecoveryAPI, error) {
	if service == nil {
		return nil, fmt.Errorf("platform service is required")
	}
	api := &JobRecoveryAPI{service: service, mux: http.NewServeMux()}
	api.mux.HandleFunc("POST /job-recovery/run", api.handleRun)
	return api, nil
}

func (a *JobRecoveryAPI) Handler() http.Handler {
	return a.mux
}

func (a *JobRecoveryAPI) handleRun(w http.ResponseWriter, _ *http.Request) {
	result, err := a.service.RecoverStaleJobs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
