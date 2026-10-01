package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type RenewalPolicyAPI struct {
	service *platform.Service
	mux     *http.ServeMux
}

func NewRenewalPolicyAPI(service *platform.Service) (*RenewalPolicyAPI, error) {
	if service == nil {
		return nil, fmt.Errorf("platform service is required")
	}
	a := &RenewalPolicyAPI{service: service, mux: http.NewServeMux()}
	a.mux.HandleFunc("GET /domains/{domain}/renewal-policy", a.handleGetPolicy)
	a.mux.HandleFunc("PUT /domains/{domain}/renewal-policy", a.handlePutPolicy)
	a.mux.HandleFunc("GET /domains/{domain}/renewal-decision", a.handleDecision)
	return a, nil
}

func (a *RenewalPolicyAPI) Handler() http.Handler {
	return a.mux
}

func (a *RenewalPolicyAPI) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	policy := a.service.RenewalPolicy(r.PathValue("domain"))
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": !policy.UpdatedAt.IsZero(),
		"policy":     policy,
	})
}

func (a *RenewalPolicyAPI) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AutoRenew       bool `json:"auto_renew"`
		RenewBeforeDays int  `json:"renew_before_days"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	policy, err := a.service.SetRenewalPolicy(r.PathValue("domain"), req.AutoRenew, req.RenewBeforeDays)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (a *RenewalPolicyAPI) handleDecision(w http.ResponseWriter, r *http.Request) {
	decision, err := a.service.RenewalDecision(r.PathValue("domain"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, decision)
}
