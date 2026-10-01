package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/dns"
	"github.com/alandtsang/go-pki-lab/internal/platform"
)

type Server struct {
	service  *platform.Service
	dnsStore *dns.Store
	rootPEM  []byte
	mux      *http.ServeMux
}

func NewServer(service *platform.Service, dnsStore *dns.Store, rootPEM []byte) (*Server, error) {
	if service == nil {
		return nil, fmt.Errorf("platform service is required")
	}
	if dnsStore == nil {
		return nil, fmt.Errorf("DNS store is required")
	}
	s := &Server{service: service, dnsStore: dnsStore, rootPEM: append([]byte(nil), rootPEM...), mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /ca/root", s.handleRootCA)
	s.mux.HandleFunc("GET /ca/crl", s.handleCRL)
	s.mux.HandleFunc("POST /ocsp", s.handleOCSP)
	s.mux.HandleFunc("POST /dns/txt", s.handleSetTXT)
	s.mux.HandleFunc("DELETE /dns/txt", s.handleDeleteTXT)
	s.mux.HandleFunc("GET /dns/txt", s.handleGetTXT)
	s.mux.HandleFunc("POST /orders", s.handleCreateOrder)
	s.mux.HandleFunc("GET /orders/{id}", s.handleGetOrder)
	s.mux.HandleFunc("POST /orders/{id}/validate", s.handleValidateOrder)
	s.mux.HandleFunc("POST /orders/{id}/issue", s.handleIssueOrder)
	s.mux.HandleFunc("POST /orders/{id}/renew", s.handleRenewOrder)
	s.mux.HandleFunc("POST /orders/{id}/revoke", s.handleRevokeOrder)
	s.mux.HandleFunc("GET /certificates", s.handleCertificateHistory)
	s.mux.HandleFunc("GET /certificates/{serial}/status", s.handleCertificateStatus)
	s.mux.HandleFunc("GET /domains/{domain}/certificate-instance", s.handleDomainCertificateInstance)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRootCA(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.rootPEM)
}

func (s *Server) handleCRL(w http.ResponseWriter, _ *http.Request) {
	crl, err := s.service.CRLPEM()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(crl)
}

func (s *Server) handleOCSP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	requestDER, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("read OCSP request: %w", err))
		return
	}
	if len(requestDER) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("OCSP request body is required"))
		return
	}
	responseDER, err := s.service.OCSPResponse(requestDER)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responseDER)
}

func (s *Server) handleSetTXT(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string   `json:"name"`
		Values []string `json:"values"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Name) == "" || len(req.Values) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("name and at least one TXT value are required"))
		return
	}
	s.dnsStore.SetTXT(req.Name, req.Values...)
	writeJSON(w, http.StatusOK, map[string]any{"name": req.Name, "values": s.dnsStore.TXT(req.Name)})
}

func (s *Server) handleDeleteTXT(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("name is required"))
		return
	}
	s.dnsStore.DeleteTXT(req.Name)
	writeJSON(w, http.StatusOK, map[string]any{"name": req.Name, "values": []string{}})
}

func (s *Server) handleGetTXT(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if strings.TrimSpace(name) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("name query parameter is required"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "values": s.dnsStore.TXT(name)})
}

func (s *Server) handleCreateOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		CSRPEM string `json:"csr_pem"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	entry, err := s.service.CreateOrder(req.Domain, []byte(req.CSRPEM))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, orderResponse(entry, false))
}

func (s *Server) handleGetOrder(w http.ResponseWriter, r *http.Request) {
	entry, err := s.service.GetOrder(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, orderResponse(entry, false))
}

func (s *Server) handleValidateOrder(w http.ResponseWriter, r *http.Request) {
	entry, err := s.service.ValidateOrder(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "order": orderResponse(entry, false)})
		return
	}
	writeJSON(w, http.StatusOK, orderResponse(entry, false))
}

func (s *Server) handleIssueOrder(w http.ResponseWriter, r *http.Request) {
	entry, err := s.service.IssueOrder(r.PathValue("id"), 90*24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "order": orderResponse(entry, false)})
		return
	}
	writeJSON(w, http.StatusOK, orderResponse(entry, true))
}

func (s *Server) handleRenewOrder(w http.ResponseWriter, r *http.Request) {
	entry, err := s.service.RenewOrder(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusCreated, orderResponse(entry, false))
}

func (s *Server) handleRevokeOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason int `json:"reason"`
	}
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	entry, err := s.service.RevokeOrder(r.PathValue("id"), req.Reason)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, orderResponse(entry, false))
}

func (s *Server) handleCertificateHistory(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("domain query parameter is required"))
		return
	}
	history, err := s.service.CertificateHistory(domain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"domain":       strings.TrimSuffix(domain, "."),
		"count":        len(history),
		"certificates": history,
	})
}

func (s *Server) handleCertificateStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.service.CertificateStatus(r.PathValue("serial"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleDomainCertificateInstance(w http.ResponseWriter, r *http.Request) {
	instance, err := s.service.DomainCertificateInstance(r.PathValue("domain"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, instance)
}

func orderResponse(entry *platform.Entry, includeCertificate bool) map[string]any {
	if entry == nil || entry.Order == nil {
		return map[string]any{}
	}
	resp := map[string]any{
		"id": entry.ID, "domain": entry.Order.Domain, "status": entry.Order.Status,
		"created_at": entry.CreatedAt, "updated_at": entry.UpdatedAt,
		"csr_submitted": entry.CSR != nil, "renewed_from": entry.RenewedFrom,
		"revoked_at": entry.RevokedAt, "revocation_reason": entry.RevocationReason,
	}
	if entry.Order.Challenge != nil {
		resp["challenge"] = map[string]any{"type": "dns-01", "name": entry.Order.Challenge.Name, "value": entry.Order.Challenge.Token}
	}
	if entry.Certificate != nil && entry.Certificate.Certificate != nil {
		resp["serial_number"] = platform.CertificateSerialHex(entry.Certificate.Certificate)
		resp["not_after"] = entry.Certificate.Certificate.NotAfter
	}
	if includeCertificate && entry.Certificate != nil {
		resp["certificate"] = map[string]any{"certificate_pem": string(entry.Certificate.CertPEM), "fullchain_pem": string(entry.Certificate.FullChainPEM)}
	}
	return resp
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
