package acme

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	"github.com/alandtsang/go-pki-lab/internal/platform"
	mdns "github.com/miekg/dns"
)

// Issuance connects the ACME protocol layer to the persistent lab CA and
// local authoritative DNS server.
type Issuance struct {
	server       *Server
	root         *ca.Authority
	intermediate *ca.Authority
	dnsServer    string
	stateStore   StateStore

	mu                  sync.RWMutex
	challengeStatus     map[string]string
	authorizationStatus map[string]string
	validatedAt         map[string]time.Time
	certificates        map[string][]byte
	revokedAt           map[string]time.Time
	revocationReason    map[string]int
}

func NewIssuance(server *Server, root, intermediate *ca.Authority, dnsServer string) (*Issuance, error) {
	return newIssuance(server, root, intermediate, dnsServer, nil)
}

func NewIssuanceWithStore(server *Server, root, intermediate *ca.Authority, dnsServer string, store StateStore) (*Issuance, error) {
	if store == nil {
		return nil, fmt.Errorf("ACME state store is required")
	}
	return newIssuance(server, root, intermediate, dnsServer, store)
}

func newIssuance(server *Server, root, intermediate *ca.Authority, dnsServer string, store StateStore) (*Issuance, error) {
	if server == nil {
		return nil, fmt.Errorf("ACME server is required")
	}
	if root == nil || root.Certificate == nil {
		return nil, fmt.Errorf("root CA is required")
	}
	if intermediate == nil || intermediate.Certificate == nil || intermediate.PrivateKey == nil {
		return nil, fmt.Errorf("intermediate CA is required")
	}
	if strings.TrimSpace(dnsServer) == "" {
		return nil, fmt.Errorf("DNS server address is required")
	}
	i := &Issuance{
		server:              server,
		root:                root,
		intermediate:        intermediate,
		dnsServer:           dnsServer,
		stateStore:          store,
		challengeStatus:     make(map[string]string),
		authorizationStatus: make(map[string]string),
		validatedAt:         make(map[string]time.Time),
		certificates:        make(map[string][]byte),
		revokedAt:           make(map[string]time.Time),
		revocationReason:    make(map[string]int),
	}
	if store != nil {
		state, err := store.Load()
		if err != nil {
			return nil, err
		}
		for id, record := range state.Issuance {
			if record.ChallengeStatus != "" {
				i.challengeStatus[id] = record.ChallengeStatus
			}
			if record.AuthorizationStatus != "" {
				i.authorizationStatus[id] = record.AuthorizationStatus
			}
			if record.ValidatedAt != nil {
				i.validatedAt[id] = *record.ValidatedAt
			}
			if len(record.CertificatePEM) > 0 {
				i.certificates[id] = append([]byte(nil), record.CertificatePEM...)
			}
			if record.RevokedAt != nil {
				i.revokedAt[id] = *record.RevokedAt
				i.revocationReason[id] = record.RevocationReason
			}
		}
	}
	return i, nil
}

func (i *Issuance) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	account, _, err := i.server.verifyAccountRequest(r)
	if err != nil {
		i.server.writeACMEError(w, err)
		return
	}
	id := r.PathValue("id")
	order := i.server.getOrder(id)
	if order == nil || order.AccountID != account.ID {
		i.server.respondProblem(w, http.StatusNotFound, "malformed", "challenge not found")
		return
	}

	if err := i.verifyDNS01(order); err != nil {
		i.mu.Lock()
		i.challengeStatus[id] = "invalid"
		i.authorizationStatus[id] = "invalid"
		i.mu.Unlock()
		if persistErr := i.persistIssuance(id); persistErr != nil {
			i.server.respondProblem(w, http.StatusInternalServerError, "serverInternal", persistErr.Error())
			return
		}
		if persistErr := i.setOrderStatus(id, "invalid"); persistErr != nil {
			i.server.respondProblem(w, http.StatusInternalServerError, "serverInternal", persistErr.Error())
			return
		}
		i.server.respondProblem(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	now := time.Now().UTC()
	i.mu.Lock()
	i.challengeStatus[id] = "valid"
	i.authorizationStatus[id] = "valid"
	i.validatedAt[id] = now
	i.mu.Unlock()
	if err := i.persistIssuance(id); err != nil {
		i.server.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	if err := i.setOrderStatus(id, "ready"); err != nil {
		i.server.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}

	i.server.addReplayNonce(w)
	writeJSON(w, http.StatusOK, i.challengeResponse(order, "valid", &now))
}

func (i *Issuance) HandleAuthorization(w http.ResponseWriter, r *http.Request) {
	account, _, err := i.server.verifyAccountRequest(r)
	if err != nil {
		i.server.writeACMEError(w, err)
		return
	}
	id := r.PathValue("id")
	order := i.server.getOrder(id)
	if order == nil || order.AccountID != account.ID {
		i.server.respondProblem(w, http.StatusNotFound, "malformed", "authorization not found")
		return
	}

	challengeStatus, authorizationStatus, validatedAt := i.statuses(id)
	i.server.addReplayNonce(w)
	response := map[string]any{
		"identifier": map[string]string{"type": "dns", "value": order.Domain},
		"status":     authorizationStatus,
		"challenges": []map[string]any{i.challengeResponse(order, challengeStatus, validatedAt)},
	}
	writeJSON(w, http.StatusOK, response)
}

func (i *Issuance) HandleOrder(w http.ResponseWriter, r *http.Request) {
	account, _, err := i.server.verifyAccountRequest(r)
	if err != nil {
		i.server.writeACMEError(w, err)
		return
	}
	order := i.server.getOrder(r.PathValue("id"))
	if order == nil || order.AccountID != account.ID {
		i.server.respondProblem(w, http.StatusNotFound, "malformed", "order not found")
		return
	}
	i.server.addReplayNonce(w)
	writeJSON(w, http.StatusOK, i.orderResponse(order, r))
}

func (i *Issuance) HandleFinalize(w http.ResponseWriter, r *http.Request) {
	account, verified, err := i.server.verifyAccountRequest(r)
	if err != nil {
		i.server.writeACMEError(w, err)
		return
	}
	id := r.PathValue("id")
	order := i.server.getOrder(id)
	if order == nil || order.AccountID != account.ID {
		i.server.respondProblem(w, http.StatusNotFound, "malformed", "order not found")
		return
	}
	if order.Status != "ready" {
		i.server.respondProblem(w, http.StatusForbidden, "orderNotReady", "order must be ready before finalize")
		return
	}

	var payload struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(verified.Payload, &payload); err != nil || payload.CSR == "" {
		i.server.respondProblem(w, http.StatusBadRequest, "malformed", "finalize payload must contain csr")
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(payload.CSR)
	if err != nil {
		i.server.respondProblem(w, http.StatusBadRequest, "badCSR", "csr must be base64url-encoded DER")
		return
	}
	req, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		i.server.respondProblem(w, http.StatusBadRequest, "badCSR", "cannot parse CSR")
		return
	}
	if err := req.CheckSignature(); err != nil {
		i.server.respondProblem(w, http.StatusBadRequest, "badCSR", "CSR signature is invalid")
		return
	}
	if len(req.DNSNames) != 1 || !strings.EqualFold(strings.TrimSuffix(req.DNSNames[0], "."), order.Domain) {
		i.server.respondProblem(w, http.StatusBadRequest, "badCSR", "CSR SAN must exactly match the order identifier")
		return
	}

	issued, err := ca.IssueServerCertificateFromCSR(i.intermediate, req, 90*24*time.Hour)
	if err != nil {
		i.server.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	if err := ca.VerifyServerCertificate(issued.Certificate, i.root, i.intermediate, order.Domain); err != nil {
		i.server.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}

	i.mu.Lock()
	i.certificates[id] = append([]byte(nil), issued.FullChainPEM...)
	delete(i.revokedAt, id)
	delete(i.revocationReason, id)
	i.mu.Unlock()
	if err := i.persistIssuance(id); err != nil {
		i.server.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	if err := i.setOrderStatus(id, "valid"); err != nil {
		i.server.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	order = i.server.getOrder(id)

	i.server.addReplayNonce(w)
	writeJSON(w, http.StatusOK, i.orderResponse(order, r))
}

func (i *Issuance) HandleCertificate(w http.ResponseWriter, r *http.Request) {
	account, _, err := i.server.verifyAccountRequest(r)
	if err != nil {
		i.server.writeACMEError(w, err)
		return
	}
	id := r.PathValue("id")
	order := i.server.getOrder(id)
	if order == nil || order.AccountID != account.ID {
		i.server.respondProblem(w, http.StatusNotFound, "malformed", "certificate not found")
		return
	}
	i.mu.RLock()
	chain := append([]byte(nil), i.certificates[id]...)
	i.mu.RUnlock()
	if order.Status != "valid" || len(chain) == 0 {
		i.server.respondProblem(w, http.StatusNotFound, "malformed", "certificate is not available")
		return
	}
	i.server.addReplayNonce(w)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(chain)
}

func (i *Issuance) verifyDNS01(order *Order) error {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn("_acme-challenge."+order.Domain), mdns.TypeTXT)
	client := &mdns.Client{Timeout: 2 * time.Second}
	resp, _, err := client.Exchange(msg, i.dnsServer)
	if err != nil {
		return fmt.Errorf("query DNS-01 TXT: %w", err)
	}
	if resp == nil {
		return fmt.Errorf("empty DNS response")
	}
	for _, answer := range resp.Answer {
		txt, ok := answer.(*mdns.TXT)
		if !ok {
			continue
		}
		for _, value := range txt.Txt {
			if value == order.DNSValue {
				return nil
			}
		}
	}
	return fmt.Errorf("DNS-01 TXT validation failed for _acme-challenge.%s", order.Domain)
}

func (i *Issuance) setOrderStatus(id, status string) error {
	i.server.mu.Lock()
	order := i.server.orders[id]
	if order == nil {
		i.server.mu.Unlock()
		return fmt.Errorf("ACME order %s not found", id)
	}
	order.Status = status
	copyOrder := *order
	i.server.mu.Unlock()
	return i.server.persistOrder(&copyOrder)
}

func (i *Issuance) persistIssuance(id string) error {
	if i.stateStore == nil {
		return nil
	}
	i.mu.RLock()
	record := IssuanceRecord{
		ChallengeStatus:     i.challengeStatus[id],
		AuthorizationStatus: i.authorizationStatus[id],
		CertificatePEM:      append([]byte(nil), i.certificates[id]...),
		RevocationReason:    i.revocationReason[id],
	}
	if value, ok := i.validatedAt[id]; ok {
		copyValue := value
		record.ValidatedAt = &copyValue
	}
	if value, ok := i.revokedAt[id]; ok {
		copyValue := value
		record.RevokedAt = &copyValue
	}
	i.mu.RUnlock()
	return i.stateStore.Update(func(state *PersistentState) error {
		state.Issuance[id] = record
		return nil
	})
}

func (i *Issuance) statuses(id string) (challenge, authorization string, validatedAt *time.Time) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	challenge = i.challengeStatus[id]
	if challenge == "" {
		challenge = "pending"
	}
	authorization = i.authorizationStatus[id]
	if authorization == "" {
		authorization = "pending"
	}
	if value, ok := i.validatedAt[id]; ok {
		copyValue := value
		validatedAt = &copyValue
	}
	return
}

func (i *Issuance) challengeResponse(order *Order, status string, validatedAt *time.Time) map[string]any {
	response := map[string]any{
		"type":   "dns-01",
		"url":    order.ChallengeURL,
		"status": status,
		"token":  order.Token,
	}
	if validatedAt != nil {
		response["validated"] = validatedAt
	}
	return response
}

func (i *Issuance) orderResponse(order *Order, r *http.Request) map[string]any {
	response := i.server.orderResponse(order)
	if order.Status == "valid" {
		response["certificate"] = absolutePathURL(r, "/acme/cert/"+order.ID)
	}
	return response
}

func (i *Issuance) FindCertificateBySerial(serial *big.Int) (*platform.CertificateState, bool, error) {
	if serial == nil {
		return nil, false, nil
	}
	i.mu.RLock()
	chains := make(map[string][]byte, len(i.certificates))
	for id, chain := range i.certificates {
		chains[id] = append([]byte(nil), chain...)
	}
	revoked := make(map[string]time.Time, len(i.revokedAt))
	for id, value := range i.revokedAt {
		revoked[id] = value
	}
	reasons := make(map[string]int, len(i.revocationReason))
	for id, value := range i.revocationReason {
		reasons[id] = value
	}
	i.mu.RUnlock()

	for id, chain := range chains {
		cert, err := firstCertificate(chain)
		if err != nil {
			return nil, false, err
		}
		if cert.SerialNumber.Cmp(serial) != 0 {
			continue
		}
		state := &platform.CertificateState{Certificate: cert, SourceID: id, RevocationReason: reasons[id]}
		if order := i.server.getOrder(id); order != nil {
			state.Domain = order.Domain
		}
		if value, ok := revoked[id]; ok {
			copyValue := value
			state.RevokedAt = &copyValue
		}
		return state, true, nil
	}
	return nil, false, nil
}

func (i *Issuance) RevokedCertificates() ([]platform.CertificateState, error) {
	i.mu.RLock()
	ids := make([]string, 0, len(i.revokedAt))
	for id := range i.revokedAt {
		ids = append(ids, id)
	}
	i.mu.RUnlock()

	states := make([]platform.CertificateState, 0, len(ids))
	for _, id := range ids {
		i.mu.RLock()
		chain := append([]byte(nil), i.certificates[id]...)
		revokedAt := i.revokedAt[id]
		reason := i.revocationReason[id]
		i.mu.RUnlock()
		cert, err := firstCertificate(chain)
		if err != nil {
			return nil, err
		}
		state := platform.CertificateState{Certificate: cert, SourceID: id, RevocationReason: reason}
		copyValue := revokedAt
		state.RevokedAt = &copyValue
		if order := i.server.getOrder(id); order != nil {
			state.Domain = order.Domain
		}
		states = append(states, state)
	}
	return states, nil
}

func (i *Issuance) CertificatesByDomain(domain string) ([]platform.CertificateState, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return nil, nil
	}

	i.mu.RLock()
	chains := make(map[string][]byte, len(i.certificates))
	for id, chain := range i.certificates {
		chains[id] = append([]byte(nil), chain...)
	}
	revoked := make(map[string]time.Time, len(i.revokedAt))
	for id, value := range i.revokedAt {
		revoked[id] = value
	}
	reasons := make(map[string]int, len(i.revocationReason))
	for id, value := range i.revocationReason {
		reasons[id] = value
	}
	i.mu.RUnlock()

	states := make([]platform.CertificateState, 0)
	for id, chain := range chains {
		order := i.server.getOrder(id)
		if order == nil || !strings.EqualFold(strings.TrimSuffix(order.Domain, "."), domain) {
			continue
		}
		cert, err := firstCertificate(chain)
		if err != nil {
			return nil, err
		}
		state := platform.CertificateState{
			Certificate:      cert,
			Domain:           order.Domain,
			SourceID:         id,
			RevocationReason: reasons[id],
		}
		if value, ok := revoked[id]; ok {
			copyValue := value
			state.RevokedAt = &copyValue
		}
		states = append(states, state)
	}
	return states, nil
}

func firstCertificate(chain []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ACME certificate chain does not start with a certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ACME certificate: %w", err)
	}
	return cert, nil
}
