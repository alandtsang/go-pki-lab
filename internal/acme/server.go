package acme

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

type Account struct {
	ID         string
	Status     string
	Contact    []string
	JWK        json.RawMessage
	Thumbprint string
	PublicKey  any
}

type Order struct {
	ID            string
	AccountID     string
	Status        string
	Domain        string
	Authorization string
	Finalize      string
	ChallengeURL  string
	Token         string
	DNSValue      string
}

type Server struct {
	mu         sync.RWMutex
	nonces     map[string]struct{}
	accounts   map[string]*Account
	orders     map[string]*Order
	stateStore StateStore
	mux        *http.ServeMux
}

func NewServer() *Server {
	s, _ := newServer(nil)
	return s
}

func NewServerWithStore(store StateStore) (*Server, error) {
	if store == nil {
		return nil, fmt.Errorf("ACME state store is required")
	}
	return newServer(store)
}

func newServer(store StateStore) (*Server, error) {
	s := &Server{
		nonces:     make(map[string]struct{}),
		accounts:   make(map[string]*Account),
		orders:     make(map[string]*Order),
		stateStore: store,
		mux:        http.NewServeMux(),
	}
	if store != nil {
		state, err := store.Load()
		if err != nil {
			return nil, err
		}
		for id, record := range state.Accounts {
			publicKey, err := parseJWK(record.JWK)
			if err != nil {
				return nil, fmt.Errorf("restore ACME account %s: %w", id, err)
			}
			s.accounts[id] = &Account{
				ID:         record.ID,
				Status:     record.Status,
				Contact:    append([]string(nil), record.Contact...),
				JWK:        append(json.RawMessage(nil), record.JWK...),
				Thumbprint: record.Thumbprint,
				PublicKey:  publicKey,
			}
		}
		for id, record := range state.Orders {
			copyOrder := record
			s.orders[id] = &copyOrder
		}
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /acme/directory", s.handleDirectory)
	s.mux.HandleFunc("HEAD /acme/new-nonce", s.handleNewNonce)
	s.mux.HandleFunc("GET /acme/new-nonce", s.handleNewNonce)
	s.mux.HandleFunc("POST /acme/new-account", s.handleNewAccount)
	s.mux.HandleFunc("POST /acme/acct/{id}", s.handleAccount)
	s.mux.HandleFunc("POST /acme/new-order", s.handleNewOrder)
	s.mux.HandleFunc("POST /acme/order/{id}", s.handleOrder)
	s.mux.HandleFunc("POST /acme/authz/{id}", s.handleAuthorization)
}

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	base := requestBaseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"newNonce":   base + "/acme/new-nonce",
		"newAccount": base + "/acme/new-account",
		"newOrder":   base + "/acme/new-order",
	})
}

func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	nonce, err := s.issueNonce()
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	verified, err := s.verifyJWSRequest(r, true)
	if err != nil {
		s.writeACMEError(w, err)
		return
	}
	var payload struct {
		Contact              []string `json:"contact"`
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
	}
	if len(verified.Payload) > 0 {
		if err := json.Unmarshal(verified.Payload, &payload); err != nil {
			s.respondProblem(w, http.StatusBadRequest, "malformed", "invalid newAccount payload")
			return
		}
	}

	thumbprint, err := jwkThumbprint(verified.JWK)
	if err != nil {
		s.respondProblem(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}

	s.mu.Lock()
	for _, account := range s.accounts {
		if account.Thumbprint == thumbprint {
			location := absolutePathURL(r, "/acme/acct/"+account.ID)
			s.mu.Unlock()
			w.Header().Set("Location", location)
			s.addReplayNonce(w)
			writeJSON(w, http.StatusOK, accountResponse(account))
			return
		}
	}
	if payload.OnlyReturnExisting {
		s.mu.Unlock()
		s.respondProblem(w, http.StatusBadRequest, "accountDoesNotExist", "account does not exist")
		return
	}
	id, err := randomID(12)
	if err != nil {
		s.mu.Unlock()
		s.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	account := &Account{
		ID:         id,
		Status:     "valid",
		Contact:    append([]string(nil), payload.Contact...),
		JWK:        append(json.RawMessage(nil), verified.JWK...),
		Thumbprint: thumbprint,
		PublicKey:  verified.PublicKey,
	}
	s.accounts[id] = account
	s.mu.Unlock()
	if err := s.persistAccount(account); err != nil {
		s.mu.Lock()
		delete(s.accounts, id)
		s.mu.Unlock()
		s.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}

	location := absolutePathURL(r, "/acme/acct/"+id)
	w.Header().Set("Location", location)
	s.addReplayNonce(w)
	writeJSON(w, http.StatusCreated, accountResponse(account))
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	account, verified, err := s.verifyAccountRequest(r)
	if err != nil {
		s.writeACMEError(w, err)
		return
	}
	if len(verified.Payload) != 0 {
		var update struct {
			Contact []string `json:"contact"`
			Status  string   `json:"status"`
		}
		if err := json.Unmarshal(verified.Payload, &update); err != nil {
			s.respondProblem(w, http.StatusBadRequest, "malformed", "invalid account payload")
			return
		}
		s.mu.Lock()
		if update.Contact != nil {
			account.Contact = append([]string(nil), update.Contact...)
		}
		if update.Status == "deactivated" {
			account.Status = "deactivated"
		}
		copyAccount := *account
		copyAccount.Contact = append([]string(nil), account.Contact...)
		copyAccount.JWK = append(json.RawMessage(nil), account.JWK...)
		s.mu.Unlock()
		if err := s.persistAccount(&copyAccount); err != nil {
			s.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
			return
		}
	}
	s.addReplayNonce(w)
	writeJSON(w, http.StatusOK, accountResponse(account))
}

func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	account, verified, err := s.verifyAccountRequest(r)
	if err != nil {
		s.writeACMEError(w, err)
		return
	}
	if account.Status != "valid" {
		s.respondProblem(w, http.StatusUnauthorized, "unauthorized", "account is not valid")
		return
	}
	var payload struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	}
	if err := json.Unmarshal(verified.Payload, &payload); err != nil {
		s.respondProblem(w, http.StatusBadRequest, "malformed", "invalid newOrder payload")
		return
	}
	if len(payload.Identifiers) != 1 || payload.Identifiers[0].Type != "dns" || strings.TrimSpace(payload.Identifiers[0].Value) == "" {
		s.respondProblem(w, http.StatusBadRequest, "unsupportedIdentifier", "this lab currently supports exactly one dns identifier")
		return
	}

	id, err := randomID(12)
	if err != nil {
		s.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	token, err := randomToken(32)
	if err != nil {
		s.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	domain := strings.TrimSuffix(strings.TrimSpace(payload.Identifiers[0].Value), ".")
	keyAuthorization := token + "." + account.Thumbprint
	digest := sha256.Sum256([]byte(keyAuthorization))
	dnsValue := base64.RawURLEncoding.EncodeToString(digest[:])
	order := &Order{
		ID:            id,
		AccountID:     account.ID,
		Status:        "pending",
		Domain:        domain,
		Authorization: absolutePathURL(r, "/acme/authz/"+id),
		Finalize:      absolutePathURL(r, "/acme/finalize/"+id),
		ChallengeURL:  absolutePathURL(r, "/acme/challenge/"+id),
		Token:         token,
		DNSValue:      dnsValue,
	}
	s.mu.Lock()
	s.orders[id] = order
	s.mu.Unlock()
	if err := s.persistOrder(order); err != nil {
		s.mu.Lock()
		delete(s.orders, id)
		s.mu.Unlock()
		s.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}

	location := absolutePathURL(r, "/acme/order/"+id)
	w.Header().Set("Location", location)
	s.addReplayNonce(w)
	writeJSON(w, http.StatusCreated, s.orderResponse(order))
}

func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	account, _, err := s.verifyAccountRequest(r)
	if err != nil {
		s.writeACMEError(w, err)
		return
	}
	order := s.getOrder(r.PathValue("id"))
	if order == nil || order.AccountID != account.ID {
		s.respondProblem(w, http.StatusNotFound, "malformed", "order not found")
		return
	}
	s.addReplayNonce(w)
	writeJSON(w, http.StatusOK, s.orderResponse(order))
}

func (s *Server) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	account, _, err := s.verifyAccountRequest(r)
	if err != nil {
		s.writeACMEError(w, err)
		return
	}
	order := s.getOrder(r.PathValue("id"))
	if order == nil || order.AccountID != account.ID {
		s.respondProblem(w, http.StatusNotFound, "malformed", "authorization not found")
		return
	}
	s.addReplayNonce(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"identifier": map[string]string{"type": "dns", "value": order.Domain},
		"status":     order.Status,
		"challenges": []map[string]any{{
			"type":   "dns-01",
			"url":    order.ChallengeURL,
			"status": "pending",
			"token":  order.Token,
		}},
	})
}

func (s *Server) verifyAccountRequest(r *http.Request) (*Account, verifiedJWS, error) {
	verified, err := s.verifyJWSRequest(r, false)
	if err != nil {
		return nil, verifiedJWS{}, err
	}
	id := strings.TrimPrefix(verified.Header.KID, absolutePathURL(r, "/acme/acct/"))
	if id == verified.Header.KID || id == "" {
		return nil, verifiedJWS{}, &acmeError{Status: http.StatusUnauthorized, Type: "accountDoesNotExist", Detail: "unknown account URL"}
	}
	s.mu.RLock()
	account := s.accounts[id]
	s.mu.RUnlock()
	if account == nil {
		return nil, verifiedJWS{}, &acmeError{Status: http.StatusUnauthorized, Type: "accountDoesNotExist", Detail: "account does not exist"}
	}
	return account, verified, nil
}

func (s *Server) verifyJWSRequest(r *http.Request, requireJWK bool) (verifiedJWS, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return verifiedJWS{}, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: "cannot read JWS body"}
	}
	_ = r.Body.Close()
	env, header, payload, signature, err := decodeJWS(body)
	if err != nil {
		return verifiedJWS{}, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: err.Error()}
	}
	if header.Alg == "" || header.Nonce == "" || header.URL == "" {
		return verifiedJWS{}, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: "alg, nonce and url are required in protected header"}
	}
	if header.URL != absoluteRequestURL(r) {
		return verifiedJWS{}, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: "JWS url does not match request URL"}
	}
	if !s.consumeNonce(header.Nonce) {
		return verifiedJWS{}, &acmeError{Status: http.StatusBadRequest, Type: "badNonce", Detail: "invalid or already-used nonce"}
	}
	if requireJWK {
		if len(header.JWK) == 0 || header.KID != "" {
			return verifiedJWS{}, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: "newAccount requires jwk and must not contain kid"}
		}
		publicKey, err := parseJWK(header.JWK)
		if err != nil {
			return verifiedJWS{}, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: err.Error()}
		}
		if err := verifyJWSSignature(env, header, signature, publicKey); err != nil {
			return verifiedJWS{}, &acmeError{Status: http.StatusBadRequest, Type: "badSignatureAlgorithm", Detail: err.Error()}
		}
		return verifiedJWS{Header: header, Payload: payload, PublicKey: publicKey, JWK: header.JWK}, nil
	}
	if header.KID == "" || len(header.JWK) != 0 {
		return verifiedJWS{}, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: "account requests require kid and must not contain jwk"}
	}
	id := strings.TrimPrefix(header.KID, absolutePathURL(r, "/acme/acct/"))
	s.mu.RLock()
	account := s.accounts[id]
	s.mu.RUnlock()
	if account == nil {
		return verifiedJWS{}, &acmeError{Status: http.StatusUnauthorized, Type: "accountDoesNotExist", Detail: "account does not exist"}
	}
	if err := verifyJWSSignature(env, header, signature, account.PublicKey); err != nil {
		return verifiedJWS{}, &acmeError{Status: http.StatusUnauthorized, Type: "unauthorized", Detail: err.Error()}
	}
	return verifiedJWS{Header: header, Payload: payload, PublicKey: account.PublicKey, JWK: account.JWK}, nil
}

func (s *Server) issueNonce() (string, error) {
	nonce, err := randomToken(24)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.nonces[nonce] = struct{}{}
	s.mu.Unlock()
	return nonce, nil
}

func (s *Server) consumeNonce(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.nonces[nonce]; !ok {
		return false
	}
	delete(s.nonces, nonce)
	return true
}

func (s *Server) addReplayNonce(w http.ResponseWriter) {
	if nonce, err := s.issueNonce(); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
}

func (s *Server) getOrder(id string) *Order {
	s.mu.RLock()
	defer s.mu.RUnlock()
	order := s.orders[id]
	if order == nil {
		return nil
	}
	copyOrder := *order
	return &copyOrder
}

func (s *Server) persistAccount(account *Account) error {
	if s.stateStore == nil {
		return nil
	}
	record := AccountRecord{
		ID:         account.ID,
		Status:     account.Status,
		Contact:    append([]string(nil), account.Contact...),
		JWK:        append(json.RawMessage(nil), account.JWK...),
		Thumbprint: account.Thumbprint,
	}
	return s.stateStore.Update(func(state *PersistentState) error {
		state.Accounts[record.ID] = record
		return nil
	})
}

func (s *Server) persistOrder(order *Order) error {
	if s.stateStore == nil {
		return nil
	}
	copyOrder := *order
	return s.stateStore.Update(func(state *PersistentState) error {
		state.Orders[copyOrder.ID] = copyOrder
		return nil
	})
}

func (s *Server) orderResponse(order *Order) map[string]any {
	return map[string]any{
		"status":         order.Status,
		"identifiers":    []map[string]string{{"type": "dns", "value": order.Domain}},
		"authorizations": []string{order.Authorization},
		"finalize":       order.Finalize,
	}
}

func accountResponse(account *Account) map[string]any {
	return map[string]any{"status": account.Status, "contact": account.Contact}
}

type acmeError struct {
	Status int
	Type   string
	Detail string
}

func (e *acmeError) Error() string { return e.Detail }

func (s *Server) writeACMEError(w http.ResponseWriter, err error) {
	if ae, ok := err.(*acmeError); ok {
		s.respondProblem(w, ae.Status, ae.Type, ae.Detail)
		return
	}
	s.respondProblem(w, http.StatusBadRequest, "malformed", err.Error())
}

func (s *Server) respondProblem(w http.ResponseWriter, status int, problemType, detail string) {
	s.addReplayNonce(w)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "urn:ietf:params:acme:error:" + problemType,
		"detail": detail,
		"status": status,
	})
}

func writeProblem(w http.ResponseWriter, status int, problemType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "urn:ietf:params:acme:error:" + problemType,
		"detail": detail,
		"status": status,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomID(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func requestBaseURL(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func absolutePathURL(r *http.Request, path string) string {
	return requestBaseURL(r) + path
}

func absoluteRequestURL(r *http.Request) string {
	return requestBaseURL(r) + r.URL.RequestURI()
}
