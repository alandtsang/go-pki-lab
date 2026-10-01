package acme

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HandleRevokeCertificate implements the RFC 8555 revokeCert resource for
// certificates issued by this ACME service. Requests may be authenticated by
// the owning ACME account key (kid) or by the certificate private key (jwk).
func (i *Issuance) HandleRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	verified, account, err := i.verifyRevocationJWS(r)
	if err != nil {
		i.server.writeACMEError(w, err)
		return
	}

	var payload struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason,omitempty"`
	}
	if err := json.Unmarshal(verified.Payload, &payload); err != nil || payload.Certificate == "" {
		i.server.respondProblem(w, http.StatusBadRequest, "malformed", "revokeCert payload must contain certificate")
		return
	}
	if !validRevocationReason(payload.Reason) {
		i.server.respondProblem(w, http.StatusBadRequest, "badRevocationReason", "unsupported revocation reason")
		return
	}

	der, err := base64.RawURLEncoding.DecodeString(payload.Certificate)
	if err != nil {
		i.server.respondProblem(w, http.StatusBadRequest, "malformed", "certificate must be base64url-encoded DER")
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		i.server.respondProblem(w, http.StatusBadRequest, "malformed", "cannot parse certificate")
		return
	}

	state, found, err := i.FindCertificateBySerial(cert.SerialNumber)
	if err != nil {
		i.server.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	if !found || state == nil || state.Certificate == nil || !bytes.Equal(state.Certificate.Raw, cert.Raw) {
		i.server.respondProblem(w, http.StatusBadRequest, "alreadyRevoked", "certificate was not issued by this ACME service")
		return
	}

	order := i.server.getOrder(state.SourceID)
	if order == nil {
		i.server.respondProblem(w, http.StatusBadRequest, "malformed", "certificate order is unavailable")
		return
	}
	if account != nil {
		if order.AccountID != account.ID {
			i.server.respondProblem(w, http.StatusUnauthorized, "unauthorized", "account does not own this certificate")
			return
		}
	} else {
		requestKeyDER, err := x509.MarshalPKIXPublicKey(verified.PublicKey)
		if err != nil {
			i.server.respondProblem(w, http.StatusBadRequest, "malformed", "cannot encode revocation JWK")
			return
		}
		certKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			i.server.respondProblem(w, http.StatusBadRequest, "malformed", "cannot encode certificate public key")
			return
		}
		if !bytes.Equal(requestKeyDER, certKeyDER) {
			i.server.respondProblem(w, http.StatusUnauthorized, "unauthorized", "revocation JWK does not match certificate key")
			return
		}
	}

	i.mu.Lock()
	if _, alreadyRevoked := i.revokedAt[state.SourceID]; !alreadyRevoked {
		i.revokedAt[state.SourceID] = time.Now().UTC()
		i.revocationReason[state.SourceID] = payload.Reason
	}
	i.mu.Unlock()
	if err := i.persistIssuance(state.SourceID); err != nil {
		i.server.respondProblem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}

	i.server.addReplayNonce(w)
	w.WriteHeader(http.StatusOK)
}

func (i *Issuance) verifyRevocationJWS(r *http.Request) (verifiedJWS, *Account, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return verifiedJWS{}, nil, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: "cannot read JWS body"}
	}
	_ = r.Body.Close()
	env, header, payload, signature, err := decodeJWS(body)
	if err != nil {
		return verifiedJWS{}, nil, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: err.Error()}
	}
	if header.Alg == "" || header.Nonce == "" || header.URL == "" {
		return verifiedJWS{}, nil, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: "alg, nonce and url are required in protected header"}
	}
	if header.URL != absoluteRequestURL(r) {
		return verifiedJWS{}, nil, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: "JWS url does not match request URL"}
	}
	if !i.server.consumeNonce(header.Nonce) {
		return verifiedJWS{}, nil, &acmeError{Status: http.StatusBadRequest, Type: "badNonce", Detail: "invalid or already-used nonce"}
	}

	if len(header.JWK) != 0 && header.KID == "" {
		publicKey, err := parseJWK(header.JWK)
		if err != nil {
			return verifiedJWS{}, nil, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: err.Error()}
		}
		if err := verifyJWSSignature(env, header, signature, publicKey); err != nil {
			return verifiedJWS{}, nil, &acmeError{Status: http.StatusUnauthorized, Type: "unauthorized", Detail: err.Error()}
		}
		return verifiedJWS{Header: header, Payload: payload, PublicKey: publicKey, JWK: header.JWK}, nil, nil
	}

	if header.KID != "" && len(header.JWK) == 0 {
		id := accountIDFromKID(r, header.KID)
		if id == "" {
			return verifiedJWS{}, nil, &acmeError{Status: http.StatusUnauthorized, Type: "accountDoesNotExist", Detail: "unknown account URL"}
		}
		i.server.mu.RLock()
		account := i.server.accounts[id]
		i.server.mu.RUnlock()
		if account == nil {
			return verifiedJWS{}, nil, &acmeError{Status: http.StatusUnauthorized, Type: "accountDoesNotExist", Detail: "account does not exist"}
		}
		if err := verifyJWSSignature(env, header, signature, account.PublicKey); err != nil {
			return verifiedJWS{}, nil, &acmeError{Status: http.StatusUnauthorized, Type: "unauthorized", Detail: err.Error()}
		}
		return verifiedJWS{Header: header, Payload: payload, PublicKey: account.PublicKey, JWK: account.JWK}, account, nil
	}

	return verifiedJWS{}, nil, &acmeError{Status: http.StatusBadRequest, Type: "malformed", Detail: "revokeCert requires exactly one of kid or jwk"}
}

func accountIDFromKID(r *http.Request, kid string) string {
	prefix := absolutePathURL(r, "/acme/acct/")
	if len(kid) <= len(prefix) || kid[:len(prefix)] != prefix {
		return ""
	}
	return kid[len(prefix):]
}

func validRevocationReason(reason int) bool {
	switch reason {
	case 0, 1, 2, 3, 4, 5, 6, 8, 9, 10:
		return true
	default:
		return false
	}
}

func revocationErrorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
