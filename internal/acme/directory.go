package acme

import "net/http"

// HandleDirectory returns the current RFC 8555 directory including resources
// implemented by the issuance/lifecycle layer.
func (s *Server) HandleDirectory(w http.ResponseWriter, r *http.Request) {
	base := requestBaseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"newNonce":   base + "/acme/new-nonce",
		"newAccount": base + "/acme/new-account",
		"newOrder":   base + "/acme/new-order",
		"revokeCert": base + "/acme/revoke-cert",
	})
}
