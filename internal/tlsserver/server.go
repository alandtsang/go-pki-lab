package tlsserver

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Config contains the runtime settings for the local HTTPS server.
type Config struct {
	Addr     string
	Domain   string
	CertFile string
	KeyFile  string
}

// NewTLSConfig loads a leaf/full-chain certificate and matching private key.
func NewTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read certificate file %s: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read private key file %s: %w", keyFile, err)
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate pair: %w", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
	}, nil
}

// NewHandler returns a small diagnostic HTTPS application used by the lab.
func NewHandler(domain string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Go PKI Lab</title></head>
<body>
<h1>Go PKI Lab HTTPS is working</h1>
<p>Requested host: <strong>%s</strong></p>
<p>Certificate domain: <strong>%s</strong></p>
<p>If the browser shows this page without a certificate warning, the local Root CA trust and certificate chain are working.</p>
</body>
</html>`, r.Host, domain)
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	return mux
}

func NewHTTPServer(cfg Config) (*http.Server, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("HTTPS listen address is required")
	}
	if cfg.Domain == "" {
		return nil, fmt.Errorf("certificate domain is required")
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("certificate and private key files are required")
	}

	tlsConfig, err := NewTLSConfig(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           NewHandler(cfg.Domain),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}, nil
}
