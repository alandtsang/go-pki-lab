package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type deploymentJob struct {
	ID                string `json:"id"`
	TargetID          string `json:"target_id"`
	Domain            string `json:"domain"`
	CertificateSerial string `json:"certificate_serial"`
	Status            string `json:"status"`
}

type jobsResponse struct {
	Jobs []deploymentJob `json:"jobs"`
}

type deploymentTarget struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
	Enabled  bool   `json:"enabled"`
}

func main() {
	apiBase := flag.String("api", "http://127.0.0.1:8080", "go-pki-lab API base URL")
	clientID := flag.String("client-id", hostname(), "deployment executor client id")
	domain := flag.String("domain", "", "optional domain filter")
	ecc := flag.Bool("ecc", true, "use acme.sh ECC certificate directory")
	sourceCert := flag.String("source-cert", "", "optional source full-chain PEM path")
	sourceKey := flag.String("source-key", "", "optional source private key PEM path")
	heartbeatInterval := flag.Duration("heartbeat-interval", 10*time.Second, "job heartbeat interval")
	flag.Parse()
	if *heartbeatInterval <= 0 {
		log.Fatal("heartbeat-interval must be positive")
	}

	job, err := findWaitingJob(*apiBase, *domain)
	if err != nil {
		log.Fatal(err)
	}
	if job == nil {
		fmt.Println("no waiting deployment job")
		return
	}
	target, err := getTarget(*apiBase, job.TargetID)
	if err != nil {
		log.Fatal(err)
	}
	if target.Type != "local_https" {
		log.Fatalf("unsupported deployment target type %q", target.Type)
	}
	if !target.Enabled {
		log.Fatalf("deployment target %s is disabled", target.ID)
	}
	if err := claimJob(*apiBase, job.ID, *clientID); err != nil {
		log.Fatal(err)
	}
	stopHeartbeat := startHeartbeat(*apiBase, job.ID, *clientID, *heartbeatInterval)
	defer stopHeartbeat()

	certPath, keyPath, err := resolveSourcePaths(job.Domain, *ecc, *sourceCert, *sourceKey)
	if err != nil {
		_ = failJob(*apiBase, job.ID, err.Error())
		log.Fatal(err)
	}
	serial, err := validateSource(certPath, keyPath, job.Domain)
	if err != nil {
		_ = failJob(*apiBase, job.ID, err.Error())
		log.Fatal(err)
	}
	if !strings.EqualFold(serial, job.CertificateSerial) {
		err := fmt.Errorf("source certificate serial %s does not match deployment job serial %s", serial, job.CertificateSerial)
		_ = failJob(*apiBase, job.ID, err.Error())
		log.Fatal(err)
	}
	if err := copyAtomic(certPath, target.CertPath, 0o644); err != nil {
		_ = failJob(*apiBase, job.ID, err.Error())
		log.Fatal(err)
	}
	if err := copyAtomic(keyPath, target.KeyPath, 0o600); err != nil {
		_ = failJob(*apiBase, job.ID, err.Error())
		log.Fatal(err)
	}

	verified, err := verifyTLS(target.Address, target.Domain)
	if err != nil {
		_ = failJob(*apiBase, job.ID, err.Error())
		log.Fatal(err)
	}
	if !strings.EqualFold(verified, job.CertificateSerial) {
		err := fmt.Errorf("deployed TLS serial %s does not match expected %s", verified, job.CertificateSerial)
		_ = failJob(*apiBase, job.ID, err.Error())
		log.Fatal(err)
	}
	if err := completeJob(*apiBase, job.ID, verified); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("deployment job %s completed: target=%s serial=%s\n", job.ID, target.ID, verified)
}

func findWaitingJob(apiBase, domain string) (*deploymentJob, error) {
	url := strings.TrimRight(apiBase, "/") + "/deployment-jobs"
	if strings.TrimSpace(domain) != "" {
		url += "?domain=" + domain
	}
	var resp jobsResponse
	if err := getJSON(url, &resp); err != nil {
		return nil, err
	}
	for _, job := range resp.Jobs {
		if job.Status == "waiting_for_client" {
			copyJob := job
			return &copyJob, nil
		}
	}
	return nil, nil
}

func getTarget(apiBase, id string) (*deploymentTarget, error) {
	var target deploymentTarget
	if err := getJSON(strings.TrimRight(apiBase, "/")+"/deployment-targets/"+id, &target); err != nil {
		return nil, err
	}
	return &target, nil
}

func resolveSourcePaths(domain string, ecc bool, certPath, keyPath string) (string, string, error) {
	if certPath != "" || keyPath != "" {
		if certPath == "" || keyPath == "" {
			return "", "", fmt.Errorf("source-cert and source-key must be provided together")
		}
		return certPath, keyPath, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	dirName := domain
	if ecc {
		dirName += "_ecc"
	}
	dir := filepath.Join(home, ".acme.sh", dirName)
	return filepath.Join(dir, "fullchain.cer"), filepath.Join(dir, domain+".key"), nil
}

func validateSource(certPath, keyPath, domain string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return "", fmt.Errorf("validate source key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return "", fmt.Errorf("source certificate chain is empty")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", err
	}
	if err := cert.VerifyHostname(domain); err != nil {
		return "", fmt.Errorf("source certificate hostname: %w", err)
	}
	return serialHex(cert), nil
}

func copyAtomic(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func verifyTLS(address, domain string) (string, error) {
	conn, err := tls.DialWithDialer(&netDialer, "tcp", address, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         domain,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", fmt.Errorf("TLS verification dial: %w", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("TLS target returned no peer certificate")
	}
	cert := state.PeerCertificates[0]
	if err := cert.VerifyHostname(domain); err != nil {
		return "", fmt.Errorf("deployed certificate hostname: %w", err)
	}
	return serialHex(cert), nil
}

var netDialer = tlsDialer()

func tlsDialer() net.Dialer {
	return net.Dialer{Timeout: 5 * time.Second}
}

func serialHex(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes()))
}

func startHeartbeat(apiBase, id, clientID string, interval time.Duration) func() {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := postJSON(strings.TrimRight(apiBase, "/")+"/deployment-jobs/"+id+"/heartbeat", map[string]string{"client_id": clientID}); err != nil {
					log.Printf("deployment heartbeat failed: %v", err)
				}
			}
		}
	}()
	return func() { close(stop) }
}

func claimJob(apiBase, id, clientID string) error {
	return postJSON(strings.TrimRight(apiBase, "/")+"/deployment-jobs/"+id+"/claim", map[string]string{"client_id": clientID})
}

func completeJob(apiBase, id, serial string) error {
	return postJSON(strings.TrimRight(apiBase, "/")+"/deployment-jobs/"+id+"/complete", map[string]string{"verified_serial": serial})
}

func failJob(apiBase, id, message string) error {
	return postJSON(strings.TrimRight(apiBase, "/")+"/deployment-jobs/"+id+"/fail", map[string]string{"error": message})
}

func getJSON(url string, dst any) error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s: status=%d body=%s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

func postJSON(url string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s: status=%d body=%s", url, resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "deployment-executor"
	}
	return name
}
