package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type renewalJob struct {
	ID           string `json:"id"`
	Domain       string `json:"domain"`
	Status       string `json:"status"`
	SourceSerial string `json:"source_serial"`
}

type jobsResponse struct {
	Jobs []renewalJob `json:"jobs"`
}

type certificateInstance struct {
	CurrentCertificate *struct {
		SerialNumber string `json:"serial_number"`
	} `json:"current_certificate"`
}

func main() {
	apiBase := flag.String("api", "http://127.0.0.1:8080", "go-pki-lab API base URL")
	acmeServer := flag.String("acme-server", "http://127.0.0.1:8080/acme/directory", "ACME directory URL")
	acmeSH := flag.String("acme-sh", defaultACMEShPath(), "path to acme.sh")
	clientID := flag.String("client-id", hostname(), "renewal executor client id")
	domain := flag.String("domain", "", "optional domain filter")
	ecc := flag.Bool("ecc", true, "pass --ecc to acme.sh")
	flag.Parse()

	job, err := findWaitingJob(*apiBase, *domain)
	if err != nil {
		log.Fatal(err)
	}
	if job == nil {
		fmt.Println("no waiting renewal job")
		return
	}
	if err := claimJob(*apiBase, job.ID, *clientID); err != nil {
		log.Fatal(err)
	}

	args := []string{"--renew", "--server", *acmeServer, "-d", job.Domain, "--force"}
	if *ecc {
		args = append(args, "--ecc")
	}
	cmd := exec.Command(*acmeSH, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = failJob(*apiBase, job.ID, err.Error())
		log.Fatal(err)
	}

	instance, err := getCertificateInstance(*apiBase, job.Domain)
	if err != nil {
		_ = failJob(*apiBase, job.ID, err.Error())
		log.Fatal(err)
	}
	if instance.CurrentCertificate == nil || strings.TrimSpace(instance.CurrentCertificate.SerialNumber) == "" {
		err := fmt.Errorf("renewal succeeded but platform has no current certificate")
		_ = failJob(*apiBase, job.ID, err.Error())
		log.Fatal(err)
	}
	serial := strings.ToUpper(instance.CurrentCertificate.SerialNumber)
	if strings.EqualFold(serial, job.SourceSerial) {
		err := fmt.Errorf("renewal did not rotate certificate serial")
		_ = failJob(*apiBase, job.ID, err.Error())
		log.Fatal(err)
	}
	if err := completeJob(*apiBase, job.ID, serial); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("renewal job %s completed: %s -> %s\n", job.ID, job.SourceSerial, serial)
}

func findWaitingJob(apiBase, domain string) (*renewalJob, error) {
	url := strings.TrimRight(apiBase, "/") + "/renewal-jobs"
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

func claimJob(apiBase, id, clientID string) error {
	return postJSON(strings.TrimRight(apiBase, "/")+"/renewal-jobs/"+id+"/claim", map[string]string{"client_id": clientID}, nil)
}

func completeJob(apiBase, id, serial string) error {
	return postJSON(strings.TrimRight(apiBase, "/")+"/renewal-jobs/"+id+"/complete", map[string]string{"result_serial": serial}, nil)
}

func failJob(apiBase, id, message string) error {
	return postJSON(strings.TrimRight(apiBase, "/")+"/renewal-jobs/"+id+"/fail", map[string]string{"error": message}, nil)
}

func getCertificateInstance(apiBase, domain string) (*certificateInstance, error) {
	var instance certificateInstance
	url := strings.TrimRight(apiBase, "/") + "/domains/" + domain + "/certificate-instance"
	if err := getJSON(url, &instance); err != nil {
		return nil, err
	}
	return &instance, nil
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

func postJSON(url string, body any, dst any) error {
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
	if dst != nil {
		return json.NewDecoder(resp.Body).Decode(dst)
	}
	return nil
}

func defaultACMEShPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "acme.sh"
	}
	return filepath.Join(home, ".acme.sh", "acme.sh")
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "renewal-executor"
	}
	return name
}
