package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	localdns "github.com/alandtsang/go-pki-lab/internal/dns"
	"github.com/alandtsang/go-pki-lab/internal/platform"
)

func TestOrderAPIFlow(t *testing.T) {
	root, err := ca.NewRoot("Test Root CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "Test Intermediate CA", 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	store := localdns.NewStore()
	dnsServer, err := localdns.StartLocalServer("127.0.0.1:0", store)
	if err != nil {
		t.Fatal(err)
	}
	defer dnsServer.Shutdown()

	service, err := platform.NewService(root, intermediate, dnsServer.Addr())
	if err != nil {
		t.Fatal(err)
	}
	apiServer, err := NewServer(service, store, root.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(apiServer.Handler())
	defer httpServer.Close()

	create := doJSON(t, http.MethodPost, httpServer.URL+"/orders", map[string]any{"domain": "hello.test"})
	if create.StatusCode != http.StatusCreated {
		t.Fatalf("create order status = %d, body = %s", create.StatusCode, create.Body)
	}
	var created struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		Challenge struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"challenge"`
	}
	if err := json.Unmarshal(create.Body, &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Status != "pending" || created.Challenge.Name == "" || created.Challenge.Value == "" {
		t.Fatalf("unexpected order response: %s", create.Body)
	}

	setTXT := doJSON(t, http.MethodPost, httpServer.URL+"/dns/txt", map[string]any{
		"name":   created.Challenge.Name,
		"values": []string{created.Challenge.Value},
	})
	if setTXT.StatusCode != http.StatusOK {
		t.Fatalf("set TXT status = %d, body = %s", setTXT.StatusCode, setTXT.Body)
	}

	validate := doJSON(t, http.MethodPost, httpServer.URL+"/orders/"+created.ID+"/validate", nil)
	if validate.StatusCode != http.StatusOK || !bytes.Contains(validate.Body, []byte(`"status":"ready"`)) {
		t.Fatalf("validate status = %d, body = %s", validate.StatusCode, validate.Body)
	}

	issue := doJSON(t, http.MethodPost, httpServer.URL+"/orders/"+created.ID+"/issue", nil)
	if issue.StatusCode != http.StatusOK {
		t.Fatalf("issue status = %d, body = %s", issue.StatusCode, issue.Body)
	}
	if !bytes.Contains(issue.Body, []byte(`"status":"valid"`)) ||
		!bytes.Contains(issue.Body, []byte("BEGIN CERTIFICATE")) ||
		!bytes.Contains(issue.Body, []byte("BEGIN PRIVATE KEY")) {
		t.Fatalf("unexpected issuance response: %s", issue.Body)
	}
}

type httpResult struct {
	StatusCode int
	Body       []byte
}

func doJSON(t *testing.T, method, url string, body any) httpResult {
	t.Helper()
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return httpResult{StatusCode: resp.StatusCode, Body: []byte(strings.TrimSpace(buf.String()))}
}
