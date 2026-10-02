package api

import (
	"github.com/alandtsang/go-pki-lab/internal/persistence"
	"github.com/alandtsang/go-pki-lab/internal/platform"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMonitoringAPI(t *testing.T) {
	service := &platform.Service{}
	repo, err := persistence.NewDeploymentTargetRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetDeploymentTargetRepository(repo); err != nil {
		t.Fatal(err)
	}
	target, err := service.CreateDeploymentTarget("hello.test", "", "invalid address", "cert", "key", true)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := service.CreateDeploymentTarget("hello.test", "", "invalid address", "cert", "key", false)
	if err != nil {
		t.Fatal(err)
	}
	api, err := NewDeploymentAPIWithMonitoring(service, platform.MonitoringOptions{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{"GET", "/deployment-targets/" + target.ID + "/monitoring", 200},
		{"POST", "/deployment-targets/" + target.ID + "/probe", 200},
		{"POST", "/certificate-monitor/run", 200},
		{"GET", "/deployment-targets/missing/monitoring", 404},
		{"POST", "/deployment-targets/missing/probe", 404},
		{"POST", "/deployment-targets/" + disabled.ID + "/probe", 409},
	} {
		rec := httptest.NewRecorder()
		api.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.path, rec.Code, rec.Body.String())
		}
	}
	got, _ := service.GetDeploymentTarget(target.ID)
	if got.Monitoring.Status != platform.MonitoringTLSUnreachable {
		t.Fatalf("unexpected state: %+v", got)
	}
	rec := httptest.NewRecorder()
	api.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/deployment-targets/"+target.ID+"/monitoring", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
}
