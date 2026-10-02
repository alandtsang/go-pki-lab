package platform

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type monitorRepository struct {
	targets []DeploymentTarget
	err     error
}

func (r *monitorRepository) LoadAll() ([]DeploymentTarget, error) { return r.targets, nil }
func (r *monitorRepository) Save(target DeploymentTarget) error {
	if r.err != nil {
		return r.err
	}
	r.targets = []DeploymentTarget{target}
	return nil
}

func monitorTLS(t *testing.T, domain string, before, after time.Time) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(10), DNSNames: []string{domain}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, cert
}

func TestMonitoringTLSStatuses(t *testing.T) {
	now := time.Now()
	options := MonitoringOptions{Timeout: time.Second, ExpiringBefore: 24 * time.Hour}
	for _, tc := range []struct {
		name, domain, status      string
		expiry                    time.Duration
		missing, mismatch, future bool
	}{
		{name: "healthy", domain: "hello.test", expiry: 48 * time.Hour, status: MonitoringHealthy},
		{name: "drift", domain: "hello.test", expiry: 48 * time.Hour, mismatch: true, status: MonitoringSerialMismatch},
		{name: "no current", domain: "hello.test", expiry: 48 * time.Hour, missing: true, status: MonitoringSerialMismatch},
		{name: "expiring", domain: "hello.test", expiry: time.Hour, status: MonitoringCertificateExpiring},
		{name: "expired", domain: "hello.test", expiry: -time.Hour, status: MonitoringCertificateExpired},
		{name: "wrong hostname", domain: "other.test", expiry: 48 * time.Hour, status: MonitoringHostnameMismatch},
		{name: "future", domain: "hello.test", expiry: 48 * time.Hour, future: true, status: MonitoringSerialMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := now.Add(-2 * time.Hour)
			if tc.future {
				before = now.Add(time.Hour)
			}
			server, cert := monitorTLS(t, tc.domain, before, now.Add(tc.expiry))
			repo := &monitorRepository{targets: []DeploymentTarget{{ID: "target", Domain: "hello.test", Address: server.Listener.Addr().String(), Enabled: true}}}
			service := &Service{}
			if err := service.SetDeploymentTargetRepository(repo); err != nil {
				t.Fatal(err)
			}
			if !tc.missing {
				expected := *cert
				expected.NotBefore = now.Add(-time.Hour)
				expected.NotAfter = now.Add(48 * time.Hour)
				if tc.mismatch {
					expected.SerialNumber = big.NewInt(11)
				}
				service.AddCertificateStateSource(&testCertificateStateSource{states: []CertificateState{{Domain: "hello.test", Certificate: &expected}}})
			}
			state, err := service.ProbeDeploymentTarget(context.Background(), "target", options)
			if err != nil {
				t.Fatal(err)
			}
			if state.Status != tc.status || state.OnlineSerial != "0A" {
				t.Fatalf("unexpected state: %+v", state)
			}
			reloaded := &Service{}
			if err := reloaded.SetDeploymentTargetRepository(repo); err != nil {
				t.Fatal(err)
			}
			target, err := reloaded.GetDeploymentTarget("target")
			if err != nil || target.Monitoring != state {
				t.Fatalf("observation not persisted: %+v %v", target, err)
			}
			if tc.name == "healthy" {
				source := service.certificateSources[0].(*testCertificateStateSource)
				original := source.states[0].Certificate
				renewed := *original
				renewed.SerialNumber = big.NewInt(11)
				source.states[0].Certificate = &renewed
				drift, err := service.ProbeDeploymentTarget(context.Background(), "target", options)
				if err != nil || drift.Status != MonitoringSerialMismatch || drift.ExpectedSerial != "0B" {
					t.Fatalf("renewal drift: %+v %v", drift, err)
				}
				source.states[0].Certificate = original
				state, err = service.ProbeDeploymentTarget(context.Background(), "target", options)
				if err != nil || state.Status != MonitoringHealthy {
					t.Fatalf("recovery: %+v %v", state, err)
				}
			}
			// Persistence failure must not replace the last successful observation.
			repo.err = errors.New("disk full")
			if _, err := service.ProbeDeploymentTarget(context.Background(), "target", options); err == nil {
				t.Fatal("expected save failure")
			}
			target, _ = service.GetDeploymentTarget("target")
			if target.Monitoring != state {
				t.Fatal("failed save changed memory")
			}
		})
	}
}

func TestMonitoringTimeoutCancellationAndScan(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// A TCP listener that never speaks TLS exercises the handshake timeout.
	service := &Service{}
	repo := &monitorRepository{targets: []DeploymentTarget{{ID: "stall", Domain: "hello.test", Address: listener.Addr().String(), Enabled: true}, {ID: "disabled", Domain: "hello.test"}}}
	if err := service.SetDeploymentTargetRepository(repo); err != nil {
		t.Fatal(err)
	}
	options := MonitoringOptions{Timeout: 50 * time.Millisecond, ExpiringBefore: time.Hour}
	result, err := service.RunMonitoringScan(context.Background(), options)
	if err != nil || result.States["stall"].Status != MonitoringTLSUnreachable || len(result.SkippedTargets) != 1 {
		t.Fatalf("unexpected scan: %+v %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before, _ := service.GetDeploymentTarget("stall")
	if _, err := service.ProbeDeploymentTarget(ctx, "stall", options); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
	after, _ := service.GetDeploymentTarget("stall")
	if before.Monitoring != after.Monitoring {
		t.Fatal("cancellation changed state")
	}
	if _, err := service.ProbeDeploymentTarget(context.Background(), "disabled", options); err == nil {
		t.Fatal("disabled target probed")
	}
	if _, err := service.RunMonitoringScan(context.Background(), MonitoringOptions{}); err == nil {
		t.Fatal("invalid options accepted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { service.RunMonitoring(ctx, time.Millisecond, options, nil); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop")
	}
}

func TestPeriodicMonitoring(t *testing.T) {
	service := &Service{}
	repo := &monitorRepository{targets: []DeploymentTarget{{ID: "target", Domain: "hello.test", Address: "invalid address", Enabled: true}}}
	if err := service.SetDeploymentTargetRepository(repo); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	started := time.Now()
	service.RunMonitoring(ctx, 10*time.Millisecond, MonitoringOptions{Timeout: time.Second}, nil)
	target, _ := service.GetDeploymentTarget("target")
	if target.Monitoring.Status != MonitoringTLSUnreachable || target.Monitoring.CheckedAt.Before(started.Add(10*time.Millisecond)) {
		t.Fatalf("periodic observation missing: %+v", target)
	}
}
