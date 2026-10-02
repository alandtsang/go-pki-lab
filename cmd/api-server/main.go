package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/acme"
	"github.com/alandtsang/go-pki-lab/internal/api"
	"github.com/alandtsang/go-pki-lab/internal/ca"
	localdns "github.com/alandtsang/go-pki-lab/internal/dns"
	"github.com/alandtsang/go-pki-lab/internal/persistence"
	"github.com/alandtsang/go-pki-lab/internal/platform"
)

func main() {
	httpAddr := flag.String("http", "127.0.0.1:8080", "HTTP API listen address")
	dnsAddr := flag.String("dns", "127.0.0.1:1053", "local DNS listen address")
	dataDir := flag.String("data-dir", "./data", "persistent data directory")
	renewalScanInterval := flag.Duration("renewal-scan-interval", time.Minute, "renewal scheduler scan interval")
	deploymentScanInterval := flag.Duration("deployment-scan-interval", 15*time.Second, "deployment reconciler scan interval")
	monitorInterval := flag.Duration("monitor-interval", time.Minute, "certificate monitoring interval; non-positive disables")
	monitorTimeout := flag.Duration("monitor-timeout", 5*time.Second, "per-target TLS probe timeout")
	monitorExpiryDays := flag.Int("monitor-expiring-before-days", 30, "certificate expiry warning window in days")
	monitorExpiryLegacy := flag.Duration("monitor-expiring-before", 0, "deprecated: certificate expiry warning window as Go duration (for example 720h)")
	flag.Parse()

	if *monitorTimeout <= 0 || *monitorExpiryDays < 0 || *monitorExpiryLegacy < 0 {
		log.Fatal("invalid monitoring options")
	}
	monitorExpiry := time.Duration(*monitorExpiryDays) * 24 * time.Hour
	if *monitorExpiryLegacy > 0 {
		monitorExpiry = *monitorExpiryLegacy
	}
	monitorOptions := platform.MonitoringOptions{Timeout: *monitorTimeout, ExpiringBefore: monitorExpiry}

	root, intermediate, created, err := loadOrCreateCA(filepath.Join(*dataDir, "ca"))
	if err != nil {
		log.Fatal(err)
	}

	store := localdns.NewStore()
	dnsServer, err := localdns.StartLocalServer(*dnsAddr, store)
	if err != nil {
		log.Fatal(err)
	}
	defer dnsServer.Shutdown()

	repository, err := persistence.NewFileRepository(filepath.Join(*dataDir, "orders"))
	if err != nil {
		log.Fatal(err)
	}
	service, err := platform.NewService(root, intermediate, dnsServer.Addr(), repository)
	if err != nil {
		log.Fatal(err)
	}
	renewalPolicyRepository, err := persistence.NewRenewalPolicyRepository(filepath.Join(*dataDir, "renewal-policies"))
	if err != nil {
		log.Fatal(err)
	}
	if err := service.SetRenewalPolicyRepository(renewalPolicyRepository); err != nil {
		log.Fatal(err)
	}
	renewalJobRepository, err := persistence.NewRenewalJobRepository(filepath.Join(*dataDir, "renewal-jobs"))
	if err != nil {
		log.Fatal(err)
	}
	if err := service.SetRenewalJobRepository(renewalJobRepository); err != nil {
		log.Fatal(err)
	}
	deploymentTargetRepository, err := persistence.NewDeploymentTargetRepository(filepath.Join(*dataDir, "deployment-targets"))
	if err != nil {
		log.Fatal(err)
	}
	if err := service.SetDeploymentTargetRepository(deploymentTargetRepository); err != nil {
		log.Fatal(err)
	}
	deploymentJobRepository, err := persistence.NewDeploymentJobRepository(filepath.Join(*dataDir, "deployment-jobs"))
	if err != nil {
		log.Fatal(err)
	}
	if err := service.SetDeploymentJobRepository(deploymentJobRepository); err != nil {
		log.Fatal(err)
	}
	apiServer, err := api.NewServer(service, store, root.CertPEM)
	if err != nil {
		log.Fatal(err)
	}
	renewalPolicyAPI, err := api.NewRenewalPolicyAPI(service)
	if err != nil {
		log.Fatal(err)
	}
	renewalJobAPI, err := api.NewRenewalJobAPI(service)
	if err != nil {
		log.Fatal(err)
	}
	deploymentAPI, err := api.NewDeploymentAPIWithMonitoring(service, monitorOptions)
	if err != nil {
		log.Fatal(err)
	}

	acmeStateStore, err := acme.NewFileStateStore(filepath.Join(*dataDir, "acme", "state.json"))
	if err != nil {
		log.Fatal(err)
	}
	acmeServer, err := acme.NewServerWithStore(acmeStateStore)
	if err != nil {
		log.Fatal(err)
	}
	acmeIssuance, err := acme.NewIssuanceWithStore(acmeServer, root, intermediate, dnsServer.Addr(), acmeStateStore)
	if err != nil {
		log.Fatal(err)
	}
	service.AddCertificateStateSource(acmeIssuance)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /acme/directory", acmeServer.HandleDirectory)
	mux.HandleFunc("POST /acme/challenge/{id}", acmeIssuance.HandleChallenge)
	mux.HandleFunc("POST /acme/authz/{id}", acmeIssuance.HandleAuthorization)
	mux.HandleFunc("POST /acme/order/{id}", acmeIssuance.HandleOrder)
	mux.HandleFunc("POST /acme/finalize/{id}", acmeIssuance.HandleFinalize)
	mux.HandleFunc("POST /acme/cert/{id}", acmeIssuance.HandleCertificate)
	mux.HandleFunc("POST /acme/revoke-cert", acmeIssuance.HandleRevokeCertificate)
	mux.Handle("/acme/", acmeServer.Handler())
	mux.Handle("GET /domains/{domain}/renewal-policy", renewalPolicyAPI.Handler())
	mux.Handle("PUT /domains/{domain}/renewal-policy", renewalPolicyAPI.Handler())
	mux.Handle("GET /domains/{domain}/renewal-decision", renewalPolicyAPI.Handler())
	mux.Handle("POST /renewal-scheduler/run", renewalJobAPI.Handler())
	mux.Handle("GET /renewal-jobs", renewalJobAPI.Handler())
	mux.Handle("GET /renewal-jobs/{id}", renewalJobAPI.Handler())
	mux.Handle("POST /renewal-jobs/{id}/claim", renewalJobAPI.Handler())
	mux.Handle("POST /renewal-jobs/{id}/complete", renewalJobAPI.Handler())
	mux.Handle("POST /renewal-jobs/{id}/fail", renewalJobAPI.Handler())
	mux.Handle("GET /deployment-targets/{id}/monitoring", deploymentAPI.Handler())
	mux.Handle("POST /deployment-targets/{id}/probe", deploymentAPI.Handler())
	mux.Handle("POST /certificate-monitor/run", deploymentAPI.Handler())
	mux.Handle("POST /deployment-targets", deploymentAPI.Handler())
	mux.Handle("GET /deployment-targets", deploymentAPI.Handler())
	mux.Handle("GET /deployment-targets/{id}", deploymentAPI.Handler())
	mux.Handle("POST /deployment-targets/{id}/deploy", deploymentAPI.Handler())
	mux.Handle("POST /deployment-reconciler/run", deploymentAPI.Handler())
	mux.Handle("GET /deployment-jobs", deploymentAPI.Handler())
	mux.Handle("GET /deployment-jobs/{id}", deploymentAPI.Handler())
	mux.Handle("POST /deployment-jobs/{id}/claim", deploymentAPI.Handler())
	mux.Handle("POST /deployment-jobs/{id}/complete", deploymentAPI.Handler())
	mux.Handle("POST /deployment-jobs/{id}/fail", deploymentAPI.Handler())
	mux.Handle("/", apiServer.Handler())

	httpServer := &http.Server{
		Addr:              *httpAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		fmt.Printf("go-pki-lab API server started\n")
		fmt.Printf("HTTP API: http://%s\n", *httpAddr)
		fmt.Printf("ACME directory: http://%s/acme/directory\n", *httpAddr)
		fmt.Printf("Local DNS: %s\n", dnsServer.Addr())
		fmt.Printf("Root CA: http://%s/ca/root\n", *httpAddr)
		fmt.Printf("Persistent data: %s\n", *dataDir)
		fmt.Printf("ACME state: %s\n", filepath.Join(*dataDir, "acme", "state.json"))
		fmt.Printf("Renewal policies: %s\n", filepath.Join(*dataDir, "renewal-policies"))
		fmt.Printf("Renewal jobs: %s\n", filepath.Join(*dataDir, "renewal-jobs"))
		fmt.Printf("Deployment targets: %s\n", filepath.Join(*dataDir, "deployment-targets"))
		fmt.Printf("Deployment jobs: %s\n", filepath.Join(*dataDir, "deployment-jobs"))
		fmt.Printf("Renewal scan interval: %s\n", renewalScanInterval.String())
		fmt.Printf("Deployment scan interval: %s\n", deploymentScanInterval.String())
		fmt.Printf("Monitoring interval: %s\n", monitorInterval.String())
		fmt.Printf("Monitoring expiry warning: %s\n", monitorExpiry)
		if created {
			fmt.Printf("CA state: initialized new persistent CA\n")
		} else {
			fmt.Printf("CA state: loaded existing persistent CA\n")
		}
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server: %v", err)
		}
	}()

	monitorCtx, stopMonitor := context.WithCancel(context.Background())
	defer stopMonitor()
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		service.RunMonitoring(monitorCtx, *monitorInterval, monitorOptions, func(err error) { log.Printf("certificate monitor: %v", err) })
	}()

	go runRenewalScheduler(service, *renewalScanInterval)
	go runDeploymentReconciler(service, *deploymentScanInterval)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	stopMonitor()
	<-monitorDone

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown: %v", err)
	}
}

func runRenewalScheduler(service *platform.Service, interval time.Duration) {
	if interval <= 0 {
		return
	}
	run := func() {
		result, err := service.RunRenewalScan()
		if err != nil {
			log.Printf("renewal scheduler: %v", err)
			return
		}
		if len(result.CreatedJobs) > 0 {
			log.Printf("renewal scheduler created %d job(s)", len(result.CreatedJobs))
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		run()
	}
}

func runDeploymentReconciler(service *platform.Service, interval time.Duration) {
	if interval <= 0 {
		return
	}
	run := func() {
		result, err := service.RunDeploymentReconcile()
		if err != nil {
			log.Printf("deployment reconciler: %v", err)
			return
		}
		if len(result.CreatedJobs) > 0 {
			log.Printf("deployment reconciler created %d job(s)", len(result.CreatedJobs))
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		run()
	}
}

func loadOrCreateCA(dir string) (root, intermediate *ca.Authority, created bool, err error) {
	root, rootErr := ca.LoadAuthority(dir, "root-ca")
	intermediate, intermediateErr := ca.LoadAuthority(dir, "intermediate-ca")
	if rootErr == nil && intermediateErr == nil {
		if err := intermediate.Certificate.CheckSignatureFrom(root.Certificate); err != nil {
			return nil, nil, false, fmt.Errorf("verify persisted intermediate CA: %w", err)
		}
		return root, intermediate, false, nil
	}
	if !os.IsNotExist(rootErr) || !os.IsNotExist(intermediateErr) {
		return nil, nil, false, fmt.Errorf("load persisted CA: root=%v intermediate=%v", rootErr, intermediateErr)
	}

	root, err = ca.NewRoot("Go PKI Lab Root CA", 10*365*24*time.Hour)
	if err != nil {
		return nil, nil, false, err
	}
	intermediate, err = ca.NewIntermediate(root, "Go PKI Lab Intermediate CA", 5*365*24*time.Hour)
	if err != nil {
		return nil, nil, false, err
	}
	if err := ca.SaveAuthority(dir, "root-ca", root); err != nil {
		return nil, nil, false, err
	}
	if err := ca.SaveAuthority(dir, "intermediate-ca", intermediate); err != nil {
		return nil, nil, false, err
	}
	return root, intermediate, true, nil
}
