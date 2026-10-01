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
	flag.Parse()

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
	apiServer, err := api.NewServer(service, store, root.CertPEM)
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
		if created {
			fmt.Printf("CA state: initialized new persistent CA\n")
		} else {
			fmt.Printf("CA state: loaded existing persistent CA\n")
		}
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown: %v", err)
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
