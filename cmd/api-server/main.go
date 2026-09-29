package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/api"
	"github.com/alandtsang/go-pki-lab/internal/ca"
	localdns "github.com/alandtsang/go-pki-lab/internal/dns"
	"github.com/alandtsang/go-pki-lab/internal/platform"
)

func main() {
	httpAddr := flag.String("http", "127.0.0.1:8080", "HTTP API listen address")
	dnsAddr := flag.String("dns", "127.0.0.1:1053", "local DNS listen address")
	flag.Parse()

	root, err := ca.NewRoot("Go PKI Lab Root CA", 10*365*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	intermediate, err := ca.NewIntermediate(root, "Go PKI Lab Intermediate CA", 5*365*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	store := localdns.NewStore()
	dnsServer, err := localdns.StartLocalServer(*dnsAddr, store)
	if err != nil {
		log.Fatal(err)
	}
	defer dnsServer.Shutdown()

	service, err := platform.NewService(root, intermediate, dnsServer.Addr())
	if err != nil {
		log.Fatal(err)
	}
	apiServer, err := api.NewServer(service, store, root.CertPEM)
	if err != nil {
		log.Fatal(err)
	}

	httpServer := &http.Server{
		Addr:              *httpAddr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		fmt.Printf("go-pki-lab API server started\n")
		fmt.Printf("HTTP API: http://%s\n", *httpAddr)
		fmt.Printf("Local DNS: %s\n", dnsServer.Addr())
		fmt.Printf("Root CA: http://%s/ca/root\n", *httpAddr)
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
