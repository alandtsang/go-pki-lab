package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	"github.com/alandtsang/go-pki-lab/internal/certificate"
	localdns "github.com/alandtsang/go-pki-lab/internal/dns"
	"github.com/alandtsang/go-pki-lab/internal/order"
)

func main() {
	domain := flag.String("domain", "hello.test", "DNS name to issue a certificate for")
	outDir := flag.String("out", "out", "directory for generated PKI material")
	dnsAddr := flag.String("dns-addr", "127.0.0.1:1053", "local DNS server listen address")
	flag.Parse()

	root, err := ca.NewRoot("Go PKI Lab Root CA", 10*365*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	intermediate, err := ca.NewIntermediate(root, "Go PKI Lab Intermediate CA", 5*365*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	ord, err := order.New(*domain)
	if err != nil {
		log.Fatal(err)
	}

	store := localdns.NewStore()
	dnsServer, err := localdns.StartLocalServer(*dnsAddr, store)
	if err != nil {
		log.Fatal(err)
	}
	defer dnsServer.Shutdown()

	fmt.Printf("certificate order created\n")
	fmt.Printf("domain: %s\n", ord.Domain)
	fmt.Printf("order status: %s\n", ord.Status)
	fmt.Printf("DNS-01 record: %s TXT %q\n", ord.Challenge.Name, ord.Challenge.Token)
	fmt.Printf("local DNS server: %s\n", dnsServer.Addr())

	// Phase 2 demo: publish the challenge into our local authoritative DNS store.
	// In a later API-based phase, this write will be performed by the user/client.
	store.SetTXT(ord.Challenge.Name, ord.Challenge.Token)

	if err := ord.ValidateDNS01(dnsServer.Addr()); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("DNS-01 validation: OK\n")
	fmt.Printf("order status: %s\n", ord.Status)

	leaf, err := ca.IssueServerCertificate(intermediate, ord.Domain, 90*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	if err := ord.MarkIssued(); err != nil {
		log.Fatal(err)
	}

	if err := ca.VerifyServerCertificate(leaf.Certificate, root, intermediate, ord.Domain); err != nil {
		log.Fatal(err)
	}

	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{"root-ca.crt", root.CertPEM, 0o644},
		{"root-ca.key", root.KeyPEM, 0o600},
		{"intermediate-ca.crt", intermediate.CertPEM, 0o644},
		{"intermediate-ca.key", intermediate.KeyPEM, 0o600},
		{ord.Domain + ".crt", leaf.CertPEM, 0o644},
		{ord.Domain + ".key", leaf.KeyPEM, 0o600},
		{"fullchain.pem", leaf.FullChainPEM, 0o644},
	}

	for _, file := range files {
		path := filepath.Join(*outDir, file.name)
		if err := certificate.WriteFile(path, file.data, file.perm); err != nil {
			log.Fatal(err)
		}
	}

	fmt.Printf("certificate issued successfully\n")
	fmt.Printf("order status: %s\n", ord.Status)
	fmt.Printf("output: %s\n", *outDir)
	fmt.Printf("chain verification: OK\n")
}
