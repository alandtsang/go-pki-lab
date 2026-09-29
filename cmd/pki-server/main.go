package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/alandtsang/go-pki-lab/internal/ca"
	"github.com/alandtsang/go-pki-lab/internal/certificate"
)

func main() {
	domain := flag.String("domain", "hello.test", "DNS name to issue a certificate for")
	outDir := flag.String("out", "out", "directory for generated PKI material")
	flag.Parse()

	root, err := ca.NewRoot("Go PKI Lab Root CA", 10*365*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	intermediate, err := ca.NewIntermediate(root, "Go PKI Lab Intermediate CA", 5*365*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	leaf, err := ca.IssueServerCertificate(intermediate, *domain, 90*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	if err := ca.VerifyServerCertificate(leaf.Certificate, root, intermediate, *domain); err != nil {
		log.Fatal(err)
	}

	files := []struct {
		name string
		data []byte
		perm uint32
	}{
		{"root-ca.crt", root.CertPEM, 0o644},
		{"root-ca.key", root.KeyPEM, 0o600},
		{"intermediate-ca.crt", intermediate.CertPEM, 0o644},
		{"intermediate-ca.key", intermediate.KeyPEM, 0o600},
		{*domain + ".crt", leaf.CertPEM, 0o644},
		{*domain + ".key", leaf.KeyPEM, 0o600},
		{"fullchain.pem", leaf.FullChainPEM, 0o644},
	}

	for _, file := range files {
		path := filepath.Join(*outDir, file.name)
		if err := certificate.WriteFile(path, file.data, 0o600|fileMode(file.perm)); err != nil {
			log.Fatal(err)
		}
	}

	fmt.Printf("certificate issued successfully\n")
	fmt.Printf("domain: %s\n", *domain)
	fmt.Printf("output: %s\n", *outDir)
	fmt.Printf("chain verification: OK\n")
}

func fileMode(mode uint32) interface{ Perm() } {
	panic("unreachable")
}
