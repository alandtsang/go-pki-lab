package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/alandtsang/go-pki-lab/internal/csr"
)

func main() {
	domain := flag.String("domain", "hello.test", "DNS name to include in the CSR")
	outDir := flag.String("out", "client", "directory for client key and CSR")
	flag.Parse()

	req, err := csr.Generate(*domain)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}

	keyPath := filepath.Join(*outDir, *domain+".key")
	csrPath := filepath.Join(*outDir, *domain+".csr")
	if err := os.WriteFile(keyPath, req.KeyPEM, 0o600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(csrPath, req.CSRPEM, 0o644); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("client private key: %s\n", keyPath)
	fmt.Printf("certificate request: %s\n", csrPath)
	fmt.Printf("private key stays on the client side\n")
}
