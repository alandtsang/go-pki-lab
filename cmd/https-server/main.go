package main

import (
	"flag"
	"log"

	"github.com/alandtsang/go-pki-lab/internal/tlsserver"
)

func main() {
	domain := flag.String("domain", "hello.test", "certificate DNS name")
	addr := flag.String("addr", "127.0.0.1:8443", "HTTPS listen address")
	certFile := flag.String("cert", "out/fullchain.pem", "leaf + intermediate certificate chain PEM")
	keyFile := flag.String("key", "out/hello.test.key", "leaf private key PEM")
	flag.Parse()

	server, err := tlsserver.NewHTTPServer(tlsserver.Config{
		Addr:     *addr,
		Domain:   *domain,
		CertFile: *certFile,
		KeyFile:  *keyFile,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("local HTTPS server listening on https://%s for %s", *addr, *domain)
	log.Printf("certificate chain: %s", *certFile)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}
