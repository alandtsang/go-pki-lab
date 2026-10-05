package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9090", "webhook receiver listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /alerts", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read request", http.StatusBadRequest)
			return
		}
		log.Printf("webhook received: %s", body)
		w.WriteHeader(http.StatusNoContent)
	})

	server := &http.Server{Addr: *addr, Handler: mux}
	fmt.Printf("webhook receiver: http://%s/alerts\n", *addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
