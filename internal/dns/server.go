package dns

import (
	"fmt"
	"net"
	"strings"
	"sync"

	mdns "github.com/miekg/dns"
)

// Store is an in-memory DNS record store used by the local test server.
type Store struct {
	mu  sync.RWMutex
	txt map[string][]string
}

func NewStore() *Store {
	return &Store{txt: make(map[string][]string)}
}

func normalizeName(name string) string {
	return strings.ToLower(mdns.Fqdn(strings.TrimSpace(name)))
}

func (s *Store) SetTXT(name string, values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValues := append([]string(nil), values...)
	s.txt[normalizeName(name)] = copyValues
}

func (s *Store) DeleteTXT(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.txt, normalizeName(name))
}

func (s *Store) TXT(name string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.txt[normalizeName(name)]...)
}

// LocalServer is an authoritative UDP DNS server backed by Store.
type LocalServer struct {
	store  *Store
	server *mdns.Server
	conn   net.PacketConn
	addr   string
}

func StartLocalServer(addr string, store *Store) (*LocalServer, error) {
	if store == nil {
		return nil, fmt.Errorf("dns store is required")
	}

	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen dns udp %s: %w", addr, err)
	}

	mux := mdns.NewServeMux()
	mux.HandleFunc(".", func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true

		if len(req.Question) != 1 {
			resp.Rcode = mdns.RcodeFormatError
			_ = w.WriteMsg(resp)
			return
		}

		q := req.Question[0]
		if q.Qtype == mdns.TypeTXT {
			for _, value := range store.TXT(q.Name) {
				resp.Answer = append(resp.Answer, &mdns.TXT{
					Hdr: mdns.RR_Header{
						Name:   mdns.Fqdn(q.Name),
						Rrtype: mdns.TypeTXT,
						Class:  mdns.ClassINET,
						Ttl:    30,
					},
					Txt: []string{value},
				})
			}
		}

		_ = w.WriteMsg(resp)
	})

	server := &mdns.Server{PacketConn: conn, Handler: mux}
	local := &LocalServer{store: store, server: server, conn: conn, addr: conn.LocalAddr().String()}
	go func() {
		_ = server.ActivateAndServe()
	}()
	return local, nil
}

func (s *LocalServer) Addr() string {
	return s.addr
}

func (s *LocalServer) Shutdown() error {
	if s == nil || s.server == nil {
		return nil
	}
	return s.server.Shutdown()
}
