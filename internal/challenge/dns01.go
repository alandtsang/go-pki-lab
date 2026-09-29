package challenge

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

type DNS01 struct {
	Domain string
	Name   string
	Token  string
}

func NewDNS01(domain string) (*DNS01, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain must not be empty")
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate challenge token: %w", err)
	}

	return &DNS01{
		Domain: domain,
		Name:   "_acme-challenge." + strings.TrimSuffix(domain, "."),
		Token:  base64.RawURLEncoding.EncodeToString(buf),
	}, nil
}

func (c *DNS01) Verify(serverAddr string) error {
	if c == nil {
		return fmt.Errorf("challenge is required")
	}

	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(c.Name), mdns.TypeTXT)

	client := &mdns.Client{Timeout: 2 * time.Second}
	resp, _, err := client.Exchange(msg, serverAddr)
	if err != nil {
		return fmt.Errorf("query TXT %s from %s: %w", c.Name, serverAddr, err)
	}
	if resp == nil {
		return fmt.Errorf("empty DNS response")
	}

	for _, answer := range resp.Answer {
		txt, ok := answer.(*mdns.TXT)
		if !ok {
			continue
		}
		for _, value := range txt.Txt {
			if value == c.Token {
				return nil
			}
		}
	}

	return fmt.Errorf("DNS-01 validation failed: expected TXT %q at %s", c.Token, c.Name)
}
