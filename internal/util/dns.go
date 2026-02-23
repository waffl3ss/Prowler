package util

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DNSResolver struct {
	servers []string
	timeout time.Duration
}

func NewDNSResolver(servers string, timeout time.Duration) *DNSResolver {
	r := &DNSResolver{timeout: timeout}
	if servers != "" {
		for _, s := range strings.Split(servers, ",") {
			s = strings.TrimSpace(s)
			if !strings.Contains(s, ":") {
				s = s + ":53"
			}
			r.servers = append(r.servers, s)
		}
	} else {
		r.servers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	return r
}

func (r *DNSResolver) query(domain string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Timeout = r.timeout

	var lastErr error
	for _, server := range r.servers {
		resp, _, err := c.Exchange(m, server)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("all resolvers failed: %w", lastErr)
}

func (r *DNSResolver) ResolveA(domain string) ([]string, error) {
	return r.resolveAddrs(domain, dns.TypeA)
}

func (r *DNSResolver) ResolveAAAA(domain string) ([]string, error) {
	return r.resolveAddrs(domain, dns.TypeAAAA)
}

func (r *DNSResolver) resolveAddrs(domain string, qtype uint16) ([]string, error) {
	resp, err := r.query(domain, qtype)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			results = append(results, rr.A.String())
		case *dns.AAAA:
			results = append(results, rr.AAAA.String())
		}
	}
	return results, nil
}

func (r *DNSResolver) ResolveCNAME(domain string) ([]string, error) {
	resp, err := r.query(domain, dns.TypeCNAME)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, ans := range resp.Answer {
		if rr, ok := ans.(*dns.CNAME); ok {
			results = append(results, strings.TrimSuffix(rr.Target, "."))
		}
	}
	return results, nil
}

func (r *DNSResolver) ResolveMX(domain string) ([]string, error) {
	resp, err := r.query(domain, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, ans := range resp.Answer {
		if rr, ok := ans.(*dns.MX); ok {
			results = append(results, strings.TrimSuffix(rr.Mx, "."))
		}
	}
	return results, nil
}

func (r *DNSResolver) ResolveNS(domain string) ([]string, error) {
	resp, err := r.query(domain, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, ans := range resp.Answer {
		if rr, ok := ans.(*dns.NS); ok {
			results = append(results, strings.TrimSuffix(rr.Ns, "."))
		}
	}
	return results, nil
}

func (r *DNSResolver) ResolveTXT(domain string) ([]string, error) {
	resp, err := r.query(domain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, ans := range resp.Answer {
		if rr, ok := ans.(*dns.TXT); ok {
			results = append(results, strings.Join(rr.Txt, " "))
		}
	}
	return results, nil
}

func (r *DNSResolver) AttemptZoneTransfer(domain string, nsHost string) (bool, error) {
	// Resolve NS to IP first
	ips, err := r.ResolveA(nsHost)
	if err != nil || len(ips) == 0 {
		return false, fmt.Errorf("cannot resolve NS %s: %w", nsHost, err)
	}

	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	ch, err := t.In(m, ips[0]+":53")
	if err != nil {
		return false, nil
	}

	for env := range ch {
		if env.Error != nil {
			return false, nil
		}
		if len(env.RR) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (r *DNSResolver) Server() string {
	if len(r.servers) > 0 {
		return r.servers[0]
	}
	return "8.8.8.8:53"
}
