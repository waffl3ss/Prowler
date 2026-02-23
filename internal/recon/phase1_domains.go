package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"prowler/internal/config"
	"prowler/internal/output"
	"prowler/internal/util"
	"prowler/pkg/models"
)

type Phase1 struct {
	cfg      *config.Config
	resolver *util.DNSResolver
	client   *http.Client
	results  *models.Phase1Results
}

func NewPhase1(cfg *config.Config, resolver *util.DNSResolver) *Phase1 {
	return &Phase1{
		cfg:      cfg,
		resolver: resolver,
		client:   util.NewHTTPClient(cfg.Timeout),
		results: &models.Phase1Results{
			Domains: make(map[string]*models.DomainInfo),
		},
	}
}

func (p *Phase1) Name() string { return "Domain Identification" }

func (p *Phase1) Run(ctx context.Context) (*models.Phase1Results, error) {
	output.PrintPhase(1, "DOMAIN IDENTIFICATION")

	discovered := make(map[string]bool)
	discovered[p.cfg.TargetDomain] = true

	// Certificate transparency
	ctDomains := p.certTransparency(ctx)
	for _, d := range ctDomains {
		discovered[d] = true
	}
	p.results.CTDomains = ctDomains
	log.Info().Int("count", len(ctDomains)).Msg("CT log domains found")

	// DNS enumeration
	dnsRecords, dnsDomains := p.dnsEnumeration(ctx)
	p.results.DNSRecords = dnsRecords
	for _, d := range dnsDomains {
		discovered[d] = true
	}
	log.Info().Int("records", len(dnsRecords)).Int("domains", len(dnsDomains)).Msg("DNS enumeration complete")

	// Subdomain bruteforce
	if !p.cfg.NoBruteforce {
		wordlist := LoadWordlist(p.cfg.WordlistPath)
		bruteDomains := p.subdomainBruteforce(ctx, wordlist)
		for _, d := range bruteDomains {
			discovered[d] = true
		}
		log.Info().Int("count", len(bruteDomains)).Msg("Subdomain bruteforce complete")
	}

	p.results.TotalDiscovered = len(discovered)
	log.Info().Int("total", len(discovered)).Msg("Total unique domains discovered")

	// Gather info for each domain
	p.gatherDomainInfo(ctx, discovered)

	// Print results
	if p.cfg.Verbosity >= 1 {
		output.PrintSection("PHASE 1 DETAILS")
		for domain, info := range p.results.Domains {
			fmt.Printf("   %s\n", domain)
			fmt.Printf("     IPs: %s\n", strings.Join(info.IPs, ", "))
			if len(info.Netblocks) > 0 {
				fmt.Printf("     Netblocks: %s\n", strings.Join(info.Netblocks, ", "))
			}
			fmt.Printf("     Registrar: %s\n", info.Registrar)
		}
	}
	output.PrintDetail("%d domains discovered (%d from CT, %d total unique)",
		len(p.results.Domains), len(ctDomains), p.results.TotalDiscovered)

	return p.results, nil
}

type ctEntry struct {
	NameValue string `json:"name_value"`
}

func (p *Phase1) certTransparency(ctx context.Context) []string {
	log.Info().Msg("Querying certificate transparency logs...")

	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", p.cfg.TargetDomain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.Debug().Err(err).Msg("CT request creation failed")
		return nil
	}

	resp, err := p.client.Do(req)
	if err != nil {
		log.Debug().Err(err).Msg("CT log query failed")
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Debug().Int("status", resp.StatusCode).Msg("CT log returned non-200")
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debug().Err(err).Msg("CT response read failed")
		return nil
	}

	var entries []ctEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		log.Debug().Err(err).Msg("CT JSON parse failed")
		return nil
	}

	seen := make(map[string]bool)
	var domains []string
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" || strings.HasPrefix(name, "*") {
				continue
			}
			if !seen[name] {
				seen[name] = true
				domains = append(domains, name)
			}
		}
	}
	return domains
}

func (p *Phase1) dnsEnumeration(ctx context.Context) ([]models.DNSRecord, []string) {
	log.Info().Msg("DNS enumeration...")

	var records []models.DNSRecord
	var domains []string
	baseParts := strings.Split(p.cfg.TargetDomain, ".")
	baseSuffix := strings.Join(baseParts[len(baseParts)-2:], ".")

	type queryResult struct {
		rtype  string
		values []string
	}

	types := map[string]func(string) ([]string, error){
		"A":     p.resolver.ResolveA,
		"AAAA":  p.resolver.ResolveAAAA,
		"CNAME": p.resolver.ResolveCNAME,
		"MX":    p.resolver.ResolveMX,
		"NS":    p.resolver.ResolveNS,
		"TXT":   p.resolver.ResolveTXT,
	}

	for rtype, fn := range types {
		values, err := fn(p.cfg.TargetDomain)
		if err != nil {
			log.Debug().Err(err).Str("type", rtype).Msg("DNS query failed")
			continue
		}
		for _, v := range values {
			records = append(records, models.DNSRecord{
				Domain:     p.cfg.TargetDomain,
				RecordType: rtype,
				Value:      v,
			})
			// Check if the value is an in-scope domain
			if strings.Contains(v, ".") && strings.HasSuffix(v, baseSuffix) {
				domains = append(domains, v)
			}
		}
	}

	return records, domains
}

func (p *Phase1) subdomainBruteforce(ctx context.Context, wordlist []string) []string {
	log.Info().Int("words", len(wordlist)).Msg("Bruteforcing subdomains...")

	var mu sync.Mutex
	var found []string

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(p.cfg.Threads)

	for _, word := range wordlist {
		word := word
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			fqdn := fmt.Sprintf("%s.%s", word, p.cfg.TargetDomain)
			ips, err := p.resolver.ResolveA(fqdn)
			if err == nil && len(ips) > 0 {
				mu.Lock()
				found = append(found, fqdn)
				mu.Unlock()
				log.Debug().Str("domain", fqdn).Msg("Subdomain found")
			}
			return nil
		})
	}

	_ = g.Wait()
	return found
}

func (p *Phase1) gatherDomainInfo(ctx context.Context, discovered map[string]bool) {
	log.Info().Int("count", len(discovered)).Msg("Gathering IP and registrar information...")

	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(p.cfg.Threads)

	for domain := range discovered {
		domain := domain
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			info := &models.DomainInfo{
				Domain:    domain,
				Registrar: "Unknown",
			}

			// Resolve IPs
			ips, err := p.resolver.ResolveA(domain)
			if err != nil || len(ips) == 0 {
				return nil // Skip domains that don't resolve
			}
			info.IPs = ips

			// Netblock lookup for first IP
			if cidrs, err := util.LookupNetblock(ips[0]); err == nil {
				info.Netblocks = cidrs
			}

			// WHOIS for base domain
			parts := strings.Split(domain, ".")
			if len(parts) >= 2 {
				baseDomain := strings.Join(parts[len(parts)-2:], ".")
				p.whoisLookup(baseDomain, info)
			}

			mu.Lock()
			p.results.Domains[domain] = info
			mu.Unlock()

			return nil
		})
	}

	_ = g.Wait()
}

func (p *Phase1) whoisLookup(domain string, info *models.DomainInfo) {
	raw, err := whois.Whois(domain)
	if err != nil {
		log.Debug().Err(err).Str("domain", domain).Msg("WHOIS failed")
		return
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		log.Debug().Err(err).Str("domain", domain).Msg("WHOIS parse failed")
		return
	}

	if parsed.Registrar.Name != "" {
		info.Registrar = parsed.Registrar.Name
	}
}

func init() {
	// Suppress the whois library's default timeout
	_ = time.Second
}
