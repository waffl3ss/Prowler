package recon

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"prowler/internal/config"
	"prowler/internal/output"
	"prowler/internal/util"
	"prowler/pkg/models"
)

type Phase2 struct {
	cfg      *config.Config
	resolver *util.DNSResolver
}

func NewPhase2(cfg *config.Config, resolver *util.DNSResolver) *Phase2 {
	return &Phase2{cfg: cfg, resolver: resolver}
}

func (p *Phase2) Name() string { return "DNS Zone Transfer Checks" }

func (p *Phase2) Run(ctx context.Context, domains []string) (*models.Phase2Results, error) {
	output.PrintPhase(2, "DNS ZONE TRANSFER CHECKS")

	results := &models.Phase2Results{}

	// Collect unique base domains to check
	toCheck := make(map[string]bool)
	for _, domain := range domains {
		toCheck[domain] = true
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			base := strings.Join(parts[len(parts)-2:], ".")
			toCheck[base] = true
		}
	}

	log.Info().Int("count", len(toCheck)).Msg("Checking zone transfers")

	for domain := range toCheck {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		log.Info().Str("domain", domain).Msg("Checking zone transfers")

		nameservers, err := p.resolver.ResolveNS(domain)
		if err != nil || len(nameservers) == 0 {
			log.Debug().Str("domain", domain).Msg("No nameservers found")
			continue
		}

		ztResult := models.ZoneTransferResult{
			Domain:      domain,
			Nameservers: make(map[string]string),
		}

		for _, ns := range nameservers {
			allowed, err := p.resolver.AttemptZoneTransfer(domain, ns)
			if err != nil {
				log.Debug().Err(err).Str("ns", ns).Msg("Zone transfer error")
				ztResult.Nameservers[ns] = "ERROR"
				continue
			}
			if allowed {
				ztResult.Nameservers[ns] = "ALLOWED"
				log.Warn().Str("domain", domain).Str("ns", ns).Msg("Zone transfer ALLOWED!")
			} else {
				ztResult.Nameservers[ns] = "PROHIBITED"
			}
		}

		results.Results = append(results.Results, ztResult)
	}

	// Count allowed transfers
	allowed := 0
	for _, zt := range results.Results {
		for _, status := range zt.Nameservers {
			if status == "ALLOWED" {
				allowed++
			}
		}
	}

	// Print results
	if p.cfg.Verbosity >= 1 {
		output.PrintSection("PHASE 2 DETAILS")
		if len(results.Results) == 0 {
			fmt.Println("   No nameservers found for any domains.")
		} else {
			for _, zt := range results.Results {
				fmt.Printf("   %s\n", zt.Domain)
				for ns, status := range zt.Nameservers {
					fmt.Printf("     %s: %s\n", ns, status)
				}
			}
		}
	}
	output.PrintDetail("%d domains checked, %d zone transfers allowed",
		len(results.Results), allowed)

	return results, nil
}
