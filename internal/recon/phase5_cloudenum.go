package recon

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"prowler/internal/config"
	"prowler/internal/output"
	"prowler/pkg/models"
)

type Phase5 struct {
	cfg *config.Config
}

func NewPhase5(cfg *config.Config) *Phase5 {
	return &Phase5{cfg: cfg}
}

func (p *Phase5) Name() string { return "Cloud Enum Keyword Generation" }

func (p *Phase5) Run(ctx context.Context, domainInfo map[string]*models.DomainInfo) (*models.Phase5Results, error) {
	output.PrintPhase(5, "CLOUD ENUM KEYWORD GENERATION")

	keywords := make(map[string]bool)

	// Extract base domain parts
	stripped := p.cfg.TargetDomain
	for _, tld := range []string{".com", ".org", ".net", ".io", ".co", ".info", ".biz", ".us", ".edu", ".gov"} {
		stripped = strings.TrimSuffix(stripped, tld)
	}

	parts := strings.Split(stripped, ".")
	for _, part := range parts {
		if len(part) > 2 {
			keywords[part] = true
			keywords[strings.ReplaceAll(part, "-", "")] = true
			keywords[strings.ReplaceAll(part, "_", "")] = true
		}
	}

	// Company name variations with common suffixes
	companyName := parts[0]
	if companyName != "" {
		keywords[companyName] = true

		suffixes := []string{
			"prod", "dev", "test", "staging", "backup",
			"files", "data", "storage", "assets", "static",
			"cdn", "app", "api", "web", "mail",
			"docs", "internal", "private", "public",
		}
		for _, suffix := range suffixes {
			keywords[companyName+suffix] = true
			keywords[companyName+"-"+suffix] = true
		}
	}

	// Subdomain-based keywords
	for domain := range domainInfo {
		subdomain := strings.TrimSuffix(domain, "."+p.cfg.TargetDomain)
		if subdomain != domain && subdomain != "" {
			keywords[strings.ReplaceAll(subdomain, ".", "-")] = true
			keywords[strings.ReplaceAll(subdomain, ".", "")] = true
		}
	}

	// Convert to sorted slice
	var keywordList []string
	for kw := range keywords {
		keywordList = append(keywordList, kw)
	}
	sort.Strings(keywordList)

	results := &models.Phase5Results{Keywords: keywordList}

	// Print results
	if p.cfg.Verbosity >= 1 {
		output.PrintSection("PHASE 5 DETAILS")
		for _, kw := range keywordList {
			fmt.Printf("   %s\n", kw)
		}
		fmt.Println("   Usage: cloud_enum -k <keyword> -l keywords.txt")
	}
	output.PrintDetail("%d cloud keywords generated", len(keywordList))

	log.Info().Int("count", len(keywordList)).Msg("Keywords generated")

	return results, nil
}
