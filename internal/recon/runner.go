package recon

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"prowler/internal/config"
	"prowler/internal/output"
	"prowler/internal/util"
	"prowler/pkg/models"
)

type Runner struct {
	cfg    *config.Config
	writer *output.Writer
}

func NewRunner(cfg *config.Config) *Runner {
	return &Runner{
		cfg:    cfg,
		writer: output.NewWriter(cfg.OutputDir),
	}
}

func (r *Runner) Run(ctx context.Context) (*models.ReconResults, error) {
	results := &models.ReconResults{
		Target:    r.cfg.TargetDomain,
		StartedAt: time.Now(),
	}

	resolver := util.NewDNSResolver(r.cfg.Resolvers, r.cfg.Timeout)

	output.PrintInfo("PROWLER - RECONNAISSANCE")
	output.PrintDetail("Target: %s", r.cfg.TargetDomain)
	log.Info().Str("target", r.cfg.TargetDomain).Msg("Starting reconnaissance")

	// Phase 1: Domain Identification (always runs)
	phase1 := NewPhase1(r.cfg, resolver)
	p1Results, err := phase1.Run(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Phase 1 failed")
		return results, err
	}
	results.Phase1 = p1Results
	r.writer.WritePhase1(p1Results)

	// Get domain list for downstream phases
	var domains []string
	for domain := range p1Results.Domains {
		domains = append(domains, domain)
	}

	// Phase 2: Zone Transfers
	if !r.cfg.SkipPhase2 {
		phase2 := NewPhase2(r.cfg, resolver)
		p2Results, err := phase2.Run(ctx, domains)
		if err != nil {
			log.Error().Err(err).Msg("Phase 2 failed")
		} else {
			results.Phase2 = p2Results
			r.writer.WritePhase2(p2Results)
		}
	} else {
		output.PrintDetail("Skipping Phase 2: Zone Transfers")
	}

	// Phase 3: SMTP Enumeration
	if !r.cfg.SkipPhase3 {
		phase3 := NewPhase3(r.cfg, resolver)
		p3Results, err := phase3.Run(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Phase 3 failed")
		} else {
			results.Phase3 = p3Results
			r.writer.WritePhase3(p3Results)
		}
	} else {
		output.PrintDetail("Skipping Phase 3: SMTP Enumeration")
	}

	// Phase 4: Web Application Discovery
	if !r.cfg.SkipPhase4 {
		phase4 := NewPhase4(r.cfg)
		p4Results, err := phase4.Run(ctx, domains)
		if err != nil {
			log.Error().Err(err).Msg("Phase 4 failed")
		} else {
			results.Phase4 = p4Results
			r.writer.WritePhase4(p4Results)
		}
	} else {
		output.PrintDetail("Skipping Phase 4: Web Application Discovery")
	}

	// Phase 5: Cloud Enum Keywords
	if !r.cfg.SkipPhase5 {
		phase5 := NewPhase5(r.cfg)
		p5Results, err := phase5.Run(ctx, p1Results.Domains)
		if err != nil {
			log.Error().Err(err).Msg("Phase 5 failed")
		} else {
			results.Phase5 = p5Results
			r.writer.WritePhase5(p5Results)
		}
	} else {
		output.PrintDetail("Skipping Phase 5: Cloud Enum Keywords")
	}

	results.EndedAt = time.Now()

	// Write unified results.json
	r.writer.WriteResultsJSON(results)

	output.PrintInfo("RECONNAISSANCE COMPLETE")
	output.PrintDetail("Duration: %s", results.EndedAt.Sub(results.StartedAt).Round(time.Second))
	output.PrintDetail("Results saved to %s", r.cfg.OutputDir)

	return results, nil
}
