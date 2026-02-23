package cmd

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"prowler/internal/config"
	"prowler/internal/output"
	"prowler/internal/recon"
	"prowler/internal/scanner"
	"prowler/pkg/models"
)

var fullCmd = &cobra.Command{
	Use:   "full [domain]",
	Short: "Run all phases (recon + scan)",
	Long: `Runs the complete OSINT pipeline: domain reconnaissance (phases 1-5)
followed by document metadata extraction (phase 6).`,
	Args: cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Pre-flight Chrome check before any work begins
		return scanner.PreflightCheck(headed)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := &config.Config{
			TargetDomain:    args[0],
			OutputDir:       outputDir,
			Verbosity:       verbosity,
			Timeout:         time.Duration(timeout) * time.Second,
			Threads:         threads,
			SkipPhase2:      skipPhase2,
			SkipPhase3:      skipPhase3,
			SkipPhase4:      skipPhase4,
			SkipPhase5:      skipPhase5,
			WordlistPath:    wordlistPath,
			NoBruteforce:    noBruteforce,
			Resolvers:       resolvers,
			Headed:          headed,
			DelayMin:        delay,
			DelayMax:        delayMax,
			NoGoogle:        noGoogle,
			NoBing:          noBing,
			NoDDG:           noDDG,
			MaxDownloads:    maxDownloads,
			URLListPath:     urlListPath,
			MaxPages:        maxPages,
			DownloadWorkers: downloadWorkers,
			NoExiftool:      noExiftool,
		}

		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		fullResults := &models.FullResults{
			Target:    cfg.TargetDomain,
			StartedAt: time.Now(),
		}

		// Phase 1-5: Recon
		reconRunner := recon.NewRunner(cfg)
		reconResults, err := reconRunner.Run(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Recon failed")
			return err
		}
		fullResults.Recon = reconResults

		// Phase 6: Document metadata scan
		scanRunner := scanner.NewRunner(cfg)
		scanResults, err := scanRunner.Run(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Scan failed")
			return err
		}
		fullResults.Scan = scanResults

		fullResults.EndedAt = time.Now()

		// Write unified results.json
		writer := output.NewWriter(cfg.OutputDir)
		writer.WriteResultsJSON(fullResults)

		output.PrintInfo("PROWLER COMPLETE")
		output.PrintDetail("All results saved to %s", cfg.OutputDir)
		return nil
	},
}

func init() {
	// Recon flags
	fullCmd.Flags().BoolVar(&skipPhase2, "skip-phase2", false, "Skip DNS zone transfer checks")
	fullCmd.Flags().BoolVar(&skipPhase3, "skip-phase3", false, "Skip SMTP enumeration")
	fullCmd.Flags().BoolVar(&skipPhase4, "skip-phase4", false, "Skip web application discovery")
	fullCmd.Flags().BoolVar(&skipPhase5, "skip-phase5", false, "Skip cloud enum keyword generation")
	fullCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Path to subdomain wordlist (default: built-in 184-word list)")
	fullCmd.Flags().BoolVar(&noBruteforce, "no-bruteforce", false, "Skip subdomain bruteforcing")
	fullCmd.Flags().StringVar(&resolvers, "resolvers", "", "Comma-separated custom DNS resolvers")

	// Scan flags
	fullCmd.Flags().BoolVar(&headed, "headed", false, "Launch visible browser for manual CAPTCHA solving")
	fullCmd.Flags().IntVarP(&delay, "delay", "d", 10, "Minimum delay between search queries (seconds)")
	fullCmd.Flags().IntVar(&delayMax, "delay-max", 15, "Maximum delay between search queries (seconds)")
	fullCmd.Flags().BoolVar(&noGoogle, "no-google", false, "Skip Google search engine")
	fullCmd.Flags().BoolVar(&noBing, "no-bing", false, "Skip Bing search engine")
	fullCmd.Flags().BoolVar(&noDDG, "no-ddg", false, "Skip DuckDuckGo search engine")
	fullCmd.Flags().IntVar(&maxDownloads, "max-downloads", 100, "Maximum documents to download")
	fullCmd.Flags().StringVarP(&urlListPath, "url-list", "u", "", "File with URLs to download directly (skips search)")
	fullCmd.Flags().IntVar(&maxPages, "max-pages", 2, "Max search result pages per dork per engine")
	fullCmd.Flags().IntVar(&downloadWorkers, "download-workers", 5, "Concurrent download goroutines")
	fullCmd.Flags().BoolVar(&noExiftool, "no-exiftool", false, "Disable exiftool even if available")
}
