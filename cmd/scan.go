package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"prowler/internal/config"
	"prowler/internal/output"
	"prowler/internal/scanner"
)

var (
	headed          bool
	delay           int
	delayMax        int
	noGoogle        bool
	noBing          bool
	noDDG           bool
	maxDownloads    int
	urlListPath     string
	maxPages        int
	downloadWorkers int
	noExiftool      bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [domain]",
	Short: "Run document metadata extraction (phase 6)",
	Long: `Searches Google, Bing, and DuckDuckGo for documents associated with a domain,
downloads them, and extracts metadata (authors, software, dates).

Uses a real browser via Chrome DevTools Protocol to bypass bot detection.
Use --headed mode to solve CAPTCHAs manually.`,
	Args: cobra.MaximumNArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Pre-flight Chrome check before any work begins
		return scanner.PreflightCheck(headed)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 && urlListPath == "" {
			return fmt.Errorf("provide a domain or --url-list")
		}

		domain := ""
		if len(args) > 0 {
			domain = args[0]
		}

		cfg := &config.Config{
			TargetDomain:    domain,
			OutputDir:       outputDir,
			Verbosity:       verbosity,
			Timeout:         time.Duration(timeout) * time.Second,
			Threads:         threads,
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

		runner := scanner.NewRunner(cfg)
		results, err := runner.Run(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Scan failed")
			return err
		}

		writer := output.NewWriter(cfg.OutputDir)
		if err := writer.WriteScan(results); err != nil {
			log.Error().Err(err).Msg("Failed to write output")
			return err
		}

		output.PrintInfo("ENUMERATION COMPLETE")
		output.PrintDetail("Results saved to %s", cfg.OutputDir)
		return nil
	},
}

func init() {
	scanCmd.Flags().BoolVar(&headed, "headed", false, "Launch visible browser for manual CAPTCHA solving")
	scanCmd.Flags().IntVarP(&delay, "delay", "d", 10, "Minimum delay between search queries (seconds)")
	scanCmd.Flags().IntVar(&delayMax, "delay-max", 15, "Maximum delay between search queries (seconds)")
	scanCmd.Flags().BoolVar(&noGoogle, "no-google", false, "Skip Google search engine")
	scanCmd.Flags().BoolVar(&noBing, "no-bing", false, "Skip Bing search engine")
	scanCmd.Flags().BoolVar(&noDDG, "no-ddg", false, "Skip DuckDuckGo search engine")
	scanCmd.Flags().IntVar(&maxDownloads, "max-downloads", 100, "Maximum documents to download")
	scanCmd.Flags().StringVarP(&urlListPath, "url-list", "u", "", "File with URLs to download directly (skips search)")
	scanCmd.Flags().IntVar(&maxPages, "max-pages", 2, "Max search result pages per dork per engine")
	scanCmd.Flags().IntVar(&downloadWorkers, "download-workers", 5, "Concurrent download goroutines")
	scanCmd.Flags().BoolVar(&noExiftool, "no-exiftool", false, "Disable exiftool even if available")
}
