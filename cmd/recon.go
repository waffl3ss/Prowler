package cmd

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"prowler/internal/config"
	"prowler/internal/recon"
)

var (
	skipPhase2   bool
	skipPhase3   bool
	skipPhase4   bool
	skipPhase5   bool
	wordlistPath string
	noBruteforce bool
	resolvers    string
)

var reconCmd = &cobra.Command{
	Use:   "recon [domain]",
	Short: "Run reconnaissance phases 1-5",
	Long: `Performs domain identification, DNS zone transfer checks, SMTP enumeration,
web application discovery, and cloud enum keyword generation.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := &config.Config{
			TargetDomain: args[0],
			OutputDir:    outputDir,
			Verbosity:    verbosity,
			Timeout:      time.Duration(timeout) * time.Second,
			Threads:      threads,
			SkipPhase2:   skipPhase2,
			SkipPhase3:   skipPhase3,
			SkipPhase4:   skipPhase4,
			SkipPhase5:   skipPhase5,
			WordlistPath: wordlistPath,
			NoBruteforce: noBruteforce,
			Resolvers:    resolvers,
		}

		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		runner := recon.NewRunner(cfg)
		_, err := runner.Run(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Recon failed")
			return err
		}

		return nil
	},
}

func init() {
	reconCmd.Flags().BoolVar(&skipPhase2, "skip-phase2", false, "Skip DNS zone transfer checks")
	reconCmd.Flags().BoolVar(&skipPhase3, "skip-phase3", false, "Skip SMTP enumeration")
	reconCmd.Flags().BoolVar(&skipPhase4, "skip-phase4", false, "Skip web application discovery")
	reconCmd.Flags().BoolVar(&skipPhase5, "skip-phase5", false, "Skip cloud enum keyword generation")
	reconCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Path to subdomain wordlist (default: built-in 184-word list)")
	reconCmd.Flags().BoolVar(&noBruteforce, "no-bruteforce", false, "Skip subdomain bruteforcing")
	reconCmd.Flags().StringVar(&resolvers, "resolvers", "", "Comma-separated custom DNS resolvers")
}
