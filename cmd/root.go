package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"prowler/internal/output"
)

var (
	outputDir string
	verbose   bool
	debug     bool
	verbosity int // computed: 0=quiet, 1=info, 2=debug
	timeout   int
	threads   int
)

var rootCmd = &cobra.Command{
	Use:           "prowler",
	Short:         "Prowler - OSINT Reconnaissance Toolkit",
	SilenceUsage:  true,
	SilenceErrors: true,
	Long: `Prowler - A comprehensive OSINT reconnaissance toolkit for authorized security assessments.

Performs domain enumeration, DNS analysis, SMTP probing, web app discovery,
cloud keyword generation, and document metadata extraction.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		output.PrintStartBanner()

		// Compute verbosity from flags
		if debug {
			verbosity = 2
		} else if verbose {
			verbosity = 1
		}

		zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

		if verbosity >= 2 {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		} else {
			zerolog.SetGlobalLevel(zerolog.Disabled)
		}

		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", "prowler_output", "Output directory for results")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Show informational output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Show debug output")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 30, "Default timeout for network operations (seconds)")
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "t", 20, "Max concurrent goroutines for parallel tasks")

	rootCmd.AddCommand(reconCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(fullCmd)

	rootCmd.CompletionOptions.DisableDefaultCmd = true
}
