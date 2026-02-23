package config

import "time"

type Config struct {
	// Global
	TargetDomain string
	OutputDir    string
	Verbose      bool // deprecated, use Verbosity
	Verbosity    int  // 0=quiet, 1=info (-v), 2=debug (-vv)
	Timeout      time.Duration
	Threads      int

	// Recon
	SkipPhase2   bool
	SkipPhase3   bool
	SkipPhase4   bool
	SkipPhase5   bool
	WordlistPath string
	NoBruteforce bool
	Resolvers    string

	// Scanner
	Headed          bool
	DelayMin        int
	DelayMax        int
	NoGoogle        bool
	NoBing          bool
	NoDDG           bool
	MaxDownloads    int
	URLListPath     string
	MaxPages        int
	DownloadWorkers int
	NoExiftool      bool
}
