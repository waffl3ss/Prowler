package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"prowler/internal/config"
	"prowler/internal/output"
	"prowler/pkg/models"
)

var fileTypes = []string{"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"}

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

func (r *Runner) Run(ctx context.Context) (*models.ScanResults, error) {
	results := &models.ScanResults{
		Target:    r.cfg.TargetDomain,
		StartedAt: time.Now(),
		Phase6:    &models.Phase6Results{},
	}

	output.PrintInfo("PROWLER - DOCUMENT METADATA ENUMERATION")

	var documentURLs []string

	if r.cfg.URLListPath != "" {
		urls, err := loadURLList(r.cfg.URLListPath)
		if err != nil {
			return results, fmt.Errorf("failed to load URL list: %w", err)
		}
		documentURLs = urls
		output.PrintDetail("Loaded %d URLs from file", len(urls))
	} else {
		urls, err := r.searchForDocuments(ctx)
		if err != nil {
			return results, err
		}
		documentURLs = urls
	}

	if len(documentURLs) == 0 {
		output.PrintWarn("No documents found. Suggestions:")
		output.PrintSub("Run with --headed to solve CAPTCHAs manually")
		output.PrintSub("Increase --delay")
		output.PrintSub("Try a different IP / VPN")
		output.PrintSub("Manually collect URLs and use --url-list")
		results.EndedAt = time.Now()
		return results, nil
	}

	// Store discovered URLs
	for _, u := range documentURLs {
		results.Phase6.DocumentURLs = append(results.Phase6.DocumentURLs, models.DocumentURL{
			URL:      u,
			FileType: guessFileType(u),
		})
	}

	// Download
	output.PrintDetail("Downloading %d documents...", len(documentURLs))
	docsDir := filepath.Join(r.cfg.OutputDir, "documents")
	downloader := NewDownloader(docsDir, r.cfg.DownloadWorkers, r.cfg.MaxDownloads, r.cfg.Timeout)
	downloads := downloader.DownloadAll(documentURLs)
	results.Phase6.Downloads = downloads

	successCount := 0
	for _, dl := range downloads {
		if dl.Success {
			successCount++
		}
	}
	output.PrintDetail("Downloaded %d/%d documents", successCount, len(downloads))

	// Extract metadata
	output.PrintDetail("Extracting metadata...")
	analyzer := NewAnalyzer(r.cfg.NoExiftool)
	metadata := analyzer.ExtractAllMetadata(downloads)
	results.Phase6.Metadata = metadata

	// Analyze
	usernames := analyzer.ExtractUsernames(metadata)
	software := analyzer.ExtractSoftware(metadata)
	results.Phase6.UniqueUsernames = usernames
	results.Phase6.UniqueSoftware = software

	// Write phase 6 output files
	r.writer.WritePhase6(results.Phase6)

	// Print detailed results only with -v
	if r.cfg.Verbosity >= 1 {
		analyzer.PrintResults(metadata)
		analyzer.PrintSummaryTable(metadata)
		analyzer.PrintIntelSummary(metadata, usernames, software)
	} else {
		analyzer.PrintIntelStats(metadata, usernames, software)
	}

	results.EndedAt = time.Now()
	return results, nil
}

func (r *Runner) searchForDocuments(ctx context.Context) ([]string, error) {
	// In headed mode, pause so user can be ready for CAPTCHAs before launching browser
	if r.cfg.Headed {
		fmt.Print("-- Press ENTER when ready to launch browser (you will solve CAPTCHAs in it)...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}

	browser, err := NewBrowser(r.cfg.Headed)
	if err != nil {
		return nil, fmt.Errorf("failed to launch browser: %w", err)
	}
	defer browser.Close()

	captcha := NewCAPTCHAChecker(browser)

	// Build search engines list
	type searcher interface {
		Name() string
		Search(ctx context.Context, dork string) ([]string, error)
	}

	var engines []searcher
	var engineNames []string
	if !r.cfg.NoGoogle {
		engines = append(engines, NewGoogleSearcher(browser, captcha, r.cfg.TargetDomain, r.cfg.Headed, r.cfg.MaxPages))
		engineNames = append(engineNames, "Google")
	}
	if !r.cfg.NoBing {
		engines = append(engines, NewBingSearcher(browser, captcha, r.cfg.TargetDomain, r.cfg.Headed, r.cfg.MaxPages))
		engineNames = append(engineNames, "Bing")
	}
	if !r.cfg.NoDDG {
		engines = append(engines, NewDDGSearcher(browser, captcha, r.cfg.TargetDomain, r.cfg.Headed, r.cfg.MaxPages))
		engineNames = append(engineNames, "DDG")
	}

	if len(engines) == 0 {
		return nil, fmt.Errorf("no search engines enabled")
	}

	// Build dorks
	var dorks []string
	for _, ft := range fileTypes {
		dorks = append(dorks, fmt.Sprintf("site:%s filetype:%s", r.cfg.TargetDomain, ft))
	}

	output.PrintDetail("Engines: %s", strings.Join(engineNames, ", "))
	output.PrintDetail("Searching %d file types across %d engines (%d queries)",
		len(fileTypes), len(engines), len(dorks)*len(engines))

	log.Info().
		Int("engines", len(engines)).
		Int("dorks", len(dorks)).
		Msg("Starting document search")

	seen := make(map[string]bool)
	var allURLs []string
	consecutiveErrors := 0

	for idx, dork := range dorks {
		if r.cfg.Verbosity >= 1 {
			fmt.Printf("   [%d/%d] %s\n", idx+1, len(dorks), dork)
		}

		for _, engine := range engines {
			select {
			case <-ctx.Done():
				return allURLs, ctx.Err()
			default:
			}

			// If browser has crashed, stop early
			if consecutiveErrors >= 3 && !browser.IsAlive() {
				output.PrintWarn("Browser process died - cannot continue searching")
				output.PrintDetail("Try: ./prowler scan --url-list <file> to skip browser search")
				return allURLs, nil
			}

			if r.cfg.Verbosity >= 1 {
				fmt.Printf("     -> %s... ", engine.Name())
			}

			urls, err := engine.Search(ctx, dork)
			if err != nil {
				if r.cfg.Verbosity >= 1 {
					fmt.Printf("error: %v\n", err)
				}
				log.Error().Err(err).Str("engine", engine.Name()).Msg("Search failed")
				consecutiveErrors++
				continue
			}
			consecutiveErrors = 0

			newCount := 0
			for _, u := range urls {
				if !seen[u] {
					seen[u] = true
					allURLs = append(allURLs, u)
					newCount++
				}
			}
			if r.cfg.Verbosity >= 1 {
				fmt.Printf("%d results (%d new)\n", len(urls), newCount)
			}

			// Short delay between engines
			delayBetweenEngines := r.cfg.DelayMin / 3
			if delayBetweenEngines < 1 {
				delayBetweenEngines = 1
			}
			time.Sleep(time.Duration(delayBetweenEngines) * time.Second)
		}

		// Longer delay between dorks
		if idx < len(dorks)-1 {
			delay := r.cfg.DelayMin + (r.cfg.DelayMax-r.cfg.DelayMin)/2
			if r.cfg.Verbosity >= 1 {
				fmt.Printf("     waiting %ds...\n", delay)
			}
			time.Sleep(time.Duration(delay) * time.Second)
		}
	}

	output.PrintDetail("Found %d unique document URLs", len(allURLs))
	return allURLs, nil
}

func loadURLList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	return urls, scanner.Err()
}

func guessFileType(url string) string {
	lower := strings.ToLower(url)
	for _, ext := range docExtensions {
		if strings.Contains(lower, ext) {
			return strings.TrimPrefix(ext, ".")
		}
	}
	return "unknown"
}
