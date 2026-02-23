package scanner

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"prowler/internal/output"
	"prowler/pkg/models"
)

type Analyzer struct {
	noExiftool bool
}

func NewAnalyzer(noExiftool bool) *Analyzer {
	return &Analyzer{noExiftool: noExiftool}
}

func (a *Analyzer) ExtractAllMetadata(downloads []models.DownloadResult) []models.DocumentMetadata {
	var results []models.DocumentMetadata

	for _, dl := range downloads {
		if !dl.Success {
			continue
		}

		log.Info().Str("file", filepath.Base(dl.LocalPath)).Msg("Extracting metadata")

		meta := a.extractMetadata(dl.LocalPath)

		results = append(results, models.DocumentMetadata{
			SourceURL:   dl.URL,
			LocalPath:   dl.LocalPath,
			FileHash:    dl.FileHash,
			FileType:    strings.ToUpper(strings.TrimPrefix(filepath.Ext(dl.LocalPath), ".")),
			Metadata:    meta,
			ExtractedAt: time.Now(),
		})
	}

	log.Info().Int("count", len(results)).Msg("Metadata extraction complete")
	return results
}

func (a *Analyzer) extractMetadata(filepath string) map[string]string {
	meta := make(map[string]string)

	// Try exiftool first if available
	if !a.noExiftool && HasExiftool() {
		meta = ExtractWithExiftool(filepath)
		if len(meta) > 0 {
			return meta
		}
	}

	// Native extraction based on file type
	ext := strings.ToLower(strings.TrimPrefix(filepath[strings.LastIndex(filepath, "."):], "."))

	switch ext {
	case "pdf":
		meta = ExtractPDFMetadata(filepath)
	case "docx", "doc", "xlsx", "xls", "pptx", "ppt":
		meta = ExtractOOXMLMetadata(filepath)
	}

	return meta
}

// softwareIndicators are substrings that identify a value as software, not a username.
var softwareIndicators = []string{
	"adobe", "microsoft", "libreoffice", "openoffice", "canva",
	"google", "apple", "acrobat", "pdf library", "writer",
	"illustrator", "indesign", "photoshop", "powerpoint",
	"excel", "word", "keynote", "pages", "numbers",
	"latex", "tex", "quark", "corel", "inkscape", "gimp",
	"figma", "sketch", "affinity",
}

func isSoftwareName(name string) bool {
	lower := strings.ToLower(name)
	for _, ind := range softwareIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func (a *Analyzer) ExtractUsernames(metadata []models.DocumentMetadata) []string {
	names := make(map[string]bool)
	fields := []string{"Author", "LastModifiedBy", "Manager"}

	for _, doc := range metadata {
		for _, f := range fields {
			if v, ok := doc.Metadata[f]; ok && v != "" && v != "Unknown" {
				// Strip email domain if present
				name := v
				if idx := strings.Index(name, "@"); idx != -1 {
					name = name[:idx]
				}
				name = strings.TrimSpace(name)
				if name != "" && !isSoftwareName(name) {
					names[name] = true
				}
			}
		}
	}

	var result []string
	for n := range names {
		result = append(result, n)
	}
	sort.Strings(result)
	return result
}

func (a *Analyzer) ExtractSoftware(metadata []models.DocumentMetadata) []string {
	sw := make(map[string]bool)
	fields := []string{"Software", "Producer", "CreatorTool", "Application"}

	for _, doc := range metadata {
		for _, f := range fields {
			if v, ok := doc.Metadata[f]; ok && v != "" {
				sw[strings.TrimSpace(v)] = true
			}
		}
	}

	var result []string
	for s := range sw {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

func (a *Analyzer) PrintResults(metadata []models.DocumentMetadata) {
	output.PrintSection("METADATA EXTRACTION RESULTS")

	for idx, doc := range metadata {
		fmt.Printf("   [%d] %s\n", idx+1, filepath.Base(doc.LocalPath))
		fmt.Printf("     Source: %s\n", doc.SourceURL)
		fmt.Printf("     Type: %s  Hash: %s\n", doc.FileType, doc.FileHash)
		if len(doc.Metadata) > 0 {
			for k, v := range doc.Metadata {
				if len(v) > 100 {
					v = v[:100]
				}
				fmt.Printf("     %s: %s\n", k, v)
			}
		} else {
			fmt.Println("     No metadata found")
		}
	}
}

func (a *Analyzer) PrintSummaryTable(metadata []models.DocumentMetadata) {
	output.PrintSection("METADATA SUMMARY TABLE")

	output.PrintTableHeader("   %-40s %-8s %-25s %-30s", "Source", "Type", "Author/Creator", "Software/Tool")

	for _, doc := range metadata {
		src := filepath.Base(doc.SourceURL)
		if len(src) > 39 {
			src = src[:39]
		}
		ft := doc.FileType
		if len(ft) > 7 {
			ft = ft[:7]
		}

		auth := doc.Metadata["Author"]
		if auth == "" {
			auth = doc.Metadata["Creator"]
		}
		if auth == "" {
			auth = doc.Metadata["LastModifiedBy"]
		}
		if auth == "" {
			auth = "Unknown"
		}
		if len(auth) > 24 {
			auth = auth[:24]
		}

		sw := doc.Metadata["Software"]
		if sw == "" {
			sw = doc.Metadata["Producer"]
		}
		if sw == "" {
			sw = doc.Metadata["CreatorTool"]
		}
		if sw == "" {
			sw = doc.Metadata["Application"]
		}
		if sw == "" {
			sw = "Unknown"
		}
		if len(sw) > 29 {
			sw = sw[:29]
		}

		fmt.Printf("   %-40s %-8s %-25s %-30s\n", src, ft, auth, sw)
	}
}

func (a *Analyzer) PrintIntelStats(metadata []models.DocumentMetadata, usernames, software []string) {
	fmt.Println()
	output.PrintDetail("Documents Analyzed:  %d", len(metadata))
	output.PrintDetail("Unique Usernames:    %d", len(usernames))
	output.PrintDetail("Software Identified: %d", len(software))
}

func (a *Analyzer) PrintIntelSummary(metadata []models.DocumentMetadata, usernames, software []string) {
	output.PrintSection("INTELLIGENCE SUMMARY")

	output.PrintDetail("Documents Analyzed: %d", len(metadata))

	fmt.Printf("\n-- Unique Usernames: %d\n", len(usernames))
	for _, u := range usernames {
		output.PrintSub("%s", u)
	}

	fmt.Printf("\n-- Software Identified: %d\n", len(software))
	for _, s := range software {
		output.PrintSub("%s", s)
	}
}
