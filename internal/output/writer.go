package output

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"prowler/pkg/models"
)

type Writer struct {
	outputDir string
	json      *JSONWriter
	txt       *TXTWriter
	csv       *CSVWriter
}

func NewWriter(outputDir string) *Writer {
	os.MkdirAll(outputDir, 0755)
	return &Writer{
		outputDir: outputDir,
		json:      NewJSONWriter(outputDir),
		txt:       NewTXTWriter(outputDir),
		csv:       NewCSVWriter(outputDir),
	}
}

// WriteResultsJSON writes the unified results.json (called at end).
func (w *Writer) WriteResultsJSON(data interface{}) {
	w.json.Write("results.json", data)
}

// --- Per-phase writers (called incrementally as each phase completes) ---

func (w *Writer) WritePhase1(p1 *models.Phase1Results) {
	if p1 == nil {
		return
	}
	w.json.Write("phase1_domains.json", p1)

	var domainLines []string
	var csvRows [][]string
	for domain, info := range p1.Domains {
		domainLines = append(domainLines, domain)
		csvRows = append(csvRows, []string{
			domain,
			strings.Join(info.IPs, "; "),
			info.Registrar,
			strings.Join(info.Netblocks, "; "),
		})
	}
	sort.Strings(domainLines)
	w.txt.WriteLines("phase1_domains.txt", domainLines)
	w.csv.Write("phase1_domains.csv",
		[]string{"Domain", "IPs", "Registrar", "Netblocks"},
		csvRows)
	log.Info().Str("dir", w.outputDir).Msg("Phase 1 output written")
}

func (w *Writer) WritePhase2(p2 *models.Phase2Results) {
	if p2 == nil {
		return
	}
	w.json.Write("phase2_zone_transfers.json", p2)
	log.Info().Str("dir", w.outputDir).Msg("Phase 2 output written")
}

func (w *Writer) WritePhase3(p3 *models.Phase3Results) {
	if p3 == nil {
		return
	}
	w.json.Write("phase3_smtp.json", p3)
	log.Info().Str("dir", w.outputDir).Msg("Phase 3 output written")
}

func (w *Writer) WritePhase4(p4 *models.Phase4Results) {
	if p4 == nil {
		return
	}
	w.json.Write("phase4_webapps.json", p4)

	var urlLines []string
	var csvRows [][]string
	for _, app := range p4.Apps {
		urlLines = append(urlLines, app.URL)
		csvRows = append(csvRows, []string{
			app.URL,
			fmt.Sprintf("%d", app.StatusCode),
			app.Title,
			app.Technology,
			app.Server,
			app.XPoweredBy,
			fmt.Sprintf("%t", app.RequiresAuth),
		})
	}
	w.txt.WriteLines("phase4_urls.txt", urlLines)
	w.csv.Write("phase4_webapps.csv",
		[]string{"URL", "Status", "Title", "Technology", "Server", "X-Powered-By", "Auth Required"},
		csvRows)
	log.Info().Str("dir", w.outputDir).Msg("Phase 4 output written")
}

func (w *Writer) WritePhase5(p5 *models.Phase5Results) {
	if p5 == nil {
		return
	}
	w.txt.WriteLines("phase5_cloud_keywords.txt", p5.Keywords)
	log.Info().Str("dir", w.outputDir).Msg("Phase 5 output written")
}

func (w *Writer) WritePhase6(p6 *models.Phase6Results) {
	if p6 == nil {
		return
	}
	w.writeScanPhase6(p6)
	log.Info().Str("dir", w.outputDir).Msg("Phase 6 output written")
}

// --- Legacy bulk writers (for backward compat, now mostly used by scan/full commands) ---

func (w *Writer) WriteRecon(results *models.ReconResults) error {
	log.Info().Str("dir", w.outputDir).Msg("Writing recon results")
	w.json.Write("results.json", results)
	w.WritePhase1(results.Phase1)
	w.WritePhase2(results.Phase2)
	w.WritePhase3(results.Phase3)
	w.WritePhase4(results.Phase4)
	w.WritePhase5(results.Phase5)
	return nil
}

func (w *Writer) WriteScan(results *models.ScanResults) error {
	log.Info().Str("dir", w.outputDir).Msg("Writing scan results")
	w.json.Write("results.json", results)
	// Phase 6 files are written incrementally by the scanner runner
	return nil
}

func (w *Writer) WriteFull(results *models.FullResults) error {
	log.Info().Str("dir", w.outputDir).Msg("Writing full results")
	w.json.Write("results.json", results)
	// Individual phase files are already written incrementally
	return nil
}

func (w *Writer) writeScanPhase6(phase6 *models.Phase6Results) {
	w.json.Write("metadata_full.json", phase6)

	// CSV summary
	var csvRows [][]string
	for _, doc := range phase6.Metadata {
		csvRows = append(csvRows, []string{
			doc.SourceURL,
			doc.FileType,
			doc.FileHash,
			getFirst(doc.Metadata, "Author", "LastModifiedBy"),
			getFirst(doc.Metadata, "Software", "Producer", "CreatorTool", "Application"),
			getFirst(doc.Metadata, "CreateDate", "Created"),
			getFirst(doc.Metadata, "ModifyDate", "Modified"),
			getFirst(doc.Metadata, "Title"),
		})
	}
	w.csv.Write("metadata_summary.csv",
		[]string{"Source URL", "File Type", "MD5 Hash", "Author", "Software", "Created", "Modified", "Title"},
		csvRows)

	// Usernames
	if len(phase6.UniqueUsernames) > 0 {
		w.txt.WriteLines("extracted_usernames.txt", phase6.UniqueUsernames)
	}

	// Software
	if len(phase6.UniqueSoftware) > 0 {
		w.txt.WriteLines("extracted_software.txt", phase6.UniqueSoftware)
	}
}

func getFirst(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != "" {
			return v
		}
	}
	return ""
}
