package scanner

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"prowler/internal/util"
	"prowler/pkg/models"
)

type Downloader struct {
	outputDir   string
	maxWorkers  int
	maxDownload int
	client      *http.Client
}

func NewDownloader(outputDir string, maxWorkers, maxDownload int, timeout time.Duration) *Downloader {
	os.MkdirAll(outputDir, 0755)
	return &Downloader{
		outputDir:   outputDir,
		maxWorkers:  maxWorkers,
		maxDownload: maxDownload,
		client:      util.NewHTTPClient(timeout),
	}
}

var filenameCleanRegex = regexp.MustCompile(`[^\w\-_.]`)

func (d *Downloader) DownloadAll(urls []string) []models.DownloadResult {
	log.Info().Int("count", len(urls)).Msg("Starting document downloads")

	// Limit to max downloads
	if len(urls) > d.maxDownload {
		urls = urls[:d.maxDownload]
		log.Info().Int("limit", d.maxDownload).Msg("Limiting downloads")
	}

	var mu sync.Mutex
	var results []models.DownloadResult

	g := new(errgroup.Group)
	g.SetLimit(d.maxWorkers)

	for _, u := range urls {
		u := u
		g.Go(func() error {
			result := d.downloadFile(u)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
			return nil
		})
	}

	g.Wait()

	ok := 0
	for _, r := range results {
		if r.Success {
			ok++
		}
	}
	log.Info().Int("success", ok).Int("total", len(results)).Msg("Downloads complete")

	return results
}

func (d *Downloader) downloadFile(rawURL string) models.DownloadResult {
	result := models.DownloadResult{URL: rawURL}

	log.Info().Str("url", rawURL).Msg("Downloading")

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", util.DefaultUserAgent)

	resp, err := d.client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}

	// Determine filename
	parsed, _ := url.Parse(rawURL)
	filename := filepath.Base(parsed.Path)
	if filename == "" || filename == "." || !strings.Contains(filename, ".") {
		ext := guessExtension(resp.Header.Get("Content-Type"))
		hash := fmt.Sprintf("%x", md5.Sum([]byte(rawURL)))
		filename = fmt.Sprintf("document_%s%s", hash[:8], ext)
	}

	filename = filenameCleanRegex.ReplaceAllString(filename, "_")
	localPath := filepath.Join(d.outputDir, filename)

	f, err := os.Create(localPath)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer f.Close()

	hasher := md5.New()
	writer := io.MultiWriter(f, hasher)

	_, err = io.Copy(writer, resp.Body)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	result.LocalPath = localPath
	result.FileHash = fmt.Sprintf("%x", hasher.Sum(nil))

	log.Info().Str("file", filename).Msg("Downloaded")
	return result
}

func guessExtension(contentType string) string {
	m := map[string]string{
		"application/pdf":       ".pdf",
		"application/msword":    ".doc",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   ".docx",
		"application/vnd.ms-excel":                                                  ".xls",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         ".xlsx",
		"application/vnd.ms-powerpoint":                                             ".ppt",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
	}

	for ct, ext := range m {
		if strings.Contains(contentType, ct) {
			return ext
		}
	}
	return ".bin"
}
