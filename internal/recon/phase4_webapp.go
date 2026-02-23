package recon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/html"
	"golang.org/x/sync/errgroup"

	"prowler/internal/config"
	"prowler/internal/output"
	"prowler/internal/util"
	"prowler/pkg/models"
)

type Phase4 struct {
	cfg    *config.Config
	client *http.Client
}

func NewPhase4(cfg *config.Config) *Phase4 {
	return &Phase4{
		cfg:    cfg,
		client: util.NewHTTPClient(cfg.Timeout),
	}
}

func (p *Phase4) Name() string { return "Web Application Discovery" }

func (p *Phase4) Run(ctx context.Context, domains []string) (*models.Phase4Results, error) {
	output.PrintPhase(4, "WEB APPLICATION ENUMERATION")

	results := &models.Phase4Results{}
	log.Info().Int("count", len(domains)).Msg("Scanning domains")

	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(p.cfg.Threads)

	for _, domain := range domains {
		domain := domain
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			apps := p.checkDomain(ctx, domain)
			if len(apps) > 0 {
				mu.Lock()
				results.Apps = append(results.Apps, apps...)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()

	// Dedup by final URL
	seen := make(map[string]bool)
	var deduped []models.WebApp
	for _, app := range results.Apps {
		if !seen[app.URL] {
			seen[app.URL] = true
			deduped = append(deduped, app)
		}
	}
	results.Apps = deduped

	// Print results
	if p.cfg.Verbosity >= 1 {
		output.PrintSection("PHASE 4 DETAILS")
		for _, app := range results.Apps {
			fmt.Printf("   %s\n", app.URL)
			fmt.Printf("     Title: %s  Tech: %s", app.Title, app.Technology)
			if app.Server != "" {
				fmt.Printf("  Server: %s", app.Server)
			}
			if app.RequiresAuth {
				fmt.Printf("  [AUTH]")
			}
			fmt.Println()
		}
	}
	output.PrintDetail("%d web applications discovered", len(results.Apps))

	return results, nil
}

func (p *Phase4) checkDomain(ctx context.Context, domain string) []models.WebApp {
	var apps []models.WebApp

	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, domain)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", util.DefaultUserAgent)

		resp, err := p.client.Do(req)
		if err != nil {
			continue
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := string(bodyBytes)

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			app := models.WebApp{
				URL:        resp.Request.URL.String(),
				StatusCode: resp.StatusCode,
				Title:      extractTitle(body),
				Technology: identifyTechnology(resp.Header, body),
				Server:     resp.Header.Get("Server"),
				XPoweredBy: resp.Header.Get("X-Powered-By"),
			}
			apps = append(apps, app)
		} else if resp.StatusCode == 401 {
			app := models.WebApp{
				URL:          resp.Request.URL.String(),
				StatusCode:   resp.StatusCode,
				Title:        "Authentication Required",
				Technology:   identifyTechnology(resp.Header, body),
				Server:       resp.Header.Get("Server"),
				RequiresAuth: true,
			}
			apps = append(apps, app)
		}
	}

	return apps
}

func extractTitle(body string) string {
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	inTitle := false
	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return "No Title"
		case html.StartTagToken:
			t := tokenizer.Token()
			if t.Data == "title" {
				inTitle = true
			}
		case html.TextToken:
			if inTitle {
				title := strings.TrimSpace(tokenizer.Token().Data)
				if len(title) > 80 {
					title = title[:80] + "..."
				}
				return title
			}
		case html.EndTagToken:
			if inTitle {
				return "No Title"
			}
		}
	}
}

func identifyTechnology(headers http.Header, body string) string {
	// Check X-Powered-By
	if xpb := headers.Get("X-Powered-By"); xpb != "" {
		return xpb
	}

	// Check Server header
	server := strings.ToLower(headers.Get("Server"))
	switch {
	case strings.Contains(server, "apache"):
		return "Apache"
	case strings.Contains(server, "nginx"):
		return "Nginx"
	case strings.Contains(server, "iis"):
		return "IIS"
	case strings.Contains(server, "cloudflare"):
		return "Cloudflare"
	case server != "":
		return headers.Get("Server")
	}

	// Check body for CMS
	bodyLower := strings.ToLower(body)
	switch {
	case strings.Contains(bodyLower, "wp-content"):
		return "WordPress"
	case strings.Contains(bodyLower, "joomla"):
		return "Joomla"
	case strings.Contains(bodyLower, "drupal"):
		return "Drupal"
	}

	return "Unknown"
}
