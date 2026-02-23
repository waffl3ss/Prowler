package scanner

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/html"

	"prowler/internal/util"
)

type GoogleSearcher struct {
	browser  *Browser
	captcha  *CAPTCHAChecker
	domain   string
	headed   bool
	maxPages int
}

func NewGoogleSearcher(browser *Browser, captcha *CAPTCHAChecker, domain string, headed bool, maxPages int) *GoogleSearcher {
	return &GoogleSearcher{
		browser:  browser,
		captcha:  captcha,
		domain:   domain,
		headed:   headed,
		maxPages: maxPages,
	}
}

func (g *GoogleSearcher) Name() string { return "Google" }

func (g *GoogleSearcher) Search(ctx context.Context, dork string) ([]string, error) {
	var allURLs []string

	searchURL := "https://www.google.com/search?q=" + url.QueryEscape(dork) + "&num=50"
	log.Info().Str("engine", "Google").Str("dork", dork).Msg("Searching")

	if err := g.browser.Navigate(ctx, searchURL); err != nil {
		return nil, err
	}

	util.RandomDelayMillis(2000, 4000)

	// Dismiss Google consent if it appears (non-blocking JS click)
	g.browser.EvalJS(`
		var btns = document.querySelectorAll('button');
		for(var i=0;i<btns.length;i++){
			var t = btns[i].textContent.toLowerCase();
			if(t.includes('reject all') || t.includes('accept all') || t.includes('i agree')){
				btns[i].click(); break;
			}
		}
	`)

	if !g.captcha.CheckCAPTCHA("Google", g.headed, 45*time.Second) {
		return allURLs, nil
	}

	// Wait for results
	g.browser.WaitForAnySelector(ctx, []string{"#search", "#rso", "div.g"}, 10*time.Second)

	urls := g.extractDocURLs(ctx)
	allURLs = append(allURLs, urls...)

	// Try additional pages
	for page := 2; page <= g.maxPages && len(urls) > 0; page++ {
		log.Debug().Int("page", page).Msg("Google next page")
		if err := g.browser.Click(ctx, "#pnnext, a[aria-label=\"Next\"]"); err != nil {
			break
		}
		util.RandomDelayMillis(3000, 5000)

		if !g.captcha.CheckCAPTCHA("Google", g.headed, 45*time.Second) {
			break
		}

		urls = g.extractDocURLs(ctx)
		allURLs = append(allURLs, urls...)
	}

	return allURLs, nil
}

func (g *GoogleSearcher) extractDocURLs(ctx context.Context) []string {
	source, err := g.browser.PageSource(ctx)
	if err != nil {
		return nil
	}
	return extractDocURLsFromHTML(source, g.domain, "Google")
}

// extractDocURLsFromHTML parses HTML and finds document URLs for the target domain
func extractDocURLsFromHTML(htmlSource, domain, engine string) []string {
	var urls []string
	seen := make(map[string]bool)

	tokenizer := html.NewTokenizer(strings.NewReader(htmlSource))
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		t := tokenizer.Token()
		if t.Data != "a" {
			continue
		}

		var href string
		for _, attr := range t.Attr {
			if attr.Key == "href" {
				href = attr.Val
				break
			}
		}
		if href == "" {
			continue
		}

		// Handle Google redirect URLs
		if strings.HasPrefix(href, "/url?") {
			if u, err := url.Parse(href); err == nil {
				if q := u.Query().Get("q"); q != "" {
					href = q
				}
			}
		}

		// Handle DDG redirect URLs
		if strings.Contains(href, "uddg=") {
			if u, err := url.Parse(href); err == nil {
				if uddg := u.Query().Get("uddg"); uddg != "" {
					decoded, err := url.QueryUnescape(uddg)
					if err == nil {
						href = decoded
					}
				}
			}
		}

		// Skip internal search engine links
		if strings.HasPrefix(href, "/") {
			continue
		}
		skip := false
		for _, s := range []string{"google.com", "bing.com", "duckduckgo.com", "microsoft.com"} {
			if strings.Contains(href, s) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// Match target domain + document extension
		if !strings.Contains(href, domain) {
			continue
		}
		if !hasDocExtension(href) {
			continue
		}

		// Clean tracking params
		clean := href
		for _, sep := range []string{"&sa=", "&ved=", "&usg="} {
			if idx := strings.Index(clean, sep); idx != -1 {
				clean = clean[:idx]
			}
		}

		if !seen[clean] {
			seen[clean] = true
			urls = append(urls, clean)
		}
	}

	return urls
}

var docExtensions = []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}

func hasDocExtension(href string) bool {
	lower := strings.ToLower(href)
	for _, ext := range docExtensions {
		if strings.Contains(lower, ext) {
			return true
		}
	}
	return false
}
