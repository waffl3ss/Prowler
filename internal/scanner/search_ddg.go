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

type DDGSearcher struct {
	browser  *Browser
	captcha  *CAPTCHAChecker
	domain   string
	headed   bool
	maxPages int
}

func NewDDGSearcher(browser *Browser, captcha *CAPTCHAChecker, domain string, headed bool, maxPages int) *DDGSearcher {
	return &DDGSearcher{
		browser:  browser,
		captcha:  captcha,
		domain:   domain,
		headed:   headed,
		maxPages: maxPages,
	}
}

func (d *DDGSearcher) Name() string { return "DDG" }

func (d *DDGSearcher) Search(ctx context.Context, dork string) ([]string, error) {
	var allURLs []string

	searchURL := "https://duckduckgo.com/?q=" + url.QueryEscape(dork)
	log.Info().Str("engine", "DDG").Str("dork", dork).Msg("Searching")

	if err := d.browser.Navigate(ctx, searchURL); err != nil {
		return nil, err
	}

	util.RandomDelayMillis(3000, 5000)

	if !d.captcha.CheckCAPTCHA("DDG", d.headed, 45*time.Second) {
		return allURLs, nil
	}

	// Wait for results
	d.browser.WaitForAnySelector(ctx, []string{
		"[data-testid=\"result\"]",
		".result__body",
		".react-results--main",
	}, 10*time.Second)

	urls := d.extractDocURLs(ctx)
	allURLs = append(allURLs, urls...)

	// If container approach got nothing, try direct links
	if len(allURLs) == 0 {
		allURLs = d.extractFallbackURLs(ctx)
	}

	return allURLs, nil
}

func (d *DDGSearcher) extractDocURLs(ctx context.Context) []string {
	source, err := d.browser.PageSource(ctx)
	if err != nil {
		return nil
	}

	return d.extractFromContainers(source)
}

func (d *DDGSearcher) extractFromContainers(htmlSource string) []string {
	var urls []string
	seen := make(map[string]bool)

	doc, err := html.Parse(strings.NewReader(htmlSource))
	if err != nil {
		return nil
	}

	// Find result containers: [data-testid="result"], .result, article
	var findResults func(*html.Node)
	findResults = func(n *html.Node) {
		if n.Type == html.ElementNode {
			isContainer := false

			for _, attr := range n.Attr {
				if attr.Key == "data-testid" && attr.Val == "result" {
					isContainer = true
					break
				}
				if attr.Key == "class" && strings.Contains(attr.Val, "result") {
					isContainer = true
					break
				}
			}
			if n.Data == "article" {
				isContainer = true
			}

			if isContainer {
				d.extractLinksFromNode(n, seen, &urls)
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findResults(c)
		}
	}
	findResults(doc)

	return urls
}

func (d *DDGSearcher) extractLinksFromNode(n *html.Node, seen map[string]bool, urls *[]string) {
	if n.Type == html.ElementNode && n.Data == "a" {
		for _, attr := range n.Attr {
			if attr.Key == "href" {
				href := attr.Val

				// DDG redirect extraction
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

				if strings.HasPrefix(href, "/") || strings.Contains(href, "duckduckgo.com") {
					continue
				}

				if strings.Contains(href, d.domain) && hasDocExtension(href) {
					if !seen[href] {
						seen[href] = true
						*urls = append(*urls, href)
					}
				}
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		d.extractLinksFromNode(c, seen, urls)
	}
}

func (d *DDGSearcher) extractFallbackURLs(ctx context.Context) []string {
	source, err := d.browser.PageSource(ctx)
	if err != nil {
		return nil
	}

	// Try matching links with data-testid="result-title-a"
	return extractDocURLsFromHTML(source, d.domain, "DDG")
}
