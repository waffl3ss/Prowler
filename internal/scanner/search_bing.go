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

type BingSearcher struct {
	browser  *Browser
	captcha  *CAPTCHAChecker
	domain   string
	headed   bool
	maxPages int
}

func NewBingSearcher(browser *Browser, captcha *CAPTCHAChecker, domain string, headed bool, maxPages int) *BingSearcher {
	return &BingSearcher{
		browser:  browser,
		captcha:  captcha,
		domain:   domain,
		headed:   headed,
		maxPages: maxPages,
	}
}

func (b *BingSearcher) Name() string { return "Bing" }

func (b *BingSearcher) Search(ctx context.Context, dork string) ([]string, error) {
	var allURLs []string

	searchURL := "https://www.bing.com/search?q=" + url.QueryEscape(dork) + "&count=50"
	log.Info().Str("engine", "Bing").Str("dork", dork).Msg("Searching")

	if err := b.browser.Navigate(ctx, searchURL); err != nil {
		return nil, err
	}

	util.RandomDelayMillis(2000, 4000)

	if !b.captcha.CheckCAPTCHA("Bing", b.headed, 45*time.Second) {
		return allURLs, nil
	}

	// Wait for results
	b.browser.WaitForAnySelector(ctx, []string{"#b_results", "li.b_algo"}, 10*time.Second)

	urls := b.extractDocURLs(ctx)
	allURLs = append(allURLs, urls...)

	return allURLs, nil
}

func (b *BingSearcher) extractDocURLs(ctx context.Context) []string {
	source, err := b.browser.PageSource(ctx)
	if err != nil {
		return nil
	}

	// For Bing, we specifically extract from b_algo sections only
	return b.extractFromBAlgo(source)
}

func (b *BingSearcher) extractFromBAlgo(htmlSource string) []string {
	var urls []string
	seen := make(map[string]bool)

	doc, err := html.Parse(strings.NewReader(htmlSource))
	if err != nil {
		return nil
	}

	// Find all li.b_algo elements and extract links within them
	var findAlgo func(*html.Node)
	findAlgo = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "li" {
			for _, attr := range n.Attr {
				if attr.Key == "class" && strings.Contains(attr.Val, "b_algo") {
					// Extract links within this result
					b.extractLinksFromNode(n, seen, &urls)
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findAlgo(c)
		}
	}
	findAlgo(doc)

	return urls
}

func (b *BingSearcher) extractLinksFromNode(n *html.Node, seen map[string]bool, urls *[]string) {
	if n.Type == html.ElementNode && n.Data == "a" {
		for _, attr := range n.Attr {
			if attr.Key == "href" {
				href := attr.Val
				if strings.HasPrefix(href, "/") || strings.Contains(href, "bing.com") || strings.Contains(href, "microsoft.com") {
					continue
				}
				if strings.Contains(href, b.domain) && hasDocExtension(href) {
					if !seen[href] {
						seen[href] = true
						*urls = append(*urls, href)
					}
				}
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		b.extractLinksFromNode(c, seen, urls)
	}
}
