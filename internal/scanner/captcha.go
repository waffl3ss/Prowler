package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type CAPTCHAChecker struct {
	browser *Browser
}

func NewCAPTCHAChecker(browser *Browser) *CAPTCHAChecker {
	return &CAPTCHAChecker{browser: browser}
}

func (c *CAPTCHAChecker) IsCAPTCHAPage(engine string) bool {
	source, err := c.browser.PageSource(context.Background())
	if err != nil {
		return false
	}
	pageSrc := strings.ToLower(source)

	switch engine {
	case "Google":
		return c.isGoogleCAPTCHA(pageSrc)
	case "Bing":
		return c.isBingCAPTCHA(pageSrc)
	case "DDG":
		return c.isDDGCAPTCHA(pageSrc)
	}
	return false
}

func (c *CAPTCHAChecker) isGoogleCAPTCHA(pageSrc string) bool {
	indicators := []string{
		"/httpservice/retry/enablejs",
		"unusual traffic from your computer",
		"our systems have detected unusual traffic",
		"please show you're not a robot",
		"recaptcha",
	}

	blocked := false
	for _, ind := range indicators {
		if strings.Contains(pageSrc, ind) {
			blocked = true
			break
		}
	}

	if !blocked {
		return false
	}

	// If we have actual search results, we're not blocked
	hasResults := c.browser.HasElement("#search") ||
		c.browser.HasElement("#rso") ||
		c.browser.HasElement("div.g")

	return !hasResults
}

func (c *CAPTCHAChecker) isBingCAPTCHA(pageSrc string) bool {
	indicators := []string{
		"please verify you are a human",
		"are you a human",
		"verify you're not a robot",
		"cf-browser-verification",
		"challenge-running",
		"<title>are you a robot",
		"blocked by bing",
	}

	blocked := false
	for _, ind := range indicators {
		if strings.Contains(pageSrc, ind) {
			blocked = true
			break
		}
	}

	hasResults := c.browser.HasElement("li.b_algo") || c.browser.HasElement("#b_results")

	if hasResults && !blocked {
		return false
	}
	return blocked
}

func (c *CAPTCHAChecker) isDDGCAPTCHA(pageSrc string) bool {
	indicators := []string{
		"please wait while we verify",
		"verify you are human",
		"bot detection",
		"challenge-running",
		"cf-browser-verification",
	}

	blocked := false
	for _, ind := range indicators {
		if strings.Contains(pageSrc, ind) {
			blocked = true
			break
		}
	}

	if !blocked {
		return false
	}

	hasResults := c.browser.HasElement("[data-testid=\"result\"]") ||
		c.browser.HasElement(".result__body") ||
		c.browser.HasElement(".react-results--main")

	return !hasResults
}

func (c *CAPTCHAChecker) HasSearchResults(engine string) bool {
	switch engine {
	case "Google":
		return c.browser.HasElement("#search") ||
			c.browser.HasElement("#rso") ||
			c.browser.HasElement("div.g")
	case "Bing":
		return c.browser.HasElement("li.b_algo")
	case "DDG":
		return c.browser.HasElement("[data-testid=\"result\"]") ||
			c.browser.HasElement(".result__body") ||
			c.browser.HasElement(".react-results--main")
	}
	return false
}

// CheckCAPTCHA detects CAPTCHAs. In headed mode, waits for manual solve.
// Returns true if page is good to parse, false if blocked.
func (c *CAPTCHAChecker) CheckCAPTCHA(engine string, headed bool, timeout time.Duration) bool {
	if !c.IsCAPTCHAPage(engine) {
		return true
	}

	if !headed {
		log.Warn().Str("engine", engine).Msg("CAPTCHA detected in headless mode")
		return false
	}

	fmt.Printf("\n[!] CAPTCHA detected! Solve it in the browser window (%ds timeout)...\n", int(timeout.Seconds()))
	log.Warn().Str("engine", engine).Dur("timeout", timeout).Msg("CAPTCHA detected")

	start := time.Now()
	for time.Since(start) < timeout {
		time.Sleep(2 * time.Second)

		// Primary: did search results appear?
		if c.HasSearchResults(engine) {
			log.Info().Str("engine", engine).Msg("Search results detected - CAPTCHA solved!")
			time.Sleep(1 * time.Second)
			return true
		}

		// Secondary: did CAPTCHA go away?
		if !c.IsCAPTCHAPage(engine) {
			log.Info().Str("engine", engine).Msg("CAPTCHA page cleared")
			time.Sleep(1 * time.Second)
			return true
		}

		elapsed := int(time.Since(start).Seconds())
		if elapsed%10 == 0 && elapsed > 0 {
			log.Info().Str("engine", engine).Int("elapsed", elapsed).Msg("Still waiting for CAPTCHA solve...")
		}
	}

	log.Warn().Str("engine", engine).Msg("CAPTCHA timeout")
	return false
}
