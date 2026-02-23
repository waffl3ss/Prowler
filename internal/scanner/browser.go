package scanner

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/stealth"
	"github.com/rs/zerolog/log"

	"prowler/internal/output"
)

type Browser struct {
	browser *rod.Browser
	page    *rod.Page
	headed  bool
}

func NewBrowser(headed bool) (*Browser, error) {
	b := &Browser{headed: headed}

	if headed {
		output.PrintDetail("Launching Chrome in headed mode...")
	} else {
		output.PrintDetail("Launching Chrome in headless mode...")
	}

	l := launcher.New().
		Headless(!headed).
		Set("disable-blink-features", "AutomationControlled").
		Set("no-sandbox").
		Set("disable-dev-shm-usage").
		Logger(io.Discard)

	controlURL, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("failed to launch Chrome: %w", err)
	}

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to Chrome: %w", err)
	}
	b.browser = browser

	// Create stealth page (anti-detection, like undetected-chromedriver)
	page, err := stealth.Page(browser)
	if err != nil {
		browser.Close()
		return nil, fmt.Errorf("failed to create stealth page: %w", err)
	}
	b.page = page

	output.PrintDetail("Browser ready")
	log.Info().Msg("Browser ready")
	return b, nil
}

func (b *Browser) Navigate(ctx context.Context, url string) error {
	err := b.page.Navigate(url)
	if err != nil {
		return err
	}
	// Wait for page load with timeout
	return rod.Try(func() {
		b.page.Timeout(15 * time.Second).MustWaitLoad()
	})
}

func (b *Browser) PageSource(ctx context.Context) (string, error) {
	return b.page.HTML()
}

func (b *Browser) WaitForSelector(ctx context.Context, sel string, timeout time.Duration) error {
	return rod.Try(func() {
		b.page.Timeout(timeout).MustElement(sel)
	})
}

func (b *Browser) WaitForAnySelector(ctx context.Context, selectors []string, timeout time.Duration) error {
	js := fmt.Sprintf(`() => new Promise((resolve) => {
		const sels = %s;
		const check = () => {
			for (const s of sels) {
				if (document.querySelector(s)) { resolve(true); return; }
			}
		};
		check();
		const iv = setInterval(check, 200);
		setTimeout(() => { clearInterval(iv); resolve(false); }, %d);
	})`, toJSArray(selectors), timeout.Milliseconds())

	result, err := b.page.Timeout(timeout + 2*time.Second).Eval(js)
	if err != nil {
		return err
	}
	if !result.Value.Bool() {
		return context.DeadlineExceeded
	}
	return nil
}

func toJSArray(strs []string) string {
	parts := make([]string, len(strs))
	for i, s := range strs {
		parts[i] = `"` + s + `"`
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func (b *Browser) Click(ctx context.Context, sel string) error {
	return rod.Try(func() {
		b.page.Timeout(5 * time.Second).MustElement(sel).MustClick()
	})
}

func (b *Browser) Sleep(d time.Duration) {
	time.Sleep(d)
}

func (b *Browser) HasElement(sel string) bool {
	result, err := b.page.Eval(`(sel) => document.querySelectorAll(sel).length > 0`, sel)
	if err != nil {
		return false
	}
	return result.Value.Bool()
}

// EvalJS runs JavaScript on the page. Non-blocking, ignores errors.
// Pass raw JS statements (they get wrapped in an arrow function).
func (b *Browser) EvalJS(js string) {
	rod.Try(func() {
		b.page.Timeout(3 * time.Second).MustEval(`() => { ` + js + ` }`)
	})
}

// IsAlive checks if the browser process is still running.
func (b *Browser) IsAlive() bool {
	err := rod.Try(func() {
		b.page.MustEval(`() => "ok"`)
	})
	return err == nil
}

func (b *Browser) Context() context.Context {
	return context.Background()
}

func (b *Browser) Close() {
	if b.page != nil {
		b.page.Close()
	}
	if b.browser != nil {
		b.browser.Close()
	}
	log.Info().Msg("Browser closed")
}
