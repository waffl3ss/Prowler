package scanner

import (
	"fmt"
	"os"
	"runtime"

	"github.com/go-rod/rod/lib/launcher"
)

// PreflightCheck verifies Chrome/Chromium is installed and, if headed mode
// is requested, that a display server is available. Call this before any
// browser work begins so the user gets a clear error up front.
func PreflightCheck(headed bool) error {
	_, has := launcher.LookPath()
	if !has {
		return fmt.Errorf("Chrome/Chromium not found\n\n" +
			"Install Chrome or Chromium:\n" +
			"  Linux:   sudo apt install chromium-browser  (or google-chrome-stable)\n" +
			"  macOS:   brew install --cask google-chrome\n" +
			"  Windows: Download from https://www.google.com/chrome/")
	}

	if headed {
		if err := checkDisplay(); err != nil {
			return fmt.Errorf("--headed mode requires a display server: %w\n\n"+
				"Options:\n"+
				"  - Run without --headed (headless mode)\n"+
				"  - On Linux: ensure $DISPLAY is set (e.g. export DISPLAY=:0)\n"+
				"  - On WSL2: install WSLg or use an X server like VcXsrv", err)
		}
	}

	return nil
}

// checkDisplay verifies a display server is available for headed mode.
func checkDisplay() error {
	switch runtime.GOOS {
	case "linux":
		display := os.Getenv("DISPLAY")
		waylandDisplay := os.Getenv("WAYLAND_DISPLAY")
		if display == "" && waylandDisplay == "" {
			return fmt.Errorf("no DISPLAY or WAYLAND_DISPLAY environment variable set")
		}
	case "darwin", "windows":
		// macOS and Windows always have a display server
	}
	return nil
}
