package browser

import (
	"context"
	"os"
	"os/exec"

	"github.com/chromedp/chromedp"
)

// Options for browser and page behavior
type Options struct {
	MaxWait    int
	UserAgent  string
	Proxy      string
	NoScripts  bool
	NoRedirect bool
	Headers    map[string]string
	Debug      bool
}

// Browser manages a headless Chrome instance
type Browser struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	Ctx         context.Context
	Cancel      context.CancelFunc
}

// New launches a headless Chrome browser
func New(opts Options) (*Browser, error) {
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("allow-running-insecure-content", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
	)

	// Explicitly find Chrome to avoid snap issues
	if chromePath := findChrome(); chromePath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(chromePath))
	}

	if opts.Proxy != "" {
		allocOpts = append(allocOpts, chromedp.ProxyServer(opts.Proxy))
	}

	if opts.UserAgent != "" {
		allocOpts = append(allocOpts, chromedp.UserAgent(opts.UserAgent))
	}

	if !opts.Debug {
		allocOpts = append(allocOpts, chromedp.Flag("headless", true))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)

	var ctx context.Context
	var cancel context.CancelFunc

	// Suppress chromedp error logs (cookie parsing errors, etc.)
	if opts.Debug {
		ctx, cancel = chromedp.NewContext(allocCtx)
	} else {
		ctx, cancel = chromedp.NewContext(allocCtx,
			chromedp.WithErrorf(func(s string, i ...interface{}) {}),
			chromedp.WithLogf(func(s string, i ...interface{}) {}),
		)
	}

	return &Browser{
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		Ctx:         ctx,
		Cancel:      cancel,
	}, nil
}

// Close shuts down the browser
func (b *Browser) Close() {
	b.Cancel()
	b.allocCancel()
}

// findChrome returns the path to a Chrome/Chromium binary, preferring
// non-snap installations. Checks CHROME_PATH env var first.
func findChrome() string {
	if p := os.Getenv("CHROME_PATH"); p != "" {
		return p
	}

	candidates := []string{
		"google-chrome-stable",
		"google-chrome",
		"chromium-browser",
		"chromium",
	}

	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			// Skip snap paths — they cause sandbox issues in WSL
			if len(path) >= 5 && path[:5] == "/snap" {
				continue
			}
			return path
		}
	}

	return ""
}
