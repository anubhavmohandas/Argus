package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"

	"reconvision/models"
)

// Screenshotter captures screenshots using a chromedp browser pool
type Screenshotter struct {
	config models.ScanConfig
}

// NewScreenshotter creates a screenshotter instance
func NewScreenshotter(cfg models.ScanConfig) *Screenshotter {
	return &Screenshotter{config: cfg}
}

// Capture takes a screenshot of the given URL and returns base64-encoded PNG
func (s *Screenshotter) Capture(targetURL string) (string, error) {
	timeout := time.Duration(s.config.TimeoutSeconds)*time.Second + 5*time.Second

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("allow-insecure-localhost", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-translate", true),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		chromedp.Flag("blink-settings", "imagesEnabled=true"),
		chromedp.UserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"),
	)

	if chromePath := os.Getenv("CHROME_PATH"); chromePath != "" {
		opts = append(opts, chromedp.ExecPath(chromePath))
	}

	// Set viewport / mode
	switch s.config.ScreenshotMode {
	case "mobile":
		opts = append(opts, chromedp.WindowSize(390, 844))
	case "fullpage":
		opts = append(opts, chromedp.WindowSize(1440, 900))
	default: // viewport
		opts = append(opts, chromedp.WindowSize(1280, 800))
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancelCtx := chromedp.NewContext(allocCtx, chromedp.WithErrorf(chromeErrorf))
	defer cancelCtx()

	ctx, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()

	var buf []byte

	tasks := chromedp.Tasks{
		chromedp.Navigate(targetURL),
		chromedp.Sleep(1500 * time.Millisecond), // let JS render
	}

	if s.config.ScreenshotMode == "fullpage" {
		tasks = append(tasks, chromedp.FullScreenshot(&buf, 85))
	} else {
		tasks = append(tasks, chromedp.CaptureScreenshot(&buf))
	}

	if err := chromedp.Run(ctx, tasks...); err != nil {
		return "", fmt.Errorf("screenshot failed: %w", err)
	}

	if len(buf) == 0 {
		return "", fmt.Errorf("empty screenshot buffer")
	}

	return base64.StdEncoding.EncodeToString(buf), nil
}

func chromeErrorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if strings.Contains(msg, "could not unmarshal event") {
		return
	}
	log.Printf("chromedp: "+format, args...)
}
