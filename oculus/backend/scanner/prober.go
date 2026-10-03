package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"reconvision/models"
)

// Prober performs fast HTTP/HTTPS probing
type Prober struct {
	client *http.Client
	config models.ScanConfig
}

// NewProber creates a prober with optimised transport settings
func NewProber(cfg models.ScanConfig) *Prober {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // recon tool, certs may be self-signed
		},
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   false, // HTTP/1.1 is faster for scanning
		TLSHandshakeTimeout: 5 * time.Second,
	}

	var redirects []string
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects = append(redirects, req.URL.String())
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	_ = redirects // used per-call below

	return &Prober{client: client, config: cfg}
}

// Probe probes a single domain and returns a ScanResult
func (p *Prober) Probe(ctx context.Context, domain string) models.ScanResult {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimRight(domain, "/")

	start := time.Now()
	result := models.ScanResult{
		Domain:    domain,
		Timestamp: start,
		Keywords:  []string{},
	}

	// Try HTTPS first, then HTTP fallback
	probeURL, statusCode, title, server, contentLen, redirectChain, redirectURL, isTLS, err := p.tryProbe(ctx, "https://"+domain)
	if err != nil || statusCode == 0 {
		probeURL, statusCode, title, server, contentLen, redirectChain, redirectURL, isTLS, err = p.tryProbe(ctx, "http://"+domain)
	}

	result.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.URL = probeURL
	result.Status = statusCode
	result.Title = title
	result.Server = server
	result.ContentLength = contentLen
	result.RedirectChain = redirectChain
	result.RedirectURL = redirectURL
	result.TLS = isTLS
	result.Keywords = detectKeywords(domain, title)
	result.Interesting = len(result.Keywords) > 0 || isInterestingStatus(statusCode)
	enrichIntelligence(&result)

	return result
}

func (p *Prober) tryProbe(ctx context.Context, rawURL string) (
	finalURL string, status int, title, server string,
	contentLen int64, redirectChain []string, redirectURL string, isTLS bool, err error,
) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.9")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	// Capture redirect chain
	var chain []string
	p.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		chain = append(chain, req.URL.String())
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	resp, err := p.client.Do(req)
	if err != nil {
		// Check if it's a redirect error with last response
		if ue, ok := err.(*url.Error); ok && ue.Err == http.ErrUseLastResponse {
			err = nil
		} else {
			return
		}
	}
	if resp == nil {
		return
	}
	defer resp.Body.Close()

	status = resp.StatusCode
	finalURL = resp.Request.URL.String()
	server = resp.Header.Get("Server")
	contentLen = resp.ContentLength
	redirectChain = chain
	isTLS = strings.HasPrefix(finalURL, "https://")

	if len(chain) > 0 {
		redirectURL = chain[len(chain)-1]
	}

	// Read body for title extraction (limit to 64KB)
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if readErr == nil && len(body) > 0 {
		title = extractTitle(string(body))
		if contentLen <= 0 {
			contentLen = int64(len(body))
		}
	}

	return
}

// extractTitle parses <title> from HTML body
func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start == -1 {
		return ""
	}
	// Find closing >
	gt := strings.Index(body[start:], ">")
	if gt == -1 {
		return ""
	}
	contentStart := start + gt + 1
	end := strings.Index(lower[contentStart:], "</title>")
	if end == -1 {
		return ""
	}
	title := strings.TrimSpace(body[contentStart : contentStart+end])
	// Collapse whitespace
	title = strings.Join(strings.Fields(title), " ")
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}

// detectKeywords checks domain and title for interesting strings
func detectKeywords(domain, title string) []string {
	combined := strings.ToLower(domain + " " + title)
	var found []string
	seen := map[string]bool{}
	for _, kw := range models.InterestingKeywords {
		if strings.Contains(combined, kw) && !seen[kw] {
			found = append(found, kw)
			seen[kw] = true
		}
	}
	return found
}

func isInterestingStatus(code int) bool {
	return code == 401 || code == 403
}

// deduplicateDomains removes duplicates while preserving order
func deduplicateDomains(domains []string) []string {
	seen := make(map[string]bool, len(domains))
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.TrimSpace(d)
		d = strings.TrimPrefix(d, "http://")
		d = strings.TrimPrefix(d, "https://")
		d = strings.TrimRight(d, "/")
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// formatBytes returns human-readable byte count
func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%dB", n)
	} else if n < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(n)/1024/1024)
}
