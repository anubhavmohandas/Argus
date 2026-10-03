package models

import "time"

// ScanResult holds all metadata + screenshot for a single domain
type ScanResult struct {
	ID            string    `json:"id"`
	Domain        string    `json:"domain"`
	URL           string    `json:"url"`
	Status        int       `json:"status"`
	Title         string    `json:"title"`
	Server        string    `json:"server"`
	ContentLength int64     `json:"contentLength"`
	RedirectURL   string    `json:"redirectUrl"`
	RedirectChain []string  `json:"redirectChain"`
	Screenshot    string    `json:"screenshot"` // base64 PNG
	Error         string    `json:"error,omitempty"`
	Interesting   bool      `json:"interesting"`
	Keywords      []string  `json:"keywords"`
	Timestamp     time.Time `json:"timestamp"`
	DurationMs    int64     `json:"durationMs"`
	TLS           bool      `json:"tls"`
	Intelligence  Intel     `json:"intelligence"`
}

// Intel captures defensive URL/domain intelligence for triage.
type Intel struct {
	RiskScore      int      `json:"riskScore"`
	RiskLevel      string   `json:"riskLevel"`
	Categories     []string `json:"categories"`
	Indicators     []string `json:"indicators"`
	Technologies   []string `json:"technologies"`
	IPAddress      string   `json:"ipAddress"`
	RootDomain     string   `json:"rootDomain"`
	Hostname       string   `json:"hostname"`
	BrandCandidate string   `json:"brandCandidate"`
}

// ScanJob represents a full scan session
type ScanJob struct {
	ID          string       `json:"id"`
	Status      string       `json:"status"` // pending | running | complete | error
	Total       int          `json:"total"`
	Processed   int          `json:"processed"`
	Live        int          `json:"live"`
	Errors      int          `json:"errors"`
	Results     []ScanResult `json:"results"`
	StartedAt   time.Time    `json:"startedAt"`
	CompletedAt *time.Time   `json:"completedAt,omitempty"`
}

// ScanConfig holds per-scan tuning parameters
type ScanConfig struct {
	Concurrency     int    `json:"concurrency"`     // HTTP probe workers (default 150)
	ScreenWorkers   int    `json:"screenWorkers"`   // chromedp workers (default 6)
	TimeoutSeconds  int    `json:"timeoutSeconds"`  // per-host timeout (default 10)
	ScreenshotMode  string `json:"screenshotMode"`  // viewport | fullpage | mobile
	MaxRetries      int    `json:"maxRetries"`      // default 1
	SkipScreenshots bool   `json:"skipScreenshots"` // probe-only mode
	OnlyLive        bool   `json:"onlyLive"`        // skip non-200
	FollowRedirects bool   `json:"followRedirects"`
}

// ScanRequest is the POST /api/scan payload
type ScanRequest struct {
	Domains []string   `json:"domains"`
	Config  ScanConfig `json:"config"`
}

// SSEEvent is a single result pushed over SSE
type SSEEvent struct {
	Type string      `json:"type"` // result | progress | done | error
	Data interface{} `json:"data"`
}

// InterestingKeywords are auto-detected in titles/domains
var InterestingKeywords = []string{
	"admin", "dashboard", "login", "panel", "staging", "dev",
	"internal", "test", "api", "console", "grafana", "jenkins",
	"gitlab", "jira", "confluence", "kibana", "elastic", "sonar",
	"vault", "secret", "phpmyadmin", "cpanel", "webmail",
	"portal", "manager", "control", "monitor", "metrics",
}
