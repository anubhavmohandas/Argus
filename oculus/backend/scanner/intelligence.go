package scanner

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"reconvision/models"
)

var brandTerms = []string{
	"paypal", "microsoft", "office", "outlook", "onedrive", "google", "gmail",
	"facebook", "instagram", "whatsapp", "apple", "icloud", "amazon", "netflix",
	"bank", "secure", "verify", "wallet", "binance", "coinbase", "dropbox",
}

var suspiciousTLDs = map[string]bool{
	"zip": true, "mov": true, "top": true, "xyz": true, "click": true,
	"live": true, "quest": true, "support": true, "rest": true, "cyou": true,
}

var shortenerHosts = []string{
	"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly",
}

var freeHostingSignals = []string{
	"github.io", "pages.dev", "web.app", "firebaseapp.com", "netlify.app",
	"vercel.app", "workers.dev", "surge.sh", "000webhostapp.com",
}

var tokenLike = regexp.MustCompile(`[a-z0-9]{24,}`)

func enrichIntelligence(r *models.ScanResult) {
	host := r.Domain
	if r.URL != "" {
		if parsed, err := url.Parse(r.URL); err == nil && parsed.Hostname() != "" {
			host = parsed.Hostname()
		}
	}

	intel := models.Intel{
		Hostname:     host,
		RootDomain:   rootDomain(host),
		Categories:   []string{},
		Indicators:   []string{},
		Technologies: []string{},
	}

	if ips, err := net.LookupHost(host); err == nil && len(ips) > 0 {
		intel.IPAddress = ips[0]
	}

	score := 0
	add := func(points int, category, indicator string) {
		score += points
		if category != "" && !contains(intel.Categories, category) {
			intel.Categories = append(intel.Categories, category)
		}
		if indicator != "" && !contains(intel.Indicators, indicator) {
			intel.Indicators = append(intel.Indicators, indicator)
		}
	}

	hostLower := strings.ToLower(host)
	titleLower := strings.ToLower(r.Title)
	urlLower := strings.ToLower(r.URL)

	if !r.TLS && r.Status > 0 {
		add(15, "transport", "No TLS on live host")
	}
	if r.Status == 401 || r.Status == 403 {
		add(8, "exposure", "Authentication or restricted endpoint")
	}
	if r.Status >= 500 {
		add(6, "exposure", "Server error response")
	}
	if len(host) > 45 {
		add(10, "phishing", "Unusually long hostname")
	}
	if strings.Count(host, "-") >= 3 {
		add(12, "phishing", "Many hyphens in hostname")
	}
	if strings.Contains(hostLower, "xn--") {
		add(25, "phishing", "Punycode hostname")
	}
	if tokenLike.MatchString(hostLower) || tokenLike.MatchString(urlLower) {
		add(10, "phishing", "Token-like random string")
	}
	if suspiciousTLDs[tld(hostLower)] {
		add(12, "phishing", "Suspicious or abuse-prone TLD")
	}
	for _, h := range shortenerHosts {
		if hostLower == h || strings.HasSuffix(hostLower, "."+h) {
			add(15, "phishing", "URL shortener host")
			break
		}
	}
	for _, h := range freeHostingSignals {
		if strings.HasSuffix(hostLower, h) {
			add(10, "phishing", "Free hosting or disposable app platform")
			break
		}
	}
	for _, brand := range brandTerms {
		if strings.Contains(hostLower, brand) || strings.Contains(titleLower, brand) {
			intel.BrandCandidate = brand
			if !strings.HasSuffix(hostLower, brand+".com") && !strings.HasSuffix(hostLower, brand+".net") {
				add(18, "brand", "Possible brand impersonation: "+brand)
			}
			break
		}
	}
	for _, kw := range r.Keywords {
		switch kw {
		case "login", "portal", "webmail", "cpanel":
			add(8, "credential", "Credential-entry keyword: "+kw)
		case "admin", "dashboard", "console", "manager":
			add(7, "exposure", "Administrative surface keyword: "+kw)
		case "grafana", "jenkins", "gitlab", "jira", "kibana", "vault", "phpmyadmin":
			add(12, "exposure", "Sensitive technology keyword: "+kw)
		}
	}

	detectTech(r, &intel)

	if score > 100 {
		score = 100
	}
	intel.RiskScore = score
	switch {
	case score >= 70:
		intel.RiskLevel = "critical"
	case score >= 45:
		intel.RiskLevel = "high"
	case score >= 20:
		intel.RiskLevel = "medium"
	default:
		intel.RiskLevel = "low"
	}

	if len(intel.Categories) == 0 {
		intel.Categories = []string{"baseline"}
	}
	if len(intel.Indicators) == 0 {
		intel.Indicators = []string{"No high-signal local indicators"}
	}

	r.Intelligence = intel
	r.Interesting = r.Interesting || score >= 20
}

func detectTech(r *models.ScanResult, intel *models.Intel) {
	joined := strings.ToLower(r.Server + " " + r.Title)
	techs := map[string]string{
		"cloudflare": "Cloudflare", "nginx": "nginx", "apache": "Apache",
		"iis": "Microsoft IIS", "wordpress": "WordPress", "grafana": "Grafana",
		"jenkins": "Jenkins", "gitlab": "GitLab", "jira": "Jira", "kibana": "Kibana",
	}
	for needle, label := range techs {
		if strings.Contains(joined, needle) {
			intel.Technologies = append(intel.Technologies, label)
		}
	}
}

func rootDomain(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	parts := strings.Split(strings.Trim(host, "."), ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func tld(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(host, "."), ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
