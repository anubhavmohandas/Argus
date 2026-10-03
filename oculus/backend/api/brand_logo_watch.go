package api

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultBrandWindowDays = 30
	defaultBrandSize       = 100
	defaultVerdictFloor    = 40
)

type brandWatchState struct {
	mu          sync.Mutex
	Hits        []brandLogoHit        `json:"hits"`
	Brands      []brandWatchBrand     `json:"brands"`
	LastRefresh string                `json:"lastRefresh"`
	QueryLog    []brandWatchQueryInfo `json:"queryLog"`
	RateLimit   urlscanRateLimitInfo  `json:"rateLimit"`
}

var brandLogoWatch = brandWatchState{Brands: defaultBrandWatchBrands()}

type brandWatchRefreshRequest struct {
	Brands []brandWatchBrand `json:"brands"`
	Days   int               `json:"days"`
	Size   int               `json:"size"`
}

type brandWatchResponse struct {
	Configured   bool                  `json:"configured"`
	Hits         []brandLogoHit        `json:"hits"`
	Brands       []brandWatchBrand     `json:"brands"`
	LastRefresh  string                `json:"lastRefresh"`
	QueryLog     []brandWatchQueryInfo `json:"queryLog"`
	RateLimit    urlscanRateLimitInfo  `json:"rateLimit"`
	GeneratedAt  string                `json:"generatedAt"`
	DedupeWindow string                `json:"dedupeWindow"`
}

type brandWatchBrand struct {
	Name             string   `json:"name"`
	QueryNames       []string `json:"queryNames"`
	LegitDomains     []string `json:"legitDomains"`
	VerdictThreshold int      `json:"verdictThreshold"`
	PollMinutes      int      `json:"pollMinutes"`
}

type brandWatchQueryInfo struct {
	Brand       string `json:"brand"`
	Mode        string `json:"mode,omitempty"`
	Query       string `json:"query"`
	Total       int    `json:"total"`
	Kept        int    `json:"kept"`
	VisionKept  int    `json:"visionKept,omitempty"`
	VisionError string `json:"visionError,omitempty"`
	Error       string `json:"error,omitempty"`
}

type brandWatchAnalyzeRequest struct {
	Hit brandLogoHit `json:"hit"`
}

type brandWatchAnalyzeResponse struct {
	Configured bool     `json:"configured"`
	Model      string   `json:"model"`
	Summary    string   `json:"summary"`
	Risk       string   `json:"risk"`
	Reasons    []string `json:"reasons"`
	Pivots     []string `json:"pivots"`
	NextSteps  []string `json:"nextSteps"`
}

type brandLogoHit struct {
	ID                string           `json:"id"`
	UUID              string           `json:"uuid"`
	Brand             string           `json:"brand"`
	VisibleBrand      string           `json:"visibleBrand"`
	ClassicBrands     []string         `json:"classicBrands"`
	Confidence        string           `json:"confidence"`
	URL               string           `json:"url"`
	Domain            string           `json:"domain"`
	ApexDomain        string           `json:"apexDomain"`
	IP                string           `json:"ip"`
	ASN               string           `json:"asn"`
	ASNName           string           `json:"asnName"`
	Country           string           `json:"country"`
	Title             string           `json:"title"`
	Screenshot        string           `json:"screenshot"`
	Result            string           `json:"result"`
	ScanTime          string           `json:"scanTime"`
	LiveStatus        int              `json:"liveStatus"`
	DomainAgeDays     int              `json:"domainAgeDays"`
	VerdictScore      int              `json:"verdictScore"`
	URLScanMalicious  bool             `json:"urlscanMalicious"`
	Suspicious        bool             `json:"suspicious"`
	Allowlisted       bool             `json:"allowlisted"`
	AILogoVerified    bool             `json:"aiLogoVerified"`
	AILogoConfidence  float64          `json:"aiLogoConfidence"`
	AILogoReason      string           `json:"aiLogoReason"`
	LogoAssets        []brandLogoAsset `json:"logoAssets"`
	Signals           []string         `json:"signals"`
	LastSeen          string           `json:"lastSeen"`
	FirstSeen         string           `json:"firstSeen"`
	RelatedPivotQuery string           `json:"relatedPivotQuery"`
	RawFields         map[string]any   `json:"rawFields,omitempty"`
}

type brandLogoAsset struct {
	URL      string `json:"url"`
	MimeType string `json:"mimeType"`
	Domain   string `json:"domain"`
}

type urlscanBrandSearchResult struct {
	Task     urlscanTask           `json:"task"`
	Page     urlscanBrandPage      `json:"page"`
	Verdicts urlscanVerdicts       `json:"verdicts"`
	Lists    urlscanLists          `json:"lists"`
	Result   string                `json:"result"`
	Visible  urlscanVisibleSignals `json:"visible"`
	Brand    urlscanBrandSignals   `json:"brand"`
	Stats    map[string]any        `json:"stats,omitempty"`
}

type urlscanBrandSearchResponse struct {
	Total   int                        `json:"total"`
	Results []urlscanBrandSearchResult `json:"results"`
}

type urlscanBrandPage struct {
	URL               string `json:"url"`
	Domain            string `json:"domain"`
	ApexDomain        string `json:"apexDomain"`
	IP                string `json:"ip"`
	ASN               string `json:"asn"`
	ASNName           string `json:"asnname"`
	Country           string `json:"country"`
	Title             string `json:"title"`
	Screenshot        string `json:"screenshot"`
	Status            string `json:"status"`
	ApexDomainAgeDays int    `json:"apexDomainAgeDays"`
	TLSIssuer         string `json:"tlsIssuer"`
}

type urlscanVisibleSignals struct {
	BrandName string `json:"brandname"`
}

type urlscanBrandSignal struct {
	Name string `json:"name"`
}

type urlscanBrandSignals []urlscanBrandSignal

func (signals *urlscanBrandSignals) UnmarshalJSON(data []byte) error {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 || string(data) == "null" {
		*signals = nil
		return nil
	}
	if data[0] == '[' {
		var many []urlscanBrandSignal
		if err := json.Unmarshal(data, &many); err != nil {
			return err
		}
		*signals = many
		return nil
	}
	var one urlscanBrandSignal
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*signals = []urlscanBrandSignal{one}
	return nil
}

func (signals urlscanBrandSignals) Names() []string {
	out := make([]string, 0, len(signals))
	for _, signal := range signals {
		if strings.TrimSpace(signal.Name) != "" {
			out = append(out, signal.Name)
		}
	}
	return uniqueStrings(out)
}

func (h *Handler) BrandLogoWatchStatus(w http.ResponseWriter, r *http.Request) {
	brandLogoWatch.mu.Lock()
	defer brandLogoWatch.mu.Unlock()
	writeJSON(w, http.StatusOK, brandWatchResponse{
		Configured:   urlscanAPIKey() != "",
		Hits:         normalizeBrandHitsForJSON(brandLogoWatch.Hits),
		Brands:       nonNilBrands(brandLogoWatch.Brands),
		LastRefresh:  brandLogoWatch.LastRefresh,
		QueryLog:     nonNilQueryLog(brandLogoWatch.QueryLog),
		RateLimit:    brandLogoWatch.RateLimit,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		DedupeWindow: "24h",
	})
}

func (h *Handler) BrandLogoWatchRefresh(w http.ResponseWriter, r *http.Request) {
	var req brandWatchRefreshRequest
	if err := decodeMaybeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	brands := sanitizeBrandWatchBrands(req.Brands)
	if len(brands) == 0 {
		brandLogoWatch.mu.Lock()
		brands = append([]brandWatchBrand(nil), brandLogoWatch.Brands...)
		brandLogoWatch.mu.Unlock()
	}
	if len(brands) == 0 {
		brands = defaultBrandWatchBrands()
	}

	days := normalizeDays(req.Days)
	if req.Days <= 0 {
		days = defaultBrandWindowDays
	}
	size := normalizeSize(req.Size)
	if req.Size <= 0 {
		size = defaultBrandSize
	}

	hits, queryLog, rate := h.collectBrandLogoHits(r.Context(), brands, days, size)

	brandLogoWatch.mu.Lock()
	merged := mergeBrandHits(removeBrandHits(brandLogoWatch.Hits, brands), hits)
	brandLogoWatch.Hits = merged
	brandLogoWatch.Brands = brands
	brandLogoWatch.LastRefresh = time.Now().UTC().Format(time.RFC3339)
	brandLogoWatch.QueryLog = queryLog
	brandLogoWatch.RateLimit = rate
	resp := brandWatchResponse{
		Configured:   urlscanAPIKey() != "",
		Hits:         normalizeBrandHitsForJSON(brandLogoWatch.Hits),
		Brands:       nonNilBrands(brandLogoWatch.Brands),
		LastRefresh:  brandLogoWatch.LastRefresh,
		QueryLog:     nonNilQueryLog(brandLogoWatch.QueryLog),
		RateLimit:    brandLogoWatch.RateLimit,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		DedupeWindow: "24h",
	}
	brandLogoWatch.mu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) BrandLogoWatchSTIX(w http.ResponseWriter, r *http.Request) {
	brand := strings.TrimSpace(r.URL.Query().Get("brand"))
	confidence := strings.TrimSpace(r.URL.Query().Get("confidence"))
	brandLogoWatch.mu.Lock()
	hits := filterBrandHits(brandLogoWatch.Hits, brand, confidence)
	brandLogoWatch.mu.Unlock()

	bundle := buildBrandSTIXBundle(hits)
	w.Header().Set("Content-Type", "application/stix+json")
	w.Header().Set("Content-Disposition", `attachment; filename="reconvision_brand_logo_watch_stix.json"`)
	_ = json.NewEncoder(w).Encode(bundle)
}

func (h *Handler) BrandLogoWatchAnalyze(w http.ResponseWriter, r *http.Request) {
	var req brandWatchAnalyzeRequest
	if err := decodeMaybeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if openAIAPIKey() == "" {
		writeJSON(w, http.StatusServiceUnavailable, brandWatchAnalyzeResponse{
			Configured: false,
			Summary:    "OPENAI_API_KEY is not configured. Add it to .env and restart run.bat to enable AI analysis.",
		})
		return
	}
	if strings.TrimSpace(req.Hit.URL) == "" && strings.TrimSpace(req.Hit.Domain) == "" {
		http.Error(w, "missing hit evidence", http.StatusBadRequest)
		return
	}
	analysis, err := runOpenAIDomainAnalysis(r.Context(), req.Hit)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

func (h *Handler) collectBrandLogoHits(ctx context.Context, brands []brandWatchBrand, days, size int) ([]brandLogoHit, []brandWatchQueryInfo, urlscanRateLimitInfo) {
	all := []brandLogoHit{}
	logs := []brandWatchQueryInfo{}
	var lastRate urlscanRateLimitInfo
	for _, brand := range brands {
		brandHits := []brandLogoHit{}
		for _, plan := range buildBrandWatchQueries(brand, days) {
			resp, rate, err := h.runBrandWatchSearch(ctx, plan.Query, size)
			lastRate = rate
			info := brandWatchQueryInfo{Brand: brand.Name, Mode: plan.Mode, Query: plan.Query}
			if err != nil {
				info.Error = err.Error()
				logs = append(logs, info)
				continue
			}
			info.Total = resp.Total
			queryHits := []brandLogoHit{}
			for _, result := range resp.Results {
				hit, ok := h.brandHitFromResult(ctx, brand, result)
				if !ok {
					continue
				}
				queryHits = append(queryHits, hit)
			}
			queryHits = dedupeBrandHits(queryHits)
			brandHits = append(brandHits, queryHits...)
			info.Kept = len(queryHits)
			logs = append(logs, info)
		}
		brandHits = dedupeBrandHits(brandHits)
		brandHits, visionErr := h.filterBrandHitsByVision(ctx, brand, brandHits)
		for i := range logs {
			if strings.EqualFold(logs[i].Brand, brand.Name) {
				logs[i].VisionKept = len(brandHits)
				if visionErr != "" {
					logs[i].VisionError = visionErr
				}
			}
		}
		all = append(all, brandHits...)
	}
	return dedupeBrandHits(all), logs, lastRate
}

func (h *Handler) runBrandWatchSearch(ctx context.Context, query string, size int) (*urlscanBrandSearchResponse, urlscanRateLimitInfo, error) {
	return h.runBrandWatchSearchRaw(ctx, query, size)
}

func (h *Handler) runBrandWatchSearchRaw(ctx context.Context, query string, size int) (*urlscanBrandSearchResponse, urlscanRateLimitInfo, error) {
	key := urlscanAPIKey()
	if key == "" {
		return nil, urlscanRateLimitInfo{}, &urlscanHTTPError{StatusCode: http.StatusServiceUnavailable, Message: "URLSCAN_API_KEY is not configured"}
	}
	endpoint, err := url.Parse(urlscanAPIBase + "/search/")
	if err != nil {
		return nil, urlscanRateLimitInfo{}, err
	}
	q := endpoint.Query()
	q.Set("q", query)
	q.Set("size", strconv.Itoa(size))
	endpoint.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, urlscanRateLimitInfo{}, err
	}
	req.Header.Set("API-Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ReconVision/1.0 BrandLogoWatch")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, urlscanRateLimitInfo{}, err
	}
	defer res.Body.Close()
	rate := urlscanRateLimitInfo{
		Limit:     res.Header.Get("X-Rate-Limit-Limit"),
		Remaining: res.Header.Get("X-Rate-Limit-Remaining"),
		Reset:     res.Header.Get("X-Rate-Limit-Reset"),
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, rate, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, rate, &urlscanHTTPError{StatusCode: res.StatusCode, Message: extractURLScanError(body), RateLimit: rate}
	}
	var parsed urlscanBrandSearchResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, rate, err
	}
	return &parsed, rate, nil
}

func (h *Handler) brandHitFromResult(ctx context.Context, brand brandWatchBrand, result urlscanBrandSearchResult) (brandLogoHit, bool) {
	pageURL := firstNonEmpty(result.Page.URL, result.Task.URL)
	domain := strings.ToLower(firstNonEmpty(result.Page.Domain, result.Task.Domain))
	apex := strings.ToLower(firstNonEmpty(result.Page.ApexDomain, rootDomainApprox(domain)))
	uuid := result.Task.UUID
	if uuid == "" {
		uuid = uuidFromResultURL(result.Result)
	}
	screenshot := firstNonEmpty(result.Page.Screenshot, screenshotURL(uuid))
	if pageURL == "" || domain == "" || uuid == "" || screenshot == "" {
		return brandLogoHit{}, false
	}
	if isAllowedDomain(domain, brand.LegitDomains) || isAllowedDomain(apex, brand.LegitDomains) {
		return brandLogoHit{}, false
	}

	visibleBrand := firstNonEmpty(result.Visible.BrandName, getString(result.RawMap(), "visible.brandname"))
	classicBrands := uniqueStrings(append(result.Verdicts.Overall.Brands, result.Verdicts.URLScan.Brands...))
	classicBrands = uniqueStrings(append(classicBrands, result.Brand.Names()...))
	if len(classicBrands) == 0 {
		classicBrands = result.PageBrands()
	}
	visibleMatch := brandMatches(brand, visibleBrand)
	classicMatch := anyBrandMatches(brand, classicBrands)
	if visibleBrand == "" || !visibleMatch {
		return brandLogoHit{}, false
	}

	score := result.Verdicts.Overall.Score
	if score < result.Verdicts.URLScan.Score {
		score = result.Verdicts.URLScan.Score
	}
	threshold := brand.VerdictThreshold
	if threshold <= 0 {
		threshold = defaultVerdictFloor
	}
	urlscanMalicious := result.Verdicts.URLScan.Malicious

	status := 0
	if strings.TrimSpace(result.Page.Status) == "200" {
		status = http.StatusOK
	}
	if status != http.StatusOK {
		status = verifyLiveStatus(ctx, pageURL)
	}
	if status != http.StatusOK {
		return brandLogoHit{}, false
	}

	confidence := "visual"
	if visibleMatch && classicMatch {
		confidence = "high"
	}
	age := result.Page.ApexDomainAgeDays
	signals := []string{}
	if visibleMatch {
		signals = append(signals, "visible.brandname match")
	}
	if classicMatch {
		signals = append(signals, "brand.name/verdict brand match")
	}
	if age > 0 && age < 90 {
		signals = append(signals, "young apex domain")
	}
	if urlscanMalicious {
		signals = append(signals, "urlscan malicious verdict")
	}
	if score >= threshold {
		signals = append(signals, fmt.Sprintf("verdict score %d", score))
	} else if !urlscanMalicious {
		signals = append(signals, "visual logo match without URLScan malicious verdict")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	return brandLogoHit{
		ID:                brandHitID(apex, brand.Name, result.Task.Time),
		UUID:              uuid,
		Brand:             brand.Name,
		VisibleBrand:      visibleBrand,
		ClassicBrands:     classicBrands,
		Confidence:        confidence,
		URL:               pageURL,
		Domain:            domain,
		ApexDomain:        apex,
		IP:                result.Page.IP,
		ASN:               result.Page.ASN,
		ASNName:           result.Page.ASNName,
		Country:           result.Page.Country,
		Title:             result.Page.Title,
		Screenshot:        screenshot,
		Result:            firstNonEmpty(result.Result, "https://urlscan.io/result/"+uuid+"/"),
		ScanTime:          firstNonEmpty(result.Task.Time, now),
		LiveStatus:        status,
		DomainAgeDays:     age,
		VerdictScore:      score,
		URLScanMalicious:  urlscanMalicious,
		Suspicious:        result.Verdicts.Overall.Suspicious || result.Verdicts.URLScan.Suspicious,
		LogoAssets:        []brandLogoAsset{},
		Signals:           signals,
		FirstSeen:         firstNonEmpty(result.Task.Time, now),
		LastSeen:          now,
		RelatedPivotQuery: buildRelatedInfraQuery(result.Page.ASN, result.Page.TLSIssuer),
	}, true
}

func (r urlscanBrandSearchResult) RawMap() map[string]any {
	body, _ := json.Marshal(r)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return out
}

func (r urlscanBrandSearchResult) PageBrands() []string {
	values := []string{}
	values = append(values, r.Brand.Names()...)
	return uniqueStrings(values)
}

func (h *Handler) fetchLogoAssets(ctx context.Context, uuid string, brand brandWatchBrand) []brandLogoAsset {
	if uuid == "" || urlscanAPIKey() == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlscanAPIBase+"/result/"+uuid+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("API-Key", urlscanAPIKey())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ReconVision/1.0 BrandLogoWatch")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil
	}
	var payload struct {
		Data struct {
			Requests []struct {
				Request struct {
					URL string `json:"url"`
				} `json:"request"`
				Response struct {
					MimeType string `json:"mimeType"`
				} `json:"response"`
			} `json:"requests"`
		} `json:"data"`
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 12<<20))
	if err != nil || json.Unmarshal(body, &payload) != nil {
		return nil
	}
	terms := []string{"logo", "brand", "favicon", strings.ToLower(brand.Name)}
	for _, alias := range brand.QueryNames {
		terms = append(terms, strings.ToLower(alias))
	}
	out := []brandLogoAsset{}
	seen := map[string]bool{}
	for _, item := range payload.Data.Requests {
		assetURL := item.Request.URL
		mime := item.Response.MimeType
		lower := strings.ToLower(assetURL)
		if assetURL == "" || !strings.HasPrefix(strings.ToLower(mime), "image/") {
			continue
		}
		matched := false
		for _, term := range terms {
			if term != "" && strings.Contains(lower, term) {
				matched = true
				break
			}
		}
		if !matched || seen[assetURL] {
			continue
		}
		seen[assetURL] = true
		assetDomain := ""
		if parsed, err := url.Parse(assetURL); err == nil {
			assetDomain = parsed.Hostname()
		}
		out = append(out, brandLogoAsset{URL: assetURL, MimeType: mime, Domain: assetDomain})
		if len(out) >= 10 {
			break
		}
	}
	return out
}

type logoVisionVerdict struct {
	ID         string  `json:"id"`
	HasLogo    bool    `json:"hasLogo"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

func (h *Handler) filterBrandHitsByVision(ctx context.Context, brand brandWatchBrand, hits []brandLogoHit) ([]brandLogoHit, string) {
	if len(hits) == 0 {
		return hits, ""
	}
	if openAIAPIKey() == "" {
		for i := range hits {
			hits[i].Signals = append(hits[i].Signals, "AI logo verification unavailable")
		}
		return hits, "OPENAI_API_KEY is not configured"
	}
	const batchSize = 8
	verified := []brandLogoHit{}
	errors := []string{}
	attempted := 0
	for start := 0; start < len(hits); start += batchSize {
		end := start + batchSize
		if end > len(hits) {
			end = len(hits)
		}
		attempted++
		verdicts, err := verifyBrandScreenshotsWithOpenAI(ctx, brand, hits[start:end])
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		for _, hit := range hits[start:end] {
			verdict, ok := verdicts[hit.ID]
			if !ok || !verdict.HasLogo || verdict.Confidence < 0.72 {
				continue
			}
			hit.AILogoVerified = true
			hit.AILogoConfidence = verdict.Confidence
			hit.AILogoReason = verdict.Reason
			hit.Signals = append(hit.Signals, fmt.Sprintf("AI visual logo verified %.0f%%", verdict.Confidence*100))
			if strings.TrimSpace(verdict.Reason) != "" {
				hit.Signals = append(hit.Signals, verdict.Reason)
			}
			verified = append(verified, hit)
		}
	}
	if len(verified) == 0 && attempted > 0 && len(errors) == attempted {
		for i := range hits {
			hits[i].Signals = append(hits[i].Signals, "AI logo verification unavailable; showing URLScan visual match")
		}
		return hits, firstNonEmpty(strings.Join(uniqueStrings(errors), "; "), "AI logo verification failed")
	}
	return verified, strings.Join(uniqueStrings(errors), "; ")
}

func verifyBrandScreenshotsWithOpenAI(ctx context.Context, brand brandWatchBrand, hits []brandLogoHit) (map[string]logoVisionVerdict, error) {
	content := []map[string]any{}
	aliases := uniqueStrings(append(brand.QueryNames, brand.Name))
	lines := []string{
		"You are verifying URLScan screenshot evidence for a defensive brand-impersonation feed.",
		"Only mark hasLogo true when the screenshot visibly contains the requested brand logo, wordmark, or unmistakable brand login/product UI.",
		"Return compact JSON only: {\"verdicts\":[{\"id\":\"...\",\"hasLogo\":true,\"confidence\":0.0,\"reason\":\"...\"}]}",
		"Reject blank pages, loading/redirect pages, generic forms, unrelated brands, or pages where the brand is only in the URL/domain.",
		"Brand to verify: " + brand.Name,
		"Allowed aliases/wordmarks: " + strings.Join(aliases, ", "),
		"Items:",
	}
	for _, hit := range hits {
		lines = append(lines, fmt.Sprintf("- id=%s domain=%s title=%s", hit.ID, hit.Domain, hit.Title))
	}
	content = append(content, map[string]any{"type": "input_text", "text": strings.Join(lines, "\n")})
	for _, hit := range hits {
		content = append(content, map[string]any{"type": "input_text", "text": fmt.Sprintf("Screenshot for id=%s domain=%s", hit.ID, hit.Domain)})
		imageURL := hit.Screenshot
		if dataURL := fetchImageDataURL(ctx, hit.Screenshot); dataURL != "" {
			imageURL = dataURL
		}
		content = append(content, map[string]any{"type": "input_image", "image_url": imageURL})
	}
	payload := map[string]any{
		"model": openAIModel(),
		"input": []map[string]any{{
			"role":    "user",
			"content": content,
		}},
		"max_output_tokens": 1200,
		"store":             false,
	}
	body, _ := json.Marshal(payload)
	reqCtx, cancel := context.WithTimeout(ctx, 70*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "https://api.openai.com/v1/responses", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+openAIAPIKey())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ReconVision/1.0 LogoVisionVerify")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(io.LimitReader(res.Body, 6<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("OpenAI logo verification failed: %s", extractURLScanError(resBody))
	}
	text := stripJSONFence(extractOpenAIOutputText(resBody))
	var parsed struct {
		Verdicts []logoVisionVerdict `json:"verdicts"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return nil, fmt.Errorf("OpenAI logo verification parse failed: %w", err)
	}
	out := map[string]logoVisionVerdict{}
	for _, verdict := range parsed.Verdicts {
		if verdict.ID != "" {
			out[verdict.ID] = verdict
		}
	}
	return out, nil
}

func fetchImageDataURL(ctx context.Context, imageURL string) string {
	if strings.TrimSpace(imageURL) == "" {
		return ""
	}
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, imageURL, nil)
	if err != nil {
		return ""
	}
	if urlscanAPIKey() != "" && strings.Contains(imageURL, "urlscan.io/") {
		req.Header.Set("API-Key", urlscanAPIKey())
	}
	req.Header.Set("Accept", "image/png,image/jpeg,image/webp,*/*")
	req.Header.Set("User-Agent", "ReconVision/1.0 screenshot fetcher")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return ""
	}
	contentType := res.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(contentType), "image/") {
		contentType = "image/png"
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 5<<20))
	if err != nil || len(body) == 0 {
		return ""
	}
	return "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(body)
}

func buildBrandWatchQuery(queryName string, brand brandWatchBrand, days int) string {
	return buildBrandWatchQueryWithField("visible.brandname", queryName, brand, days)
}

type brandWatchQueryPlan struct {
	Mode  string
	Query string
}

func buildBrandWatchQueries(brand brandWatchBrand, days int) []brandWatchQueryPlan {
	names := uniqueStrings(append(brand.QueryNames, brand.Name))
	if len(names) == 0 {
		names = []string{brand.Name}
	}
	plans := []brandWatchQueryPlan{}
	seen := map[string]bool{}
	add := func(mode, query string) {
		if query == "" || seen[query] {
			return
		}
		seen[query] = true
		plans = append(plans, brandWatchQueryPlan{Mode: mode, Query: query})
	}
	primary := firstNonEmpty(names[0], brand.Name)
	add("visual exact", buildBrandWatchQueryWithField("visible.brandname", primary, brand, days))
	for _, name := range names[1:] {
		add("visual alias", buildBrandWatchQueryWithField("visible.brandname", name, brand, days))
	}
	lowerPrimary := strings.ToLower(primary)
	if lowerPrimary != primary {
		add("visual lowercase", buildBrandWatchQueryWithField("visible.brandname", lowerPrimary, brand, days))
	}
	add("classic assisted", buildBrandWatchQueryWithField("brand.name", primary, brand, days))
	return plans
}

func buildBrandWatchQueryWithField(field, queryName string, brand brandWatchBrand, days int) string {
	allow := make([]string, 0, len(brand.LegitDomains))
	for _, domain := range brand.LegitDomains {
		clean := strings.TrimSpace(strings.ToLower(domain))
		if clean != "" {
			allow = append(allow, clean)
		}
	}
	notClause := ""
	if len(allow) > 0 {
		notClause = " AND NOT page.domain:(" + strings.Join(allow, " OR ") + ")"
	}
	return fmt.Sprintf(`%s:%s AND page.status:200 AND task.visibility:public AND date:>now-%dd%s`,
		field,
		quoteURLScanValue(queryName),
		days,
		notClause,
	)
}

func verifyLiveStatus(ctx context.Context, target string) int {
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "ReconVision/1.0 live verifier")
	client := &http.Client{Timeout: 7 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	res, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer res.Body.Close()
	return res.StatusCode
}

func defaultBrandWatchBrands() []brandWatchBrand {
	return []brandWatchBrand{
		{Name: "PayPal", QueryNames: []string{"PayPal", "paypal"}, LegitDomains: []string{"paypal.com", "paypalobjects.com", "paypal-corp.com", "paypal-community.com", "paypal.me", "braintreepayments.com"}, VerdictThreshold: defaultVerdictFloor, PollMinutes: 15},
		{Name: "Revolut", QueryNames: []string{"Revolut", "revolut"}, LegitDomains: []string{"revolut.com", "revolut.codes", "revolut.me"}, VerdictThreshold: defaultVerdictFloor, PollMinutes: 15},
		{Name: "OpenAI", QueryNames: []string{"OpenAI", "ChatGPT", "chatgpt"}, LegitDomains: []string{"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "auth0.openai.com"}, VerdictThreshold: defaultVerdictFloor, PollMinutes: 15},
		{Name: "Netflix", QueryNames: []string{"Netflix", "netflix"}, LegitDomains: []string{"netflix.com", "netflix.net", "nflxext.com", "nflximg.net", "nflxso.net", "nflxvideo.net"}, VerdictThreshold: defaultVerdictFloor, PollMinutes: 15},
	}
}

func sanitizeBrandWatchBrands(brands []brandWatchBrand) []brandWatchBrand {
	out := []brandWatchBrand{}
	for _, brand := range brands {
		brand.Name = strings.TrimSpace(brand.Name)
		if brand.Name == "" {
			continue
		}
		brand.QueryNames = uniqueStrings(append(brand.QueryNames, brand.Name))
		brand.LegitDomains = uniqueStrings(lowerStrings(brand.LegitDomains))
		if brand.VerdictThreshold <= 0 {
			brand.VerdictThreshold = defaultVerdictFloor
		}
		if brand.PollMinutes <= 0 {
			brand.PollMinutes = 15
		}
		out = append(out, brand)
	}
	return out
}

func lowerStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.ToLower(strings.TrimSpace(value)))
	}
	return out
}

func brandMatches(brand brandWatchBrand, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	for _, name := range append(brand.QueryNames, brand.Name) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" && (value == name || strings.Contains(value, name) || strings.Contains(name, value)) {
			return true
		}
	}
	return false
}

func anyBrandMatches(brand brandWatchBrand, values []string) bool {
	for _, value := range values {
		if brandMatches(brand, value) {
			return true
		}
	}
	return false
}

func isAllowedDomain(domain string, allowlist []string) bool {
	domain = strings.Trim(strings.ToLower(domain), ".")
	for _, allowed := range allowlist {
		allowed = strings.Trim(strings.ToLower(allowed), ".")
		if allowed == "" {
			continue
		}
		if domain == allowed || strings.HasSuffix(domain, "."+allowed) {
			return true
		}
	}
	return false
}

func brandHitID(apex, brand, scanTime string) string {
	day := time.Now().UTC().Format("2006-01-02")
	if parsed, err := time.Parse(time.RFC3339, scanTime); err == nil {
		day = parsed.UTC().Format("2006-01-02")
	}
	sum := sha1.Sum([]byte(strings.ToLower(apex + "|" + brand + "|" + day)))
	return hex.EncodeToString(sum[:])[:16]
}

func dedupeBrandHits(hits []brandLogoHit) []brandLogoHit {
	byID := map[string]brandLogoHit{}
	for _, hit := range hits {
		existing, ok := byID[hit.ID]
		if !ok || hit.ScanTime > existing.ScanTime {
			if ok && existing.FirstSeen != "" {
				hit.FirstSeen = existing.FirstSeen
			}
			byID[hit.ID] = hit
		}
	}
	out := make([]brandLogoHit, 0, len(byID))
	for _, hit := range byID {
		out = append(out, hit)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence == out[j].Confidence {
			return out[i].ScanTime > out[j].ScanTime
		}
		return out[i].Confidence == "high"
	})
	return out
}

func mergeBrandHits(existing, incoming []brandLogoHit) []brandLogoHit {
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	all := append(append([]brandLogoHit{}, existing...), incoming...)
	filtered := []brandLogoHit{}
	for _, hit := range all {
		t, err := time.Parse(time.RFC3339, firstNonEmpty(hit.LastSeen, hit.ScanTime))
		if err == nil && t.Before(cutoff) {
			continue
		}
		filtered = append(filtered, hit)
	}
	return dedupeBrandHits(filtered)
}

func removeBrandHits(existing []brandLogoHit, refreshedBrands []brandWatchBrand) []brandLogoHit {
	if len(existing) == 0 || len(refreshedBrands) == 0 {
		return existing
	}
	refreshed := map[string]bool{}
	for _, brand := range refreshedBrands {
		name := strings.ToLower(strings.TrimSpace(brand.Name))
		if name != "" {
			refreshed[name] = true
		}
	}
	out := make([]brandLogoHit, 0, len(existing))
	for _, hit := range existing {
		if !refreshed[strings.ToLower(strings.TrimSpace(hit.Brand))] {
			out = append(out, hit)
		}
	}
	return out
}

func filterBrandHits(hits []brandLogoHit, brand, confidence string) []brandLogoHit {
	out := []brandLogoHit{}
	for _, hit := range hits {
		if brand != "" && !strings.EqualFold(hit.Brand, brand) {
			continue
		}
		if confidence != "" && confidence != "all" && hit.Confidence != confidence {
			continue
		}
		out = append(out, hit)
	}
	return out
}

func normalizeBrandHitsForJSON(hits []brandLogoHit) []brandLogoHit {
	if hits == nil {
		return []brandLogoHit{}
	}
	out := make([]brandLogoHit, 0, len(hits))
	for _, hit := range hits {
		if hit.ClassicBrands == nil {
			hit.ClassicBrands = []string{}
		}
		if hit.LogoAssets == nil {
			hit.LogoAssets = []brandLogoAsset{}
		}
		if hit.Signals == nil {
			hit.Signals = []string{}
		}
		out = append(out, hit)
	}
	return out
}

func nonNilBrands(brands []brandWatchBrand) []brandWatchBrand {
	if brands == nil {
		return []brandWatchBrand{}
	}
	return brands
}

func nonNilQueryLog(logs []brandWatchQueryInfo) []brandWatchQueryInfo {
	if logs == nil {
		return []brandWatchQueryInfo{}
	}
	return logs
}

func screenshotURL(uuid string) string {
	if uuid == "" {
		return ""
	}
	return "https://urlscan.io/screenshots/" + uuid + ".png"
}

func openAIAPIKey() string {
	return strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
}

func openAIModel() string {
	return firstNonEmpty(strings.TrimSpace(os.Getenv("OPENAI_MODEL")), "gpt-5-mini")
}

func runOpenAIDomainAnalysis(ctx context.Context, hit brandLogoHit) (brandWatchAnalyzeResponse, error) {
	model := openAIModel()
	prompt := fmt.Sprintf(`You are a defensive CTI analyst reviewing a URLScan logo-impersonation hit.
Return compact JSON only with keys: summary string, risk string, reasons string array, pivots string array, nextSteps string array.
Focus on evidence, false-positive risk, defensive pivots, and authorized bug bounty/CTI workflow. Do not provide phishing instructions.

Brand: %s
Visible logo brand: %s
Classic brands: %s
URL: %s
Domain: %s
Apex domain: %s
IP: %s
ASN: %s %s
Country: %s
Title: %s
Live status: %d
Domain age days: %d
URLScan score: %d
URLScan malicious: %t
Signals: %s
Logo asset URLs: %s
Related infra pivot query: %s`,
		hit.Brand,
		hit.VisibleBrand,
		strings.Join(hit.ClassicBrands, ", "),
		hit.URL,
		hit.Domain,
		hit.ApexDomain,
		hit.IP,
		hit.ASN,
		hit.ASNName,
		hit.Country,
		hit.Title,
		hit.LiveStatus,
		hit.DomainAgeDays,
		hit.VerdictScore,
		hit.URLScanMalicious,
		strings.Join(hit.Signals, "; "),
		strings.Join(brandAssetURLs(hit.LogoAssets), "\n"),
		hit.RelatedPivotQuery,
	)
	payload := map[string]any{
		"model":             model,
		"input":             prompt,
		"max_output_tokens": 700,
		"store":             false,
	}
	body, _ := json.Marshal(payload)
	reqCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "https://api.openai.com/v1/responses", bytes.NewReader(body))
	if err != nil {
		return brandWatchAnalyzeResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+openAIAPIKey())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ReconVision/1.0 DomainAnalysis")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return brandWatchAnalyzeResponse{}, err
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return brandWatchAnalyzeResponse{}, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return brandWatchAnalyzeResponse{}, fmt.Errorf("OpenAI analysis failed: %s", extractURLScanError(resBody))
	}
	text := extractOpenAIOutputText(resBody)
	if text == "" {
		return brandWatchAnalyzeResponse{}, fmt.Errorf("OpenAI analysis returned no text")
	}
	var parsed struct {
		Summary   string   `json:"summary"`
		Risk      string   `json:"risk"`
		Reasons   []string `json:"reasons"`
		Pivots    []string `json:"pivots"`
		NextSteps []string `json:"nextSteps"`
	}
	if err := json.Unmarshal([]byte(stripJSONFence(text)), &parsed); err != nil {
		parsed.Summary = text
		parsed.Risk = "review"
	}
	return brandWatchAnalyzeResponse{
		Configured: true,
		Model:      model,
		Summary:    parsed.Summary,
		Risk:       firstNonEmpty(parsed.Risk, "review"),
		Reasons:    parsed.Reasons,
		Pivots:     parsed.Pivots,
		NextSteps:  parsed.NextSteps,
	}, nil
}

func extractOpenAIOutputText(body []byte) string {
	var payload struct {
		OutputText string `json:"output_text"`
		Output     []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	if strings.TrimSpace(payload.OutputText) != "" {
		return strings.TrimSpace(payload.OutputText)
	}
	for _, item := range payload.Output {
		for _, content := range item.Content {
			if strings.TrimSpace(content.Text) != "" {
				return strings.TrimSpace(content.Text)
			}
		}
	}
	return ""
}

func stripJSONFence(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "```json")
	value = strings.TrimPrefix(value, "```")
	value = strings.TrimSuffix(value, "```")
	return strings.TrimSpace(value)
}

func brandAssetURLs(assets []brandLogoAsset) []string {
	out := make([]string, 0, len(assets))
	for _, asset := range assets {
		if strings.TrimSpace(asset.URL) != "" {
			out = append(out, asset.URL)
		}
	}
	return out
}

func uuidFromResultURL(value string) string {
	value = strings.TrimRight(value, "/")
	parts := strings.Split(value, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func rootDomainApprox(domain string) string {
	domain = strings.Trim(strings.ToLower(domain), ".")
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func buildRelatedInfraQuery(asn, tlsIssuer string) string {
	parts := []string{}
	if asn != "" {
		parts = append(parts, "page.asn:"+quoteURLScanValue(strings.TrimPrefix(strings.ToUpper(asn), "AS")))
	}
	if tlsIssuer != "" {
		parts = append(parts, "page.tlsIssuer:"+quoteURLScanValue(tlsIssuer))
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, " AND ") + ") AND date:>now-7d"
}

func getString(payload map[string]any, dotted string) string {
	var current any = payload
	for _, part := range strings.Split(dotted, ".") {
		obj, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = obj[part]
	}
	if s, ok := current.(string); ok {
		return s
	}
	return ""
}

func buildBrandSTIXBundle(hits []brandLogoHit) map[string]any {
	now := time.Now().UTC().Format(time.RFC3339)
	objects := []map[string]any{}
	for _, hit := range hits {
		identityID := "identity--" + stixUUID(hit.Brand)
		indicatorID := "indicator--" + stixUUID(hit.ID+"indicator")
		urlID := "url--" + stixUUID(hit.URL)
		sightingID := "sighting--" + stixUUID(hit.ID+"sighting")
		objects = append(objects,
			map[string]any{"type": "identity", "spec_version": "2.1", "id": identityID, "created": now, "modified": now, "name": hit.Brand, "identity_class": "organization"},
			map[string]any{"type": "url", "spec_version": "2.1", "id": urlID, "value": hit.URL},
			map[string]any{
				"type": "indicator", "spec_version": "2.1", "id": indicatorID, "created": now, "modified": now,
				"name":         fmt.Sprintf("%s logo impersonation: %s", hit.Brand, hit.ApexDomain),
				"description":  strings.Join(hit.Signals, "; "),
				"pattern":      fmt.Sprintf("[url:value = '%s']", strings.ReplaceAll(hit.URL, "'", "\\'")),
				"pattern_type": "stix", "valid_from": now,
				"labels": []string{"phishing", "brand-impersonation", hit.Confidence},
			},
			map[string]any{
				"type": "sighting", "spec_version": "2.1", "id": sightingID, "created": now, "modified": now,
				"sighting_of_ref": indicatorID, "where_sighted_refs": []string{identityID}, "observed_data_refs": []string{urlID}, "count": 1,
				"first_seen": hit.FirstSeen, "last_seen": hit.LastSeen,
			},
		)
	}
	return map[string]any{"type": "bundle", "id": "bundle--" + stixUUID(now), "objects": objects}
}

func stixUUID(seed string) string {
	sum := sha1.Sum([]byte(seed))
	hexed := hex.EncodeToString(sum[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexed[0:8], hexed[8:12], hexed[12:16], hexed[16:20], hexed[20:32])
}

func hostFromURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(host)
}
