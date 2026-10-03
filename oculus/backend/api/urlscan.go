package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	urlscanAPIBase     = "https://urlscan.io/api/v1"
	defaultPivotDays   = 7
	defaultPivotSize   = 25
	maxPivotSize       = 100
	maxPivotIndicators = 8
)

type urlscanStatusResponse struct {
	Configured bool `json:"configured"`
}

type urlscanSearchRequest struct {
	Query string `json:"query"`
	Type  string `json:"type"`
	Value string `json:"value"`
	Days  int    `json:"days"`
	Size  int    `json:"size"`
}

type urlscanPivotRequest struct {
	Indicator string `json:"indicator"`
	Type      string `json:"type"`
	Days      int    `json:"days"`
	Size      int    `json:"size"`
}

type urlscanSearchResponse struct {
	Total        int                  `json:"total"`
	Took         int                  `json:"took"`
	HasMore      bool                 `json:"has_more"`
	Results      []urlscanResult      `json:"results"`
	Raw          map[string]any       `json:"raw,omitempty"`
	RateLimit    urlscanRateLimitInfo `json:"rateLimit"`
	Query        string               `json:"query"`
	ResultSource string               `json:"resultSource"`
}

type urlscanPivotResponse struct {
	Indicator  string                  `json:"indicator"`
	Type       string                  `json:"type"`
	Days       int                     `json:"days"`
	Query      string                  `json:"query"`
	Total      int                     `json:"total"`
	Results    []urlscanPivotHit       `json:"results"`
	Clusters   urlscanPivotClusters    `json:"clusters"`
	NextPivots []urlscanPivotIndicator `json:"nextPivots"`
	RateLimit  urlscanRateLimitInfo    `json:"rateLimit"`
}

type urlscanPivotHit struct {
	Time        string   `json:"time"`
	Domain      string   `json:"domain"`
	IP          string   `json:"ip"`
	ASN         string   `json:"asn"`
	ASNName     string   `json:"asnName"`
	URL         string   `json:"url"`
	Title       string   `json:"title"`
	Country     string   `json:"country"`
	Screenshot  string   `json:"screenshot"`
	Result      string   `json:"result"`
	Malicious   bool     `json:"malicious"`
	Suspicious  bool     `json:"suspicious"`
	Brands      []string `json:"brands"`
	RelatedTags []string `json:"relatedTags"`
}

type urlscanPivotClusters struct {
	Domains []urlscanClusterItem `json:"domains"`
	IPs     []urlscanClusterItem `json:"ips"`
	ASNs    []urlscanClusterItem `json:"asns"`
	Brands  []urlscanClusterItem `json:"brands"`
}

type urlscanClusterItem struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type urlscanPivotIndicator struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Count int    `json:"count"`
	Query string `json:"query"`
}

type urlscanRateLimitInfo struct {
	Limit     string `json:"limit,omitempty"`
	Remaining string `json:"remaining,omitempty"`
	Reset     string `json:"reset,omitempty"`
}

type urlscanResult struct {
	Task     urlscanTask     `json:"task"`
	Page     urlscanPage     `json:"page"`
	Verdicts urlscanVerdicts `json:"verdicts"`
	Lists    urlscanLists    `json:"lists"`
	Result   string          `json:"result"`
	Stats    map[string]any  `json:"stats,omitempty"`
}

type urlscanTask struct {
	Time       string   `json:"time"`
	URL        string   `json:"url"`
	Domain     string   `json:"domain"`
	UUID       string   `json:"uuid"`
	Visibility string   `json:"visibility"`
	Tags       []string `json:"tags"`
}

type urlscanPage struct {
	URL        string   `json:"url"`
	Domain     string   `json:"domain"`
	IP         string   `json:"ip"`
	ASN        string   `json:"asn"`
	ASNName    string   `json:"asnname"`
	Country    string   `json:"country"`
	Server     string   `json:"server"`
	Title      string   `json:"title"`
	Screenshot string   `json:"screenshot"`
	Brands     []string `json:"brands"`
}

type urlscanVerdicts struct {
	Overall urlscanVerdict `json:"overall"`
	URLScan urlscanVerdict `json:"urlscan"`
	Engines urlscanVerdict `json:"engines"`
}

type urlscanVerdict struct {
	Score      int      `json:"score"`
	Malicious  bool     `json:"malicious"`
	Suspicious bool     `json:"suspicious"`
	Brands     []string `json:"brands"`
	Tags       []string `json:"tags"`
}

type urlscanLists struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
	ASNs    []string `json:"asns"`
	Hashes  []string `json:"hashes"`
	URLs    []string `json:"urls"`
	Servers []string `json:"servers"`
}

func (h *Handler) URLScanStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, urlscanStatusResponse{Configured: urlscanAPIKey() != ""})
}

func (h *Handler) URLScanSearch(w http.ResponseWriter, r *http.Request) {
	var req urlscanSearchRequest
	if err := decodeMaybeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Query == "" && req.Type != "" && req.Value != "" {
		req.Query = buildURLScanQuery(req.Type, req.Value, req.Days)
	}
	if strings.TrimSpace(req.Query) == "" {
		http.Error(w, "missing URLScan query", http.StatusBadRequest)
		return
	}

	resp, err := h.runURLScanSearch(r.Context(), req.Query, normalizeSize(req.Size))
	if err != nil {
		writeURLScanError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) URLScanPivot(w http.ResponseWriter, r *http.Request) {
	var req urlscanPivotRequest
	if err := decodeMaybeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	req.Indicator = cleanURLScanIndicator(req.Type, req.Indicator)
	if req.Type == "" || req.Indicator == "" {
		http.Error(w, "missing pivot type or indicator", http.StatusBadRequest)
		return
	}

	req.Days = normalizeDays(req.Days)
	req.Size = normalizeSize(req.Size)
	query := buildURLScanQuery(req.Type, req.Indicator, req.Days)

	searchResp, err := h.runURLScanSearch(r.Context(), query, req.Size)
	if err != nil {
		writeURLScanError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, buildPivotResponse(req, query, searchResp))
}

func (h *Handler) runURLScanSearch(ctx context.Context, query string, size int) (*urlscanSearchResponse, error) {
	key := urlscanAPIKey()
	if key == "" {
		return nil, &urlscanHTTPError{StatusCode: http.StatusServiceUnavailable, Message: "URLSCAN_API_KEY is not configured"}
	}

	endpoint, err := url.Parse(urlscanAPIBase + "/search/")
	if err != nil {
		return nil, err
	}
	q := endpoint.Query()
	q.Set("q", query)
	q.Set("size", strconv.Itoa(size))
	endpoint.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("API-Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ReconVision/1.0")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	rate := urlscanRateLimitInfo{
		Limit:     res.Header.Get("X-Rate-Limit-Limit"),
		Remaining: res.Header.Get("X-Rate-Limit-Remaining"),
		Reset:     res.Header.Get("X-Rate-Limit-Reset"),
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, &urlscanHTTPError{StatusCode: res.StatusCode, Message: extractURLScanError(body), RateLimit: rate}
	}

	var parsed urlscanSearchResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	parsed.Query = query
	parsed.ResultSource = "urlscan.io"
	parsed.RateLimit = rate
	return &parsed, nil
}

func buildPivotResponse(req urlscanPivotRequest, query string, searchResp *urlscanSearchResponse) urlscanPivotResponse {
	domainCounts := map[string]int{}
	ipCounts := map[string]int{}
	asnCounts := map[string]int{}
	brandCounts := map[string]int{}
	hits := make([]urlscanPivotHit, 0, len(searchResp.Results))

	for _, result := range searchResp.Results {
		hit := urlscanPivotHit{
			Time:        firstNonEmpty(result.Task.Time),
			Domain:      firstNonEmpty(result.Page.Domain, result.Task.Domain),
			IP:          result.Page.IP,
			ASN:         firstNonEmpty(result.Page.ASN),
			ASNName:     result.Page.ASNName,
			URL:         firstNonEmpty(result.Page.URL, result.Task.URL),
			Title:       result.Page.Title,
			Country:     result.Page.Country,
			Screenshot:  result.Page.Screenshot,
			Result:      result.Result,
			Malicious:   result.Verdicts.Overall.Malicious || result.Verdicts.URLScan.Malicious || result.Verdicts.Engines.Malicious,
			Suspicious:  result.Verdicts.Overall.Suspicious || result.Verdicts.URLScan.Suspicious || result.Verdicts.Engines.Suspicious,
			Brands:      uniqueStrings(append(append(result.Page.Brands, result.Verdicts.Overall.Brands...), result.Verdicts.URLScan.Brands...)),
			RelatedTags: uniqueStrings(append(append(result.Task.Tags, result.Verdicts.Overall.Tags...), result.Verdicts.URLScan.Tags...)),
		}
		hits = append(hits, hit)

		addCount(domainCounts, hit.Domain)
		for _, domain := range result.Lists.Domains {
			addCount(domainCounts, domain)
		}
		addCount(ipCounts, hit.IP)
		for _, ip := range result.Lists.IPs {
			addCount(ipCounts, ip)
		}
		addCount(asnCounts, hit.ASN)
		for _, asn := range result.Lists.ASNs {
			addCount(asnCounts, asn)
		}
		for _, brand := range hit.Brands {
			addCount(brandCounts, brand)
		}
	}

	clusters := urlscanPivotClusters{
		Domains: topClusterItems(domainCounts, 12),
		IPs:     topClusterItems(ipCounts, 12),
		ASNs:    topClusterItems(asnCounts, 10),
		Brands:  topClusterItems(brandCounts, 10),
	}

	return urlscanPivotResponse{
		Indicator:  req.Indicator,
		Type:       req.Type,
		Days:       req.Days,
		Query:      query,
		Total:      searchResp.Total,
		Results:    hits,
		Clusters:   clusters,
		NextPivots: buildNextPivots(req, clusters),
		RateLimit:  searchResp.RateLimit,
	}
}

func buildNextPivots(req urlscanPivotRequest, clusters urlscanPivotClusters) []urlscanPivotIndicator {
	var out []urlscanPivotIndicator
	appendPivot := func(kind string, item urlscanClusterItem) {
		if len(out) >= maxPivotIndicators || item.Value == "" || item.Value == req.Indicator {
			return
		}
		out = append(out, urlscanPivotIndicator{
			Type:  kind,
			Value: item.Value,
			Count: item.Count,
			Query: buildURLScanQuery(kind, item.Value, req.Days),
		})
	}
	for _, item := range clusters.Domains {
		appendPivot("domain", item)
	}
	for _, item := range clusters.IPs {
		appendPivot("ip", item)
	}
	for _, item := range clusters.ASNs {
		appendPivot("asn", item)
	}
	for _, item := range clusters.Brands {
		appendPivot("brand", item)
	}
	return out
}

func buildURLScanQuery(kind, value string, days int) string {
	days = normalizeDays(days)
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = cleanURLScanIndicator(kind, value)
	dateClause := fmt.Sprintf("date:>now-%dd", days)

	switch kind {
	case "domain":
		return fmt.Sprintf("domain:%s AND %s", quoteURLScanValue(value), dateClause)
	case "ip":
		return fmt.Sprintf("ip:%s AND %s", quoteURLScanValue(value), dateClause)
	case "asn":
		return fmt.Sprintf("asn:%s AND %s", quoteURLScanValue(strings.TrimPrefix(strings.ToUpper(value), "AS")), dateClause)
	case "hash":
		return fmt.Sprintf("hash:%s AND %s", quoteURLScanValue(value), dateClause)
	case "brand":
		safeBrand := wildcardSafe(value)
		if safeBrand == "" {
			safeBrand = value
		}
		return fmt.Sprintf("(page.url:*%s* OR task.url:*%s* OR page.title:*%s*) AND %s", safeBrand, safeBrand, safeBrand, dateClause)
	default:
		return fmt.Sprintf("%s:%s AND %s", wildcardSafe(kind), quoteURLScanValue(value), dateClause)
	}
}

func decodeMaybeJSON(r *http.Request, target any) error {
	if r.Body == nil {
		return nil
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	return json.Unmarshal(data, target)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

type urlscanHTTPError struct {
	StatusCode int
	Message    string
	RateLimit  urlscanRateLimitInfo
}

func (e *urlscanHTTPError) Error() string {
	return e.Message
}

func writeURLScanError(w http.ResponseWriter, err error) {
	var apiErr *urlscanHTTPError
	if errors.As(err, &apiErr) {
		writeJSON(w, apiErr.StatusCode, map[string]any{
			"error":     apiErr.Message,
			"rateLimit": apiErr.RateLimit,
		})
		return
	}
	writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
}

func urlscanAPIKey() string {
	return strings.TrimSpace(os.Getenv("URLSCAN_API_KEY"))
}

func normalizeDays(days int) int {
	if days <= 0 {
		return defaultPivotDays
	}
	if days > 90 {
		return 90
	}
	return days
}

func normalizeSize(size int) int {
	if size <= 0 {
		return defaultPivotSize
	}
	if size > maxPivotSize {
		return maxPivotSize
	}
	return size
}

func cleanURLScanIndicator(kind, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" && (kind == "domain" || kind == "") {
			return strings.ToLower(parsed.Hostname())
		}
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, " \t\r\n/.")
	if kind == "domain" {
		value = strings.ToLower(value)
	}
	return value
}

func quoteURLScanValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func wildcardSafe(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func addCount(counts map[string]int, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		counts[value]++
	}
}

func topClusterItems(counts map[string]int, limit int) []urlscanClusterItem {
	items := make([]urlscanClusterItem, 0, len(counts))
	for value, count := range counts {
		items = append(items, urlscanClusterItem{Value: value, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Value < items[j].Value
		}
		return items[i].Count > items[j].Count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func extractURLScanError(body []byte) string {
	var payload struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		if payload.Message != "" {
			return payload.Message
		}
		if payload.Error != "" {
			return payload.Error
		}
	}
	text := strings.TrimSpace(string(body))
	if len(text) > 240 {
		text = text[:240]
	}
	if text == "" {
		return "URLScan request failed"
	}
	return text
}
