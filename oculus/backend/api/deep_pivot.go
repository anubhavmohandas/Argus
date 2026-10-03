package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultDeepPivotDays = 30
	defaultDeepPivotSize = 30
	maxDeepPivotSize     = 80
)

type deepPivotRequest struct {
	Indicator string   `json:"indicator"`
	Type      string   `json:"type"`
	Days      int      `json:"days"`
	Size      int      `json:"size"`
	Seeds     []string `json:"seeds"`
}

type deepPivotResponse struct {
	Indicator  string                  `json:"indicator"`
	Type       string                  `json:"type"`
	Days       int                     `json:"days"`
	Sources    []deepPivotSource       `json:"sources"`
	Assets     []deepPivotAsset        `json:"assets"`
	Screens    []deepPivotScreenshot   `json:"screens"`
	DNS        []deepPivotRecord       `json:"dns"`
	Certs      []deepPivotCert         `json:"certs"`
	Wayback    []deepPivotWayback      `json:"wayback"`
	RDAP       deepPivotRDAP           `json:"rdap"`
	Clusters   deepPivotClusters       `json:"clusters"`
	NextPivots []urlscanPivotIndicator `json:"nextPivots"`
	Errors     []string                `json:"errors"`
	Generated  string                  `json:"generated"`
}

type deepPivotSource struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Count  int    `json:"count"`
	Error  string `json:"error,omitempty"`
}

type deepPivotAsset struct {
	Domain     string   `json:"domain"`
	URL        string   `json:"url"`
	Title      string   `json:"title"`
	IP         string   `json:"ip"`
	ASN        string   `json:"asn"`
	ASNName    string   `json:"asnName"`
	Country    string   `json:"country"`
	Source     string   `json:"source"`
	Screenshot string   `json:"screenshot"`
	Result     string   `json:"result"`
	Time       string   `json:"time"`
	Tags       []string `json:"tags"`
	Signals    []string `json:"signals"`
}

type deepPivotScreenshot struct {
	Domain     string `json:"domain"`
	Screenshot string `json:"screenshot"`
	Result     string `json:"result"`
	Title      string `json:"title"`
	Source     string `json:"source"`
}

type deepPivotRecord struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl,omitempty"`
	Source string `json:"source"`
}

type deepPivotCert struct {
	Domain    string `json:"domain"`
	Issuer    string `json:"issuer,omitempty"`
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
	Source    string `json:"source"`
}

type deepPivotWayback struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
	MimeType  string `json:"mimeType"`
	Status    string `json:"status"`
	Source    string `json:"source"`
}

type deepPivotRDAP struct {
	Domain       string   `json:"domain,omitempty"`
	Handle       string   `json:"handle,omitempty"`
	Registrar    string   `json:"registrar,omitempty"`
	Created      string   `json:"created,omitempty"`
	Updated      string   `json:"updated,omitempty"`
	Expires      string   `json:"expires,omitempty"`
	Nameservers  []string `json:"nameservers"`
	RawAvailable bool     `json:"rawAvailable"`
}

type deepPivotClusters struct {
	Domains []urlscanClusterItem `json:"domains"`
	IPs     []urlscanClusterItem `json:"ips"`
	ASNs    []urlscanClusterItem `json:"asns"`
	Sources []urlscanClusterItem `json:"sources"`
}

type deepPivotCollector struct {
	mu      sync.Mutex
	assets  []deepPivotAsset
	screens []deepPivotScreenshot
	dns     []deepPivotRecord
	certs   []deepPivotCert
	wayback []deepPivotWayback
	rdap    deepPivotRDAP
	sources []deepPivotSource
	errors  []string
}

func (h *Handler) DeepPivot(w http.ResponseWriter, r *http.Request) {
	var req deepPivotRequest
	if err := decodeMaybeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	if req.Type == "" {
		req.Type = inferDeepPivotType(req.Indicator)
	}
	seeds := normalizeDeepPivotSeeds(req.Type, req.Indicator, req.Seeds)
	if len(seeds) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing pivot indicator"})
		return
	}
	req.Indicator = strings.Join(seeds, ", ")
	req.Days = normalizeDeepPivotDays(req.Days)
	req.Size = normalizeDeepPivotSize(req.Size)

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	collector := &deepPivotCollector{}
	var wg sync.WaitGroup
	run := func(name string, seedReq deepPivotRequest, fn func(context.Context, deepPivotRequest, *deepPivotCollector) (int, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			count, err := fn(ctx, seedReq, collector)
			status := "ok"
			errText := ""
			if err != nil {
				status = "degraded"
				errText = err.Error()
				if name == "urlscan.io" {
					collector.addError(name + ": " + errText)
				}
			}
			collector.addSource(deepPivotSource{Name: name, Status: status, Count: count, Error: errText})
		}()
	}

	for _, seed := range seeds {
		seedReq := req
		seedReq.Indicator = seed
		seedReq.Type = firstNonEmpty(req.Type, inferDeepPivotType(seed))
		run("urlscan.io "+seed, seedReq, h.collectDeepURLScan)
		if seedReq.Type == "domain" {
			run("crt.sh "+seed, seedReq, collector.collectDeepCRTSh)
			run("rdap.org "+seed, seedReq, collector.collectDeepRDAP)
			run("google-doh "+seed, seedReq, collector.collectDeepDNS)
			run("wayback-cdx "+seed, seedReq, collector.collectDeepWayback)
		}
	}
	wg.Wait()

	resp := collector.response(req)
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) collectDeepURLScan(ctx context.Context, req deepPivotRequest, collector *deepPivotCollector) (int, error) {
	query := buildURLScanQuery(req.Type, req.Indicator, req.Days)
	searchResp, err := h.runURLScanSearch(ctx, query, req.Size)
	if err != nil {
		return 0, err
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	for _, result := range searchResp.Results {
		domain := firstNonEmpty(result.Page.Domain, result.Task.Domain)
		pageURL := firstNonEmpty(result.Page.URL, result.Task.URL)
		screenshot := firstNonEmpty(result.Page.Screenshot, screenshotURL(result.Task.UUID))
		signals := uniqueStrings(append(append(result.Task.Tags, result.Verdicts.Overall.Tags...), result.Verdicts.URLScan.Tags...))
		asset := deepPivotAsset{
			Domain:     domain,
			URL:        pageURL,
			Title:      result.Page.Title,
			IP:         result.Page.IP,
			ASN:        result.Page.ASN,
			ASNName:    result.Page.ASNName,
			Country:    result.Page.Country,
			Source:     "urlscan.io",
			Screenshot: screenshot,
			Result:     result.Result,
			Time:       firstNonEmpty(result.Task.Time),
			Tags:       result.Task.Tags,
			Signals:    signals,
		}
		if asset.Domain != "" || asset.URL != "" {
			collector.assets = append(collector.assets, asset)
		}
		if screenshot != "" {
			collector.screens = append(collector.screens, deepPivotScreenshot{
				Domain:     domain,
				Screenshot: screenshot,
				Result:     result.Result,
				Title:      result.Page.Title,
				Source:     "urlscan.io",
			})
		}
		for _, domain := range result.Lists.Domains {
			if domain != "" {
				collector.assets = append(collector.assets, deepPivotAsset{Domain: domain, Source: "urlscan.io lists", Signals: []string{"loaded by observed scan"}})
			}
		}
	}
	return len(searchResp.Results), nil
}

func (c *deepPivotCollector) response(req deepPivotRequest) deepPivotResponse {
	c.mu.Lock()
	defer c.mu.Unlock()

	assets := dedupeDeepAssets(c.assets, maxDeepPivotSize)
	screens := dedupeDeepScreens(c.screens, 36)
	certs := dedupeDeepCerts(c.certs, 80)
	wayback := dedupeDeepWayback(c.wayback, 80)
	dns := dedupeDeepRecords(c.dns, 80)

	domainCounts := map[string]int{}
	ipCounts := map[string]int{}
	asnCounts := map[string]int{}
	sourceCounts := map[string]int{}
	for _, asset := range assets {
		addCount(domainCounts, asset.Domain)
		addCount(ipCounts, asset.IP)
		addCount(asnCounts, asset.ASN)
		addCount(sourceCounts, asset.Source)
	}
	for _, cert := range certs {
		addCount(domainCounts, cert.Domain)
		addCount(sourceCounts, cert.Source)
	}
	for _, record := range dns {
		if record.Type == "A" || record.Type == "AAAA" {
			addCount(ipCounts, record.Value)
		}
		addCount(sourceCounts, record.Source)
	}

	clusters := deepPivotClusters{
		Domains: topClusterItems(domainCounts, 18),
		IPs:     topClusterItems(ipCounts, 16),
		ASNs:    topClusterItems(asnCounts, 12),
		Sources: topClusterItems(sourceCounts, 8),
	}
	return deepPivotResponse{
		Indicator:  req.Indicator,
		Type:       req.Type,
		Days:       req.Days,
		Sources:    c.sources,
		Assets:     assets,
		Screens:    screens,
		DNS:        dns,
		Certs:      certs,
		Wayback:    wayback,
		RDAP:       c.rdap,
		Clusters:   clusters,
		NextPivots: buildDeepNextPivots(req, clusters),
		Errors:     uniqueStrings(c.errors),
		Generated:  time.Now().UTC().Format(time.RFC3339),
	}
}

func (c *deepPivotCollector) addSource(source deepPivotSource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sources = append(c.sources, source)
}

func (c *deepPivotCollector) addError(err string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors = append(c.errors, err)
}

func inferDeepPivotType(indicator string) string {
	indicator = strings.TrimSpace(indicator)
	if net.ParseIP(indicator) != nil {
		return "ip"
	}
	if strings.Contains(indicator, "://") {
		return "domain"
	}
	if strings.HasPrefix(strings.ToUpper(indicator), "AS") {
		return "asn"
	}
	return "domain"
}

func normalizeDeepPivotDays(days int) int {
	if days <= 0 {
		return defaultDeepPivotDays
	}
	if days > 365 {
		return 365
	}
	return days
}

func normalizeDeepPivotSize(size int) int {
	if size <= 0 {
		return defaultDeepPivotSize
	}
	if size > maxDeepPivotSize {
		return maxDeepPivotSize
	}
	return size
}

func normalizeDeepPivotSeeds(kind, indicator string, seeds []string) []string {
	raw := append([]string{}, seeds...)
	raw = append(raw, strings.FieldsFunc(indicator, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || r == '\t'
	})...)
	seen := map[string]bool{}
	out := []string{}
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		itemKind := kind
		if itemKind == "" || itemKind == "auto" {
			itemKind = inferDeepPivotType(item)
		}
		clean := cleanURLScanIndicator(itemKind, item)
		key := strings.ToLower(itemKind + ":" + clean)
		if clean == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, clean)
		if len(out) >= 12 {
			break
		}
	}
	return out
}

func (c *deepPivotCollector) collectDeepCRTSh(ctx context.Context, req deepPivotRequest, _ *deepPivotCollector) (int, error) {
	endpoint := "https://crt.sh/?q=" + url.QueryEscape("%."+req.Indicator) + "&output=json"
	body, err := fetchPublicBody(ctx, endpoint, 6<<20)
	if err != nil {
		return 0, err
	}
	var rows []struct {
		NameValue string `json:"name_value"`
		Issuer    string `json:"issuer_name"`
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for _, row := range rows {
		for _, name := range strings.Split(row.NameValue, "\n") {
			name = cleanCertDomain(name)
			if name == "" {
				continue
			}
			c.certs = append(c.certs, deepPivotCert{
				Domain:    name,
				Issuer:    row.Issuer,
				NotBefore: row.NotBefore,
				NotAfter:  row.NotAfter,
				Source:    "crt.sh",
			})
			c.assets = append(c.assets, deepPivotAsset{Domain: name, Source: "crt.sh", Signals: []string{"certificate transparency name"}})
			count++
		}
		if count >= maxDeepPivotSize*3 {
			break
		}
	}
	return count, nil
}

func (c *deepPivotCollector) collectDeepRDAP(ctx context.Context, req deepPivotRequest, _ *deepPivotCollector) (int, error) {
	body, err := fetchPublicBody(ctx, "https://rdap.org/domain/"+url.PathEscape(req.Indicator), 2<<20)
	if err != nil {
		return 0, err
	}
	var parsed struct {
		LDHName string `json:"ldhName"`
		Handle  string `json:"handle"`
		Events  []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles  []string `json:"roles"`
			VCard  []any    `json:"vcardArray"`
			Handle string   `json:"handle"`
		} `json:"entities"`
		Nameservers []struct {
			LDHName string `json:"ldhName"`
		} `json:"nameservers"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, err
	}
	rdap := deepPivotRDAP{Domain: firstNonEmpty(parsed.LDHName, req.Indicator), Handle: parsed.Handle, RawAvailable: true}
	for _, event := range parsed.Events {
		switch strings.ToLower(event.Action) {
		case "registration":
			rdap.Created = event.Date
		case "last changed", "last update of rdap database":
			rdap.Updated = firstNonEmpty(rdap.Updated, event.Date)
		case "expiration":
			rdap.Expires = event.Date
		}
	}
	for _, ns := range parsed.Nameservers {
		name := strings.ToLower(strings.TrimSuffix(ns.LDHName, "."))
		if name != "" {
			rdap.Nameservers = append(rdap.Nameservers, name)
		}
	}
	for _, entity := range parsed.Entities {
		if hasStringFold(entity.Roles, "registrar") {
			rdap.Registrar = firstNonEmpty(extractVCardName(entity.VCard), entity.Handle)
			break
		}
	}
	c.mu.Lock()
	c.rdap = rdap
	for _, ns := range rdap.Nameservers {
		c.dns = append(c.dns, deepPivotRecord{Name: req.Indicator, Type: "NS", Value: ns, Source: "rdap.org"})
	}
	c.mu.Unlock()
	return 1, nil
}

func (c *deepPivotCollector) collectDeepDNS(ctx context.Context, req deepPivotRequest, _ *deepPivotCollector) (int, error) {
	types := []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME"}
	count := 0
	for _, rrType := range types {
		endpoint := "https://dns.google/resolve?name=" + url.QueryEscape(req.Indicator) + "&type=" + rrType
		body, err := fetchPublicBody(ctx, endpoint, 1<<20)
		if err != nil {
			continue
		}
		var parsed struct {
			Answer []struct {
				Name string `json:"name"`
				Type int    `json:"type"`
				TTL  int    `json:"TTL"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if json.Unmarshal(body, &parsed) != nil {
			continue
		}
		c.mu.Lock()
		for _, ans := range parsed.Answer {
			value := strings.Trim(ans.Data, `"`)
			c.dns = append(c.dns, deepPivotRecord{
				Name:   strings.TrimSuffix(ans.Name, "."),
				Type:   dnsTypeName(ans.Type, rrType),
				Value:  strings.TrimSuffix(value, "."),
				TTL:    ans.TTL,
				Source: "google-doh",
			})
			count++
		}
		c.mu.Unlock()
	}
	return count, nil
}

func (c *deepPivotCollector) collectDeepWayback(ctx context.Context, req deepPivotRequest, _ *deepPivotCollector) (int, error) {
	endpoint := "https://web.archive.org/cdx?url=" + url.QueryEscape(req.Indicator+"/*") + "&output=json&fl=timestamp,original,mimetype,statuscode&collapse=urlkey&limit=80"
	body, err := fetchPublicBody(ctx, endpoint, 4<<20)
	if err != nil {
		return 0, err
	}
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for i, row := range rows {
		if i == 0 || len(row) < 4 {
			continue
		}
		item := deepPivotWayback{
			Timestamp: row[0],
			URL:       row[1],
			MimeType:  row[2],
			Status:    row[3],
			Source:    "wayback-cdx",
		}
		c.wayback = append(c.wayback, item)
		if parsed, err := url.Parse(item.URL); err == nil && parsed.Hostname() != "" {
			c.assets = append(c.assets, deepPivotAsset{Domain: strings.ToLower(parsed.Hostname()), URL: item.URL, Source: "wayback-cdx", Signals: []string{"archived URL"}})
		}
		count++
	}
	return count, nil
}

func fetchPublicBody(ctx context.Context, endpoint string, limit int64) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 16*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json,text/plain,*/*")
	req.Header.Set("User-Agent", "ReconVision/1.0 DeepPivot")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, limit))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, truncateString(strings.TrimSpace(string(body)), 160))
	}
	return body, nil
}

func buildDeepNextPivots(req deepPivotRequest, clusters deepPivotClusters) []urlscanPivotIndicator {
	var out []urlscanPivotIndicator
	add := func(kind string, item urlscanClusterItem) {
		if len(out) >= 16 || item.Value == "" || strings.EqualFold(item.Value, req.Indicator) {
			return
		}
		out = append(out, urlscanPivotIndicator{Type: kind, Value: item.Value, Count: item.Count, Query: buildURLScanQuery(kind, item.Value, req.Days)})
	}
	for _, item := range clusters.Domains {
		add("domain", item)
	}
	for _, item := range clusters.IPs {
		add("ip", item)
	}
	for _, item := range clusters.ASNs {
		add("asn", item)
	}
	return out
}

func dedupeDeepAssets(items []deepPivotAsset, limit int) []deepPivotAsset {
	seen := map[string]bool{}
	out := []deepPivotAsset{}
	for _, item := range items {
		key := strings.ToLower(firstNonEmpty(item.URL, item.Domain+"|"+item.Source))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Screenshot != "") != (out[j].Screenshot != "") {
			return out[i].Screenshot != ""
		}
		return out[i].Domain < out[j].Domain
	})
	if len(out) > limit {
		return out[:limit]
	}
	return out
}

func dedupeDeepScreens(items []deepPivotScreenshot, limit int) []deepPivotScreenshot {
	seen := map[string]bool{}
	out := []deepPivotScreenshot{}
	for _, item := range items {
		key := strings.ToLower(firstNonEmpty(item.Screenshot, item.Domain))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	if len(out) > limit {
		return out[:limit]
	}
	return out
}

func dedupeDeepCerts(items []deepPivotCert, limit int) []deepPivotCert {
	seen := map[string]bool{}
	out := []deepPivotCert{}
	for _, item := range items {
		key := strings.ToLower(item.Domain + "|" + item.NotBefore)
		if item.Domain == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	if len(out) > limit {
		return out[:limit]
	}
	return out
}

func dedupeDeepWayback(items []deepPivotWayback, limit int) []deepPivotWayback {
	seen := map[string]bool{}
	out := []deepPivotWayback{}
	for _, item := range items {
		key := strings.ToLower(item.URL)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	if len(out) > limit {
		return out[:limit]
	}
	return out
}

func dedupeDeepRecords(items []deepPivotRecord, limit int) []deepPivotRecord {
	seen := map[string]bool{}
	out := []deepPivotRecord{}
	for _, item := range items {
		key := strings.ToLower(item.Name + "|" + item.Type + "|" + item.Value)
		if item.Value == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	if len(out) > limit {
		return out[:limit]
	}
	return out
}

func cleanCertDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "*.")
	value = strings.Trim(value, ". ")
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return ""
	}
	return value
}

func hasStringFold(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(value, needle) {
			return true
		}
	}
	return false
}

func extractVCardName(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	rows, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, row := range rows {
		fields, ok := row.([]any)
		if !ok || len(fields) < 4 {
			continue
		}
		if key, _ := fields[0].(string); key == "fn" {
			if value, ok := fields[3].(string); ok {
				return value
			}
		}
	}
	return ""
}

func dnsTypeName(code int, fallback string) string {
	switch code {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	default:
		return fallback
	}
}

func truncateString(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
