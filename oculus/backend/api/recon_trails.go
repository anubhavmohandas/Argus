package api

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultReconTrailsDays = 30
	defaultReconTrailsSize = 80
)

type reconTrailsRequest struct {
	Domain  string   `json:"domain"`
	Domains []string `json:"domains"`
	Days    int      `json:"days"`
	Size    int      `json:"size"`
}

type reconTrailsResponse struct {
	Domains      []string                  `json:"domains"`
	Generated    string                    `json:"generated"`
	Summary      reconTrailsSummary        `json:"summary"`
	Sources      []deepPivotSource         `json:"sources"`
	Subdomains   []reconTrailsSubdomain    `json:"subdomains"`
	DNS          []deepPivotRecord         `json:"dns"`
	Certificates []deepPivotCert           `json:"certificates"`
	RDAP         deepPivotRDAP             `json:"rdap"`
	URLs         []deepPivotWayback        `json:"urls"`
	Screens      []deepPivotScreenshot     `json:"screens"`
	Assets       []deepPivotAsset          `json:"assets"`
	IPNeighbors  []reconTrailsIPNeighbor   `json:"ipNeighbors"`
	NextPivots   []urlscanPivotIndicator   `json:"nextPivots"`
	Errors       []string                  `json:"errors"`
	Exports      reconTrailsExportManifest `json:"exports"`
}

type reconTrailsSummary struct {
	DomainCount      int `json:"domainCount"`
	SubdomainCount   int `json:"subdomainCount"`
	DNSCount         int `json:"dnsCount"`
	CertificateCount int `json:"certificateCount"`
	URLCount         int `json:"urlCount"`
	ScreenshotCount  int `json:"screenshotCount"`
	IPNeighborCount  int `json:"ipNeighborCount"`
	RiskyAssetCount  int `json:"riskyAssetCount"`
}

type reconTrailsSubdomain struct {
	Domain     string   `json:"domain"`
	Root       string   `json:"root"`
	IP         string   `json:"ip"`
	ASN        string   `json:"asn"`
	ASNName    string   `json:"asnName"`
	Country    string   `json:"country"`
	Title      string   `json:"title"`
	URL        string   `json:"url"`
	Screenshot string   `json:"screenshot"`
	Result     string   `json:"result"`
	Sources    []string `json:"sources"`
	Signals    []string `json:"signals"`
}

type reconTrailsIPNeighbor struct {
	IP      string   `json:"ip"`
	ASN     string   `json:"asn"`
	ASNName string   `json:"asnName"`
	Country string   `json:"country"`
	Domains []string `json:"domains"`
	Count   int      `json:"count"`
	Source  string   `json:"source"`
}

type reconTrailsExportManifest struct {
	JSON bool `json:"json"`
	CSV  bool `json:"csv"`
	TXT  bool `json:"txt"`
	STIX bool `json:"stix"`
}

func (h *Handler) ReconTrailsDomain(w http.ResponseWriter, r *http.Request) {
	var req reconTrailsRequest
	if err := decodeMaybeJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	seeds := normalizeReconTrailsDomains(req.Domain, req.Domains)
	if len(seeds) == 0 {
		writeJSON(w, 400, map[string]string{"error": "missing domain"})
		return
	}

	days := normalizeDeepPivotDays(req.Days)
	if req.Days <= 0 {
		days = defaultReconTrailsDays
	}
	size := normalizeDeepPivotSize(req.Size)
	if req.Size <= 0 {
		size = defaultReconTrailsSize
	}

	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
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
				collector.addError(name + ": " + errText)
			}
			collector.addSource(deepPivotSource{Name: name, Status: status, Count: count, Error: errText})
		}()
	}

	for _, seed := range seeds {
		seedReq := deepPivotRequest{
			Indicator: seed,
			Type:      "domain",
			Days:      days,
			Size:      size,
			Seeds:     seeds,
		}
		run("urlscan screenshots "+seed, seedReq, h.collectDeepURLScan)
		run("certificate transparency "+seed, seedReq, collector.collectDeepCRTSh)
		run("rdap profile "+seed, seedReq, collector.collectDeepRDAP)
		run("current dns "+seed, seedReq, collector.collectDeepDNS)
		run("wayback urls "+seed, seedReq, collector.collectDeepWayback)
	}
	wg.Wait()

	deep := collector.response(deepPivotRequest{
		Indicator: strings.Join(seeds, ", "),
		Type:      "domain",
		Days:      days,
		Size:      size,
		Seeds:     seeds,
	})

	resp := buildReconTrailsResponse(seeds, deep)
	writeJSON(w, 200, resp)
}

func normalizeReconTrailsDomains(domain string, domains []string) []string {
	raw := append([]string{}, domains...)
	raw = append(raw, strings.FieldsFunc(domain, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || r == '\t' || r == ' '
	})...)
	seen := map[string]bool{}
	out := []string{}
	for _, item := range raw {
		item = cleanURLScanIndicator("domain", item)
		if parsed, err := url.Parse(item); err == nil && parsed.Hostname() != "" {
			item = parsed.Hostname()
		}
		item = strings.ToLower(strings.Trim(item, ". "))
		if item == "" || !strings.Contains(item, ".") || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
		if len(out) >= 12 {
			break
		}
	}
	return out
}

func buildReconTrailsResponse(roots []string, deep deepPivotResponse) reconTrailsResponse {
	assets := dedupeDeepAssets(deep.Assets, 160)
	certs := dedupeDeepCerts(deep.Certs, 220)
	wayback := dedupeDeepWayback(deep.Wayback, 220)
	dns := dedupeDeepRecords(deep.DNS, 180)
	screens := dedupeDeepScreens(deep.Screens, 80)
	subdomains := buildReconTrailsSubdomains(roots, assets, certs, wayback)
	neighbors := buildReconTrailsIPNeighbors(assets)
	risky := 0
	for _, asset := range assets {
		if len(asset.Signals) > 0 || len(asset.Tags) > 0 {
			risky++
		}
	}
	return reconTrailsResponse{
		Domains:      roots,
		Generated:    time.Now().UTC().Format(time.RFC3339),
		Summary:      reconTrailsSummary{DomainCount: len(roots), SubdomainCount: len(subdomains), DNSCount: len(dns), CertificateCount: len(certs), URLCount: len(wayback), ScreenshotCount: len(screens), IPNeighborCount: len(neighbors), RiskyAssetCount: risky},
		Sources:      deep.Sources,
		Subdomains:   subdomains,
		DNS:          dns,
		Certificates: certs,
		RDAP:         deep.RDAP,
		URLs:         wayback,
		Screens:      screens,
		Assets:       assets,
		IPNeighbors:  neighbors,
		NextPivots:   deep.NextPivots,
		Errors:       deep.Errors,
		Exports:      reconTrailsExportManifest{JSON: true, CSV: true, TXT: true, STIX: true},
	}
}

func buildReconTrailsSubdomains(roots []string, assets []deepPivotAsset, certs []deepPivotCert, wayback []deepPivotWayback) []reconTrailsSubdomain {
	type row struct {
		item reconTrailsSubdomain
		src  map[string]bool
		sig  map[string]bool
	}
	rows := map[string]*row{}
	upsert := func(domain, root, source string) *row {
		domain = strings.ToLower(strings.Trim(domain, ". "))
		if domain == "" || domain == root {
			return nil
		}
		if !isSubdomainOf(domain, root) {
			return nil
		}
		entry := rows[domain]
		if entry == nil {
			entry = &row{
				item: reconTrailsSubdomain{Domain: domain, Root: root},
				src:  map[string]bool{},
				sig:  map[string]bool{},
			}
			rows[domain] = entry
		}
		if source != "" {
			entry.src[source] = true
		}
		return entry
	}
	for _, asset := range assets {
		for _, root := range roots {
			entry := upsert(asset.Domain, root, asset.Source)
			if entry == nil {
				continue
			}
			entry.item.IP = firstNonEmpty(entry.item.IP, asset.IP)
			entry.item.ASN = firstNonEmpty(entry.item.ASN, asset.ASN)
			entry.item.ASNName = firstNonEmpty(entry.item.ASNName, asset.ASNName)
			entry.item.Country = firstNonEmpty(entry.item.Country, asset.Country)
			entry.item.Title = firstNonEmpty(entry.item.Title, asset.Title)
			entry.item.URL = firstNonEmpty(entry.item.URL, asset.URL)
			entry.item.Screenshot = firstNonEmpty(entry.item.Screenshot, asset.Screenshot)
			entry.item.Result = firstNonEmpty(entry.item.Result, asset.Result)
			for _, signal := range append(asset.Signals, asset.Tags...) {
				if signal != "" {
					entry.sig[signal] = true
				}
			}
		}
	}
	for _, cert := range certs {
		for _, root := range roots {
			entry := upsert(cert.Domain, root, cert.Source)
			if entry != nil && cert.Issuer != "" {
				entry.sig["certificate issuer: "+cert.Issuer] = true
			}
		}
	}
	for _, item := range wayback {
		parsed, err := url.Parse(item.URL)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		for _, root := range roots {
			entry := upsert(host, root, item.Source)
			if entry != nil {
				entry.item.URL = firstNonEmpty(entry.item.URL, item.URL)
				entry.sig["archived URL"] = true
			}
		}
	}
	out := make([]reconTrailsSubdomain, 0, len(rows))
	for _, entry := range rows {
		entry.item.Sources = mapKeys(entry.src)
		entry.item.Signals = mapKeys(entry.sig)
		out = append(out, entry.item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Screenshot != "") != (out[j].Screenshot != "") {
			return out[i].Screenshot != ""
		}
		if len(out[i].Sources) != len(out[j].Sources) {
			return len(out[i].Sources) > len(out[j].Sources)
		}
		return out[i].Domain < out[j].Domain
	})
	if len(out) > 200 {
		return out[:200]
	}
	return out
}

func buildReconTrailsIPNeighbors(assets []deepPivotAsset) []reconTrailsIPNeighbor {
	type bucket struct {
		neighbor reconTrailsIPNeighbor
		domains  map[string]bool
	}
	buckets := map[string]*bucket{}
	for _, asset := range assets {
		if asset.IP == "" || asset.Domain == "" {
			continue
		}
		entry := buckets[asset.IP]
		if entry == nil {
			entry = &bucket{
				neighbor: reconTrailsIPNeighbor{
					IP:      asset.IP,
					ASN:     asset.ASN,
					ASNName: asset.ASNName,
					Country: asset.Country,
					Source:  "urlscan observed dns",
				},
				domains: map[string]bool{},
			}
			buckets[asset.IP] = entry
		}
		entry.domains[asset.Domain] = true
		entry.neighbor.ASN = firstNonEmpty(entry.neighbor.ASN, asset.ASN)
		entry.neighbor.ASNName = firstNonEmpty(entry.neighbor.ASNName, asset.ASNName)
		entry.neighbor.Country = firstNonEmpty(entry.neighbor.Country, asset.Country)
	}
	out := make([]reconTrailsIPNeighbor, 0, len(buckets))
	for _, entry := range buckets {
		entry.neighbor.Domains = mapKeys(entry.domains)
		entry.neighbor.Count = len(entry.neighbor.Domains)
		out = append(out, entry.neighbor)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Count > out[j].Count
	})
	if len(out) > 80 {
		return out[:80]
	}
	return out
}

func isSubdomainOf(domain, root string) bool {
	domain = strings.ToLower(strings.Trim(domain, ". "))
	root = strings.ToLower(strings.Trim(root, ". "))
	return domain != root && strings.HasSuffix(domain, "."+root)
}

func mapKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
