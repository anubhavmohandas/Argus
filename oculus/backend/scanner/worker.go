package scanner

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"

	"reconvision/models"
	"reconvision/store"
)

// ResultCallback is called whenever a result is ready
type ResultCallback func(result models.ScanResult)

// Engine orchestrates the full scan pipeline
type Engine struct {
	store  *store.Store
	config models.ScanConfig
}

// NewEngine creates a new scan engine
func NewEngine(st *store.Store, cfg models.ScanConfig) *Engine {
	// Apply sane defaults
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 150
	}
	if cfg.ScreenWorkers <= 0 {
		cfg.ScreenWorkers = 6
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 10
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 1
	}
	if cfg.ScreenshotMode == "" {
		cfg.ScreenshotMode = "viewport"
	}
	return &Engine{store: st, config: cfg}
}

// Run executes a full scan job, streaming results via callback
func (e *Engine) Run(jobID string, rawDomains []string, cb ResultCallback) {
	domains := deduplicateDomains(rawDomains)

	now := time.Now()
	e.store.SetStatus(jobID, "running")
	_ = now

	log.Printf("[%s] Starting scan: %d unique domains | concurrency=%d screeners=%d",
		jobID, len(domains), e.config.Concurrency, e.config.ScreenWorkers)

	// --- Phase 1: HTTP probing ---
	probeCh := make(chan string, e.config.Concurrency*2)
	probedCh := make(chan models.ScanResult, e.config.Concurrency*2)

	prober := NewProber(e.config)

	var probeWg sync.WaitGroup
	for i := 0; i < e.config.Concurrency; i++ {
		probeWg.Add(1)
		go func() {
			defer probeWg.Done()
			for domain := range probeCh {
				ctx, cancel := context.WithTimeout(context.Background(),
					time.Duration(e.config.TimeoutSeconds)*time.Second)
				result := probeWithRetry(ctx, prober, domain, e.config.MaxRetries)
				cancel()
				result.ID = uuid.New().String()
				probedCh <- result
			}
		}()
	}

	// Feed domains into probe channel
	go func() {
		for _, d := range domains {
			probeCh <- d
		}
		close(probeCh)
	}()

	// Close probedCh when all probers finish
	go func() {
		probeWg.Wait()
		close(probedCh)
	}()

	// --- Phase 2: Screenshot workers ---
	var screener *Screenshotter
	screenshotJobs := make(chan models.ScanResult, e.config.ScreenWorkers*4)
	finalCh := make(chan models.ScanResult, e.config.ScreenWorkers*4)

	if !e.config.SkipScreenshots {
		screener = NewScreenshotter(e.config)
		var screenWg sync.WaitGroup
		for i := 0; i < e.config.ScreenWorkers; i++ {
			screenWg.Add(1)
			go func() {
				defer screenWg.Done()
				for r := range screenshotJobs {
					if r.Status > 0 && r.Error == "" {
						shot, err := screener.Capture(r.URL)
						if err != nil {
							log.Printf("[%s] screenshot error %s: %v", jobID, r.Domain, err)
						} else {
							r.Screenshot = shot
						}
					}
					finalCh <- r
				}
			}()
		}
		go func() {
			screenWg.Wait()
			close(finalCh)
		}()
	}

	// --- Dispatch: route probed results to screenshot or final ---
	go func() {
		for r := range probedCh {
			if e.config.SkipScreenshots {
				finalCh <- r
			} else {
				// Only screenshot live hosts (status > 0, no DNS/connect error)
				if r.Status > 0 && r.Error == "" {
					screenshotJobs <- r
				} else {
					// Dead host — skip screenshot, send directly
					finalCh <- r
				}
			}
		}
		if !e.config.SkipScreenshots {
			close(screenshotJobs)
		} else {
			close(finalCh)
		}
	}()

	// --- Collect results ---
	for r := range finalCh {
		e.store.AppendResult(jobID, r)
		if cb != nil {
			cb(r)
		}
	}

	e.store.SetStatus(jobID, "complete")
	log.Printf("[%s] Scan complete", jobID)
}

// probeWithRetry retries on transient errors
func probeWithRetry(ctx context.Context, p *Prober, domain string, retries int) models.ScanResult {
	var r models.ScanResult
	for i := 0; i <= retries; i++ {
		r = p.Probe(ctx, domain)
		if r.Error == "" || i == retries {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	return r
}

// GenerateJobID creates a new unique job ID
func GenerateJobID() string {
	return fmt.Sprintf("job_%s", uuid.New().String()[:8])
}
