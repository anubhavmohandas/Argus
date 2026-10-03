package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"reconvision/models"
	"reconvision/scanner"
	"reconvision/store"
)

// Handler holds dependencies for all HTTP handlers
type Handler struct {
	store *store.Store
}

// NewHandler creates a new Handler
func NewHandler(st *store.Store) *Handler {
	return &Handler{store: st}
}

// StartScan handles POST /api/scan
func (h *Handler) StartScan(w http.ResponseWriter, r *http.Request) {
	var req models.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Domains) == 0 {
		http.Error(w, "no domains provided", http.StatusBadRequest)
		return
	}
	if len(req.Domains) > 100000 {
		http.Error(w, "maximum 100,000 domains per scan", http.StatusBadRequest)
		return
	}

	jobID := scanner.GenerateJobID()
	h.store.CreateJob(jobID, len(req.Domains), req.Config)

	// Run scan in background
	go func() {
		eng := scanner.NewEngine(h.store, req.Config)
		eng.Run(jobID, req.Domains, nil) // SSE subscribers get data via polling or direct SSE
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"jobId": jobID})
}

// StartScanSSE handles POST /api/scan/stream — starts scan and SSE-streams results
func (h *Handler) StartScanSSE(w http.ResponseWriter, r *http.Request) {
	var req models.ScanRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Domains) == 0 {
		http.Error(w, "no domains provided", http.StatusBadRequest)
		return
	}

	jobID := scanner.GenerateJobID()
	h.store.CreateJob(jobID, len(req.Domains), req.Config)

	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Job-ID", jobID)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Send job ID as first event
	writeSSE(w, flusher, "start", map[string]string{"jobId": jobID})

	resultCh := make(chan models.ScanResult, 256)

	// Callback writes to channel
	cb := func(result models.ScanResult) {
		select {
		case resultCh <- result:
		default:
		}
	}

	// Run scan
	go func() {
		eng := scanner.NewEngine(h.store, req.Config)
		eng.Run(jobID, req.Domains, cb)
		close(resultCh)
	}()

	// Stream results to client
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case result, more := <-resultCh:
			if !more {
				// Scan done — send final progress event
				total, processed, live, errors, status, _ := h.store.GetProgress(jobID)
				writeSSE(w, flusher, "done", map[string]interface{}{
					"jobId":     jobID,
					"total":     total,
					"processed": processed,
					"live":      live,
					"errors":    errors,
					"status":    status,
				})
				return
			}
			writeSSE(w, flusher, "result", result)

		case <-ticker.C:
			// Heartbeat with progress
			total, processed, live, errors, _, _ := h.store.GetProgress(jobID)
			writeSSE(w, flusher, "progress", map[string]interface{}{
				"total": total, "processed": processed,
				"live": live, "errors": errors,
			})

		case <-r.Context().Done():
			log.Printf("[%s] Client disconnected", jobID)
			return
		}
	}
}

// GetJob handles GET /api/scan/{jobId}
func (h *Handler) GetJob(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobId")
	job, ok := h.store.GetJob(jobID)
	if !ok {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

// GetJobProgress handles GET /api/scan/{jobId}/progress
func (h *Handler) GetJobProgress(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobId")
	total, processed, live, errors, status, ok := h.store.GetProgress(jobID)
	if !ok {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total": total, "processed": processed,
		"live": live, "errors": errors, "status": status,
	})
}

// ListJobs handles GET /api/jobs
func (h *Handler) ListJobs(w http.ResponseWriter, r *http.Request) {
	jobs := h.store.AllJobs()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jobs)
}

// ExportJob handles GET /api/scan/{jobId}/export?format=csv|json|txt|md
func (h *Handler) ExportJob(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobId")
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	job, ok := h.store.GetJob(jobID)
	if !ok {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="reconvision_%s.json"`, jobID))
		json.NewEncoder(w).Encode(job.Results)

	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="reconvision_%s.csv"`, jobID))
		cw := csv.NewWriter(w)
		cw.Write([]string{"domain", "url", "status", "risk_score", "risk_level", "categories", "indicators", "brand_candidate", "ip_address", "title", "server", "content_length", "redirect_url", "keywords", "interesting", "duration_ms", "timestamp"})
		for _, r := range job.Results {
			cw.Write([]string{
				r.Domain, r.URL, fmt.Sprintf("%d", r.Status),
				fmt.Sprintf("%d", r.Intelligence.RiskScore), r.Intelligence.RiskLevel,
				strings.Join(r.Intelligence.Categories, "|"),
				strings.Join(r.Intelligence.Indicators, "|"),
				r.Intelligence.BrandCandidate, r.Intelligence.IPAddress,
				r.Title, r.Server, fmt.Sprintf("%d", r.ContentLength), r.RedirectURL,
				strings.Join(r.Keywords, "|"),
				fmt.Sprintf("%v", r.Interesting),
				fmt.Sprintf("%d", r.DurationMs),
				r.Timestamp.Format(time.RFC3339),
			})
		}
		cw.Flush()

	case "txt":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="reconvision_%s.txt"`, jobID))
		for _, r := range job.Results {
			if r.Status > 0 {
				fmt.Fprintf(w, "%s\n", r.URL)
			}
		}

	case "md":
		w.Header().Set("Content-Type", "text/markdown")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="reconvision_%s.md"`, jobID))
		fmt.Fprintf(w, "# ReconVision Results — %s\n\n", jobID)
		fmt.Fprintf(w, "| Domain | Status | Risk | Title | Server | Size | Evidence |\n")
		fmt.Fprintf(w, "|--------|--------|------|-------|--------|------|----------|\n")
		for _, r := range job.Results {
			if r.Status > 0 {
				fmt.Fprintf(w, "| %s | %d | %d %s | %s | %s | %d | %s |\n",
					r.Domain, r.Status, r.Intelligence.RiskScore, r.Intelligence.RiskLevel,
					r.Title, r.Server, r.ContentLength, strings.Join(r.Intelligence.Indicators, "; "))
			}
		}

	default:
		http.Error(w, "unknown format", http.StatusBadRequest)
	}
}

// Health handles GET /api/health
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": "1.0.0",
		"name":    "ReconVision",
	})
}

func writeSSE(w http.ResponseWriter, f http.Flusher, event string, data interface{}) {
	payload, err := json.Marshal(data)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload)
	f.Flush()
}
