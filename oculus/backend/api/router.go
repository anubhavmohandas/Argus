package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"reconvision/store"
)

// NewRouter creates and configures the HTTP router
func NewRouter(st *store.Store) http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Job-ID"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	h := NewHandler(st)

	r.Route("/api", func(r chi.Router) {
		r.Get("/health", h.Health)
		r.Get("/jobs", h.ListJobs)
		r.Get("/urlscan/status", h.URLScanStatus)
		r.Post("/urlscan/search", h.URLScanSearch)
		r.Post("/urlscan/pivot", h.URLScanPivot)
		r.Post("/deep-pivot", h.DeepPivot)
		r.Post("/recon-trails/domain", h.ReconTrailsDomain)
		r.Get("/brand-logo-watch/status", h.BrandLogoWatchStatus)
		r.Post("/brand-logo-watch/refresh", h.BrandLogoWatchRefresh)
		r.Post("/brand-logo-watch/analyze", h.BrandLogoWatchAnalyze)
		r.Get("/brand-logo-watch/stix", h.BrandLogoWatchSTIX)

		// Start scan — async (returns jobId immediately)
		r.Post("/scan", h.StartScan)

		// Start scan — SSE streaming (blocks while streaming results)
		r.Post("/scan/stream", h.StartScanSSE)

		// Job operations
		r.Get("/scan/{jobId}", h.GetJob)
		r.Get("/scan/{jobId}/progress", h.GetJobProgress)
		r.Get("/scan/{jobId}/export", h.ExportJob)
	})

	serveStaticApp(r, "./static")

	return r
}

func serveStaticApp(r chi.Router, staticDir string) {
	indexPath := filepath.Join(staticDir, "index.html")
	if _, err := os.Stat(indexPath); err != nil {
		return
	}

	fileServer := http.FileServer(http.Dir(staticDir))

	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/api/") {
			http.NotFound(w, req)
			return
		}

		relPath := strings.TrimPrefix(req.URL.Path, "/")
		requestedPath := filepath.Join(staticDir, relPath)

		if info, err := os.Stat(requestedPath); err == nil && !info.IsDir() {
			fileServer.ServeHTTP(w, req)
			return
		}

		http.ServeFile(w, req, indexPath)
	})
}
