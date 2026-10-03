package store

import (
	"sync"
	"time"

	"reconvision/models"
)

// Store manages all active scan jobs
type Store struct {
	mu   sync.RWMutex
	jobs map[string]*JobEntry
}

// JobEntry wraps a ScanJob with per-job mutex for concurrent result appending
type JobEntry struct {
	mu  sync.Mutex
	Job models.ScanJob
}

// New creates an empty Store
func New() *Store {
	return &Store{jobs: make(map[string]*JobEntry)}
}

// CreateJob initialises a new job
func (s *Store) CreateJob(id string, total int, cfg models.ScanConfig) {
	entry := &JobEntry{}
	entry.Job.ID = id
	entry.Job.Status = "pending"
	entry.Job.Total = total
	entry.Job.StartedAt = time.Now()

	s.mu.Lock()
	s.jobs[id] = entry
	s.mu.Unlock()
}

// GetJob returns a snapshot of the job (copy-safe)
func (s *Store) GetJob(id string) (models.ScanJob, bool) {
	s.mu.RLock()
	entry, ok := s.jobs[id]
	s.mu.RUnlock()
	if !ok {
		return models.ScanJob{}, false
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.Job, true
}

// SetStatus updates job status
func (s *Store) SetStatus(id, status string) {
	s.mu.RLock()
	entry, ok := s.jobs[id]
	s.mu.RUnlock()
	if !ok {
		return
	}
	entry.mu.Lock()
	entry.Job.Status = status
	if status == "complete" || status == "error" {
		now := time.Now()
		entry.Job.CompletedAt = &now
	}
	entry.mu.Unlock()
}

// AppendResult adds a result and increments counters
func (s *Store) AppendResult(id string, r models.ScanResult) {
	s.mu.RLock()
	entry, ok := s.jobs[id]
	s.mu.RUnlock()
	if !ok {
		return
	}
	entry.mu.Lock()
	entry.Job.Results = append(entry.Job.Results, r)
	entry.Job.Processed++
	if r.Error == "" && r.Status > 0 {
		entry.Job.Live++
	} else if r.Error != "" {
		entry.Job.Errors++
	}
	entry.mu.Unlock()
}

// IncrProcessed increments processed counter without appending result
func (s *Store) IncrProcessed(id string) {
	s.mu.RLock()
	entry, ok := s.jobs[id]
	s.mu.RUnlock()
	if !ok {
		return
	}
	entry.mu.Lock()
	entry.Job.Processed++
	entry.Job.Errors++
	entry.mu.Unlock()
}

// GetProgress returns lightweight progress counters
func (s *Store) GetProgress(id string) (total, processed, live, errors int, status string, ok bool) {
	s.mu.RLock()
	entry, exists := s.jobs[id]
	s.mu.RUnlock()
	if !exists {
		return 0, 0, 0, 0, "", false
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.Job.Total, entry.Job.Processed, entry.Job.Live,
		entry.Job.Errors, entry.Job.Status, true
}

// AllJobs returns all job IDs and statuses (for listing)
func (s *Store) AllJobs() []models.ScanJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.ScanJob, 0, len(s.jobs))
	for _, e := range s.jobs {
		e.mu.Lock()
		// Return lightweight copy without results slice
		j := e.Job
		j.Results = nil
		e.mu.Unlock()
		out = append(out, j)
	}
	return out
}
