// Package health provides liveness and readiness endpoints.
//
// The distinction matters operationally and is routinely got wrong:
//
//	/healthz  LIVENESS  — is the process alive? Checks NOTHING external.
//	                      A failing liveness probe gets the pod KILLED.
//	/readyz   READINESS — can it serve traffic? Checks dependencies.
//	                      A failing readiness probe removes it from the load
//	                      balancer; the pod keeps running.
//
// Putting a database check in liveness is the classic mistake: the database
// blips, every pod fails liveness, Kubernetes kills the entire fleet, and the
// restart storm turns a brief outage into a long one. Liveness answers one
// question — is this process wedged — and nothing else.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Status is a dependency's state.
type Status string

const (
	StatusUp       Status = "up"
	StatusDown     Status = "down"
	StatusDegraded Status = "degraded"
)

// CheckFunc reports on one dependency. It must respect ctx cancellation: a
// probe that hangs is worse than one that fails, because it holds the whole
// readiness response open.
type CheckFunc func(ctx context.Context) error

type check struct {
	name string
	fn   CheckFunc
	// critical=false means a failure degrades rather than un-readies the
	// service. Tracing being down should not remove a service from the load
	// balancer; Postgres being down should.
	critical bool
}

// Checker aggregates dependency checks.
type Checker struct {
	service string
	version string
	mu      sync.RWMutex
	checks  []check
	timeout time.Duration
}

// New returns a Checker.
func New(service, version string) *Checker {
	return &Checker{service: service, version: version, timeout: 3 * time.Second}
}

// Register adds a critical dependency. Failure means not ready.
func (c *Checker) Register(name string, fn CheckFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks = append(c.checks, check{name: name, fn: fn, critical: true})
}

// RegisterOptional adds a non-critical dependency. Failure means degraded but
// still ready to serve.
func (c *Checker) RegisterOptional(name string, fn CheckFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks = append(c.checks, check{name: name, fn: fn, critical: false})
}

type response struct {
	Status  Status            `json:"status"`
	Service string            `json:"service"`
	Version string            `json:"version,omitempty"`
	Checks  map[string]detail `json:"checks,omitempty"`
}

type detail struct {
	Status Status `json:"status"`
	Error  string `json:"error,omitempty"`
	TookMS int64  `json:"took_ms"`
}

// LivenessHandler answers "is this process alive".
//
// It intentionally performs no I/O. If the goroutine scheduler can run this
// handler, the process is alive.
func (c *Checker) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, response{
			Status:  StatusUp,
			Service: c.service,
			Version: c.version,
		})
	}
}

// ReadinessHandler answers "can this instance serve traffic".
//
// Checks run concurrently and each is bounded, so one slow dependency cannot
// stall the probe past its own deadline.
func (c *Checker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), c.timeout)
		defer cancel()

		c.mu.RLock()
		checks := make([]check, len(c.checks))
		copy(checks, c.checks)
		c.mu.RUnlock()

		results := make(map[string]detail, len(checks))
		var mu sync.Mutex
		var wg sync.WaitGroup

		overall := StatusUp
		ready := true

		for _, ch := range checks {
			wg.Add(1)
			go func(ch check) {
				defer wg.Done()
				start := time.Now()
				err := ch.fn(ctx)
				took := time.Since(start).Milliseconds()

				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					results[ch.name] = detail{Status: StatusDown, Error: err.Error(), TookMS: took}
					if ch.critical {
						ready = false
						overall = StatusDown
					} else if overall == StatusUp {
						overall = StatusDegraded
					}
					return
				}
				results[ch.name] = detail{Status: StatusUp, TookMS: took}
			}(ch)
		}
		wg.Wait()

		code := http.StatusOK
		if !ready {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, response{
			Status:  overall,
			Service: c.service,
			Version: c.version,
			Checks:  results,
		})
	}
}

// Mount registers both endpoints on a mux.
func (c *Checker) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", c.LivenessHandler())
	mux.HandleFunc("GET /readyz", c.ReadinessHandler())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Probe responses must never be cached by an intermediary — a cached
	// "healthy" is indistinguishable from a real one and hides an outage.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
