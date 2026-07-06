package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Probe struct {
	client    *http.Client
	backend   *url.URL
	healthURL string
}

func NewProbe(backendURL, healthPath string, timeout time.Duration) (*Probe, error) {
	parsed, err := url.Parse(backendURL)
	if err != nil {
		return nil, fmt.Errorf("parse backend URL: %w", err)
	}
	if healthPath == "" {
		healthPath = "/"
	}
	if !strings.HasPrefix(healthPath, "/") {
		return nil, fmt.Errorf("health path must start with /")
	}
	healthURL := parsed.ResolveReference(&url.URL{Path: healthPath}).String()
	return &Probe{
		client:    &http.Client{Timeout: timeout},
		backend:   parsed,
		healthURL: healthURL,
	}, nil
}

func LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

func ReadinessHandler(probe *Probe) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), probe.client.Timeout)
		defer cancel()
		if err := probe.Check(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unready", "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
}

func (p *Probe) Check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.healthURL, nil)
	if err != nil {
		return fmt.Errorf("create backend health request: %w", err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("backend %s unreachable: %w", p.backend.Host, err)
	}
	defer resp.Body.Close()
	// Accept 2xx and 3xx status codes as healthy
	// CSS may redirect from / to other pages, which is still healthy
	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError {
		return fmt.Errorf("backend health returned %d", resp.StatusCode)
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("backend health returned %d", resp.StatusCode)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
