package ratelimit

import (
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/audit"
)

type Limiter struct {
	mu      sync.Mutex
	entries map[string]entry
	max     int
	window  time.Duration
	now     func() time.Time
}

type entry struct {
	count int
	reset time.Time
}

func New(max int, window time.Duration) *Limiter {
	return &Limiter{
		entries: make(map[string]entry),
		max:     max,
		window:  window,
		now:     time.Now,
	}
}

func (l *Limiter) Allow(key string) (allowed bool, remaining int, reset time.Time) {
	if key == "" {
		key = "unknown"
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	current := l.entries[key]
	if current.reset.IsZero() || !now.Before(current.reset) {
		current = entry{count: 0, reset: now.Add(l.window)}
	}
	if current.count >= l.max {
		l.entries[key] = current
		return false, 0, current.reset
	}
	current.count++
	l.entries[key] = current
	return true, l.max - current.count, current.reset
}

func Middleware(logger *slog.Logger, limiter *Limiter, next http.Handler) http.Handler {
	if limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		allowed, remaining, reset := limiter.Allow(audit.RemoteIP(r))
		w.Header().Set("RateLimit-Limit", strconv.Itoa(limiter.max))
		w.Header().Set("RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		if !allowed {
			w.Header().Set("Retry-After", strconv.FormatInt(maxInt64(1, int64(time.Until(reset).Seconds())), 10))
			audit.LogRejectedRequest(logger, r, http.StatusTooManyRequests, "rate limit exceeded")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
