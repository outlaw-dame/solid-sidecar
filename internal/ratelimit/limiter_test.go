package ratelimit

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiterAllow(t *testing.T) {
	limiter := New(2, time.Minute)
	now := time.Unix(100, 0)
	limiter.now = func() time.Time { return now }
	if ok, _, _ := limiter.Allow("client"); !ok {
		t.Fatal("first request should pass")
	}
	if ok, _, _ := limiter.Allow("client"); !ok {
		t.Fatal("second request should pass")
	}
	if ok, _, _ := limiter.Allow("client"); ok {
		t.Fatal("third request should be limited")
	}
	now = now.Add(time.Minute + time.Second)
	if ok, _, _ := limiter.Allow("client"); !ok {
		t.Fatal("request after reset should pass")
	}
}

func TestMiddlewareSkipsHealth(t *testing.T) {
	limiter := New(0, time.Minute)
	handler := Middleware(slog.New(slog.NewTextHandler(io.Discard, nil)), limiter, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected health request to bypass limiter, got %d", rr.Code)
	}
}

func TestMiddlewareLimitsRequests(t *testing.T) {
	limiter := New(1, time.Minute)
	handler := Middleware(slog.New(slog.NewTextHandler(io.Discard, nil)), limiter, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "192.0.2.10:1111"
	handler.ServeHTTP(httptest.NewRecorder(), req)
	rr := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "192.0.2.10:1111"
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
}
