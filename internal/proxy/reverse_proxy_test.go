package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/config"
	"github.com/outlaw-dame/solid-sidecar/internal/observability"
)

func TestReverseProxyForwardsPathQueryAndHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/alice/profile/card?x=1" {
			t.Fatalf("unexpected backend URL: %s", r.URL.String())
		}
		if r.Header.Get("X-Forwarded-Host") != "pod.example" {
			t.Fatalf("missing forwarded host: %q", r.Header.Get("X-Forwarded-Host"))
		}
		if r.Header.Get("Connection") != "" {
			t.Fatalf("hop-by-hop header leaked: %q", r.Header.Get("Connection"))
		}
		w.Header().Set("X-Backend", "css")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	cfg := config.Defaults()
	cfg.Backend.URL = backend.URL
	handler, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://pod.example/alice/profile/card?x=1", nil)
	req.Host = "pod.example"
	req.Header.Set("Connection", "close")
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-1"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status mismatch: %d", rr.Code)
	}
	if rr.Header().Get("X-Backend") != "css" {
		t.Fatalf("backend header missing")
	}
}

func TestLimitBodyRejectsLargeContentLength(t *testing.T) {
	called := false
	handler := LimitBody(4, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("hello"))
	req.ContentLength = 5
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if called {
		t.Fatal("next handler should not be called")
	}
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

func TestReverseProxyReturnsBadGatewayForBackendError(t *testing.T) {
	cfg := config.Defaults()
	cfg.Backend.URL = "http://127.0.0.1:1"
	cfg.Backend.Timeout = 50 * time.Millisecond
	handler, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rr.Code)
	}
}
