package safety

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateRequestRejectsEncodedDotSegment(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/alice/%2e%2e/secret", nil)
	if err := ValidateRequest(req); err == nil {
		t.Fatal("expected encoded dot segment to be rejected")
	}
}

func TestValidateRequestRejectsBackslash(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/alice/%5csecret", nil)
	if err := ValidateRequest(req); err == nil {
		t.Fatal("expected backslash to be rejected")
	}
}

func TestRejectUnsafeRequestsReturnsBadRequest(t *testing.T) {
	called := false
	handler := RejectUnsafeRequests(slog.New(slog.NewTextHandler(io.Discard, nil)), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/a/%2e%2e/b", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if called {
		t.Fatal("next handler should not be called")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestOriginPolicyAllowsConfiguredOrigin(t *testing.T) {
	policy := NewOriginPolicy([]string{"https://app.example"})
	handler := policy.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatal("expected allow-origin header")
	}
}

func TestOriginPolicyRejectsUnknownOrigin(t *testing.T) {
	policy := NewOriginPolicy([]string{"https://app.example"})
	handler := policy.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}
