package health

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReadinessHandlerReady(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	probe, err := NewProbe(backend.URL, "/", time.Second)
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	ReadinessHandler(probe).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", recorder.Code)
	}
}

func TestReadinessHandlerNotReadyWhenBackendReturnsServerError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	probe, err := NewProbe(backend.URL, "/", time.Second)
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	ReadinessHandler(probe).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected HTTP 503, got %d", recorder.Code)
	}
}
