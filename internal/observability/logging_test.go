package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDMiddlewareSanitizesHeaderInjection(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if RequestIDFromContext(r.Context()) == "bad\nvalue" {
			t.Fatal("header injection request id was accepted")
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "bad\nvalue")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected generated request id")
	}
}
