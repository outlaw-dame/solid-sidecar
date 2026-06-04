package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/observability"
)

func TestBuildRequestUsesContextRequestIDAndPublicBaseURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://internal/alice/card?x=1#ignored", nil)
	req = req.WithContext(observability.WithRequestID(req.Context(), "req-123"))
	req.Header.Set("Origin", "https://app.example")

	built, err := BuildRequest(req, BuildOptions{
		PublicBaseURL: "https://pod.example/base/",
		Now:           fixedNow,
	})
	if err != nil {
		t.Fatalf("BuildRequest returned error: %v", err)
	}

	if built.SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected schema version: %q", built.SchemaVersion)
	}
	if built.RequestID != "req-123" {
		t.Fatalf("unexpected request id: %q", built.RequestID)
	}
	if built.ResourceURI != "https://pod.example/base/alice/card?x=1" {
		t.Fatalf("unexpected resource uri: %q", built.ResourceURI)
	}
	if built.Origin != "https://app.example" {
		t.Fatalf("unexpected origin: %q", built.Origin)
	}
	if built.NowUnix != fixedNow().Unix() {
		t.Fatalf("unexpected now_unix: %d", built.NowUnix)
	}
	assertModes(t, built.RequestedModes, []AccessMode{AccessModeRead})
}

func TestBuildRequestFallsBackToHeaderRequestID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://pod.example/inbox", nil)
	req.Header.Set("X-Request-ID", "from-header")

	built, err := BuildRequest(req, BuildOptions{Now: fixedNow})
	if err != nil {
		t.Fatalf("BuildRequest returned error: %v", err)
	}

	if built.RequestID != "from-header" {
		t.Fatalf("unexpected request id: %q", built.RequestID)
	}
	if built.ResourceURI != "http://pod.example/inbox" {
		t.Fatalf("unexpected resource uri: %q", built.ResourceURI)
	}
	assertModes(t, built.RequestedModes, []AccessMode{AccessModeAppend})
}

func TestBuildRequestRequiresRequestID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://pod.example/card", nil)
	req = req.WithContext(context.Background())

	if _, err := BuildRequest(req, BuildOptions{Now: fixedNow}); err == nil {
		t.Fatal("expected missing request id to fail")
	}
}

func TestModesForMethod(t *testing.T) {
	tests := []struct {
		method string
		modes  []AccessMode
	}{
		{method: http.MethodGet, modes: []AccessMode{AccessModeRead}},
		{method: http.MethodHead, modes: []AccessMode{AccessModeRead}},
		{method: http.MethodOptions, modes: []AccessMode{AccessModeRead}},
		{method: http.MethodPost, modes: []AccessMode{AccessModeAppend}},
		{method: http.MethodPut, modes: []AccessMode{AccessModeWrite}},
		{method: http.MethodPatch, modes: []AccessMode{AccessModeWrite}},
		{method: http.MethodDelete, modes: []AccessMode{AccessModeWrite}},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			modes, err := modesForMethod(tt.method)
			if err != nil {
				t.Fatalf("modesForMethod returned error: %v", err)
			}
			assertModes(t, modes, tt.modes)
		})
	}

	if _, err := modesForMethod("TRACE"); err == nil {
		t.Fatal("expected unsupported method to fail")
	}
}

func TestResourceURIRequiresHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/relative", nil)
	req.Host = ""

	if _, err := resourceURIForRequest(req, ""); err == nil {
		t.Fatal("expected missing host to fail")
	}
}

func TestJoinBaseAndRequestPath(t *testing.T) {
	tests := []struct {
		base string
		req  string
		want string
	}{
		{base: "", req: "/a", want: "/a"},
		{base: "/base", req: "/a", want: "/base/a"},
		{base: "/base/", req: "/a", want: "/base/a"},
		{base: "/base", req: "/", want: "/base"},
	}

	for _, tt := range tests {
		if got := joinBaseAndRequestPath(tt.base, tt.req); got != tt.want {
			t.Fatalf("joinBaseAndRequestPath(%q, %q) = %q, want %q", tt.base, tt.req, got, tt.want)
		}
	}
}

func assertModes(t *testing.T, got, want []AccessMode) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("mode length = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("mode[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func fixedNow() time.Time {
	return time.Unix(1_700_000_000, 0).UTC()
}
