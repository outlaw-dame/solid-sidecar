package audit

import (
	"net/http/httptest"
	"testing"
)

func TestRemoteIPParsesHostPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	if got := RemoteIP(req); got != "192.0.2.10" {
		t.Fatalf("unexpected remote IP: %q", got)
	}
}
