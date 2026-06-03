package audit

import (
	"log/slog"
	"net"
	"net/http"

	"github.com/outlaw-dame/solid-sidecar/internal/observability"
)

// LogRejectedRequest records a rejected request without logging authorization,
// cookies, or other sensitive headers.
func LogRejectedRequest(logger *slog.Logger, r *http.Request, status int, reason string) {
	logger.Warn("request rejected",
		"request_id", observability.RequestIDFromContext(r.Context()),
		"method", r.Method,
		"path", r.URL.EscapedPath(),
		"status", status,
		"reason", reason,
		"remote_ip", RemoteIP(r),
	)
}

func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}
