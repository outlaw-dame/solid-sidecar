package safety

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/outlaw-dame/solid-sidecar/internal/audit"
)

// RejectUnsafeRequests blocks request-target and header forms that are unsafe
// for a front-door reverse proxy. It deliberately rejects encoded dot segments
// because allowing them through the sidecar risks backend/path normalization
// disagreement.
func RejectUnsafeRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := ValidateRequest(r); err != nil {
			audit.LogRejectedRequest(logger, r, http.StatusBadRequest, err.Error())
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ValidateRequest(r *http.Request) error {
	if r.URL == nil {
		return fmt.Errorf("missing request URL")
	}
	if r.URL.IsAbs() {
		return fmt.Errorf("absolute-form request target is not accepted")
	}
	if r.URL.Path == "" || !strings.HasPrefix(r.URL.Path, "/") {
		return fmt.Errorf("path must start with /")
	}
	if !utf8.ValidString(r.URL.Path) || !utf8.ValidString(r.URL.RawPath) {
		return fmt.Errorf("path must be valid UTF-8")
	}
	decodedPath, err := url.PathUnescape(r.URL.EscapedPath())
	if err != nil {
		return fmt.Errorf("path contains invalid escape sequence")
	}
	if strings.ContainsAny(decodedPath, "\x00\\") {
		return fmt.Errorf("path contains unsafe characters")
	}
	for _, segment := range strings.Split(decodedPath, "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("path contains dot segment")
		}
	}
	for name, values := range r.Header {
		if strings.ContainsAny(name, "\r\n\x00") {
			return fmt.Errorf("header name contains control characters")
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n\x00") {
				return fmt.Errorf("header %s contains control characters", name)
			}
		}
	}
	return ValidateWriteRequest(r)
}
