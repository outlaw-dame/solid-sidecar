package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/audit"
	"github.com/outlaw-dame/solid-sidecar/internal/config"
	"github.com/outlaw-dame/solid-sidecar/internal/observability"
)

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

var spoofableForwardedHeaders = []string{
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Real-IP",
}

// New creates the CSS reverse proxy. It keeps behavior intentionally boring:
// forward method/path/query/body to CSS, apply backend timeouts, set trusted
// forwarded headers, and strip hop-by-hop and spoofable forwarded headers.
func New(cfg config.Config, logger *slog.Logger) (http.Handler, error) {
	backend, err := url.Parse(cfg.Backend.URL)
	if err != nil {
		return nil, fmt.Errorf("parse backend URL: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.DialContext = (&net.Dialer{
		Timeout:   cfg.Backend.Timeout,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.ResponseHeaderTimeout = cfg.Backend.Timeout
	transport.ExpectContinueTimeout = time.Second

	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			originalHost := proxyRequest.In.Host
			originalScheme := schemeFor(proxyRequest.In)
			clientIP := audit.RemoteIP(proxyRequest.In)
			proxyRequest.SetURL(backend)
			// Use localhost as the host to match CSS baseUrl configuration
			// CSS is configured with --baseUrl http://localhost:3000
			// This ensures identifier space validation passes while still
			// connecting to the correct backend service
			proxyRequest.Out.Host = "localhost:" + backend.Port()
			stripHopByHopHeaders(proxyRequest.Out.Header)
			stripSpoofableForwardedHeaders(proxyRequest.Out.Header)
			proxyRequest.Out.Header.Set("X-Forwarded-For", clientIP)
			proxyRequest.Out.Header.Set("X-Forwarded-Host", originalHost)
			proxyRequest.Out.Header.Set("X-Forwarded-Proto", originalScheme)
			if requestID := observability.RequestIDFromContext(proxyRequest.In.Context()); requestID != "" {
				proxyRequest.Out.Header.Set("X-Request-ID", requestID)
			}
		},
	}
	reverseProxy.Transport = roundTripperWithTimeout{base: transport, timeout: cfg.Backend.Timeout}
	reverseProxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		logger.Error("backend proxy failure",
			"request_id", observability.RequestIDFromContext(req.Context()),
			"method", req.Method,
			"path", req.URL.EscapedPath(),
			"error", err.Error(),
		)
		http.Error(w, "backend unavailable", http.StatusBadGateway)
	}
	reverseProxy.ModifyResponse = func(resp *http.Response) error {
		stripHopByHopHeaders(resp.Header)
		return nil
	}
	return LimitBody(cfg.Limits.MaxBodyBytes, reverseProxy), nil
}

type roundTripperWithTimeout struct {
	base    http.RoundTripper
	timeout time.Duration
}

func (r roundTripperWithTimeout) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.timeout <= 0 {
		return nil, errors.New("backend timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(req.Context(), r.timeout)
	defer cancel()
	return r.base.RoundTrip(req.WithContext(ctx))
}

func LimitBody(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if maxBytes <= 0 {
			http.Error(w, "invalid body limit", http.StatusInternalServerError)
			return
		}
		if r.ContentLength > maxBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}

func stripHopByHopHeaders(header http.Header) {
	if connection := header.Get("Connection"); connection != "" {
		for _, value := range strings.Split(connection, ",") {
			header.Del(strings.TrimSpace(value))
		}
	}
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

func stripSpoofableForwardedHeaders(header http.Header) {
	for _, h := range spoofableForwardedHeaders {
		header.Del(h)
	}
}

func schemeFor(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}
