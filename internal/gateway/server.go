package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/config"
	"github.com/outlaw-dame/solid-sidecar/internal/health"
	"github.com/outlaw-dame/solid-sidecar/internal/observability"
	"github.com/outlaw-dame/solid-sidecar/internal/proxy"
)

type Server struct {
	cfg    config.Config
	logger *slog.Logger
	http   *http.Server
}

func New(cfg config.Config, logger *slog.Logger) (*Server, error) {
	probe, err := health.NewProbe(cfg.Backend.URL, cfg.Backend.HealthPath, cfg.Backend.Timeout)
	if err != nil {
		return nil, fmt.Errorf("create health probe: %w", err)
	}
	proxyHandler, err := proxy.New(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("create reverse proxy: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.LivenessHandler())
	mux.Handle("GET /readyz", health.ReadinessHandler(probe))
	mux.Handle("/", proxyHandler)

	handler := observability.RequestID(observability.AccessLog(logger, secureHeaders(mux)))
	httpServer := &http.Server{
		Addr:              cfg.Server.Address,
		Handler:           handler,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}
	return &Server{cfg: cfg, logger: logger, http: httpServer}, nil
}

func (s *Server) ListenAndServe() error {
	s.logger.Info("solid sidecar starting", "address", s.cfg.Server.Address, "backend", s.cfg.Backend.URL)
	if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(ctx, s.cfg.Server.ShutdownTimeout)
	defer cancel()
	s.logger.Info("solid sidecar shutting down")
	return s.http.Shutdown(shutdownCtx)
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// ShutdownDelayForTests exposes the configured timeout to tests without making
// the entire http.Server public.
func (s *Server) ShutdownDelayForTests() time.Duration {
	return s.cfg.Server.ShutdownTimeout
}
