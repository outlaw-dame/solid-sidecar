package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/authn"
	"github.com/outlaw-dame/solid-sidecar/internal/authz"
	"github.com/outlaw-dame/solid-sidecar/internal/config"
	"github.com/outlaw-dame/solid-sidecar/internal/health"
	"github.com/outlaw-dame/solid-sidecar/internal/observability"
	"github.com/outlaw-dame/solid-sidecar/internal/proxy"
	"github.com/outlaw-dame/solid-sidecar/internal/ratelimit"
	"github.com/outlaw-dame/solid-sidecar/internal/safety"
)

type Server struct {
	cfg          config.Config
	logger       *slog.Logger
	http         *http.Server
	authzMetrics *authz.ShadowMetrics
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

	var limiter *ratelimit.Limiter
	if cfg.RateLimit.Enabled {
		limiter = ratelimit.New(cfg.RateLimit.RequestsPerWindow, cfg.RateLimit.Window)
	}
	authCache := authn.NewReplayCache()
	authzMetrics := authz.NewShadowMetrics()

	inner := authn.Middleware(cfg.Auth, logger, authCache, mux)
	if cfg.Authz.ShadowEnabled {
		evaluator, err := newAuthzEvaluator(cfg.Authz)
		if err != nil {
			return nil, err
		}
		inner = authz.Middleware(authz.MiddlewareOptions{
			BuildOptions:      authz.BuildOptions{PublicBaseURL: cfg.Authz.PublicBaseURL},
			Evaluator:         evaluator,
			FallbackEvaluator: newAuthzFallbackEvaluator(cfg.Authz),
			Logger:            logger,
			Metrics:           authzMetrics,
		}, inner)
	}

	handler := observability.RequestID(
		observability.AccessLog(logger,
			safety.SecurityHeaders(
				safety.RejectUnsafeRequests(logger,
					safety.NewOriginPolicy(cfg.Security.AllowedOrigins).Middleware(
						ratelimit.Middleware(logger, limiter, inner),
					),
				),
			),
		),
	)
	httpServer := &http.Server{
		Addr:              cfg.Server.Address,
		Handler:           handler,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}
	return &Server{cfg: cfg, logger: logger, http: httpServer, authzMetrics: authzMetrics}, nil
}

func newAuthzEvaluator(cfg config.AuthzConfig) (authz.Evaluator, error) {
	switch cfg.Evaluator {
	case config.DefaultAuthzEvaluatorLocal:
		return authz.NewShadowEvaluator(), nil
	case config.DefaultAuthzEvaluatorExternalCLI:
		externalEvaluator, err := authz.NewExternalCLIEvaluator(authz.ExternalCLIEvaluatorOptions{
			Command:        cfg.ExternalCommand,
			Args:           cfg.ExternalArgs,
			Timeout:        cfg.ExternalTimeout,
			MaxOutputBytes: cfg.ExternalMaxOutputBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("create external authz evaluator: %w", err)
		}
		evaluator, err := authz.NewBackoffEvaluator(authz.BackoffEvaluatorOptions{
			Evaluator: externalEvaluator,
			BaseDelay: cfg.ExternalBackoffBaseDelay,
			MaxDelay:  cfg.ExternalBackoffMaxDelay,
		})
		if err != nil {
			return nil, fmt.Errorf("create backoff authz evaluator: %w", err)
		}
		return evaluator, nil
	default:
		return nil, fmt.Errorf("unsupported authz evaluator %q", cfg.Evaluator)
	}
}

func newAuthzFallbackEvaluator(cfg config.AuthzConfig) authz.Evaluator {
	if cfg.Evaluator == config.DefaultAuthzEvaluatorExternalCLI {
		return authz.NewShadowEvaluator()
	}
	return nil
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

// ShutdownDelayForTests exposes the configured timeout to tests without making
// the entire http.Server public.
func (s *Server) ShutdownDelayForTests() time.Duration {
	return s.cfg.Server.ShutdownTimeout
}

func (s *Server) AuthzMetricsSnapshotForTests() authz.ShadowMetricsSnapshot {
	return s.authzMetrics.Snapshot()
}
