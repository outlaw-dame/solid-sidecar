package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/authn"
	"github.com/outlaw-dame/solid-sidecar/internal/authz"
	"github.com/outlaw-dame/solid-sidecar/internal/compression"
	"github.com/outlaw-dame/solid-sidecar/internal/config"
	"github.com/outlaw-dame/solid-sidecar/internal/health"
	"github.com/outlaw-dame/solid-sidecar/internal/observability"
	"github.com/outlaw-dame/solid-sidecar/internal/proxy"
	"github.com/outlaw-dame/solid-sidecar/internal/ratelimit"
	"github.com/outlaw-dame/solid-sidecar/internal/safety"
	"github.com/outlaw-dame/solid-sidecar/internal/sai"
)

type Server struct {
	cfg             config.Config
	logger          *slog.Logger
	http            *http.Server
	authzMetrics    *authz.ShadowMetrics
	enforcementGate *authz.EnforcementGate
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

	// Add SAI routes if SAI is enabled
	if cfg.SAI.Enabled {
		saiService, err := createSAIService(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("create SAI service: %w", err)
		}

		// Create IdentityVerifier for SAI authentication
		// Use the same authn configuration as the main authn middleware
		var saiIdentityVerifier *authn.IdentityVerifier
		if cfg.Auth.IdentityValidationEnabled && len(cfg.Auth.AllowedIdentityIssuers) > 0 {
			// Create HTTP client for issuer discovery (nil uses default HTTP client)
			discoveryClient := authn.NewIssuerDiscoveryClient(nil)
			saiIdentityVerifier = authn.NewIdentityVerifierWithWebID(
				discoveryClient,
				authn.IdentityValidationOptions{
					AllowedIssuers:   cfg.Auth.AllowedIdentityIssuers,
					ExpectedAudience: cfg.Auth.ExpectedIdentityAudience,
					Now:              time.Now(),
					ClockSkew:        cfg.Auth.MaxClockSkew,
				},
				cfg.Auth.VerifyWebIDOwnership,
			)
		}

		// If SAI requires authentication and it's not configured, fail to start
		if cfg.SAI.RequireAuthentication && saiIdentityVerifier == nil {
			return nil, fmt.Errorf("SAI requires authentication but identity validation is not configured. Configure Auth.AllowedIdentityIssuers or set SAI.RequireAuthentication to false")
		}

		// Log warning if SAI is enabled without authentication
		if !cfg.SAI.RequireAuthentication && saiIdentityVerifier == nil {
			logger.Warn("SAI authentication will use fail-secure mode: identity validation not configured. All SAI endpoints will deny access.")
		}

		// Create SAI authenticator with identity verifier
		var saiAuthenticator sai.Authenticator
		if saiIdentityVerifier != nil {
			saiAuthenticator = sai.NewDefaultAuthenticator(logger, saiIdentityVerifier)
		} else {
			// Even without identity verifier, create authenticator (will fail-secure)
			saiAuthenticator = sai.NewDefaultAuthenticator(logger, nil)
		}

		// Create configurable rate limiter for SAI
		var saiRateLimiter *sai.RateLimiter
		if cfg.SAI.RateLimit.Enabled {
			if cfg.SAI.RateLimit.RequestsPerWindow <= 0 {
				cfg.SAI.RateLimit.RequestsPerWindow = 100
			}
			if cfg.SAI.RateLimit.Window <= 0 {
				cfg.SAI.RateLimit.Window = 1 * time.Minute
			}
			saiRateLimiter = sai.NewRateLimiter(
				cfg.SAI.RateLimit.RequestsPerWindow,
				cfg.SAI.RateLimit.Window,
			)
		} else {
			// Use default rate limiter if not configured
			saiRateLimiter = sai.NewRateLimiter(
				sai.DefaultSAIRateLimitRequestsPerWindow,
				sai.DefaultSAIRateLimitWindow,
			)
		}

		// Determine max body size
		maxBodySize := cfg.SAI.MaxRequestBodySize
		if maxBodySize <= 0 {
			maxBodySize = sai.DefaultMaxSAIRequestBodySize
		}

		// Create SAI handler with security middleware
		saiHandler := sai.NewHandler(saiService, sai.HandlerOptions{
			Logger:        logger,
			RateLimiter:   saiRateLimiter,
			Authenticator: saiAuthenticator,
			MaxBodySize:   maxBodySize,
		})
		saiHandler.RegisterRoutes(mux)
		logger.Info("SAI support enabled with authorization agent", "url", cfg.SAI.AuthorizationAgentURL)
	}

	mux.Handle("/", proxyHandler)

	var limiter *ratelimit.Limiter
	if cfg.RateLimit.Enabled {
		limiter = ratelimit.New(cfg.RateLimit.RequestsPerWindow, cfg.RateLimit.Window)
	}
	authCache := authn.NewReplayCache()
	authzMetrics := authz.NewShadowMetrics()

	// Create enforcement gate with startup guardrails
	// Enforcement is disabled by default (AllowEnforcement: false)
	enforcementGate, err := authz.NewEnforcementGate(authz.EnforcementGateOptions{
		InitialMode:            authz.EnforcementModeShadow,
		AllowEnforcement:       false, // Startup guardrail: must be explicitly enabled
		EmergencyBypassEnabled: true,
		MaxEnforcementDuration: 0, // No auto-revert by default
		MethodAllowlist:        []string{"GET", "HEAD"},
		AuditLogger:            logger,
		Logger:                 logger,
	})
	if err != nil {
		return nil, fmt.Errorf("create enforcement gate: %w", err)
	}

	// Create compression middleware config from the main config
	// Initialize metrics for compression observation
	compressionMetrics := compression.NewMetrics()
	compressionConfig := compression.Config{
		Responses: compression.ResponsesConfig{
			Enabled:                cfg.Compression.Responses.Enabled,
			Gzip:                   compression.GzipConfig(cfg.Compression.Responses.Gzip),
			Zstd:                   compression.ZstdConfig(cfg.Compression.Responses.Zstd),
			Prefer:                 cfg.Compression.Responses.Prefer,
			SkipContentTypes:       cfg.Compression.Responses.SkipContentTypes,
			SkipSensitiveResponses: cfg.Compression.Responses.SkipSensitiveResponses,
			SkipErrorResponses:     cfg.Compression.Responses.SkipErrorResponses,
			SkipRanges:             cfg.Compression.Responses.SkipRanges,
			MinBytes:               cfg.Compression.Responses.MinBytes,
		},
		Requests: compression.RequestsConfig{
			Enabled:              cfg.Compression.Requests.Enabled,
			AllowedEncodings:     cfg.Compression.Requests.AllowedEncodings,
			MaxDecompressedBytes: cfg.Compression.Requests.MaxDecompressedBytes,
			ZstdEnabled:          cfg.Compression.Requests.ZstdEnabled,
		},
		Metrics: compressionMetrics,
	}

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

	// Add enforcement gate middleware for authorization enforcement control
	inner = authz.EnforcementGateMiddleware(enforcementGate, inner)

	// Add compression middleware if enabled
	if cfg.Compression.Responses.Enabled || cfg.Compression.Requests.Enabled {
		inner = compression.Middleware(compressionConfig)(inner)
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
	return &Server{cfg: cfg, logger: logger, http: httpServer, authzMetrics: authzMetrics, enforcementGate: enforcementGate}, nil
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

func createSAIService(cfg config.Config, logger *slog.Logger) (*sai.SAIService, error) {
	saiOptions := sai.SAIServiceOptions{
		Logger:                logger,
		Timeout:               cfg.SAI.Timeout,
		MaxRetries:            cfg.SAI.MaxRetries,
		AuthorizationAgentURL: cfg.SAI.AuthorizationAgentURL,
		BaseURL:               cfg.Backend.URL,
		Storage:               sai.NewInMemorySAIStorage(), // In-memory storage for now
	}
	return sai.NewSAIService(saiOptions)
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

// EnforcementGateForTests exposes the enforcement gate for testing
func (s *Server) EnforcementGateForTests() *authz.EnforcementGate {
	return s.enforcementGate
}
