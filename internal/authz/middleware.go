package authz

import (
	"log/slog"
	"net/http"
)

type MiddlewareOptions struct {
	BuildOptions BuildOptions
	Evaluator    Evaluator
	Logger       *slog.Logger
}

func Middleware(options MiddlewareOptions, next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	evaluator := options.Evaluator
	if evaluator == nil {
		evaluator = NewShadowEvaluator()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := BuildRequest(r, options.BuildOptions)
		if err != nil {
			logShadowError(options.Logger, r, "authz request build failed", err)
			next.ServeHTTP(w, r)
			return
		}

		decision, err := evaluator.Evaluate(r.Context(), request)
		if err != nil {
			logShadowError(options.Logger, r, "authz evaluation failed", err)
			next.ServeHTTP(w, r)
			return
		}

		logShadowDecision(options.Logger, r, decision)
		next.ServeHTTP(w, r)
	})
}

func logShadowError(logger *slog.Logger, r *http.Request, message string, err error) {
	if logger == nil {
		return
	}
	logger.Warn(message,
		"method", r.Method,
		"path", r.URL.EscapedPath(),
		"error", err.Error(),
	)
}

func logShadowDecision(logger *slog.Logger, r *http.Request, decision Decision) {
	if logger == nil {
		return
	}
	logger.Debug("authz shadow decision",
		"method", r.Method,
		"path", r.URL.EscapedPath(),
		"request_id", decision.RequestID,
		"decision", decision.Decision,
		"reason_code", decision.ReasonCode,
	)
}
