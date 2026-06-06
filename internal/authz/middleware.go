package authz

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/outlaw-dame/solid-sidecar/internal/observability"
)

const (
	ShadowLogMessageDecision                = "authz shadow decision"
	ShadowLogMessageRequestBuildFailed      = "authz request build failed"
	ShadowLogMessageEvaluationFailed        = "authz evaluation failed"
	ShadowLogMessageEvaluationBackoffActive = "authz evaluation skipped during backoff"
	ShadowLogMessageInvalidDecision         = "authz evaluation returned invalid decision"
	ShadowLogMessageFallbackFailed          = "authz fallback evaluation failed"
	ShadowErrorReasonRequestBuildFailed     = "request_build_failed"
	ShadowErrorReasonEvaluationFailed       = "evaluation_failed"
	ShadowErrorReasonBackoffActive          = "backoff_active"
	ShadowErrorReasonInvalidDecision        = "invalid_decision"
	ShadowErrorReasonFallbackFailed         = "fallback_failed"
)

const (
	ShadowLogFieldMethod          = "method"
	ShadowLogFieldPath            = "path"
	ShadowLogFieldRequestID       = "request_id"
	ShadowLogFieldErrorReason     = "error_reason"
	ShadowLogFieldDecision        = "decision"
	ShadowLogFieldReasonCode      = "reason_code"
	ShadowLogFieldStatusHint      = "status_hint"
	ShadowLogFieldCacheTTLSeconds = "cache_ttl_seconds"
	ShadowLogFieldPolicyVersion   = "policy_version"
	ShadowLogFieldResourceVersion = "resource_version"
	ShadowLogFieldRequestHash     = "request_hash"
	ShadowLogFieldPolicyHash      = "policy_hash"
)

type MiddlewareOptions struct {
	BuildOptions      BuildOptions
	Evaluator         Evaluator
	FallbackEvaluator Evaluator
	Logger            *slog.Logger
	Metrics           ShadowMetricsRecorder
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
			logShadowError(options.Logger, r, ShadowLogMessageRequestBuildFailed, ShadowErrorReasonRequestBuildFailed)
			recordShadowWarningMetric(options.Metrics, ShadowErrorReasonRequestBuildFailed)
			next.ServeHTTP(w, r)
			return
		}

		decision, err := evaluator.Evaluate(r.Context(), request)
		if err != nil {
			message, reason := evaluationWarning(err)
			logShadowError(options.Logger, r, message, reason)
			recordShadowWarningMetric(options.Metrics, reason)
			if !evaluateFallback(options.Logger, options.Metrics, r, request, options.FallbackEvaluator) {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if err := ValidateDecision(decision); err != nil {
			logShadowError(options.Logger, r, ShadowLogMessageInvalidDecision, ShadowErrorReasonInvalidDecision)
			recordShadowWarningMetric(options.Metrics, ShadowErrorReasonInvalidDecision)
			if !evaluateFallback(options.Logger, options.Metrics, r, request, options.FallbackEvaluator) {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		logShadowDecision(options.Logger, r, decision)
		recordShadowDecisionMetric(options.Metrics, ShadowMetricDecision, decision)
		next.ServeHTTP(w, r)
	})
}

func evaluationWarning(err error) (string, string) {
	if errors.Is(err, ErrEvaluatorBackoffActive) {
		return ShadowLogMessageEvaluationBackoffActive, ShadowErrorReasonBackoffActive
	}
	return ShadowLogMessageEvaluationFailed, ShadowErrorReasonEvaluationFailed
}

func evaluateFallback(logger *slog.Logger, metrics ShadowMetricsRecorder, r *http.Request, request Request, evaluator Evaluator) bool {
	if evaluator == nil {
		return false
	}
	decision, err := evaluator.Evaluate(r.Context(), request)
	if err != nil {
		logShadowError(logger, r, ShadowLogMessageFallbackFailed, ShadowErrorReasonFallbackFailed)
		recordShadowMetric(metrics, ShadowMetricEvent{Event: ShadowMetricFallbackFailure, ErrorReason: ShadowErrorReasonFallbackFailed})
		return false
	}
	if err := ValidateDecision(decision); err != nil {
		logShadowError(logger, r, ShadowLogMessageFallbackFailed, ShadowErrorReasonFallbackFailed)
		recordShadowMetric(metrics, ShadowMetricEvent{Event: ShadowMetricFallbackFailure, ErrorReason: ShadowErrorReasonFallbackFailed})
		return false
	}
	logShadowDecision(logger, r, decision)
	recordShadowDecisionMetric(metrics, ShadowMetricFallbackDecision, decision)
	return true
}

func logShadowError(logger *slog.Logger, r *http.Request, message string, reason string) {
	if logger == nil {
		return
	}
	logger.Warn(message,
		ShadowLogFieldMethod, r.Method,
		ShadowLogFieldPath, r.URL.EscapedPath(),
		ShadowLogFieldRequestID, observability.RequestIDFromContext(r.Context()),
		ShadowLogFieldErrorReason, reason,
	)
}

func logShadowDecision(logger *slog.Logger, r *http.Request, decision Decision) {
	if logger == nil {
		return
	}
	logger.Debug(ShadowLogMessageDecision,
		ShadowLogFieldMethod, r.Method,
		ShadowLogFieldPath, r.URL.EscapedPath(),
		ShadowLogFieldRequestID, decision.RequestID,
		ShadowLogFieldDecision, decision.Decision,
		ShadowLogFieldReasonCode, decision.ReasonCode,
		ShadowLogFieldStatusHint, decision.StatusHint,
		ShadowLogFieldCacheTTLSeconds, decision.CacheTTLSeconds,
		ShadowLogFieldPolicyVersion, decision.PolicyVersion,
		ShadowLogFieldResourceVersion, decision.ResourceVersion,
		ShadowLogFieldRequestHash, decision.Audit.RequestHash,
		ShadowLogFieldPolicyHash, decision.Audit.PolicyHash,
	)
}

func recordShadowWarningMetric(metrics ShadowMetricsRecorder, reason string) {
	recordShadowMetric(metrics, ShadowMetricEvent{Event: ShadowMetricWarning, ErrorReason: reason})
}

func recordShadowDecisionMetric(metrics ShadowMetricsRecorder, event string, decision Decision) {
	recordShadowMetric(metrics, ShadowMetricEvent{
		Event:      event,
		Decision:   decision.Decision,
		ReasonCode: decision.ReasonCode,
	})
}
