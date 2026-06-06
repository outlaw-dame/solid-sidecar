package gateway

import (
	"testing"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/config"
)

func TestNewAuthzEvaluatorDefaultsToLocalShadowEvaluator(t *testing.T) {
	cfg := config.Defaults().Authz
	evaluator, err := newAuthzEvaluator(cfg)
	if err != nil {
		t.Fatalf("newAuthzEvaluator returned error: %v", err)
	}
	if evaluator == nil {
		t.Fatal("expected evaluator")
	}
	if fallback := newAuthzFallbackEvaluator(cfg); fallback != nil {
		t.Fatal("local evaluator should not configure fallback")
	}
}

func TestNewAuthzEvaluatorAcceptsExternalCLIConfig(t *testing.T) {
	cfg := config.Defaults().Authz
	cfg.Evaluator = config.DefaultAuthzEvaluatorExternalCLI
	cfg.ExternalCommand = "/usr/local/bin/solid-policy-kernel-eval"
	cfg.ExternalArgs = []string{"--json"}
	cfg.ExternalTimeout = 500 * time.Millisecond
	cfg.ExternalMaxOutputBytes = 32768
	evaluator, err := newAuthzEvaluator(cfg)
	if err != nil {
		t.Fatalf("newAuthzEvaluator returned error: %v", err)
	}
	if evaluator == nil {
		t.Fatal("expected evaluator")
	}
	if fallback := newAuthzFallbackEvaluator(cfg); fallback == nil {
		t.Fatal("external evaluator should configure local fallback")
	}
}

func TestNewAuthzEvaluatorRejectsUnsupportedEvaluator(t *testing.T) {
	cfg := config.Defaults().Authz
	cfg.Evaluator = "remote"
	if _, err := newAuthzEvaluator(cfg); err == nil {
		t.Fatal("expected error")
	}
}
