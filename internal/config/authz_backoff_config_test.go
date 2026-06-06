package config

import (
	"testing"
	"time"
)

func TestAuthzBackoffDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Authz.ExternalBackoffBaseDelay != DefaultAuthzExternalBackoffBaseDelay {
		t.Fatalf("base delay = %s, want %s", cfg.Authz.ExternalBackoffBaseDelay, DefaultAuthzExternalBackoffBaseDelay)
	}
	if cfg.Authz.ExternalBackoffMaxDelay != DefaultAuthzExternalBackoffMaxDelay {
		t.Fatalf("max delay = %s, want %s", cfg.Authz.ExternalBackoffMaxDelay, DefaultAuthzExternalBackoffMaxDelay)
	}
}

func TestAuthzBackoffEnvOverrides(t *testing.T) {
	t.Setenv("SOLID_SIDECAR_AUTHZ_EXTERNAL_BACKOFF_BASE_DELAY", "250ms")
	t.Setenv("SOLID_SIDECAR_AUTHZ_EXTERNAL_BACKOFF_MAX_DELAY", "4s")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Authz.ExternalBackoffBaseDelay != 250*time.Millisecond {
		t.Fatalf("base delay = %s, want 250ms", cfg.Authz.ExternalBackoffBaseDelay)
	}
	if cfg.Authz.ExternalBackoffMaxDelay != 4*time.Second {
		t.Fatalf("max delay = %s, want 4s", cfg.Authz.ExternalBackoffMaxDelay)
	}
}

func TestValidateRejectsUnsafeAuthzBackoffBounds(t *testing.T) {
	cfg := Defaults()
	cfg.Authz.ExternalBackoffBaseDelay = 0
	if err := Validate(cfg); err == nil {
		t.Fatal("expected zero base delay validation error")
	}

	cfg = Defaults()
	cfg.Authz.ExternalBackoffMaxDelay = 0
	if err := Validate(cfg); err == nil {
		t.Fatal("expected zero max delay validation error")
	}

	cfg = Defaults()
	cfg.Authz.ExternalBackoffBaseDelay = 5 * time.Second
	cfg.Authz.ExternalBackoffMaxDelay = time.Second
	if err := Validate(cfg); err == nil {
		t.Fatal("expected inverted backoff validation error")
	}

	cfg = Defaults()
	cfg.Authz.ExternalBackoffMaxDelay = maxAuthzExternalBackoffMaxDelay + time.Second
	if err := Validate(cfg); err == nil {
		t.Fatal("expected excessive max delay validation error")
	}
}
