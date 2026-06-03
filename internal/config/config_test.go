package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Server.Address != defaultAddress {
		t.Fatalf("address mismatch: got %q", cfg.Server.Address)
	}
	if cfg.Backend.URL != defaultBackendURL {
		t.Fatalf("backend URL mismatch: got %q", cfg.Backend.URL)
	}
	if !cfg.RateLimit.Enabled {
		t.Fatal("rate limit should be enabled by default")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sidecar.yaml")
	contents := []byte(`server:
  address: ":9443"
  read_header_timeout: "2s"
  read_timeout: "3s"
  write_timeout: "4s"
  idle_timeout: "5s"
  shutdown_timeout: "6s"
  max_header_bytes: 2048
backend:
  url: "http://css:3000"
  health_path: "/.well-known/solid"
  timeout: "7s"
limits:
  max_body_bytes: 1024
rate_limit:
  enabled: true
  requests_per_window: 12
  window: "30s"
security:
  allowed_origins: "https://app.example, https://admin.example"
log:
  level: "debug"
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Server.Address != ":9443" {
		t.Fatalf("address mismatch: %q", cfg.Server.Address)
	}
	if cfg.Server.MaxHeaderBytes != 2048 {
		t.Fatalf("max header bytes mismatch: %d", cfg.Server.MaxHeaderBytes)
	}
	if cfg.Backend.HealthPath != "/.well-known/solid" {
		t.Fatalf("health path mismatch: %q", cfg.Backend.HealthPath)
	}
	if cfg.Backend.Timeout != 7*time.Second {
		t.Fatalf("backend timeout mismatch: %s", cfg.Backend.Timeout)
	}
	if cfg.Limits.MaxBodyBytes != 1024 {
		t.Fatalf("max body bytes mismatch: %d", cfg.Limits.MaxBodyBytes)
	}
	if cfg.RateLimit.RequestsPerWindow != 12 || cfg.RateLimit.Window != 30*time.Second {
		t.Fatalf("rate limit mismatch: %+v", cfg.RateLimit)
	}
	if len(cfg.Security.AllowedOrigins) != 2 {
		t.Fatalf("allowed origins mismatch: %#v", cfg.Security.AllowedOrigins)
	}
}

func TestValidateRejectsBadBackendURL(t *testing.T) {
	cfg := Defaults()
	cfg.Backend.URL = "file:///tmp/css.sock"
	if err := Validate(cfg); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateRejectsOriginWithPath(t *testing.T) {
	cfg := Defaults()
	cfg.Security.AllowedOrigins = []string{"https://app.example/path"}
	if err := Validate(cfg); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("SOLID_SIDECAR_ADDRESS", ":9555")
	t.Setenv("SOLID_SIDECAR_BACKEND_URL", "http://localhost:3010")
	t.Setenv("SOLID_SIDECAR_RATE_LIMIT_ENABLED", "false")
	t.Setenv("SOLID_SIDECAR_ALLOWED_ORIGINS", "https://app.example")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Server.Address != ":9555" {
		t.Fatalf("address override mismatch: %q", cfg.Server.Address)
	}
	if cfg.Backend.URL != "http://localhost:3010" {
		t.Fatalf("backend override mismatch: %q", cfg.Backend.URL)
	}
	if cfg.RateLimit.Enabled {
		t.Fatal("rate limit env override failed")
	}
	if len(cfg.Security.AllowedOrigins) != 1 || cfg.Security.AllowedOrigins[0] != "https://app.example" {
		t.Fatalf("allowed origins override mismatch: %#v", cfg.Security.AllowedOrigins)
	}
}
