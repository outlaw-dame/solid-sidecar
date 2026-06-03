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
backend:
  url: "http://css:3000"
  health_path: "/.well-known/solid"
  timeout: "7s"
limits:
  max_body_bytes: 1024
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
	if cfg.Backend.HealthPath != "/.well-known/solid" {
		t.Fatalf("health path mismatch: %q", cfg.Backend.HealthPath)
	}
	if cfg.Backend.Timeout != 7*time.Second {
		t.Fatalf("backend timeout mismatch: %s", cfg.Backend.Timeout)
	}
	if cfg.Limits.MaxBodyBytes != 1024 {
		t.Fatalf("max body bytes mismatch: %d", cfg.Limits.MaxBodyBytes)
	}
}

func TestValidateRejectsBadBackendURL(t *testing.T) {
	cfg := Defaults()
	cfg.Backend.URL = "file:///tmp/css.sock"
	if err := Validate(cfg); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("SOLID_SIDECAR_ADDRESS", ":9555")
	t.Setenv("SOLID_SIDECAR_BACKEND_URL", "http://localhost:3010")
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
}
