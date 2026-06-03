package config

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAddress         = ":8443"
	defaultBackendURL      = "http://127.0.0.1:3000"
	defaultBackendHealth   = "/"
	defaultMaxBodyBytes    = int64(32 << 20) // 32 MiB
	defaultProxyTimeout    = 30 * time.Second
	defaultServerTimeout   = 15 * time.Second
	defaultReadHeaderLimit = 5 * time.Second
	defaultShutdownTimeout = 10 * time.Second
)

// Config is the complete Phase 1 sidecar configuration.
// It intentionally covers only the service shell: listener, backend CSS target,
// proxy limits, and timeouts. Auth, policy kernels, and Rust integrations belong
// to later phases and should not be smuggled into this type early.
type Config struct {
	Server  ServerConfig
	Backend BackendConfig
	Limits  LimitsConfig
	Log     LogConfig
}

type ServerConfig struct {
	Address           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

type BackendConfig struct {
	URL        string
	HealthPath string
	Timeout    time.Duration
}

type LimitsConfig struct {
	MaxBodyBytes int64
}

type LogConfig struct {
	Level string
}

// Defaults returns a safe local-development configuration.
func Defaults() Config {
	return Config{
		Server: ServerConfig{
			Address:           defaultAddress,
			ReadHeaderTimeout: defaultReadHeaderLimit,
			ReadTimeout:       defaultServerTimeout,
			WriteTimeout:      defaultServerTimeout,
			IdleTimeout:       60 * time.Second,
			ShutdownTimeout:   defaultShutdownTimeout,
		},
		Backend: BackendConfig{
			URL:        defaultBackendURL,
			HealthPath: defaultBackendHealth,
			Timeout:    defaultProxyTimeout,
		},
		Limits: LimitsConfig{
			MaxBodyBytes: defaultMaxBodyBytes,
		},
		Log: LogConfig{Level: "info"},
	}
}

// Load reads a small YAML-like configuration file, applies environment overrides,
// and validates the final result. The parser deliberately supports only the
// simple nested key/value shape used by configs/sidecar.example.yaml.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path != "" {
		if err := loadFile(path, &cfg); err != nil {
			return Config{}, err
		}
	}
	applyEnv(&cfg)
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func loadFile(path string, cfg *Config) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config %q: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	section := ""
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := stripComment(scanner.Text())
		if strings.TrimSpace(raw) == "" {
			continue
		}

		trimmed := strings.TrimSpace(raw)
		if !strings.Contains(trimmed, ":") {
			return fmt.Errorf("config %s:%d: expected key/value pair", path, lineNo)
		}

		parts := strings.SplitN(trimmed, ":", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return fmt.Errorf("config %s:%d: empty key", path, lineNo)
		}
		if value == "" && !strings.Contains(parts[1], "\"") && !strings.Contains(parts[1], "'") {
			section = key
			continue
		}
		value = unquote(value)
		if err := setValue(cfg, section, key, value); err != nil {
			return fmt.Errorf("config %s:%d: %w", path, lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read config %q: %w", path, err)
	}
	return nil
}

func stripComment(s string) string {
	inSingle := false
	inDouble := false
	for i, r := range s {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return s[:i]
			}
		}
	}
	return s
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func setValue(cfg *Config, section, key, value string) error {
	switch section + "." + key {
	case "server.address":
		cfg.Server.Address = value
	case "server.read_header_timeout":
		return parseDuration(value, &cfg.Server.ReadHeaderTimeout)
	case "server.read_timeout":
		return parseDuration(value, &cfg.Server.ReadTimeout)
	case "server.write_timeout":
		return parseDuration(value, &cfg.Server.WriteTimeout)
	case "server.idle_timeout":
		return parseDuration(value, &cfg.Server.IdleTimeout)
	case "server.shutdown_timeout":
		return parseDuration(value, &cfg.Server.ShutdownTimeout)
	case "backend.url":
		cfg.Backend.URL = value
	case "backend.health_path":
		cfg.Backend.HealthPath = value
	case "backend.timeout":
		return parseDuration(value, &cfg.Backend.Timeout)
	case "limits.max_body_bytes":
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("limits.max_body_bytes must be an integer: %w", err)
		}
		cfg.Limits.MaxBodyBytes = parsed
	case "log.level":
		cfg.Log.Level = strings.ToLower(value)
	default:
		return fmt.Errorf("unknown setting %q", section+"."+key)
	}
	return nil
}

func parseDuration(value string, dest *time.Duration) error {
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("duration %q is invalid: %w", value, err)
	}
	*dest = parsed
	return nil
}

func applyEnv(cfg *Config) {
	if value := os.Getenv("SOLID_SIDECAR_ADDRESS"); value != "" {
		cfg.Server.Address = value
	}
	if value := os.Getenv("SOLID_SIDECAR_BACKEND_URL"); value != "" {
		cfg.Backend.URL = value
	}
	if value := os.Getenv("SOLID_SIDECAR_BACKEND_HEALTH_PATH"); value != "" {
		cfg.Backend.HealthPath = value
	}
	if value := os.Getenv("SOLID_SIDECAR_MAX_BODY_BYTES"); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			cfg.Limits.MaxBodyBytes = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_LOG_LEVEL"); value != "" {
		cfg.Log.Level = strings.ToLower(value)
	}
}

// Validate verifies that the sidecar can start from cfg without dangerous or
// ambiguous network behavior.
func Validate(cfg Config) error {
	if strings.TrimSpace(cfg.Server.Address) == "" {
		return errors.New("server.address is required")
	}
	if cfg.Server.ReadHeaderTimeout <= 0 {
		return errors.New("server.read_header_timeout must be positive")
	}
	if cfg.Server.ReadTimeout <= 0 {
		return errors.New("server.read_timeout must be positive")
	}
	if cfg.Server.WriteTimeout <= 0 {
		return errors.New("server.write_timeout must be positive")
	}
	if cfg.Server.IdleTimeout <= 0 {
		return errors.New("server.idle_timeout must be positive")
	}
	if cfg.Server.ShutdownTimeout <= 0 {
		return errors.New("server.shutdown_timeout must be positive")
	}
	backend, err := url.Parse(cfg.Backend.URL)
	if err != nil {
		return fmt.Errorf("backend.url is invalid: %w", err)
	}
	if backend.Scheme != "http" && backend.Scheme != "https" {
		return errors.New("backend.url must use http or https")
	}
	if backend.Host == "" {
		return errors.New("backend.url must include a host")
	}
	if cfg.Backend.HealthPath == "" || !strings.HasPrefix(cfg.Backend.HealthPath, "/") {
		return errors.New("backend.health_path must start with /")
	}
	if cfg.Backend.Timeout <= 0 {
		return errors.New("backend.timeout must be positive")
	}
	if cfg.Limits.MaxBodyBytes <= 0 {
		return errors.New("limits.max_body_bytes must be positive")
	}
	switch cfg.Log.Level {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return errors.New("log.level must be one of debug, info, warn, error")
	}
}
