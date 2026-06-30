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
	defaultAddress                       = ":8443"
	defaultBackendURL                    = "http://127.0.0.1:3000"
	defaultBackendHealth                 = "/"
	defaultMaxBodyBytes                  = int64(32 << 20) // 32 MiB
	defaultProxyTimeout                  = 30 * time.Second
	defaultServerTimeout                 = 15 * time.Second
	defaultReadHeaderLimit               = 5 * time.Second
	defaultShutdownTimeout               = 10 * time.Second
	defaultMaxHeaderBytes                = 1 << 20 // 1 MiB, matching net/http's default.
	DefaultAuthzEvaluatorLocal           = "local"
	DefaultAuthzEvaluatorExternalCLI     = "external_cli"
	DefaultAuthzExternalTimeout          = 2 * time.Second
	DefaultAuthzExternalMaxOutputBytes   = int64(64 << 10) // 64 KiB
	DefaultAuthzExternalBackoffBaseDelay = 500 * time.Millisecond
	DefaultAuthzExternalBackoffMaxDelay  = 30 * time.Second
	maxAuthzExternalTimeout              = 10 * time.Second
	maxAuthzExternalMaxOutputBytes       = int64(1 << 20) // 1 MiB
	maxAuthzExternalBackoffMaxDelay      = 5 * time.Minute
)

// Config is the complete sidecar configuration for the current Go gateway.
// Auth is limited to Phase 3 preflight checks; CSS remains the Solid authority.
type Config struct {
	Server    ServerConfig
	Backend   BackendConfig
	Limits    LimitsConfig
	RateLimit RateLimitConfig
	Security  SecurityConfig
	Auth      AuthConfig
	Authz     AuthzConfig
	Log       LogConfig
}

type ServerConfig struct {
	Address           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxHeaderBytes    int
}

type BackendConfig struct {
	URL        string
	HealthPath string
	Timeout    time.Duration
}

type LimitsConfig struct {
	MaxBodyBytes int64
}

type RateLimitConfig struct {
	Enabled           bool
	RequestsPerWindow int
	Window            time.Duration
}

type SecurityConfig struct {
	AllowedOrigins []string
}

type AuthConfig struct {
	PreflightEnabled                bool
	RequireDPoPForDPoPAuthorization bool
	ValidateDPoPSignature           bool
	RequireDPoPKeyConfirmation      bool
	MaxClockSkew                    time.Duration
	ReplayWindow                    time.Duration
	PublicBaseURL                   string
	// Identity validation configuration
	IdentityValidationEnabled bool
	AllowedIdentityIssuers    []string
	ExpectedIdentityAudience  string
	VerifyWebIDOwnership      bool
}

type AuthzConfig struct {
	ShadowEnabled            bool
	PublicBaseURL            string
	Evaluator                string
	ExternalCommand          string
	ExternalArgs             []string
	ExternalTimeout          time.Duration
	ExternalMaxOutputBytes   int64
	ExternalBackoffBaseDelay time.Duration
	ExternalBackoffMaxDelay  time.Duration
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
			MaxHeaderBytes:    defaultMaxHeaderBytes,
		},
		Backend: BackendConfig{
			URL:        defaultBackendURL,
			HealthPath: defaultBackendHealth,
			Timeout:    defaultProxyTimeout,
		},
		Limits: LimitsConfig{MaxBodyBytes: defaultMaxBodyBytes},
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerWindow: 600,
			Window:            time.Minute,
		},
		Security: SecurityConfig{},
		Auth: AuthConfig{
			PreflightEnabled:                true,
			RequireDPoPForDPoPAuthorization: true,
			ValidateDPoPSignature:           true,
			RequireDPoPKeyConfirmation:      true,
			VerifyWebIDOwnership:            false, // Disabled by default for compatibility
			MaxClockSkew:                    5 * time.Minute,
			ReplayWindow:                    10 * time.Minute,
		},
		Authz: AuthzConfig{
			ShadowEnabled:            false,
			Evaluator:                DefaultAuthzEvaluatorLocal,
			ExternalTimeout:          DefaultAuthzExternalTimeout,
			ExternalMaxOutputBytes:   DefaultAuthzExternalMaxOutputBytes,
			ExternalBackoffBaseDelay: DefaultAuthzExternalBackoffBaseDelay,
			ExternalBackoffMaxDelay:  DefaultAuthzExternalBackoffMaxDelay,
		},
		Log: LogConfig{Level: "info"},
	}
}

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
	case "server.max_header_bytes":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("server.max_header_bytes must be an integer: %w", err)
		}
		cfg.Server.MaxHeaderBytes = parsed
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
	case "rate_limit.enabled":
		return parseBool(value, &cfg.RateLimit.Enabled, "rate_limit.enabled")
	case "rate_limit.requests_per_window":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("rate_limit.requests_per_window must be an integer: %w", err)
		}
		cfg.RateLimit.RequestsPerWindow = parsed
	case "rate_limit.window":
		return parseDuration(value, &cfg.RateLimit.Window)
	case "security.allowed_origins":
		cfg.Security.AllowedOrigins = splitCSV(value)
	case "auth.preflight_enabled":
		return parseBool(value, &cfg.Auth.PreflightEnabled, "auth.preflight_enabled")
	case "auth.require_dpop_for_dpop_authorization":
		return parseBool(value, &cfg.Auth.RequireDPoPForDPoPAuthorization, "auth.require_dpop_for_dpop_authorization")
	case "auth.validate_dpop_signature":
		return parseBool(value, &cfg.Auth.ValidateDPoPSignature, "auth.validate_dpop_signature")
	case "auth.require_dpop_key_confirmation":
		return parseBool(value, &cfg.Auth.RequireDPoPKeyConfirmation, "auth.require_dpop_key_confirmation")
	case "auth.max_clock_skew":
		return parseDuration(value, &cfg.Auth.MaxClockSkew)
	case "auth.replay_window":
		return parseDuration(value, &cfg.Auth.ReplayWindow)
	case "auth.public_base_url":
		cfg.Auth.PublicBaseURL = value
	case "auth.identity_validation_enabled":
		return parseBool(value, &cfg.Auth.IdentityValidationEnabled, "auth.identity_validation_enabled")
	case "auth.verify_webid_ownership":
		return parseBool(value, &cfg.Auth.VerifyWebIDOwnership, "auth.verify_webid_ownership")
	case "auth.allowed_identity_issuers":
		cfg.Auth.AllowedIdentityIssuers = splitCSV(value)
	case "auth.expected_identity_audience":
		cfg.Auth.ExpectedIdentityAudience = value
	case "authz.shadow_enabled":
		return parseBool(value, &cfg.Authz.ShadowEnabled, "authz.shadow_enabled")
	case "authz.public_base_url":
		cfg.Authz.PublicBaseURL = value
	case "authz.evaluator":
		cfg.Authz.Evaluator = strings.ToLower(strings.TrimSpace(value))
	case "authz.external_command":
		cfg.Authz.ExternalCommand = value
	case "authz.external_args":
		cfg.Authz.ExternalArgs = splitCSV(value)
	case "authz.external_timeout":
		return parseDuration(value, &cfg.Authz.ExternalTimeout)
	case "authz.external_max_output_bytes":
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("authz.external_max_output_bytes must be an integer: %w", err)
		}
		cfg.Authz.ExternalMaxOutputBytes = parsed
	case "authz.external_backoff_base_delay":
		return parseDuration(value, &cfg.Authz.ExternalBackoffBaseDelay)
	case "authz.external_backoff_max_delay":
		return parseDuration(value, &cfg.Authz.ExternalBackoffMaxDelay)
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

func parseBool(value string, dest *bool, name string) error {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("%s must be boolean: %w", name, err)
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
	if value := os.Getenv("SOLID_SIDECAR_RATE_LIMIT_ENABLED"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			cfg.RateLimit.Enabled = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_RATE_LIMIT_REQUESTS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			cfg.RateLimit.RequestsPerWindow = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_RATE_LIMIT_WINDOW"); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			cfg.RateLimit.Window = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_ALLOWED_ORIGINS"); value != "" {
		cfg.Security.AllowedOrigins = splitCSV(value)
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTH_PREFLIGHT_ENABLED"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			cfg.Auth.PreflightEnabled = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTH_VALIDATE_DPOP_SIGNATURE"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			cfg.Auth.ValidateDPoPSignature = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTH_REQUIRE_DPOP_KEY_CONFIRMATION"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			cfg.Auth.RequireDPoPKeyConfirmation = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTH_MAX_CLOCK_SKEW"); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			cfg.Auth.MaxClockSkew = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTH_REPLAY_WINDOW"); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			cfg.Auth.ReplayWindow = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTH_PUBLIC_BASE_URL"); value != "" {
		cfg.Auth.PublicBaseURL = value
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTH_IDENTITY_VALIDATION_ENABLED"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			cfg.Auth.IdentityValidationEnabled = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTH_VERIFY_WEBID_OWNERSHIP"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			cfg.Auth.VerifyWebIDOwnership = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTH_ALLOWED_IDENTITY_ISSUERS"); value != "" {
		cfg.Auth.AllowedIdentityIssuers = splitCSV(value)
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTH_EXPECTED_IDENTITY_AUDIENCE"); value != "" {
		cfg.Auth.ExpectedIdentityAudience = value
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTHZ_SHADOW_ENABLED"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			cfg.Authz.ShadowEnabled = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTHZ_PUBLIC_BASE_URL"); value != "" {
		cfg.Authz.PublicBaseURL = value
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTHZ_EVALUATOR"); value != "" {
		cfg.Authz.Evaluator = strings.ToLower(strings.TrimSpace(value))
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTHZ_EXTERNAL_COMMAND"); value != "" {
		cfg.Authz.ExternalCommand = value
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTHZ_EXTERNAL_ARGS"); value != "" {
		cfg.Authz.ExternalArgs = splitCSV(value)
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTHZ_EXTERNAL_TIMEOUT"); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			cfg.Authz.ExternalTimeout = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTHZ_EXTERNAL_MAX_OUTPUT_BYTES"); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
			cfg.Authz.ExternalMaxOutputBytes = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTHZ_EXTERNAL_BACKOFF_BASE_DELAY"); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			cfg.Authz.ExternalBackoffBaseDelay = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_AUTHZ_EXTERNAL_BACKOFF_MAX_DELAY"); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			cfg.Authz.ExternalBackoffMaxDelay = parsed
		}
	}
	if value := os.Getenv("SOLID_SIDECAR_LOG_LEVEL"); value != "" {
		cfg.Log.Level = strings.ToLower(value)
	}
}

func Validate(cfg Config) error {
	if strings.TrimSpace(cfg.Server.Address) == "" {
		return errors.New("server.address is required")
	}
	if cfg.Server.ReadHeaderTimeout <= 0 || cfg.Server.ReadTimeout <= 0 || cfg.Server.WriteTimeout <= 0 || cfg.Server.IdleTimeout <= 0 || cfg.Server.ShutdownTimeout <= 0 {
		return errors.New("server timeouts must be positive")
	}
	if cfg.Server.MaxHeaderBytes <= 0 {
		return errors.New("server.max_header_bytes must be positive")
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
	if cfg.RateLimit.Enabled {
		if cfg.RateLimit.RequestsPerWindow <= 0 || cfg.RateLimit.Window <= 0 {
			return errors.New("rate limit settings must be positive when enabled")
		}
	}
	for _, origin := range cfg.Security.AllowedOrigins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("security.allowed_origins contains invalid origin %q", origin)
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return fmt.Errorf("security.allowed_origins must not include paths: %q", origin)
		}
	}
	if cfg.Auth.PreflightEnabled {
		if cfg.Auth.MaxClockSkew <= 0 {
			return errors.New("auth.max_clock_skew must be positive when auth preflight is enabled")
		}
		if cfg.Auth.ReplayWindow <= 0 {
			return errors.New("auth.replay_window must be positive when auth preflight is enabled")
		}
		if err := validateOptionalBaseURL("auth.public_base_url", cfg.Auth.PublicBaseURL); err != nil {
			return err
		}
	}
	if err := validateAuthzConfig(cfg.Authz); err != nil {
		return err
	}
	switch cfg.Log.Level {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return errors.New("log.level must be one of debug, info, warn, error")
	}
}

func validateAuthzConfig(cfg AuthzConfig) error {
	if cfg.Evaluator == "" {
		return errors.New("authz.evaluator is required")
	}
	switch cfg.Evaluator {
	case DefaultAuthzEvaluatorLocal, DefaultAuthzEvaluatorExternalCLI:
	default:
		return errors.New("authz.evaluator must be one of local, external_cli")
	}
	if cfg.ShadowEnabled {
		if err := validateOptionalBaseURL("authz.public_base_url", cfg.PublicBaseURL); err != nil {
			return err
		}
		if cfg.Evaluator == DefaultAuthzEvaluatorExternalCLI {
			if strings.TrimSpace(cfg.ExternalCommand) == "" {
				return errors.New("authz.external_command is required when authz.evaluator is external_cli")
			}
			if containsControlCharacter(cfg.ExternalCommand) {
				return errors.New("authz.external_command must not contain control characters")
			}
		}
	}
	for _, arg := range cfg.ExternalArgs {
		if containsControlCharacter(arg) {
			return errors.New("authz.external_args must not contain control characters")
		}
	}
	if cfg.ExternalTimeout <= 0 || cfg.ExternalTimeout > maxAuthzExternalTimeout {
		return fmt.Errorf("authz.external_timeout must be positive and <= %s", maxAuthzExternalTimeout)
	}
	if cfg.ExternalMaxOutputBytes <= 0 || cfg.ExternalMaxOutputBytes > maxAuthzExternalMaxOutputBytes {
		return fmt.Errorf("authz.external_max_output_bytes must be positive and <= %d", maxAuthzExternalMaxOutputBytes)
	}
	if cfg.ExternalBackoffBaseDelay <= 0 || cfg.ExternalBackoffMaxDelay <= 0 {
		return errors.New("authz external backoff delays must be positive")
	}
	if cfg.ExternalBackoffBaseDelay > cfg.ExternalBackoffMaxDelay {
		return errors.New("authz.external_backoff_base_delay must be <= authz.external_backoff_max_delay")
	}
	if cfg.ExternalBackoffMaxDelay > maxAuthzExternalBackoffMaxDelay {
		return fmt.Errorf("authz.external_backoff_max_delay must be <= %s", maxAuthzExternalBackoffMaxDelay)
	}
	return nil
}

func validateOptionalBaseURL(name, value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s is invalid: %q", name, value)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must not include query or fragment", name)
	}
	return nil
}

func containsControlCharacter(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
