# Solid Runtime Configuration Schema

This document describes the complete configuration schema for the Solid runtime as required by Phase 17.

## Overview

The Solid runtime uses a hierarchical YAML/JSON configuration system with environment variable overrides. All configurations support:

- **Environment variable overrides**: Use `SOLID_` prefix (e.g., `SOLID_LISTEN_ADDR`)
- **File-based configuration**: Load from `config.yaml` or specified path
- **Validation**: All configurations are validated on startup
- **Security**: Sensitive values can be referenced from environment variables or secret stores

## Root Configuration

```yaml
# Server configuration
server:
  listen_addr: ":8080"
  base_url: "https://solid.example.com/"
  environment: "production" # production, staging, development
  log_level: "info" # debug, info, warn, error
  shutdown_timeout: "30s"

# Runtime mode
authz:
  mode: "shadow" # shadow, enforce_dry_run, enforce_canary, enforce, bypass
  shadow_mode: true

# Storage configuration
storage:
  backend: "multi" # single, multi, memory
  primary: "css"
  backends:
    css:
      type: "css"
      url: "http://localhost:3000"
      timeout: "5s"
      max_retries: 3

# Authentication configuration  
authn:
  dpop:
    enabled: true
    replay_cache_size: 10000
    replay_cache_ttl: "1h"
    nonce_ttl: "10m"
  webid:
    enabled: true
    profile_cache_size: 1000
    profile_cache_ttl: "1h"

# Caching configuration
cache:
  policy:
    ttl: "10m"
    stale_while_revalidate: "5m"
    max_size: 10000
  decision:
    enabled: true
    ttl: "5m"
    max_size: 10000

# Compression configuration
compression:
  enabled: true
  gzip:
    enabled: true
    level: 6
    min_size: 1024
  zstd:
    enabled: false
    level: 3

# Rate limiting configuration
rate_limit:
  global:
    requests_per_second: 1000
    burst_size: 2000
  per_ip:
    enabled: true
    requests_per_minute: 60
  authn:
    requests_per_second: 100
    burst_size: 200

# Observability configuration
observability:
  metrics:
    enabled: true
    otel_enabled: false
    otel_endpoint: "http://localhost:4317"
    otel_span_exporter: "otlp" # otlp, jaeger, zipkin, none
    prometheus_enabled: true
    prometheus_addr: ":9090"
  tracing:
    enabled: false
    sample_rate: 0.1
    service_name: "solid-runtime"
  health:
    enabled: true
    addr: ":8081"
  logging:
    format: "json" # json, text
    include_timestamps: true
    include caller: true

# Security configuration
security:
  tls:
    enabled: true
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"
    min_version: "TLS12"
  cors:
    enabled: true
    allowed_origins: ["https://solid.example.com"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_headers: ["Authorization", "Content-Type", "DPoP"]
    max_age: "86400"
  debug:
    enabled: false
    auth_token: "" # Set via environment: SOLID_SECURITY_DEBUG_AUTH_TOKEN
    allowed_ips: ["127.0.0.1", "::1"]
    rate_limit: 10

# Notifications configuration
notifications:
  enabled: true
  event_stream:
    max_buffer_size: 10000
    retention_time: "24h"
    max_subscribers: 1000
  webhook:
    enabled: false
    endpoints: []

# Indexing configuration
indexing:
  enabled: true
  max_indexed_resources: 100000
  max_resource_size: 10485760 # 10MB
  max_metadata_keys: 50
  max_metadata_size: 4096
  reindex_interval: "1h"

# Policy configuration
policy:
  discovery:
    enabled: true
    timeout: "2s"
    max_retries: 3
    max_body_size: 65536 # 64KB
  wac:
    enabled: true
    shadow_mode: true
  acp:
    enabled: false
    shadow_mode: true
  sai:
    enabled: false
    shadow_mode: true

# DID configuration
did:
  solid:
    enabled: false
    resolver:
      cache_size: 1000
      cache_ttl: "1h"
      timeout: "2s"

# Multi-tenant configuration
multi_tenant:
  enabled: false
  tenant_allowlist: []
  storage_per_tenant: false

# Migration configuration
migration:
  css:
    enabled: false
    batch_size: 100
    rate_limit: 10

# Hardening configuration (Phase 16 & 17)
hardening:
  event_stream:
    max_metadata_size: 4096
    max_metadata_keys: 50
    max_metadata_key_length: 256
    max_metadata_value_length: 1024
    max_subscriber_buffer_size: 1000
    max_subscribers: 1000
    max_events_per_second: 1000
    event_burst_limit: 2000
    circuit_breaker:
      failure_threshold: 5
      reset_timeout: "30s"
    subscriber_cleanup:
      inactivity_time: "1h"
      cleanup_interval: "5m"

  resource_index:
    max_resource_size: 10485760
    max_owner_count: 100
    max_contributor_count: 1000
    max_access_info_size: 1024
    max_resources_per_container: 10000
    max_containers_per_tenant: 1000
    rate_limit:
      operations_per_second: 500
      burst_size: 1000
    circuit_breaker:
      failure_threshold: 3
      reset_timeout: "1m"

  leak_detection:
    enabled: true
    check_interval: "1m"
    memory:
      leak_threshold_percent: 10.0
      max_peak_tracking: true
    goroutines:
      leak_threshold_count: 10
      max_peak_tracking: true

# Resource limits
limits:
  max_request_body_size: 10485760 # 10MB
  max_response_body_size: 10485760 # 10MB
  max_header_size: 8192
  max_concurrent_connections: 10000
  max_concurrent_requests: 1000
