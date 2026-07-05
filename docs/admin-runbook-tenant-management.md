# Solid Sidecar: Tenant Management Admin Runbook

## Overview

This runbook provides procedures for administrators to manage tenants in a multi-tenant Solid Sidecar deployment. These procedures cover tenant onboarding, offboarding, monitoring, and troubleshooting.

**Phase 21: Multi-tenant/operator platform**

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Tenant Onboarding](#tenant-onboarding)
3. [Tenant Configuration](#tenant-configuration)
4. [Tenant Monitoring](#tenant-monitoring)
5. [Tenant Maintenance](#tenant-maintenance)
6. [Tenant Offboarding](#tenant-offboarding)
7. [Emergency Procedures](#emergency-procedures)
8. [Security Considerations](#security-considerations)
9. [Troubleshooting](#troubleshooting)
10. [Audit and Compliance](#audit-and-compliance)

---

## 1. Prerequisites

### 1.1 Admin Access Requirements

- **Operator API Access**: Admin API key for the `/admin/api/v1` endpoint
- **File System Access**: Read/write access to tenant configuration directory (default: `./config/tenants/`)
- **Storage Access**: Access to configure storage backends for tenants
- **Monitoring Access**: Access to metrics and logging systems

### 1.2 Required Tools

- `curl` for API interactions
- `jq` for JSON processing (optional but recommended)
- Text editor for configuration files
- Backup storage for tenant data

### 1.3 Environment Setup

```bash
# Set admin API key
EXPORT ADMIN_API_KEY="your-admin-api-key"

# Set base URL for the sidecar
EXPORT SIDECAR_BASE_URL="https://your-sidecar.example.com"

# Set tenant config directory
EXPORT TENANT_CONFIG_DIR="./config/tenants"
```

---

## 2. Tenant Onboarding

### 2.1 Pre-Onboarding Checklist

- [ ] Verify tenant identity and authorization
- [ ] Confirm tenant requirements (storage, quotas, authn/authz modes)
- [ ] Validate tenant ID follows naming conventions
- [ ] Check available storage backends and capacity
- [ ] Verify no conflicts with existing tenant IDs
- [ ] Prepare tenant configuration file
- [ ] Set up monitoring and alerting for the new tenant

### 2.2 Tenant ID Requirements

Tenant IDs must:

- Be 1-256 characters long
- Contain only alphanumeric characters, hyphens (`-`), underscores (`_`), and periods (`.`)
- Not contain spaces or special characters (except those explicitly allowed)
- Be unique across all tenants
- Not be sensitive or personally identifiable information

**Valid Examples:**
- `acme-corp`
- `tenant_123`
- `production.accounting`

**Invalid Examples:**
- `John Doe Inc` (contains spaces)
- `tenant@domain.com` (contains `@`)
- `https://tenant.example.com` (too long, contains `://`)

### 2.3 Create Tenant via API

#### Method A: Using curl (Recommended)

```bash
# Create a new tenant
curl -X POST "${SIDECAR_BASE_URL}/admin/api/v1/tenants" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "new-tenant",
    "storage_backend": "s3-production",
    "allowed_storage_backends": ["s3-production", "s3-backup"],
    "resource_quotas": {
      "max_resources": 10000,
      "max_storage": 107374182400,  # 100 GB
      "max_bandwidth": 104857600,     # 100 MB/s
      "max_requests_per_second": 100
    },
    "acl_config": {
      "default_access": "private",
      "inherit_acl": true,
      "public_read_enabled": false
    },
    "auth_config": {
      "issuer_trust_policy": {
        "allowed_issuers": ["https://issuer.example.com"],
        "blocked_issuers": [],
        "require_issuer_allowlist": true,
        "allow_issuer_discovery": true,
        "issuer_pinning": {},
        "jwks_endpoint_ttl": 3600
      },
      "authz_mode": "shadow",
      "compression_mode": "gzip",
      "dpop_settings": {
        "require_dpop_for_all_requests": false,
        "require_dpop_for_write_requests": true,
        "dpop_replay_window": 600,
        "dpop_max_nonce_age": 600,
        "dpop_nonce_cleanup_interval": 300
      },
      "webid_profile_cache_ttl": 300,
      "max_webid_profile_cache_size": 1000,
      "identity_assurance_level": "medium"
    },
    "metadata": {
      "admin_contact": "admin@tenant.example.com",
      "created_by": "admin-username",
      "purpose": "production"
    },
    "enabled": true
  }'
```

#### Method B: Expected Response

```json
{
  "tenant_id": "new-tenant",
  "message": "Tenant created successfully",
  "created": "2026-07-05T10:00:00Z",
  "storage_backend": "s3-production"
}
```

#### Method C: Using Configuration File

1. Create tenant configuration file:

```bash
# Create tenant configuration
cat > ${TENANT_CONFIG_DIR}/new-tenant.json << 'EOF'
{
  "tenant_id": "new-tenant",
  "storage_backend": "s3-production",
  "allowed_storage_backends": ["s3-production", "s3-backup"],
  "resource_quotas": {
    "max_resources": 10000,
    "max_storage": 107374182400,
    "max_bandwidth": 104857600,
    "max_requests_per_second": 100,
    "current_usage": {
      "resource_count": 0,
      "storage_used": 0,
      "last_request_time": ""
    }
  },
  "acl_config": {
    "default_access": "private",
    "inherit_acl": true,
    "public_read_enabled": false
  },
  "auth_config": {
    "issuer_trust_policy": {
      "allowed_issuers": ["https://issuer.example.com"],
      "blocked_issuers": [],
      "require_issuer_allowlist": true,
      "allow_issuer_discovery": true,
      "issuer_pinning": {},
      "jwks_endpoint_ttl": 3600
    },
    "authz_mode": "shadow",
    "compression_mode": "gzip",
    "dpop_settings": {
      "require_dpop_for_all_requests": false,
      "require_dpop_for_write_requests": true,
      "dpop_replay_window": 600,
      "dpop_max_nonce_age": 600,
      "dpop_nonce_cleanup_interval": 300
    },
    "webid_profile_cache_ttl": 300,
    "max_webid_profile_cache_size": 1000,
    "identity_assurance_level": "medium"
  },
  "metadata": {
    "admin_contact": "admin@tenant.example.com",
    "created_by": "admin-username",
    "purpose": "production"
  },
  "created": "2026-07-05T10:00:00Z",
  "modified": "2026-07-05T10:00:00Z",
  "enabled": true
}
EOF
```

2. The system will automatically load the tenant configuration on next reload.

### 2.4 Verify Tenant Creation

```bash
# List all tenants
curl -X GET "${SIDECAR_BASE_URL}/admin/api/v1/tenants" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json"

# Get specific tenant details
curl -X GET "${SIDECAR_BASE_URL}/admin/api/v1/tenants/new-tenant" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json"
```

### 2.5 Post-Creation Checklist

- [ ] Verify tenant appears in tenant list
- [ ] Confirm tenant storage backend is accessible
- [ ] Test basic tenant operations (read/write)
- [ ] Verify authentication works for tenant
- [ ] Check tenant health status
- [ ] Confirm monitoring is capturing tenant metrics
- [ ] Document tenant creation in change log

---

## 3. Tenant Configuration

### 3.1 Update Tenant Configuration

```bash
# Update tenant configuration
curl -X PUT "${SIDECAR_BASE_URL}/admin/api/v1/tenants/existing-tenant" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "storage_backend": "s3-premium",
    "resource_quotas": {
      "max_resources": 20000,
      "max_storage": 214748364800  # 200 GB
    }
  }'
```

### 3.2 Update Tenant Authentication Configuration

```bash
# Update tenant auth configuration
curl -X PUT "${SIDECAR_BASE_URL}/admin/api/v1/tenants/existing-tenant/auth" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_config": {
      "issuer_trust_policy": {
        "allowed_issuers": ["https://issuer.example.com", "https://trusted-issuer.example.org"],
        "require_issuer_allowlist": true
      },
      "authz_mode": "native",
      "identity_assurance_level": "high"
    }
  }'
```

### 3.3 Configure Per-Tenant Rate Limits

Tenant rate limits can be configured in the `resource_quotas` section:

```json
{
  "resource_quotas": {
    "max_requests_per_second": 100,
    "max_bandwidth": 104857600
  }
}
```

### 3.4 Configure Per-Tenant Storage Quotas

```json
{
  "resource_quotas": {
    "max_resources": 10000,
    "max_storage": 107374182400
  }
}
```

### 3.5 Configure Per-Tenant Issuer Trust

```json
{
  "auth_config": {
    "issuer_trust_policy": {
      "allowed_issuers": [
        "https://primary-issuer.example.com",
        "https://secondary-issuer.example.org"
      ],
      "blocked_issuers": [
        "https://untrusted-issuer.example.com"
      ],
      "require_issuer_allowlist": true,
      "issuer_pinning": {
        "https://pinned-issuer.example.com": {
          "public_key_hash": "a1b2c3...",
          "valid_from": "2026-01-01T00:00:00Z",
          "valid_until": "2027-01-01T00:00:00Z",
          "trust_level": "high"
        }
      }
    }
  }
}
```

---

## 4. Tenant Monitoring

### 4.1 Health Status Monitoring

```bash
# Get tenant health status
curl -X GET "${SIDECAR_BASE_URL}/admin/api/v1/tenants/tenant-id/health" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json"
```

### 4.2 Resource Usage Monitoring

Monitor tenant resource usage via Prometheus metrics:

```promql
# Tenant storage usage
solid_sidecar_tenant_storage_usage_bytes{tenant_id="tenant-123"}

# Tenant resource count
solid_sidecar_tenant_resource_count{tenant_id="tenant-123"}

# Tenant request rate
rate(solid_sidecar_tenant_requests_total{tenant_id="tenant-123"}[5m])

# Tenant error rate
rate(solid_sidecar_tenant_request_errors_total{tenant_id="tenant-123"}[5m])
```

### 4.3 Audit Log Monitoring

```bash
# Get tenant audit logs
curl -X GET "${SIDECAR_BASE_URL}/admin/api/v1/tenants/tenant-id/audit" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "start_time": "2026-07-01T00:00:00Z",
    "end_time": "2026-07-05T23:59:59Z",
    "action": "ACCESS_DENIED"
  }'
```

### 4.4 Set Up Alerts

Create alerts for tenant-specific issues:

```yaml
# Example Prometheus alert rules for tenants
groups:
- name: tenant-alerts
  rules:
  - alert: TenantHighErrorRate
    expr: rate(solid_sidecar_tenant_request_errors_total[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High error rate for tenant {{ $labels.tenant_id }}"
      description: "Tenant {{ $labels.tenant_id }} has error rate {{ $value }}"

  - alert: TenantStorageQuotaExceeded
    expr: solid_sidecar_tenant_storage_usage_bytes / solid_sidecar_tenant_storage_quota_bytes > 0.9
    for: 10m
    labels:
      severity: critical
    annotations:
      summary: "Storage quota exceeded for tenant {{ $labels.tenant_id }}"
      description: "Tenant {{ $labels.tenant_id }} is using {{ $value * 100 }}% of storage quota"

  - alert: TenantUnhealthy
    expr: solid_sidecar_tenant_health_status{tenant_id="tenant-123"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Tenant {{ $labels.tenant_id }} is unhealthy"
      description: "Tenant {{ $labels.tenant_id }} health check has failed"
```

---

## 5. Tenant Maintenance

### 5.1 Tenant Configuration Reload

```bash
# Trigger configuration reload for all tenants
# This is automatic if using file-based configuration
# For manual reload, restart the sidecar or use the reload endpoint

# Check if tenant config loader is running
# (This would be a sidecar-specific endpoint)
```

### 5.2 Backup Tenant Configuration

```bash
# Backup all tenant configurations
BACKUP_DIR="./backups/tenants/$(date +%Y%m%d-%H%M%S)"
mkdir -p ${BACKUP_DIR}

# Copy all tenant config files
cp ${TENANT_CONFIG_DIR}/*.json ${BACKUP_DIR}/

# Verify backup
ls -la ${BACKUP_DIR}
```

### 5.3 Restore Tenant Configuration

```bash
# Restore from backup
BACKUP_DIR="./backups/tenants/20260705-100000"

# Copy config files back
cp ${BACKUP_DIR}/*.json ${TENANT_CONFIG_DIR}/

# Trigger reload (or restart sidecar)
# The sidecar will automatically reload configurations
```

### 5.4 Scale Tenant Resources

```bash
# Update tenant quotas to scale up
curl -X PUT "${SIDECAR_BASE_URL}/admin/api/v1/tenants/growing-tenant" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_quotas": {
      "max_resources": 50000,
      "max_storage": 536870912000  # 500 GB
    }
  }'
```

### 5.5 Rotate Tenant Secrets

If using per-tenant API keys or other secrets:

1. Generate new credentials
2. Update tenant configuration with new credentials
3. Notify tenant administrators
4. Verify new credentials work
5. Revoke old credentials

---

## 6. Tenant Offboarding

### 6.1 Pre-Offboarding Checklist

- [ ] Notify tenant administrators of offboarding schedule
- [ ] Confirm data retention requirements
- [ ] Export tenant data if required (see Data Export)
- [ ] Verify no active sessions for the tenant
- [ ] Check for any pending operations
- [ ] Confirm backup of tenant data exists
- [ ] Schedule offboarding during low-traffic period

### 6.2 Data Export Procedures

#### Method A: Export via API

```bash
# Export tenant audit logs
curl -X GET "${SIDECAR_BASE_URL}/admin/api/v1/tenants/tenant-to-remove/audit/export" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  --output tenant-audit-logs.json

# Export tenant configuration
curl -X GET "${SIDECAR_BASE_URL}/admin/api/v1/tenants/tenant-to-remove" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  --output tenant-config.json
```

#### Method B: Export from Files

```bash
# Copy tenant configuration
cp ${TENANT_CONFIG_DIR}/tenant-to-remove.json ./exports/

# Export audit logs (if stored in files)
EXPORT_DIR="./exports/tenant-to-remove/audit"
mkdir -p ${EXPORT_DIR}
cp ${AUDIT_LOG_DIR}/tenant-to-remove*.json ${EXPORT_DIR}/
```

### 6.3 Disable Tenant Access

```bash
# Disable tenant (stops new requests but preserves data)
curl -X PUT "${SIDECAR_BASE_URL}/admin/api/v1/tenants/tenant-to-remove" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false
  }'
```

### 6.4 Delete Tenant

```bash
# Delete tenant (permanent, destroys all tenant data)
curl -X DELETE "${SIDECAR_BASE_URL}/admin/api/v1/tenants/tenant-to-remove" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json"
```

### 6.5 Post-Offboarding Checklist

- [ ] Confirm tenant is removed from tenant list
- [ ] Verify tenant data is deleted (if applicable)
- [ ] Check that tenant metrics are no longer reported
- [ ] Confirm audit logs are preserved (if required)
- [ ] Update documentation and inventory
- [ ] Notify stakeholders of completion
- [ ] Archive offboarding records

---

## 7. Emergency Procedures

### 7.1 Emergency Tenant Suspension

```bash
# Immediately disable a problematic tenant
curl -X PUT "${SIDECAR_BASE_URL}/admin/api/v1/tenants/problematic-tenant" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false
  }'
```

### 7.2 Emergency Configuration Rollback

```bash
# Restore tenant configuration from backup
BACKUP_DIR="./backups/tenants/latest"
cp ${BACKUP_DIR}/problematic-tenant.json ${TENANT_CONFIG_DIR}/

# Restart sidecar to reload configurations
# Or use reload endpoint if available
```

### 7.3 Emergency Storage Migration

If a tenant's storage backend fails:

1. Create new storage backend for tenant
2. Update tenant configuration to point to new backend
3. Migrate data from old to new backend
4. Verify data integrity
5. Update tenant to use new backend

### 7.4 Emergency Security Incident Response

1. **Containment**: Disable affected tenant(s)
2. **Investigation**: Review audit logs for the affected tenant
3. **Remediation**: Apply security patches or configuration changes
4. **Recovery**: Restore service for unaffected tenants
5. **Notification**: Notify affected parties as required

---

## 8. Security Considerations

### 8.1 Tenant Isolation

- Tenants cannot access each other's resources
- Tenant configurations are isolated
- Tenant authentication credentials are isolated
- Tenant audit logs are isolated

### 8.2 Privacy Protection

- Avoid using personally identifiable information in tenant IDs
- Never expose WebIDs, resource URLs, or other PII in metrics labels
- Use categorized labels instead of raw values
- Regularly review tenant configurations for sensitive data

### 8.3 Access Control

- Operator API requires explicit authentication
- Admin API keys should be rotated regularly
- Access to tenant management should be limited to authorized personnel
- All tenant management actions should be audited

### 8.4 Data Protection

- Tenant configurations should be backed up regularly
- Audit logs should be retained according to policy
- Sensitive tenant data should be encrypted at rest
- Data exports should be secured

---

## 9. Troubleshooting

### 9.1 Common Issues

#### Issue: Tenant creation fails with "Invalid tenant ID"

**Cause**: Tenant ID contains invalid characters or is too long.

**Solution**: Use a valid tenant ID (alphanumeric, hyphens, underscores, periods only, max 256 chars).

#### Issue: Tenant not found after creation

**Cause**: Configuration reload failed or tenant ID was mistyped.

**Solution**: Check sidecar logs for errors, verify tenant ID, restart sidecar if needed.

#### Issue: Tenant storage backend not accessible

**Cause**: Storage backend configuration is incorrect or backend is unavailable.

**Solution**: Verify storage backend configuration, check backend connectivity, test with `curl`.

#### Issue: High cardinality warnings in metrics

**Cause**: Too many unique tenant IDs or other label values.

**Solution**: Increase cardinality limits, use categorized labels, or consolidate tenants.

### 9.2 Debugging Tenant Issues

```bash
# Check sidecar logs for tenant-specific errors
grep "tenant-id" /var/log/solid-sidecar/sidecar.log

# Check tenant health status
curl -s -X GET "${SIDECAR_BASE_URL}/admin/api/v1/tenants/tenant-id/health" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" | jq

# Check tenant configuration
curl -s -X GET "${SIDECAR_BASE_URL}/admin/api/v1/tenants/tenant-id" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" | jq
```

### 9.3 Performance Issues

```bash
# Check tenant request latency
curl -s -X GET "${SIDECAR_BASE_URL}/admin/api/v1/tenants/tenant-id" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" | jq '.metrics'

# Check Prometheus metrics for tenant performance
# Use queries from Section 4.2
```

---

## 10. Audit and Compliance

### 10.1 Audit Requirements

- All tenant management actions must be audited
- Audit logs must include: timestamp, tenant ID, admin user, action, status
- Audit logs must be retained according to policy (default: 90 days)
- Audit logs must be protected from tampering

### 10.2 Compliance Checklist

- [ ] Tenant IDs do not contain PII
- [ ] Metrics do not expose PII
- [ ] Audit logs capture all required information
- [ ] Data retention policies are enforced
- [ ] Access controls are properly configured
- [ ] Tenant isolation is maintained

### 10.3 Audit Log Review

```bash
# Review recent admin actions
curl -s -X GET "${SIDECAR_BASE_URL}/admin/api/v1/tenants/all-tenant/audit" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -d '{
    "action": "ADMIN",
    "start_time": "2026-07-01T00:00:00Z",
    "end_time": "2026-07-05T23:59:59Z"
  }' | jq

# Check for failed operations
curl -s -X GET "${SIDECAR_BASE_URL}/admin/api/v1/tenants/all-tenant/audit" \
  -H "Authorization: Bearer ${ADMIN_API_KEY}" \
  -d '{
    "status": "FAILURE",
    "start_time": "2026-07-01T00:00:00Z"
  }' | jq
```

### 10.4 Compliance Reporting

Generate compliance reports showing:

- Number of tenants
- Tenant creation/deletion dates
- Audit log retention compliance
- Data protection measures in place
- Access control configuration

---

## Appendix A: Configuration Examples

### A.1 Minimal Tenant Configuration

```json
{
  "tenant_id": "minimal-tenant",
  "storage_backend": "default",
  "auth_config": {
    "issuer_trust_policy": {
      "require_issuer_allowlist": false
    },
    "authz_mode": "shadow"
  },
  "enabled": true
}
```

### A.2 Production Tenant Configuration

```json
{
  "tenant_id": "production-tenant",
  "storage_backend": "s3-production",
  "allowed_storage_backends": ["s3-production", "s3-backup"],
  "resource_quotas": {
    "max_resources": 100000,
    "max_storage": 1099511627776,  # 1 TB
    "max_bandwidth": 1073741824,      # 1 GB/s
    "max_requests_per_second": 1000
  },
  "acl_config": {
    "default_access": "private",
    "inherit_acl": true,
    "public_read_enabled": false
  },
  "auth_config": {
    "issuer_trust_policy": {
      "allowed_issuers": [
        "https://company-issuer.example.com",
        "https://trusted-partner.example.org"
      ],
      "blocked_issuers": [],
      "require_issuer_allowlist": true,
      "allow_issuer_discovery": true,
      "issuer_pinning": {
        "https://company-issuer.example.com": {
          "public_key_hash": "a1b2c3d4e5f6...",
          "valid_from": "2026-01-01T00:00:00Z",
          "valid_until": "2027-01-01T00:00:00Z",
          "trust_level": "high"
        }
      },
      "jwks_endpoint_ttl": 3600
    },
    "authz_mode": "native",
    "compression_mode": "gzip",
    "dpop_settings": {
      "require_dpop_for_all_requests": true,
      "require_dpop_for_write_requests": true,
      "dpop_replay_window": 600,
      "dpop_max_nonce_age": 600,
      "dpop_nonce_cleanup_interval": 300
    },
    "webid_profile_cache_ttl": 300,
    "max_webid_profile_cache_size": 1000,
    "identity_assurance_level": "high"
  },
  "metadata": {
    "admin_contact": "admin@company.example.com",
    "created_by": "system-admin",
    "purpose": "production",
    "environment": "production",
    "compliance_requirements": "GDPR,HIPAA"
  },
  "created": "2026-07-05T10:00:00Z",
  "modified": "2026-07-05T10:00:00Z",
  "enabled": true
}
```

---

## Appendix B: API Reference

### B.1 Tenant Lifecycle Endpoints

| Method | Endpoint | Description | Requires Admin |
|--------|----------|-------------|----------------|
| GET | `/admin/api/v1/tenants` | List all tenants | ✅ |
| POST | `/admin/api/v1/tenants` | Create a new tenant | ✅ |
| GET | `/admin/api/v1/tenants/{tenantID}` | Get tenant details | ✅ |
| PUT | `/admin/api/v1/tenants/{tenantID}` | Update tenant | ✅ |
| DELETE | `/admin/api/v1/tenants/{tenantID}` | Delete tenant | ✅ |
| GET | `/admin/api/v1/tenants/{tenantID}/health` | Get tenant health | ✅ |
| GET | `/admin/api/v1/tenants/{tenantID}/auth` | Get tenant auth config | ✅ |
| PUT | `/admin/api/v1/tenants/{tenantID}/auth` | Update tenant auth config | ✅ |
| GET | `/admin/api/v1/tenants/{tenantID}/storage` | Get tenant storage config | ✅ |

### B.2 Response Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request (invalid input) |
| 401 | Unauthorized (missing/invalid API key) |
| 403 | Forbidden (admin action not allowed) |
| 404 | Not Found (tenant not found) |
| 409 | Conflict (tenant already exists) |
| 429 | Too Many Requests (rate limited) |
| 500 | Internal Server Error |

---

## Appendix C: Best Practices

### C.1 Tenant Naming

- Use descriptive, meaningful tenant IDs
- Avoid sensitive or personally identifiable information
- Consider including environment or region in tenant ID
- Maintain consistency in naming conventions

### C.2 Configuration Management

- Use configuration files for complex tenant setups
- Backup configurations before making changes
- Test changes in staging before applying to production
- Document all configuration changes

### C.3 Monitoring and Alerting

- Set up alerts for critical tenant metrics
- Monitor tenant health status regularly
- Track resource usage trends
- Review audit logs periodically

### C.4 Security

- Rotate admin API keys regularly
- Limit access to tenant management functions
- Audit all tenant management actions
- Follow principle of least privilege

---

## Revision History

| Date | Author | Changes |
|------|--------|---------|
| 2026-07-05 | Admin | Initial version for Phase 21 |

---

*This document is part of Phase 21: Multi-tenant/operator platform implementation.*
*Last updated: 2026-07-05*
*Version: 1.0*