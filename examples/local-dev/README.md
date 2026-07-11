# Local Development Environment

This directory contains configuration files for setting up a local development environment for testing the solid-sidecar.

## Quick Start

### Using Docker Compose

1. Clone this repository
2. Navigate to this directory:
   ```bash
   cd examples/local-dev
   ```
3. Start the development environment:
   ```bash
   docker-compose up -d
   ```

This will start:
- Community Solid Server (CSS) on port 3000
- solid-sidecar on port 8080 (in shadow mode, comparing with CSS)
- Redis for caching on port 6379 (optional)

### Verify the Setup

Check that services are running:
```bash
# Check CSS
curl http://localhost:3000/.well-known/solid

# Check sidecar health
curl http://localhost:8080/health

# Check sidecar is proxying to CSS
curl http://localhost:8080/.well-known/solid
```

## Configuration

### Environment Variables

The sidecar can be configured through environment variables. Common configurations:

#### Shadow Mode (for development)
```bash
SIDECAR_MODE=shadow
CSS_COMPARISON_ENABLED=true
CSS_BASE_URL=http://localhost:3000
SIDECAR_PORT=8080
SIDECAR_LOG_LEVEL=debug
```

#### Enforcement Mode (for production testing)
```bash
SIDECAR_MODE=enforce
SIDECAR_LOG_LEVEL=info
# Require CSS comparison thresholds to be met before enabling
SIDECAR_AUTHZ_REQUIRE_COMPARISON_THRESHOLD=true
SIDECAR_AUTHZ_COMPARISON_THRESHOLD_PERCENTAGE=100
SIDECAR_AUTHZ_COMPARISON_THRESHOLD_COUNT=100
```

### Sample Pod Setup

To create a sample pod for testing:

1. Register a new account with CSS at http://localhost:3000
2. Note your WebID (typically something like `http://localhost:3000/profile/card#me`)
3. Use the HTTP examples in `../clients/http/` to interact with your pod through the sidecar

## Testing with the Sidecar

### Basic Resource Operations

```bash
# Create a resource (through sidecar)
curl -X PUT http://localhost:8080/my-resource.ttl \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Content-Type: text/turtle" \
  --data-binary @my-resource.ttl

# Read the resource
curl -X GET http://localhost:8080/my-resource.ttl \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Accept: text/turtle"

# Update the resource with conditional write
ETAG=$(curl -I http://localhost:8080/my-resource.ttl \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -s | grep -oP '(?<=ETag: ).*' | tr -d '\r')

curl -X PUT http://localhost:8080/my-resource.ttl \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "If-Match: $ETAG" \
  -H "Content-Type: text/turtle" \
  --data-binary @updated-resource.ttl
```

### Access Control

```bash
# Get the ACL for a resource
curl -X GET http://localhost:8080/my-resource.ttl.acl \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Accept: text/turtle"

# Update the ACL
curl -X PUT http://localhost:8080/my-resource.ttl.acl \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF" \
  -H "Content-Type: text/turtle" \
  --data-binary @new-acl.ttl
```

## CSS Configuration

The `docker-compose.yml` file expects a `css-config.json` file for CSS configuration. A basic configuration:

```json
{
  "serverUri": "http://localhost:3000",
  "multiUser": true,
  "enableCors": true,
  "corsProxy": {
    "enabled": true,
    "allowCredentials": true
  }
}
```

## Troubleshooting

### Logs

View logs for debugging:
```bash
# View sidecar logs
docker-compose logs sidecar

# View CSS logs
docker-compose logs css

# Follow logs in real-time
docker-compose logs -f
```

### Common Issues

1. **Connection refused**: Make sure all services are running (`docker-compose ps`)
2. **Authentication errors**: Verify your access token and DPoP proof are valid
3. **CORS issues**: Ensure your client includes the correct Origin header
4. **CSS comparison mismatches**: Check the sidecar logs for details on why decisions differ

### Resetting the Environment

To start fresh:
```bash
docker-compose down -v
docker-compose up -d
```

This will remove all data volumes and start with a clean state.
