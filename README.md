# S3 Vault Proxy

A secure S3-compatible proxy that provides transparent encryption/decryption using HashiCorp Vault's transit engine.

## Features

- **S3 API Compatibility**: Works with any S3-compatible client
- **Transparent Encryption**: Automatic encryption/decryption using Vault
- **KMS Integration**: Maps AWS KMS ARNs to Vault transit keys
- **Metadata Management**: Stores object metadata separately
- **Health Monitoring**: Built-in health checks and metrics
- **Connection Pooling**: Optimized performance with persistent connections

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   S3 Client     │───▶│  S3-Vault-Proxy  │───▶│   MinIO/S3      │
│   (encrypted)   │    │                  │    │   (encrypted)   │
└─────────────────┘    └─────────┬────────┘    └─────────────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │ HashiCorp Vault  │
                        │ (Transit Engine) │
                        └──────────────────┘
```

## Quick Start

### Prerequisites

- Go 1.21+
- Running HashiCorp Vault with transit engine enabled
- MinIO or S3-compatible storage backend

### Installation

```bash
# Clone and build
git clone <repository>
cd s3-vault-proxy
go build -o s3-vault-proxy ./cmd/server
```

### Configuration

Set the following environment variables:

```bash
# Required
export S3_ENDPOINT="http://localhost:9000"        # MinIO/S3 backend
export VAULT_ADDR="http://localhost:8200"         # Vault server
export VAULT_TOKEN="your-vault-token"             # Vault auth token

# Optional
export PORT="9000"                                 # Server port (default: 9000)
export VAULT_TOKEN_PATH="/vault/secrets/token"    # Token file path

# Logging (optional)
export LOG_LEVEL="info"                           # debug, info, warn, error
export LOG_FORMAT="json"                          # json, console  
export LOG_TIME_FORMAT="15:04:05"                # Console time format
```

### Usage

```bash
# Start the proxy
./s3-vault-proxy

# Use any S3 client with KMS encryption
aws s3 cp file.txt s3://bucket/key \
  --endpoint-url http://localhost:9000 \
  --sse aws:kms \
  --sse-kms-key-id arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
```

## API Endpoints

### S3 API
- `GET /` - List buckets
- `PUT /:bucket` - Create bucket
- `GET /:bucket` - List objects
- `PUT /:bucket/:key` - Upload object (with encryption)
- `GET /:bucket/:key` - Download object (with decryption)
- `HEAD /:bucket/:key` - Get object metadata
- `DELETE /:bucket/:key` - Delete object

### Health Checks
- `GET /health` - Basic health status
- `GET /ready` - Readiness probe (checks Vault connectivity)
- `GET /version` - Build and version information

## Development

### Project Structure

```
cmd/server/          # Application entry point
internal/config/     # Configuration management  
internal/handlers/   # HTTP request handlers
internal/vault/      # Vault client operations
internal/s3/         # S3 backend communication
internal/metadata/   # Object metadata management
internal/server/     # HTTP server setup
pkg/types/          # Shared types and structures
tests/mocks/        # Mock implementations for testing
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./pkg/types -v
go test ./internal/config -v

# Run with coverage
go test -cover ./...
```

### Building

```bash
# Development build
go build ./cmd/server

# Production build with version info
go build -ldflags "-X main.version=v1.0.0 -X main.commit=$(git rev-parse HEAD)" ./cmd/server
```

## Monitoring

The proxy exposes several endpoints for monitoring:

- `/health` - Returns 200 if service is healthy
- `/ready` - Returns 200 if Vault is accessible, 503 otherwise
- `/version` - Returns build information in JSON format

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]