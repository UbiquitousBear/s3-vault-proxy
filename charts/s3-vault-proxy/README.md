# S3 Vault Proxy Helm Chart

This Helm chart deploys the S3 Vault Proxy - a secure S3-compatible proxy that provides transparent encryption/decryption using HashiCorp Vault's transit engine.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- HashiCorp Vault with transit engine enabled
- S3-compatible storage backend (MinIO, AWS S3, etc.)

## Installation

### Quick Start

```bash
# Add the repository (if published)
helm repo add s3-vault-proxy https://charts.example.com/s3-vault-proxy
helm repo update

# Install with minimal configuration
helm install my-s3-vault-proxy s3-vault-proxy/s3-vault-proxy \
  --set config.vault.addr="http://vault:8200" \
  --set config.s3.endpoint="http://minio:9000" \
  --set secrets.vaultToken.enabled=true \
  --set secrets.vaultToken.value="your-vault-token"
```

### From Source

```bash
# Clone the repository
git clone https://github.com/UbiquitousBear/s3-vault-proxy
cd s3-vault-proxy

# Install the chart
helm install my-s3-vault-proxy ./charts/s3-vault-proxy \
  --set config.vault.addr="http://vault:8200" \
  --set config.s3.endpoint="http://minio:9000" \
  --set secrets.vaultToken.enabled=true \
  --set secrets.vaultToken.value="your-vault-token"
```

## Configuration

### Required Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.vault.addr` | Vault server address | `"http://vault:8200"` |
| `config.s3.endpoint` | S3-compatible backend endpoint | `"http://minio:9000"` |

### Authentication

Choose one of these methods to provide the Vault token:

#### Method 1: Create Secret via Values

```yaml
secrets:
  vaultToken:
    enabled: true
    value: "your-vault-token-here"
```

#### Method 2: Use Existing Secret

```yaml
secrets:
  vaultToken:
    enabled: true
    existingSecret: "vault-token-secret"
    key: "token"
```

#### Method 3: Environment Variable

```yaml
config:
  vault:
    token: "your-vault-token-here"
```

#### Method 4: Token File

```yaml
config:
  vault:
    tokenPath: "/vault/secrets/token"

volumeMounts:
  - name: vault-token
    mountPath: /vault/secrets
    readOnly: true

volumes:
  - name: vault-token
    secret:
      secretName: vault-token-file
```

### Performance Tuning

```yaml
config:
  performance:
    bodyLimit: "100MB"          # Maximum request body size
    readBufferSize: 8192        # Read buffer size in bytes
    writeBufferSize: 8192       # Write buffer size in bytes
    readTimeout: "30s"          # Read timeout
    writeTimeout: "30s"         # Write timeout
    idleTimeout: "120s"         # Idle connection timeout

resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 200m
    memory: 256Mi
```

### Logging Configuration

```yaml
config:
  logging:
    level: "info"              # debug, info, warn, error, disabled
    format: "json"             # json, console
    timeFormat: "15:04:05"     # Console time format
```

### High Availability

```yaml
replicaCount: 3

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

podDisruptionBudget:
  enabled: true
  minAvailable: 2

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - s3-vault-proxy
        topologyKey: kubernetes.io/hostname
```

### Ingress Configuration

```yaml
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  hosts:
    - host: s3-proxy.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: s3-proxy-tls
      hosts:
        - s3-proxy.example.com
```

### Monitoring

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
  path: /metrics
  labels:
    prometheus: kube-prometheus
```

## Values Reference

| Parameter | Description | Default |
|-----------|-------------|---------|
| **Image Settings** | | |
| `image.repository` | Container image repository | `ghcr.io/ubiquitousbear/s3-vault-proxy` |
| `image.tag` | Container image tag | `"latest"` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| **Service Configuration** | | |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `9000` |
| **Application Config** | | |
| `config.port` | Application port | `"9000"` |
| `config.vault.addr` | Vault server address | `"http://vault:8200"` |
| `config.s3.endpoint` | S3 backend endpoint | `"http://minio:9000"` |
| `config.logging.level` | Log level | `"info"` |
| **Security** | | |
| `securityContext.runAsNonRoot` | Run as non-root user | `true` |
| `securityContext.runAsUser` | User ID | `65534` |
| `securityContext.readOnlyRootFilesystem` | Read-only root filesystem | `true` |
| **Resources** | | |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `512Mi` |

For a complete list of values, see [values.yaml](values.yaml).

## Usage Examples

### Basic S3 Operations

After installing the chart, configure your S3 client:

```bash
# Get the service endpoint
export S3_ENDPOINT="http://s3-proxy.example.com"

# Upload encrypted file
aws s3 cp myfile.txt s3://mybucket/mykey \
  --endpoint-url $S3_ENDPOINT \
  --sse aws:kms \
  --sse-kms-key-id arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012

# Download and decrypt file
aws s3 cp s3://mybucket/mykey myfile.txt \
  --endpoint-url $S3_ENDPOINT
```

### Health Checks

```bash
# Basic health check
curl $S3_ENDPOINT/health

# Readiness check (validates Vault connectivity)
curl $S3_ENDPOINT/ready

# Version information
curl $S3_ENDPOINT/version
```

## Troubleshooting

### Common Issues

1. **Vault Connection Failed**
   ```bash
   kubectl logs -l app.kubernetes.io/name=s3-vault-proxy
   ```
   Check vault address and token configuration.

2. **S3 Backend Unreachable**
   ```bash
   kubectl exec -it deployment/my-s3-vault-proxy -- wget -O- http://minio:9000/minio/health/live
   ```
   Verify S3 endpoint configuration.

3. **Pod Startup Issues**
   ```bash
   kubectl describe pod -l app.kubernetes.io/name=s3-vault-proxy
   ```
   Check resource limits and security context.

### Debug Mode

Enable debug logging for troubleshooting:

```bash
helm upgrade my-s3-vault-proxy ./charts/s3-vault-proxy \
  --set config.logging.level=debug \
  --set config.logging.format=console
```

### Vault Token Issues

Check token validity:

```bash
# If using secret
kubectl get secret my-s3-vault-proxy-vault-token -o yaml

# If using existing secret
kubectl get secret your-existing-secret -o yaml

# Test token with vault CLI
vault auth -method=token token=your-token-here
vault read auth/token/lookup-self
```

## Upgrading

```bash
# Upgrade to new version
helm upgrade my-s3-vault-proxy ./charts/s3-vault-proxy

# Upgrade with new values
helm upgrade my-s3-vault-proxy ./charts/s3-vault-proxy \
  --set image.tag=v2.0.0 \
  --set replicaCount=5
```

## Uninstallation

```bash
helm uninstall my-s3-vault-proxy
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with `helm lint` and `helm template`
5. Submit a pull request

## License

This chart is licensed under the same license as the S3 Vault Proxy application.