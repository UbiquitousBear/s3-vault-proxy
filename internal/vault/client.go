package vault

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"s3-vault-proxy/internal/logging"

	"github.com/hashicorp/vault/api"
)

// Client wraps Vault operations for encryption/decryption
type Client struct {
	client        *api.Client
	tokenPath     string
	usingTokenFile bool
}

// Interface defines operations for Vault client
type Interface interface {
	Encrypt(data []byte, transitKey string) (string, error)
	Decrypt(ciphertext string, transitKey string) ([]byte, error)
	ARNToVaultKey(arn string) (string, error)
	Address() string
	HealthCheck() error
}

// NewClient creates a new Vault client with automatic token management
func NewClient(vaultAddr, vaultToken, tokenPath string) (*Client, error) {
	config := api.DefaultConfig()
	if vaultAddr != "" {
		config.Address = vaultAddr
	}

	vaultClient, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client := &Client{
		client:    vaultClient,
		tokenPath: tokenPath,
	}

	if err := client.setToken(vaultToken, tokenPath); err != nil {
		return nil, fmt.Errorf("failed to set vault token: %w", err)
	}

	// Start token watcher only if we're actually using a token file
	if client.usingTokenFile {
		go client.watchTokenFile()
	}

	return client, nil
}

// setToken sets the Vault token from various sources and tracks which source was used
func (c *Client) setToken(vaultToken, tokenPath string) error {
	// Try token file first
	if tokenBytes, err := os.ReadFile(tokenPath); err == nil {
		token := strings.TrimSpace(string(tokenBytes))
		if token != "" {
			c.client.SetToken(token)
			c.usingTokenFile = true
			logging.Info().Str("token_path", tokenPath).Msg("Using Vault token from file")
			return nil
		}
	}

	// Fall back to environment variable or direct token
	if vaultToken != "" {
		c.client.SetToken(vaultToken)
		c.usingTokenFile = false
		logging.Info().Msg("Using Vault token from environment variable")
		return nil
	}

	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		c.client.SetToken(token)
		c.usingTokenFile = false
		logging.Info().Msg("Using Vault token from VAULT_TOKEN environment variable")
		return nil
	}

	return fmt.Errorf("no vault token found in file %s, provided token, or VAULT_TOKEN environment variable", tokenPath)
}

// watchTokenFile monitors the token file for changes and updates the client
func (c *Client) watchTokenFile() {
	if c.tokenPath == "" {
		return
	}

	logging.Info().Str("token_path", c.tokenPath).Msg("Watching token file")

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	var lastToken string

	for range ticker.C {
		if tokenBytes, err := os.ReadFile(c.tokenPath); err == nil {
			newToken := strings.TrimSpace(string(tokenBytes))
			if newToken != "" && newToken != lastToken {
				c.client.SetToken(newToken)
				logging.Info().Msg("Updated Vault token from file")
				lastToken = newToken
			}
		}
	}
}

// Encrypt encrypts data using Vault's transit engine
func (c *Client) Encrypt(data []byte, transitKey string) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("vault client not configured")
	}

	plaintext := base64.StdEncoding.EncodeToString(data)

	resp, err := c.client.Logical().Write(fmt.Sprintf("transit/encrypt/%s", transitKey), map[string]interface{}{
		"plaintext": plaintext,
	})
	if err != nil {
		return "", fmt.Errorf("vault encryption failed for key %s: %w", transitKey, err)
	}

	if resp == nil || resp.Data == nil {
		return "", fmt.Errorf("empty response from vault")
	}

	ciphertext, ok := resp.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("invalid ciphertext response from vault")
	}

	return ciphertext, nil
}

// Decrypt decrypts data using Vault's transit engine
func (c *Client) Decrypt(ciphertext string, transitKey string) ([]byte, error) {
	if c.client == nil {
		return nil, fmt.Errorf("vault client not configured")
	}

	resp, err := c.client.Logical().Write(fmt.Sprintf("transit/decrypt/%s", transitKey), map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("vault decryption failed for key %s: %w", transitKey, err)
	}

	if resp == nil || resp.Data == nil {
		return nil, fmt.Errorf("empty response from vault")
	}

	plaintext, ok := resp.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid plaintext response from vault")
	}

	data, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode decrypted data: %w", err)
	}

	return data, nil
}

// ARNToVaultKey converts KMS ARN to Vault transit key format
func (c *Client) ARNToVaultKey(arn string) (string, error) {
	if arn == "" {
		return "", fmt.Errorf("KMS key ARN is required")
	}

	// Validate ARN format: arn:aws:kms:region:account:key/key-id
	if !strings.HasPrefix(arn, "arn:aws:kms:") {
		return "", fmt.Errorf("invalid KMS ARN format: %s", arn)
	}

	parts := strings.Split(arn, ":")
	if len(parts) != 6 {
		return "", fmt.Errorf("invalid KMS ARN format, expected 6 parts: %s", arn)
	}

	region := parts[3]
	account := parts[4]
	keyPart := parts[5] // This should be "key/uuid"

	keyParts := strings.Split(keyPart, "/")
	if len(keyParts) != 2 || keyParts[0] != "key" {
		return "", fmt.Errorf("invalid KMS ARN key format, expected 'key/uuid': %s", arn)
	}

	keyUUID := keyParts[1]

	// Validate we have all required parts
	if region == "" || account == "" || keyUUID == "" {
		return "", fmt.Errorf("missing required ARN components (region/account/key): %s", arn)
	}

	// Format as region_account_keyuuid
	vaultKey := fmt.Sprintf("%s_%s_%s", region, account, keyUUID)

	return vaultKey, nil
}

// Address returns the Vault server address
func (c *Client) Address() string {
	if c.client == nil {
		return ""
	}
	return c.client.Address()
}

// HealthCheck performs a health check against Vault
func (c *Client) HealthCheck() error {
	if c.client == nil {
		return fmt.Errorf("vault client not configured")
	}

	_, err := c.client.Sys().Health()
	return err
}