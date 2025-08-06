package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	// Clean up environment before each test
	envVars := []string{
		"PORT", "S3_ENDPOINT", "VAULT_ADDR", "VAULT_TOKEN", "VAULT_TOKEN_PATH",
		"DISABLE_STARTUP_MSG", "VERSION", "COMMIT", "DATE", "BUILT_BY",
	}

	for _, env := range envVars {
		os.Unsetenv(env)
	}

	t.Run("Default configuration", func(t *testing.T) {
		// Set required environment variables
		os.Setenv("S3_ENDPOINT", "http://localhost:9000")
		os.Setenv("VAULT_ADDR", "http://localhost:8200")
		os.Setenv("VAULT_TOKEN", "test-token")
		defer func() {
			os.Unsetenv("S3_ENDPOINT")
			os.Unsetenv("VAULT_ADDR")
			os.Unsetenv("VAULT_TOKEN")
		}()

		cfg, err := LoadConfig()
		require.NoError(t, err)

		// Test defaults
		assert.Equal(t, "9000", cfg.Port)
		assert.Equal(t, "S3-Vault-Proxy/1.0", cfg.ServerHeader)
		assert.Equal(t, 30*time.Second, cfg.ReadTimeout)
		assert.Equal(t, 30*time.Second, cfg.WriteTimeout)
		assert.Equal(t, 60*time.Second, cfg.IdleTimeout)
		assert.Equal(t, 100*1024*1024, cfg.BodyLimit)
		assert.Equal(t, 16384, cfg.ReadBufferSize)
		assert.Equal(t, 16384, cfg.WriteBufferSize)
		assert.Equal(t, true, cfg.DisableStartupMsg)

		// Test environment values
		assert.Equal(t, "http://localhost:9000", cfg.S3Endpoint)
		assert.Equal(t, "http://localhost:8200", cfg.VaultAddr)
		assert.Equal(t, "test-token", cfg.VaultToken)
		assert.Equal(t, "/vault/secrets/token", cfg.VaultTokenPath)

		// Test build defaults
		assert.Equal(t, "dev", cfg.Version)
		assert.Equal(t, "none", cfg.Commit)
		assert.Equal(t, "unknown", cfg.Date)
		assert.Equal(t, "unknown", cfg.BuiltBy)
	})

	t.Run("Custom configuration", func(t *testing.T) {
		os.Setenv("PORT", "8080")
		os.Setenv("S3_ENDPOINT", "https://s3.amazonaws.com")
		os.Setenv("VAULT_ADDR", "https://vault.example.com")
		os.Setenv("VAULT_TOKEN", "custom-token")
		os.Setenv("VAULT_TOKEN_PATH", "/custom/path")
		os.Setenv("DISABLE_STARTUP_MSG", "false")
		os.Setenv("VERSION", "1.0.0")
		os.Setenv("COMMIT", "abc123")
		os.Setenv("DATE", "2023-01-01")
		os.Setenv("BUILT_BY", "ci")

		defer func() {
			for _, env := range envVars {
				os.Unsetenv(env)
			}
		}()

		cfg, err := LoadConfig()
		require.NoError(t, err)

		assert.Equal(t, "8080", cfg.Port)
		assert.Equal(t, "https://s3.amazonaws.com", cfg.S3Endpoint)
		assert.Equal(t, "https://vault.example.com", cfg.VaultAddr)
		assert.Equal(t, "custom-token", cfg.VaultToken)
		assert.Equal(t, "/custom/path", cfg.VaultTokenPath)
		assert.Equal(t, false, cfg.DisableStartupMsg)
		assert.Equal(t, "1.0.0", cfg.Version)
		assert.Equal(t, "abc123", cfg.Commit)
		assert.Equal(t, "2023-01-01", cfg.Date)
		assert.Equal(t, "ci", cfg.BuiltBy)
	})
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		setupEnv    func()
		expectError string
	}{
		{
			name: "Valid configuration",
			setupEnv: func() {
				os.Setenv("S3_ENDPOINT", "http://localhost:9000")
				os.Setenv("VAULT_ADDR", "http://localhost:8200")
				os.Setenv("VAULT_TOKEN", "test-token")
			},
			expectError: "",
		},
		{
			name: "Missing S3_ENDPOINT",
			setupEnv: func() {
				os.Setenv("VAULT_ADDR", "http://localhost:8200")
				os.Setenv("VAULT_TOKEN", "test-token")
			},
			expectError: "S3_ENDPOINT is required",
		},
		{
			name: "Missing VAULT_ADDR",
			setupEnv: func() {
				os.Setenv("S3_ENDPOINT", "http://localhost:9000")
				os.Setenv("VAULT_TOKEN", "test-token")
			},
			expectError: "VAULT_ADDR is required",
		},
		{
			name: "Valid with VAULT_TOKEN_PATH only",
			setupEnv: func() {
				os.Setenv("S3_ENDPOINT", "http://localhost:9000")
				os.Setenv("VAULT_ADDR", "http://localhost:8200")
				os.Setenv("VAULT_TOKEN_PATH", "/vault/secrets/token")
			},
			expectError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean environment
			envVars := []string{
				"S3_ENDPOINT", "VAULT_ADDR", "VAULT_TOKEN", "VAULT_TOKEN_PATH",
			}
			for _, env := range envVars {
				os.Unsetenv(env)
			}

			// Setup test environment
			tt.setupEnv()

			// Load and validate config
			cfg, err := LoadConfig()

			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
				assert.Nil(t, cfg)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cfg)
			}

			// Clean up after test
			for _, env := range envVars {
				os.Unsetenv(env)
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	t.Run("Environment variable exists", func(t *testing.T) {
		os.Setenv("TEST_VAR", "test-value")
		defer os.Unsetenv("TEST_VAR")

		result := getEnv("TEST_VAR", "default")
		assert.Equal(t, "test-value", result)
	})

	t.Run("Environment variable does not exist", func(t *testing.T) {
		os.Unsetenv("TEST_VAR")

		result := getEnv("TEST_VAR", "default")
		assert.Equal(t, "default", result)
	})

	t.Run("Environment variable is empty", func(t *testing.T) {
		os.Setenv("TEST_VAR", "")
		defer os.Unsetenv("TEST_VAR")

		result := getEnv("TEST_VAR", "default")
		assert.Equal(t, "default", result)
	})
}

func TestGetBoolEnv(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		defaultVal  bool
		expected    bool
		shouldSet   bool
	}{
		{"true string", "true", false, true, true},
		{"false string", "false", true, false, true},
		{"1 string", "1", false, true, true},
		{"0 string", "0", true, false, true},
		{"invalid string", "invalid", false, false, true},
		{"empty string", "", true, true, true},
		{"not set", "", false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv("TEST_BOOL")

			if tt.shouldSet {
				os.Setenv("TEST_BOOL", tt.envValue)
				defer os.Unsetenv("TEST_BOOL")
			}

			result := getBoolEnv("TEST_BOOL", tt.defaultVal)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetIntEnv(t *testing.T) {
	tests := []struct {
		name       string
		envValue   string
		defaultVal int
		expected   int
		shouldSet  bool
	}{
		{"valid integer", "123", 456, 123, true},
		{"zero", "0", 456, 0, true},
		{"negative", "-123", 456, -123, true},
		{"invalid string", "invalid", 456, 456, true},
		{"empty string", "", 456, 456, true},
		{"not set", "", 456, 456, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv("TEST_INT")

			if tt.shouldSet {
				os.Setenv("TEST_INT", tt.envValue)
				defer os.Unsetenv("TEST_INT")
			}

			result := getIntEnv("TEST_INT", tt.defaultVal)
			assert.Equal(t, tt.expected, result)
		})
	}
}