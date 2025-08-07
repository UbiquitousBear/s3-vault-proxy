package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	// Server configuration
	Port                string
	ServerHeader        string
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	BodyLimit           int
	ReadBufferSize      int
	WriteBufferSize     int
	DisableStartupMsg   bool
	
	// Vault configuration
	VaultAddr       string
	VaultToken      string
	VaultTokenPath  string
	
	// S3/MinIO configuration
	S3Endpoint      string
	S3CACertPath    string
	
	// Logging configuration
	LogLevel        string
	LogFormat       string
	LogTimeFormat   string
	
	// Application metadata
	Version         string
	Commit          string
	Date            string
	BuiltBy         string
}

// LoadConfig loads configuration from environment variables with sensible defaults
func LoadConfig() (*Config, error) {
	cfg := &Config{
		// Server defaults
		Port:              getEnv("PORT", "9000"),
		ServerHeader:      "S3-Vault-Proxy/1.0",
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		BodyLimit:         100 * 1024 * 1024, // 100MB
		ReadBufferSize:    16384,             // 16KB
		WriteBufferSize:   16384,             // 16KB
		DisableStartupMsg: getBoolEnv("DISABLE_STARTUP_MSG", true),
		
		// Vault configuration
		VaultAddr:      getEnv("VAULT_ADDR", ""),
		VaultToken:     getEnv("VAULT_TOKEN", ""),
		VaultTokenPath: getEnv("VAULT_TOKEN_PATH", "/vault/secrets/token"),
		
		// S3 configuration
		S3Endpoint:   getEnv("S3_ENDPOINT", ""),
		S3CACertPath: getEnv("S3_CA_CERT_PATH", ""),
		
		// Logging configuration
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		LogFormat:     getEnv("LOG_FORMAT", "json"),
		LogTimeFormat: getEnv("LOG_TIME_FORMAT", "15:04:05"),
		
		// Build info (typically set at build time)
		Version: getEnv("VERSION", "dev"),
		Commit:  getEnv("COMMIT", "none"),
		Date:    getEnv("DATE", "unknown"),
		BuiltBy: getEnv("BUILT_BY", "unknown"),
	}
	
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return cfg, nil
}

// Validate ensures all required configuration is present
func (c *Config) Validate() error {
	if c.S3Endpoint == "" {
		return fmt.Errorf("S3_ENDPOINT is required")
	}
	
	if c.VaultAddr == "" && os.Getenv("VAULT_ADDR") == "" {
		return fmt.Errorf("VAULT_ADDR is required")
	}
	
	// Check if we have any way to get a vault token
	hasToken := c.VaultToken != ""
	hasTokenFile := c.VaultTokenPath != ""
	hasTokenEnv := os.Getenv("VAULT_TOKEN") != ""
	
	if !hasToken && !hasTokenFile && !hasTokenEnv {
		return fmt.Errorf("either VAULT_TOKEN or VAULT_TOKEN_PATH must be set")
	}
	
	return nil
}

// getEnv gets an environment variable with a fallback default
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getBoolEnv gets a boolean environment variable with a fallback default
func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// getIntEnv gets an integer environment variable with a fallback default
func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}