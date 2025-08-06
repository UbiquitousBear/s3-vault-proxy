package main

import (
	"log"

	"s3-vault-proxy/internal/config"
	"s3-vault-proxy/internal/server"
)

// Build-time variables (generally set by goreleaser)
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Override build-time variables if they were set
	if version != "dev" {
		cfg.Version = version
	}
	if commit != "none" {
		cfg.Commit = commit
	}
	if date != "unknown" {
		cfg.Date = date
	}
	if builtBy != "unknown" {
		cfg.BuiltBy = builtBy
	}

	// Create and start server
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}