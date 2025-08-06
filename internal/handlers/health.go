package handlers

import (
	"s3-vault-proxy/internal/config"
	"s3-vault-proxy/internal/vault"

	"github.com/gofiber/fiber/v2"
)

// HealthHandler handles health check endpoints
type HealthHandler struct {
	config *config.Config
	vault  vault.Interface
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(cfg *config.Config, vaultClient vault.Interface) *HealthHandler {
	return &HealthHandler{
		config: cfg,
		vault:  vaultClient,
	}
}

// Health returns basic health information
func (h *HealthHandler) Health(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	return c.SendString(`{"status":"healthy","vault":"` + h.vault.Address() + `","version":"` + h.config.Version + `"}`)
}

// Ready checks if the service is ready to handle requests
func (h *HealthHandler) Ready(c *fiber.Ctx) error {
	if err := h.vault.HealthCheck(); err != nil {
		return c.Status(503).SendString(`{"status":"not ready","error":"vault unreachable"}`)
	}
	return c.SendString(`{"status":"ready","version":"` + h.config.Version + `"}`)
}

// Version returns version information
func (h *HealthHandler) Version(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"version": h.config.Version,
		"commit":  h.config.Commit,
		"date":    h.config.Date,
		"builtBy": h.config.BuiltBy,
	})
}