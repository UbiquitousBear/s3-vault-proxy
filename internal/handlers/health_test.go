package handlers

import (
	"io"
	"net/http/httptest"
	"testing"

	"s3-vault-proxy/internal/config"
	"s3-vault-proxy/tests/mocks"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupHealthTest() (*fiber.App, *HealthHandler) {
	cfg := &config.Config{
		Version: "1.0.0",
		Commit:  "abc123",
		Date:    "2023-01-01",
		BuiltBy: "test",
	}

	vaultClient := mocks.NewMockVaultClient()
	handler := NewHealthHandler(cfg, vaultClient)

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	return app, handler
}

func TestHealthHandler_Health(t *testing.T) {
	app, handler := setupHealthTest()
	app.Get("/health", handler.Health)

	req := httptest.NewRequest("GET", "/health", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	bodyStr := string(body)
	assert.Contains(t, bodyStr, `"status":"healthy"`)
	assert.Contains(t, bodyStr, `"vault":"http://localhost:8200"`)
	assert.Contains(t, bodyStr, `"version":"1.0.0"`)
}

func TestHealthHandler_Ready(t *testing.T) {
	t.Run("Vault is healthy", func(t *testing.T) {
		app, handler := setupHealthTest()
		app.Get("/ready", handler.Ready)

		req := httptest.NewRequest("GET", "/ready", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		bodyStr := string(body)
		assert.Contains(t, bodyStr, `"status":"ready"`)
		assert.Contains(t, bodyStr, `"version":"1.0.0"`)
	})

	t.Run("Vault is unhealthy", func(t *testing.T) {
		cfg := &config.Config{
			Version: "1.0.0",
		}

		vaultClient := mocks.NewMockVaultClient()
		// Override the health check to return an error
		vaultClient.ExpectedCalls = nil
		vaultClient.On("HealthCheck").Return(assert.AnError)

		handler := NewHealthHandler(cfg, vaultClient)

		app := fiber.New(fiber.Config{
			DisableStartupMessage: true,
		})
		app.Get("/ready", handler.Ready)

		req := httptest.NewRequest("GET", "/ready", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 503, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		bodyStr := string(body)
		assert.Contains(t, bodyStr, `"status":"not ready"`)
		assert.Contains(t, bodyStr, `"error":"vault unreachable"`)
	})
}

func TestHealthHandler_Version(t *testing.T) {
	app, handler := setupHealthTest()
	app.Get("/version", handler.Version)

	req := httptest.NewRequest("GET", "/version", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	bodyStr := string(body)
	assert.Contains(t, bodyStr, `"version":"1.0.0"`)
	assert.Contains(t, bodyStr, `"commit":"abc123"`)
	assert.Contains(t, bodyStr, `"date":"2023-01-01"`)
	assert.Contains(t, bodyStr, `"builtBy":"test"`)
}

func TestNewHealthHandler(t *testing.T) {
	cfg := &config.Config{Version: "1.0.0"}
	vaultClient := mocks.NewMockVaultClient()

	handler := NewHealthHandler(cfg, vaultClient)

	assert.NotNil(t, handler)
	assert.Equal(t, cfg, handler.config)
	assert.Equal(t, vaultClient, handler.vault)
}