package server

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"s3-vault-proxy/internal/config"
	"s3-vault-proxy/internal/handlers"
	"s3-vault-proxy/internal/logging"
	"s3-vault-proxy/internal/metadata"
	"s3-vault-proxy/internal/s3"
	"s3-vault-proxy/internal/vault"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// Server represents the HTTP server
type Server struct {
	app    *fiber.App
	config *config.Config
}

// New creates a new server instance
func New(cfg *config.Config) (*Server, error) {
	// Initialize logging first
	logging.InitGlobalLogger(logging.Config{
		Level:      cfg.LogLevel,
		Format:     cfg.LogFormat,
		TimeFormat: cfg.LogTimeFormat,
	})
	// Initialize Vault client
	vaultClient, err := vault.NewClient(cfg.VaultAddr, cfg.VaultToken, cfg.VaultTokenPath)
	if err != nil {
		return nil, err
	}

	// Initialize S3 client
	s3Client := s3.NewClient(cfg.S3Endpoint, cfg.S3CACertPath)

	// Initialize metadata service
	metadataService := metadata.NewService(s3Client)

	// Initialize handlers
	healthHandler := handlers.NewHealthHandler(cfg, vaultClient)
	s3Handler := handlers.NewS3Handler(s3Client, vaultClient, metadataService)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		Prefork:                   false,
		DisableKeepalive:          false,
		DisableDefaultDate:        true,
		DisableDefaultContentType: true,
		DisableHeaderNormalizing:  true,
		DisableStartupMessage:     cfg.DisableStartupMsg,

		CaseSensitive:     true,
		StrictRouting:     false,
		UnescapePath:      false,
		ReduceMemoryUsage: false,

		BodyLimit:       cfg.BodyLimit,
		ReadBufferSize:  cfg.ReadBufferSize,
		WriteBufferSize: cfg.WriteBufferSize,
		ReadTimeout:     cfg.ReadTimeout,
		WriteTimeout:    cfg.WriteTimeout,
		IdleTimeout:     cfg.IdleTimeout,

		ServerHeader: cfg.ServerHeader,
		AppName:      "S3-Vault-Proxy",

		ErrorHandler: errorHandler,
	})

	// Add middleware
	app.Use(recover.New(recover.Config{
		EnableStackTrace: true,
	}))

	// Custom logging middleware using zerolog
	app.Use(func(c *fiber.Ctx) error {
		start := time.Now()
		
		// Process request
		err := c.Next()
		
		// Log request after processing
		duration := time.Since(start)
		
		logEvent := logging.Info().
			Str("method", c.Method()).
			Str("path", c.Path()).
			Int("status", c.Response().StatusCode()).
			Dur("latency", duration).
			Str("ip", c.IP()).
			Str("user_agent", c.Get("User-Agent")).
			Int("bytes_sent", len(c.Response().Body()))
		
		// Add auth header info for debug level
		if authHeader := c.Get("Authorization"); authHeader != "" {
			logEvent = logEvent.Str("auth_present", "true")
		}
		
		if kmsKey := c.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"); kmsKey != "" {
			logEvent = logEvent.Str("kms_key", kmsKey)
		}
		
		if err != nil {
			logEvent = logEvent.Err(err)
		}
		
		logEvent.Msg("HTTP request processed")
		
		return err
	})

	app.Use(cors.New(cors.Config{
		AllowCredentials: false,
		AllowOrigins:     "*",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Amz-Date, X-Amz-Content-Sha256, X-Amz-Security-Token",
		AllowMethods:     "GET, POST, PUT, DELETE, HEAD, OPTIONS",
		MaxAge:           86400, // Cache preflight for 24 hours
	}))

	// Health check routes
	app.Get("/health", healthHandler.Health)
	app.Get("/ready", healthHandler.Ready)
	app.Get("/version", healthHandler.Version)

	// S3 API routes
	app.Get("/", s3Handler.ListBuckets)
	app.Put("/:bucket", s3Handler.CreateBucket)
	app.Get("/:bucket", s3Handler.ListObjects)
	app.Put("/:bucket/*", s3Handler.PutObject)
	app.Head("/:bucket/*", s3Handler.HeadObject)
	app.Get("/:bucket/*", s3Handler.GetObject)
	app.Delete("/:bucket/*", s3Handler.DeleteObject)

	return &Server{
		app:    app,
		config: cfg,
	}, nil
}

// Start starts the server
func (s *Server) Start() error {
	logging.Info().
		Str("version", s.config.Version).
		Str("commit", s.config.Commit).
		Str("build_date", s.config.Date).
		Str("port", s.config.Port).
		Str("s3_backend", s.config.S3Endpoint).
		Str("vault_addr", s.config.VaultAddr).
		Str("log_level", s.config.LogLevel).
		Str("log_format", s.config.LogFormat).
		Msg("Starting S3 Vault Proxy")

	// Set up graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		logging.Info().Msg("Gracefully shutting down...")
		_ = s.app.ShutdownWithTimeout(30 * time.Second)
	}()

	return s.app.Listen(":" + s.config.Port)
}

// errorHandler handles application errors
func errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	logging.Error().
		Err(err).
		Str("path", c.Path()).
		Str("method", c.Method()).
		Int("status_code", code).
		Msg("Request error")

	return c.Status(code).JSON(fiber.Map{
		"error": err.Error(),
	})
}