package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/hashicorp/vault/api"
)

// Build-time variables (generally set by goreleaser)
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

type S3VaultProxy struct {
	vault       *api.Client
	storagePath string
	tokenPath   string
}

// S3 XML response structures
type ListBucketsResult struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Owner   Owner    `xml:"Owner"`
	Buckets Buckets  `xml:"Buckets"`
}

type Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type Buckets struct {
	Bucket []Bucket `xml:"Bucket"`
}

type Bucket struct {
	Name         string    `xml:"Name"`
	CreationDate time.Time `xml:"CreationDate"`
}

type ListBucketResult struct {
	XMLName     xml.Name  `xml:"ListBucketResult"`
	Name        string    `xml:"Name"`
	Prefix      string    `xml:"Prefix"`
	MaxKeys     int       `xml:"MaxKeys"`
	IsTruncated bool      `xml:"IsTruncated"`
	Contents    []Content `xml:"Contents"`
}

type Content struct {
	Key          string    `xml:"Key"`
	LastModified time.Time `xml:"LastModified"`
	ETag         string    `xml:"ETag"`
	Size         int64     `xml:"Size"`
	StorageClass string    `xml:"StorageClass"`
}

type ErrorResponse struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func NewS3VaultProxy() (*S3VaultProxy, error) {
	config := api.DefaultConfig()
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		config.Address = addr
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	tokenPath := os.Getenv("VAULT_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = "/vault/secrets/token" // Default Vault Agent path (if using injector)
	}

	storagePath := os.Getenv("STORAGE_PATH")
	if storagePath == "" {
		storagePath = "./data"
	}

	if err := setVaultToken(client, tokenPath); err != nil {
		return nil, fmt.Errorf("failed to set vault token: %w", err)
	}

	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage path: %w", err)
	}

	proxy := &S3VaultProxy{
		vault:       client,
		storagePath: storagePath,
		tokenPath:   tokenPath,
	}

	go proxy.watchTokenFile()

	return proxy, nil
}

func setVaultToken(client *api.Client, tokenPath string) error {
	if tokenBytes, err := os.ReadFile(tokenPath); err == nil {
		token := strings.TrimSpace(string(tokenBytes))
		if token != "" {
			client.SetToken(token)
			log.Printf("Using Vault token from file: %s", tokenPath)
			return nil
		}
	}

	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		client.SetToken(token)
		log.Printf("Using Vault token from environment variable")
		return nil
	}

	return fmt.Errorf("no vault token found in file %s or VAULT_TOKEN environment variable", tokenPath)
}

func (p *S3VaultProxy) watchTokenFile() {
	if p.tokenPath == "" {
		return
	}

	log.Printf("Watching token file: %s", p.tokenPath)

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	var lastToken string

	for range ticker.C {
		if tokenBytes, err := os.ReadFile(p.tokenPath); err == nil {
			newToken := strings.TrimSpace(string(tokenBytes))
			if newToken != "" && newToken != lastToken {
				p.vault.SetToken(newToken)
				log.Printf("Updated Vault token from file")
				lastToken = newToken
			}
		}
	}
}

// Convert KMS ARN to Vault transit key format: region_account_keyuuid to handle unloved chars such as : and /
func (p *S3VaultProxy) arnToVaultKey(arn string) (string, error) {
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

// Get KMS key ARN from request headers
func (p *S3VaultProxy) getKMSKeyARN(c *fiber.Ctx) (string, error) {
	// Check for KMS key in headers
	kmsKeyARN := c.Get("x-amz-server-side-encryption-aws-kms-key-id")
	if kmsKeyARN == "" {
		return "", fmt.Errorf("KMS key ARN is required (x-amz-server-side-encryption-aws-kms-key-id header)")
	}

	return kmsKeyARN, nil
}

func (p *S3VaultProxy) encrypt(data []byte, transitKey string) (string, error) {
	plaintext := base64.StdEncoding.EncodeToString(data)

	resp, err := p.vault.Logical().Write(fmt.Sprintf("transit/encrypt/%s", transitKey), map[string]interface{}{
		"plaintext": plaintext,
	})
	if err != nil {
		return "", fmt.Errorf("vault encryption failed for key %s: %w", transitKey, err)
	}

	ciphertext, ok := resp.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("invalid ciphertext response from vault")
	}

	return ciphertext, nil
}

func (p *S3VaultProxy) decrypt(ciphertext string, transitKey string) ([]byte, error) {
	resp, err := p.vault.Logical().Write(fmt.Sprintf("transit/decrypt/%s", transitKey), map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("vault decryption failed for key %s: %w", transitKey, err)
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

func (p *S3VaultProxy) getObjectPath(bucket, key string) string {
	return filepath.Join(p.storagePath, bucket, key)
}

func (p *S3VaultProxy) getMetadataPath(bucket, key string) string {
	return filepath.Join(p.storagePath, bucket, ".metadata", key)
}

func (p *S3VaultProxy) ensureBucketExists(bucket string) error {
	bucketPath := filepath.Join(p.storagePath, bucket)
	metadataPath := filepath.Join(bucketPath, ".metadata")

	if err := os.MkdirAll(bucketPath, 0755); err != nil {
		return err
	}

	return os.MkdirAll(metadataPath, 0755)
}

func (p *S3VaultProxy) objectExists(bucket, key string) bool {
	path := p.getObjectPath(bucket, key)
	_, err := os.Stat(path)
	return err == nil
}

func (p *S3VaultProxy) putObject(c *fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")

	if bucket == "" || key == "" {
		return c.Status(400).XML(ErrorResponse{
			Code:    "InvalidRequest",
			Message: "Missing bucket or key",
		})
	}

	body := c.Body()
	if len(body) == 0 {
		return c.Status(400).XML(ErrorResponse{
			Code:    "InvalidRequest",
			Message: "Empty request body",
		})
	}

	kmsKeyARN, err := p.getKMSKeyARN(c)
	if err != nil {
		log.Printf("Missing KMS key: %v", err)
		return c.Status(400).XML(ErrorResponse{
			Code:    "InvalidRequest",
			Message: err.Error(),
		})
	}

	// Convert ARN to Vault-compatible transit key name
	transitKey, err := p.arnToVaultKey(kmsKeyARN)
	if err != nil {
		log.Printf("Invalid KMS ARN: %v", err)
		return c.Status(400).XML(ErrorResponse{
			Code:    "InvalidRequest",
			Message: err.Error(),
		})
	}

	log.Printf("Using ARN '%s' as Vault transit key '%s' for bucket '%s'", kmsKeyARN, transitKey, bucket)

	// Ensure bucket exists
	if err := p.ensureBucketExists(bucket); err != nil {
		log.Printf("Failed to create bucket directory: %v", err)
		return c.Status(500).XML(ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to create bucket",
		})
	}

	ciphertext, err := p.encrypt(body, transitKey)
	if err != nil {
		log.Printf("Encryption failed: %v", err)
		return c.Status(500).XML(ErrorResponse{
			Code:    "InternalError",
			Message: "Encryption failed",
		})
	}

	objectPath := p.getObjectPath(bucket, key)
	objectDir := filepath.Dir(objectPath)
	if err := os.MkdirAll(objectDir, 0755); err != nil {
		log.Printf("Failed to create object directory: %v", err)
		return c.Status(500).XML(ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to create object directory",
		})
	}

	if err := os.WriteFile(objectPath, []byte(ciphertext), 0644); err != nil {
		log.Printf("Failed to write object: %v", err)
		return c.Status(500).XML(ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to store object",
		})
	}

	metadata := map[string]string{
		"content-length": strconv.Itoa(len(body)),
		"content-type":   c.Get("Content-Type", "binary/octet-stream"),
		"etag":           fmt.Sprintf(`"%x"`, md5.Sum(body)),
		"last-modified":  time.Now().UTC().Format(time.RFC1123),
		"kms-key-arn":    kmsKeyARN, // Store the full ARN
	}

	metadataPath := p.getMetadataPath(bucket, key)
	metadataDir := filepath.Dir(metadataPath)
	if err := os.MkdirAll(metadataDir, 0755); err != nil {
		log.Printf("Failed to create metadata directory: %v", err)
	}

	metadataContent := ""
	for k, v := range metadata {
		metadataContent += fmt.Sprintf("%s: %s\n", k, v)
	}
	os.WriteFile(metadataPath, []byte(metadataContent), 0644)

	c.Set("ETag", metadata["etag"])
	c.Set("x-amz-server-side-encryption", "aws:kms")
	c.Set("x-amz-server-side-encryption-aws-kms-key-id", kmsKeyARN)

	return c.SendStatus(200)
}

func (p *S3VaultProxy) getObject(c *fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")

	if !p.objectExists(bucket, key) {
		return c.Status(404).XML(ErrorResponse{
			Code:    "NoSuchKey",
			Message: "The specified key does not exist",
		})
	}

	metadataPath := p.getMetadataPath(bucket, key)
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		log.Printf("Failed to read metadata: %v", err)
		return c.Status(500).XML(ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to read object metadata",
		})
	}

	var kmsKeyARN string
	lines := strings.Split(string(metadataBytes), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "kms-key-arn:") {
			kmsKeyARN = strings.TrimSpace(strings.TrimPrefix(line, "kms-key-arn:"))
			break
		}
	}

	if kmsKeyARN == "" {
		log.Printf("No KMS key ARN found in metadata for %s/%s", bucket, key)
		return c.Status(500).XML(ErrorResponse{
			Code:    "InternalError",
			Message: "Missing encryption key information",
		})
	}

	transitKey, err := p.arnToVaultKey(kmsKeyARN)
	if err != nil {
		log.Printf("Invalid stored KMS ARN: %v", err)
		return c.Status(500).XML(ErrorResponse{
			Code:    "InternalError",
			Message: "Invalid encryption key information",
		})
	}

	log.Printf("Decrypting with ARN '%s' as Vault transit key '%s' for bucket '%s'", kmsKeyARN, transitKey, bucket)

	objectPath := p.getObjectPath(bucket, key)
	ciphertext, err := os.ReadFile(objectPath)
	if err != nil {
		log.Printf("Failed to read object: %v", err)
		return c.Status(500).XML(ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to read object",
		})
	}

	data, err := p.decrypt(string(ciphertext), transitKey)
	if err != nil {
		log.Printf("Decryption failed: %v", err)
		return c.Status(500).XML(ErrorResponse{
			Code:    "InternalError",
			Message: "Decryption failed",
		})
	}

	// Set metadata headers
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				switch strings.ToLower(key) {
				case "content-type":
					c.Set("Content-Type", value)
				case "etag":
					c.Set("ETag", value)
				case "last-modified":
					c.Set("Last-Modified", value)
				}
			}
		}
	}

	// Set KMS-related headers
	c.Set("x-amz-server-side-encryption", "aws:kms")
	c.Set("x-amz-server-side-encryption-aws-kms-key-id", kmsKeyARN)
	c.Set("Content-Length", strconv.Itoa(len(data)))

	return c.Send(data)
}

func (p *S3VaultProxy) headObject(c *fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")

	if !p.objectExists(bucket, key) {
		return c.Status(404).XML(ErrorResponse{
			Code:    "NoSuchKey",
			Message: "The specified key does not exist",
		})
	}

	// Read metadata
	metadataPath := p.getMetadataPath(bucket, key)
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		log.Printf("Failed to read metadata: %v", err)
		return c.Status(500).XML(ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to read object metadata",
		})
	}

	var kmsKeyARN string
	lines := strings.Split(string(metadataBytes), "\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				switch strings.ToLower(key) {
				case "content-type":
					c.Set("Content-Type", value)
				case "content-length":
					c.Set("Content-Length", value)
				case "etag":
					c.Set("ETag", value)
				case "last-modified":
					c.Set("Last-Modified", value)
				case "kms-key-arn":
					kmsKeyARN = value
				}
			}
		}
	}

	// Set KMS-related headers
	if kmsKeyARN != "" {
		c.Set("x-amz-server-side-encryption", "aws:kms")
		c.Set("x-amz-server-side-encryption-aws-kms-key-id", kmsKeyARN)
	}

	return c.SendStatus(200)
}

func (p *S3VaultProxy) deleteObject(c *fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")

	objectPath := p.getObjectPath(bucket, key)
	metadataPath := p.getMetadataPath(bucket, key)

	os.Remove(objectPath)
	os.Remove(metadataPath)

	return c.SendStatus(204)
}

func (p *S3VaultProxy) listBuckets(c *fiber.Ctx) error {
	buckets := []Bucket{}

	entries, err := os.ReadDir(p.storagePath)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				info, err := entry.Info()
				if err == nil {
					buckets = append(buckets, Bucket{
						Name:         entry.Name(),
						CreationDate: info.ModTime(),
					})
				}
			}
		}
	}

	response := ListBucketsResult{
		Owner: Owner{
			ID:          "vault-s3-proxy",
			DisplayName: "vault-s3-proxy",
		},
		Buckets: Buckets{Bucket: buckets},
	}

	return c.XML(response)
}

func (p *S3VaultProxy) listObjects(c *fiber.Ctx) error {
	bucket := c.Params("bucket")
	prefix := c.Query("prefix", "")
	maxKeys := 1000

	if mk := c.Query("max-keys"); mk != "" {
		if parsed, err := strconv.Atoi(mk); err == nil {
			maxKeys = parsed
		}
	}

	bucketPath := filepath.Join(p.storagePath, bucket)
	contents := []Content{}

	err := filepath.Walk(bucketPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.Contains(path, ".metadata") {
			return nil
		}

		relPath, err := filepath.Rel(bucketPath, path)
		if err != nil {
			return nil
		}

		key := strings.ReplaceAll(relPath, "\\", "/")

		if prefix != "" && !strings.HasPrefix(key, prefix) {
			return nil
		}

		if len(contents) >= maxKeys {
			return nil
		}

		// Try to get original size from metadata
		size := info.Size() // This is encrypted size, not ideal but fallback
		etag := fmt.Sprintf(`"%x"`, md5.Sum([]byte(key)))

		metadataPath := p.getMetadataPath(bucket, key)
		if metadataBytes, err := os.ReadFile(metadataPath); err == nil {
			lines := strings.Split(string(metadataBytes), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "content-length:") {
					if sizeStr := strings.TrimSpace(strings.TrimPrefix(line, "content-length:")); sizeStr != "" {
						if parsedSize, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
							size = parsedSize
						}
					}
				} else if strings.HasPrefix(line, "etag:") {
					if etagStr := strings.TrimSpace(strings.TrimPrefix(line, "etag:")); etagStr != "" {
						etag = etagStr
					}
				}
			}
		}

		contents = append(contents, Content{
			Key:          key,
			LastModified: info.ModTime(),
			ETag:         etag,
			Size:         size,
			StorageClass: "STANDARD",
		})

		return nil
	})

	if err != nil {
		log.Printf("Error walking bucket: %v", err)
	}

	response := ListBucketResult{
		Name:        bucket,
		Prefix:      prefix,
		MaxKeys:     maxKeys,
		IsTruncated: false,
		Contents:    contents,
	}

	return c.XML(response)
}

func (p *S3VaultProxy) createBucket(c *fiber.Ctx) error {
	bucket := c.Params("bucket")

	if err := p.ensureBucketExists(bucket); err != nil {
		log.Printf("Failed to create bucket: %v", err)
		return c.Status(500).XML(ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to create bucket",
		})
	}

	return c.SendStatus(200)
}

func main() {
	// Initialize proxy
	proxy, err := NewS3VaultProxy()
	if err != nil {
		log.Fatalf("Failed to initialize S3 Vault Proxy: %v", err)
	}

	// Create Fiber app with maximum performance config
	app := fiber.New(fiber.Config{
		Prefork:                   false, // Removed prefork adjustments
		DisableKeepalive:          false, // Keep connections alive for better performance
		DisableDefaultDate:        true,  // Skip automatic date header
		DisableDefaultContentType: true,  // Skip automatic content-type header
		DisableHeaderNormalizing:  true,  // Skip header case normalization
		DisableStartupMessage:     false, // Keep startup message for debugging

		CaseSensitive:     true,  // Faster routing, apparently
		StrictRouting:     false, // More flexible routing
		UnescapePath:      false, // Don't unescape paths automatically
		ReduceMemoryUsage: false, // Prioritize speed over memory

		BodyLimit:       100 * 1024 * 1024, // 100MB limit
		ReadBufferSize:  16384,             // 16KB read buffer
		WriteBufferSize: 16384,             // 16KB write buffer ReadTimeout:     30 * time.Second,    // Prevent hanging connections
		WriteTimeout:    30 * time.Second,  // Prevent hanging connections
		IdleTimeout:     60 * time.Second,  // Keep-alive timeout

		ServerHeader: "S3-Vault-Proxy/1.0",
		AppName:      "S3-Vault-Proxy",

		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}

			log.Printf("Request error: %v (path: %s)", err, c.Path())

			return c.Status(code).XML(ErrorResponse{
				Code:    "InternalError",
				Message: err.Error(),
			})
		},
	})

	app.Use(recover.New(recover.Config{
		EnableStackTrace: true,
	}))

	if os.Getenv("ENABLE_LOGGING") == "true" {
		app.Use(logger.New(logger.Config{
			Format:     "[${time}] ${status} - ${latency} ${method} ${path} ${bytesSent}B\n",
			TimeFormat: "15:04:05",
			TimeZone:   "UTC",
			Done: func(c *fiber.Ctx, logString []byte) {
				os.Stdout.Write(logString)
			},
		}))
	}

	app.Use(cors.New(cors.Config{
		AllowCredentials: false,
		AllowOrigins:     "*",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Amz-Date, X-Amz-Content-Sha256, X-Amz-Security-Token",
		AllowMethods:     "GET, POST, PUT, DELETE, HEAD, OPTIONS",
		MaxAge:           86400, // Cache preflight for 24 hours
	}))

	app.Get("/health", func(c *fiber.Ctx) error {
		c.Set("Content-Type", "application/json")
		return c.SendString(`{"status":"healthy","vault":"` + proxy.vault.Address() + `","version":"` + version + `"}`)
	})

	app.Get("/ready", func(c *fiber.Ctx) error {
		// Quick Vault connectivity test
		_, err := proxy.vault.Sys().Health()
		if err != nil {
			return c.Status(503).SendString(`{"status":"not ready","error":"vault unreachable"}`)
		}
		return c.SendString(`{"status":"ready","version":"` + version + `"}`)
	})

	app.Get("/version", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"version": version,
			"commit":  commit,
			"date":    date,
			"builtBy": builtBy,
		})
	})

	// S3 API Routes
	app.Get("/", proxy.listBuckets)

	app.Put("/:bucket", proxy.createBucket)
	app.Get("/:bucket", proxy.listObjects)
	app.Put("/:bucket/*", proxy.putObject)
	app.Get("/:bucket/*", proxy.getObject)
	app.Head("/:bucket/*", proxy.headObject)
	app.Delete("/:bucket/*", proxy.deleteObject)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	log.Printf("Starting S3 Vault Proxy")
	log.Printf("   Version: %s", version)
	log.Printf("   Commit: %s", commit)
	log.Printf("   Built: %s", date)
	log.Printf("   Port: %s", port)
	log.Printf("   Storage: %s", proxy.storagePath)
	log.Printf("   Vault: %s", proxy.vault.Address())

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Gracefully shutting down...")
		_ = app.Shutdown()
	}()

	log.Fatal(app.Listen(":" + port))
}
