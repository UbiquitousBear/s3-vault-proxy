package handlers

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"s3-vault-proxy/internal/logging"
	"s3-vault-proxy/internal/metadata"
	"s3-vault-proxy/internal/s3"
	"s3-vault-proxy/internal/vault"
	"s3-vault-proxy/pkg/types"

	"github.com/gofiber/fiber/v2"
)

// S3Handler handles S3 API operations
type S3Handler struct {
	s3Client        s3.Interface
	vaultClient     vault.Interface
	metadataService metadata.Interface
}

// NewS3Handler creates a new S3 handler
func NewS3Handler(s3Client s3.Interface, vaultClient vault.Interface, metadataService metadata.Interface) *S3Handler {
	return &S3Handler{
		s3Client:        s3Client,
		vaultClient:     vaultClient,
		metadataService: metadataService,
	}
}

// ListBuckets handles GET / - list all buckets
func (h *S3Handler) ListBuckets(c *fiber.Ctx) error {
	headers := h.extractHeaders(c)
	resp, err := h.s3Client.ForwardRequest("GET", "/", nil, headers, c.Request().URI().QueryString())
	if err != nil {
		logging.Error().Err(err).Msg("Failed to list buckets")
		return c.Status(500).XML(types.ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to list buckets",
		})
	}
	defer resp.Body.Close()

	return h.forwardResponse(c, resp)
}

// CreateBucket handles PUT /:bucket - create a bucket
func (h *S3Handler) CreateBucket(c *fiber.Ctx) error {
	bucket := c.Params("bucket")
	path := fmt.Sprintf("/%s", bucket)
	headers := h.extractHeaders(c)

	resp, err := h.s3Client.ForwardRequest("PUT", path, nil, headers, c.Request().URI().QueryString())
	if err != nil {
		logging.Error().Err(err).Msg("Failed to create bucket")
		return c.Status(500).XML(types.ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to create bucket",
		})
	}
	defer resp.Body.Close()

	return h.forwardResponse(c, resp)
}

// ListObjects handles GET /:bucket - list objects in bucket
func (h *S3Handler) ListObjects(c *fiber.Ctx) error {
	bucket := c.Params("bucket")
	path := fmt.Sprintf("/%s", bucket)
	headers := h.extractHeaders(c)
	queryString := c.Request().URI().QueryString()

	logging.Debug().
		Str("bucket", bucket).
		Str("path", path).
		Str("original_query", string(queryString)).
		Str("original_host", c.Get("Host")).
		Msg("ListObjects request details")

	resp, err := h.s3Client.ForwardRequest("GET", path, nil, headers, queryString)
	if err != nil {
		logging.Error().Err(err).Msg("Failed to list objects")
		return c.Status(500).XML(types.ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to list objects",
		})
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return h.forwardResponse(c, resp)
	}

	// Parse and filter response to remove metadata files
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.Status(500).XML(types.ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to read list response",
		})
	}

	var listResult types.ListBucketResult
	if err := xml.Unmarshal(body, &listResult); err != nil {
		// If we can't parse it, just forward the original response
		return h.forwardRawResponse(c, resp.StatusCode, resp.Header, body)
	}

	// Filter out .metadata files and enhance with stored metadata
	filteredContents := metadata.FilterMetadataObjects(listResult.Contents)
	for i := range filteredContents {
		if storedMeta, metaErr := h.metadataService.Get(bucket, filteredContents[i].Key, headers); metaErr == nil {
			filteredContents[i].Size = storedMeta.ContentLength
			filteredContents[i].ETag = storedMeta.ETag
		}
	}

	listResult.Contents = filteredContents
	c.Set("Content-Type", "application/xml")
	return c.XML(listResult)
}

// PutObject handles PUT /:bucket/* - forward request directly for signature validation
func (h *S3Handler) PutObject(c *fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")

	if bucket == "" || key == "" {
		return c.Status(400).XML(types.ErrorResponse{
			Code:    "InvalidRequest",
			Message: "Missing bucket or key",
		})
	}

	// Get KMS key from headers for logging purposes
	kmsKeyARN, err := h.getKMSKeyARN(c)
	if err != nil {
		logging.Warn().Err(err).Msg("Missing KMS key in request")
		return c.Status(400).XML(types.ErrorResponse{
			Code:    "InvalidRequest",
			Message: err.Error(),
		})
	}

	// Convert KMS ARN to Vault key for logging
	transitKey, err := h.vaultClient.ARNToVaultKey(kmsKeyARN)
	if err != nil {
		logging.Error().Err(err).Str("kms_arn", kmsKeyARN).Msg("Invalid KMS ARN format")
		return c.Status(400).XML(types.ErrorResponse{
			Code:    "InvalidRequest",
			Message: err.Error(),
		})
	}

	logging.Info().
		Str("bucket", bucket).
		Str("key", key).
		Str("kms_arn", kmsKeyARN).
		Str("transit_key", transitKey).
		Msg("Mapped KMS ARN to Vault transit key")

	// CRITICAL: Forward the original request body directly to preserve AWS signature validation
	// This maintains compatibility with chunked encoding and streaming signatures
	path := fmt.Sprintf("/%s/%s", bucket, key)
	headers := h.extractHeaders(c)
	
	// Use the raw Fiber request to preserve all original headers including Content-Length
	// This is essential for AWS signature validation with chunked encoding
	bodyReader := bytes.NewReader(c.Body())
	
	resp, err := h.s3Client.ForwardRequest("PUT", path, bodyReader, headers, c.Request().URI().QueryString())
	if err != nil {
		logging.Error().Err(err).Msg("Failed to store encrypted object")
		return c.Status(500).XML(types.ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to store object",
		})
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		logging.Error().Int("status_code", resp.StatusCode).Msg("S3 storage failed")
		// Forward the error response from MinIO directly
		return c.Status(resp.StatusCode).Send(nil)
	}

	// Copy response headers from MinIO
	for key, values := range resp.Header {
		if len(values) > 0 {
			c.Set(key, values[0])
		}
	}

	// Ensure KMS encryption headers are set for client compatibility
	c.Set("x-amz-server-side-encryption", "aws:kms")
	c.Set("x-amz-server-side-encryption-aws-kms-key-id", kmsKeyARN)

	return c.SendStatus(resp.StatusCode)
}

// GetObject handles GET /:bucket/* - download object directly from Garage
func (h *S3Handler) GetObject(c *fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")
	headers := h.extractHeaders(c)
	path := fmt.Sprintf("/%s/%s", bucket, key)

	// Forward the GET request directly to Garage - no encryption/metadata needed
	resp, err := h.s3Client.ForwardRequest("GET", path, nil, headers, nil)
	if err != nil {
		logging.Error().Err(err).Msg("Failed to get object")
		return c.Status(500).XML(types.ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to get object",
		})
	}
	defer resp.Body.Close()

	// Forward the response directly from Garage
	return h.forwardResponse(c, resp)
}

// HeadObject handles HEAD /:bucket/* - get object metadata
func (h *S3Handler) HeadObject(c *fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")
	headers := h.extractHeaders(c)
	path := fmt.Sprintf("/%s/%s", bucket, key)

	// Forward the HEAD request directly to Garage and return the response
	resp, err := h.s3Client.ForwardRequest("HEAD", path, nil, headers, nil)
	if err != nil {
		logging.Error().Err(err).Msg("Failed to head object")
		return c.Status(500).XML(types.ErrorResponse{
			Code:    "InternalError",
			Message: "Failed to head object",
		})
	}
	defer resp.Body.Close()

	// Forward the response directly - no metadata service needed for plain storage
	return h.forwardResponse(c, resp)
}

// DeleteObject handles DELETE /:bucket/* - delete object and metadata
func (h *S3Handler) DeleteObject(c *fiber.Ctx) error {
	bucket := c.Params("bucket")
	key := c.Params("*")
	headers := h.extractHeaders(c)

	// Delete the main object
	path := fmt.Sprintf("/%s/%s", bucket, key)
	resp, err := h.s3Client.ForwardRequest("DELETE", path, nil, headers, nil)
	if err != nil {
		logging.Error().Err(err).Msg("Failed to delete object")
	} else {
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			logging.Error().Int("status_code", resp.StatusCode).Msg("Failed to delete object")
		}
	}

	// Delete the metadata object
	metadataKey := key + ".metadata"
	metadataPath := fmt.Sprintf("/%s/%s", bucket, metadataKey)
	metaResp, err := h.s3Client.ForwardRequest("DELETE", metadataPath, nil, headers, nil)
	if err != nil {
		logging.Error().Err(err).Msg("Failed to delete metadata")
	} else {
		defer metaResp.Body.Close()
		if metaResp.StatusCode >= 400 {
			logging.Error().Int("status_code", metaResp.StatusCode).Msg("Failed to delete metadata")
		}
	}

	return c.SendStatus(204)
}

// Helper methods

func (h *S3Handler) extractHeaders(c *fiber.Ctx) http.Header {
	headers := make(http.Header)
	c.Request().Header.VisitAll(func(key, value []byte) {
		// CRITICAL: Preserve exact header case for AWS signature validation
		// Use direct map assignment instead of Add() or Set() to avoid canonicalization
		keyStr := string(key)
		valueStr := string(value)
		headers[keyStr] = append(headers[keyStr], valueStr)
	})
	return headers
}

func (h *S3Handler) getKMSKeyARN(c *fiber.Ctx) (string, error) {
	kmsKeyARN := c.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id")
	if kmsKeyARN == "" {
		kmsKeyARN = c.Get("x-amz-server-side-encryption-aws-kms-key-id")
	}
	if kmsKeyARN == "" {
		return "", fmt.Errorf("KMS key ARN is required (x-amz-server-side-encryption-aws-kms-key-id header)")
	}
	return kmsKeyARN, nil
}

func (h *S3Handler) setObjectHeaders(c *fiber.Ctx, metadata *types.ObjectMetadata, isEncrypted bool) {
	c.Set("Content-Type", metadata.ContentType)
	c.Set("Content-Length", strconv.FormatInt(metadata.ContentLength, 10))
	c.Set("ETag", metadata.ETag)

	// Parse and set Last-Modified header
	if parsedTime, err := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", metadata.LastModified); err == nil {
		c.Set("Last-Modified", parsedTime.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	} else if parsedTime, err := time.Parse(time.RFC1123, metadata.LastModified); err == nil {
		c.Set("Last-Modified", parsedTime.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	} else {
		c.Set("Last-Modified", metadata.LastModified)
	}

	if isEncrypted {
		c.Set("x-amz-server-side-encryption", "aws:kms")
		c.Set("x-amz-server-side-encryption-aws-kms-key-id", metadata.KMSKeyARN)
	}
}

func (h *S3Handler) copyResponseHeaders(c *fiber.Ctx, headers http.Header) {
	for key, values := range headers {
		if len(values) > 0 {
			c.Set(key, values[0])
		}
	}
}

func (h *S3Handler) forwardResponse(c *fiber.Ctx, resp *http.Response) error {
	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			c.Set(key, value)
		}
	}

	// Set status and return body
	c.Status(resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return c.Send(body)
}

func (h *S3Handler) forwardRawResponse(c *fiber.Ctx, statusCode int, headers http.Header, body []byte) error {
	for key, values := range headers {
		for _, value := range values {
			c.Set(key, value)
		}
	}
	c.Status(statusCode)
	return c.Send(body)
}
