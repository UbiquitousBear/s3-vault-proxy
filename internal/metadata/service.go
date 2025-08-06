package metadata

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"s3-vault-proxy/internal/logging"
	"s3-vault-proxy/internal/s3"
	"s3-vault-proxy/pkg/types"
)

// Service handles object metadata operations
type Service struct {
	s3Client s3.Interface
}

// Interface defines operations for metadata service
type Interface interface {
	Store(bucket, key string, metadata *types.ObjectMetadata, headers http.Header) error
	Get(bucket, key string, headers http.Header) (*types.ObjectMetadata, error)
	Exists(bucket, key string, headers http.Header) bool
}

// NewService creates a new metadata service
func NewService(s3Client s3.Interface) *Service {
	return &Service{
		s3Client: s3Client,
	}
}

// Store saves object metadata as a separate S3 object
func (s *Service) Store(bucket, key string, metadata *types.ObjectMetadata, headers http.Header) error {
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	metadataKey := s.getMetadataKey(key)
	path := fmt.Sprintf("/%s/%s", bucket, metadataKey)

	logging.Debug().
		Str("bucket", bucket).
		Str("key", key).
		Str("path", path).
		Msg("Storing object metadata")

	resp, err := s.s3Client.ForwardRequest("PUT", path, bytes.NewReader(metadataBytes), headers, nil)
	if err != nil {
		return fmt.Errorf("failed to store metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		logging.Error().
			Str("bucket", bucket).
			Str("key", key).
			Int("status_code", resp.StatusCode).
			Str("error_body", string(body)).
			Msg("Failed to store metadata")
		return fmt.Errorf("failed to store metadata: HTTP %d", resp.StatusCode)
	}

	logging.Debug().
		Str("bucket", bucket).
		Str("key", key).
		Msg("Successfully stored object metadata")
	return nil
}

// Get retrieves object metadata from S3
func (s *Service) Get(bucket, key string, headers http.Header) (*types.ObjectMetadata, error) {
	metadataKey := s.getMetadataKey(key)
	path := fmt.Sprintf("/%s/%s", bucket, metadataKey)

	logging.Debug().
		Str("bucket", bucket).
		Str("key", key).
		Str("path", path).
		Msg("Retrieving object metadata")

	resp, err := s.s3Client.ForwardRequest("GET", path, nil, headers, nil)
	if err != nil {
		logging.Error().
			Err(err).
			Str("bucket", bucket).
			Str("key", key).
			Msg("Failed to forward metadata request")
		return nil, fmt.Errorf("failed to get metadata: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 404:
		logging.Debug().
			Str("path", path).
			Msg("Metadata file not found - object may not have encryption metadata")
		return nil, fmt.Errorf("metadata not found for object %s/%s", bucket, key)
	case 403:
		body, _ := io.ReadAll(resp.Body)
		logging.Warn().
			Str("path", path).
			Str("response_body", string(body)).
			Msg("Access denied when reading metadata - check signature forwarding")
		return nil, fmt.Errorf("access denied reading metadata: HTTP %d", resp.StatusCode)
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		logging.Error().
			Int("status_code", resp.StatusCode).
			Str("response_body", string(body)).
			Msg("Failed to get metadata")
		return nil, fmt.Errorf("failed to get metadata: HTTP %d", resp.StatusCode)
	}

	metadataBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	logging.Debug().
		Str("metadata_content", string(metadataBytes)).
		Msg("Retrieved metadata content")

	var metadata types.ObjectMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &metadata, nil
}

// Exists checks if an object exists by performing a HEAD request
func (s *Service) Exists(bucket, key string, headers http.Header) bool {
	resp, err := s.s3Client.HeadObject(bucket, key, headers)
	if err != nil {
		logging.Debug().
			Err(err).
			Str("bucket", bucket).
			Str("key", key).
			Msg("Failed to check object existence")
		return false
	}
	defer resp.Body.Close()

	exists := resp.StatusCode == 200 || resp.StatusCode == 204
	logging.Debug().
		Str("bucket", bucket).
		Str("key", key).
		Bool("exists", exists).
		Int("status_code", resp.StatusCode).
		Msg("Object existence check")
	return exists
}

// getMetadataKey returns the S3 key for storing metadata
func (s *Service) getMetadataKey(objectKey string) string {
	return objectKey + ".metadata"
}

// FilterMetadataObjects removes metadata files from object listings
func FilterMetadataObjects(contents []types.Content) []types.Content {
	filtered := make([]types.Content, 0, len(contents))
	for _, obj := range contents {
		if !strings.HasSuffix(obj.Key, ".metadata") {
			filtered = append(filtered, obj)
		}
	}
	return filtered
}