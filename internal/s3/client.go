package s3

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"s3-vault-proxy/internal/logging"
)

// Client handles communication with S3/MinIO backend
type Client struct {
	endpoint   string
	httpClient *http.Client
}

// Interface defines operations for S3 client
type Interface interface {
	ForwardRequest(method, path string, body io.Reader, headers http.Header, queryString []byte) (*http.Response, error)
	HeadObject(bucket, key string, headers http.Header) (*http.Response, error)
}

// NewClient creates a new S3 client with connection pooling
func NewClient(endpoint string) *Client {
	return &Client{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  false,
			},
		},
	}
}

// ForwardRequest forwards an HTTP request to the S3 backend
func (c *Client) ForwardRequest(method, path string, body io.Reader, headers http.Header, queryString []byte) (*http.Response, error) {
	// Build the full URL
	fullURL := c.endpoint + path
	if queryString != nil && len(queryString) > 0 {
		fullURL += "?" + string(queryString)
	}

	// Create HTTP request
	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Copy headers, preserving authentication and other important headers
	c.copyHeaders(req, headers)

	// Debug logging for signature-sensitive headers
	logging.Debug().
		Str("method", method).
		Str("url", fullURL).
		Str("final_host", req.Host).
		Str("authorization", req.Header.Get("Authorization")).
		Str("date", req.Header.Get("Date")).
		Str("x-amz-date", req.Header.Get("X-Amz-Date")).
		Str("x-amz-content-sha256", req.Header.Get("X-Amz-Content-Sha256")).
		Msg("Forwarding request to S3 with headers")

	// Make the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to forward request to S3: %w", err)
	}

	if resp.StatusCode >= 400 {
		// Read error response for debugging
		if body, readErr := io.ReadAll(resp.Body); readErr == nil {
			resp.Body.Close()
			logging.Warn().
				Int("status_code", resp.StatusCode).
				Str("method", method).
				Str("error_body", string(body)).
				Msg("S3 error response")
			// Create a new reader for the response body so it can be read again
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}
	} else {
		logging.Debug().
			Int("status_code", resp.StatusCode).
			Str("method", method).
			Msg("S3 response received")
	}

	return resp, nil
}

// HeadObject performs a HEAD request for an object
func (c *Client) HeadObject(bucket, key string, headers http.Header) (*http.Response, error) {
	path := fmt.Sprintf("/%s/%s", bucket, key)
	return c.ForwardRequest("HEAD", path, nil, headers, nil)
}

// copyHeaders copies headers from source to destination request, handling special cases
func (c *Client) copyHeaders(req *http.Request, headers http.Header) {
	var originalHost string

	logger := logging.Debug()
	headerCount := 0

	for key, values := range headers {
		if len(values) == 0 {
			continue
		}

		value := values[0]
		headerCount++

		// Capture the original Host header for later
		if key == "Host" {
			originalHost = value
		}

		// Skip hop-by-hop headers
		if c.isHopByHopHeader(key) {
			logging.Debug().
				Str("header", key).
				Str("value", value).
				Msg("Skipping hop-by-hop header")
			continue
		}

		req.Header.Set(key, value)
	}

	// CRITICAL: Preserve the original Host header for MinIO domain validation
	// MinIO is configured with MINIO_DOMAIN=xxx and expects this exact host
	if originalHost != "" {
		req.Host = originalHost
		req.Header.Set("Host", originalHost)
		logging.Debug().
			Str("host", originalHost).
			Str("endpoint", c.endpoint).
			Msg("Preserved original Host header for MinIO domain validation")
	}

	logger.Int("header_count", headerCount).
		Str("final_host", req.Host).
		Msg("Headers processed for S3 request")
}

// isHopByHopHeader checks if a header is hop-by-hop and should not be forwarded
func (c *Client) isHopByHopHeader(header string) bool {
	hopByHopHeaders := []string{
		"Connection",
		"Transfer-Encoding",
		"Upgrade",
		"Proxy-Connection",
		"TE",
		"Trailer",
		"Keep-Alive",
	}

	for _, hopHeader := range hopByHopHeaders {
		if header == hopHeader {
			return true
		}
	}
	return false
}

// Close closes the HTTP client and cleans up resources
func (c *Client) Close() {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
}
