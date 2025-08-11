package s3

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"s3-vault-proxy/internal/logging"
)

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

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
func NewClient(endpoint string, caCertPath string) *Client {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}
	
	// Configure custom CA for internal MinIO if provided
	logging.Debug().
		Str("ca_path", caCertPath).
		Str("endpoint", endpoint).
		Bool("has_ca_path", caCertPath != "").
		Bool("is_https", strings.HasPrefix(endpoint, "https://")).
		Msg("S3 client CA certificate configuration check")
		
	if caCertPath != "" && strings.HasPrefix(endpoint, "https://") {
		logging.Info().
			Str("endpoint", endpoint).
			Str("ca_path", caCertPath).
			Msg("Loading custom CA certificate for S3 client")
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			logging.Error().Err(err).Str("ca_path", caCertPath).Msg("Failed to read CA certificate")
		} else {
			logging.Debug().
				Str("ca_path", caCertPath).
				Int("cert_size", len(caCert)).
				Str("cert_preview", string(caCert[:minInt(100, len(caCert))])).
				Msg("Successfully read CA certificate")
			
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				transport.TLSClientConfig = &tls.Config{
					RootCAs: caCertPool,
				}
				logging.Info().
					Str("endpoint", endpoint).
					Str("ca_path", caCertPath).
					Msg("Successfully configured S3 client with custom CA")
			} else {
				logging.Error().
					Str("ca_path", caCertPath).
					Int("cert_size", len(caCert)).
					Msg("Failed to parse CA certificate - invalid PEM format")
			}
		}
	} else {
		if caCertPath == "" {
			logging.Debug().Msg("No CA cert path provided - using system CA store")
		}
		if !strings.HasPrefix(endpoint, "https://") {
			logging.Debug().Msg("HTTP endpoint - no CA certificate needed")
		}
	}
	
	return &Client{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

// ForwardRequest forwards an HTTP request to the S3 backend
func (c *Client) ForwardRequest(method, path string, body io.Reader, headers http.Header, queryString []byte) (*http.Response, error) {
	// Always use the configured endpoint for the actual request
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
	
	// CRITICAL: For AWS chunked encoding, preserve the original Content-Length header
	// Go's HTTP client might reset this to 0 for streaming bodies, breaking AWS signatures
	if originalContentLength := headers.Get("Content-Length"); originalContentLength != "" {
		req.Header.Set("Content-Length", originalContentLength)
		// Set ContentLength field to prevent Go from overriding
		if length, parseErr := strconv.ParseInt(originalContentLength, 10, 64); parseErr == nil {
			req.ContentLength = length
		}
	}
	
	// For HTTP backend with HTTPS frontend, ensure MinIO receives correct signature context
	// Remove any forwarded proto headers that might confuse MinIO's signature validation
	req.Header.Del("X-Forwarded-Proto")
	req.Header.Del("X-Forwarded-Scheme")
	req.Header.Del("X-Scheme")
	
	// Keep KMS headers unchanged since they're part of the signed headers
	// Any modification would break AWS signature validation

	// Debug logging for signature-sensitive headers
	// Use case-insensitive lookup since we preserve exact header case
	getHeaderCaseInsensitive := func(headerName string) string {
		for k, v := range req.Header {
			if strings.EqualFold(k, headerName) && len(v) > 0 {
				return v[0]
			}
		}
		return ""
	}
	
	logging.Debug().
		Str("method", method).
		Str("url", fullURL).
		Str("final_host", req.Host).
		Str("authorization", getHeaderCaseInsensitive("Authorization")).
		Str("date", getHeaderCaseInsensitive("Date")).
		Str("x-amz-date", getHeaderCaseInsensitive("X-Amz-Date")).
		Str("x-amz-content-sha256", getHeaderCaseInsensitive("X-Amz-Content-Sha256")).
		Msg("Forwarding request to S3 with headers")
	
	// Dump all headers being sent to MinIO
	logging.Debug().
		Interface("all_headers", req.Header).
		Str("request_uri", req.URL.RequestURI()).
		Str("raw_query", req.URL.RawQuery).
		Msg("Complete request dump to MinIO")

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
		if strings.EqualFold(key, "host") {
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

		// CRITICAL: Use direct header map assignment to preserve exact case
		// Go's Header.Set() canonicalizes header names, breaking AWS signatures
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header[key] = []string{value}
	}

	// CRITICAL: Preserve the original Host header for signature validation
	// The client signed the request with the external host (s3.r2-int.dev)
	// MinIO must receive the same Host header that was used during signature calculation
	if originalHost != "" {
		req.Host = originalHost
		req.Header["Host"] = []string{originalHost}
		logging.Debug().
			Str("host", originalHost).
			Str("endpoint", c.endpoint).
			Msg("Preserved original Host header for AWS signature validation")
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
		// Note: X-Forwarded-Proto and related headers are handled explicitly in ForwardRequest
		"Cf-Visitor",
		"X-Forwarded-Host",
		"X-Forwarded-Port",
		"X-Forwarded-For",
		"X-Real-Ip",
		"X-Request-Id",
		"Cf-Connecting-Ip",
		"Cf-Ipcountry", 
		"Cf-Ray",
		"Cdn-Loop",
	}

	for _, hopHeader := range hopByHopHeaders {
		if strings.EqualFold(header, hopHeader) {
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
