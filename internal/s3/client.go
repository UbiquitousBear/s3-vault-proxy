package s3

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
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
	// Check if this was originally an HTTPS request from Cloudflare headers
	originalScheme := "http"
	if cfVisitor := headers.Get("Cf-Visitor"); cfVisitor != "" {
		if strings.Contains(cfVisitor, `"scheme":"https"`) {
			originalScheme = "https"
		}
	} else if xForwardedProto := headers.Get("X-Forwarded-Proto"); xForwardedProto == "https" {
		originalScheme = "https"
	}
	
	// Build URL with original scheme for AWS signature compatibility
	var fullURL string
	if originalScheme == "https" && strings.HasPrefix(c.endpoint, "http://") {
		// Convert HTTP endpoint to HTTPS if original request was HTTPS
		httpsEndpoint := strings.Replace(c.endpoint, "http://", "https://", 1)
		fullURL = httpsEndpoint + path
		logging.Debug().
			Str("original_endpoint", c.endpoint).
			Str("https_endpoint", httpsEndpoint).
			Str("cf_visitor", headers.Get("Cf-Visitor")).
			Msg("Converted endpoint to HTTPS for signature compatibility")
	} else {
		fullURL = c.endpoint + path
	}
	
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
	
	// Add X-Forwarded-Proto header for HTTPS requests to help MinIO with signature validation
	if strings.HasPrefix(fullURL, "https://") {
		req.Header.Set("X-Forwarded-Proto", "https")
		logging.Debug().
			Str("url", fullURL).
			Msg("Added X-Forwarded-Proto: https for MinIO signature validation")
	}

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

	// CRITICAL: Preserve the original Host header for signature validation
	// AWS signatures include the Host header, so MinIO must receive the exact
	// same Host header that was used during signature calculation
	if originalHost != "" {
		req.Host = originalHost
		req.Header.Set("Host", originalHost)
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
		// Strip proxy headers that confuse MinIO about scheme
		"X-Forwarded-Proto",
		"X-Forwarded-Scheme", 
		"X-Scheme",
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
