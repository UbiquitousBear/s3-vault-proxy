package mocks

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/stretchr/testify/mock"
)

// S3Client is a mock implementation of s3.Interface
type S3Client struct {
	mock.Mock
	responses map[string]*http.Response
}

// ForwardRequest mocks the ForwardRequest method
func (m *S3Client) ForwardRequest(method, path string, body io.Reader, headers http.Header, queryString []byte) (*http.Response, error) {
	args := m.Called(method, path, body, headers, queryString)
	return args.Get(0).(*http.Response), args.Error(1)
}

// HeadObject mocks the HeadObject method
func (m *S3Client) HeadObject(bucket, key string, headers http.Header) (*http.Response, error) {
	args := m.Called(bucket, key, headers)
	return args.Get(0).(*http.Response), args.Error(1)
}

// NewMockS3Client creates a new mock S3 client
func NewMockS3Client() *S3Client {
	return &S3Client{
		responses: make(map[string]*http.Response),
	}
}

// SetResponse configures a mock response for a specific method and path
func (m *S3Client) SetResponse(method, path string, statusCode int, body string, headers map[string]string) {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
	
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	
	key := method + " " + path
	m.responses[key] = resp
	
	// Set up the mock expectation
	m.On("ForwardRequest", method, path, mock.Anything, mock.Anything, mock.Anything).Return(resp, nil)
}

// SetHeadResponse configures a mock response for HEAD requests
func (m *S3Client) SetHeadResponse(bucket, key string, statusCode int, headers map[string]string) {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}
	
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	
	m.On("HeadObject", bucket, key, mock.Anything).Return(resp, nil)
}

// CreateMockServer creates an httptest.Server for integration testing
func CreateMockServer(responses map[string]MockResponse) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		if resp, exists := responses[key]; exists {
			w.WriteHeader(resp.StatusCode)
			for k, v := range resp.Headers {
				w.Header().Set(k, v)
			}
			w.Write([]byte(resp.Body))
		} else {
			w.WriteHeader(404)
			w.Write([]byte("Not found"))
		}
	}))
}

// MockResponse represents a mock HTTP response
type MockResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}