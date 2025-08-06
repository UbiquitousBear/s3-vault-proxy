package mocks

import (
	"net/http"

	"s3-vault-proxy/pkg/types"

	"github.com/stretchr/testify/mock"
)

// MetadataService is a mock implementation of metadata.Interface
type MetadataService struct {
	mock.Mock
	storage map[string]*types.ObjectMetadata
}

// Store mocks the Store method
func (m *MetadataService) Store(bucket, key string, metadata *types.ObjectMetadata, headers http.Header) error {
	args := m.Called(bucket, key, metadata, headers)
	
	// Store in memory for later retrieval
	if m.storage == nil {
		m.storage = make(map[string]*types.ObjectMetadata)
	}
	storageKey := bucket + "/" + key
	m.storage[storageKey] = metadata
	
	return args.Error(0)
}

// Get mocks the Get method
func (m *MetadataService) Get(bucket, key string, headers http.Header) (*types.ObjectMetadata, error) {
	args := m.Called(bucket, key, headers)
	
	// Try to return stored metadata first
	if m.storage != nil {
		storageKey := bucket + "/" + key
		if metadata, exists := m.storage[storageKey]; exists {
			return metadata, args.Error(1)
		}
	}
	
	return args.Get(0).(*types.ObjectMetadata), args.Error(1)
}

// Exists mocks the Exists method
func (m *MetadataService) Exists(bucket, key string, headers http.Header) bool {
	args := m.Called(bucket, key, headers)
	return args.Bool(0)
}

// NewMockMetadataService creates a new mock metadata service
func NewMockMetadataService() *MetadataService {
	m := &MetadataService{
		storage: make(map[string]*types.ObjectMetadata),
	}
	
	// Set up default behaviors
	m.On("Store", mock.Anything, mock.Anything, 
		mock.Anything, mock.Anything).Return(nil)
		
	m.On("Exists", mock.Anything, mock.Anything, 
		mock.Anything).Return(true)
	
	return m
}