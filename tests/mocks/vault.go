package mocks

import (
	"encoding/base64"
	"fmt"

	"github.com/stretchr/testify/mock"
)

// VaultClient is a mock implementation of vault.Interface
type VaultClient struct {
	mock.Mock
}

// Encrypt mocks the Encrypt method
func (m *VaultClient) Encrypt(data []byte, transitKey string) (string, error) {
	args := m.Called(data, transitKey)
	return args.String(0), args.Error(1)
}

// Decrypt mocks the Decrypt method
func (m *VaultClient) Decrypt(ciphertext string, transitKey string) ([]byte, error) {
	args := m.Called(ciphertext, transitKey)
	return args.Get(0).([]byte), args.Error(1)
}

// ARNToVaultKey mocks the ARNToVaultKey method
func (m *VaultClient) ARNToVaultKey(arn string) (string, error) {
	args := m.Called(arn)
	return args.String(0), args.Error(1)
}

// Address mocks the Address method
func (m *VaultClient) Address() string {
	args := m.Called()
	return args.String(0)
}

// HealthCheck mocks the HealthCheck method
func (m *VaultClient) HealthCheck() error {
	args := m.Called()
	return args.Error(0)
}

// NewMockVaultClient creates a new mock Vault client with default behaviors
func NewMockVaultClient() *VaultClient {
	m := &VaultClient{}
	
	// Set up default successful behaviors
	m.On("Address").Return("http://localhost:8200")
	m.On("HealthCheck").Return(nil)
	
	// Default ARN conversion
	m.On("ARNToVaultKey", mock.Anything).Return("test-vault-key", nil)
	
	// Default encryption
	m.On("Encrypt", mock.Anything, mock.Anything).Return(
		func(data []byte, key string) string {
			// Mock encryption: just base64 encode with a prefix
			encoded := base64.StdEncoding.EncodeToString(data)
			return fmt.Sprintf("vault:v1:mock-%s", encoded)
		},
		nil,
	)
	
	// Default decryption
	m.On("Decrypt", mock.Anything, mock.Anything).Return(
		func(ciphertext string, key string) []byte {
			// Mock decryption: extract base64 from mock format
			if len(ciphertext) > 14 && ciphertext[:14] == "vault:v1:mock-" {
				encoded := ciphertext[14:]
				if data, err := base64.StdEncoding.DecodeString(encoded); err == nil {
					return data
				}
			}
			return []byte("decrypted-data")
		},
		nil,
	)
	
	return m
}