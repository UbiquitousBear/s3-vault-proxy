package types

import (
	"encoding/json"
	"encoding/xml"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestS3Time_MarshalXML(t *testing.T) {
	testTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	s3Time := S3Time(testTime)

	type testStruct struct {
		XMLName xml.Name `xml:"Test"`
		Time    S3Time   `xml:"CreationDate"`
	}

	test := testStruct{
		Time: s3Time,
	}

	data, err := xml.Marshal(test)
	assert.NoError(t, err)

	expected := `<Test><CreationDate>2023-01-01T12:00:00.000Z</CreationDate></Test>`
	assert.Equal(t, expected, string(data))
}

func TestS3Time_Conversion(t *testing.T) {
	testTime := time.Date(2023, 6, 15, 14, 30, 45, 123456789, time.UTC)
	s3Time := S3Time(testTime)

	// Test conversion back to time.Time
	converted := time.Time(s3Time)
	assert.Equal(t, testTime, converted)
}

func TestListBucketsResult_XML(t *testing.T) {
	result := ListBucketsResult{
		Owner: Owner{
			ID:          "owner-id",
			DisplayName: "owner-name",
		},
		Buckets: Buckets{
			Bucket: []Bucket{
				{
					Name:         "test-bucket",
					CreationDate: S3Time(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				},
			},
		},
	}

	data, err := xml.Marshal(result)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "ListAllMyBucketsResult")
	assert.Contains(t, string(data), "test-bucket")
	assert.Contains(t, string(data), "2023-01-01T00:00:00.000Z")
}

func TestListBucketResult_XML(t *testing.T) {
	result := ListBucketResult{
		Name:        "test-bucket",
		Prefix:      "test/",
		MaxKeys:     1000,
		IsTruncated: false,
		Contents: []Content{
			{
				Key:          "test/file.txt",
				LastModified: S3Time(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
				ETag:         `"abcd1234"`,
				Size:         1024,
				StorageClass: "STANDARD",
			},
		},
	}

	data, err := xml.Marshal(result)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "ListBucketResult")
	assert.Contains(t, string(data), "test/file.txt")
	assert.Contains(t, string(data), "2023-01-01T12:00:00.000Z")
}

func TestErrorResponse_XML(t *testing.T) {
	errResp := ErrorResponse{
		Code:    "NoSuchKey",
		Message: "The specified key does not exist",
	}

	data, err := xml.Marshal(errResp)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "Error")
	assert.Contains(t, string(data), "NoSuchKey")
	assert.Contains(t, string(data), "The specified key does not exist")
}

func TestObjectMetadata_JSON(t *testing.T) {
	metadata := ObjectMetadata{
		ContentLength: 1024,
		ContentType:   "text/plain",
		ETag:          `"abcd1234"`,
		LastModified:  "Mon, 02 Jan 2006 15:04:05 GMT",
		KMSKeyARN:     "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		CustomMeta: map[string]string{
			"custom-key": "custom-value",
		},
	}

	// Test JSON marshaling (not XML, since ObjectMetadata is used for JSON storage)
	data, err := json.Marshal(metadata)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Test JSON unmarshaling
	var unmarshaled ObjectMetadata
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, metadata.ContentLength, unmarshaled.ContentLength)
	assert.Equal(t, metadata.ContentType, unmarshaled.ContentType)
	assert.Equal(t, metadata.KMSKeyARN, unmarshaled.KMSKeyARN)
	assert.Equal(t, metadata.CustomMeta["custom-key"], unmarshaled.CustomMeta["custom-key"])
}