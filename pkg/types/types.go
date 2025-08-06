package types

import (
	"encoding/xml"
	"time"
)

// S3Time is a custom time type that marshals to S3-compatible XML format
type S3Time time.Time

func (t S3Time) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(time.Time(t).UTC().Format("2006-01-02T15:04:05.000Z"), start)
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
	Name         string `xml:"Name"`
	CreationDate S3Time `xml:"CreationDate"`
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
	Key          string `xml:"Key"`
	LastModified S3Time `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type ErrorResponse struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

// ObjectMetadata represents metadata stored alongside encrypted objects
type ObjectMetadata struct {
	ContentLength int64             `json:"content_length"`
	ContentType   string            `json:"content_type"`
	ETag          string            `json:"etag"`
	LastModified  string            `json:"last_modified"`
	KMSKeyARN     string            `json:"kms_key_arn"`
	CustomMeta    map[string]string `json:"custom_meta,omitempty"`
}