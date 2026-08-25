// Package blob is content-addressed object storage over S3/MinIO.
//
// Two invariants shape this package:
//
//  1. RAW ARTIFACTS ARE IMMUTABLE (CLAUDE.md invariant 10). Scanner output is
//     written once and never mutated or deleted, because re-normalization
//     replays it months later and a report has to remain defensible. So the
//     API has Put and Get, and no Overwrite.
//
//  2. WE DO NOT EXTRACT. This package stores and retrieves bytes. Nothing here
//     opens an archive, follows a symlink or decompresses anything — that is
//     untrusted-input handling and belongs in the Phase 5 sandbox. Keeping the
//     capability out of the storage layer means an accidental extraction has
//     nowhere to hide.
package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/axebom/axebom/libs/go-shared/platform/config"
)

// ErrNotFound is returned when an object does not exist.
var ErrNotFound = errors.New("object not found")

// Object describes a stored object.
type Object struct {
	// Key is the object key within the bucket.
	Key string
	// SHA256 is the hex digest of the content, computed while streaming.
	SHA256 string
	// Size is the byte count actually written.
	Size int64
}

// Store is object storage.
type Store struct {
	client *minio.Client
	bucket string
}

// Open connects to the object store.
func Open(ctx context.Context, cfg config.S3) (*Store, error) {
	endpoint, secure, err := parseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds: credentials.NewStaticV4(
			cfg.AccessKey.Reveal(), cfg.SecretKey.Reveal(), ""),
		Secure: secure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("object store: %w", err)
	}

	s := &Store{client: client, bucket: cfg.Bucket}

	// Verify the bucket at startup rather than on first upload: a missing
	// bucket should stop a deploy, not surface as a failed upload after a user
	// has waited through a 200 MB transfer.
	ok, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("object store: checking bucket %q: %w", cfg.Bucket, err)
	}
	if !ok {
		return nil, fmt.Errorf("object store: bucket %q does not exist", cfg.Bucket)
	}
	return s, nil
}

// parseEndpoint splits a URL into the host:port and TLS flag minio-go wants.
func parseEndpoint(raw string) (host string, secure bool, err error) {
	if raw == "" {
		return "", false, errors.New("object store: no endpoint configured")
	}
	if !strings.Contains(raw, "://") {
		// A bare host:port. Assume TLS — guessing wrong in this direction
		// fails loudly at connect time, whereas assuming plaintext would
		// silently send credentials in the clear.
		return raw, true, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("object store: bad endpoint %q: %w", raw, err)
	}
	return u.Host, u.Scheme == "https", nil
}

// Ping reports whether the store is reachable, for readiness checks.
func (s *Store) Ping(ctx context.Context) error {
	_, err := s.client.BucketExists(ctx, s.bucket)
	return err
}

// PutOptions configures an upload.
type PutOptions struct {
	// ContentType is stored as metadata. It is NOT trusted for anything: a
	// client-declared type says nothing about the bytes.
	ContentType string
	// MaxBytes caps the upload. Zero means DefaultMaxBytes.
	MaxBytes int64
}

// DefaultMaxBytes bounds an upload when the caller does not.
//
// A cap is not optional. Without one a single request can fill the object store
// and take down every tenant — the cheapest denial of service in the product.
const DefaultMaxBytes = 512 << 20 // 512 MiB

// ErrTooLarge is returned when an upload exceeds its cap.
var ErrTooLarge = errors.New("upload exceeds the maximum allowed size")

// Put streams r into the store, hashing as it goes.
//
// The hash is computed from the bytes ACTUALLY WRITTEN, never supplied by the
// caller. A client-provided digest would let a caller claim any hash for any
// content, which defeats content addressing and every integrity check built on
// it later.
func (s *Store) Put(ctx context.Context, key string, r io.Reader, opts PutOptions) (Object, error) {
	if err := validateKey(key); err != nil {
		return Object{}, err
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	// LimitReader with ONE EXTRA BYTE: reading exactly maxBytes cannot
	// distinguish "exactly at the limit" from "truncated here", and silently
	// storing a truncated archive is worse than refusing it.
	limited := io.LimitReader(r, maxBytes+1)
	hasher := sha256.New()
	counter := &countingReader{r: io.TeeReader(limited, hasher)}

	contentType := opts.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Size -1 makes minio-go stream in multipart chunks without buffering the
	// whole object in memory. A 200 MB upload must not cost 200 MB of heap.
	info, err := s.client.PutObject(ctx, s.bucket, key, counter, -1,
		minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return Object{}, fmt.Errorf("put %q: %w", key, err)
	}

	if counter.n > maxBytes {
		// The oversized object is already partly written, so remove it. A
		// rejected upload must not leave a billable, unreferenced object.
		_ = s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
		return Object{}, fmt.Errorf("%w: limit is %d bytes", ErrTooLarge, maxBytes)
	}

	return Object{
		Key:    key,
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
		Size:   info.Size,
	}, nil
}

// Get opens an object for reading. The caller must close it.
func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get %q: %w", key, err)
	}
	// GetObject is lazy — it returns no error for a missing key until the
	// first read. Stat now so the caller learns immediately.
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("stat %q: %w", key, err)
	}
	return obj, nil
}

// PresignedGet returns a time-limited download URL.
//
// Used for report downloads so large files stream from object storage rather
// than through the API. The expiry is short by design: a presigned URL is a
// bearer credential, and it lands in browser history and Referer headers.
func (s *Store) PresignedGet(ctx context.Context, key string, ttl time.Duration) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	if ttl <= 0 || ttl > time.Hour {
		ttl = 15 * time.Minute
	}
	u, err := s.client.PresignedGetObject(ctx, s.bucket, key, ttl, url.Values{})
	if err != nil {
		return "", fmt.Errorf("presign %q: %w", key, err)
	}
	return u.String(), nil
}

// validateKey rejects keys that could escape their intended prefix.
//
// Object keys are constructed from tenant and project ids, so a separator
// sequence here means something upstream is building a key from user input.
// S3 has no directories, but ".." in a key still breaks the prefix-based
// isolation every listing and lifecycle rule depends on.
func validateKey(key string) error {
	switch {
	case key == "":
		return errors.New("blob: empty key")
	case strings.HasPrefix(key, "/"):
		return fmt.Errorf("blob: key %q must be relative", key)
	case strings.Contains(key, ".."):
		return fmt.Errorf("blob: key %q contains a parent-directory reference", key)
	case strings.ContainsAny(key, "\x00\n\r"):
		return errors.New("blob: key contains a control character")
	case len(key) > 1024:
		return errors.New("blob: key exceeds 1024 bytes")
	}
	return nil
}

// countingReader counts bytes read, so an over-limit upload is detectable after
// streaming without buffering it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
