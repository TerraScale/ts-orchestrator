// Package bootstrap stores immutable, pre-NATS controller bootstrap records.
package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const (
	maxLedgerRecordBytes = 64 << 10
	maxRetryAge          = 23 * time.Hour
)

var (
	ErrRecordMissing      = errors.New("bootstrap ledger record is missing")
	ErrIntentMissing      = errors.New("bootstrap ledger intent is missing")
	ErrImmutableConflict  = errors.New("bootstrap ledger key contains a different immutable record")
	ErrOutcomeUnknown     = errors.New("bootstrap ledger write outcome is unknown")
	ErrIntentDigest       = errors.New("bootstrap ledger result does not match its intent")
	ErrRetryWindowExpired = errors.New("bootstrap ledger intent retry window has expired")
	ErrInvalidRetryClock  = errors.New("bootstrap ledger retry clock metadata is missing or inconsistent")

	ledgerIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	ledgerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,255}$`)
)

// ObjectStorageClient is the only OCI capability needed by the ledger.
// Production callers must supply a client pinned to the manifest-authorized
// region and private KMS-encrypted bucket.
type ObjectStorageClient interface {
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
}

type objectStorageServiceError interface {
	error
	common.ServiceError
}

// LedgerConfig pins the namespace, private bucket, KMS key, and manifest-owned
// prefix. Bucket ACL and key policy remain deployment responsibilities.
type LedgerConfig struct {
	Namespace       string
	Bucket          string
	KMSKeyID        string
	Prefix          string
	HeadBucket      string
	HeadKMSKeyID    string
	Environment     string
	TrustRoots      trust.Keyring
	Delegations     []trust.VerifiedDelegation
	TrustPolicy     trust.Policy
	VerificationNow func() time.Time
}

// BootstrapScope is the stable identity for one controller slot. A manifest
// digest deliberately does not participate in the object key: rotating a
// manifest cannot authorize a second launch for the same slot.
type BootstrapScope struct {
	DeploymentID string
	Cell         string
	Slot         string
}

// StoredRecord carries exact immutable source bytes and provider metadata.
// LastModified is the server timestamp of the original create; ServerDate is
// the OCI server clock observed during the exact-key read.
type StoredRecord struct {
	Bytes        []byte
	SHA256       string
	ETag         string
	LastModified time.Time
	ServerDate   time.Time
	Created      bool
}

// Ledger reads and creates exact-name intent and result objects. It exposes no
// list, raw object key, delete, or overwrite operation.
type Ledger struct {
	client    ObjectStorageClient
	config    LedgerConfig
	maxRecord int
}

// NewLedger validates the fixed storage scope. The caller provisions and
// authorizes the private KMS bucket before constructing the ledger.
func NewLedger(client ObjectStorageClient, config LedgerConfig) (*Ledger, error) {
	if client == nil || !ledgerIDPattern.MatchString(config.Namespace) ||
		!ledgerNamePattern.MatchString(config.Bucket) || !strings.HasPrefix(config.KMSKeyID, "ocid1.key.") ||
		len(config.KMSKeyID) > 255 || strings.ContainsAny(config.KMSKeyID, " \t\r\n") || !validLedgerPrefix(config.Prefix) ||
		!ledgerNamePattern.MatchString(config.HeadBucket) || config.HeadBucket == config.Bucket ||
		!strings.HasPrefix(config.HeadKMSKeyID, "ocid1.key.") || len(config.HeadKMSKeyID) > 255 ||
		strings.ContainsAny(config.HeadKMSKeyID, " \t\r\n") ||
		!ledgerIDPattern.MatchString(config.Environment) || config.TrustPolicy.MaxLifetime <= 0 || config.TrustPolicy.ClockSkew < 0 ||
		len(config.TrustRoots) == 0 && len(config.Delegations) == 0 {
		return nil, errors.New("bootstrap ledger requires separate immutable and coordination buckets, KMS keys, environment, trust policy, and a valid Object Storage client")
	}
	roots := make(trust.Keyring, len(config.TrustRoots))
	for keyID, key := range config.TrustRoots {
		roots[keyID] = bytes.Clone(key)
	}
	config.TrustRoots = roots
	config.Delegations = slices.Clone(config.Delegations)
	if config.VerificationNow == nil {
		config.VerificationNow = time.Now
	}
	return &Ledger{client: client, config: config, maxRecord: maxLedgerRecordBytes}, nil
}

// CheckRetryWindow compares OCI's current server clock to the original
// object's Last-Modified time. Missing or inconsistent clock metadata fails
// closed; callers must hold once the 23-hour OCI create-token window expires.
func CheckRetryWindow(record StoredRecord) error {
	if record.LastModified.IsZero() || record.ServerDate.IsZero() || record.ServerDate.Before(record.LastModified) {
		return ErrInvalidRetryClock
	}
	if record.ServerDate.Sub(record.LastModified) >= maxRetryAge {
		return ErrRetryWindowExpired
	}
	return nil
}

type ledgerRecordKind string

const (
	ledgerIntent      ledgerRecordKind = "intent"
	ledgerResult      ledgerRecordKind = "result"
	ledgerRetirement  ledgerRecordKind = "retirement"
	ledgerSeedReceipt ledgerRecordKind = "seed-receipt"
)

func (ledger *Ledger) createOrRead(ctx context.Context, scope BootstrapScope, attempt uint64, kind ledgerRecordKind, body []byte) (StoredRecord, error) {
	if err := validateLedgerScope(scope); err != nil {
		return StoredRecord{}, err
	}
	if attempt == 0 || len(body) == 0 || len(body) > ledger.maxRecord {
		return StoredRecord{}, errors.New("bootstrap ledger record is empty or exceeds its size bound")
	}
	objectName := ledger.objectName(scope, attempt, kind)
	sourceDigest := sha256.Sum256(body)
	ifNoneMatch := "*"
	digestHeader := base64.StdEncoding.EncodeToString(sourceDigest[:])
	length := int64(len(body))
	response, putErr := ledger.client.PutObject(ctx, objectstorage.PutObjectRequest{
		NamespaceName:        new(ledger.config.Namespace),
		BucketName:           new(ledger.config.Bucket),
		ObjectName:           new(objectName),
		PutObjectBody:        io.NopCloser(bytes.NewReader(body)),
		ContentLength:        &length,
		ContentType:          new("application/json"),
		IfNoneMatch:          &ifNoneMatch,
		OpcSseKmsKeyId:       new(ledger.config.KMSKeyID),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
		OpcContentSha256:     &digestHeader,
	})
	if putErr != nil && !shouldReadAfterPutError(putErr) {
		return StoredRecord{}, fmt.Errorf("create immutable bootstrap %s: %w", kind, putErr)
	}
	stored, readErr := ledger.readObject(ctx, ledger.config.Bucket, objectName)
	if readErr != nil {
		if putErr != nil && errors.Is(readErr, ErrRecordMissing) {
			return StoredRecord{}, fmt.Errorf("%w: create immutable bootstrap %s: %v; exact-key read: %w", ErrOutcomeUnknown, kind, putErr, readErr)
		}
		if putErr == nil {
			return StoredRecord{}, fmt.Errorf("%w: acknowledged bootstrap %s is unavailable on exact-key read: %w", ErrOutcomeUnknown, kind, readErr)
		}
		return StoredRecord{}, fmt.Errorf("%w: create immutable bootstrap %s: %v; exact-key read: %w", ErrOutcomeUnknown, kind, putErr, readErr)
	}
	if !bytes.Equal(stored.Bytes, body) {
		return StoredRecord{}, ErrImmutableConflict
	}
	if putErr == nil && response.ETag != nil && *response.ETag != "" && stored.ETag != *response.ETag {
		return StoredRecord{}, fmt.Errorf("%w: acknowledged ETag differs from exact-key read", ErrImmutableConflict)
	}
	stored.Created = putErr == nil
	return stored, nil
}

func (ledger *Ledger) read(ctx context.Context, scope BootstrapScope, attempt uint64, kind ledgerRecordKind) (StoredRecord, error) {
	if err := validateLedgerScope(scope); err != nil {
		return StoredRecord{}, err
	}
	if attempt == 0 {
		return StoredRecord{}, errors.New("bootstrap ledger attempt must be positive")
	}
	return ledger.readObject(ctx, ledger.config.Bucket, ledger.objectName(scope, attempt, kind))
}

func (ledger *Ledger) readExistingExact(
	ctx context.Context,
	scope BootstrapScope,
	attempt uint64,
	kind ledgerRecordKind,
	body []byte,
) (StoredRecord, bool, error) {
	record, err := ledger.read(ctx, scope, attempt, kind)
	if errors.Is(err, ErrRecordMissing) {
		return StoredRecord{}, false, nil
	}
	if err != nil {
		return StoredRecord{}, false, err
	}
	if !bytes.Equal(record.Bytes, body) {
		return StoredRecord{}, true, ErrImmutableConflict
	}
	return record, true, nil
}

func (ledger *Ledger) readObject(ctx context.Context, bucket, objectName string) (StoredRecord, error) {
	response, err := ledger.client.GetObject(ctx, objectstorage.GetObjectRequest{
		NamespaceName: new(ledger.config.Namespace),
		BucketName:    new(bucket),
		ObjectName:    new(objectName),
	})
	if err != nil {
		if serviceErr, ok := errors.AsType[objectStorageServiceError](err); ok && serviceErr.GetHTTPStatusCode() == http.StatusNotFound {
			return StoredRecord{}, ErrRecordMissing
		}
		return StoredRecord{}, fmt.Errorf("read exact bootstrap object: %w", err)
	}
	if response.Content == nil {
		return StoredRecord{}, errors.New("bootstrap object response has no body")
	}
	if response.ContentLength == nil || *response.ContentLength < 1 || *response.ContentLength > int64(ledger.maxRecord) {
		response.Content.Close()
		return StoredRecord{}, errors.New("bootstrap object has missing or invalid content length")
	}
	body, err := io.ReadAll(io.LimitReader(response.Content, int64(ledger.maxRecord)+1))
	closeErr := response.Content.Close()
	if err := errors.Join(err, closeErr); err != nil {
		return StoredRecord{}, fmt.Errorf("read bootstrap object body: %w", err)
	}
	if len(body) != int(*response.ContentLength) || len(body) > ledger.maxRecord {
		return StoredRecord{}, errors.New("bootstrap object body length does not match its metadata")
	}
	if response.ETag == nil || strings.TrimSpace(*response.ETag) == "" || response.LastModified == nil {
		return StoredRecord{}, errors.New("bootstrap object is missing ETag or Last-Modified metadata")
	}
	if response.RawResponse == nil {
		return StoredRecord{}, errors.New("bootstrap object response is missing server headers")
	}
	serverDate, err := http.ParseTime(response.RawResponse.Header.Get("Date"))
	if err != nil {
		return StoredRecord{}, errors.New("bootstrap object response has a missing or invalid server Date")
	}
	lastModified := response.LastModified.Time.UTC()
	serverDate = serverDate.UTC()
	if lastModified.IsZero() || serverDate.Before(lastModified) {
		return StoredRecord{}, errors.New("bootstrap object server timestamps are inconsistent")
	}
	digest := sha256.Sum256(body)
	return StoredRecord{
		Bytes: body, SHA256: hex.EncodeToString(digest[:]), ETag: *response.ETag,
		LastModified: lastModified, ServerDate: serverDate,
	}, nil
}

func (ledger *Ledger) objectName(scope BootstrapScope, attempt uint64, kind ledgerRecordKind) string {
	identity := sha256.Sum256([]byte(scope.Cell + "\x00controller\x00" + scope.Slot))
	name := "bootstrap/v1/" + scope.DeploymentID + "/" + hex.EncodeToString(identity[:]) +
		fmt.Sprintf("/attempt-%020d/%s.json", attempt, kind)
	if ledger.config.Prefix != "" {
		return ledger.config.Prefix + "/" + name
	}
	return name
}

func validateLedgerScope(scope BootstrapScope) error {
	if !ledgerIDPattern.MatchString(scope.DeploymentID) || !ledgerIDPattern.MatchString(scope.Slot) ||
		(scope.Cell != "GRU" && scope.Cell != "SFO" && scope.Cell != "FRA") {
		return errors.New("bootstrap ledger scope has an invalid deployment, cell, or controller slot")
	}
	return nil
}

func validLedgerPrefix(prefix string) bool {
	if prefix == "" {
		return true
	}
	if len(prefix) > 512 || strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") || strings.Contains(prefix, "//") {
		return false
	}
	for segment := range strings.SplitSeq(prefix, "/") {
		if segment == "." || segment == ".." || !ledgerIDPattern.MatchString(segment) {
			return false
		}
	}
	return true
}

func shouldReadAfterPutError(err error) bool {
	if serviceErr, ok := errors.AsType[objectStorageServiceError](err); ok {
		status := serviceErr.GetHTTPStatusCode()
		return status == http.StatusPreconditionFailed || status == http.StatusRequestTimeout ||
			status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
	}
	return true
}
