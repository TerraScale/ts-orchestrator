package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// MaxAcceptedInstallBytes bounds a published accepted-install marker.
const MaxAcceptedInstallBytes = 128 << 10

// PublishAcceptedInstall stores a controller's canonical accepted-install
// marker once, beside its slot HEAD. The marker holds only public identities
// and digests; publishing it lets the offline root sign install continuity
// without access to the controller. A retry succeeds only for identical bytes.
func (ledger *Ledger) PublishAcceptedInstall(ctx context.Context, scope BootstrapScope, marker []byte) error {
	if err := validateLedgerScope(scope); err != nil {
		return err
	}
	if len(marker) == 0 || len(marker) > MaxAcceptedInstallBytes {
		return fmt.Errorf("%w: accepted-install marker is empty or oversized", ErrInvalidRecord)
	}
	name := ledger.acceptedInstallObjectName(scope)
	if existing, err := ledger.readObjectLimit(ctx, ledger.config.HeadBucket, name, MaxAcceptedInstallBytes); err == nil {
		if !bytes.Equal(existing.Bytes, marker) {
			return fmt.Errorf("%w: a different accepted-install marker is already published", ErrRecordAuthorization)
		}
		return nil
	} else if !errors.Is(err, ErrRecordMissing) {
		return err
	}
	length := int64(len(marker))
	digest := sha256.Sum256(marker)
	digestHeader := base64.StdEncoding.EncodeToString(digest[:])
	_, putErr := ledger.client.PutObject(ctx, objectstorage.PutObjectRequest{
		NamespaceName:        new(ledger.config.Namespace),
		BucketName:           new(ledger.config.HeadBucket),
		ObjectName:           new(name),
		PutObjectBody:        io.NopCloser(bytes.NewReader(marker)),
		ContentLength:        &length,
		ContentType:          new("application/json"),
		OpcSseKmsKeyId:       new(ledger.config.HeadKMSKeyID),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
		OpcContentSha256:     &digestHeader,
		IfNoneMatch:          new("*"),
	})
	if putErr != nil && !shouldReadAfterPutError(putErr) {
		return fmt.Errorf("publish accepted-install marker: %w", putErr)
	}
	stored, err := ledger.readObjectLimit(ctx, ledger.config.HeadBucket, name, MaxAcceptedInstallBytes)
	if err != nil {
		return fmt.Errorf("%w: publish accepted-install marker: %v; exact-key read: %w", ErrOutcomeUnknown, putErr, err)
	}
	if !bytes.Equal(stored.Bytes, marker) {
		return fmt.Errorf("%w: published accepted-install marker differs", ErrRecordAuthorization)
	}
	return nil
}

// ReadAcceptedInstall returns the marker a controller published for its slot.
func (ledger *Ledger) ReadAcceptedInstall(ctx context.Context, scope BootstrapScope) ([]byte, error) {
	if err := validateLedgerScope(scope); err != nil {
		return nil, err
	}
	stored, err := ledger.readObjectLimit(ctx, ledger.config.HeadBucket, ledger.acceptedInstallObjectName(scope), MaxAcceptedInstallBytes)
	if err != nil {
		return nil, err
	}
	if len(stored.Bytes) > MaxAcceptedInstallBytes {
		return nil, ErrInvalidRecord
	}
	return stored.Bytes, nil
}

func (ledger *Ledger) acceptedInstallObjectName(scope BootstrapScope) string {
	return strings.TrimSuffix(ledger.headObjectName(scope), "head.json") + "accepted-install.json"
}
