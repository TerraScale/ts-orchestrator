package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// statefulReleaseReader consumes finite operation-bound root reads. It never
// receives an OCI principal, SDK client, caller-selected bucket or object key.
type statefulReleaseReader struct {
	client     *rootoci.Client
	deliveries *delivery.Service
}

func (reader statefulReleaseReader) claim(ctx context.Context, operationID string, read func(context.Context, string) (delivery.Intent, error)) (release.ContainerBundle, string, error) {
	if reader.client == nil || reader.deliveries == nil {
		return release.ContainerBundle{}, "", execution.ErrUnsafe
	}
	intent, err := read(ctx, operationID)
	if err != nil {
		return release.ContainerBundle{}, "", err
	}
	if intent.Container == nil || intent.Role != "terrabase" {
		return release.ContainerBundle{}, "", execution.ErrUnsafe
	}
	envelope, err := trust.DecodeEnvelope(intent.Container.Claim)
	if err != nil {
		return release.ContainerBundle{}, "", err
	}
	fingerprint, err := trust.Fingerprint(envelope)
	return *intent.Container, fingerprint, err
}

func (reader statefulReleaseReader) evidence(ctx context.Context, operationID, digest string) (io.ReadCloser, error) {
	return reader.readEvidence(ctx, operationID, digest, reader.deliveries.ContainerIntent, reader.client.ContainerEvidence)
}

func (reader statefulReleaseReader) retainedEvidence(ctx context.Context, operationID, digest string) (io.ReadCloser, error) {
	return reader.readEvidence(ctx, operationID, digest, reader.deliveries.RetainedContainerIntent, func(ctx context.Context, request rootoci.ContainerEvidenceRequest) (rootoci.ContainerEvidenceChunk, error) {
		chunk, err := reader.client.RetainedContainerEvidence(ctx, rootoci.RetainedContainerEvidenceRequest(request))
		return rootoci.ContainerEvidenceChunk(chunk), err
	})
}

func (reader statefulReleaseReader) readEvidence(ctx context.Context, operationID, digest string, intent func(context.Context, string) (delivery.Intent, error), read func(context.Context, rootoci.ContainerEvidenceRequest) (rootoci.ContainerEvidenceChunk, error)) (io.ReadCloser, error) {
	_, fingerprint, err := reader.claim(ctx, operationID, intent)
	if err != nil {
		return nil, err
	}
	var data []byte
	var total int64
	var expires time.Time
	for {
		readCtx, finish := ctx, func() {}
		if !expires.IsZero() {
			readCtx, finish = context.WithDeadline(ctx, expires)
		}
		chunk, err := read(readCtx, rootoci.ContainerEvidenceRequest{
			OperationID: operationID, ExpectedFingerprint: fingerprint, EvidenceSHA256: digest, Offset: int64(len(data)),
		})
		finish()
		if err != nil {
			return nil, err
		}
		if chunk.OperationID != operationID || chunk.Fingerprint != fingerprint || chunk.EvidenceSHA256 != digest || chunk.Offset != int64(len(data)) ||
			chunk.TotalBytes < 1 || chunk.TotalBytes > release.MaxProductionEvidenceBytes || len(chunk.Data) < 1 || len(chunk.Data) > rootoci.ContainerEvidenceChunkBytes ||
			int64(len(data))+int64(len(chunk.Data)) > chunk.TotalBytes || !time.Now().Before(chunk.ExpiresAt) || total != 0 && chunk.TotalBytes != total {
			return nil, execution.ErrUnsafe
		}
		if expires.IsZero() || chunk.ExpiresAt.Before(expires) {
			expires = chunk.ExpiresAt
		}
		if !time.Now().Before(expires) {
			return nil, execution.ErrUnsafe
		}
		total = chunk.TotalBytes
		data = append(data, chunk.Data...)
		if int64(len(data)) == total {
			break
		}
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, execution.ErrUnsafe
	}
	return &statefulMaterialBytes{Reader: bytes.NewReader(data), ctx: ctx, expires: expires}, nil
}

func (reader statefulReleaseReader) allocations(ctx context.Context, operationID string, requested release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget) (release.SequenceLocation, error) {
	return reader.readAllocation(ctx, operationID, requested, roots, target, reader.deliveries.ContainerIntent, reader.client.ContainerAllocation)
}

func (reader statefulReleaseReader) retainedAllocations(ctx context.Context, operationID string, requested release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget) (release.SequenceLocation, error) {
	return reader.readAllocation(ctx, operationID, requested, roots, target, reader.deliveries.RetainedContainerIntent, func(ctx context.Context, request rootoci.ContainerAllocationRequest) (rootoci.ContainerAllocationObservation, error) {
		observed, err := reader.client.RetainedContainerAllocation(ctx, rootoci.RetainedContainerAllocationRequest(request))
		return rootoci.ContainerAllocationObservation(observed), err
	})
}

func (reader statefulReleaseReader) readAllocation(ctx context.Context, operationID string, requested release.ContainerBundle, roots trust.Keyring, target release.ContainerTarget, intent func(context.Context, string) (delivery.Intent, error), read func(context.Context, rootoci.ContainerAllocationRequest) (rootoci.ContainerAllocationObservation, error)) (release.SequenceLocation, error) {
	bundle, fingerprint, err := reader.claim(ctx, operationID, intent)
	if err != nil {
		return release.SequenceLocation{}, err
	}
	if !slices.Equal(bundle.Claim, requested.Claim) || !slices.Equal(bundle.Migration, requested.Migration) || !slices.Equal(bundle.Sequence, requested.Sequence) {
		return release.SequenceLocation{}, execution.ErrUnsafe
	}
	envelope, err := trust.DecodeEnvelope(bundle.Migration)
	if err != nil {
		return release.SequenceLocation{}, err
	}
	migration, err := release.VerifySequenceMigrationHistorical(envelope, roots, target.Role, target.Environment)
	if err != nil {
		return release.SequenceLocation{}, err
	}
	observed, err := read(ctx, rootoci.ContainerAllocationRequest{OperationID: operationID, ExpectedFingerprint: fingerprint})
	if err != nil {
		return release.SequenceLocation{}, err
	}
	if observed.OperationID != operationID || observed.Fingerprint != fingerprint || observed.Namespace != migration.Namespace || observed.Bucket != migration.Bucket ||
		observed.ObjectName == "" || len(observed.Data) == 0 || len(observed.Data) > trust.MaxPayloadBytes || !time.Now().Before(observed.ExpiresAt) {
		return release.SequenceLocation{}, execution.ErrUnsafe
	}
	return release.SequenceLocation{Client: statefulAllocationObject{observation: observed, ctx: ctx}, Namespace: observed.Namespace, Bucket: observed.Bucket}, nil
}

type statefulAllocationObject struct {
	observation rootoci.ContainerAllocationObservation
	ctx         context.Context
}

func (reader statefulAllocationObject) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	observed := reader.observation
	if ctx == nil || ctx.Err() != nil || reader.ctx == nil || reader.ctx.Err() != nil || request.NamespaceName == nil || *request.NamespaceName != observed.Namespace || request.BucketName == nil ||
		*request.BucketName != observed.Bucket || request.ObjectName == nil || *request.ObjectName != observed.ObjectName || request.Range != nil ||
		request.VersionId != nil || !time.Now().Before(observed.ExpiresAt) {
		return objectstorage.GetObjectResponse{}, execution.ErrUnsafe
	}
	return objectstorage.GetObjectResponse{Content: &statefulMaterialBytes{Reader: bytes.NewReader(observed.Data), ctx: ctx, source: reader.ctx, expires: observed.ExpiresAt}, ContentLength: new(int64(len(observed.Data)))}, nil
}

func (statefulAllocationObject) PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	return objectstorage.PutObjectResponse{}, errors.New("stateful allocation verification cannot write reservations")
}

type statefulMaterialBytes struct {
	*bytes.Reader
	ctx     context.Context
	source  context.Context
	expires time.Time
}

func (reader *statefulMaterialBytes) Read(data []byte) (int, error) {
	if reader.source != nil {
		if err := reader.source.Err(); err != nil {
			return 0, err
		}
	}
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	if !time.Now().Before(reader.expires) {
		return 0, execution.ErrUnsafe
	}
	return reader.Reader.Read(data)
}

func (*statefulMaterialBytes) Close() error { return nil }
