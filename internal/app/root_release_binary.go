package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootrelease"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func rootReleaseNotFound(err error) bool {
	service, ok := common.IsServiceError(err)
	return ok && service.GetHTTPStatusCode() == 404
}

func bytesReaderCloser(wire []byte) io.ReadCloser { return io.NopCloser(bytes.NewReader(wire)) }

func (o *rootReleaseObservation) readStatusBack(ctx context.Context, location releasechannel.Location, name string, expected []byte) error {
	response, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{NamespaceName: new(location.Namespace), BucketName: new(location.Bucket), ObjectName: new(name)})
	if err != nil {
		return err
	}
	if response.Content == nil {
		return rootrelease.ErrPending
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, releasechannel.MaxValueBytes+1))
	if err != nil || !bytes.Equal(wire, expected) {
		return errors.Join(rootrelease.ErrPending, err)
	}
	return nil
}

func (b *rootReleaseChannels) ReleaseBinaryChunk(ctx context.Context, call rootoci.Call, request rootoci.ReleaseBinaryChunkRequest) (rootoci.ReleaseBinaryChunk, error) {
	ctx, cancel, o, err := b.beginChannel(ctx, call, rootoci.OperationReleaseBinaryChunk)
	defer cancel()
	if err != nil {
		return rootoci.ReleaseBinaryChunk{}, err
	}
	if len(request.Digest) != 64 || !lowerHexString(request.Digest) || request.Offset < 0 {
		return rootoci.ReleaseBinaryChunk{}, rootoci.ErrInvalid
	}
	history, err := o.rollouts.Retained(ctx)
	if err != nil {
		return rootoci.ReleaseBinaryChunk{}, err
	}
	var size int64
	for _, retained := range history {
		if retained.Digest != request.Digest {
			continue
		}
		if err := o.verifyRetained(retained); err != nil {
			return rootoci.ReleaseBinaryChunk{}, err
		}
		binary, err := o.retainedBinary(retained)
		if err != nil {
			return rootoci.ReleaseBinaryChunk{}, err
		}
		size = binary.Bytes
		break
	}
	if size <= 0 {
		return rootoci.ReleaseBinaryChunk{}, rootrelease.ErrPending
	}
	location, err := o.location(ctx)
	if err != nil {
		return rootoci.ReleaseBinaryChunk{}, err
	}
	return o.binaryChunk(ctx, location, releasechannel.BinaryPrefix+request.Digest, request.Digest, size, request.Offset)
}

func (o *rootReleaseObservation) binaryChunk(ctx context.Context, location releasechannel.Location, name, digest string, size, offset int64) (rootoci.ReleaseBinaryChunk, error) {
	if size <= 0 || size > releasechannel.MaxServiceBinaryBytes || offset < 0 || offset > size {
		return rootoci.ReleaseBinaryChunk{}, rootoci.ErrInvalid
	}
	if err := o.guard(ctx); err != nil {
		return rootoci.ReleaseBinaryChunk{}, err
	}
	result := rootoci.ReleaseBinaryChunk{Size: size, Digest: digest, ExpiresAt: o.deadline}
	if offset == size {
		return result, o.guard(ctx)
	}
	count := min(int64(rootoci.ReleaseBinaryChunkBytes), size-offset)
	response, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{NamespaceName: new(location.Namespace), BucketName: new(location.Bucket), ObjectName: new(name), Range: new(fmt.Sprintf("bytes=%d-%d", offset, offset+count-1))})
	if err != nil {
		return rootoci.ReleaseBinaryChunk{}, err
	}
	if response.Content == nil {
		return rootoci.ReleaseBinaryChunk{}, rootrelease.ErrPending
	}
	defer response.Content.Close()
	if response.ContentLength == nil || *response.ContentLength != count || response.ContentRange == nil || *response.ContentRange != fmt.Sprintf("bytes %d-%d/%d", offset, offset+count-1, size) {
		return rootoci.ReleaseBinaryChunk{}, rootoci.ErrInvalid
	}
	result.Data, err = io.ReadAll(io.LimitReader(response.Content, count+1))
	if err != nil || int64(len(result.Data)) != count {
		return rootoci.ReleaseBinaryChunk{}, errors.Join(rootrelease.ErrPending, err)
	}
	if !time.Now().Before(o.deadline) {
		return rootoci.ReleaseBinaryChunk{}, rootrelease.ErrPending
	}
	if err := o.guard(ctx); err != nil {
		return rootoci.ReleaseBinaryChunk{}, err
	}
	return result, nil
}
