package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func (s *channelSource) readChannel(ctx context.Context) (releasechannel.Channel, bool, error) {
	if s.client != nil {
		observation, err := s.client.ReleaseChannel(ctx)
		return observation.Channel, observation.Found, err
	}
	location, err := s.get(ctx)
	if err != nil {
		return releasechannel.Channel{}, false, err
	}
	return releasechannel.ReadChannel(ctx, location)
}

func (s *channelSource) readNativeClaim(ctx context.Context, role string) ([]byte, bool, error) {
	if s.client != nil {
		observation, err := s.client.NativeRelease(ctx, rootoci.NativeReleaseRequest{Role: role})
		if err != nil {
			return nil, false, err
		}
		if !time.Now().Before(observation.ExpiresAt) || observation.Found && (len(observation.Claim) > releasechannel.MaxServiceClaimBytes || controllerSHA256(observation.Claim) != observation.ClaimSHA256) {
			return nil, false, rootoci.ErrUnauthorized
		}
		return observation.Claim, observation.Found, nil
	}
	location, err := s.get(ctx)
	if err != nil {
		return nil, false, err
	}
	return releasechannel.ReadServiceClaim(ctx, location, role)
}

func (s *channelSource) readBinary(ctx context.Context, digest string, dst io.Writer) error {
	if s.client != nil {
		return copyRootRelease(ctx, digest, dst, func(ctx context.Context, offset int64) (rootoci.ReleaseBinaryChunk, error) {
			return s.client.ReleaseBinaryChunk(ctx, rootoci.ReleaseBinaryChunkRequest{Digest: digest, Offset: offset})
		})
	}
	location, err := s.get(ctx)
	if err != nil {
		return err
	}
	return releasechannel.ReadBinary(ctx, location, digest, dst)
}

func (s *channelSource) readNativeBinary(ctx context.Context, role, digest string, claim []byte, dst io.Writer) error {
	if s.client != nil {
		return copyRootRelease(ctx, digest, dst, func(ctx context.Context, offset int64) (rootoci.ReleaseBinaryChunk, error) {
			return s.client.NativeReleaseBinaryChunk(ctx, rootoci.NativeReleaseBinaryChunkRequest{Role: role, ExpectedClaimSHA256: controllerSHA256(claim), Offset: offset})
		})
	}
	location, err := s.get(ctx)
	if err != nil {
		return err
	}
	return releasechannel.ReadServiceBinary(ctx, location, role, digest, dst)
}

func copyRootRelease(ctx context.Context, digest string, dst io.Writer, read func(context.Context, int64) (rootoci.ReleaseBinaryChunk, error)) error {
	hash := sha256.New()
	var offset, size int64
	for {
		chunk, err := read(ctx, offset)
		if err != nil {
			return err
		}
		if offset == 0 {
			size = chunk.Size
		}
		if !time.Now().Before(chunk.ExpiresAt) || chunk.Digest != digest || size <= 0 || size > releasechannel.MaxServiceBinaryBytes || chunk.Size != size || len(chunk.Data) == 0 || len(chunk.Data) > rootoci.ReleaseBinaryChunkBytes || int64(len(chunk.Data)) > size-offset {
			return rootoci.ErrUnauthorized
		}
		if _, err := io.MultiWriter(dst, hash).Write(chunk.Data); err != nil {
			return err
		}
		offset += int64(len(chunk.Data))
		if offset == size {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return errors.New("root release bytes differ from the signed digest")
	}
	return nil
}
