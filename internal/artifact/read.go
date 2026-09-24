// Package artifact verifies content-addressed NATS object-store bytes without
// creating a JetStream consumer.
package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/nats-io/nats.go/jetstream"
)

var ErrInvalid = errors.New("invalid artifact")

// ReadVerified fetches the exact chunk sequence described by object metadata,
// checks both the object digest and signed content digest, and writes to dst.
// Callers must discard dst if this function returns an error.
func ReadVerified(ctx context.Context, js jetstream.JetStream, store interface {
	GetInfo(context.Context, string, ...jetstream.GetObjectInfoOpt) (*jetstream.ObjectInfo, error)
}, bucket, name, digest string, signedSize, maxBytes int64, dst io.Writer) error {
	if js == nil || store == nil || dst == nil || signedSize <= 0 || signedSize > maxBytes || len(digest) != 64 {
		return fmt.Errorf("%w: reader arguments", ErrInvalid)
	}
	info, err := store.GetInfo(ctx, name)
	if err != nil {
		return fmt.Errorf("inspect artifact: %w", err)
	}
	if info == nil || info.Name != name || info.Bucket != bucket || info.Deleted ||
		info.Opts != nil && info.Opts.Link != nil || info.Size != uint64(signedSize) ||
		info.NUID == "" || info.Chunks == 0 || uint64(info.Chunks) > uint64(signedSize) {
		return fmt.Errorf("%w: artifact object metadata", ErrInvalid)
	}
	stream, err := js.Stream(ctx, "OBJ_"+bucket)
	if err != nil {
		return fmt.Errorf("bind artifact readback stream: %w", err)
	}
	return verifyChunks(ctx, info, bucket, digest, signedSize, dst, func(ctx context.Context, sequence uint64, subject string) (*jetstream.RawStreamMsg, error) {
		return stream.GetMsg(ctx, sequence, jetstream.WithGetMsgSubject(subject))
	})
}

func verifyChunks(ctx context.Context, info *jetstream.ObjectInfo, bucket, digest string, sizeLimit int64, dst io.Writer,
	get func(context.Context, uint64, string) (*jetstream.RawStreamMsg, error)) error {
	if info == nil || info.NUID == "" || info.Chunks == 0 || sizeLimit <= 0 ||
		uint64(info.Chunks) > uint64(sizeLimit) {
		return fmt.Errorf("%w: artifact chunk metadata", ErrInvalid)
	}
	storedDigest, err := jetstream.DecodeObjectDigest(info.Digest)
	if err != nil || len(storedDigest) != sha256.Size {
		return fmt.Errorf("%w: artifact object digest", ErrInvalid)
	}
	subject := "$O." + bucket + ".C." + info.NUID
	h := sha256.New()
	var size int64
	sequence := uint64(1)
	for range info.Chunks {
		if err := ctx.Err(); err != nil {
			return err
		}
		message, err := get(ctx, sequence, subject)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			return fmt.Errorf("artifact chunk is not visible: %w", jetstream.ErrObjectNotFound)
		}
		if err != nil {
			return fmt.Errorf("read artifact chunk: %w", err)
		}
		if message == nil || message.Subject != subject || message.Sequence < sequence ||
			message.Sequence == ^uint64(0) || len(message.Data) == 0 || int64(len(message.Data)) > sizeLimit-size {
			return fmt.Errorf("%w: artifact chunk sequence or size", ErrInvalid)
		}
		if _, err := dst.Write(message.Data); err != nil {
			return fmt.Errorf("spool artifact chunk: %w", err)
		}
		_, _ = h.Write(message.Data)
		size += int64(len(message.Data))
		sequence = message.Sequence + 1
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	extra, err := get(ctx, sequence, subject)
	if err == nil || extra != nil {
		return fmt.Errorf("%w: artifact has extra chunks", ErrInvalid)
	}
	if !errors.Is(err, jetstream.ErrMsgNotFound) {
		return fmt.Errorf("check artifact chunk count: %w", err)
	}
	actual := h.Sum(nil)
	if size != sizeLimit || hex.EncodeToString(actual) != digest || !bytes.Equal(actual, storedDigest) {
		return fmt.Errorf("%w: artifact bytes differ from signed digest", ErrInvalid)
	}
	return nil
}
