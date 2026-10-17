// Package artifact verifies content-addressed NATS object-store bytes without
// creating a JetStream consumer.
package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"

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
	if err := validateMetadata(info, bucket, name, signedSize); err != nil {
		return err
	}
	stream, err := js.Stream(ctx, "OBJ_"+bucket)
	if err != nil {
		return fmt.Errorf("bind artifact readback stream: %w", err)
	}
	return verifyChunks(ctx, info, bucket, digest, signedSize, dst, func(ctx context.Context, sequence uint64, subject string) (*jetstream.RawStreamMsg, error) {
		return stream.GetMsg(ctx, sequence, jetstream.WithGetMsgSubject(subject))
	})
}

// ReadVerifiedAuthoritative verifies captured leader metadata using standard
// MSG.GET chunk reads, so a stale replica cannot authorize corruption repair.
// Callers must discard dst if this function returns an error.
func ReadVerifiedAuthoritative(ctx context.Context, js jetstream.JetStream, info *jetstream.ObjectInfo,
	bucket, name, digest string, signedSize, maxBytes int64, dst io.Writer,
) error {
	if js == nil || js.Conn() == nil || dst == nil || signedSize <= 0 || signedSize > maxBytes || len(digest) != 64 {
		return fmt.Errorf("%w: reader arguments", ErrInvalid)
	}
	if err := validateMetadata(info, bucket, name, signedSize); err != nil {
		return err
	}
	options := js.Options()
	prefix := options.APIPrefix
	if options.Domain != "" {
		prefix = "$JS." + options.Domain + ".API."
	} else if prefix == "" {
		prefix = jetstream.DefaultAPIPrefix
	}
	apiSubject := strings.TrimSuffix(prefix, ".") + ".STREAM.MSG.GET.OBJ_" + bucket
	if _, bounded := ctx.Deadline(); !bounded && options.DefaultTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.DefaultTimeout)
		defer cancel()
	}
	return verifyChunks(ctx, info, bucket, digest, signedSize, dst, func(ctx context.Context, sequence uint64, subject string) (*jetstream.RawStreamMsg, error) {
		request, err := json.Marshal(struct {
			Sequence uint64 `json:"seq"`
			Subject  string `json:"next_by_subj"`
		}{sequence, subject})
		if err != nil {
			return nil, err
		}
		message, err := js.Conn().RequestWithContext(ctx, apiSubject, request)
		if err != nil {
			return nil, err
		}
		var response struct {
			Error   *jetstream.APIError `json:"error"`
			Message *struct {
				Subject  string `json:"subject"`
				Sequence uint64 `json:"seq"`
				Data     []byte `json:"data"`
			} `json:"message"`
		}
		if err := json.Unmarshal(message.Data, &response); err != nil {
			return nil, err
		}
		if response.Error != nil {
			return nil, response.Error
		}
		if response.Message == nil {
			return nil, jetstream.ErrInvalidJetStreamResponse
		}
		return &jetstream.RawStreamMsg{Subject: response.Message.Subject, Sequence: response.Message.Sequence,
			Data: response.Message.Data}, nil
	})
}

func validateMetadata(info *jetstream.ObjectInfo, bucket, name string, signedSize int64) error {
	if info == nil || info.Name != name || info.Bucket != bucket || info.Deleted ||
		info.Opts != nil && info.Opts.Link != nil || info.Size != uint64(signedSize) ||
		info.NUID == "" || info.Chunks == 0 || uint64(info.Chunks) > uint64(signedSize) {
		return fmt.Errorf("%w: artifact object metadata", ErrInvalid)
	}
	return nil
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
