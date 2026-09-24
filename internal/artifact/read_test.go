package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
)

func TestVerifyChunksChecksCompleteOrderedContent(t *testing.T) {
	parts := [][]byte{[]byte("first"), []byte("middle"), []byte("last")}
	content := bytes.Join(parts, nil)
	sum := sha256.Sum256(content)
	h := sha256.New()
	_, _ = h.Write(content)
	info := jetstream.ObjectInfo{NUID: "fixtureNUID", Size: uint64(len(content)), Chunks: uint32(len(parts)),
		Digest: jetstream.GetObjectDigestValue(h)}
	size := int64(len(content))
	digest := hex.EncodeToString(sum[:])
	subject := "$O." + "TS_ARTIFACTS" + ".C." + info.NUID
	messages := []jetstream.RawStreamMsg{
		{Subject: subject, Sequence: 2, Data: parts[0]},
		{Subject: subject, Sequence: 5, Data: parts[1]},
		{Subject: subject, Sequence: 9, Data: parts[2]},
	}
	for _, test := range []struct {
		name          string
		change        func(*jetstream.ObjectInfo, *int64, *string, *[]jetstream.RawStreamMsg)
		nonadvancing  bool
		wantError     error
		wantSequences []uint64
	}{
		{name: "multi-chunk object with interleaved stream messages", wantSequences: []uint64{1, 3, 6, 10}},
		{name: "zero-byte object", change: func(i *jetstream.ObjectInfo, r *int64, _ *string, _ *[]jetstream.RawStreamMsg) {
			i.Size, i.Chunks, *r = 0, 0, 0
		}, wantError: ErrInvalid},
		{name: "missing chunk", change: func(_ *jetstream.ObjectInfo, _ *int64, _ *string, msgs *[]jetstream.RawStreamMsg) {
			*msgs = (*msgs)[:2]
		}, wantError: jetstream.ErrObjectNotFound},
		{name: "nonadvancing sequence", nonadvancing: true, wantError: ErrInvalid},
		{name: "oversize chunk", change: func(_ *jetstream.ObjectInfo, _ *int64, _ *string, msgs *[]jetstream.RawStreamMsg) {
			(*msgs)[0].Data = bytes.Repeat([]byte("x"), len(content)+1)
		}, wantError: ErrInvalid},
		{name: "signed digest mismatch", change: func(_ *jetstream.ObjectInfo, _ *int64, r *string, _ *[]jetstream.RawStreamMsg) {
			*r = strings.Repeat("0", 64)
		}, wantError: ErrInvalid},
		{name: "object digest mismatch", change: func(i *jetstream.ObjectInfo, _ *int64, _ *string, _ *[]jetstream.RawStreamMsg) {
			i.Digest = "SHA-256=bad"
		}, wantError: ErrInvalid},
		{name: "extra chunk", change: func(_ *jetstream.ObjectInfo, _ *int64, _ *string, msgs *[]jetstream.RawStreamMsg) {
			*msgs = append(*msgs, jetstream.RawStreamMsg{Subject: subject, Sequence: 11, Data: []byte("extra")})
		}, wantError: ErrInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			objectInfo, expectedSize, expectedDigest := info, size, digest
			stored := slices.Clone(messages)
			if test.change != nil {
				test.change(&objectInfo, &expectedSize, &expectedDigest, &stored)
			}
			var sequences []uint64
			var output bytes.Buffer
			err := verifyChunks(t.Context(), &objectInfo, "TS_ARTIFACTS", expectedDigest, expectedSize, &output,
				func(_ context.Context, sequence uint64, gotSubject string) (*jetstream.RawStreamMsg, error) {
					sequences = append(sequences, sequence)
					if gotSubject != subject {
						t.Fatalf("chunk subject = %q, want %q", gotSubject, subject)
					}
					if test.nonadvancing && sequence > 2 {
						return &stored[0], nil
					}
					index := slices.IndexFunc(stored, func(m jetstream.RawStreamMsg) bool { return m.Sequence >= sequence })
					if index < 0 {
						return nil, jetstream.ErrMsgNotFound
					}
					return &stored[index], nil
				})
			if !errors.Is(err, test.wantError) {
				t.Fatalf("verifyChunks() error = %v, want %v", err, test.wantError)
			}
			if err == nil && !bytes.Equal(output.Bytes(), content) {
				t.Fatalf("verified bytes = %q, want %q", output.Bytes(), content)
			}
			if test.wantSequences != nil && !slices.Equal(sequences, test.wantSequences) {
				t.Fatalf("chunk cursors = %v, want %v", sequences, test.wantSequences)
			}
		})
	}
}
