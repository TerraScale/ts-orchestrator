package host

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type rolloutSinkFake struct {
	host     Registration
	exchange RolloutExchange
	digest   string
	offset   int64
}

func (f *rolloutSinkFake) Exchange(_ context.Context, host Registration, exchange RolloutExchange) (RolloutStep, error) {
	f.host, f.exchange = host, exchange
	return RolloutStep{Step: []byte("signed step")}, nil
}

func (f *rolloutSinkFake) Binary(_ context.Context, digest string, offset int64, limit int) (RolloutChunk, error) {
	f.digest, f.offset = digest, offset
	return RolloutChunk{Data: bytes.Repeat([]byte{1}, min(limit, 10)), Size: 10}, nil
}

// The rollout operations reach the leader's sink only on an authenticated
// session, with the registration of the host that sent them.
func TestRolloutOperationsReachTheSinkWithTheHostsRegistration(t *testing.T) {
	c, hostKey, s, _ := reportedTestHost(t)
	exchange := RolloutExchange{Proof: []byte("proof"), Reply: []byte(`{"unit":"node-a"}`)}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "rollout", s.SessionID, s.Epoch, exchange)); !errors.Is(err, errRolloutDisabled) {
		t.Fatalf("rollout accepted without a sink: %v", err)
	}
	sink := &rolloutSinkFake{}
	c.SetRolloutSink(sink)
	payload, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "rollout", s.SessionID, s.Epoch, exchange))
	if err != nil {
		t.Fatal(err)
	}
	if step, ok := payload.(RolloutStep); !ok || string(step.Step) != "signed step" || sink.host.Node != "node-a" ||
		string(sink.exchange.Proof) != "proof" {
		t.Fatalf("payload %#v, sink saw %+v", payload, sink)
	}
	digest := strings.Repeat("a", 64)
	payload, err = c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "rollout-binary", s.SessionID, s.Epoch,
		RolloutBinaryQuery{Digest: digest, Offset: 4}))
	if chunk, ok := payload.(RolloutChunk); err != nil || !ok || chunk.Size != 10 || sink.digest != digest || sink.offset != 4 {
		t.Fatalf("binary chunk = %#v %v", payload, err)
	}
	for _, query := range []RolloutBinaryQuery{{Digest: "not-a-digest"}, {Digest: digest, Offset: -1}} {
		if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "rollout-binary", s.SessionID, s.Epoch, query)); err == nil {
			t.Fatalf("binary query %+v accepted", query)
		}
	}
}

// A host assembles a release only from chunks that continue it.
func TestReadReleaseRefusesChunksThatDoNotContinueTheRelease(t *testing.T) {
	release := bytes.Repeat([]byte("orchestrator"), 3)
	serve := func(edit func(offset int64, chunk *RolloutChunk)) func(int64) (RolloutChunk, error) {
		return func(offset int64) (RolloutChunk, error) {
			chunk := RolloutChunk{Data: release[offset:min(offset+10, int64(len(release)))], Size: int64(len(release))}
			if edit != nil {
				edit(offset, &chunk)
			}
			return chunk, nil
		}
	}
	var got bytes.Buffer
	if err := readRelease("d", serve(nil), &got); err != nil || !bytes.Equal(got.Bytes(), release) {
		t.Fatalf("release = %q %v", got.Bytes(), err)
	}
	for name, edit := range map[string]func(int64, *RolloutChunk){
		"size changes":    func(offset int64, chunk *RolloutChunk) { chunk.Size += offset },
		"empty chunk":     func(_ int64, chunk *RolloutChunk) { chunk.Data = nil },
		"past the size":   func(_ int64, chunk *RolloutChunk) { chunk.Size = 5 },
		"oversized chunk": func(_ int64, chunk *RolloutChunk) { chunk.Data = make([]byte, artifactChunkBytes+1) },
	} {
		if err := readRelease("d", serve(edit), &bytes.Buffer{}); err == nil {
			t.Errorf("%s: release accepted", name)
		}
	}
}
