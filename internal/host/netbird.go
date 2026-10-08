package host

import (
	"context"
	"errors"
	"io"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

// NetBirdSink uses the existing authenticated host session; hosts get no KV
// write grant or arbitrary artifact access for managing their network agent.
type NetBirdSink interface {
	Exchange(context.Context, Registration, network.Status) ([]byte, error)
	BinaryAllowed(string) bool
}

type NetBirdStep struct {
	Step []byte `json:"step,omitempty"`
}

func (c *Controller) SetNetBirdSink(sink NetBirdSink) {
	if sink == nil {
		c.netbirdSink.Store(nil)
	} else {
		c.netbirdSink.Store(&sink)
	}
}

func (c *Controller) serveNetBird(ctx context.Context, req request, registration Registration) (any, error) {
	sink := c.netbirdSink.Load()
	if sink == nil {
		return nil, errors.New("NetBird management is not enabled")
	}
	if req.Operation == "netbird-binary" {
		var query RolloutBinaryQuery
		if err := decodeStrict(req.Payload, &query); err != nil {
			return nil, err
		}
		if validateDigest(query.Digest) != nil || query.Offset < 0 || !(*sink).BinaryAllowed(query.Digest) {
			return nil, errors.New("NetBird artifact does not match the cell pin")
		}
		data, size, err := c.readCachedArtifact(ctx, &c.netbirdCache, client.MaxBinaryBytes, query.Digest, query.Offset, artifactChunkBytes)
		return RolloutChunk{Data: data, Size: size}, err
	}
	var status network.Status
	if len(req.Payload) > 4096 {
		return nil, errors.New("NetBird status exceeds limit")
	}
	if err := decodeStrict(req.Payload, &status); err != nil {
		return nil, err
	}
	step, err := (*sink).Exchange(ctx, registration, status)
	return NetBirdStep{Step: step}, err
}

type NetBirdSession interface {
	NetBirdExchange(context.Context, network.Status) (NetBirdStep, error)
	FetchNetBirdBinary(context.Context, string, io.Writer) error
	SessionLost() bool
}

func (a *Agent) NetBirdExchange(ctx context.Context, status network.Status) (NetBirdStep, error) {
	var step NetBirdStep
	err := a.request(ctx, "netbird", status, &step)
	return step, err
}

func (a *Agent) FetchNetBirdBinary(ctx context.Context, digest string, dst io.Writer) error {
	return readRelease(digest, func(offset int64) (RolloutChunk, error) {
		var chunk RolloutChunk
		err := a.request(ctx, "netbird-binary", RolloutBinaryQuery{Digest: digest, Offset: offset}, &chunk)
		return chunk, err
	}, dst)
}
