package host

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

// Host self-update over the host session. A host cannot read the rollout
// bucket or publish proofs, so its follower (AgentConfig.FollowRollouts)
// sends the "rollout" operation: its signed health proof and its root step
// agent's newest reply in, its pending leader-signed step out. It spools the
// step for the node's root step agent (the self-update watchdog) and
// fetches the release it names in chunks with "rollout-binary". The
// authority leader's RolloutSink does the rest; the step agent verifies
// every byte before it acts.

var errRolloutDisabled = errors.New("orchestrator rollouts are not enabled on this controller")

// RolloutExchange is a host's side of one "rollout" operation.
type RolloutExchange struct {
	// Proof is the agent's signed rolloutexec.HealthProof.
	Proof []byte `json:"proof"`
	// Reply is the root step agent's newest reply, as it wrote it.
	Reply []byte `json:"reply,omitempty"`
	// Held says a restart hold (RestartHoldSuffix) is set on the host: the
	// leader moves it only once the operator removed it.
	Held bool `json:"held,omitzero"`
}

// RolloutStep is the leader's answer: the host's pending signed step.
type RolloutStep struct {
	Step []byte `json:"step,omitempty"`
}

// RolloutBinaryQuery asks for one chunk of a release binary.
type RolloutBinaryQuery struct {
	Digest string `json:"digest"`
	Offset int64  `json:"offset"`
}

// RolloutChunk is one chunk of a release binary of Size bytes.
type RolloutChunk struct {
	Data []byte `json:"data"`
	Size int64  `json:"size"`
}

// RolloutSink serves hosts the cell's orchestrator rollout on the authority
// leader. host is the authenticated registration of the requesting host.
type RolloutSink interface {
	Exchange(ctx context.Context, host Registration, exchange RolloutExchange) (RolloutStep, error)
	// Binary returns at most limit bytes of the release binary with digest
	// from offset.
	Binary(ctx context.Context, digest string, offset int64, limit int) (RolloutChunk, error)
}

// SetRolloutSink enables the "rollout" and "rollout-binary" host
// operations; nil disables them again.
func (c *Controller) SetRolloutSink(sink RolloutSink) {
	if sink == nil {
		c.rolloutSink.Store(nil)
		return
	}
	c.rolloutSink.Store(&sink)
}

func (c *Controller) serveRollout(ctx context.Context, req request, r Registration) (any, error) {
	sink := c.rolloutSink.Load()
	if sink == nil {
		return nil, errRolloutDisabled
	}
	if req.Operation == "rollout-binary" {
		var query RolloutBinaryQuery
		if err := decodeStrict(req.Payload, &query); err != nil {
			return nil, err
		}
		if validateDigest(query.Digest) != nil || query.Offset < 0 {
			return nil, errors.New("rollout binary query is invalid")
		}
		return (*sink).Binary(ctx, query.Digest, query.Offset, artifactChunkBytes)
	}
	var exchange RolloutExchange
	if err := decodeStrict(req.Payload, &exchange); err != nil {
		return nil, err
	}
	return (*sink).Exchange(ctx, r, exchange)
}

// RolloutSession is the agent's side of the rollout operations, which the
// follower in AgentConfig.FollowRollouts drives.
type RolloutSession interface {
	// RolloutExchange sends one "rollout" exchange to the leader.
	RolloutExchange(ctx context.Context, exchange RolloutExchange) (RolloutStep, error)
	// FetchRelease copies the release binary with digest from the leader to
	// dst in chunks; the caller checks the bytes against the digest.
	FetchRelease(ctx context.Context, digest string, dst io.Writer) error
	// SessionLost reports a lost controller session; the follower stops.
	SessionLost() bool
}

// RolloutExchange implements RolloutSession.
func (a *Agent) RolloutExchange(ctx context.Context, exchange RolloutExchange) (RolloutStep, error) {
	var step RolloutStep
	err := a.request(ctx, "rollout", exchange, &step)
	return step, err
}

// FetchRelease implements RolloutSession.
func (a *Agent) FetchRelease(ctx context.Context, digest string, dst io.Writer) error {
	return readRelease(digest, func(offset int64) (RolloutChunk, error) {
		var chunk RolloutChunk
		err := a.request(ctx, "rollout-binary", RolloutBinaryQuery{Digest: digest, Offset: offset}, &chunk)
		return chunk, err
	}, dst)
}

// SessionLost implements RolloutSession.
func (a *Agent) SessionLost() bool { return a.sessionLost.Load() }

// readRelease copies a release from consecutive chunks, refusing one that
// does not continue the release it started.
func readRelease(digest string, chunk func(offset int64) (RolloutChunk, error), dst io.Writer) error {
	size := int64(-1)
	for offset := int64(0); ; {
		next, err := chunk(offset)
		if err != nil {
			return err
		}
		if next.Size <= 0 || next.Size > selfupdate.MaxBinaryBytes || size >= 0 && next.Size != size ||
			len(next.Data) == 0 || len(next.Data) > artifactChunkBytes || offset+int64(len(next.Data)) > next.Size {
			return fmt.Errorf("release %s chunk at %d is invalid", digest, offset)
		}
		size = next.Size
		if _, err := dst.Write(next.Data); err != nil {
			return err
		}
		if offset += int64(len(next.Data)); offset == size {
			return nil
		}
	}
}
