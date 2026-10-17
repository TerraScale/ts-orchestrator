package host

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

type RuntimeReadinessObserver interface {
	ObserveRuntimeReadiness(context.Context, ContainerReadinessChallenge, *Controller) (protocol.Envelope, error)
}

type containerReadinessObservation struct {
	Request protocol.Envelope `json:"request"`
}

func (c *Controller) serveObserveContainerReadiness(ctx context.Context, req request) (any, error) {
	var challenge ContainerReadinessChallenge
	if err := decodeStrict(req.Payload, &challenge); err != nil {
		return nil, err
	}
	if !lowerHex(challenge.Nonce, 32) || !time.Now().Before(challenge.Deadline) || challenge.Deadline.After(time.Now().Add(3*time.Second)) {
		return nil, errors.New("readiness observation challenge is invalid")
	}
	observer, ok := c.runtimeEffects.(RuntimeReadinessObserver)
	if !ok {
		return nil, errors.New("live runtime readiness source is unavailable")
	}
	ctx, cancel := context.WithDeadline(ctx, challenge.Deadline)
	defer cancel()
	envelope, err := observer.ObserveRuntimeReadiness(ctx, challenge, c)
	if err != nil {
		return nil, err
	}
	return containerReadinessObservation{Request: envelope}, nil
}

// ObserveContainerReadiness relays bytes only. The root reader admits the original
// target signature independently; a signed controller reply is not readiness.
func (a *Agent) ObserveContainerReadiness(ctx context.Context, challenge ContainerReadinessChallenge) (protocol.Envelope, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || !time.Now().Before(challenge.Deadline) {
		return protocol.Envelope{}, errors.New("readiness relay deadline expired")
	}
	ctx, cancel := context.WithDeadline(ctx, challenge.Deadline)
	defer cancel()
	var observation containerReadinessObservation
	err := a.request(ctx, "runtime-readiness-observe", challenge, &observation)
	return observation.Request, err
}
