package app

import (
	"context"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// The first MainPID admission owns this immutable startup lifetime, including
// failed TLS attempts. Neither reconnects nor ownhost sessions can renew it.
type rootBrokerStartup struct {
	ctx      context.Context
	cancel   context.CancelFunc
	process  *rootOCIProcess
	current  bootstrapstart.RuntimeAuthority
	deadline time.Time
}

func (authority *rootOCIAuthority) readBrokerOrigin(ctx context.Context) (bootstrapstart.RuntimeAuthority, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || authority.ctx.Err() != nil || authority.parent.Verify() != nil || authority.verifyMarker() != nil || authority.verifyBinary(authority.parent) != nil {
		return bootstrapstart.RuntimeAuthority{}, rootoci.ErrUnauthorized
	}
	source := authority.ownhost
	source.mu.RLock()
	defer source.mu.RUnlock()
	return source.reader.ReadRuntimeAuthority(ctx, authority.accepted, time.Now().UTC())
}

func (broker *rootBrokerRuntime) guard(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || broker.ctx.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	deadline := broker.origin.ExpiresAt()
	broker.authority.mu.Lock()
	sources := broker.authority.sources
	if sources != nil {
		deadline = earlier(deadline, sources.deadline)
	}
	broker.authority.mu.Unlock()
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if bootstrapstart.VerifyAcceptedLocalIdentity(broker.authority.accepted, controllerIdentityObserver(broker.cfg)) != nil {
		return rootoci.ErrUnauthorized
	}
	current, err := broker.authority.readBrokerOrigin(ctx)
	if err != nil || !reflect.DeepEqual(current, broker.origin) {
		return rootoci.ErrUnauthorized
	}
	broker.authority.mu.Lock()
	defer broker.authority.mu.Unlock()
	if sources = broker.authority.sources; sources != nil {
		ctx, cancel := context.WithDeadline(ctx, sources.deadline)
		defer cancel()
		if err := sources.guard(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (broker *rootBrokerRuntime) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline := broker.origin.ExpiresAt()
	broker.authority.mu.Lock()
	if sources := broker.authority.sources; sources != nil {
		deadline = earlier(deadline, sources.deadline)
	}
	broker.authority.mu.Unlock()
	operation, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(broker.ctx, cancel)
	return operation, func() { stop(); cancel() }
}

func (authority *rootOCIAuthority) admitBrokerStartup(ctx context.Context, peer nativerootoci.Peer) (*rootBrokerStartup, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || authority.ctx.Err() != nil || peer.UID != authority.uid || peer.GID != authority.gid {
		return nil, rootoci.ErrUnauthorized
	}
	probe, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	deadline, _ := probe.Deadline()
	if authority.main != nil && authority.main.witness.Peer() == peer {
		deadline = earlier(deadline, authority.main.startupEnd)
	}
	if authority.sources != nil {
		deadline = earlier(deadline, authority.sources.deadline)
	}
	probe, cancelKnown := context.WithDeadline(probe, deadline)
	defer cancelKnown()
	process, err := authority.currentProcess(probe, peer)
	if err != nil || process == authority.child || process.brokerStartup != nil {
		return nil, rootoci.ErrUnauthorized
	}
	probe, cancelStartup := context.WithDeadline(probe, process.startupEnd)
	defer cancelStartup()
	if probe.Err() != nil || authority.verifyMarker() != nil || authority.verifyBinary(process.witness) != nil || authority.verifyProcess(probe, process) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	source := authority.ownhost
	source.mu.RLock()
	defer source.mu.RUnlock()
	current, err := source.reader.ReadRuntimeAuthority(probe, authority.accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	deadline = earlier(process.startupEnd, current.ExpiresAt())
	if authority.sources != nil {
		deadline = earlier(deadline, authority.sources.deadline)
	}
	if !time.Now().Before(deadline) {
		return nil, rootoci.ErrUnauthorized
	}
	lease, cancelLease := context.WithDeadline(process.ctx, deadline)
	startup := &rootBrokerStartup{ctx: lease, cancel: cancelLease, process: process, current: current, deadline: deadline}
	// Install before TLS or any downstream wait: an unsuccessful first attempt
	// consumes this process's only private transport admission.
	process.brokerStartup = startup
	return startup, nil
}

func (authority *rootOCIAuthority) verifyBrokerStartup(ctx context.Context, startup *rootBrokerStartup) error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.verifyBrokerStartupLocked(ctx, startup)
}

func (authority *rootOCIAuthority) verifyBrokerStartupLocked(ctx context.Context, startup *rootBrokerStartup) error {
	if ctx == nil || ctx.Err() != nil || startup == nil || startup.ctx.Err() != nil || authority.ctx.Err() != nil ||
		authority.main != startup.process || startup.process.brokerStartup != startup {
		return rootoci.ErrUnauthorized
	}
	deadline := startup.deadline
	if authority.sources != nil {
		deadline = earlier(deadline, authority.sources.deadline)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if ctx.Err() != nil || authority.verifyMarker() != nil || authority.verifyBinary(startup.process.witness) != nil || authority.verifyProcess(ctx, startup.process) != nil {
		return rootoci.ErrUnauthorized
	}
	source := authority.ownhost
	source.mu.RLock()
	defer source.mu.RUnlock()
	fresh, err := source.reader.ReadRuntimeAuthority(ctx, authority.accepted, time.Now().UTC())
	if err != nil || !reflect.DeepEqual(fresh, startup.current) {
		return rootoci.ErrUnauthorized
	}
	if authority.sources != nil {
		if !time.Now().Before(authority.sources.deadline) {
			return rootoci.ErrUnauthorized
		}
		if err := authority.sources.guard(ctx); err != nil {
			return err
		}
	}
	if ctx.Err() != nil || startup.ctx.Err() != nil || startup.process.witness.Verify() != nil {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func (authority *rootOCIAuthority) brokerObservationLease(ctx context.Context, peer nativerootoci.Peer) (rootoci.Lease, error) {
	authority.mu.Lock()
	process := authority.main
	if process != nil && process.witness.Peer() == peer && peer.UID == authority.uid && peer.GID == authority.gid && process.brokerStartup != nil && process.brokerStartup.ctx.Err() == nil {
		startup := process.brokerStartup
		err := authority.verifyBrokerStartupLocked(ctx, startup)
		if err != nil {
			startup.cancel()
			authority.mu.Unlock()
			return rootoci.Lease{}, err
		}
		deadline := startup.deadline
		if authority.sources != nil {
			deadline = earlier(deadline, authority.sources.deadline)
		}
		authority.mu.Unlock()
		return rootoci.Lease{Context: startup.ctx, Deadline: deadline, Binding: process.witness.Binding() + ":broker-startup"}, nil
	}
	authority.mu.Unlock()
	return authority.authorizeRuntime(ctx, peer)
}
