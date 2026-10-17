package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// This registry never enters root authority: a source child can be launched
// while authorizeProcess already holds the authority lock.
type rootBrokerSourceChildren struct {
	mu       sync.Mutex
	children map[int]*rootBrokerSourceChild
	ctx      context.Context
	cancel   context.CancelFunc
	stopRoot func() bool
	deadline time.Time
	parent   *rootoci.ProcessWitness
	uid, gid uint32
	proxy    *natscell.ControllerProxy
}

type rootBrokerSourceChild struct {
	registry     *rootBrokerSourceChildren
	witness      *rootoci.ProcessWitness
	original     context.Context
	ctx          context.Context
	cancel       context.CancelFunc
	deadline     time.Time
	command      string
	query        []byte
	querySHA256  [sha256.Size]byte
	registration *swarmruntime.WorkerRegistrationQuery
	membership   *hostenroll.WorkerMembershipQuery
}

var _ swarmruntime.SourceChildRegistrar = (*rootBrokerSourceChildren)(nil)

func newRootBrokerSourceChildren(broker *rootBrokerRuntime) (*rootBrokerSourceChildren, error) {
	if broker == nil || broker.ctx == nil || broker.ctx.Err() != nil || broker.authority == nil ||
		broker.authority.ctx == nil || broker.authority.ctx.Err() != nil || broker.authority.uid == 0 || broker.authority.gid == 0 ||
		broker.authority.parent == nil || os.Geteuid() != 0 || os.Getegid() != 0 {
		return nil, rootoci.ErrUnauthorized
	}
	deadline, finite := broker.ctx.Deadline()
	parent := broker.authority.parent
	if !finite || !time.Now().Before(deadline) || parent.Peer().PID != os.Getpid() ||
		parent.Peer().UID != 0 || parent.Peer().GID != 0 || parent.Verify() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	proxy, err := natscell.NewControllerProxy(broker.runtime)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(broker.ctx)
	registry := &rootBrokerSourceChildren{children: make(map[int]*rootBrokerSourceChild), ctx: ctx, cancel: cancel,
		deadline: deadline, parent: parent, uid: broker.authority.uid, gid: broker.authority.gid, proxy: proxy}
	registry.stopRoot = context.AfterFunc(broker.authority.ctx, cancel)
	if err := registry.guardRoot(); err != nil {
		_ = registry.Close()
		return nil, err
	}
	return registry, nil
}

func (registry *rootBrokerSourceChildren) RegisterSourceChild(ctx context.Context, pid int, command string, query []byte) (func(), error) {
	if registry == nil || ctx == nil || ctx.Err() != nil || registry.guardRoot() != nil || pid < 2 || pid == os.Getpid() {
		return nil, rootoci.ErrUnauthorized
	}
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) || deadline.After(time.Now().Add(20*time.Second)) {
		return nil, rootoci.ErrUnauthorized
	}
	query = bytes.Clone(query)
	registration, membership, err := rootBrokerSourceQuery(command, query)
	if err != nil {
		return nil, err
	}
	witness, err := rootoci.CaptureProcess(pid)
	if err != nil {
		return nil, err
	}
	childCtx, cancel := context.WithDeadline(ctx, earlier(deadline, registry.deadline))
	stopRoot := context.AfterFunc(registry.ctx, cancel)
	child := &rootBrokerSourceChild{registry: registry, witness: witness, original: ctx, ctx: childCtx, cancel: cancel,
		deadline: deadline, command: command, query: query, querySHA256: sha256.Sum256(query), registration: registration, membership: membership}
	// Even a failed registration returns cleanup for the launcher to call after Wait.
	release := sync.OnceFunc(func() {
		cancel()
		stopRoot()
		registry.mu.Lock()
		if registry.children[pid] == child {
			delete(registry.children, pid)
		}
		registry.mu.Unlock()
		_ = witness.Close()
	})
	if err := child.verifyProcess(); err != nil {
		return release, err
	}
	registry.mu.Lock()
	if registry.ctx.Err() != nil || childCtx.Err() != nil || registry.children[pid] != nil {
		registry.mu.Unlock()
		return release, rootoci.ErrUnauthorized
	}
	registry.children[pid] = child
	registry.mu.Unlock()
	if err := child.guard(childCtx); err != nil {
		return release, err
	}
	return release, nil
}

func rootBrokerSourceQuery(command string, wire []byte) (*swarmruntime.WorkerRegistrationQuery, *hostenroll.WorkerMembershipQuery, error) {
	if len(wire) == 0 || len(wire) > 128<<10 {
		return nil, nil, rootoci.ErrUnauthorized
	}
	var registration *swarmruntime.WorkerRegistrationQuery
	var membership *hostenroll.WorkerMembershipQuery
	var query any
	switch command {
	case "runtime-worker-admission-source", runtimeControllerHostSourceCommand:
		registration = new(swarmruntime.WorkerRegistrationQuery)
		if protocol.DecodeStrict(wire, registration, 128<<10) != nil || len(registration.Request) == 0 || len(registration.Response) == 0 ||
			command == runtimeControllerHostSourceCommand && registration.Swarm != nil {
			return nil, nil, rootoci.ErrUnauthorized
		}
		query = registration
	case "runtime-worker-membership-source":
		membership = new(hostenroll.WorkerMembershipQuery)
		if protocol.DecodeStrict(wire, membership, 128<<10) != nil || membership.NodeID == "" ||
			!entityid.Valid(membership.RegistrationID) || membership.InstanceID == "" {
			return nil, nil, rootoci.ErrUnauthorized
		}
		query = membership
	default:
		return nil, nil, rootoci.ErrUnauthorized
	}
	exact, err := protocol.EncodeJSON(query)
	if err != nil || !bytes.Equal(exact, wire) {
		return nil, nil, rootoci.ErrUnauthorized
	}
	return registration, membership, nil
}

func (registry *rootBrokerSourceChildren) guardRoot() error {
	if registry == nil || registry.ctx == nil || registry.ctx.Err() != nil || !time.Now().Before(registry.deadline) ||
		registry.parent == nil || registry.parent.Peer().PID != os.Getpid() || registry.parent.Peer().UID != 0 ||
		registry.parent.Peer().GID != 0 || registry.parent.Verify() != nil {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func (child *rootBrokerSourceChild) verifyProcess() error {
	if child == nil || child.original == nil || child.original.Err() != nil || child.ctx == nil || child.ctx.Err() != nil || !time.Now().Before(child.deadline) ||
		child.registry.guardRoot() != nil || child.witness == nil || child.witness.Verify() != nil {
		return rootoci.ErrUnauthorized
	}
	registry := child.registry
	peer := child.witness.Peer()
	if peer.UID != registry.uid || peer.GID != registry.gid || child.witness.ParentPID() != registry.parent.Peer().PID ||
		child.witness.Cgroup() != registry.parent.Cgroup() {
		return rootoci.ErrUnauthorized
	}
	parentExecutable, err := os.Stat(registry.parent.ExecutablePath())
	if err != nil {
		return rootoci.ErrUnauthorized
	}
	childExecutable, err := os.Stat(child.witness.ExecutablePath())
	if err != nil || !os.SameFile(parentExecutable, childExecutable) {
		return rootoci.ErrUnauthorized
	}
	commandLine, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", peer.PID))
	if err != nil || !bytes.Equal(commandLine, []byte("/proc/self/exe\x00"+child.command+"\x00")) ||
		sha256.Sum256(child.query) != child.querySHA256 || child.witness.Verify() != nil || registry.guardRoot() != nil || child.ctx.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func (child *rootBrokerSourceChild) guard(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || child.verifyProcess() != nil {
		return rootoci.ErrUnauthorized
	}
	child.registry.mu.Lock()
	retained := child.registry.children[child.witness.Peer().PID] == child
	child.registry.mu.Unlock()
	if !retained || child.ctx.Err() != nil || ctx.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func (registry *rootBrokerSourceChildren) lookup(conn *net.UnixConn) (*rootBrokerSourceChild, error) {
	if conn == nil || registry.guardRoot() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	peer, err := nativerootoci.PeerCredential(conn)
	if err != nil || peer.UID != registry.uid || peer.GID != registry.gid {
		return nil, rootoci.ErrUnauthorized
	}
	registry.mu.Lock()
	child := registry.children[peer.PID]
	registry.mu.Unlock()
	if child == nil || child.witness.Peer() != peer || child.guard(child.ctx) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	return child, nil
}

func (child *rootBrokerSourceChild) servePublic(ctx context.Context, conn *net.UnixConn) error {
	if child == nil || ctx == nil || child.guard(ctx) != nil {
		return rootoci.ErrUnauthorized
	}
	retained, err := child.registry.lookup(conn)
	if err != nil || retained != child {
		return rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithDeadline(ctx, earlier(child.deadline, child.registry.deadline))
	defer cancel()
	stop := context.AfterFunc(child.ctx, cancel)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if child.guard(ctx) != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	if err := child.guard(ctx); err != nil {
		return err
	}
	if err := child.registry.proxy.ServeReconnect(ctx, conn); err != nil {
		return err
	}
	return child.guard(ctx)
}

func (registry *rootBrokerSourceChildren) Close() error {
	registry.cancel()
	registry.stopRoot()
	registry.mu.Lock()
	children := make([]*rootBrokerSourceChild, 0, len(registry.children))
	for _, child := range registry.children {
		children = append(children, child)
	}
	registry.mu.Unlock()
	for _, child := range children {
		child.cancel()
	}
	// Only each launcher's post-Wait release closes its retained witness.
	return nil
}
