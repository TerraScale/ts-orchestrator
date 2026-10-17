package app

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type rootOCIProcess struct {
	witness    *rootoci.ProcessWitness
	ctx        context.Context
	cancel     context.CancelFunc
	startupEnd time.Time
	generation uint64
	runtime    bool
	invocation string
	session    context.Context
	lease      context.Context
	stopLease  func()
}

func (process *rootOCIProcess) close() {
	process.cancel()
	if process.stopLease != nil {
		process.stopLease()
	}
	_ = process.witness.Close()
}

// Only root's private supervisor and the independently observed systemd MainPID
// can enter the startup read phase. Session loss never reopens that phase.
type rootOCIAuthority struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	accepted bootstrapstart.AcceptedIdentity
	encoded  []byte
	ownhost  *managedRuntimeHost
	layout   selfupdate.Layout
	uid, gid uint32
	parent   *rootoci.ProcessWitness
	child    *rootOCIProcess
	main     *rootOCIProcess
}

func newRootOCIAuthority(ctx context.Context, accepted bootstrapstart.AcceptedIdentity, ownhost *managedRuntimeHost,
	layout selfupdate.Layout, uid, gid uint32,
) (*rootOCIAuthority, error) {
	if os.Geteuid() != 0 || ctx == nil || ownhost == nil || ownhost.reader == nil || uid == 0 || gid == 0 {
		return nil, rootoci.ErrUnauthorized
	}
	encoded, err := bootstrapstart.EncodeAcceptedIdentity(accepted)
	if err != nil {
		return nil, err
	}
	parent, err := rootoci.CaptureProcess(os.Getpid())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &rootOCIAuthority{ctx: ctx, cancel: cancel, accepted: accepted.Clone(), encoded: encoded,
		ownhost: ownhost, layout: layout, uid: uid, gid: gid, parent: parent}, nil
}

func (authority *rootOCIAuthority) Close() error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.cancel()
	if authority.child != nil {
		authority.child.close()
	}
	if authority.main != nil {
		authority.main.close()
	}
	return authority.parent.Close()
}

func (authority *rootOCIAuthority) process(witness *rootoci.ProcessWitness, invocation string) *rootOCIProcess {
	ctx, cancel := context.WithCancel(authority.ctx)
	authority.ownhost.mu.RLock()
	generation := authority.ownhost.generation
	authority.ownhost.mu.RUnlock()
	return &rootOCIProcess{witness: witness, ctx: ctx, cancel: cancel, invocation: invocation,
		startupEnd: time.Now().Add(controllerAdmissionTimeout), generation: generation}
}

// registerAdmissionChild is called only after Start and before releasing stdin.
func (authority *rootOCIAuthority) registerAdmissionChild(pid int) (func(), error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.ctx.Err() != nil || authority.child != nil || authority.parent.Verify() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	witness, err := rootoci.CaptureProcess(pid)
	if err != nil {
		return nil, err
	}
	if witness.Peer().UID != authority.uid || witness.Peer().GID != authority.gid || witness.ParentPID() != os.Getpid() ||
		witness.Cgroup() != authority.parent.Cgroup() || authority.verifyBinary(witness) != nil {
		_ = witness.Close()
		return nil, rootoci.ErrUnauthorized
	}
	process := authority.process(witness, "")
	authority.child = process
	return func() {
		authority.mu.Lock()
		defer authority.mu.Unlock()
		process.close()
		if authority.child == process {
			authority.child = nil
		}
	}, nil
}

func (authority *rootOCIAuthority) verifyBinary(witness *rootoci.ProcessWitness) error {
	inputs, err := bootstrapstart.LoadTrustInputs(authority.accepted)
	if err != nil || witness.Verify() != nil {
		return rootoci.ErrUnauthorized
	}
	if err := bootstrapstart.VerifyRestartProcessBinary(witness.Peer().PID, authority.accepted, authority.layout, inputs.Roots.Historical); err != nil {
		return rootoci.ErrUnauthorized
	}
	return witness.Verify()
}

func (authority *rootOCIAuthority) authorize(request context.Context, peer nativerootoci.Peer, operation rootoci.Operation) (rootoci.Lease, error) {
	return authority.authorizeProcess(request, peer, operation.ReadOnly())
}

func (authority *rootOCIAuthority) authorizeRuntime(request context.Context, peer nativerootoci.Peer) (rootoci.Lease, error) {
	return authority.authorizeProcess(request, peer, false)
}

func (authority *rootOCIAuthority) authorizeProcess(request context.Context, peer nativerootoci.Peer, startupRead bool) (rootoci.Lease, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.ctx.Err() != nil || request == nil || request.Err() != nil || peer.UID != authority.uid || peer.GID != authority.gid {
		return rootoci.Lease{}, rootoci.ErrUnauthorized
	}
	// Guard verification must not recursively inherit a backend's SDK guard.
	deadline := time.Now().Add(30 * time.Second)
	if original, ok := request.Deadline(); ok && original.Before(deadline) {
		deadline = original
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	stopRequest := context.AfterFunc(request, cancel)
	stopAuthority := context.AfterFunc(authority.ctx, cancel)
	defer func() { stopRequest(); stopAuthority(); cancel() }()
	process, err := authority.currentProcess(ctx, peer)
	if err != nil {
		return rootoci.Lease{}, err
	}
	deny := func() (rootoci.Lease, error) { return rootoci.Lease{}, rootoci.ErrUnauthorized }
	if process.ctx.Err() != nil || authority.verifyBinary(process.witness) != nil {
		return deny()
	}
	if authority.verifyMarker() != nil {
		return deny()
	}
	source := authority.ownhost
	source.mu.RLock()
	defer source.mu.RUnlock()
	currentAuthority, err := source.reader.ReadRuntimeAuthority(ctx, authority.accepted, time.Now().UTC())
	if err != nil {
		return deny()
	}
	if source.generation != process.generation || source.session != nil {
		process.runtime = true
	}
	if !process.runtime {
		if !startupRead || !time.Now().Before(process.startupEnd) {
			return rootoci.Lease{}, rootoci.ErrUnauthorized
		}
		observer, err := source.reader.RuntimeInstanceObserver(ctx, authority.accepted)
		if err != nil {
			return deny()
		}
		observed, err := observer.ObserveInstance(ctx, authority.accepted.InstanceOCID)
		if err != nil || observed.InstanceOCID != authority.accepted.InstanceOCID || observed.ImageOCID != authority.accepted.ImageOCID ||
			observed.PrimaryVNICOCID != authority.accepted.PrimaryVNICOCID || observed.PrimaryPrivateIP != authority.accepted.PrimaryPrivateIP ||
			!observed.PrimaryVNIC || observed.LifecycleState != "RUNNING" {
			return deny()
		}
		confirmed, err := source.reader.ReadRuntimeAuthority(ctx, authority.accepted, time.Now().UTC())
		if err != nil || confirmed.Identity() != currentAuthority.Identity() || confirmed.Anchor().Digest() != currentAuthority.Anchor().Digest() ||
			authority.verifyMarker() != nil || authority.verifyProcess(ctx, process) != nil || ctx.Err() != nil {
			return deny()
		}
		return rootoci.Lease{Context: process.ctx, Deadline: earlier(process.startupEnd, confirmed.ExpiresAt()),
			Binding: process.witness.Binding() + ":startup:" + confirmed.Anchor().Digest()}, nil
	}
	if process == authority.child || source.agent == nil || source.session == nil || source.session.Err() != nil {
		return rootoci.Lease{}, rootoci.ErrUnauthorized
	}
	stopSession := context.AfterFunc(source.session, cancel)
	defer stopSession()
	binding, err := swarmruntime.ReadControllerHostBinding(ctx, source.reader, authority.accepted, source.agent, source.transport.Request, source.transport.Response)
	if err != nil {
		return rootoci.Lease{}, rootoci.ErrUnauthorized
	}
	identity, err := source.agent.RuntimeWorkerIdentity(binding.Identity().InstanceID, source.nodeID)
	if err != nil || binding.ControllerSlot() != authority.accepted.Slot || binding.Identity() != currentAuthority.Identity() ||
		authority.verifyMarker() != nil || authority.verifyProcess(ctx, process) != nil || ctx.Err() != nil || source.session.Err() != nil {
		return rootoci.Lease{}, rootoci.ErrUnauthorized
	}
	if process.session != source.session {
		if process.stopLease != nil {
			process.stopLease()
		}
		lease, cancelLease := context.WithCancel(process.ctx)
		stop := context.AfterFunc(source.session, cancelLease)
		process.session, process.lease = source.session, lease
		process.stopLease = func() { stop(); cancelLease() }
	}
	worker := identity.Identity()
	return rootoci.Lease{Context: process.lease, Deadline: earlier(identity.ExpiresAt(), currentAuthority.ExpiresAt()),
		RuntimeID: entityid.Derive("controller-runtime", process.witness.Binding()),
		Binding: fmt.Sprintf("%s:runtime:%s:%d:%s", process.witness.Binding(), worker.HostSessionID,
			worker.RegistrationGeneration, currentAuthority.Anchor().Digest())}, nil
}

func controllerRuntimeID() (string, error) {
	witness, err := rootoci.CaptureProcess(os.Getpid())
	if err != nil {
		return "", err
	}
	defer witness.Close()
	return entityid.Derive("controller-runtime", witness.Binding()), nil
}

func (authority *rootOCIAuthority) verifyMarker() error {
	current, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return rootoci.ErrUnauthorized
	}
	encoded, err := bootstrapstart.EncodeAcceptedIdentity(current)
	if err != nil || !bytes.Equal(encoded, authority.encoded) {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func (authority *rootOCIAuthority) verifyProcess(ctx context.Context, process *rootOCIProcess) error {
	if process.ctx.Err() != nil || process.witness.Verify() != nil {
		process.cancel()
		return rootoci.ErrUnauthorized
	}
	if process == authority.child {
		if authority.parent.Verify() != nil || process.witness.ParentPID() != os.Getpid() || process.witness.Cgroup() != authority.parent.Cgroup() {
			process.cancel()
			return rootoci.ErrUnauthorized
		}
		return nil
	}
	service, err := observeRootOCIController(ctx)
	if err != nil || service.pid != process.witness.Peer().PID || service.invocation != process.invocation ||
		!rootOCIProcessCgroup(process.witness.Cgroup(), service.cgroup) || process.witness.Verify() != nil {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func earlier(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func (authority *rootOCIAuthority) currentProcess(ctx context.Context, peer nativerootoci.Peer) (*rootOCIProcess, error) {
	if authority.child != nil && authority.child.witness.Peer() == peer {
		if authority.parent.Verify() != nil || authority.child.witness.Verify() != nil {
			authority.child.cancel()
			return nil, rootoci.ErrUnauthorized
		}
		return authority.child, nil
	}
	service, err := observeRootOCIController(ctx)
	if err != nil || service.pid != peer.PID {
		return nil, rootoci.ErrUnauthorized
	}
	if authority.main != nil && authority.main.witness.Peer() == peer {
		if authority.main.witness.Verify() == nil {
			if authority.main.invocation != service.invocation || !rootOCIProcessCgroup(authority.main.witness.Cgroup(), service.cgroup) {
				authority.main.cancel()
				return nil, rootoci.ErrUnauthorized
			}
			return authority.main, nil
		}
		authority.main.cancel()
	}
	witness, err := rootoci.CaptureProcess(peer.PID)
	if err != nil {
		return nil, rootoci.ErrUnauthorized
	}
	confirmed, err := observeRootOCIController(ctx)
	if err != nil || confirmed != service || witness.Peer() != peer || !rootOCIProcessCgroup(witness.Cgroup(), service.cgroup) ||
		authority.main != nil && authority.main.witness.Peer().PID == peer.PID && authority.main.witness.KernelStart() == witness.KernelStart() {
		_ = witness.Close()
		return nil, rootoci.ErrUnauthorized
	}
	if authority.main != nil {
		authority.main.close()
	}
	authority.main = authority.process(witness, service.invocation)
	return authority.main, nil
}

type rootOCIController struct {
	pid                int
	invocation, cgroup string
}

func observeRootOCIController(ctx context.Context) (rootOCIController, error) {
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(probe, "/usr/bin/systemctl", "show", selfupdate.ControllerUnit,
		"--property=LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,ControlGroup")
	command.WaitDelay = time.Second
	wire, err := command.Output()
	if err != nil || len(wire) > 8192 {
		return rootOCIController{}, rootoci.ErrUnauthorized
	}
	return parseRootOCIController(wire)
}

func parseRootOCIController(wire []byte) (rootOCIController, error) {
	fields := make(map[string]string)
	for line := range strings.SplitSeq(strings.TrimSpace(string(wire)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if _, duplicate := fields[key]; !ok || duplicate {
			return rootOCIController{}, rootoci.ErrUnauthorized
		}
		fields[key] = value
	}
	pid, err := strconv.Atoi(fields["MainPID"])
	invocation, cgroup := fields["InvocationID"], fields["ControlGroup"]
	live := fields["ActiveState"] == "active" && fields["SubState"] == "running" ||
		fields["ActiveState"] == "activating" && fields["SubState"] == "start"
	if err != nil || pid < 2 || fields["LoadState"] != "loaded" || !live || fields["ControlPID"] != "0" ||
		len(invocation) != 32 || cgroup == "" || cgroup == "/" || !strings.HasPrefix(cgroup, "/") || strings.ContainsAny(cgroup, "\r\n:") {
		return rootOCIController{}, rootoci.ErrUnauthorized
	}
	for _, char := range invocation {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return rootOCIController{}, rootoci.ErrUnauthorized
		}
	}
	return rootOCIController{pid: pid, invocation: invocation, cgroup: cgroup}, nil
}

func rootOCIProcessCgroup(wire, expected string) bool {
	return strings.TrimSuffix(wire, "\n") == "0::"+expected
}
