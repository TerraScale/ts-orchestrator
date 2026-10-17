package app

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootociwire"
	"golang.org/x/sys/unix"
)

const rootHostEnrollmentMaxPreface = 1024

type rootHostEnrollmentPreface struct {
	Version       uint8                             `json:"version"`
	TLSVersion    uint16                            `json:"tls_version"`
	CipherSuite   uint16                            `json:"cipher_suite"`
	RemoteAddress string                            `json:"remote_address"`
	LocalAddress  string                            `json:"local_address"`
	AcceptedAt    time.Time                         `json:"accepted_at"`
	Deadline      time.Time                         `json:"deadline"`
	Startup       *rootHostEnrollmentStartupIdentity `json:"startup,omitempty"`
}

// Startup is descriptive evidence carried only by the authenticated root
// connection. It cannot grant authority through HTTP headers or caller DTOs.
type rootHostEnrollmentStartupIdentity struct {
	Cell       string `json:"cell"`
	Region     string `json:"region"`
	Slot       string `json:"slot"`
	InstanceID string `json:"instance_id"`
	PrivateIP  string `json:"private_ip"`
}

func (preface rootHostEnrollmentPreface) valid(local string) bool {
	now := time.Now()
	peer, err := netip.ParseAddrPort(preface.RemoteAddress)
	if preface.Startup != nil {
		identity := preface.Startup
		if err != nil || identity.Cell == "" || identity.Region == "" || identity.Slot == "" || identity.InstanceID == "" ||
			identity.PrivateIP != peer.Addr().String() || local != net.JoinHostPort(identity.PrivateIP, "8443") {
			return false
		}
	}
	return err == nil && peer.Addr().Is4() && peer.Addr().IsPrivate() && !peer.Addr().IsLoopback() && peer.Port() != 0 &&
		preface.Version == 1 && preface.TLSVersion == tls.VersionTLS13 &&
		(preface.CipherSuite == tls.TLS_AES_128_GCM_SHA256 || preface.CipherSuite == tls.TLS_AES_256_GCM_SHA384 ||
			preface.CipherSuite == tls.TLS_CHACHA20_POLY1305_SHA256) &&
		preface.LocalAddress == local && !preface.AcceptedAt.IsZero() && !preface.AcceptedAt.After(now) &&
		preface.Deadline.After(preface.AcceptedAt) && preface.Deadline.Sub(preface.AcceptedAt) <= rootHostEnrollmentLifetime &&
		now.Before(preface.Deadline)
}

func writeRootHostEnrollmentPreface(conn *net.UnixConn, preface rootHostEnrollmentPreface) error {
	if !preface.valid(preface.LocalAddress) {
		return rootoci.ErrUnauthorized
	}
	wire, err := protocol.EncodeJSON(preface)
	if err != nil {
		return err
	}
	return rootociwire.WriteBoundedFrame(conn, wire, rootHostEnrollmentMaxPreface)
}

type rootHostEnrollmentSource struct {
	broker       *rootBrokerRuntime
	process      *rootOCIProcess
	sources      *rootBoundRuntimeSources
	binding      *rootManagerRuntimeBinding
	session      context.Context
	sessionLease context.Context
	peer         nativerootoci.Peer
	startup      *rootBrokerStartup
}

func (enrollment *rootHostEnrollment) captureSource() (*rootHostEnrollmentSource, error) {
	authority := enrollment.broker.authority
	authority.mu.Lock()
	defer authority.mu.Unlock()
	process, sources := authority.main, authority.sources
	if process == nil || process.witness == nil || process.ctx.Err() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	source := &rootHostEnrollmentSource{broker: enrollment.broker, process: process, sources: sources,
		binding: process.managerBinding, session: process.session, sessionLease: process.lease, peer: process.witness.Peer()}
	if sources != nil && process.managerBinding != nil && process.session != nil && process.lease != nil &&
		process.session.Err() == nil && process.lease.Err() == nil && sources.lease.Err() == nil {
		return source, nil
	}
	// This is a separate enrollment-only use of the already accepted startup
	// transport. It never falls through to an OCI observation or runtime lease.
	source.startup = process.brokerStartup
	if source.startup == nil || source.startup.process != process || source.startup.ctx.Err() != nil ||
		!source.startupRetainedLocked() || sources != nil && sources.lease.Err() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	return source, nil
}

// Caller holds authority.mu; lock order matches verifyBrokerStartupLocked.
func (source *rootHostEnrollmentSource) startupRetainedLocked() bool {
	ownhost := source.broker.authority.ownhost
	ownhost.mu.RLock()
	defer ownhost.mu.RUnlock()
	return !source.process.runtime && ownhost.session == nil && ownhost.generation == source.process.generation &&
		source.process.brokerStartup == source.startup && source.startup.process == source.process && source.startup.ctx.Err() == nil
}

func (source *rootHostEnrollmentSource) retained() bool {
	if source.broker.ctx.Err() != nil || source.process.ctx.Err() != nil || source.process.witness.Verify() != nil {
		return false
	}
	authority := source.broker.authority
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.main != source.process || authority.sources != source.sources || source.process.managerBinding != source.binding ||
		source.process.session != source.session || source.process.lease != source.sessionLease || source.process.witness.Peer() != source.peer {
		return false
	}
	if source.sources != nil && source.sources.lease.Err() != nil {
		return false
	}
	if source.startup != nil {
		return source.startupRetainedLocked()
	}
	return source.session != nil && source.sessionLease != nil && source.session.Err() == nil && source.sessionLease.Err() == nil
}

func (source *rootHostEnrollmentSource) context(parent context.Context) (context.Context, context.CancelFunc) {
	deadline := source.broker.origin.ExpiresAt()
	parents := []context.Context{source.broker.ctx, source.process.ctx}
	if source.sources != nil {
		deadline = earlier(deadline, source.sources.deadline)
		parents = append(parents, source.sources.lease)
	}
	if source.startup != nil {
		deadline = earlier(deadline, source.startup.deadline)
		parents = append(parents, source.startup.ctx)
	} else {
		deadline = earlier(deadline, source.binding.signed.Binding.ExpiresAt)
		parents = append(parents, source.session, source.sessionLease)
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	stops := make([]func() bool, 0, len(parents))
	for _, parent := range parents {
		stops = append(stops, context.AfterFunc(parent, cancel))
	}
	return ctx, func() {
		for _, stop := range stops {
			stop()
		}
		cancel()
	}
}

// Only the runtime branch contains a general runtime lease. The startup branch
// retains the original accepted capability without minting or promoting one.
type rootHostEnrollmentAdmission struct {
	runtime  rootoci.Lease
	startup  *rootBrokerStartup
	deadline time.Time
}

func (source *rootHostEnrollmentSource) admit(ctx context.Context) (rootHostEnrollmentAdmission, error) {
	if ctx.Err() != nil || !source.retained() {
		return rootHostEnrollmentAdmission{}, rootoci.ErrUnauthorized
	}
	var admission rootHostEnrollmentAdmission
	if source.startup != nil {
		if err := source.broker.authority.verifyBrokerStartup(ctx, source.startup); err != nil {
			return rootHostEnrollmentAdmission{}, err
		}
		admission.startup, admission.deadline = source.startup, source.startup.deadline
		if source.sources != nil {
			admission.deadline = earlier(admission.deadline, source.sources.deadline)
		}
	} else {
		lease, err := source.broker.authority.authorizeRuntime(ctx, source.peer)
		if err != nil || lease.Context == nil || lease.Context != source.sessionLease || lease.Context.Err() != nil {
			return rootHostEnrollmentAdmission{}, rootoci.ErrUnauthorized
		}
		admission.runtime, admission.deadline = lease, lease.Deadline
	}
	admission.deadline = earlier(admission.deadline, source.broker.origin.ExpiresAt())
	if !time.Now().Before(admission.deadline) || !source.retained() {
		return rootHostEnrollmentAdmission{}, rootoci.ErrUnauthorized
	}
	if err := source.broker.guard(ctx); err != nil {
		return rootHostEnrollmentAdmission{}, err
	}
	return admission, nil
}

func (source *rootHostEnrollmentSource) guard(ctx context.Context, admission rootHostEnrollmentAdmission) error {
	current, err := source.admit(ctx)
	if err != nil || current.startup != admission.startup || !current.deadline.Equal(admission.deadline) ||
		current.runtime.Context != admission.runtime.Context || current.runtime.Binding != admission.runtime.Binding ||
		current.runtime.RuntimeID != admission.runtime.RuntimeID || !current.runtime.Deadline.Equal(admission.runtime.Deadline) || ctx.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func (source *rootHostEnrollmentSource) same(other *rootHostEnrollmentSource) bool {
	return source.process == other.process && source.sources == other.sources && source.binding == other.binding &&
		source.session == other.session && source.sessionLease == other.sessionLease && source.peer == other.peer && source.startup == other.startup
}

func (source *rootHostEnrollmentSource) startupIdentity() *rootHostEnrollmentStartupIdentity {
	if source.startup == nil {
		return nil
	}
	identity := source.startup.current.Identity()
	return &rootHostEnrollmentStartupIdentity{Cell: identity.Cell, Region: identity.OCIRegion,
		Slot: identity.Slot, InstanceID: identity.InstanceID, PrivateIP: identity.PrivateIP}
}

func (source *rootHostEnrollmentSource) monitor(ctx context.Context, conn syscall.Conn, cancel context.CancelFunc) <-chan struct{} {
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
				if !source.retained() || rootHostEnrollmentDisconnected(conn) {
					cancel()
					return
				}
			}
		}
	}()
	return done
}

func rootHostEnrollmentDisconnected(conn syscall.Conn) bool {
	control, err := conn.SyscallConn()
	if err != nil {
		return true
	}
	disconnected := false
	err = control.Control(func(fd uintptr) {
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLRDHUP | unix.POLLHUP | unix.POLLERR}}
		_, err := unix.Poll(poll, 0)
		disconnected = err != nil || poll[0].Revents&(unix.POLLRDHUP|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0
	})
	return err != nil || disconnected
}

type rootHostEnrollmentDestination struct {
	ctx    context.Context
	conn   *net.UnixConn
	source *rootHostEnrollmentSource
	lease  rootHostEnrollmentAdmission
	done   chan struct{}
}

func (destination *rootHostEnrollmentDestination) guard(ctx context.Context) error {
	peer, err := nativerootoci.PeerCredential(destination.conn)
	if err != nil || peer != destination.source.peer || destination.ctx.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	return destination.source.guard(ctx, destination.lease)
}

func (enrollment *rootHostEnrollment) servePrivate(parent context.Context, conn *net.UnixConn) {
	peer, err := nativerootoci.PeerCredential(conn)
	if err != nil {
		return
	}
	source, err := enrollment.captureSource()
	if err != nil || source.peer != peer {
		return
	}
	ctx, cancel := source.context(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	monitor := source.monitor(ctx, conn, cancel)
	defer func() { cancel(); <-monitor }()
	lease, err := source.admit(ctx)
	if err != nil {
		return
	}
	ctx, stopLease := context.WithDeadline(ctx, lease.deadline)
	defer stopLease()
	stopLeaseClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopLeaseClose()
	destination := &rootHostEnrollmentDestination{ctx: ctx, conn: conn, source: source, lease: lease, done: make(chan struct{})}
	if destination.guard(ctx) != nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	case enrollment.demands <- destination:
	}
	select {
	case <-destination.done:
	case <-ctx.Done():
		_ = conn.Close()
		<-destination.done
	}
}

func serveRootHostEnrollmentTunnel(parent context.Context, public net.Conn, destination *rootHostEnrollmentDestination) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	closePair := func() { _ = public.Close(); _ = destination.conn.Close() }
	stop := context.AfterFunc(ctx, closePair)
	defer stop()
	defer closePair()
	monitor := make(chan struct{})
	go func() {
		defer close(monitor)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if destination.guard(ctx) != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-monitor }()
	copied := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(destination.conn, public); copied <- struct{}{} }()
	go func() { _, _ = io.Copy(public, destination.conn); copied <- struct{}{} }()
	<-copied
	cancel()
	closePair()
	<-copied
}
