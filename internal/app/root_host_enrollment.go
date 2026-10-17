package app

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

const rootHostEnrollmentSocket = "/run/terrascale-orchestrator/host-enrollment.sock"
const rootHostEnrollmentLifetime = 30 * time.Second

type rootHostEnrollment struct {
	broker   *rootBrokerRuntime
	ctx      context.Context
	cancel   context.CancelFunc
	listener *net.TCPListener
	tls      *tls.Config
	demands  chan *rootHostEnrollmentDestination
	workers  sync.WaitGroup
	once     sync.Once
}

func newRootHostEnrollment(broker *rootBrokerRuntime) (*rootHostEnrollment, error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 || broker == nil || broker.runtime == nil ||
		broker.authority == nil || broker.cfg.NATS.Embedded == nil || broker.runtime.BrokerTLS() == nil ||
		broker.ctx == nil || broker.ctx.Err() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	address, err := netip.ParseAddr(broker.origin.Identity().PrivateIP)
	if err != nil || !address.Is4() || !address.IsPrivate() || address.IsLoopback() ||
		broker.cfg.NATS.Embedded.Host != address.String() ||
		broker.cfg.Controller.HostEnrollmentListenAddress != net.JoinHostPort(address.String(), "8443") {
		return nil, rootoci.ErrUnauthorized
	}
	if err := broker.guard(broker.ctx); err != nil {
		return nil, err
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(address.AsSlice()), Port: 8443})
	if err != nil {
		return nil, err
	}
	if listener.Addr().String() != broker.cfg.Controller.HostEnrollmentListenAddress {
		_ = listener.Close()
		return nil, rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithCancel(broker.ctx)
	enrollment := &rootHostEnrollment{broker: broker, ctx: ctx, cancel: cancel, listener: listener,
		tls: &tls.Config{MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true,
			GetCertificate: broker.runtime.BrokerTLS().Certificate},
		demands: make(chan *rootHostEnrollmentDestination)}
	enrollment.workers.Go(enrollment.runPublic)
	return enrollment, nil
}

func (enrollment *rootHostEnrollment) Close() error {
	enrollment.once.Do(func() {
		enrollment.cancel()
		_ = enrollment.listener.Close()
		enrollment.workers.Wait()
	})
	return nil
}

func (enrollment *rootHostEnrollment) runPublic() {
	stop := context.AfterFunc(enrollment.ctx, func() { _ = enrollment.listener.Close() })
	defer stop()
	slots := make(chan struct{}, 2)
	for {
		conn, err := enrollment.listener.AcceptTCP()
		accepted := time.Now()
		if err != nil {
			if enrollment.ctx.Err() == nil {
				enrollment.broker.cancel()
			}
			return
		}
		original, cancel := context.WithDeadline(enrollment.ctx, accepted.Add(rootHostEnrollmentLifetime))
		stop := context.AfterFunc(original, func() { _ = conn.Close() })
		if conn.SetDeadline(accepted.Add(rootHostEnrollmentLifetime)) != nil {
			cancel()
			stop()
			_ = conn.Close()
			continue
		}
		// Capture the original MainPID/session before scheduling or pairing.
		source, err := enrollment.captureSource()
		if err != nil {
			cancel()
			stop()
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			enrollment.workers.Go(func() {
				defer func() { cancel(); stop(); <-slots; _ = conn.Close() }()
				enrollment.servePublic(original, conn, source, accepted)
			})
		default:
			cancel()
			stop()
			_ = conn.Close()
		}
	}
}

func (enrollment *rootHostEnrollment) servePublic(original context.Context, raw *net.TCPConn, source *rootHostEnrollmentSource, accepted time.Time) {
	ctx, cancel := source.context(original)
	defer cancel()
	stopClose := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopClose()
	deadline, _ := ctx.Deadline()
	if raw.SetDeadline(deadline) != nil {
		return
	}
	monitor := source.monitor(ctx, raw, cancel)
	defer func() { cancel(); <-monitor }()
	lease, err := source.admit(ctx)
	if err != nil {
		return
	}
	ctx, stopLease := context.WithDeadline(ctx, lease.Deadline)
	defer stopLease()
	stopLeaseClose := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopLeaseClose()
	deadline, _ = ctx.Deadline()
	if raw.SetDeadline(deadline) != nil {
		return
	}
	secured := tls.Server(raw, enrollment.tls)
	handshake, stopHandshake := context.WithTimeout(ctx, 5*time.Second)
	err = secured.HandshakeContext(handshake)
	stopHandshake()
	if err != nil {
		return
	}
	state := secured.ConnectionState()
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || source.guard(ctx, lease) != nil {
		return
	}
	var destination *rootHostEnrollmentDestination
	select {
	case <-ctx.Done():
		return
	case destination = <-enrollment.demands:
	}
	// A selected stream is never reassigned to another demand or successor.
	defer close(destination.done)
	if !source.same(destination.source) || destination.guard(ctx) != nil || source.guard(ctx, lease) != nil {
		return
	}
	deadline = earlier(deadline, destination.lease.Deadline)
	ctx, stopDelivery := context.WithDeadline(ctx, deadline)
	defer stopDelivery()
	stopDestination := context.AfterFunc(destination.ctx, stopDelivery)
	defer stopDestination()
	if ctx.Err() != nil || raw.SetDeadline(deadline) != nil || destination.conn.SetDeadline(deadline) != nil {
		return
	}
	preface := rootHostEnrollmentPreface{Version: 1, TLSVersion: state.Version, CipherSuite: state.CipherSuite,
		RemoteAddress: raw.RemoteAddr().String(), LocalAddress: raw.LocalAddr().String(), AcceptedAt: accepted.UTC(), Deadline: deadline.UTC()}
	if writeRootHostEnrollmentPreface(destination.conn, preface) != nil || destination.guard(ctx) != nil {
		return
	}
	serveRootHostEnrollmentTunnel(ctx, secured, destination)
}
