package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootociwire"
)

type rootHostEnrollmentListener struct {
	ctx     context.Context
	cancel  context.CancelFunc
	address *net.TCPAddr
	self    *rootoci.ProcessWitness
	binding rootBrokerPeerIdentity
	mu      sync.Mutex
	initial *net.UnixConn
	once    sync.Once
}

func openRootHostEnrollmentListener(parent context.Context, cfg Config) (*rootHostEnrollmentListener, error) {
	if parent == nil || parent.Err() != nil || cfg.NATS.Embedded == nil || os.Geteuid() == 0 || os.Getegid() == 0 {
		return nil, rootoci.ErrUnauthorized
	}
	address, err := netip.ParseAddrPort(cfg.Controller.HostEnrollmentListenAddress)
	if err != nil || address.Port() != 8443 || !address.Addr().Is4() || !address.Addr().IsPrivate() ||
		address.Addr().IsLoopback() || address.Addr().String() != cfg.NATS.Embedded.Host {
		return nil, rootoci.ErrUnauthorized
	}
	self, err := rootoci.CaptureProcess(os.Getpid())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	listener := &rootHostEnrollmentListener{ctx: ctx, cancel: cancel, self: self,
		address: &net.TCPAddr{IP: net.IP(address.Addr().AsSlice()), Port: 8443}}
	conn, binding, err := listener.dial()
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	listener.initial, listener.binding = conn, binding
	return listener, nil
}

func (listener *rootHostEnrollmentListener) dial() (*net.UnixConn, rootBrokerPeerIdentity, error) {
	if listener.ctx.Err() != nil || listener.self.Verify() != nil {
		return nil, rootBrokerPeerIdentity{}, rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(listener.ctx, 12*time.Second)
	defer cancel()
	connection, err := new(net.Dialer).DialContext(ctx, "unix", rootHostEnrollmentSocket)
	if err != nil {
		return nil, rootBrokerPeerIdentity{}, err
	}
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, rootBrokerPeerIdentity{}, rootoci.ErrUnauthorized
	}
	binding, err := rootBrokerPeerBinding(conn, rootHostEnrollmentSocket)
	if err != nil || listener.ctx.Err() != nil || ctx.Err() != nil || listener.self.Verify() != nil ||
		(listener.binding != (rootBrokerPeerIdentity{}) && binding != listener.binding) {
		_ = conn.Close()
		return nil, rootBrokerPeerIdentity{}, rootoci.ErrUnauthorized
	}
	return conn, binding, nil
}

func (listener *rootHostEnrollmentListener) Accept() (net.Conn, error) {
	for listener.ctx.Err() == nil {
		listener.mu.Lock()
		conn := listener.initial
		listener.initial = nil
		listener.mu.Unlock()
		if conn == nil {
			var err error
			conn, _, err = listener.dial()
			if err != nil {
				return nil, err
			}
		}
		stop := context.AfterFunc(listener.ctx, func() { _ = conn.Close() })
		wire, err := rootociwire.ReadBoundedFrame(conn, rootHostEnrollmentMaxPreface)
		if err != nil {
			stop()
			_ = conn.Close()
			if errors.Is(err, io.EOF) && listener.ctx.Err() == nil && listener.self.Verify() == nil {
				// An idle pull can expire before any public connection is paired.
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-listener.ctx.Done():
					timer.Stop()
				case <-timer.C:
				}
				continue
			}
			return nil, err
		}
		var preface rootHostEnrollmentPreface
		if protocol.DecodeStrict(wire, &preface, rootHostEnrollmentMaxPreface) != nil ||
			!preface.valid(listener.address.String()) {
			stop()
			_ = conn.Close()
			return nil, rootoci.ErrUnauthorized
		}
		ctx, cancel := context.WithDeadline(listener.ctx, preface.Deadline)
		stopSource := context.AfterFunc(ctx, func() { _ = conn.Close() })
		secured := &rootHostEnrollmentConn{UnixConn: conn, listener: listener, preface: preface,
			ctx: ctx, cancel: cancel, stop: func() bool { first, second := stop(), stopSource(); return first && second }}
		if conn.SetDeadline(preface.Deadline) != nil || secured.guard(ctx) != nil {
			_ = secured.Close()
			return nil, rootoci.ErrUnauthorized
		}
		return secured, nil
	}
	return nil, net.ErrClosed
}

func (listener *rootHostEnrollmentListener) Close() error {
	listener.once.Do(func() {
		listener.cancel()
		listener.mu.Lock()
		if listener.initial != nil {
			_ = listener.initial.Close()
			listener.initial = nil
		}
		listener.mu.Unlock()
		_ = listener.self.Close()
	})
	return nil
}

func (listener *rootHostEnrollmentListener) Addr() net.Addr { return listener.address }

type rootHostEnrollmentConn struct {
	*net.UnixConn
	listener *rootHostEnrollmentListener
	preface  rootHostEnrollmentPreface
	ctx      context.Context
	cancel   context.CancelFunc
	stop     func() bool
	once     sync.Once
}

func (conn *rootHostEnrollmentConn) Close() error {
	conn.once.Do(func() {
		conn.cancel()
		conn.stop()
		_ = conn.UnixConn.Close()
	})
	return nil
}

func (conn *rootHostEnrollmentConn) guard(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || conn.ctx.Err() != nil || conn.listener.ctx.Err() != nil ||
		conn.listener.self.Verify() != nil || !conn.preface.valid(conn.listener.address.String()) {
		return rootoci.ErrUnauthorized
	}
	deadline, finite := ctx.Deadline()
	if !finite || deadline.After(conn.preface.Deadline) {
		return rootoci.ErrUnauthorized
	}
	binding, err := rootBrokerPeerBinding(conn.UnixConn, rootHostEnrollmentSocket)
	if err != nil || binding != conn.listener.binding || conn.ctx.Err() != nil || ctx.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	return nil
}

type rootHostEnrollmentContextKey struct{}

func rootHostEnrollmentConnContext(ctx context.Context, connection net.Conn) context.Context {
	conn, ok := connection.(*rootHostEnrollmentConn)
	if !ok || conn.guard(conn.ctx) != nil {
		denied, cancel := context.WithCancel(ctx)
		cancel()
		_ = connection.Close()
		return denied
	}
	ctx, cancel := context.WithDeadline(ctx, conn.preface.Deadline)
	stop := context.AfterFunc(conn.ctx, cancel)
	context.AfterFunc(ctx, func() { stop(); cancel() })
	return context.WithValue(ctx, rootHostEnrollmentContextKey{}, conn)
}

func hostEnrollmentTransport(request *http.Request) bool {
	if request != nil && request.TLS != nil {
		return true
	}
	_, err := hostEnrollmentPeer(request)
	return err == nil
}

func hostEnrollmentPeer(request *http.Request) (string, error) {
	if request == nil || request.Context().Err() != nil {
		return "", rootoci.ErrUnauthorized
	}
	// Direct TLS remains the existing handler boundary; the private listener
	// never constructs a TLS state or accepts provenance from HTTP headers.
	if request.TLS != nil {
		peer, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil || net.ParseIP(peer) == nil {
			return "", rootoci.ErrUnauthorized
		}
		return peer, nil
	}
	conn, ok := request.Context().Value(rootHostEnrollmentContextKey{}).(*rootHostEnrollmentConn)
	if !ok || conn.guard(request.Context()) != nil || conn.preface.Startup != nil &&
		(request.Method != http.MethodPost || request.URL.Path != "/v1/host-enrollment") {
		return "", rootoci.ErrUnauthorized
	}
	peer, err := netip.ParseAddrPort(conn.preface.RemoteAddress)
	if err != nil {
		return "", rootoci.ErrUnauthorized
	}
	return peer.Addr().String(), nil
}

// The original authenticated root stream supplies transport provenance. The
// separately parsed signed request and adopted signed spec supply host admission.
func (enrollment *managedHostEnrollment) admitStartupHostEnrollment(request *http.Request,
	enrolled hostenroll.Request, descriptor hostboot.Descriptor, peerIP string,
) bool {
	conn, ok := request.Context().Value(rootHostEnrollmentContextKey{}).(*rootHostEnrollmentConn)
	if !ok || conn.preface.Startup == nil {
		return true
	}
	identity := conn.preface.Startup
	accepted := enrollment.runtimeIdentity
	// Accepted/root identity uses the exact cell code and OCI region; signed
	// host descriptors use the catalog's lower-case cell and region code.
	cell, known := catalog.Lookup(accepted.Cell)
	grant, _, granted := enrollment.services.hostGrant(descriptor.Node)
	return known && conn.guard(request.Context()) == nil && descriptor.IsController() &&
		identity.Cell == accepted.Cell && identity.Region == cell.OCIRegion && enrollment.cell == cell.Name() &&
		identity.InstanceID == accepted.InstanceOCID && identity.PrivateIP == accepted.PrimaryPrivateIP && identity.Slot == accepted.Slot &&
		descriptor.Cell == cell.Name() && descriptor.Region == cell.Cell && string(enrollment.region) == cell.Cell &&
		enrolled.InstanceID == identity.InstanceID &&
		peerIP == identity.PrivateIP && granted && grant.Controller == identity.Slot && grant.PrivateIP == identity.PrivateIP
}
