package natscell

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
)

// ProbeNetBirdController uses root's original identity for one actual remote
// NATS exchange. The caller independently proves the signed target and session.
func (r *Runtime) ProbeNetBirdController(ctx context.Context, meshIP netip.Addr, privateIP, serverName string, beforeEffect func(context.Context) error) (time.Time, error) {
	underlay, err := netip.ParseAddr(privateIP)
	if r == nil || !meshIP.Is4() || !netip.MustParsePrefix(networkplan.Mesh).Contains(meshIP) ||
		err != nil || !underlay.Is4() || !underlay.IsPrivate() || underlay.IsLoopback() ||
		netip.MustParsePrefix(networkplan.Mesh).Contains(underlay) || !slices.Contains(r.brokerNames, serverName) {
		return time.Time{}, errors.New("NetBird controller probe requires the exact signed regional broker target")
	}
	return r.probeNetBirdController(ctx, net.JoinHostPort(meshIP.String(), "4222"), privateIP, serverName, beforeEffect)
}

func (r *Runtime) probeNetBirdController(ctx context.Context, destination, privateIP, serverName string, beforeEffect func(context.Context) error) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil || beforeEffect == nil || r == nil || r.conn == nil || r.server == nil {
		return time.Time{}, errors.New("original NetBird controller probe source is unavailable")
	}
	if _, finite := ctx.Deadline(); !finite {
		return time.Time{}, errors.New("NetBird controller probe requires its original finite lifetime")
	}
	if err := beforeEffect(ctx); err != nil {
		return time.Time{}, err
	}
	proxy, err := NewControllerProxy(r)
	if err != nil {
		return time.Time{}, err
	}
	claim, err := jwt.DecodeUserClaims(r.controllerJWT)
	if err != nil {
		return time.Time{}, err
	}
	deadline := proxy.deadline
	if claim.Expires > 0 && time.Unix(claim.Expires, 0).Before(deadline) {
		deadline = time.Unix(claim.Expires, 0)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	guard := func() error {
		if ctx.Err() != nil || !time.Now().Before(deadline) || !r.server.Running() || r.conn.IsClosed() {
			return errors.New("original NetBird controller probe authority ended")
		}
		validation := jwt.CreateValidationResults()
		claim.Validate(validation)
		if validation.IsBlocking(true) {
			return errors.New("original NetBird controller JWT expired")
		}
		if err := beforeEffect(ctx); err != nil {
			return err
		}
		return ctx.Err()
	}
	if err := guard(); err != nil {
		return time.Time{}, err
	}
	config := proxy.config.Clone()
	config.ServerName = privateIP
	dialer := &netBirdProbeDialer{ctx: ctx, config: config, destination: destination,
		expected: net.JoinHostPort(privateIP, "4222"), guard: guard}
	defer func() {
		if dialer.close != nil {
			dialer.close()
		}
	}()
	conn, err := nats.Connect("nats://"+dialer.expected,
		nats.Name("terrascale-"+r.cell+"-netbird-probe"),
		nats.Timeout(min(3*time.Second, time.Until(deadline))), nats.NoReconnect(), nats.IgnoreDiscoveredServers(),
		nats.SetCustomDialer(dialer), nats.ErrorHandler(ErrorHandler),
		nats.UserJWT(func() (string, error) {
			if err := dialer.live(); err != nil {
				return "", err
			}
			return r.controllerJWT, nil
		}, func(nonce []byte) ([]byte, error) {
			if err := dialer.live(); err != nil {
				return nil, err
			}
			r.controllerKeyMu.Lock()
			var signature []byte
			var err error
			if r.controllerKey == nil {
				err = errors.New("original root controller key was retired")
			} else {
				signature, err = r.controllerKey.Sign(nonce)
			}
			r.controllerKeyMu.Unlock()
			if err != nil {
				return nil, err
			}
			if err := dialer.live(); err != nil {
				clear(signature)
				return nil, err
			}
			return signature, nil
		}))
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()
	if err := dialer.live(); err != nil {
		return time.Time{}, err
	}
	if conn.ConnectedServerName() != serverName {
		return time.Time{}, errors.New("NetBird NATS endpoint differs from the signed controller server")
	}
	if err := conn.FlushWithContext(ctx); err != nil {
		return time.Time{}, err
	}
	if !conn.IsConnected() || conn.ConnectedServerName() != serverName {
		return time.Time{}, errors.New("NetBird controller connection ended during its exchange")
	}
	if err := dialer.live(); err != nil {
		return time.Time{}, err
	}
	return dialer.peerExpiry, nil
}

type netBirdProbeDialer struct {
	ctx         context.Context
	config      *tls.Config
	destination string
	expected    string
	guard       func() error
	connection  net.Conn
	peerExpiry  time.Time
	close       func()
}

func (d *netBirdProbeDialer) live() error {
	if !d.peerExpiry.IsZero() && !time.Now().Before(d.peerExpiry) {
		return errors.New("original NetBird controller TLS peer expired")
	}
	return d.guard()
}

func (d *netBirdProbeDialer) Dial(network, address string) (_ net.Conn, resultErr error) {
	if network != "tcp" || address != d.expected || d.connection != nil {
		return nil, errors.New("NetBird controller probe cannot select another endpoint or reconnect")
	}
	if err := d.live(); err != nil {
		return nil, err
	}
	raw, err := new(net.Dialer).DialContext(d.ctx, "tcp", d.destination)
	if err != nil {
		return nil, err
	}
	d.connection = raw
	transport, cancel := context.WithCancel(d.ctx)
	var peerTimer *time.Timer
	done := make(chan struct{})
	stop := context.AfterFunc(transport, func() { _ = raw.Close(); close(done) })
	d.close = sync.OnceFunc(func() {
		if peerTimer != nil {
			peerTimer.Stop()
		}
		_ = raw.Close()
		if !stop() {
			<-done
		}
		cancel()
	})
	defer func() {
		if resultErr != nil {
			d.close()
		}
	}()
	deadline, _ := d.ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := d.live(); err != nil {
		return nil, err
	}
	secured := tls.Client(raw, d.config)
	if err := secured.HandshakeContext(d.ctx); err != nil {
		return nil, err
	}
	state := secured.ConnectionState()
	if len(state.VerifiedChains) == 0 {
		return nil, errors.New("NetBird controller TLS chain is unavailable")
	}
	d.peerExpiry = deadline
	for _, chain := range state.VerifiedChains {
		for _, certificate := range chain {
			if certificate.NotAfter.Before(d.peerExpiry) {
				d.peerExpiry = certificate.NotAfter
			}
		}
	}
	peerTimer = time.AfterFunc(time.Until(d.peerExpiry), cancel)
	if err := raw.SetDeadline(d.peerExpiry); err != nil {
		return nil, err
	}
	if err := d.live(); err != nil {
		return nil, err
	}
	return secured, nil
}

func (*netBirdProbeDialer) SkipTLSHandshake() bool { return true }
