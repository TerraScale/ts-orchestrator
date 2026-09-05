// Package globalclient admits and opens the dedicated GRU worker connection.
package globalclient

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
)

// Plan owns resolved immutable file references, never credential bytes.
type Plan struct{ url, seed, public, ca, certificate, key string }

// Admit validates operational session inputs without opening a listener or client.
func Admit(config *directory.GlobalAuthorityNatsConfiguration) (*Plan, error) {
	if config == nil || config.Cell != "gru" || config.Replicas != 3 || config.Authentication == nil || config.Tls == nil {
		return nil, errors.New("global worker connection requires complete GRU R3 identity configuration")
	}
	auth := config.Authentication
	if auth.CredentialsFile != nil {
		return nil, errors.New("global operational sessions require an NKey seed file; JWT credential-file mode is unsupported by their journals")
	}
	if auth.NKeyFile == nil {
		return nil, errors.New("global operational sessions require an NKey seed file")
	}
	endpoint, err := url.Parse(config.Url)
	if err != nil || endpoint.Scheme != "tls" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.Opaque != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawFragment != "" || strings.Contains(config.Url, "#") {
		return nil, errors.New("global worker connection requires an absolute tls URL without embedded credentials or request components")
	}
	plan := &Plan{url: endpoint.String(), public: auth.PublicKey}
	for _, binding := range []struct {
		source string
		target *string
	}{{*auth.NKeyFile, &plan.seed}, {config.Tls.CaFile, &plan.ca}, {config.Tls.CertificateFile, &plan.certificate}, {config.Tls.KeyFile, &plan.key}} {
		if binding.source == "" {
			return nil, errIdentityFiles
		}
		absolute, err := filepath.Abs(binding.source)
		if err != nil {
			return nil, errIdentityFiles
		}
		*binding.target = absolute
	}
	identity, err := plan.identity(context.Background())
	if err != nil {
		return nil, err
	}
	identity.pair.Wipe()
	return plan, nil
}

// Matches prevents later configuration mutation from changing the admitted client.
func (p *Plan) Matches(config *directory.GlobalAuthorityNatsConfiguration) bool {
	if p == nil || config == nil || config.Authentication == nil || config.Authentication.NKeyFile == nil || config.Authentication.CredentialsFile != nil || config.Tls == nil || config.Cell != "gru" || config.Replicas != 3 {
		return false
	}
	absolute := func(path string) string {
		result, err := filepath.Abs(path)
		if err != nil {
			return ""
		}
		return result
	}
	return config.Url == p.url && config.Authentication.PublicKey == p.public && absolute(*config.Authentication.NKeyFile) == p.seed && absolute(config.Tls.CaFile) == p.ca && absolute(config.Tls.CertificateFile) == p.certificate && absolute(config.Tls.KeyFile) == p.key
}

type pendingSocket struct {
	connection net.Conn
	stop       func() bool
	done       chan struct{}
}

// NATS calls Dial serially during initial connection; reconnect is disabled.
type contextDialer struct {
	ctx     context.Context
	dialer  net.Dialer
	sockets []*pendingSocket
}

func (d *contextDialer) Dial(network, address string) (net.Conn, error) {
	connection, err := d.dialer.DialContext(d.ctx, network, address)
	if err != nil {
		return nil, err
	}
	socket := &pendingSocket{connection: connection, done: make(chan struct{})}
	socket.stop = context.AfterFunc(d.ctx, func() { connection.Close(); close(socket.done) })
	d.sockets = append(d.sockets, socket)
	return connection, nil
}
func (d *contextDialer) finish(keep bool) bool {
	for _, socket := range d.sockets {
		if socket.stop() {
			close(socket.done)
		} else {
			<-socket.done
			keep = false
		}
	}
	if d.ctx.Err() != nil {
		keep = false
	}
	if !keep {
		for _, socket := range d.sockets {
			socket.connection.Close()
		}
	}
	return keep
}

// Connect opens one authenticated, unbuffered session. The caller owns Close.
func (p *Plan) Connect(ctx context.Context) (*nats.Conn, error) {
	return p.connect(ctx, net.Dialer{Timeout: 2 * time.Second})
}
func (p *Plan) connect(ctx context.Context, network net.Dialer) (*nats.Conn, error) {
	if p == nil || ctx == nil {
		return nil, errors.New("global worker connection plan and context are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	identity, err := p.identity(bounded)
	if err != nil {
		return nil, err
	}
	transferred := false
	dialer := &contextDialer{ctx: bounded, dialer: network}
	defer func() {
		if !transferred {
			dialer.finish(false)
			identity.pair.Wipe()
		}
	}()
	settings := nats.GetDefaultOptions()
	settings.Url = p.url
	for _, option := range []nats.Option{nats.Secure(identity.tls), nats.Nkey(p.public, identity.pair.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1), nats.RetryOnFailedConnect(false), nats.SkipHostLookup(), nats.SetCustomDialer(dialer)} {
		if err := option(&settings); err != nil {
			return nil, err
		}
	}
	deadline, _ := bounded.Deadline()
	settings.Timeout = time.Until(deadline)
	if settings.Timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	connection, err := settings.Connect()
	if err != nil {
		if bounded.Err() != nil {
			return nil, bounded.Err()
		}
		return nil, err
	}
	if err := bounded.Err(); err != nil {
		connection.Close()
		return nil, err
	}
	state, err := connection.TLSConnectionState()
	if err != nil || !connection.AuthRequired() || !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		connection.Close()
		return nil, errors.New("global worker connection did not establish authenticated verified TLS 1.3")
	}
	if !dialer.finish(true) {
		connection.Close()
		if err := bounded.Err(); err != nil {
			return nil, err
		}
		return nil, context.Canceled
	}
	transferred = true
	return connection, nil
}
