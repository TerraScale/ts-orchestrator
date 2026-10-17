package natscell

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// A bridge terminates mTLS before NATS INFO, so embedded NATS truthfully
// advertises tls_required=false to its in-process side. nats.TLSHandshakeFirst
// would reject that INFO as "secure connection not available". This dialer
// performs the same TLS-first handshake on every initial/reconnect attempt;
// nats.go then runs its native JWT authentication over the established socket.
type tlsFirstDialer struct {
	ctx     context.Context
	config  *tls.Config
	timeout time.Duration
	forward map[string]string
	// reload, when set, supplies the current client certificate per dial so a
	// renewed host certificate is presented on the next reconnect.
	reload func() (*tls.Config, error)
}

func (d *tlsFirstDialer) Dial(network, address string) (net.Conn, error) {
	destination, config := address, d.config
	if d.reload != nil {
		if current, err := d.reload(); err == nil {
			config = current
		}
	}
	if len(d.forward) != 0 {
		if network != "tcp" {
			return nil, errors.New("operator forward requires TCP")
		}
		mapped, ok := d.forward[address]
		if !ok {
			return nil, fmt.Errorf("NATS controller %q has no operator forward", address)
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		destination = mapped
		config = config.Clone()
		config.ServerName = host
	}
	if d.ctx != nil {
		raw, err := (&net.Dialer{Timeout: d.timeout}).DialContext(d.ctx, network, destination)
		if err != nil {
			return nil, err
		}
		// Close the socket directly so cancellation cannot wait on TLS close-notify.
		stop := context.AfterFunc(d.ctx, func() { raw.Close() })
		if config.ServerName == "" {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				stop()
				raw.Close()
				return nil, err
			}
			config = config.Clone()
			config.ServerName = host
		}
		conn := tls.Client(&contextSocket{Conn: raw, stop: stop}, config)
		handshake, cancel := context.WithTimeout(d.ctx, d.timeout)
		err = conn.HandshakeContext(handshake)
		cancel()
		if err != nil {
			stop()
			raw.Close()
			return nil, err
		}
		return conn, nil
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: d.timeout}, network, destination, config)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// A replaced connection must release its lifetime callback before reconnecting.
type contextSocket struct {
	net.Conn
	stop func() bool
}

func (c *contextSocket) Close() error {
	c.stop()
	return c.Conn.Close()
}

func (*tlsFirstDialer) SkipTLSHandshake() bool { return true }

// nats.go treats tls:// as an instruction to wrap TLS after INFO even with a
// custom dialer. Keep every configured endpoint but prevent that second wrap.
func bridgeClientURLs(raw string) string {
	parts := strings.Split(raw, ",")
	for index, part := range parts {
		trimmed := strings.TrimSpace(part)
		if rest, ok := strings.CutPrefix(trimmed, "tls://"); ok {
			parts[index] = "nats://" + rest
		} else {
			parts[index] = trimmed
		}
	}
	return strings.Join(parts, ",")
}
