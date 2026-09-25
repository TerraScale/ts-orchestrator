package natscell

import (
	"crypto/tls"
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
	config  *tls.Config
	timeout time.Duration
}

func (d *tlsFirstDialer) Dial(network, address string) (net.Conn, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: d.timeout}, network, address, d.config)
	if err != nil {
		return nil, err
	}
	return conn, nil
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
