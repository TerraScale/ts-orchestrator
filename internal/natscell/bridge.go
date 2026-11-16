package natscell

import (
	"net"
	"sync"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

// Bridge is the only production client TCP listener. Its mTLS handshakes
// happen before NATS INFO; the NATS server itself has DontListen set. The gate
// starts closed and a fence closes every accepted socket, including live ones.
type Bridge struct {
	server    *server.Server
	listener  net.Listener
	listeners map[net.Listener]struct{}
	account   string
	mu        sync.Mutex
	open      bool
	closed    bool
	deadline  time.Time
	sequence  uint64
	floor     uint64
	jwt       string
	pairs     map[*bridgePair]struct{}
	timer     *time.Timer
}

type bridgePair struct {
	external, internal net.Conn
	listener           net.Listener
}
