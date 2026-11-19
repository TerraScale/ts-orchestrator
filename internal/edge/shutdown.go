package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
)

type shutdownListener struct {
	net.Listener
	mu          sync.Mutex
	connections map[*shutdownConn]struct{}
	closed      bool
	draining    bool
	changed     chan struct{}
}

func (l *shutdownListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		conn.Close()
		return nil, net.ErrClosed
	}
	tracked := &shutdownConn{Conn: conn, listener: l}
	if l.connections == nil {
		l.connections = make(map[*shutdownConn]struct{})
	}
	l.connections[tracked] = struct{}{}
	return tracked, nil
}

func trackedConnection(conn net.Conn) *shutdownConn {
	for {
		switch current := conn.(type) {
		case *tls.Conn:
			conn = current.NetConn()
		case *limitedConn:
			conn = current.Conn
		case bufConn:
			conn = current.Conn
		case *shutdownConn:
			return current
		default:
			return nil
		}
	}
}

func (l *shutdownListener) httpState(conn net.Conn, state http.ConnState) {
	if tracked := trackedConnection(conn); tracked != nil {
		l.mu.Lock()
		tracked.state = state
		l.mu.Unlock()
	}
}

func (c *shutdownConn) drainWhenIdle(drain func()) {
	c.listener.mu.Lock()
	c.drain = drain
	draining := c.listener.draining
	c.listener.mu.Unlock()
	if draining {
		drain()
	}
}

func (l *shutdownListener) drainPostgres(ctx context.Context) error {
	l.mu.Lock()
	l.draining = true
	var drains []func()
	for conn := range l.connections {
		if conn.drain != nil {
			drains = append(drains, conn.drain)
		}
	}
	l.mu.Unlock()
	for _, drain := range drains {
		drain()
	}
	for {
		l.mu.Lock()
		if len(l.connections) == 0 {
			l.mu.Unlock()
			return nil
		}
		if l.changed == nil {
			l.changed = make(chan struct{})
		}
		changed := l.changed
		l.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

type shutdownConnections struct {
	Total    int
	New      int
	Active   int
	Idle     int
	Hijacked int
}

func (l *shutdownListener) closeConnections() shutdownConnections {
	l.mu.Lock()
	l.closed = true
	connections := make([]*shutdownConn, 0, len(l.connections))
	remaining := shutdownConnections{Total: len(l.connections)}
	for conn := range l.connections {
		connections = append(connections, conn)
		switch conn.state {
		case http.StateNew:
			remaining.New++
		case http.StateActive:
			remaining.Active++
		case http.StateIdle:
			remaining.Idle++
		case http.StateHijacked:
			remaining.Hijacked++
		}
	}
	l.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
	return remaining
}

type shutdownConn struct {
	net.Conn
	listener *shutdownListener
	state    http.ConnState
	drain    func()
}

func (c *shutdownConn) Close() error {
	err := c.Conn.Close()
	c.listener.mu.Lock()
	delete(c.listener.connections, c)
	if c.listener.changed != nil {
		close(c.listener.changed)
		c.listener.changed = nil
	}
	c.listener.mu.Unlock()
	return err
}

func (c *shutdownConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.ErrUnsupported
}
