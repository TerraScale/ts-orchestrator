package edge

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/plannedstop"
)

const shutdownGrace = plannedstop.EdgeShare - plannedstop.DrainWindow

type shutdownListener struct {
	net.Listener
	mu          sync.Mutex
	connections map[*shutdownConn]struct{}
	closed      bool
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

func (l *shutdownListener) httpState(conn net.Conn, state http.ConnState) {
	for {
		switch current := conn.(type) {
		case *tls.Conn:
			conn = current.NetConn()
		case *limitedConn:
			conn = current.Conn
		case *shutdownConn:
			l.mu.Lock()
			current.state = state
			l.mu.Unlock()
			return
		default:
			return
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
}

func (c *shutdownConn) Close() error {
	err := c.Conn.Close()
	c.listener.mu.Lock()
	delete(c.listener.connections, c)
	c.listener.mu.Unlock()
	return err
}

func (c *shutdownConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.ErrUnsupported
}
