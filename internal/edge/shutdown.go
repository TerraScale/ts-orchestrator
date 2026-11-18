package edge

import (
	"errors"
	"net"
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

func (l *shutdownListener) closeConnections() int {
	l.mu.Lock()
	l.closed = true
	connections := make([]*shutdownConn, 0, len(l.connections))
	for conn := range l.connections {
		connections = append(connections, conn)
	}
	l.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
	return len(connections)
}

type shutdownConn struct {
	net.Conn
	listener *shutdownListener
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
