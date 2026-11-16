package edge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

const maxUpstreamConnections = maxPublicConnections / 2
const maxTaskConnections = maxUpstreamConnections / 2

type upstreamBudget struct {
	mu    sync.Mutex
	total int
	tasks map[string]int
}

func (b *upstreamBudget) take(address string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.total == maxUpstreamConnections {
		return edgeRefusal{http.StatusServiceUnavailable, "upstream_node"}
	}
	if b.tasks[address] == maxTaskConnections {
		return edgeRefusal{http.StatusServiceUnavailable, "upstream_task"}
	}
	if b.tasks == nil {
		b.tasks = map[string]int{}
	}
	b.total++
	b.tasks[address]++
	return nil
}

func (b *upstreamBudget) release(address string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.total--
	b.tasks[address]--
	if b.tasks[address] == 0 {
		delete(b.tasks, address)
	}
}

func (b *upstreamBudget) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total
}

type upstreamConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *upstreamConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (c *upstreamConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (e *Edge) configureUpstream(transport *http.Transport, dial func(context.Context, string, string) (net.Conn, error)) {
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return e.dialBounded(ctx, network, address, dial)
	}
	transport.MaxConnsPerHost = maxTaskConnections
	transport.MaxIdleConns = maxUpstreamConnections / 4
	transport.MaxIdleConnsPerHost = maxSourceConnections
	transport.IdleConnTimeout = 90 * time.Second
}

func (e *Edge) dialBounded(ctx context.Context, network, address string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	if err := e.upstreamSockets.take(address); err != nil {
		return nil, err
	}
	release := func() { e.upstreamSockets.release(address) }
	conn, err := dial(ctx, network, address)
	if err != nil {
		release()
		return nil, err
	}
	return &upstreamConn{Conn: conn, release: release}, nil
}
