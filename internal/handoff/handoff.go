// Package handoff keeps a service port answering while its task is replaced.
//
// A task that listens on its own port (its spec names ${PORT}) is served on the
// service port by a forwarder here: the newest ready task takes new
// connections while its predecessor drains, so an update has no gap.
//
// Any other task binds the service port itself; the old task holds it until it
// exits and the new one binds it before its readyPath answers, so edge dials
// wait on a hold for that window.
package handoff

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"
)

var held sync.Map // port (uint16) -> chan struct{}, closed on Release

// Hold makes Wait block for port until Release. The executor calls it before it
// stops a task that has a readyPath.
func Hold(port uint16) { held.LoadOrStore(port, make(chan struct{})) }

// Release ends the hold on port, once its new task answers its readyPath.
func Release(port uint16) {
	if ch, ok := held.LoadAndDelete(port); ok {
		close(ch.(chan struct{}))
	}
}

// Held reports whether port's task is being replaced.
func Held(port uint16) bool {
	_, ok := held.Load(port)
	return ok
}

// HeldPorts lists every port whose task is being replaced.
func HeldPorts() []uint16 {
	var ports []uint16
	held.Range(func(port, _ any) bool {
		ports = append(ports, port.(uint16))
		return true
	})
	slices.Sort(ports)
	return ports
}

// Wait returns once port is not held, deadline passes or ctx ends.
func Wait(ctx context.Context, port uint16, deadline time.Time) {
	ch, ok := held.Load(port)
	if !ok {
		return
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ch.(chan struct{}):
	case <-timer.C:
	case <-ctx.Done():
	}
}

// spliced maps the client port of each forwarded connection (the edge's side)
// to the task port it reaches, while the connection lives.
var spliced sync.Map // uint16 -> uint16

// Spliced returns the task port a forwarded connection from clientPort reaches.
func Spliced(clientPort uint16) (uint16, bool) {
	target, ok := spliced.Load(clientPort)
	if !ok {
		return 0, false
	}
	return target.(uint16), true
}

type forwarder struct {
	targets []uint16 // ready task ports, newest last
	stop    chan struct{}
}

var (
	mu         sync.Mutex
	forwarders = map[uint16]*forwarder{}
)

// bindRetry bounds how late the forwarder takes a service port its
// predecessor (a task that bound it itself) frees.
const bindRetry = 50 * time.Millisecond

// Serve sends new connections on port to target, a ready task's own port,
// until Unserve. The newest served target takes new connections.
func Serve(port, target uint16) {
	mu.Lock()
	defer mu.Unlock()
	f := forwarders[port]
	if f == nil {
		f = &forwarder{stop: make(chan struct{})}
		forwarders[port] = f
		go f.run(port)
	}
	if !slices.Contains(f.targets, target) {
		f.targets = append(f.targets, target)
	}
}

// Unserve stops new connections to target; in-flight ones finish. The last
// target's Unserve frees port.
func Unserve(port, target uint16) {
	mu.Lock()
	defer mu.Unlock()
	f := forwarders[port]
	if f == nil {
		return
	}
	if f.targets = slices.DeleteFunc(f.targets, func(p uint16) bool { return p == target }); len(f.targets) == 0 {
		close(f.stop)
		delete(forwarders, port)
	}
}

func (f *forwarder) target() (uint16, bool) {
	mu.Lock()
	defer mu.Unlock()
	if len(f.targets) == 0 {
		return 0, false
	}
	return f.targets[len(f.targets)-1], true
}

func (f *forwarder) run(port uint16) {
	// Loopback only: the edge is the public path, and every client here looks local to the task.
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	var ln net.Listener
	// The previous task may still hold the port (an update from a spec without ${PORT}).
	for {
		var err error
		if ln, err = net.Listen("tcp", address); err == nil {
			break
		}
		select {
		case <-f.stop:
			return
		case <-time.After(bindRetry):
		}
	}
	Release(port)
	go func() {
		<-f.stop
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			time.Sleep(bindRetry)
			continue
		}
		go f.forward(conn)
	}
}

func (f *forwarder) forward(conn net.Conn) {
	defer conn.Close()
	var backend net.Conn
	var target uint16
	// A target that just left (its Unserve raced this accept) refuses; the next one takes the connection.
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(bindRetry) {
		var ok bool
		if target, ok = f.target(); !ok {
			return
		}
		var err error
		if backend, err = net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(target)))); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return
		}
	}
	defer backend.Close()
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		spliced.Store(uint16(client.Port), target)
		defer spliced.Delete(uint16(client.Port))
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(backend, conn)
		backend.(*net.TCPConn).CloseWrite()
		close(done)
	}()
	_, _ = io.Copy(conn, backend)
	conn.(*net.TCPConn).CloseWrite()
	<-done
}
