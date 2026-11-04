package handoff

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// backend answers each connection with its name.
func backend(t *testing.T, name string) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte(name + "\n"))
			conn.Close()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// answer dials port until it answers (the forwarder binds asynchronously).
func answer(t *testing.T, port uint16) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		if err == nil {
			line, err := bufio.NewReader(conn).ReadString('\n')
			conn.Close()
			if err == nil {
				return line[:len(line)-1]
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %d never answered: %v", port, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A predecessor that bound the service port itself keeps it until it exits;
// the forwarder then takes it and releases the edge's hold.
func TestServeTakesPortFromPredecessor(t *testing.T) {
	predecessor, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(predecessor.Addr().(*net.TCPAddr).Port)
	Hold(port)
	Serve(port, backend(t, "new"))
	defer Unserve(port, 0)
	time.Sleep(3 * bindRetry)
	predecessor.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	Wait(ctx, port, time.Now().Add(2*time.Second))
	if ctx.Err() != nil {
		t.Fatal("hold not released once the forwarder bound the port")
	}
	if got := answer(t, port); got != "new" {
		t.Fatalf("got %q, want new", got)
	}
}
