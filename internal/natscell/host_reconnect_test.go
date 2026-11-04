package natscell

import (
	"net"
	"testing"
)

func freeClientPort(t *testing.T) int {
	t.Helper()
	return freeClientPorts(t, 1)[0]
}

func freeClientPorts(t *testing.T, count int) []int {
	t.Helper()
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			if err := listener.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	ports := make([]int, count)
	for index := range count {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		ports[index] = listener.Addr().(*net.TCPAddr).Port
	}
	return ports
}
