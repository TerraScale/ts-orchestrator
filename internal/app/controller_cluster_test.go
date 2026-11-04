package app

import (
	"math/rand/v2"
	"net"
	"testing"
)

func reserveControllerPorts(t *testing.T, count int) []int {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			if err := listener.Close(); err != nil {
				t.Errorf("close reserved controller port: %v", err)
			}
		}
	}()
	ports := make([]int, count)
	for index := range ports {
		// Keep restart listeners outside the outbound ephemeral port range.
		var listener *net.TCPListener
		var err error
		for range 100 {
			listener, err = net.ListenTCP("tcp4", &net.TCPAddr{
				IP: net.IPv4(127, 0, 0, 1), Port: 20000 + rand.IntN(12000),
			})
			if err == nil {
				break
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		ports[index] = listener.Addr().(*net.TCPAddr).Port
	}
	return ports
}
