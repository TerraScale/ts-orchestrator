package natscell

import (
	"fmt"
	"math/rand/v2"
	"net"
	"testing"
)

func freeClientPort(t *testing.T) int {
	t.Helper()
	return freeClientPorts(t, 1)[0]
}

// freeClientPorts returns distinct free ports below the kernel's ephemeral
// range (32768+). Outbound connections and :0 listeners never receive these,
// so a stopped broker can rebind its port while parallel tests run.
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
		for attempt := 0; ; attempt++ {
			if attempt == 1000 {
				t.Fatal("no free port below the ephemeral range")
			}
			port := 20000 + rand.IntN(12000)
			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				continue
			}
			listeners = append(listeners, listener)
			ports[index] = port
			break
		}
	}
	return ports
}
