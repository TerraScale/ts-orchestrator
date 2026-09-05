//go:build sandboxvm && linux

package vmqualruntime

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestKernelListenerObservationTCPAndUDP(t *testing.T) {
	for _, protocol := range []string{"tcp4", "udp4"} {
		t.Run(protocol, func(t *testing.T) {
			var address string
			var closeSocket func() error
			if protocol == "tcp4" {
				listener, err := net.Listen(protocol, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address, closeSocket = listener.Addr().String(), listener.Close
			} else {
				listener, err := net.ListenPacket(protocol, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address, closeSocket = listener.LocalAddr().String(), listener.Close
			}
			t.Cleanup(func() { _ = closeSocket() })
			if exists, err := kernelListenerExists(context.Background(), address); err != nil || !exists {
				t.Fatalf("live %s socket: exists=%v error=%v", protocol, exists, err)
			}
			if err := closeSocket(); err != nil {
				t.Fatal(err)
			}
			if exists, err := kernelListenerExists(context.Background(), address); err != nil || exists {
				t.Fatalf("closed %s socket: exists=%v error=%v", protocol, exists, err)
			}
		})
	}
}

func TestKernelListenerObservationFailsClosed(t *testing.T) {
	target := netip.MustParseAddrPort("127.0.0.1:123")
	for _, input := range []string{"", "unrecognized\n", "local_address\ninvalid\n", "local_address\n0: ZZZZZZZZ:007B 0 07\n"} {
		if _, err := scanKernelListeners(context.Background(), strings.NewReader(input), target, "udp"); err == nil {
			t.Fatalf("accepted malformed kernel socket table %q", input)
		}
	}
}
