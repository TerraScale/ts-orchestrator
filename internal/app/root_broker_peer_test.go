package app

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestRootBrokerPeerLossAndExtraInputCancelOriginalOperation(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(map[bool]string{false: "disconnect", true: "extra-input"}[extra], func(t *testing.T) {
			address := &net.UnixAddr{Name: filepath.Join(t.TempDir(), "peer.sock"), Net: "unix"}
			listener, err := net.ListenUnix("unix", address)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.DialUnix("unix", nil, address)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			stop := watchRootBrokerPeer(server, cancel)
			defer stop()
			if extra {
				if _, err := client.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = client.Close()
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("original operation survived peer loss or unexpected input")
			}
		})
	}
}
