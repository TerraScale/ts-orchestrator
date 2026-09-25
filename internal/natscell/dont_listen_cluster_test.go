package natscell

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

// This one-broker lifecycle regression checks the route listener and shutdown;
// the app JWT caller separately proves R3 formation. Production uses
// DontListen so that the gated mTLS bridge owns the sole external client socket.
func TestDontListenStartsRoutesWithoutClientSocketAndShutsDown(t *testing.T) {
	clientPort := freeClientPort(t)
	routePort := freeClientPort(t)
	options := &server.Options{ServerName: "dont-listen-route-test", Host: "127.0.0.1", Port: clientPort,
		DontListen: true, NoLog: true, NoSigs: true,
		Cluster: server.ClusterOpts{Name: "dont-listen-test", Host: "127.0.0.1", Port: routePort}}
	broker, err := server.NewServer(options)
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	ready := broker.ReadyForConnections(3 * time.Second)
	shutdown := make(chan struct{})
	defer func() {
		go func() {
			broker.Shutdown()
			broker.WaitForShutdown()
			close(shutdown)
		}()
		select {
		case <-shutdown:
		case <-time.After(3 * time.Second):
			t.Error("DontListen broker did not complete Shutdown and WaitForShutdown")
		}
	}()
	if !ready {
		t.Fatal("DontListen broker did not start its route listener")
	}
	if broker.Addr() != nil {
		t.Fatal("DontListen broker opened a direct NATS client listener")
	}
	clientAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort))
	if direct, err := net.DialTimeout("tcp", clientAddress, 100*time.Millisecond); err == nil {
		_ = direct.Close()
		t.Fatal("direct NATS client socket is reachable outside the bridge")
	}
	routeAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(routePort))
	route, err := net.DialTimeout("tcp", routeAddress, time.Second)
	if err != nil {
		t.Fatalf("route socket did not start: %v", err)
	}
	_ = route.Close()
}
