package authority

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func newIdentityHostR3(t *testing.T) (jetstream.JetStream, []*server.Server) {
	t.Helper()
	var servers []*server.Server
	for index := range 3 {
		routeAddress := "nats-route://127.0.0.1:1"
		if index != 0 {
			routeAddress = "nats-route://" + servers[0].ClusterAddr().String()
		}
		route, err := url.Parse(routeAddress)
		if err != nil {
			t.Fatal(err)
		}
		routes := []*url.URL{route}
		for _, peer := range servers {
			if peer == servers[0] {
				continue
			}
			peerRoute, err := url.Parse("nats-route://" + peer.ClusterAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			routes = append(routes, peerRoute)
		}
		srv, err := server.NewServer(&server.Options{ServerName: fmt.Sprintf("identity-r3-%d", index), Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream"), Cluster: server.ClusterOpts{Name: "identity-r3", Host: "127.0.0.1", Port: -1}, Routes: routes})
		if err != nil {
			t.Fatal(err)
		}
		go srv.Start()
		if !srv.ReadyForConnections(5 * time.Second) {
			t.Fatal("routed NATS failed to start")
		}
		servers = append(servers, srv)
		t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		ready := false
		for _, srv := range servers {
			if srv.JetStreamIsLeader() && len(srv.JetStreamClusterPeers()) == 3 {
				ready = true
			}
		}
		for _, srv := range servers {
			routeInfo, err := srv.Routez(nil)
			if err != nil {
				t.Fatal(err)
			}
			remoteIDs := map[string]bool{}
			for _, route := range routeInfo.Routes {
				remoteIDs[route.RemoteID] = true
			}
			ready = ready && len(remoteIDs) == 2 && srv.JetStreamIsCurrent()
		}
		if ready && servers[0].JetStreamIsCurrent() {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("R3 metadata did not form: ", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	conn, err := nats.Connect(servers[0].ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return js, servers
}
