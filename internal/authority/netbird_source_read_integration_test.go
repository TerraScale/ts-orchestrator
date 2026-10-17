package authority

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestNetBirdPublicSourcesAuthenticatedR3(t *testing.T) {
	js, managerJS, denied := newNetBirdSourceR3(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", DeploymentID: entityid.New(), CandidateID: entityid.New(), Replicas: 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	var buckets [2]jetstream.KeyValue
	for index, name := range []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS"} {
		buckets[index], err = js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: name, History: 4, Replicas: 3, Storage: jetstream.FileStorage})
		if err != nil {
			t.Fatal(err)
		}
	}
	specRevision, err := buckets[0].Put(ctx, "current", []byte("public-spec-v1"))
	if err != nil {
		t.Fatal(err)
	}
	rootRevision, err := buckets[1].Put(ctx, "chain", []byte("public-roots-v1"))
	if err != nil {
		t.Fatal(err)
	}
	// Private values follow the public keys so currentness needs a skipped highwater.
	for index := range buckets {
		if _, err := buckets[index].Put(ctx, "material-generations", []byte("private-config-must-not-be-delivered")); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range netBirdPublicSources {
		for _, subject := range []string{"$JS.API.STREAM.MSG.GET." + source.stream, "$JS.API.DIRECT.GET." + source.stream,
			"$JS.API.CONSUMER.DELETE." + source.stream + "." + source.consumer, "$JS.API.CONSUMER.CREATE." + source.stream + "." + source.consumer} {
			if err := managerJS.Conn().Publish(subject, []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			if err := managerJS.Conn().FlushWithContext(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-denied:
			case <-ctx.Done():
				t.Fatalf("manager authority escalation %s was not denied", subject)
			}
		}
	}
	nonce := entityid.New()
	if err := runtime.OpenNetBirdSourceRead(ctx, nonce); err != nil {
		t.Fatal(err)
	}
	reader, err := ConnectNetBirdSourceRead(ctx, managerJS, nonce)
	if err != nil {
		t.Fatal(err)
	}
	var created [2]time.Time
	for index, name := range []string{"KV_TS_SERVICE_SET", "KV_TS_TRUST_ROOTS"} {
		stream, err := js.Stream(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		info, err := stream.Info(ctx)
		if err != nil || info.Created.IsZero() {
			t.Fatalf("public stream creation %s: %v", name, err)
		}
		created[index] = info.Created
	}
	spec, roots, err := reader.Read(ctx)
	if err != nil || !spec.Created.Equal(created[0]) || !roots.Created.Equal(created[1]) || spec.Revision != specRevision || roots.Revision != rootRevision || !bytes.Equal(spec.Wire, []byte("public-spec-v1")) || !bytes.Equal(roots.Wire, []byte("public-roots-v1")) {
		t.Fatalf("current public sources = %+v %+v %v", spec, roots, err)
	}
	if _, err := ConnectNetBirdSourceRead(ctx, managerJS, nonce); err == nil {
		t.Fatal("consumed public source cursor was reused")
	}
	// More than the retained history overwrites the public key without increasing its count.
	for index := range 7 {
		specRevision, err = buckets[0].Put(ctx, "current", fmt.Appendf(nil, "public-spec-v%d", index+2))
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := buckets[0].Put(ctx, "material-generations", []byte("private-config-after-overwrite")); err != nil {
		t.Fatal(err)
	}
	spec, _, err = reader.Read(ctx)
	if err != nil || spec.Revision != specRevision || !bytes.Equal(spec.Wire, []byte("public-spec-v8")) {
		t.Fatalf("overwritten public source = %+v %v", spec, err)
	}
	// KV deletion is a retained marker; it must never authorize the cached value.
	if err := buckets[0].Delete(ctx, "current"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.Read(ctx); err == nil {
		t.Fatal("deleted latest public source remained authorized")
	}
	if _, err := buckets[0].Put(ctx, "current", []byte("public-spec-after-delete")); err != nil {
		t.Fatal(err)
	}
	nonce = entityid.New()
	if err := runtime.OpenNetBirdSourceRead(ctx, nonce); err != nil {
		t.Fatal(err)
	}
	reader, err = ConnectNetBirdSourceRead(ctx, managerJS, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.Read(ctx); err != nil {
		t.Fatalf("fresh cursor could not observe current value after deletion: %v", err)
	}
	if err := runtime.OpenNetBirdSourceRead(ctx, entityid.New()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.Read(ctx); err == nil {
		t.Fatal("replaced public source cursor was adopted")
	}
}

func newNetBirdSourceR3(t *testing.T) (jetstream.JetStream, jetstream.JetStream, <-chan error) {
	t.Helper()
	var servers []*server.Server
	var subjects []string
	for _, source := range netBirdPublicSources {
		subjects = append(subjects, "$JS.API.STREAM.INFO."+source.stream,
			"$JS.API.CONSUMER.INFO."+source.stream+"."+source.consumer,
			"$JS.API.CONSUMER.MSG.NEXT."+source.stream+"."+source.consumer)
	}
	for index := range 3 {
		var routes []*url.URL
		for _, peer := range servers {
			route, err := url.Parse("nats-route://" + peer.ClusterAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			routes = append(routes, route)
		}
		if len(routes) == 0 {
			route, err := url.Parse("nats-route://127.0.0.1:1")
			if err != nil {
				t.Fatal(err)
			}
			routes = []*url.URL{route}
		}
		srv, err := server.NewServer(&server.Options{ServerName: fmt.Sprintf("net-source-r3-%d", index), Host: "127.0.0.1", Port: -1,
			NoLog: true, NoSigs: true, JetStream: true, StoreDir: t.TempDir(), Routes: routes,
			Cluster: server.ClusterOpts{Name: "net-source-r3", Host: "127.0.0.1", Port: -1},
			Users: []*server.User{{Username: "controller", Password: "controller-test-password"},
				{Username: "manager", Password: "manager-test-password", Permissions: &server.Permissions{
					Publish: &server.SubjectPermission{Allow: subjects}, Subscribe: &server.SubjectPermission{Allow: []string{"_NET_SOURCE.>"}}}}}})
		if err != nil {
			t.Fatal(err)
		}
		go srv.Start()
		if !srv.ReadyForConnections(5 * time.Second) {
			t.Fatal("public source broker did not start")
		}
		servers = append(servers, srv)
		t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for {
		ready := false
		for _, srv := range servers {
			if srv.JetStreamIsLeader() && len(srv.JetStreamClusterPeers()) == 3 {
				ready = true
			}
		}
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("public source R3 metadata did not form: ", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	admin, err := nats.Connect(servers[0].ClientURL(), nats.UserInfo("controller", "controller-test-password"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	js, err := jetstream.New(admin)
	if err != nil {
		t.Fatal(err)
	}
	denied := make(chan error, 16)
	manager, err := nats.Connect(servers[0].ClientURL(), nats.UserInfo("manager", "manager-test-password"),
		nats.CustomInboxPrefix("_NET_SOURCE"), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { denied <- err }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	managerJS, err := jetstream.New(manager)
	if err != nil {
		t.Fatal(err)
	}
	return js, managerJS, denied
}
