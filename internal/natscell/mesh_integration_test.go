package natscell

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

// TestMeshHubRecoveryPreservesLocalServing exercises production JWT accounts,
// mTLS leaves and disk stores; loopback endpoints stand in for the overlay.
func TestMeshHubRecoveryPreservesLocalServing(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	signer, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	signerID, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"gru", "sfo", "fra"}
	regions := map[string]*testRegion{}
	runtimes := map[string]*Runtime{}
	for _, name := range names {
		region := newLinkRegion(t, filepath.Join(root, name), name, signerID)
		region.cfg.CredentialsFile = linkControllerCredentials(t, root, name+"-controller.creds", region)
		regions[name] = region
	}
	leafTLS := testBridgeTLS(t, filepath.Join(root, "leaf-tls"))
	useLinkListener(t, freeClientPort(t))
	regions["gru"].cfg.Embedded.Link = &Link{TLS: leafTLS}
	for _, name := range names[1:] {
		regions[name].cfg.Embedded.Link = &Link{TLS: leafTLS,
			CredentialsFile: linkUserCredentials(t, root, name+"-leaf.creds", signer, regions["gru"].cellID, name)}
	}
	t.Cleanup(func() {
		for _, runtime := range runtimes {
			_ = runtime.Close()
		}
	})
	start := func(name string) {
		t.Helper()
		runtime, err := Start(ctx, regions[name].cfg)
		if err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		runtimes[name] = runtime
		_, err = runtime.Conn().Subscribe(protocol.InterRegionObservabilitySubject(name, protocol.ObservabilityRegionLeaf),
			func(msg *nats.Msg) { _ = msg.Respond([]byte(name)) })
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.Conn().Flush(); err != nil {
			t.Fatal(err)
		}
	}
	probe := func(from, to string) {
		t.Helper()
		subject := protocol.InterRegionObservabilitySubject(to, protocol.ObservabilityRegionLeaf)
		if reply := requestUntil(ctx, t, runtimes[from].Conn(), subject); string(reply.Data) != to {
			t.Fatalf("%s -> %s replied %q", from, to, reply.Data)
		}
	}
	allDirections := func(phase string) {
		t.Helper()
		for _, from := range names {
			for _, to := range names {
				if from != to {
					probe(from, to)
					t.Logf("%s: %s -> %s authenticated reply identifies %s", phase, from, to, to)
				}
			}
		}
	}
	identity := func(name string) string {
		t.Helper()
		var identity string
		for _, file := range []string{storeIdentityFile, nodeIdentityFile} {
			data, err := os.ReadFile(filepath.Join(regions[name].cfg.Embedded.StoreDir, file))
			if err != nil {
				t.Fatal(err)
			}
			identity += string(data)
		}
		return identity
	}
	for _, name := range names {
		start(name)
		_, err := runtimes[name].JetStream().CreateStream(ctx, jetstream.StreamConfig{
			Name: "LOCAL", Subjects: []string{protocol.Regional(name, "local")}, Storage: jetstream.FileStorage,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runtimes[name].JetStream().Publish(ctx, protocol.Regional(name, "local"), []byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	waitLeafCount(ctx, t, runtimes["gru"], 2)
	allDirections("before hub loss")
	identities := map[string]string{}
	serverIDs := map[string]string{}
	for _, name := range names {
		identities[name], serverIDs[name] = identity(name), runtimes[name].server.ID()
	}

	cut := time.Now()
	if err := runtimes["gru"].Close(); err != nil {
		t.Fatal(err)
	}
	if runtimes["gru"].Ready() {
		t.Fatal("stopped hub reports ready")
	}
	for _, name := range names[1:] {
		runtime := runtimes[name]
		waitLeafCount(ctx, t, runtime, 0)
		if !runtime.Ready() || !runtime.FullClusterReady(1) {
			t.Fatalf("%s lost local readiness with the hub stopped", name)
		}
		probe(name, name)
		if _, err := runtime.JetStream().Publish(ctx, protocol.Regional(name, "local"), []byte("hub unavailable")); err != nil {
			t.Fatalf("%s local publish while hub stopped: %v", name, err)
		}
		for _, to := range names {
			if name == to {
				continue
			}
			requestCtx, stop := context.WithTimeout(ctx, 300*time.Millisecond)
			_, err := runtime.Conn().RequestWithContext(requestCtx,
				protocol.InterRegionObservabilitySubject(to, protocol.ObservabilityRegionLeaf), []byte("probe"))
			stop()
			if !errors.Is(err, nats.ErrNoResponders) && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s -> %s with hub stopped: got %v, want unavailable request", name, to, err)
			}
			t.Logf("hub stopped: %s -> %s reports %v; local serving remains ready", name, to, err)
		}
	}

	start("gru")
	waitLeafCount(ctx, t, runtimes["gru"], 2)
	allDirections("after hub restart")
	for _, name := range names {
		runtime := runtimes[name]
		if got := identity(name); got != identities[name] || runtime.CellAccount() != regions[name].cellID {
			t.Fatalf("%s changed persistent node/store/account identity", name)
		}
		if name != "gru" && (runtime.server.ID() != serverIDs[name] || runtime.Conn().Stats().Reconnects != 0) {
			t.Fatalf("%s restarted its regional broker/client during global recovery", name)
		}
		stream, err := runtime.JetStream().Stream(ctx, "LOCAL")
		if err != nil {
			t.Fatal(err)
		}
		message, err := stream.GetMsg(ctx, 1)
		if err != nil || string(message.Data) != name {
			t.Fatalf("%s lost its original local message: %+v, %v", name, message, err)
		}
		if name != "gru" {
			message, err := stream.GetMsg(ctx, 2)
			if err != nil || string(message.Data) != "hub unavailable" {
				t.Fatalf("%s lost its partition-time write: %+v, %v", name, message, err)
			}
		}
		info, err := runtime.JetStream().AccountInfo(ctx)
		if err != nil || info.Domain != name {
			t.Fatalf("%s JetStream domain: %+v, %v", name, info, err)
		}
	}
	t.Logf("hub loss and automatic recovery completed in %s", time.Since(cut).Round(time.Millisecond))
}
