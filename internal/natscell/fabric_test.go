package natscell

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// fabricTarget is how fast a relayed config change must be live in every
// region (TS-562).
const fabricTarget = 30 * time.Second

// TestRelayedCellSpecReachesTheSpokeThroughPartitions links a home and a
// spoke region through the production leafnode contract. A cell spec the
// home relays through TS_GLOBAL_CONTROL reaches the spoke's mirror and its
// follower within the target. During a partition the spoke keeps serving
// its local replica and catches up after the heal. The spoke acts only on
// specs signed for it under its own roots, and nothing written in the
// spoke enters its replica.
func TestRelayedCellSpecReachesTheSpokeThroughPartitions(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	root := t.TempDir()
	topology := HubAndSpoke("gru", []string{"sfo"})
	leafTLS := testBridgeTLS(t, filepath.Join(root, "leaf-tls"))
	gru := newTestRegion(t, filepath.Join(root, "gru"), "gru", topology)
	sfo := newTestRegion(t, filepath.Join(root, "sfo"), "sfo", topology)
	leafPort := freeClientPort(t)
	gru.cfg.Embedded.InterRegion.Listen = &LeafListen{Host: "127.0.0.1", Port: leafPort, TLS: leafTLS}
	proxy := newTCPProxy(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(leafPort)))
	defer proxy.Close()
	sfo.cfg.Embedded.InterRegion.Remotes = []LeafRemote{{
		Peer: "gru", URLs: []string{"nats-leaf://" + proxy.Addr()},
		CredentialsFile: gru.childLeafCredentials(t, "sfo-leaf.creds", "sfo"), PeerAccount: gru.interregionID, TLS: leafTLS,
	}}
	gruRuntime, err := Start(ctx, gru.cfg)
	if err != nil {
		t.Fatalf("start gru: %v", err)
	}
	defer gruRuntime.Close()
	sfoRuntime, err := Start(ctx, sfo.cfg)
	if err != nil {
		t.Fatalf("start sfo: %v", err)
	}
	defer sfoRuntime.Close()
	waitLeafCount(ctx, t, gruRuntime, 1)

	global, err := authority.Start(ctx, gruRuntime.JetStream(), authority.Config{
		Scope: protocol.GlobalScope, CandidateID: "gru-a", Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer global.Close()
	for !global.Current().CanMutate() {
		if ctx.Err() != nil {
			t.Fatal("global authority never became leader")
		}
		time.Sleep(20 * time.Millisecond)
	}
	epoch := global.Current().Epoch
	writer, err := globalcontrol.OpenHome(ctx, gruRuntime.JetStream(), "gru", []string{"sfo"}, 1, global)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := globalcontrol.OpenMirror(ctx, sfoRuntime.JetStream(), "gru", "sfo", 1)
	if err != nil {
		t.Fatal(err)
	}

	// SFO's own roots; GRU never holds them and only relays bytes.
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	identity := cellspec.Identity{DeploymentID: "terrascale-test", Cell: "sfo", Environment: "production"}
	sign := func(id cellspec.Identity, generation uint64, signer ed25519.PrivateKey) []byte {
		t.Helper()
		spec := cellspec.Spec{Schema: cellspec.Schema, Identity: id, Generation: generation, RequiresBinary: 1}
		signerRoots := roots
		if !bytes.Equal(signer, rootPrivate) {
			signerRoots, _ = trust.ParseKeyring(signer.Public().(ed25519.PublicKey))
		}
		wire, err := cellspec.Sign(spec, nil, signerRoots, time.Now(), time.Hour, signer)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	// The follower adopts like a controller: only a generation newer than
	// its current one, and it reports each refused record once.
	adopted := make(chan uint64, 8)
	refused := make(chan error, 8)
	go func() {
		var current, lastRefused uint64
		_ = reader.Follow(ctx, globalcontrol.KindCellSpec, "sfo", time.Second,
			func(_ context.Context, document globalcontrol.Document) {
				verified, err := cellspec.VerifyCurrent(document.Payload, roots, identity, time.Now())
				switch {
				case err != nil && document.Sequence != lastRefused:
					lastRefused = document.Sequence
					refused <- err
				case err == nil && verified.Generation > current:
					current = verified.Generation
					adopted <- current
				}
			})
	}()
	publish := func(wire []byte) time.Time {
		t.Helper()
		if _, err := writer.PutDocument(ctx, epoch, globalcontrol.KindCellSpec, "sfo", wire); err != nil {
			t.Fatal(err)
		}
		return time.Now()
	}
	expectAdopted := func(generation uint64, since time.Time) {
		t.Helper()
		select {
		case got := <-adopted:
			if got != generation {
				t.Fatalf("spoke adopted generation %d, want %d", got, generation)
			}
			if elapsed := time.Since(since); elapsed > fabricTarget {
				t.Fatalf("generation %d took %s to reach the spoke", generation, elapsed)
			} else {
				t.Logf("generation %d live in the spoke after %s", generation, elapsed)
			}
		case err := <-refused:
			t.Fatalf("spoke refused generation %d: %v", generation, err)
		case <-time.After(fabricTarget):
			t.Fatalf("generation %d did not reach the spoke within %s", generation, fabricTarget)
		}
	}
	expectAdopted(1, publish(sign(identity, 1, rootPrivate)))

	// Partition: the home keeps writing, the spoke keeps serving its replica.
	proxy.Close()
	waitLeafCount(ctx, t, gruRuntime, 0)
	waitLeafCount(ctx, t, sfoRuntime, 0)
	second := sign(identity, 2, rootPrivate)
	written := publish(second)
	held, err := reader.Document(ctx, globalcontrol.KindCellSpec, "sfo")
	if err != nil {
		t.Fatalf("spoke cannot read its replica during the partition: %v", err)
	}
	if verified, err := cellspec.VerifyCurrent(held.Payload, roots, identity, time.Now()); err != nil || verified.Generation != 1 {
		t.Fatalf("spoke replica during the partition = %+v, %v", verified.Spec, err)
	}
	select {
	case generation := <-adopted:
		t.Fatalf("generation %d crossed a partitioned link", generation)
	case <-time.After(time.Second):
	}
	proxy.Reopen(t)
	expectAdopted(2, written)
	if time.Since(written) > fabricTarget+5*time.Second {
		t.Fatalf("heal took %s", time.Since(written))
	}

	// Tamper: a spec signed by anything but SFO's roots, or for another
	// cell, arrives through the relay and is refused; SFO keeps generation 2.
	_, rogue, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, wire := range map[string][]byte{
		"unsigned by the roots": sign(identity, 3, rogue),
		"for another cell": sign(cellspec.Identity{DeploymentID: identity.DeploymentID, Cell: "fra",
			Environment: identity.Environment}, 3, rootPrivate),
	} {
		publish(wire)
		select {
		case err := <-refused:
			t.Logf("%s refused: %v", name, err)
		case generation := <-adopted:
			t.Fatalf("%s spec adopted as generation %d", name, generation)
		case <-time.After(fabricTarget):
			t.Fatalf("%s spec never reached the spoke", name)
		}
	}
	// The replica is read-only: a write in the spoke has no stream, and the
	// subject never crosses the link to the home stream.
	forged := sign(identity, 9, rootPrivate)
	if _, err := sfoRuntime.JetStream().Publish(ctx, protocol.GlobalState(string(globalcontrol.KindCellSpec), "sfo"), forged); err == nil {
		t.Fatal("spoke wrote into its read-only replica")
	}
	if err := sfoRuntime.Conn().Publish(protocol.GlobalState(string(globalcontrol.KindCellSpec), "sfo"), forged); err != nil {
		t.Fatal(err)
	}
	if err := sfoRuntime.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if home, err := writer.Document(ctx, globalcontrol.KindCellSpec, "sfo"); err != nil || bytes.Equal(home.Payload, forged) {
		t.Fatalf("a spoke write reached the home stream: %v", err)
	}
	select {
	case generation := <-adopted:
		t.Fatalf("spoke adopted generation %d it wrote itself", generation)
	default:
	}
}
