package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func rootKeys(keys ...ed25519.PrivateKey) []ed25519.PrivateKey { return keys }

func newRootKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private
}

// signTestRotation signs the statement that replaces base's roots with next.
func signTestRotation(t *testing.T, id trust.ChainIdentity, base trust.VerifiedRoots, next []ed25519.PrivateKey,
	signers ...ed25519.PrivateKey,
) trust.SignedRotation {
	t.Helper()
	publics := make([]ed25519.PublicKey, 0, len(next))
	for _, key := range next {
		publics = append(publics, key.Public().(ed25519.PublicKey))
	}
	rotation, err := trust.NextRotation(base, publics...)
	if err != nil {
		t.Fatal(err)
	}
	var signed trust.SignedRotation
	now := time.Now().UTC().Truncate(time.Second)
	for _, key := range signers {
		envelope, err := trust.SignRotation(rotation, id, now.Add(-time.Minute), now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		signed.Signatures = append(signed.Signatures, envelope)
	}
	return signed
}

// A controller adopts only a chain that extends its own, and persists it
// before it switches roots, so neither a restart nor a written record can
// return it to the replaced roots.
func TestRootRegistryAdoptsOnlyExtendingChains(t *testing.T) {
	r0, r1, attacker := newRootKey(t), newRootKey(t), newRootKey(t)
	genesis, err := trust.ParseKeyring(r0.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	id := trust.ChainIdentity{DeploymentID: "0000000000EKZ0YK71TYZK31W5", Cell: "gru", Environment: "test"}
	path := filepath.Join(t.TempDir(), "trust", "root-chain.json")
	registry, err := newRootRegistry(genesis, id, trust.RootChain{Version: 1}, path)
	if err != nil {
		t.Fatal(err)
	}
	start := registry.verified
	rotated := trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{signTestRotation(t, id, start, rootKeys(r1), r0, r1)}}
	if err := registry.adopt(rotated); err != nil {
		t.Fatal(err)
	}
	r1ID, _ := trust.KeyID(r1.Public().(ed25519.PublicKey))
	if current := registry.current(); len(current) != 1 || current[r1ID] == nil || len(registry.verified.Historical) != 2 {
		t.Fatalf("after rotation current %v historical %v", current, registry.verified.Historical)
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("persisted chain mode %v", info.Mode())
	}
	persisted, err := trust.DecodeRootChain(wire)
	if err != nil || !persisted.Extends(rotated) || !rotated.Extends(persisted) {
		t.Fatalf("persisted chain %v", err)
	}

	rival := trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{signTestRotation(t, id, start, rootKeys(attacker), r0, attacker)}}
	extended := trust.RootChain{Version: 1, Rotations: append(rotated.Rotations,
		signTestRotation(t, id, registry.verified, rootKeys(attacker), r0, attacker))}
	stripped := trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{{Signatures: rotated.Rotations[0].Signatures[1:]}}}
	for name, chain := range map[string]trust.RootChain{"rollback": {Version: 1}, "fork by the replaced root": rival,
		"extension by the replaced root": extended, "the adopted statement without the old root's signature": stripped} {
		if err := registry.adopt(chain); err == nil {
			t.Errorf("%s adopted", name)
		}
		if current := registry.current(); current[r1ID] == nil {
			t.Fatalf("%s moved the roots", name)
		}
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(again, wire) {
		t.Fatal("a refused chain was persisted")
	}
}

// The leader repairs only an invalid record: a valid newer chain it fails to
// adopt (here its persistence fails) is never overwritten with the older
// adopted chain.
func TestRootRepairNeverRollsBackAValidRecord(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	r0, r1 := newRootKey(t), newRootKey(t)
	genesis, err := trust.ParseKeyring(r0.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	id := trust.ChainIdentity{DeploymentID: "0000000000EKZ0YK71TYZK31W5", Cell: "gru", Environment: "test"}
	// The persisted chain's directory is a file, so every persist fails.
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := newRootRegistry(genesis, id, trust.RootChain{Version: 1}, filepath.Join(blocked, "root-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	registry.fencer = rolloutTestFence{epoch: 7}
	if err := registry.open(t.Context(), js, 1); err != nil {
		t.Fatal(err)
	}
	newer, err := trust.EncodeRootChain(trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{
		signTestRotation(t, id, registry.verified, rootKeys(r1), r0, r1)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.kv.Put(t.Context(), rootChainKey, newer); err != nil {
		t.Fatal(err)
	}
	if err := registry.repair(t.Context()); err == nil || !strings.Contains(err.Error(), "persist") {
		t.Fatalf("repair over a valid newer record: %v", err)
	}
	if entry, err := registry.kv.Get(t.Context(), rootChainKey); err != nil || !bytes.Equal(entry.Value(), newer) {
		t.Fatalf("the valid newer record was replaced: %v", err)
	}
	// An invalid record is rewritten with the adopted chain.
	if _, err := registry.kv.Put(t.Context(), rootChainKey, []byte("{")); err != nil {
		t.Fatal(err)
	}
	if err := registry.repair(t.Context()); err != nil {
		t.Fatal(err)
	}
	if entry, err := registry.kv.Get(t.Context(), rootChainKey); err != nil || string(entry.Value()) != `{"version":1,"rotations":[]}` {
		t.Fatalf("the invalid record was not repaired: %v", err)
	}
}

// TestRootRotationOnARunningController rotates the cell's root through the
// operator path and checks that the controller switches roots without a
// restart or rebuild, and that the replaced root, treated as leaked, can
// neither fork nor extend the chain nor authorize a cell spec.
func TestRootRotationOnARunningController(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	root := t.TempDir()
	port := freeTCPPort(t)
	controllerNKey, controllerSeed := testNKey(t)
	operatorNKey, operatorSeed := testNKey(t)
	testEd25519(t, root, "controller.key")
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	identity := cellspec.Identity{DeploymentID: "0000000000EKZ0YK71TYZK31W5", Cell: "gru", Environment: "test"}
	id := trust.ChainIdentity{DeploymentID: identity.DeploymentID, Cell: identity.Cell, Environment: identity.Environment}
	genesisTrust := newTestSpecTrust(t, root, identity)
	r1, attacker := newRootKey(t), newRootKey(t)
	rotatedTrust := newTestSpecTrustWithRoot(t, root, identity, r1)
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase", "web"}, Environments: []string{"test"}}
	resources := placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 128 << 20}
	controllerConfig := testJSONFile(t, root, "controller.json", Config{Version: ConfigVersion,
		NATS: natscell.Config{Cell: "gru", Instance: "one", Replicas: 1, Lab: true, NKeySeedFile: controllerSeed,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(root, "nats"),
				StoreMaxBytes: 4 << 30, Users: []natscell.NKeyGrant{{PublicKey: controllerNKey, Role: "controller", Global: true},
					{PublicKey: operatorNKey, Role: "operator"}}}},
		Controller: ControllerConfig{CandidateID: "0000000000DV8998ZCQW1J2V2R", ResponseKeyFile: filepath.Join(root, "controller.key"),
			ArtifactStoreMaxBytes: 64 << 20, TrustedSigners: []TrustedSignerConfig{grant},
			Workloads: map[string]WorkloadProfile{"terrabase": {Resources: resources}},
			SpecTrust: genesisTrust.config()},
	})
	operatorConfig := testJSONFile(t, root, "operator.json", Config{Version: ConfigVersion,
		NATS: natscell.Config{Cell: "gru", Instance: "operator", Replicas: 1, Lab: true,
			URL: fmt.Sprintf("nats://127.0.0.1:%d", port), NKeySeedFile: operatorSeed},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")}})
	start := func() (context.CancelFunc, chan error) {
		runCtx, stop := context.WithCancel(ctx)
		output := &readyWriter{ready: make(chan struct{})}
		done := make(chan error, 1)
		go func() { done <- Run(runCtx, []string{"run", "--config", controllerConfig}, output) }()
		select {
		case <-output.ready:
		case err := <-done:
			t.Fatalf("controller exited before ready: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		return stop, done
	}
	stop, done := start()
	defer func() {
		stop()
		<-done
	}()
	operator := func(args ...string) (string, error) {
		var output bytes.Buffer
		err := Run(ctx, append([]string{"operator", args[0], "--config", operatorConfig}, args[1:]...), &output)
		return output.String(), err
	}
	roots := func() rootChainReply {
		t.Helper()
		out, err := operator("trust-roots")
		if err != nil {
			t.Fatal(err)
		}
		var reply rootChainReply
		if err := json.Unmarshal([]byte(out), &reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	writeRotation := func(name string, signed trust.SignedRotation) string {
		wire, err := protocol.EncodeJSON(signed)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, wire, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	set := cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: 1, RequiresBinary: 1,
		Services: []cellspec.Service{{Role: "web", Profile: WorkloadProfile{Resources: resources}}}}

	chainFile := filepath.Join(root, "chain-0.json")
	if got := roots(); got.Sequence != 0 {
		t.Fatalf("genesis %+v", got)
	}
	if _, err := operator("trust-roots", "--out", chainFile); err != nil {
		t.Fatal(err)
	}
	chain, err := trust.DecodeRootChain(mustRead(t, chainFile))
	if err != nil {
		t.Fatal(err)
	}
	base, err := trust.VerifyRootChain(genesisTrust.roots, id, chain)
	if err != nil {
		t.Fatal(err)
	}
	// Each root alone is not enough: the old root must vouch for the new
	// one, and the new one must prove it holds its key.
	for name, signer := range map[string]ed25519.PrivateKey{"old root only": genesisTrust.root, "new root only": r1} {
		path := writeRotation("partial-"+strings.ReplaceAll(name, " ", "-")+".json", signTestRotation(t, id, base, rootKeys(r1), signer))
		if _, err := operator("trust-rotate", "--file", path); err == nil {
			t.Errorf("%s: rotation applied", name)
		}
	}
	serviceGeneration := func() uint64 {
		t.Helper()
		var output bytes.Buffer
		if err := Run(ctx, []string{"service", "list", "--config", operatorConfig}, &output); err != nil {
			t.Fatal(err)
		}
		var listed cellspec.Spec
		if err := json.Unmarshal(output.Bytes(), &listed); err != nil {
			t.Fatal(err)
		}
		return listed.Generation
	}
	// A spec signed under r1 reaches the store before r1 is a root, as on a
	// follower whose spec watch runs ahead of its root watch: it is refused
	// now and adopted when the rotation adds r1.
	probe, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "probe", Replicas: 1, Lab: true,
		URL: fmt.Sprintf("nats://127.0.0.1:%d", port), NKeySeedFile: controllerSeed})
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	sets, err := probe.JetStream().KeyValue(ctx, cellSpecBucket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sets.Put(ctx, cellSpecKey, mustRead(t, rotatedTrust.sign(t, root, set))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := serviceGeneration(); got != 0 {
		t.Fatalf("a spec signed under a root not yet adopted moved the spec to generation %d", got)
	}
	rotation := writeRotation("rotation-1.json", signTestRotation(t, id, base, rootKeys(r1), genesisTrust.root, r1))
	if out, err := operator("trust-rotate", "--file", rotation); err != nil || !strings.Contains(out, `"status":"applied"`) {
		t.Fatalf("rotate: %v\n%s", err, out)
	}
	for deadline := time.Now().Add(10 * time.Second); serviceGeneration() != 1; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the stored spec signed under the new root was not adopted after the rotation")
		}
	}
	if out, err := operator("trust-rotate", "--file", rotation); err != nil || !strings.Contains(out, `"status":"unchanged"`) {
		t.Fatalf("re-apply: %v\n%s", err, out)
	}
	// Re-applying an applied statement still needs its signatures.
	var forgedWrapper trust.SignedRotation
	if err := protocol.DecodeStrict(mustRead(t, rotation), &forgedWrapper, trust.MaxRootChainBytes); err != nil {
		t.Fatal(err)
	}
	forgedWrapper.Signatures = forgedWrapper.Signatures[1:]
	if _, err := operator("trust-rotate", "--file", writeRotation("forged-wrapper.json", forgedWrapper)); err == nil {
		t.Fatal("an applied statement without the old root's signature was accepted")
	}
	r1ID, _ := trust.KeyID(r1.Public().(ed25519.PublicKey))
	if got := roots(); got.Sequence != 1 || len(got.Roots) != 1 || got.Roots[0] != r1ID {
		t.Fatalf("after rotation %+v", got)
	}

	// The controller now verifies with the new root only.
	service := func(path string) (string, error) {
		var output bytes.Buffer
		err := Run(ctx, []string{"service", "apply", "--config", operatorConfig, "--file", path}, &output)
		return output.String(), err
	}
	if _, err := service(genesisTrust.sign(t, root, set)); err == nil {
		t.Fatal("a set delegated by the replaced root was applied")
	}

	// The replaced root leaks. It cannot fork the first rotation, extend the
	// chain, or move the controller with records written straight into the
	// store by a holder of controller credentials.
	fork := writeRotation("fork.json", signTestRotation(t, id, base, rootKeys(attacker), genesisTrust.root, attacker))
	after, err := trust.VerifyRootChain(genesisTrust.roots, id, trust.RootChain{Version: 1,
		Rotations: []trust.SignedRotation{signTestRotation(t, id, base, rootKeys(r1), genesisTrust.root, r1)}})
	if err != nil {
		t.Fatal(err)
	}
	extension := writeRotation("extension.json", signTestRotation(t, id, after, rootKeys(attacker), genesisTrust.root, attacker))
	for name, path := range map[string]string{"fork": fork, "extension": extension} {
		if _, err := operator("trust-rotate", "--file", path); err == nil {
			t.Errorf("leaked root %s applied", name)
		}
	}
	store, err := probe.JetStream().KeyValue(ctx, rootChainBucket)
	if err != nil {
		t.Fatal(err)
	}
	forkWire, err := trust.EncodeRootChain(trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{
		signTestRotation(t, id, base, rootKeys(attacker), genesisTrust.root, attacker)}})
	if err != nil {
		t.Fatal(err)
	}
	adoptedWire, err := store.Get(ctx, rootChainKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{forkWire, []byte(`{"version":1,"rotations":[]}`), []byte("{")} {
		if _, err := store.Put(ctx, rootChainKey, value); err != nil {
			t.Fatal(err)
		}
		// The leader rewrites the record with its adopted chain.
		deadline := time.Now().Add(10 * time.Second)
		for {
			entry, err := store.Get(ctx, rootChainKey)
			if err == nil && bytes.Equal(entry.Value(), adoptedWire.Value()) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("written record %q was not rewritten", value)
			}
			time.Sleep(50 * time.Millisecond)
		}
		if got := roots(); got.Sequence != 1 || got.Roots[0] != r1ID {
			t.Fatalf("a written record moved the roots to %+v", got)
		}
	}
	if out, err := operator("trust-rotate", "--file", rotation); err != nil || !strings.Contains(out, `"status":"unchanged"`) {
		t.Fatalf("re-apply: %v\n%s", err, out)
	}

	// The set delegated by the new root is in force. A set the leaked root
	// signs and writes straight into the store is not adopted.
	if out, err := service(rotatedTrust.sign(t, root, set)); err != nil || !strings.Contains(out, `"status":"unchanged"`) {
		t.Fatalf("set under the new root: %v\n%s", err, out)
	}
	forged := set
	forged.Generation = 2
	if _, err := sets.Put(ctx, cellSpecKey, mustRead(t, genesisTrust.sign(t, root, forged))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := serviceGeneration(); got != 1 {
		t.Fatalf("a set signed by the replaced root was adopted: generation %d", got)
	}
	// The next generation replaces the forged record.
	if out, err := service(rotatedTrust.sign(t, root, forged)); err != nil {
		t.Fatalf("replace the forged record: %v\n%s", err, out)
	}

	// A rotation may not orphan the stored set: r1 -> r2 is refused, while
	// make-before-break (add r2, re-sign the set under r2, drop r1) works.
	r2 := newRootKey(t)
	r2Trust := newTestSpecTrustWithRoot(t, root, identity, r2)
	head := func() trust.VerifiedRoots {
		t.Helper()
		path := filepath.Join(root, fmt.Sprintf("chain-%d.json", time.Now().UnixNano()))
		if _, err := operator("trust-roots", "--out", path); err != nil {
			t.Fatal(err)
		}
		chain, err := trust.DecodeRootChain(mustRead(t, path))
		if err != nil {
			t.Fatal(err)
		}
		verified, err := trust.VerifyRootChain(genesisTrust.roots, id, chain)
		if err != nil {
			t.Fatal(err)
		}
		return verified
	}
	orphaning := writeRotation("orphaning.json", signTestRotation(t, id, head(), rootKeys(r2), r1, r2))
	if _, err := operator("trust-rotate", "--file", orphaning); err == nil || !strings.Contains(err.Error(), "stored cell spec") {
		t.Fatalf("a rotation orphaned the stored set: %v", err)
	}
	both := writeRotation("both.json", signTestRotation(t, id, head(), rootKeys(r1, r2), r1, r2))
	if out, err := operator("trust-rotate", "--file", both); err != nil {
		t.Fatalf("add r2: %v\n%s", err, out)
	}
	resigned := set
	resigned.Generation = 3
	if out, err := service(r2Trust.sign(t, root, resigned)); err != nil {
		t.Fatalf("set under r2: %v\n%s", err, out)
	}
	only := writeRotation("only.json", signTestRotation(t, id, head(), rootKeys(r2), r1, r2))
	if out, err := operator("trust-rotate", "--file", only); err != nil {
		t.Fatalf("drop r1: %v\n%s", err, out)
	}
	r2ID, _ := trust.KeyID(r2.Public().(ed25519.PublicKey))

	// The chain and the set survive a restart.
	stop()
	if err := <-done; err != nil {
		t.Fatalf("controller stop: %v", err)
	}
	stop, done = start()
	if got := roots(); got.Sequence != 3 || len(got.Roots) != 1 || got.Roots[0] != r2ID {
		t.Fatalf("after restart %+v", got)
	}
	if got := serviceGeneration(); got != 3 {
		t.Fatalf("cell spec after restart: generation %d", got)
	}
}
