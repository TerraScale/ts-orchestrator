//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/nats-io/nats.go/jetstream"
)

type artifactLookupHook struct {
	ArtifactStore
	before func()
}

func (s artifactLookupHook) GetInfo(ctx context.Context, name string, opts ...jetstream.GetObjectInfoOpt) (*jetstream.ObjectInfo, error) {
	s.before()
	return s.ArtifactStore.GetInfo(ctx, name, opts...)
}

// A desired-generation update leaves the old member running during artifact
// fetch. If its mount disappears then, preparation must stop it before repair.
func TestTerraBaseDataVolumeLostDuringArtifactUpdate(t *testing.T) {
	for _, stopFails := range []bool{false, true} {
		name := "stops before repair"
		if stopFails {
			name = "stop error aborts repair"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			const uuid = "0f8fad5b-d9cb-469f-a165-70867728950e"
			const volumeID = "ocid1.volume.oc1..node-a"
			mounted, filesystem := true, uuid
			_, confirms := fakeDataVolume(t, &mounted, &filesystem)
			var mountPresent atomic.Bool
			mountPresent.Store(true)
			verifyDataMount = func(string, WorkloadIdentity) error {
				if !mountPresent.Load() {
					return errors.New("mount lost during artifact fetch")
				}
				return nil
			}

			c, conn, store, _, controllerKey := testController(t)
			public, hostKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Register(ctx, Registration{Cell: "gru", Node: "node-a", Environment: "production",
				Roles: []string{terrabase.Role}, PublicKey: base64.StdEncoding.EncodeToString(public),
				NATSUserPublicKey: testNATSUserKey("node-a"), Generation: 1, TerraBaseDataVolumeID: volumeID}); err != nil {
				t.Fatal(err)
			}
			artifact := []byte("terrabase generation update")
			hash := sha256.Sum256(artifact)
			digest := hex.EncodeToString(hash[:])
			if _, err := store.PutBytes(ctx, "sha256-"+digest, artifact); err != nil {
				t.Fatal(err)
			}
			d := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: terrabase.Role,
				Digest: digest, Generation: 1, AuthorityEpoch: 1, Env: map[string]string{
					terrabase.EnvPeerPort: "9443", terrabase.EnvPeers: "node-a=10.0.0.1:9443"}}
			if _, err := c.ApplyDesired(ctx, d); err != nil {
				t.Fatal(err)
			}
			oldFingerprint, err := desiredFingerprint(d)
			if err != nil {
				t.Fatal(err)
			}
			d.Generation = 2
			if _, err := c.ApplyDesired(ctx, d); err != nil {
				t.Fatal(err)
			}
			caPEM, caKey, err := terrabase.NewCA("gru", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			caRoot := t.TempDir()
			for name, data := range map[string][]byte{"ca.pem": caPEM, "ca.key": caKey} {
				if err := os.WriteFile(filepath.Join(caRoot, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if c.terraBaseCA, err = terrabase.LoadCA(filepath.Join(caRoot, "ca.pem"), filepath.Join(caRoot, "ca.key")); err != nil {
				t.Fatal(err)
			}
			runner := &failingRunner{memoryRunner: &memoryRunner{observed: map[string]Observation{
				terrabase.Role: {Role: terrabase.Role, Digest: digest, Fingerprint: oldFingerprint, Running: true}}}}
			stopErr := errors.New("cgroup kill failed")
			if stopFails {
				runner.stopErr = stopErr
			}
			fetchObserved := make(chan bool, 1)
			var loseMount sync.Once
			c.artifacts = artifactLookupHook{ArtifactStore: store, before: func() {
				loseMount.Do(func() {
					observed, _ := runner.Observe(ctx, terrabase.Role)
					fetchObserved <- observed.Running
					mountPresent.Store(false)
				})
			}}

			socket := filepath.Join(t.TempDir(), "init.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var repairs, unsafeRepairs atomic.Int32
			initializerDone := make(chan struct{})
			go func() {
				defer close(initializerDone)
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				defer connection.Close()
				repairs.Add(1)
				observed, _ := runner.Observe(ctx, terrabase.Role)
				if observed.Running {
					unsafeRepairs.Add(1)
				}
				var size [4]byte
				if _, err := io.ReadFull(connection, size[:]); err != nil {
					return
				}
				wire := make([]byte, binary.BigEndian.Uint32(size[:]))
				if _, err := io.ReadFull(connection, wire); err != nil {
					return
				}
				if observed.Running || !bytes.Equal(wire, terraBaseDataRequest) {
					_, _ = connection.Write([]byte{1})
					return
				}
				mountPresent.Store(true)
				_, _ = connection.Write([]byte{0})
			}()

			controllerDone := make(chan error, 1)
			go func() { controllerDone <- c.Run(ctx) }()
			defer func() { cancel(); <-controllerDone }()
			select {
			case <-c.Ready():
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			agent, err := NewAgent(AgentConfig{Cell: "gru", Node: "node-a", Environment: "production",
				Roles: []string{terrabase.Role}, Conn: conn, Identity: hostKey,
				NATSUserPublicKey: testNATSUserKey("node-a"), ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey),
				ClockCheck: func() error { return nil }, Runner: runner, WorkloadIdentity: testAgentIdentity(),
				InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t),
				TerraBaseRoot: filepath.Join(traversableTempDir(t), "terrabase"), TerraBaseDataVolume: true,
				TerraBaseDataVolumeID: volumeID, VolumeInitSocket: socket})
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.acquire(ctx); err != nil {
				t.Fatal(err)
			}
			agent.terraBaseVolumeConfirmed, agent.terraBaseVolumeChecked = uuid, time.Now()
			agent.terraBase[terrabase.Role] = terraBaseMember{}
			err = agent.reconcile(ctx, terrabase.Role)
			select {
			case running := <-fetchObserved:
				if !running {
					t.Fatal("old member was stopped before the artifact fetch lost its mount")
				}
			default:
				t.Fatalf("artifact fetch was not reached: %v", err)
			}
			listener.Close()
			select {
			case <-initializerDone:
			case <-ctx.Done():
				t.Fatalf("initializer did not finish: %v; reconcile: %v", ctx.Err(), err)
			}
			if runner.stops != 1 || unsafeRepairs.Load() != 0 {
				t.Fatalf("stops=%d, repair contacts while running=%d, reconcile=%v", runner.stops, unsafeRepairs.Load(), err)
			}
			observed, _ := runner.Observe(ctx, terrabase.Role)
			if stopFails {
				if !errors.Is(err, stopErr) || repairs.Load() != 0 || *confirms != 0 || runner.applied != 0 || !observed.Running {
					t.Fatalf("failed stop: err=%v repairs=%d confirms=%d applies=%d observed=%+v",
						err, repairs.Load(), *confirms, runner.applied, observed)
				}
				if _, tracked := agent.terraBase[terrabase.Role]; !tracked {
					t.Fatal("failed stop forgot the member that may still run")
				}
			} else {
				fingerprint, _ := desiredFingerprint(d)
				if err != nil || repairs.Load() != 1 || *confirms != 1 || runner.applied != 1 ||
					!observed.Running || observed.Fingerprint != fingerprint || agent.terraBaseVolumeConfirmed != uuid {
					t.Fatalf("repaired update: err=%v repairs=%d confirms=%d applies=%d observed=%+v confirmed=%q",
						err, repairs.Load(), *confirms, runner.applied, observed, agent.terraBaseVolumeConfirmed)
				}
			}
		})
	}
}
