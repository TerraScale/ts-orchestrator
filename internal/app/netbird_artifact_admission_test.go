package app

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/artifact"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

func netbirdArtifactStore(t *testing.T, conn *nats.Conn) jetstream.ObjectStore {
	t.Helper()
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	store, err := js.CreateObjectStore(t.Context(), jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func stageTestNetbirdArtifacts(t *testing.T, store jetstream.ObjectStore, pin client.Pin) {
	t.Helper()
	for architecture, digest := range map[string]string{"arm64": pin.Archives.Arm64.BinarySHA256, "amd64": pin.Archives.AMD64.BinarySHA256} {
		body := netbirdArtifactELF(architecture)
		if netbirdStageDigest(body) != digest {
			t.Fatal("artifact fixture pin does not match its ELF bytes")
		}
		if _, err := store.PutBytes(t.Context(), "sha256-"+digest, body); err != nil {
			t.Fatal(err)
		}
	}
}

func netbirdArtifactELF(architecture string) []byte {
	body := netbirdStageELF("verified " + architecture + " client")
	if architecture == "arm64" {
		binary.LittleEndian.PutUint16(body[18:], 183)
	}
	return body
}

func netbirdArtifactTestPin(t *testing.T) client.Pin {
	t.Helper()
	pin := netbirdStageTestPin(t, netbirdArtifactELF("amd64"))
	pin.Archives.Arm64.BinarySHA256 = netbirdStageDigest(netbirdArtifactELF("arm64"))
	return pin
}

func netbirdArtifactTest(t *testing.T, deniedDigest string) (*netbirdRollout, client.Pin, jetstream.JetStream) {
	t.Helper()
	pin := netbirdArtifactTestPin(t)
	deniedSubject := "$O." + delivery.ArtifactBucket + ".M." + base64.URLEncoding.EncodeToString([]byte("sha256-"+deniedDigest))
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), Users: []*server.User{
		{Username: "admin", Password: "admin"},
		{Username: "admission", Password: "admission", Permissions: &server.Permissions{
			Publish:   &server.SubjectPermission{Allow: []string{">"}, Deny: []string{deniedSubject}},
			Subscribe: &server.SubjectPermission{Allow: []string{">"}},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("artifact NATS did not start")
	}
	connect := func(user string) *nats.Conn {
		t.Helper()
		conn, err := nats.Connect(broker.ClientURL(), nats.UserInfo(user, user), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(conn.Close)
		return conn
	}
	conn := connect("admin")
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "TS_RELEASE_CHANNEL"})
	if err != nil {
		t.Fatal(err)
	}
	r := &netbirdRollout{cell: "gru", conn: conn, fence: &releaseFence{kv: kv, fencer: &fenceLease{}}, services: &specRegistry{}, artifacts: netbirdArtifactStore(t, conn)}
	if deniedDigest != "" {
		r.conn = connect("admission")
	}
	return r, pin, js
}

func TestNetBirdArtifactAdmissionFencesAlreadySelectedCollection(t *testing.T) {
	r, pin, js := netbirdArtifactTest(t, "")
	stageTestNetbirdArtifacts(t, r.artifacts, pin)
	// Warm the receipts, then let the collector select the inactive pin.
	// Cached admission must still fence that already-selected collection.
	r.services.current.NetBird = &cellspec.NetBird{Pin: pin}
	if err := r.artifactsReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.services.current.NetBird = nil
	collector, err := delivery.Open(t.Context(), delivery.Config{Conn: r.conn, JS: js, Cell: "gru", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	guards := 0
	collection, err := collector.CollectArtifacts(t.Context(), r.artifactsInUse, time.Now().Add(24*time.Hour), func(ctx context.Context) error {
		guards++
		if guards == 1 {
			// Both old objects were selected while NetBird was disabled. The
			// automatic admission now reactivates the pin before deletion.
			r.services.current.NetBird = &cellspec.NetBird{Pin: pin}
			return r.artifactsReady(ctx)
		}
		return nil
	})
	if err != nil || guards != 2 || len(collection.Deleted) != 0 {
		t.Fatalf("collector after pin admission: guards=%d collection=%+v err=%v", guards, collection, err)
	}
	for _, digest := range []string{pin.Archives.Arm64.BinarySHA256, pin.Archives.AMD64.BinarySHA256} {
		body, err := r.artifacts.GetBytes(t.Context(), "sha256-"+digest)
		if err != nil || netbirdStageDigest(body) != digest {
			t.Fatalf("admitted binary %s lost its metadata or chunks: %q %v", digest, body, err)
		}
	}
}

func TestNetBirdArtifactAdmissionReusesOnlyUnchangedMetadata(t *testing.T) {
	r, pin, _ := netbirdArtifactTest(t, "")
	stageTestNetbirdArtifacts(t, r.artifacts, pin)
	r.services.current.NetBird = &cellspec.NetBird{Pin: pin}
	var chunkReads atomic.Int64
	_, err := r.conn.Subscribe("$JS.API.STREAM.MSG.GET.OBJ_"+delivery.ArtifactBucket, func(msg *nats.Msg) {
		var request struct {
			Subject string `json:"next_by_subj"`
		}
		if json.Unmarshal(msg.Data, &request) == nil && request.Subject != "" {
			chunkReads.Add(1)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	reads := func() int64 {
		t.Helper()
		if err := r.conn.Flush(); err != nil {
			t.Fatal(err)
		}
		finished := make(chan struct{})
		if err := r.conn.Barrier(func() { close(finished) }); err != nil {
			t.Fatal(err)
		}
		select {
		case <-finished:
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
		return chunkReads.Load()
	}
	if err := r.artifactsReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	verifiedReads := reads()
	if verifiedReads == 0 {
		t.Fatal("initial admission did not verify artifact chunks")
	}
	legacy, err := r.conn.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	digest := pin.Archives.Arm64.BinarySHA256
	name := "sha256-" + digest
	if err := artifact.Touch(t.Context(), legacy, delivery.ArtifactBucket, name); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := r.artifactsReady(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if got := reads(); got != verifiedReads {
		t.Fatalf("unchanged metadata and touches reread chunks: before=%d after=%d", verifiedReads, got)
	}
	// The same digest with a new NUID must be read back rather than inheriting
	// the old receipt, even when its content remains correct.
	if _, err := r.artifacts.PutBytes(t.Context(), name, netbirdArtifactELF("arm64")); err != nil {
		t.Fatal(err)
	}
	if err := r.artifactsReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := reads(); got <= verifiedReads {
		t.Fatal("replacement metadata reused an old verification receipt")
	}
	info, err := r.artifacts.GetInfo(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	info.Size++
	wire, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Publish("$O."+delivery.ArtifactBucket+".M."+base64.URLEncoding.EncodeToString([]byte(name)), wire); err != nil {
		t.Fatal(err)
	}
	if err := r.artifactsReady(t.Context()); err == nil {
		t.Fatal("changed size inherited an old verification receipt")
	}
	body := netbirdArtifactELF("arm64")
	body[len(body)-1] ^= 1
	if _, err := r.artifacts.PutBytes(t.Context(), name, body); err != nil {
		t.Fatal(err)
	}
	if err := r.artifactsReady(t.Context()); err == nil || !errors.Is(err, artifact.ErrInvalid) {
		t.Fatalf("corrupt replacement inherited an old receipt: %v", err)
	}
	if err := r.artifacts.Delete(t.Context(), name); err != nil {
		t.Fatal(err)
	}
	if err := r.artifactsReady(t.Context()); err == nil || !strings.Contains(err.Error(), "not staged") {
		t.Fatalf("deleted object inherited an old receipt: %v", err)
	}
}

func TestNetBirdArtifactReceiptIsBoundToArchitectureAndPin(t *testing.T) {
	r, pin, _ := netbirdArtifactTest(t, "")
	stageTestNetbirdArtifacts(t, r.artifacts, pin)
	r.services.current.NetBird = &cellspec.NetBird{Pin: pin}
	if err := r.artifactsReady(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.services.current.NetBird.Pin.Archives.Arm64.BinarySHA256 = pin.Archives.AMD64.BinarySHA256
	if err := r.artifactsReady(t.Context()); err == nil || !strings.Contains(err.Error(), "ELF64 little-endian arm64") {
		t.Fatalf("changed pin reused another architecture's receipt: %v", err)
	}
}

func TestNetBirdArtifactTouchFailureStopsAdmissionAndDrain(t *testing.T) {
	pin := netbirdArtifactTestPin(t)
	for architecture, digest := range map[string]string{"arm64": pin.Archives.Arm64.BinarySHA256, "amd64": pin.Archives.AMD64.BinarySHA256} {
		t.Run(architecture, func(t *testing.T) {
			r, pin, _ := netbirdArtifactTest(t, digest)
			stageTestNetbirdArtifacts(t, r.artifacts, pin)
			r.services.current.NetBird = &cellspec.NetBird{Pin: pin}
			for _, phase := range []string{"", "drain"} {
				reconciler := network.Reconciler{
					Load: func(context.Context) (network.Record, error) {
						return network.Record{Phase: phase, Node: "node-a", Deadline: time.Now().Add(time.Minute)}, nil
					},
					Status:    func(context.Context, string) (network.Status, error) { return network.Status{Version: "0.79.0"}, nil },
					Preflight: func(ctx context.Context, _ string) error { return r.artifactsReady(ctx) },
					Save: func(context.Context, network.Record) error {
						t.Fatal("failed artifact touch admitted a transaction")
						return nil
					},
					Drain: func(context.Context, string) error { t.Fatal("failed artifact touch drained a node"); return nil },
				}
				ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
				err := reconciler.Tick(ctx, network.Target{Pin: pin}, []string{"node-a"})
				cancel()
				if err == nil || !strings.Contains(err.Error(), "retain NetBird artifact "+digest+" before drain") {
					t.Fatalf("phase %q ignored failed %s metadata touch: %v", phase, architecture, err)
				}
			}
		})
	}
}

func TestNetBirdArtifactVerificationStopsAdmissionAndDrain(t *testing.T) {
	for _, architecture := range []string{"arm64", "amd64"} {
		for _, fault := range []string{"checksum", "architecture", "missing-chunks", "oversize"} {
			t.Run(architecture+"/"+fault, func(t *testing.T) {
				r, pin, _ := netbirdArtifactTest(t, "")
				stageTestNetbirdArtifacts(t, r.artifacts, pin)
				archive, err := pin.Archive(architecture)
				if err != nil {
					t.Fatal(err)
				}
				digest := archive.BinarySHA256
				want := "before drain"
				switch fault {
				case "checksum":
					body := netbirdArtifactELF(architecture)
					body[len(body)-1] ^= 1
					if _, err := r.artifacts.PutBytes(t.Context(), "sha256-"+digest, body); err != nil {
						t.Fatal(err)
					}
				case "architecture":
					other := "arm64"
					if architecture == other {
						other = "amd64"
					}
					digest = netbirdStageDigest(netbirdArtifactELF(other))
					if architecture == "arm64" {
						pin.Archives.Arm64.BinarySHA256 = digest
					} else {
						pin.Archives.AMD64.BinarySHA256 = digest
					}
					want = "ELF64 little-endian " + architecture
				case "missing-chunks", "oversize":
					info, err := r.artifacts.GetInfo(t.Context(), "sha256-"+digest)
					if err != nil {
						t.Fatal(err)
					}
					legacy, err := r.conn.JetStream()
					if err != nil {
						t.Fatal(err)
					}
					if fault == "missing-chunks" {
						if err := legacy.PurgeStream("OBJ_"+delivery.ArtifactBucket, &nats.StreamPurgeRequest{
							Subject: "$O." + delivery.ArtifactBucket + ".C." + info.NUID,
						}, nats.Context(t.Context())); err != nil {
							t.Fatal(err)
						}
						want = "chunk is not visible"
					} else {
						info.Size = client.MaxBinaryBytes + 1
						wire, err := json.Marshal(info)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := legacy.Publish("$O."+delivery.ArtifactBucket+".M."+
							base64.URLEncoding.EncodeToString([]byte(info.Name)), wire, nats.Context(t.Context())); err != nil {
							t.Fatal(err)
						}
						want = "not staged"
					}
				}
				r.services.current.NetBird = &cellspec.NetBird{Pin: pin}
				for _, phase := range []string{"", "drain"} {
					reconciler := network.Reconciler{
						Load: func(context.Context) (network.Record, error) {
							return network.Record{Phase: phase, Node: "node-a", Deadline: time.Now().Add(time.Minute)}, nil
						},
						Status:    func(context.Context, string) (network.Status, error) { return network.Status{Version: "0.79.0"}, nil },
						Preflight: func(ctx context.Context, _ string) error { return r.artifactsReady(ctx) },
						Save: func(context.Context, network.Record) error {
							t.Fatal("invalid artifact admitted or advanced a transaction")
							return nil
						},
						Drain: func(context.Context, string) error { t.Fatal("invalid artifact drained a node"); return nil },
					}
					if err := reconciler.Tick(t.Context(), network.Target{Pin: pin}, []string{"node-a"}); err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("phase %q ignored invalid %s artifact (%s): %v", phase, architecture, fault, err)
					}
				}
			})
		}
	}
}

func TestNetBirdArtifactAdmissionRespectsCanceledContext(t *testing.T) {
	r, pin, _ := netbirdArtifactTest(t, "")
	stageTestNetbirdArtifacts(t, r.artifacts, pin)
	r.services.current.NetBird = &cellspec.NetBird{Pin: pin}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := r.artifactsReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled admission succeeded: %v", err)
	}
}
