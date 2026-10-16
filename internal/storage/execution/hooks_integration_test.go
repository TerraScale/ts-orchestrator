package execution

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// These adapters simulate missing upstream admission/provider inputs. Authority,
// OCI fleet inspection, JetStream journals and member FileStore are real clients.
type admissionFixture struct {
	binding Binding
	path    string
}

func (s *admissionFixture) VerifyTaskBinding(context.Context, *api.Task) (Binding, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return Binding{}, err
	}
	if string(data) != "qualified" {
		return Binding{}, ErrUnsafe
	}
	return s.binding, nil
}
func (s *admissionFixture) VerifyRemoval(context.Context, *api.Task, Binding) error {
	return errors.New("independent writer stop and final drain evidence unavailable")
}

type volumeFixture struct{ inspect func() }

func (v volumeFixture) InspectVolumeInitialization(context.Context, oci.VolumeInitializationPins) (oci.VolumeInitializationProof, error) {
	if v.inspect != nil {
		v.inspect()
	}
	return oci.VolumeInitializationProof{BootDescriptorSHA256: strings.Repeat("a", 64)}, nil
}

type emptyInventory struct{ oci.Provider }

func (emptyInventory) ListInstances(context.Context, string) ([]oci.CloudInstance, error) {
	return nil, nil
}

func TestExecutorSafetyIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "js")})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS startup")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	var clockHealthy atomic.Bool
	clockHealthy.Store(true)
	auth, err := authority.Start(ctx, js, authority.Config{Scope: "gru", DeploymentID: entityid.Derive("deployment", t.Name()), CandidateID: entityid.Derive("candidate", t.Name()), Replicas: 1, ClockCheck: func() error {
		if !clockHealthy.Load() {
			return authority.ErrClockUnhealthy
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auth.Close() })
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := memberstatus.NewFileStore(filepath.Join(directory, "drain.json"))
	if err != nil {
		t.Fatal(err)
	}
	scope := memberstatus.Scope{ClusterID: strings.Repeat("b", 32), TenantID: entityid.Derive("tenant", t.Name()), DatabaseID: entityid.Derive("database", t.Name()), ShardID: 1, MemberID: entityid.Derive("member", t.Name()), Incarnation: strings.Repeat("c", 32)}
	memberAuthority := memberstatus.Authority{Epoch: auth.Current().Epoch, ConfigurationID: strings.Repeat("d", 64), CertificateSHA256: strings.Repeat("e", 64), TLSLeafSHA256: strings.Repeat("f", 64)}
	client, err := memberstatus.NewClient(filepath.Join(directory, "absent.sock"), scope, memberAuthority, func(context.Context) (memberstatus.ProcessObservation, error) {
		return memberstatus.ProcessObservation{PID: os.Getpid(), UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), KernelStart: "verified-start", Cgroup: "/qualified/member"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	task := &api.Task{ID: "task", ServiceID: "service", NodeID: "node", Annotations: api.Annotations{Labels: map[string]string{"terrascale.role": "terrabase"}}}
	digest, err := TaskSHA256(task)
	if err != nil {
		t.Fatal(err)
	}
	source := &admissionFixture{path: filepath.Join(directory, "admission")}
	if err := os.WriteFile(source.path, []byte("qualified"), 0o600); err != nil {
		t.Fatal(err)
	}
	source.binding = Binding{TaskSHA256: digest, AdmissionSHA256: strings.Repeat("1", 64), Epoch: auth.Current().Epoch, Member: client, DrainStore: store,
		Survivor: memberstatus.Survivor{MemberID: entityid.Derive("survivor", t.Name()), Incarnation: strings.Repeat("3", 32)}, OperationID: entityid.Derive("drain", t.Name()),
		Volume: oci.VolumeInitializationPins{DatabaseID: scope.DatabaseID, PartitionID: entityid.Derive("partition", t.Name()), InstanceID: "ocid1.instance.test", HostCreateKey: entityid.Derive("host", t.Name()), VolumeID: "ocid1.volume.test", AttachmentID: "ocid1.volumeattachment.test", AttachmentETag: "etag", Device: "/dev/oracleoci/oraclevdb", FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4"}}
	hooks := &Hooks{Authority: auth, Volumes: volumeFixture{}, Bindings: source}
	effects := 0
	run := func(before func(context.Context, *api.Task) error) error {
		return hooks.WithTaskEffect(ctx, task, func(effectCtx context.Context) error {
			if err := before(effectCtx, task); err != nil {
				return err
			}
			effects++
			return nil
		})
	}
	for _, before := range []func(context.Context, *api.Task) error{hooks.BeforePrepare, hooks.BeforeStart, hooks.BeforeShutdown, hooks.BeforeRemove} {
		if err := before(ctx, task); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("unheld prehook = %v", err)
		}
		if err := before(ctx, nil); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("nil prehook = %v", err)
		}
	}
	missing := &Hooks{Authority: auth, Volumes: volumeFixture{}}
	if err := missing.WithTaskEffect(ctx, task, func(context.Context) error { effects++; return nil }); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("missing adapter = %v", err)
	}
	if err := run(hooks.BeforePrepare); err != nil {
		t.Fatal(err)
	}
	if err := run(hooks.BeforeStart); err != nil {
		t.Fatal(err)
	}
	if effects != 2 {
		t.Fatalf("prepared effects = %d", effects)
	}
	if err := hooks.WithTaskEffect(ctx, task, func(held context.Context) error {
		changed := task.Copy()
		delete(changed.Annotations.Labels, "terrascale.role")
		if err := hooks.BeforeStart(held, changed); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("changed task labels bypassed binding: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var expired context.Context
	if err := hooks.WithTaskEffect(ctx, task, func(held context.Context) error { expired = held; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := hooks.BeforeStart(expired, task); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("released holder reused: %v", err)
	}
	if err := os.WriteFile(source.path, []byte("missing release or disk/CPU qualification"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(hooks.BeforeStart); err == nil {
		t.Fatal("missing admission accepted")
	}
	if err := os.WriteFile(source.path, []byte("qualified"), 0o600); err != nil {
		t.Fatal(err)
	}
	hooks.Volumes = volumeFixture{inspect: func() { clockHealthy.Store(false) }}
	if err := run(hooks.BeforeStart); !errors.Is(err, authority.ErrClockUnhealthy) && !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("authority loss during volume read = %v", err)
	}
	clockHealthy.Store(true)
	hooks.Volumes = volumeFixture{inspect: func() { source.binding.AdmissionSHA256 = strings.Repeat("2", 64) }}
	if err := run(hooks.BeforeStart); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("changed admission = %v", err)
	}
	hooks.Volumes = volumeFixture{}
	if err := run(hooks.BeforeShutdown); err == nil {
		t.Fatal("unavailable bound member authorized shutdown")
	}
	if _, found, err := store.Load(); err != nil || found {
		t.Fatalf("unavailable member manufactured drain record: found=%v err=%v", found, err)
	}
	if err := run(hooks.BeforeRemove); err == nil {
		t.Fatal("missing writer-stop receipt authorized removal")
	}
	peer, peerDirectory := startDrainPeer(t, peerBinding{Scope: scope, Authority: memberAuthority, Survivor: source.binding.Survivor})
	source.binding.Member = peer
	if err := run(hooks.BeforeShutdown); !errors.Is(err, memberstatus.ErrOutcomeUnknown) {
		t.Fatalf("pending drain reached runtime effect: %v", err)
	}
	record, found, err := store.Load()
	if err != nil || !found {
		t.Fatalf("drain request not persisted before POST: %v", err)
	}
	if err := os.WriteFile(filepath.Join(peerDirectory, "mode"), []byte("lag"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(hooks.BeforeShutdown); err == nil {
		t.Fatal("survivor below final root frontier accepted")
	}
	if err := os.WriteFile(filepath.Join(peerDirectory, "mode"), []byte("complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := memberstatus.NewFileStore(filepath.Join(directory, "drain.json"))
	if err != nil {
		t.Fatal(err)
	}
	source.binding.DrainStore = reopened
	if err := run(hooks.BeforeShutdown); err != nil {
		t.Fatalf("completed verified durable drain: %v", err)
	}
	replay, found, err := reopened.Load()
	if err != nil || !found || replay != record {
		t.Fatalf("recovered drain request changed: %v", err)
	}
	journal, err := oci.OpenJournal(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	config := oci.RegionConfig{Region: oci.RegionGRU, Generation: 7, Endpoint: "https://iaas.sa-saopaulo-1.oraclecloud.com", CompartmentID: "ocid1.compartment.oc1.." + strings.Repeat("a", 52), ImageCompartmentID: "ocid1.compartment.oc1.." + strings.Repeat("b", 52), AvailabilityDomain: "sa-saopaulo-1-AD-1", FaultDomains: []string{"FAULT-DOMAIN-1"}, SubnetID: "ocid1.subnet.oc1.sa-saopaulo-1." + strings.Repeat("a", 52), ImageID: "ocid1.image.oc1.sa-saopaulo-1." + strings.Repeat("a", 52), BootVolumeGB: 50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 32768, Shape: "VM.Standard.E5.Flex", Owner: "orchestrator"}
	fleet, err := oci.NewFleet(config, oci.RegionIntent{SchemaVersion: 1, Generation: 7, BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}}, emptyInventory{}, journal, auth, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	hooks.Volumes = fleet.(oci.VolumeInitializationInspector)
	if err := run(hooks.BeforeStart); !errors.Is(err, oci.ErrForeignResource) {
		t.Fatalf("missing owned volume/host accepted: %v", err)
	}
	if effects != 3 {
		t.Fatalf("unsafe boundary reached %d effects, expected 2 prepared effects + 1 verified drain", effects)
	}
}
