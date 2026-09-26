package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"github.com/nats-io/nats.go/jetstream"
)

func TestManagedPlacementEnrollmentThroughSignedOperatorAndCurrentHostSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	broker, err := natscell.Start(ctx, natscell.Config{
		Cell: "gru", Instance: "managed-enrollment", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(root, "nats")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{Scope: "gru", CandidateID: "managed-enrollment", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() {
		t.Fatal("regional authority did not acquire a mutable lease")
	}
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	controllerPublic, controllerPrivate := testEd25519(t, root, "controller.key")
	hostPublic, hostPrivate := testEd25519(t, root, "host.key")
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"production"}, CanRegisterHosts: true, CanPlaceTerraBase: true}
	policy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: "gru"}, Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
	if err != nil {
		t.Fatal(err)
	}
	operatorConfig := testJSONFile(t, root, "operator.json", Config{
		NATS: natscell.Config{Cell: "gru", Instance: "enrollment-operator", Replicas: 1, Lab: true,
			URL: broker.URL()},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")},
	})
	placementSubscription, err := servePlacementAdmission(ctx, broker.Conn(), "gru", policy, control)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = placementSubscription.Unsubscribe() })
	if err := broker.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	apply := func(name string, intent placement.Intent) placementApplyResponse {
		t.Helper()
		path := testJSONFile(t, root, name, intent)
		var output bytes.Buffer
		if err := Run(ctx, []string{"operator", "placement-apply", "--config", operatorConfig, "--intent", path}, &output); err != nil {
			t.Fatalf("signed placement apply: %v", err)
		}
		var receipt placementApplyResponse
		if err := json.Unmarshal(output.Bytes(), &receipt); err != nil || receipt.Sequence == 0 {
			t.Fatalf("placement receipt: %+v, %v", receipt, err)
		}
		return receipt
	}
	intent := testManagedPlacementIntent()
	first := apply("placement-7.json", intent)
	entry, err := control.ReadPlacementIntent(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil || entry.Sequence != first.Sequence || entry.SubjectKey != "db-main.partition-a" {
		t.Fatalf("real authority readback: entry=%+v err=%v", entry, err)
	}
	admitted, err := placement.NewAuthorityIntentReader(control, "gru", oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	store, err := placement.NewJetStreamStore(ctx, broker.JetStream(), "gru", 1, admitted)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := oci.OpenJournal(ctx, broker.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	regionIntent := oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}}
	region := oci.RegionConfig{Region: oci.RegionGRU, Generation: 1,
		Endpoint: "https://iaas.sa-saopaulo-1.oraclecloud.com", CompartmentID: "ocid1.compartment.oc1..owned",
		AvailabilityDomain: "AD-1", FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		SubnetID: "ocid1.subnet.oc1..owned", ImageID: "ocid1.image.oc1..owned",
		Shape: "VM.Standard.E4.Flex", Owner: "regional-owner"}
	provider := &managedEnrollmentProvider{placementSizingProvider: &placementSizingProvider{config: region}}
	fleet, err := oci.NewFleet(region, regionIntent, provider, journal, control, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := newManagedRegistrationVerifier("gru", oci.RegionGRU, region.Owner, region.Generation, control, store, fleet)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := broker.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{
		Bucket: "ENROLLMENT_ARTIFACTS", Storage: jetstream.FileStorage, Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	hostController, err := host.NewController(ctx, host.ControllerConfig{
		Cell: "gru", Conn: broker.Conn(), JS: broker.JetStream(), Artifacts: artifacts,
		StateReplicas: 1, ResponseKey: controllerPrivate, HostMutations: control,
		AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard,
		ManagedRegistrationVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	hostSubscription, err := serveHostEnrollment(ctx, broker.Conn(), "gru", policy, control, hostController)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hostSubscription.Unsubscribe() })
	hostRunDone := make(chan error, 1)
	go func() { hostRunDone <- hostController.Run(ctx) }()
	select {
	case <-hostController.Ready():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	controller, err := placement.StartController(ctx, placement.Config{
		Cell: "gru", Region: oci.RegionGRU, FaultDomains: region.FaultDomains,
		ManagedOwner: region.Owner, FleetGeneration: region.Generation,
		ImageID:     region.ImageID,
		Environment: "production", MemberRole: "terrabase",
		Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 32 << 30},
	}, store, control, fleet, hostController, hostController, testPlacementAdmittedArtifact(intent))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := controller.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	member, err := store.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, "permanent-a")
	if err != nil || member.State.Stage != placement.StageAwaitingHost || member.Revision == 0 || len(provider.launches) != 1 {
		t.Fatalf("durable placement did not launch one OCI host: member=%+v launches=%d err=%v", member, len(provider.launches), err)
	}
	observed, err := fleet.Observe(ctx)
	if err != nil || len(observed) != 1 || observed[0].ID != member.State.InstanceID {
		t.Fatalf("OCI reobservation: instances=%+v err=%v", observed, err)
	}
	row := member.State.CanonicalRosterRow
	roster := intent.CanonicalRoster
	registration := host.Registration{
		Cell: "gru", Node: member.State.HostNode, FailureDomain: row.FailureDomain,
		Environment: "production", Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(hostPublic),
		Generation: 1, Capacity: host.Capacity{CPU: 1, MemoryBytes: int64(member.State.ManagedHostProfile.AllocatableMemoryBytes), DiskBytes: 32 << 30},
		SystemReserveBytes: int64(member.State.ManagedHostProfile.SystemReserveBytes),
		ManagedPlacement: &host.ManagedPlacementBinding{
			DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID, SeatID: row.SeatID,
			IntentGeneration: intent.Generation, IntentPayloadDigest: member.State.IntentPayloadDigest,
			CanonicalRosterDigest: member.State.CanonicalRosterDigest, ManagedHostProfileDigest: member.State.ManagedHostProfileDigest,
		},
		ManagedMember: &host.ManagedMemberBinding{Scope: host.MemberScope{
			ClusterID: roster.ClusterID, TenantID: roster.TenantID, DatabaseID: roster.DatabaseID,
			ShardID: roster.ShardID, MemberID: row.MemberID, Incarnation: row.Incarnation,
		}, HostAttempt: member.State.HostAttempt},
		ManagedOCI: &host.ManagedOCIBinding{Region: string(observed[0].Region), InstanceID: observed[0].ID,
			Owner: observed[0].Owner, FleetGeneration: observed[0].Generation, CreateKey: observed[0].CreateKey},
	}
	register := func(name string, value host.Registration) error {
		t.Helper()
		path := testJSONFile(t, root, name, value)
		return Run(ctx, []string{"operator", "host-register", "--config", operatorConfig, "--registration", path}, &bytes.Buffer{})
	}
	stale := registration
	stalePlacement := *registration.ManagedPlacement
	stalePlacement.IntentPayloadDigest = strings.Repeat("a", 64)
	stale.ManagedPlacement = &stalePlacement
	if err := register("stale-registration.json", stale); err == nil {
		t.Fatal("signed stale placement digest enrolled a host")
	}
	if statuses, err := hostController.ListHosts(ctx); err != nil || len(statuses) != 0 {
		t.Fatalf("rejected registration reached host discovery: statuses=%+v err=%v", statuses, err)
	}
	if err := register("registration.json", registration); err != nil {
		t.Fatalf("signed exact managed host registration: %v", err)
	}
	hostRuntime, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "enrolled-host", Replicas: 1,
		Lab: true, URL: broker.URL(), ClientRole: "host"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hostRuntime.Close() })
	agent, err := host.NewAgent(host.AgentConfig{
		Cell: "gru", Node: registration.Node, Environment: "production", Roles: []string{"terrabase"},
		Conn: hostRuntime.Conn(), Identity: hostPrivate, ControllerPublicKey: controllerPublic,
		Runner: &inMemoryRunner{}, InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t),
		WorkloadIdentity: testHostWorkloadIdentity(),
		PollInterval:     100 * time.Millisecond, ClockCheck: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()
	for {
		statuses, err := hostController.ListHosts(ctx)
		if err == nil && len(statuses) == 1 && statuses[0].Verified && statuses[0].SessionExpiresAt.After(time.Now().Add(5*time.Second)) {
			break
		}
		select {
		case err := <-agentDone:
			t.Fatalf("host agent exited before current session: %v", err)
		case <-ctx.Done():
			t.Fatal("host did not establish current session: ", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err := controller.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	member, err = store.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, row.SeatID)
	if err != nil || member.State.Stage != placement.StagePreparedVolume || member.State.HostGeneration != registration.Generation || provider.volumeCalls != 0 {
		t.Fatalf("current enrolled host did not reach volume preparation: member=%+v volumes=%d err=%v", member, provider.volumeCalls, err)
	}
	superseding := intent
	superseding.Generation++
	second := apply("placement-8.json", superseding)
	if second.Sequence <= first.Sequence {
		t.Fatalf("signed supersession did not advance authority sequence: first=%+v second=%+v", first, second)
	}
	if err := register("replayed-registration.json", registration); err == nil {
		t.Fatal("previously valid signed registration replayed after placement supersession")
	}
	if err := controller.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := store.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, row.SeatID)
	if err != nil || after.Revision != member.Revision || after.State.Stage != placement.StagePreparedVolume || provider.volumeCalls != 0 {
		t.Fatalf("stale enrolled host caused a retained-volume effect: before=%+v after=%+v volumes=%d err=%v", member, after, provider.volumeCalls, err)
	}
	cancel()
	if err := <-hostRunDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("host controller shutdown: %v", err)
	}
	if err := <-agentDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("host agent shutdown: %v", err)
	}
}

type managedEnrollmentProvider struct {
	*placementSizingProvider
	volumeCalls int
}

func (provider *managedEnrollmentProvider) CreateVolume(context.Context, oci.VolumeCreateRequest, map[string]string, string) (oci.CloudVolume, error) {
	provider.volumeCalls++
	return oci.CloudVolume{}, errors.New("unexpected retained-volume creation")
}

var _ oci.Provider = (*managedEnrollmentProvider)(nil)
