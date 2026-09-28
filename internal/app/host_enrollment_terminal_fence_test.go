package app

import (
	"context"
	"errors"
	"testing"
	"time"
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestFenceTerminalGrantsRetriesAfterPartialPreMarkerFailure(t *testing.T) {
	ctx := t.Context()
	broker, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		broker.Shutdown()
		broker.WaitForShutdown()
		t.Fatal("embedded NATS did not start")
	}
	t.Cleanup(func() {
		broker.Shutdown()
		broker.WaitForShutdown()
	})

	conn, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := hostenroll.OpenGrantStore(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}

	intent := terminalFenceRetryIntent()
	fencer := &terminalFenceRetryFencer{epoch: 7, failGuardAt: 2}
	enrollment := &managedHostEnrollment{cell: intent.Cell, region: oci.RegionGRU,
		owner: intent.Owner, generation: intent.FleetGeneration, grants: grants,
		members: terminalFenceRetryMembers{}, fencer: fencer}
	if err := enrollment.fenceTerminalGrants(ctx, fencer.epoch, intent); err == nil {
		t.Fatal("first pre-marker fence unexpectedly completed")
	}
	first, firstRevision, err := grants.Read(ctx, intent.Targets[0].InstanceID)
	if err != nil || !terminalFenceRetryTombstone(first, intent, intent.Targets[0]) {
		t.Fatalf("first target tombstone was not durable before second-target failure: grant=%+v err=%v", first, err)
	}
	if _, _, err := grants.Read(ctx, intent.Targets[1].InstanceID); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("failed target was unexpectedly fenced: err=%v", err)
	}

	if err := enrollment.fenceTerminalGrants(ctx, fencer.epoch, intent); err != nil {
		t.Fatalf("retrying the exact same pre-marker operation: %v", err)
	}
	firstRetry, firstRetryRevision, err := grants.Read(ctx, intent.Targets[0].InstanceID)
	if err != nil || firstRetryRevision != firstRevision || !terminalFenceRetryTombstone(firstRetry, intent, intent.Targets[0]) {
		t.Fatalf("retry did not preserve the first exact tombstone: grant=%+v revision=%d err=%v",
			firstRetry, firstRetryRevision, err)
	}
	second, _, err := grants.Read(ctx, intent.Targets[1].InstanceID)
	if err != nil || !terminalFenceRetryTombstone(second, intent, intent.Targets[1]) {
		t.Fatalf("retry did not fence the remaining target: grant=%+v err=%v", second, err)
	}
	if err := enrollment.verifyTerminalGrantFence(ctx, intent); err != nil {
		t.Fatalf("read-only exact grant fence proof: %v", err)
	}
}

func terminalFenceRetryIntent() authority.TerminalIntent {
	return authority.TerminalIntent{
		Cell: "gru", DatabaseID: "db-terminal-retry", PartitionID: "partition-terminal-retry",
		Region: string(oci.RegionGRU), Owner: "regional-owner", CompartmentID: "ocid1.compartment.oc1..owned",
		FleetGeneration: 1, PlacementGeneration: 1,
		PlacementPayloadDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		OperationID:            "terminal-retry", Nonce: uuid.New().String(), Targets: []authority.TerminalTarget{
			{SeatID: "seat-a", MemberID: "member-a", HostCreateKey: "host-create-a", DataCreateKey: "data-create-a",
				InstanceID: "ocid1.instance.oc1..terminal-a", BootVolumeID: "ocid1.bootvolume.oc1..terminal-a"},
			{SeatID: "seat-b", MemberID: "member-b", HostCreateKey: "host-create-b", DataCreateKey: "data-create-b",
				InstanceID: "ocid1.instance.oc1..terminal-b", BootVolumeID: "ocid1.bootvolume.oc1..terminal-b"},
		},
		DisposableWorkload: true, AcknowledgePermanentDataLoss: true, AuthorizeForcedStop: true,
	}
}

func terminalFenceRetryTombstone(grant hostenroll.Grant, intent authority.TerminalIntent,
	target authority.TerminalTarget,
) bool {
	return grant.SchemaVersion == 1 && grant.InstanceID == target.InstanceID &&
		grant.CreateKey == target.HostCreateKey && grant.Disabled &&
		grant.TerminalOperationID == intent.OperationID && len(grant.Request) == 0 &&
		grant.DescriptorSHA256 == ""
}

type terminalFenceRetryMembers struct{}

func (terminalFenceRetryMembers) ReadMember(context.Context, string, string, string) (placement.VersionedMemberState, error) {
	return placement.VersionedMemberState{}, errors.New("tombstone verification should not require an enrolled member")
}

type terminalFenceRetryFencer struct {
	epoch       uint64
	guardCalls  int
	failGuardAt int
}

func (fencer *terminalFenceRetryFencer) Current() authority.Snapshot {
	return authority.Snapshot{Scope: "gru", CandidateID: "terminal-test", OwnerID: "terminal-test",
		Leader: true, Ready: true, Epoch: fencer.epoch, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}
}

func (fencer *terminalFenceRetryFencer) Guard(ctx context.Context, epoch uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if epoch != fencer.epoch {
		return authority.ErrFenced
	}
	fencer.guardCalls++
	if fencer.guardCalls == fencer.failGuardAt {
		return errors.New("injected second-target guard failure")
	}
	return nil
}

func (*terminalFenceRetryFencer) ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error) {
	return authority.LogEntry{}, authority.ErrNotFound
}

func (*terminalFenceRetryFencer) ListPendingEnrollmentEffects(context.Context,
	authority.WorkloadScope,
) ([]authority.EnrollmentEffect, error) {
	return nil, nil
}

func (*terminalFenceRetryFencer) SettleEnrollmentEffect(context.Context, uint64, authority.WorkloadScope,
	string, string, uint64,
) (uint64, error) {
	return 0, errors.New("unexpected enrollment effect settlement")
}

func (*terminalFenceRetryFencer) SettleFencedEnrollmentEffect(context.Context, uint64, authority.WorkloadScope,
	string, string, uint64, func(context.Context) error,
) (uint64, error) {
	return 0, errors.New("unexpected prior-epoch effect settlement")
}
