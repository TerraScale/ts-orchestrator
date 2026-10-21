package failover

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/storage"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var integrationRequest = Request{DatabaseID: "0000000000FFE2BMB99VWR8Y1A", PartitionID: "00000000002J6YKHD7MH6HKSBC",
	VolumeID: "vol", OldInstanceID: "old", ReplacementInstanceID: "new", AttachKey: "reattach-1"}

func observedAttachment(id, instance, state string) oci.Attachment {
	return oci.Attachment{ID: id, VolumeID: "vol", InstanceID: instance, State: state, ETag: "e-" + id}
}

// The external fleet simulator stores observations and effects over the real
// JetStream protocol. Mount permits use the production OCI journal.
type fleetObservation struct {
	OldState    string
	Attachments []oci.Attachment
}

type protocolFleet struct {
	kv         jetstream.KeyValue
	journal    *oci.KVJournal
	beforeList func()
	loseAck    bool
}

func (fleet *protocolFleet) read(ctx context.Context) (fleetObservation, error) {
	entry, err := fleet.kv.Get(ctx, "observation")
	if err != nil {
		return fleetObservation{}, err
	}
	var observation fleetObservation
	err = json.Unmarshal(entry.Value(), &observation)
	return observation, err
}

func (fleet *protocolFleet) write(ctx context.Context, observation fleetObservation) error {
	data, err := json.Marshal(observation)
	if err != nil {
		return err
	}
	_, err = fleet.kv.Put(ctx, "observation", data)
	return err
}

func (fleet *protocolFleet) FencedInstanceState(ctx context.Context, _ string) (string, error) {
	observation, err := fleet.read(ctx)
	if err == nil && observation.OldState == "" {
		err = errors.New("instance lookup unavailable")
	}
	return observation.OldState, err
}

func (fleet *protocolFleet) RetainedVolumeAttachments(ctx context.Context, _ string) ([]oci.Attachment, error) {
	observation, err := fleet.read(ctx)
	if fleet.beforeList != nil {
		fleet.beforeList()
	}
	return observation.Attachments, err
}

func (fleet *protocolFleet) DetachFencedAttachment(ctx context.Context, request oci.FencedDetachRequest) error {
	observation, err := fleet.read(ctx)
	if err != nil {
		return err
	}
	for index := range observation.Attachments {
		if observation.Attachments[index].ID == request.AttachmentID {
			observation.Attachments[index].State = "DETACHING"
		}
	}
	return fleet.write(ctx, observation)
}

func (fleet *protocolFleet) AttachRetainedVolume(ctx context.Context, request oci.VolumeAttachRequest) (oci.Attachment, error) {
	if !request.AllowDetachedHistory {
		return oci.Attachment{}, errors.New("reattach must preserve detached history")
	}
	observation, err := fleet.read(ctx)
	if err != nil {
		return oci.Attachment{}, err
	}
	attached := observedAttachment(request.IdempotencyKey, request.InstanceID, "ATTACHING")
	if !slices.ContainsFunc(observation.Attachments, func(value oci.Attachment) bool { return value.ID == attached.ID }) {
		observation.Attachments = append(observation.Attachments, attached)
		if err := fleet.write(ctx, observation); err != nil {
			return oci.Attachment{}, err
		}
	}
	if fleet.loseAck {
		return oci.Attachment{}, errors.New("attachment accepted; reply lost")
	}
	return attached, nil
}

func (fleet *protocolFleet) GrantVolumeMountExisting(ctx context.Context, permit oci.VolumeMountPermit) error {
	return fleet.journal.RecordVolumeMountPermit(ctx, oci.VolumeMountPermitRecord{
		Region: oci.Region("gru"), Generation: 1, Owner: "integration", DatabaseID: permit.DatabaseID,
		PartitionID: permit.PartitionID, VolumeID: permit.VolumeID, AttachmentID: permit.AttachmentID,
		ReplacementInstanceID: permit.ReplacementInstanceID, FencedInstanceID: permit.FencedInstanceID,
		FencedInstanceState: "TERMINATED",
	})
}

func (fleet *protocolFleet) HasVolumeMountExisting(ctx context.Context, permit oci.VolumeMountPermit) (bool, error) {
	record, found, err := fleet.journal.GetVolumeMountPermit(ctx, oci.Region("gru"), 1, "integration", permit.VolumeID, permit.AttachmentID)
	return found && record.DatabaseID == permit.DatabaseID && record.PartitionID == permit.PartitionID &&
		record.ReplacementInstanceID == permit.ReplacementInstanceID && record.FencedInstanceID == permit.FencedInstanceID, err
}

type reattachFixture struct {
	directory string
	server    *server.Server
	conn      *nats.Conn
	authority *authority.Runtime
	fleet     *protocolFleet
}

func newReattachFixture(t *testing.T) *reattachFixture {
	t.Helper()
	fixture := &reattachFixture{directory: t.TempDir()}
	t.Cleanup(fixture.close)
	fixture.open(t)
	return fixture
}

func (fixture *reattachFixture) close() {
	if fixture.authority != nil {
		_ = fixture.authority.Close()
	}
	if fixture.conn != nil {
		fixture.conn.Close()
	}
	if fixture.server != nil {
		fixture.server.Shutdown()
		fixture.server.WaitForShutdown()
	}
}

func (fixture *reattachFixture) open(t *testing.T) {
	t.Helper()
	var err error
	fixture.server, err = server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: fixture.directory, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go fixture.server.Start()
	if !fixture.server.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	fixture.conn, err = nats.Connect(fixture.server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	js, err := jetstream.New(fixture.conn)
	if err != nil {
		t.Fatal(err)
	}
	fixture.authority, err = authority.Start(t.Context(), js, authority.Config{Scope: "gru", Replicas: 1,
		DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", CandidateID: "0000000000C66H81REBS854264"})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := oci.OpenJournal(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.CreateOrUpdateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "EXTERNAL_FLEET", Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	fixture.fleet = &protocolFleet{kv: kv, journal: journal}
}

func (fixture *reattachFixture) reattacher() Reattacher {
	boundary, _ := NewOCIBoundary(fixture.fleet)
	return Reattacher{Fencer: fixture.authority, Instances: boundary, Volumes: boundary, Permits: boundary,
		ExpectedEpoch: fixture.authority.Current().Epoch}
}

func (fixture *reattachFixture) seed(t *testing.T, state string, attachments ...oci.Attachment) {
	t.Helper()
	if err := fixture.fleet.write(t.Context(), fleetObservation{OldState: state, Attachments: attachments}); err != nil {
		t.Fatal(err)
	}
}

func requireStep(t *testing.T, fixture *reattachFixture, kind StepKind) Step {
	t.Helper()
	step, err := fixture.reattacher().Step(t.Context(), integrationRequest)
	if err != nil || step.Kind != kind {
		t.Fatalf("step = %+v, %v; want %s", step, err, kind)
	}
	return step
}

func TestIntegrationReattachRecoversPersistentMountWithoutFormatting(t *testing.T) {
	fixture := newReattachFixture(t)
	old := observedAttachment("previous", "old", "ATTACHED")
	for _, state := range []string{"RUNNING", "STOPPED", "TERMINATING", ""} {
		fixture.seed(t, state, old)
		step, err := fixture.reattacher().Step(t.Context(), integrationRequest)
		if step.Kind != StepProveFence || !errors.Is(err, storage.ErrWriterNotFenced) || (state == "") != errors.Is(err, ErrFenceUnobserved) {
			t.Fatalf("state %q: step=%+v err=%v", state, step, err)
		}
		observation, err := fixture.fleet.read(t.Context())
		if err != nil || observation.Attachments[0].State != "ATTACHED" {
			t.Fatalf("unproven writer changed attachment: %+v %v", observation, err)
		}
	}
	fixture.seed(t, "TERMINATED", old)
	requireStep(t, fixture, StepDetach)
	requireStep(t, fixture, StepWaitDetached)
	old.State = "DETACHED"
	fixture.seed(t, "TERMINATED", old)
	fixture.fleet.loseAck = true
	if step, err := fixture.reattacher().Step(t.Context(), integrationRequest); step.Kind != StepAttach || err == nil {
		t.Fatalf("lost attach reply = %+v %v", step, err)
	}
	fixture.close()
	fixture.open(t)
	requireStep(t, fixture, StepWaitAttached)
	attached := observedAttachment(integrationRequest.AttachKey, "new", "ATTACHED")
	fixture.seed(t, "TERMINATED", old, attached)
	requireStep(t, fixture, StepGrantMount)
	requireStep(t, fixture, StepDone)
	fixture.close()
	fixture.open(t)
	requireStep(t, fixture, StepDone)
	observation, err := fixture.fleet.read(t.Context())
	if err != nil || len(observation.Attachments) != 2 {
		t.Fatalf("attach retry duplicated attachment: %+v %v", observation, err)
	}
	permit, found, err := fixture.fleet.journal.GetVolumeMountPermit(t.Context(), oci.Region("gru"), 1, "integration", "vol", attached.ID)
	if err != nil || !found || permit.FencedInstanceState != "TERMINATED" || permit.ReplacementInstanceID != "new" {
		t.Fatalf("persistent mount-only permit = %+v, %v, %v", permit, found, err)
	}
}

func TestIntegrationReattachValidatesWholeInventoryBeforeEffects(t *testing.T) {
	fixture := newReattachFixture(t)
	old := observedAttachment("previous", "old", "ATTACHED")
	wrongVolume := observedAttachment("wrong-volume", "new", "ATTACHED")
	wrongVolume.VolumeID = "another-volume"
	cases := [][]oci.Attachment{
		{old, observedAttachment("foreign", "third", "ATTACHED")},
		{old, wrongVolume},
		{old, observedAttachment("replacement-1", "new", "ATTACHED"), observedAttachment("replacement-2", "new", "ATTACHING")},
		{old, observedAttachment("fault", "new", "FAULTY")},
		{old, observedAttachment("", "new", "ATTACHED")},
		{old, observedAttachment("unknown", "old", "FAULTY")},
	}
	for index, attachments := range cases {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			fixture.seed(t, "TERMINATED", attachments...)
			step, err := fixture.reattacher().Step(t.Context(), integrationRequest)
			if step.Kind != StepHold || !errors.Is(err, storage.ErrVolumeHeld) {
				t.Fatalf("unsafe inventory = %+v %v", step, err)
			}
			observation, err := fixture.fleet.read(t.Context())
			if err != nil || !slices.Equal(observation.Attachments, attachments) {
				t.Fatalf("held inventory changed: %+v %v", observation, err)
			}
		})
	}
}

func TestIntegrationReattachFencesEveryMutationAfterAuthorityLoss(t *testing.T) {
	for _, kind := range []StepKind{StepDetach, StepAttach, StepGrantMount} {
		t.Run(string(kind), func(t *testing.T) {
			fixture := newReattachFixture(t)
			var attachments []oci.Attachment
			switch kind {
			case StepDetach:
				attachments = []oci.Attachment{observedAttachment("previous", "old", "ATTACHED")}
			case StepGrantMount:
				attachments = []oci.Attachment{observedAttachment("current", "new", "ATTACHED")}
			}
			fixture.seed(t, "TERMINATED", attachments...)
			reattacher := fixture.reattacher()
			reattacher.ExpectedEpoch++
			if _, err := reattacher.Step(t.Context(), integrationRequest); !errors.Is(err, authority.ErrFenced) {
				t.Fatalf("stale expected epoch = %v", err)
			}
			fixture.fleet.beforeList = func() {
				if err := fixture.authority.Close(); err != nil {
					t.Fatal(err)
				}
			}
			step, err := fixture.reattacher().Step(t.Context(), integrationRequest)
			if step.Kind != kind || !errors.Is(err, authority.ErrFenced) {
				t.Fatalf("authority loss before %s = %+v %v", kind, step, err)
			}
			observation, err := fixture.fleet.read(t.Context())
			if err != nil || !slices.Equal(observation.Attachments, attachments) {
				t.Fatalf("fenced effect changed observations: %+v %v", observation, err)
			}
			if has, err := fixture.fleet.HasVolumeMountExisting(t.Context(), mountPermit(integrationRequest, Attachment{ID: "current"})); err != nil || has {
				t.Fatalf("fenced effect granted a mount: %v %v", has, err)
			}
		})
	}
}

func TestIntegrationReattachRefusesFollowerAndInvalidRequests(t *testing.T) {
	fixture := newReattachFixture(t)
	old := observedAttachment("previous", "old", "ATTACHED")
	fixture.seed(t, "TERMINATED", old)
	js, err := jetstream.New(fixture.conn)
	if err != nil {
		t.Fatal(err)
	}
	follower, err := authority.Start(t.Context(), js, authority.Config{Scope: "gru", Replicas: 1,
		DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", CandidateID: "000000000082B6JM3GHXKNG2CR"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = follower.Close() })
	reattacher := fixture.reattacher()
	reattacher.Fencer = follower
	if _, err := reattacher.Step(t.Context(), integrationRequest); !errors.Is(err, authority.ErrNotLeader) {
		t.Fatalf("follower mutated volume: %v", err)
	}
	for _, invalid := range []Request{{}, {DatabaseID: integrationRequest.DatabaseID, PartitionID: integrationRequest.PartitionID,
		VolumeID: "vol", OldInstanceID: "old", ReplacementInstanceID: "old", AttachKey: "invalid"}} {
		if _, err := fixture.reattacher().Step(t.Context(), invalid); err == nil {
			t.Fatalf("invalid request was accepted: %+v", invalid)
		}
	}
	observation, err := fixture.fleet.read(t.Context())
	if err != nil || !slices.Equal(observation.Attachments, []oci.Attachment{old}) {
		t.Fatalf("refused request changed volume: %+v %v", observation, err)
	}
}
