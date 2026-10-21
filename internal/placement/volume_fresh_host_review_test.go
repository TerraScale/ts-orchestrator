package placement

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

func TestControllerPreparedVolumeChecksInputsBeforeFreshHost(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*Controller)
		wantErr bool
	}{
		{"artifact unavailable", func(controller *Controller) {
			controller.resolveArtifact = func(context.Context, string, string, string) (AdmittedArtifact, error) {
				return AdmittedArtifact{}, errors.New("artifact is not admitted")
			}
		}, false},
		{"artifact source differs", func(controller *Controller) {
			controller.resolveArtifact = func(_ context.Context, digest, _, _ string) (AdmittedArtifact, error) {
				return AdmittedArtifact{Digest: digest}, nil
			}
		}, false},
		{"volume exceeds OCI limit", func(controller *Controller) {
			controller.config.Resources.DiskBytes = 32768*bytesPerGiB + 1
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, fleet, hosts, controller := preparedVolumeFreshFixture(t, 50)
			before := store.members[permanentMember(oci.RegionGRU)]
			test.prepare(controller)
			fleet.observeFresh = func(int) ([]oci.Instance, error) {
				return nil, errors.New("unready volume inputs triggered fresh OCI reads")
			}
			lists := 0
			hosts.onListHosts = func() { lists++ }
			for range 3 {
				if err := controller.Tick(t.Context()); (err != nil) != test.wantErr {
					t.Fatalf("Tick error = %v, want error=%t", err, test.wantErr)
				}
			}
			if fleet.sweeps != 3 || lists != 3 || fleet.freshCalls != 0 || fleet.imageVerifyCalls != 0 ||
				fleet.volumeCalls != 0 || len(fleet.resizeRequests) != 0 || hosts.desiredWrites != 0 || store.casCalls != 0 ||
				!reflect.DeepEqual(store.members[before.State.MemberID], before) {
				t.Fatalf("unready inputs triggered extra reads or effects: sweeps=%d host lists=%d fresh=%d image=%d volumes=%d resizes=%+v desired=%d CAS=%d",
					fleet.sweeps, lists, fleet.freshCalls, fleet.imageVerifyCalls, fleet.volumeCalls, fleet.resizeRequests, hosts.desiredWrites, store.casCalls)
			}
		})
	}
}

func TestControllerPreparedVolumeRechecksArtifactAfterFreshHost(t *testing.T) {
	store, fleet, hosts, controller := preparedVolumeFreshFixture(t, 50)
	before := store.members[permanentMember(oci.RegionGRU)]
	fleet.observeFresh = func(int) ([]oci.Instance, error) {
		controller.resolveArtifact = func(context.Context, string, string, string) (AdmittedArtifact, error) {
			return AdmittedArtifact{}, errors.New("artifact admission revoked during fresh observation")
		}
		return []oci.Instance{fleet.bound}, nil
	}
	if err := controller.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if fleet.freshCalls != 1 || fleet.volumeCalls != 0 || len(fleet.resizeRequests) != 0 ||
		hosts.desiredWrites != 0 || store.casCalls != 0 || !reflect.DeepEqual(store.members[before.State.MemberID], before) {
		t.Fatalf("revoked artifact caused a volume effect: fresh=%d volumes=%d resizes=%+v desired=%d CAS=%d",
			fleet.freshCalls, fleet.volumeCalls, fleet.resizeRequests, hosts.desiredWrites, store.casCalls)
	}
}

func TestControllerPreparedVolumeRequiresFreshHostBeforeCreateRecoveryAndResize(t *testing.T) {
	readErr := errors.New("fresh OCI read failed")
	for _, test := range []struct {
		name        string
		sizeGB      int64
		withholdAt  int
		failAt      int
		wantFresh   int
		wantVolumes int
		wantResizes int
	}{
		{name: "fresh host permits create", sizeGB: 50, wantFresh: 1, wantVolumes: 1},
		{name: "fresh host permits recovered volume growth", sizeGB: 40, wantFresh: 2, wantVolumes: 1, wantResizes: 1},
		{name: "boot drift after cached sweep withholds create", sizeGB: 50, withholdAt: 1, wantFresh: 1},
		{name: "network drift after cached sweep withholds recovery", sizeGB: 40, withholdAt: 1, wantFresh: 1},
		{name: "drift during recovery withholds resize", sizeGB: 40, withholdAt: 2, wantFresh: 2, wantVolumes: 1},
		{name: "fresh observation error withholds create", sizeGB: 50, failAt: 1, wantFresh: 1},
		{name: "fresh observation error withholds resize", sizeGB: 40, failAt: 2, wantFresh: 2, wantVolumes: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, fleet, hosts, controller := preparedVolumeFreshFixture(t, test.sizeGB)
			before := store.members[permanentMember(oci.RegionGRU)]
			fleet.observeFresh = func(call int) ([]oci.Instance, error) {
				if call == test.failAt {
					return nil, readErr
				}
				if call == test.withholdAt {
					return nil, nil
				}
				return []oci.Instance{fleet.bound}, nil
			}
			err := controller.Tick(t.Context())
			if test.failAt != 0 {
				if !errors.Is(err, readErr) {
					t.Fatalf("Tick error = %v, want fresh observation error", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if fleet.sweeps != 1 || fleet.freshCalls != test.wantFresh || fleet.volumeCalls != test.wantVolumes ||
				len(fleet.resizeRequests) != test.wantResizes || hosts.desiredWrites != 0 {
				t.Fatalf("unexpected effects: sweeps=%d fresh=%d create/recovery=%d resizes=%+v desired=%d",
					fleet.sweeps, fleet.freshCalls, fleet.volumeCalls, fleet.resizeRequests, hosts.desiredWrites)
			}
			if test.withholdAt != 0 || test.failAt != 0 {
				if store.casCalls != 0 || !reflect.DeepEqual(store.members[before.State.MemberID], before) {
					t.Fatalf("withheld host advanced durable placement: CAS=%d member=%+v", store.casCalls, store.members[before.State.MemberID])
				}
			} else if state := store.members[before.State.MemberID].State; store.casCalls != 1 ||
				state.Stage != StagePreparedAttach || state.VolumeID != fleet.volumeResult.ID {
				t.Fatalf("fresh exact host did not advance: CAS=%d state=%+v", store.casCalls, state)
			}
		})
	}
}

func TestControllerPreparedVolumeRejectsFreshHostMismatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*oci.Instance)
	}{
		{"instance sharing bound node", func(instance *oci.Instance) { instance.ID = "other-instance" }},
		{"node", func(instance *oci.Instance) { instance.Node = "other-node" }},
		{"create key", func(instance *oci.Instance) { instance.CreateKey = "other-create-key" }},
		{"private IP", func(instance *oci.Instance) { instance.PrivateIP = "10.0.0.99" }},
		{"region", func(instance *oci.Instance) { instance.Region = oci.RegionSJC }},
		{"failure domain", func(instance *oci.Instance) { instance.FaultDomain = "FAULT-DOMAIN-2" }},
		{"owner", func(instance *oci.Instance) { instance.Owner = "other-owner" }},
		{"fleet generation", func(instance *oci.Instance) { instance.Generation++ }},
		{"ETag missing", func(instance *oci.Instance) { instance.ETag = "" }},
		{"compute profile", func(instance *oci.Instance) { instance.MemoryInGBs++ }},
		{"placement generation", func(instance *oci.Instance) { instance.PlacementGeneration++ }},
		{"boot descriptor", func(instance *oci.Instance) { instance.BootDescriptorSHA256 = "different" }},
		{"duplicate identity", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, fleet, _, controller := preparedVolumeFreshFixture(t, 40)
			before := store.members[permanentMember(oci.RegionGRU)]
			fleet.observeFresh = func(int) ([]oci.Instance, error) {
				instance := fleet.bound
				if test.change == nil {
					return []oci.Instance{instance, instance}, nil
				}
				test.change(&instance)
				return []oci.Instance{instance}, nil
			}
			if err := controller.Tick(t.Context()); err == nil || fleet.freshCalls != 1 || fleet.volumeCalls != 0 ||
				len(fleet.resizeRequests) != 0 || store.casCalls != 0 || !reflect.DeepEqual(store.members[before.State.MemberID], before) {
				t.Fatalf("fresh mismatch caused an effect: err=%v fresh=%d create/recovery=%d resizes=%+v CAS=%d",
					err, fleet.freshCalls, fleet.volumeCalls, fleet.resizeRequests, store.casCalls)
			}
		})
	}
}

func TestControllerPreparedVolumeRechecksCurrentRegistrationBeforeEachEffect(t *testing.T) {
	for _, effect := range []struct {
		name      string
		freshCall int
	}{
		{"create or recover", 1},
		{"resize recovered volume", 2},
	} {
		for _, test := range []struct {
			name      string
			change    func(*placementTestHosts)
			wantError bool
		}{
			{"missing", func(hosts *placementTestHosts) { hosts.statuses = nil }, false},
			{"expired session", func(hosts *placementTestHosts) { hosts.statuses[0].SessionExpiresAt = time.Now().Add(-time.Second) }, false},
			{"generation changed", func(hosts *placementTestHosts) { hosts.statuses[0].Registration.Generation++ }, false},
			{"seat changed", func(hosts *placementTestHosts) { hosts.statuses[0].Registration.ManagedPlacement.SeatID = "other-seat" }, false},
			{"duplicate", func(hosts *placementTestHosts) { hosts.statuses = append(hosts.statuses, hosts.statuses[0]) }, true},
		} {
			t.Run(effect.name+"/"+test.name, func(t *testing.T) {
				store, fleet, hosts, controller := preparedVolumeFreshFixture(t, 40)
				before := store.members[permanentMember(oci.RegionGRU)]
				fleet.observeFresh = func(call int) ([]oci.Instance, error) {
					if call == effect.freshCall {
						test.change(hosts)
					}
					return []oci.Instance{fleet.bound}, nil
				}
				err := controller.Tick(t.Context())
				if (err != nil) != test.wantError || fleet.freshCalls != effect.freshCall ||
					fleet.volumeCalls != effect.freshCall-1 || len(fleet.resizeRequests) != 0 || store.casCalls != 0 ||
					!reflect.DeepEqual(store.members[before.State.MemberID], before) {
					t.Fatalf("stale registration caused an effect: err=%v fresh=%d create/recovery=%d resizes=%+v CAS=%d",
						err, fleet.freshCalls, fleet.volumeCalls, fleet.resizeRequests, store.casCalls)
				}
			})
		}
	}
}

func preparedVolumeFreshFixture(t *testing.T, sizeGB int64) (*placementMemoryStore, *placementVolumeFreshFleet, *placementTestHosts, *Controller) {
	t.Helper()
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seat := Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}
	store := newPlacementMemoryStore(t, intent)
	member := store.members[seat.MemberID]
	member.State.Stage = StagePreparedVolume
	member.State.VolumeID, member.State.AttachmentID = "", ""
	store.members[seat.MemberID] = member
	fleet := &placementVolumeFreshFleet{
		placementTestFleet: &placementTestFleet{instances: attachedInstances(t, intent), volumeResult: &oci.RetainedVolume{
			ID: "volume-created", CreateKey: volumeCreateKey(intent, seat), Region: oci.RegionGRU,
			Owner: "owner-a", Generation: 1, SizeGB: sizeGB,
		}},
		t: t, originalContext: t.Context(),
	}
	fleet.bound = fleet.instances[0]
	hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
	controller := startTestPlacementController(t, store, fleet, hosts, nil)
	return store, fleet, hosts, controller
}

type placementVolumeFreshFleet struct {
	*placementTestFleet
	t               *testing.T
	originalContext context.Context
	bound           oci.Instance
	observeFresh    func(int) ([]oci.Instance, error)
	sweeps          int
	freshCalls      int
}

func (fleet *placementVolumeFreshFleet) Observe(ctx context.Context) ([]oci.Instance, error) {
	fleet.t.Helper()
	if ctx == fleet.originalContext {
		fleet.t.Fatal("periodic sweep stopped using its cached-verification context")
	}
	fleet.sweeps++
	return slices.Clone(fleet.instances), nil
}

func (fleet *placementVolumeFreshFleet) ObserveSelected(ctx context.Context, selectInstance func(id, node string) bool) ([]oci.Instance, error) {
	fleet.t.Helper()
	if ctx != fleet.originalContext {
		fleet.t.Fatal("fresh observation did not receive the unmarked original context")
	}
	if selectInstance == nil || !selectInstance(fleet.bound.ID, "other-node") ||
		!selectInstance("other-instance", fleet.bound.Node) || selectInstance("other-instance", "other-node") {
		return nil, fmt.Errorf("fresh observation did not select exactly the bound instance ID or host node")
	}
	fleet.freshCalls++
	return fleet.observeFresh(fleet.freshCalls)
}

var _ oci.SelectiveObserver = (*placementVolumeFreshFleet)(nil)
