package volume

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

var testSettings = Settings{CompartmentID: "ocid1.compartment.oc1..workload", Zone: testZone,
	KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.vault.key1"}

type testFence struct {
	epoch  atomic.Uint64
	leader atomic.Bool
}

func newFence() *testFence {
	fence := &testFence{}
	fence.epoch.Store(7)
	fence.leader.Store(true)
	return fence
}

func (f *testFence) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: f.leader.Load(), Epoch: f.epoch.Load(), Revision: 1,
		ExpiresAt: time.Now().Add(time.Hour)}
}

func (f *testFence) Guard(_ context.Context, epoch uint64) error {
	if !f.leader.Load() || epoch != f.epoch.Load() {
		return authority.ErrFenced
	}
	return nil
}

// fakeCloud is an in-memory OCI Block Volume API. A create whose retry token
// was seen returns the first volume, as OCI does.
type fakeCloud struct {
	mu          sync.Mutex
	volumes     map[string]CloudVolume
	tokens      map[string]string
	policies    []BackupPolicy
	assignments map[string]Assignment
	calls       []string
	loseCreate  bool
	// onGet changes what GetVolume reads, as a change after a listing does.
	onGet func(*CloudVolume)
	seq   int
}

func newFakeCloud() *fakeCloud {
	return &fakeCloud{volumes: map[string]CloudVolume{}, tokens: map[string]string{}, assignments: map[string]Assignment{}}
}

func (c *fakeCloud) next(kind string) string {
	c.seq++
	return fmt.Sprintf("ocid1.%s.oc1.sa-saopaulo-1.f%d", kind, c.seq)
}

func (c *fakeCloud) mutations() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, call := range c.calls {
		if !strings.HasPrefix(call, "get") && !strings.HasPrefix(call, "list") && !strings.HasPrefix(call, "assignment") {
			out = append(out, call)
		}
	}
	return out
}

// settle finishes every OCI work request.
func (c *fakeCloud) settle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, v := range c.volumes {
		if v.State == "PROVISIONING" {
			v.State = "AVAILABLE"
			c.volumes[id] = v
		}
	}
}

func (c *fakeCloud) put(v CloudVolume) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.volumes[v.ID] = v
}

func (c *fakeCloud) ListVolumes(_ context.Context, compartmentID, zone string) ([]CloudVolume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "list")
	var out []CloudVolume
	for _, v := range c.volumes {
		if v.CompartmentID == compartmentID && v.Zone == zone {
			v.ETag = ""
			out = append(out, v)
		}
	}
	return out, nil
}

func (c *fakeCloud) GetVolume(_ context.Context, id string) (CloudVolume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "get")
	v, ok := c.volumes[id]
	if !ok {
		return CloudVolume{}, ErrGone
	}
	v.Tags = maps.Clone(v.Tags)
	if c.onGet != nil {
		c.onGet(&v)
	}
	return v, nil
}

func (c *fakeCloud) CreateVolume(_ context.Context, request CreateRequest) (CloudVolume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "create")
	if id, ok := c.tokens[request.RetryToken]; ok {
		return c.volumes[id], nil
	}
	v := CloudVolume{ID: c.next("volume"), CompartmentID: request.CompartmentID, Zone: request.Zone,
		SizeGB: request.SizeGB, VPUsPerGB: request.VPUsPerGB, KMSKeyID: request.KMSKeyID,
		State: "PROVISIONING", ETag: "e1", Tags: maps.Clone(request.Tags)}
	c.volumes[v.ID], c.tokens[request.RetryToken] = v, v.ID
	if c.loseCreate {
		return CloudVolume{}, errors.New("create response lost")
	}
	return v, nil
}

func (c *fakeCloud) update(id, etag, call string, change func(*CloudVolume)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, call)
	v, ok := c.volumes[id]
	if !ok || v.ETag != etag {
		return errors.New("precondition failed")
	}
	change(&v)
	v.ETag += "+"
	c.volumes[id] = v
	return nil
}

func (c *fakeCloud) ResizeVolume(_ context.Context, id, etag string, sizeGB int64) error {
	return c.update(id, etag, fmt.Sprintf("resize %d", sizeGB), func(v *CloudVolume) { v.SizeGB = sizeGB })
}

func (c *fakeCloud) SetVolumePerformance(_ context.Context, id, etag string, vpus int) error {
	return c.update(id, etag, fmt.Sprintf("vpus %d", vpus), func(v *CloudVolume) { v.VPUsPerGB = vpus })
}

func (c *fakeCloud) ListBackupPolicies(context.Context, string) ([]BackupPolicy, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "list policies")
	return append([]BackupPolicy(nil), c.policies...), nil
}

func (c *fakeCloud) CreateBackupPolicy(_ context.Context, _ string, policy BackupPolicy, _ string) (BackupPolicy, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "create policy "+policy.Name)
	policy.ID = c.next("volumebackuppolicy")
	c.policies = append(c.policies, policy)
	return policy, nil
}

func (c *fakeCloud) PolicyAssignment(_ context.Context, volumeID string) (Assignment, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "assignment")
	return c.assignments[volumeID], nil
}

func (c *fakeCloud) AssignPolicy(_ context.Context, volumeID, policyID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "assign "+policyID)
	if c.assignments[volumeID].ID != "" {
		return errors.New("volume already has a backup policy")
	}
	c.assignments[volumeID] = Assignment{ID: c.next("volumebackuppolicyassignment"), PolicyID: policyID}
	return nil
}

func (c *fakeCloud) DeleteAssignment(_ context.Context, assignmentID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "unassign")
	for volumeID, assignment := range c.assignments {
		if assignment.ID == assignmentID {
			delete(c.assignments, volumeID)
		}
	}
	return nil
}

func testReconciler(t *testing.T) (*Reconciler, *fakeCloud, *testFence) {
	t.Helper()
	store, _ := testStore(t)
	cloud, fence := newFakeCloud(), newFence()
	return &Reconciler{Store: store, Cloud: cloud, Fencer: fence, Settings: testSettings}, cloud, fence
}

func mustPass(t *testing.T, r *Reconciler) {
	t.Helper()
	if err := r.Pass(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func reload(t *testing.T, r *Reconciler, id string) Volume {
	t.Helper()
	v, err := r.Store.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestReconcilerCreatesAnEncryptedVolumeOnce(t *testing.T) {
	r, cloud, _ := testReconciler(t)
	v := mustCreate(t, r.Store, testVolume(NewID()))

	mustPass(t, r)
	got := reload(t, r, v.ID)
	created, ok := cloud.volumes[got.Status.OCID]
	if !ok || got.Status.State != StateCreating || got.Status.Epoch != 7 {
		t.Fatalf("after the create pass: %+v", got.Status)
	}
	if created.KMSKeyID != testSettings.KMSKeyID || created.VPUsPerGB != 10 || created.SizeGB != 50 ||
		created.Tags[tagCreateKey] != v.ID || created.Tags[tagOwner] != "gru-1" || created.Tags[tagApp] != "terrabase" {
		t.Fatalf("created OCI volume %+v", created)
	}

	cloud.settle()
	mustPass(t, r)
	got = reload(t, r, v.ID)
	if got.Status.State != StateCreated || got.Status.SizeGB != 50 {
		t.Fatalf("after the volume became available: %+v", got.Status)
	}
	assignment := cloud.assignments[created.ID]
	if len(cloud.policies) != 1 || cloud.policies[0].Name != "gru-1-volumes-5d" || assignment.PolicyID != cloud.policies[0].ID {
		t.Fatalf("policies %+v, assignment %+v", cloud.policies, assignment)
	}

	before := len(cloud.mutations())
	mustPass(t, r)
	if again := reload(t, r, v.ID); again.Revision != got.Revision || len(cloud.mutations()) != before {
		t.Fatalf("a converged pass changed something: %v", cloud.mutations()[before:])
	}
}

func TestReconcilerBindsAVolumeWhoseCreateResponseWasLost(t *testing.T) {
	r, cloud, _ := testReconciler(t)
	v := mustCreate(t, r.Store, testVolume(NewID()))
	cloud.loseCreate = true
	if err := r.Pass(t.Context()); err == nil {
		t.Fatal("pass with a lost create response succeeded")
	}
	if got := reload(t, r, v.ID); got.Status.OCID != "" {
		t.Fatalf("status after a lost response: %+v", got.Status)
	}
	cloud.loseCreate = false
	cloud.settle()
	mustPass(t, r)
	got := reload(t, r, v.ID)
	if got.Status.State != StateCreated || len(cloud.volumes) != 1 || cloud.volumes[got.Status.OCID].Tags[tagCreateKey] != v.ID {
		t.Fatalf("after binding: %+v, %d volumes", got.Status, len(cloud.volumes))
	}
	if creates := slices.Index(cloud.mutations(), "create"); creates != 0 || slices.Contains(cloud.mutations()[1:], "create") {
		t.Fatalf("OCI calls %v; want exactly one create", cloud.mutations())
	}
}

func TestReconcilerGrowsRetiersAndChangesRetention(t *testing.T) {
	r, cloud, _ := testReconciler(t)
	v := mustCreate(t, r.Store, testVolume(NewID()))
	mustPass(t, r)
	cloud.settle()
	mustPass(t, r)

	v = reload(t, r, v.ID)
	v.SizeGB, v.VPUsPerGB, v.SnapshotRetentionDays = 120, 0, 30
	if _, err := r.Store.Update(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	before := len(cloud.mutations())
	for range 3 {
		mustPass(t, r)
	}
	got := reload(t, r, v.ID)
	cloudVolume := cloud.volumes[got.Status.OCID]
	if cloudVolume.SizeGB != 120 || cloudVolume.VPUsPerGB != 0 || got.Status.SizeGB != 120 {
		t.Fatalf("OCI volume %+v, status %+v", cloudVolume, got.Status)
	}
	want := []string{"resize 120", "vpus 0", "create policy gru-1-volumes-30d", "unassign"}
	changes := cloud.mutations()[before:]
	if len(changes) != 5 || !equalPrefix(changes, want) || !strings.HasPrefix(changes[4], "assign ") {
		t.Fatalf("changes %v", changes)
	}
	if cloud.assignments[got.Status.OCID].PolicyID != cloud.policies[1].ID {
		t.Fatalf("assignment %+v", cloud.assignments[got.Status.OCID])
	}
}

func equalPrefix(got, want []string) bool {
	return len(got) >= len(want) && strings.Join(got[:len(want)], ",") == strings.Join(want, ",")
}

func TestReconcilerHoldsVolumesItCannotProve(t *testing.T) {
	foreignTags := func(id string) map[string]string {
		return map[string]string{tagManagedBy: managedBy, tagOwner: "gru-1", tagResource: resourceVolume, tagCreateKey: id}
	}
	for name, tc := range map[string]struct {
		mutate func(*Volume)
		setup  func(c *fakeCloud, v Volume) string // returns the status OCID to record, if any
	}{
		"000000000050XVKQQF0BK88ENZ": {setup: func(*fakeCloud, Volume) string { return "ocid1.volume.oc1.sa-saopaulo-1.gone" }},
		"other volume's tags": {setup: func(c *fakeCloud, v Volume) string {
			other := CloudVolume{ID: "ocid1.volume.oc1.sa-saopaulo-1.x", CompartmentID: testSettings.CompartmentID, Zone: testZone,
				SizeGB: 50, State: "AVAILABLE", Tags: foreignTags(NewID())}
			c.put(other)
			return other.ID
		}},
		"faulty": {setup: func(c *fakeCloud, v Volume) string {
			faulty := CloudVolume{ID: "ocid1.volume.oc1.sa-saopaulo-1.y", CompartmentID: testSettings.CompartmentID, Zone: testZone,
				SizeGB: 50, State: "FAULTY", Tags: foreignTags(v.ID)}
			c.put(faulty)
			return faulty.ID
		}},
		"two tagged volumes": {setup: func(c *fakeCloud, v Volume) string {
			for _, id := range []string{"a", "b"} {
				c.put(CloudVolume{ID: "ocid1.volume.oc1.sa-saopaulo-1." + id, CompartmentID: testSettings.CompartmentID,
					Zone: testZone, SizeGB: 50, KMSKeyID: testSettings.KMSKeyID, State: "AVAILABLE", Tags: foreignTags(v.ID)})
			}
			return ""
		}},
		"tagged without the KMS key": {setup: func(c *fakeCloud, v Volume) string {
			c.put(CloudVolume{ID: "ocid1.volume.oc1.sa-saopaulo-1.k", CompartmentID: testSettings.CompartmentID,
				Zone: testZone, SizeGB: 50, State: "AVAILABLE", Tags: foreignTags(v.ID)})
			return ""
		}},
		"zone outside the cell": {mutate: func(v *Volume) { v.Zone = "Uocm:SA-SAOPAULO-1-AD-2" }},
		"recorded volume re-keyed": {setup: func(c *fakeCloud, v Volume) string {
			c.put(CloudVolume{ID: "ocid1.volume.oc1.sa-saopaulo-1.r", CompartmentID: testSettings.CompartmentID,
				Zone: testZone, SizeGB: 50, KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.vault.other", State: "AVAILABLE", Tags: foreignTags(v.ID)})
			return "ocid1.volume.oc1.sa-saopaulo-1.r"
		}},
		"tags removed after the listing": {setup: func(c *fakeCloud, v Volume) string {
			c.put(CloudVolume{ID: "ocid1.volume.oc1.sa-saopaulo-1.t", CompartmentID: testSettings.CompartmentID,
				Zone: testZone, SizeGB: 50, KMSKeyID: testSettings.KMSKeyID, State: "AVAILABLE", Tags: foreignTags(v.ID)})
			c.onGet = func(read *CloudVolume) { delete(read.Tags, tagCreateKey) }
			return ""
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r, cloud, _ := testReconciler(t)
			v := testVolume(NewID())
			if tc.mutate != nil {
				tc.mutate(&v)
			}
			v = mustCreate(t, r.Store, v)
			if tc.setup != nil {
				if ocid := tc.setup(cloud, v); ocid != "" {
					v.Status = Status{State: StateCreated, Epoch: 1, OCID: ocid, SizeGB: 50}
					if _, err := r.Store.Update(t.Context(), v); err != nil {
						t.Fatal(err)
					}
				}
			}
			mustPass(t, r)
			got := reload(t, r, v.ID)
			if got.Status.State != StateFailed || !strings.Contains(got.Status.Message, "needs an operator") {
				t.Fatalf("status %+v", got.Status)
			}
			if changes := cloud.mutations(); len(changes) != 0 {
				t.Fatalf("held volume caused OCI changes %v", changes)
			}
		})
	}
}

func TestReconcilerLeavesAForeignBackupPolicy(t *testing.T) {
	r, cloud, _ := testReconciler(t)
	v := mustCreate(t, r.Store, testVolume(NewID()))
	mustPass(t, r)
	cloud.settle()
	ocid := reload(t, r, v.ID).Status.OCID
	cloud.assignments[ocid] = Assignment{ID: "ocid1.volumebackuppolicyassignment.oc1..other", PolicyID: "ocid1.volumebackuppolicy.oc1..gold"}
	mustPass(t, r)
	if got := reload(t, r, v.ID); got.Status.State != StateFailed || cloud.assignments[ocid].PolicyID != "ocid1.volumebackuppolicy.oc1..gold" {
		t.Fatalf("status %+v, assignment %+v", got.Status, cloud.assignments[ocid])
	}
	// A cell-named policy whose schedule was changed is not the cell's
	// either: its assignment stays when the retention changes.
	cloud.assignments[ocid] = Assignment{ID: "ocid1.volumebackuppolicyassignment.oc1..cell", PolicyID: "ocid1.volumebackuppolicy.oc1..edited"}
	edited := (&pass{owner: "gru-1"}).policy(5)
	edited.ID, edited.Schedules[0].RetentionSeconds = "ocid1.volumebackuppolicy.oc1..edited", 3600
	cloud.policies = append(cloud.policies, edited)
	mustPass(t, r)
	if got := reload(t, r, v.ID); got.Status.State != StateFailed || cloud.assignments[ocid].PolicyID != edited.ID {
		t.Fatalf("edited policy: status %+v, assignment %+v", got.Status, cloud.assignments[ocid])
	}
	// Once an operator removes the foreign policy the volume recovers.
	delete(cloud.assignments, ocid)
	mustPass(t, r)
	if got := reload(t, r, v.ID); got.Status.State != StateCreated || got.Status.Message != "" {
		t.Fatalf("status after the operator fix %+v", got.Status)
	}
}

func TestReconcilerActsOnlyAsTheCurrentLeader(t *testing.T) {
	r, cloud, fence := testReconciler(t)
	v := mustCreate(t, r.Store, testVolume(NewID()))

	fence.leader.Store(false)
	mustPass(t, r)
	if len(cloud.calls) != 0 {
		t.Fatalf("a follower called OCI: %v", cloud.calls)
	}

	// The leader is deposed after its pass began: it reads, but no create or
	// status write lands.
	fence.leader.Store(true)
	r.Fencer = deposeOnList{testFence: fence, cloud: cloud}
	if err := r.Pass(t.Context()); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("deposed pass = %v, want ErrFenced", err)
	}
	if changes := cloud.mutations(); len(changes) != 0 {
		t.Fatalf("a deposed leader changed OCI: %v", changes)
	}
	if got := reload(t, r, v.ID); got.Revision != v.Revision {
		t.Fatalf("a deposed leader wrote status %+v", got.Status)
	}
}

// deposeOnList moves the epoch on once the pass has listed OCI volumes.
type deposeOnList struct {
	*testFence
	cloud *fakeCloud
}

func (f deposeOnList) Guard(ctx context.Context, epoch uint64) error {
	f.cloud.mu.Lock()
	listed := len(f.cloud.calls) > 0
	f.cloud.mu.Unlock()
	if listed {
		f.epoch.Store(epoch + 1)
	}
	return f.testFence.Guard(ctx, epoch)
}
