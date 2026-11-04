package volume

import (
	"context"
	"errors"
	"fmt"
	"maps"

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
