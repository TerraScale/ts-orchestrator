package app

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

type netbirdInventoryHosts struct {
	statuses []host.HostStatus
	calls    int
	err      error
}

func (h *netbirdInventoryHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	h.calls++
	return slices.Clone(h.statuses), h.err
}

func (*netbirdInventoryHosts) ListDesired(context.Context, string) ([]host.Desired, error) {
	return nil, nil
}

type netbirdInventoryFleet struct {
	oci.Fleet
	instances []oci.Instance
	reject    map[string]bool
	selected  []string
	fullCalls int
}

func (f *netbirdInventoryFleet) Observe(context.Context) ([]oci.Instance, error) {
	f.fullCalls++
	return nil, errors.New("unrelated fleet observation failed")
}

func (f *netbirdInventoryFleet) ObserveSelected(_ context.Context, selectInstance func(string, string) bool) ([]oci.Instance, error) {
	var observed []oci.Instance
	for _, instance := range f.instances {
		if selectInstance(instance.ID, instance.Node) {
			f.selected = append(f.selected, instance.ID)
			if f.reject[instance.ID] {
				return nil, errors.New("retired instance observation failed")
			}
			observed = append(observed, instance)
		}
	}
	return observed, nil
}

func netbirdInventoryHost(node, ip string) (host.HostStatus, oci.Instance) {
	binding := &host.ManagedOCIBinding{InstanceID: "instance-" + node, Owner: "cell-owner", CreateKey: "create-" + node,
		FleetGeneration: 5, Region: string(oci.RegionGRU)}
	status := host.HostStatus{Registration: host.Registration{Node: node, ManagedOCI: binding}, SessionExpiresAt: time.Now().Add(time.Minute)}
	instance := oci.Instance{ID: binding.InstanceID, Node: node, Owner: binding.Owner, CreateKey: binding.CreateKey,
		Generation: binding.FleetGeneration, Region: oci.RegionGRU, PrivateIP: ip, State: "RUNNING"}
	return status, instance
}

func TestNetBirdManagedInventoryAdmitsOnlyLiveOwnedRunningCandidates(t *testing.T) {
	live, running := netbirdInventoryHost("live", "10.251.0.21")
	expired, retired := netbirdInventoryHost("expired", "10.251.0.22")
	expired.SessionExpiresAt = time.Now().Add(-time.Second)
	unjoined, neverJoined := netbirdInventoryHost("unjoined", "10.251.0.23")
	unjoined.SessionExpiresAt = time.Time{}
	stopped, stopping := netbirdInventoryHost("stopped", "10.251.0.24")
	stopping.State = "STOPPED"
	unmatched, otherBinding := netbirdInventoryHost("unmatched", "10.251.0.25")
	otherBinding.Owner = "different-owner"
	hosts := &netbirdInventoryHosts{statuses: []host.HostStatus{live, expired, unjoined, stopped, unmatched}}
	fleet := &netbirdInventoryFleet{instances: []oci.Instance{running, retired, neverJoined, stopping, otherBinding},
		reject: map[string]bool{retired.ID: true, neverJoined.ID: true}}
	n := netbirdRollout{fence: &releaseFence{hosts: hosts}, fleet: fleet}
	if err := n.refreshManaged(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(n.managedAddresses) != 1 || n.managedAddresses["live"] != running.PrivateIP || fleet.fullCalls != 0 ||
		slices.Contains(fleet.selected, retired.ID) || slices.Contains(fleet.selected, neverJoined.ID) {
		t.Fatalf("candidate admission included historical or unverified hosts: addresses=%v selected=%v full=%d", n.managedAddresses, fleet.selected, fleet.fullCalls)
	}
}
