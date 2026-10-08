package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
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

func TestNetBirdAdmittedInventoryKeepsLivePeersThroughDrainAndLeaderFailover(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-leader", true: "new-leader"}[restart], func(t *testing.T) {
			n, pin, _ := netbirdArtifactTest(t, "")
			stageTestNetbirdArtifacts(t, n.artifacts, pin)
			selected, selectedInstance := netbirdInventoryHost("selected", "10.251.0.21")
			peer, peerInstance := netbirdInventoryHost("peer", "10.251.0.22")
			hosts := &netbirdInventoryHosts{statuses: []host.HostStatus{selected, peer}}
			fleet := &netbirdInventoryFleet{instances: []oci.Instance{selectedInstance, peerInstance}}
			n.fence.hosts, n.fleet = hosts, fleet
			n.services.current = cellspec.Spec{NetBird: &cellspec.NetBird{Pin: pin},
				HostGrants: []cellspec.HostGrant{{Node: "selected", Controller: "controller-a"}, {Node: "peer", Controller: "controller-b"}}}
			n.cfg.NATS = natscell.Config{Instance: "controller-a"}
			n.fence.spec = func() (*cellspec.ReleaseFence, map[string]string) {
				return &cellspec.ReleaseFence{}, map[string]string{}
			}
			quorumGate := errors.New("stop before host network probes")
			checks, drains := 0, 0
			n.nodes = &nodeOps{cluster: func(context.Context, string) error { checks++; return quorumGate },
				controllers: func(string) bool { return true }}
			for _, node := range []string{"selected", "peer"} {
				if err := n.saveAt(t.Context(), 3, "netbird.status."+node, network.Status{Version: "0.79.0", Connected: true, ObservedAt: time.Now()}); err != nil {
					t.Fatal(err)
				}
			}
			var state netbirdState
			r := network.Reconciler{
				Load: func(ctx context.Context) (network.Record, error) {
					var err error
					state, err = n.state(ctx)
					return state.Record, err
				},
				Save:   func(ctx context.Context, record network.Record) error { return n.saveRecordAt(ctx, 3, &state, record) },
				Status: func(ctx context.Context, node string) (network.Status, error) { return n.status(ctx, node) },
				Preflight: func(ctx context.Context, node string) error {
					if err := n.preflight(ctx, node); !errors.Is(err, quorumGate) {
						t.Fatalf("dynamic peers did not reach live preflight gates: %v", err)
					}
					return nil
				},
				Drain: func(context.Context, string) error { drains++; return nil },
			}
			target := network.Target{Pin: pin}
			if err := n.refreshInventory(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := r.Tick(t.Context(), target, []string{"selected", "peer"}); err != nil {
				t.Fatal(err)
			}
			if state.Record.Phase != "drain" || state.Record.OCIAddress != selectedInstance.PrivateIP || drains != 0 {
				t.Fatalf("initial admission did not persist its recovery address: %+v drains=%d", state.Record, drains)
			}
			fleet.instances[0].PrivateIP, fleet.instances[1].PrivateIP = "10.251.0.99", "10.251.0.23"
			n.observed = time.Time{}
			if restart {
				// A new leader rebuilds its inventory and verification receipts.
				n = &netbirdRollout{cell: n.cell, fence: n.fence, services: n.services, nodes: n.nodes,
					key: n.key, cfg: n.cfg, fleet: n.fleet, artifacts: n.artifacts, conn: n.conn, runtime: n.runtime}
				n.cfg.NATS.Instance = "controller-b"
			}
			if err := n.refreshInventory(t.Context()); err != nil {
				t.Fatal(err)
			}
			_, addresses := n.addresses()
			if len(addresses) != 2 || addresses["selected"] != selectedInstance.PrivateIP || addresses["peer"] != "10.251.0.23" {
				t.Fatalf("admitted inventory lost live peers or replaced saved recovery address: %v", addresses)
			}
			if err := r.Tick(t.Context(), target, nil); err != nil || state.Record.Phase != "install" || checks != 2 || drains != 1 {
				t.Fatalf("admitted dynamic node failed to drain: phase=%s checks=%d drains=%d err=%v", state.Record.Phase, checks, drains, err)
			}
			leader := n.services.controllerNode(n.cell, n.cfg.NATS.Instance)
			status := network.Status{Connected: true, IP: "10.200.1.2", DNS: leader + ".nb.ts.internal"}
			if err := n.healthy(t.Context(), leader, status, time.Time{}); err == nil || !strings.Contains(err.Error(), "cannot reach a healthy controller peer") {
				t.Fatalf("leader mesh check lost its dynamically discovered controller peer: %v", err)
			}
		})
	}
}

func TestNetBirdAdmittedRecoveryKeepsPeersAndProgressWhenInventoryFails(t *testing.T) {
	hosts := &netbirdInventoryHosts{err: errors.New("unrelated host inventory failed")}
	n := netbirdRollout{fence: &releaseFence{kv: fenceKV(t), fencer: &fenceLease{}, hosts: hosts,
		spec: func() (*cellspec.ReleaseFence, map[string]string) {
			return &cellspec.ReleaseFence{}, map[string]string{"selected": "10.251.0.21"}
		}}, services: &specRegistry{}, managedAddresses: map[string]string{"peer": "10.251.0.22"}}
	record := network.Record{ID: "admitted", Node: "selected", Phase: "drain", Deadline: time.Now().Add(time.Minute)}
	if err := saveNetBirdTestAdmission(t.Context(), &n, 3, record); err != nil {
		t.Fatal(err)
	}
	if err := n.load(t.Context(), netbirdRecordKey, &record); err != nil {
		t.Fatal(err)
	}
	n.fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return nil, map[string]string{} }
	if err := n.refreshInventory(t.Context()); !errors.Is(err, hosts.err) {
		t.Fatalf("unavailable peer inventory admitted a fresh drain: %v", err)
	}
	for _, phase := range []string{"install", "check", "confirm", "return", "rollback", "rollback-check", "failed"} {
		record.Phase = phase
		if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
			t.Fatal(err)
		}
		if err := n.refreshInventory(t.Context()); err != nil || len(n.managedAddresses) != 2 ||
			n.managedAddresses["selected"] != record.OCIAddress || n.managedAddresses["peer"] != "10.251.0.22" {
			t.Fatalf("%s recovery lost cached peers or waited on unrelated inventory: addresses=%v err=%v", phase, n.managedAddresses, err)
		}
	}
	record.Phase = "rollback-check"
	if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
		t.Fatal(err)
	}
	returns := 0
	r := network.Reconciler{
		Load: func(ctx context.Context) (network.Record, error) {
			var record network.Record
			err := n.load(ctx, netbirdRecordKey, &record)
			return record, err
		},
		Save: func(ctx context.Context, record network.Record) error {
			return saveNetBirdTestRecord(ctx, &n, 3, record)
		},
		Status: func(context.Context, string) (network.Status, error) {
			return network.Status{Missing: true, ActionID: record.ID + ".rollback", ObservedAt: time.Now()}, nil
		},
		Return: func(context.Context, string) error { returns++; return nil },
	}
	if err := r.Tick(t.Context(), network.Target{}, nil); err != nil || returns != 1 {
		t.Fatalf("unrelated inventory or removed pin/fence/grants blocked recovered node return: returns=%d err=%v", returns, err)
	}
	if err := n.load(t.Context(), netbirdRecordKey, &record); err != nil || !record.RecoveryComplete {
		t.Fatalf("recovery failed to complete: %+v %v", record, err)
	}
}

func TestNetBirdRecordedNodeRecoveryIgnoresUnrelatedRetiredInventory(t *testing.T) {
	selected, running := netbirdInventoryHost("recovering", "10.251.0.21")
	selected.SessionExpiresAt = time.Now().Add(-time.Second)
	unrelated, retired := netbirdInventoryHost("retired", "10.251.0.22")
	unrelated.SessionExpiresAt = time.Time{}
	retired.State = "TERMINATED"
	hosts := &netbirdInventoryHosts{statuses: []host.HostStatus{selected, unrelated}}
	fleet := &netbirdInventoryFleet{instances: []oci.Instance{running, retired}, reject: map[string]bool{retired.ID: true}}
	n := netbirdRollout{fence: &releaseFence{kv: fenceKV(t), fencer: &fenceLease{}, hosts: hosts,
		spec: func() (*cellspec.ReleaseFence, map[string]string) {
			return &cellspec.ReleaseFence{}, map[string]string{"controller": "10.251.0.11"}
		}}, fleet: fleet, managedAddresses: map[string]string{"retired": retired.PrivateIP}}
	if err := n.refreshRecoveryNode(t.Context(), selected.Registration.Node); err != nil {
		t.Fatal(err)
	}
	_, addresses := n.addresses()
	if len(n.managedAddresses) != 1 || addresses["recovering"] != running.PrivateIP || addresses["controller"] == "" || fleet.fullCalls != 0 ||
		!slices.Equal(fleet.selected, []string{running.ID}) {
		t.Fatalf("record recovery used unrelated inventory or lost adopted peers: addresses=%v selected=%v full=%d", addresses, fleet.selected, fleet.fullCalls)
	}
	pin, err := client.LoadPin("../../deploy/image/image-inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	target := network.Target{Pin: pin}
	record := network.Record{ID: "recovering-netbird", Node: selected.Registration.Node, Previous: "0.79.0", Phase: "rollback-check",
		Target: target, PinHash: network.Hash(target), StartedAt: time.Now().Add(-time.Minute), Deadline: time.Now().Add(time.Minute)}
	if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
		t.Fatal(err)
	}
	if err := n.fence.save(t.Context(), 3, record.Node, fenceRecord{Holders: []string{netbirdHold}}); err != nil {
		t.Fatal(err)
	}
	if err := n.saveAt(t.Context(), 3, "netbird.status."+record.Node, network.Status{Version: record.Previous,
		ActionID: record.ID + ".rollback", Connected: true, IP: "10.200.1.2", DNS: record.Node + ".nb.ts.internal", ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r := network.Reconciler{
		Load: func(ctx context.Context) (network.Record, error) {
			var record network.Record
			err := n.load(ctx, netbirdRecordKey, &record)
			return record, err
		},
		Save: func(ctx context.Context, record network.Record) error {
			return saveNetBirdTestRecord(ctx, &n, 3, record)
		},
		Status: n.status, Healthy: func(context.Context, string, network.Status, time.Time) error { return nil },
		Return: func(ctx context.Context, node string) error {
			_, err := n.fence.restore(ctx, nil, 3, node, netbirdHold, true)
			return err
		},
	}
	if err := r.Tick(t.Context(), target, nil); err != nil {
		t.Fatal(err)
	}
	if err := n.load(t.Context(), netbirdRecordKey, &record); err != nil || !record.RecoveryComplete {
		t.Fatalf("recorded node could not complete recovery: %+v %v", record, err)
	}
	if _, found, err := n.fence.record(t.Context(), record.Node); err != nil || found {
		t.Fatalf("recovered node remained fenced: found=%t error=%v", found, err)
	}
}

func TestNetBirdGrantedRecoveryUsesOnlyTheAdoptedPrivateAddress(t *testing.T) {
	hosts := &netbirdInventoryHosts{err: errors.New("unrelated host inventory failed")}
	fleet := &netbirdInventoryFleet{}
	n := netbirdRollout{fence: &releaseFence{hosts: hosts, spec: func() (*cellspec.ReleaseFence, map[string]string) {
		return nil, map[string]string{"controller": "10.251.0.11"}
	}}, fleet: fleet, managedAddresses: map[string]string{"stale": "10.251.0.22"}}
	if err := n.refreshRecoveryNode(t.Context(), "controller"); err != nil || hosts.calls != 0 || fleet.fullCalls != 0 || len(fleet.selected) != 0 || len(n.managedAddresses) != 0 {
		t.Fatalf("adopted controller recovery queried unrelated state: addresses=%v hosts=%d selected=%v full=%d error=%v",
			n.managedAddresses, hosts.calls, fleet.selected, fleet.fullCalls, err)
	}
}

func TestNetBirdRecoveryRejectsUnverifiedOrUnsafeManagedIdentity(t *testing.T) {
	for _, invalid := range []string{"id", "node", "owner", "create-key", "generation", "region", "stopped", "mesh-ip", "public-ip", "loopback", "ambiguous"} {
		t.Run(invalid, func(t *testing.T) {
			selected, instance := netbirdInventoryHost("recovering", "10.251.0.21")
			switch invalid {
			case "id":
				instance.ID = "another-instance"
			case "node":
				instance.Node = "another-node"
			case "owner":
				instance.Owner = "another-owner"
			case "create-key":
				instance.CreateKey = "another-create"
			case "generation":
				instance.Generation++
			case "region":
				instance.Region = oci.RegionSFO
			case "stopped":
				instance.State = "STOPPED"
			case "mesh-ip":
				instance.PrivateIP = "10.200.1.2"
			case "public-ip":
				instance.PrivateIP = "8.8.8.8"
			case "loopback":
				instance.PrivateIP = "127.0.0.1"
			}
			fleet := &netbirdInventoryFleet{instances: []oci.Instance{instance}}
			if invalid == "ambiguous" {
				duplicate := instance
				duplicate.ID = "duplicate-node"
				fleet.instances = append(fleet.instances, duplicate)
			}
			n := netbirdRollout{fence: &releaseFence{hosts: &netbirdInventoryHosts{statuses: []host.HostStatus{selected}},
				spec: func() (*cellspec.ReleaseFence, map[string]string) { return nil, nil }}, fleet: fleet}
			if err := n.refreshRecoveryNode(t.Context(), selected.Registration.Node); err == nil || len(n.managedAddresses) != 0 {
				t.Fatalf("accepted %s recovery identity: addresses=%v error=%v", invalid, n.managedAddresses, err)
			}
		})
	}
}
