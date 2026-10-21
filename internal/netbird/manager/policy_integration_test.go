package manager

import (
	"encoding/json/v2"
	"io"
	"os"
	"path/filepath"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDirectPeerPolicyAndDNSConvergeWithoutTSOps(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	f.peers = slices.DeleteFunc(f.peers, func(peer *fakePeer) bool { return peer.ID == ids.tsOps })
	networkBefore, err := json.Marshal(f.networks)
	if err != nil {
		t.Fatal(err)
	}
	foreign := f.addPeer("ts-gru-9", "198.51.100.1", true, time.Now(), ids.operators)
	fresh := f.addPeer("ts-gru-8", "10.251.0.38", true, time.Now(), ids.servers)
	sjc := f.addGroup("sjc-servers")
	seedHistoricalFabric(f, ids.servers, sjc)
	f.addGroup("fra-servers")
	api := f.api(t)
	if _, err := Sync(t.Context(), api, GRU(), true); err != nil {
		t.Fatal(err)
	}
	networkAfter, err := json.Marshal(f.networks)
	if err != nil || string(networkAfter) != string(networkBefore) {
		t.Fatalf("unowned routing changed: %s, %v", networkAfter, err)
	}
	if f.groupByName("ts-ops-gateway") != nil || f.groupByName("gateway") == nil {
		t.Fatal("adopted ts-ops resources")
	}
	if f.groupByName("gru-servers").ID != ids.servers || rawString(f.account, "dns_domain") != "nb.ts.internal" ||
		string(f.account["lazy_connection_enabled"]) != "true" || string(f.account["extra"]) != `{"user_approval_required":false}` {
		t.Fatal("reconciliation changed retained group identity or unmanaged account settings")
	}
	for _, group := range []string{"sjc-servers", "fra-servers"} {
		index := slices.IndexFunc(f.policies, func(policy apiPolicy) bool { return policy.Name == group+"-to-gru-servers-fabric" })
		if index < 0 {
			t.Fatalf("missing spoke leaf policy for %s", group)
		}
		rule := f.policies[index].Rules[0]
		if rule.Bidirectional || !slices.Equal(rule.Ports, []string{"7422"}) || !slices.Equal(minimumIDs(rule.Sources), []string{f.groupByName(group).ID}) || !slices.Equal(minimumIDs(rule.Destinations), []string{ids.servers}) {
			t.Fatalf("widened leaf policy: %+v", rule)
		}
		if slices.ContainsFunc(f.policies, func(policy apiPolicy) bool { return policy.Name == "gru-servers-to-"+group+"-fabric" }) {
			t.Fatal("created reverse leaf policy")
		}
		for _, name := range []string{"gru-servers-to-" + group + "-terrabase", group + "-to-gru-servers-terrabase"} {
			index := slices.IndexFunc(f.policies, func(policy apiPolicy) bool { return policy.Name == name })
			if index < 0 || !slices.Equal(f.policies[index].Rules[0].Ports, []string{"9443"}) {
				t.Fatalf("lost TerraBase peer reachability: %s", name)
			}
		}

	}
	var records []apiRecord
	for _, zone := range f.zones {
		if zone.Name == GRU().Zone.Name {
			records = zone.records
		}
	}
	for _, peerID := range []string{ids.server1, fresh} {
		peer := f.peer(peerID)
		labels := []string{peer.Name}
		if peerID == ids.server1 {
			labels = append(labels, "nats")
		}
		for _, label := range labels {
			if !slices.ContainsFunc(records, func(record apiRecord) bool {
				return record.Name == label+".gru.ts.internal" && record.Content == peer.IP
			}) {
				t.Fatalf("no direct overlay DNS for %s: %+v", label, records)
			}
		}
	}
	if slices.ContainsFunc(records, func(record apiRecord) bool {
		return record.Content == f.peer(foreign).IP || strings.HasPrefix(record.Content, "10.251.") ||
			record.Content == f.peer(fresh).IP && (record.Name == "nats.gru.ts.internal" || record.Name == "terrabase.gru.ts.internal")
	}) {
		t.Fatalf("published unadmitted or routed private address: %+v", records)
	}
	f.mutations = nil
	if _, err := Sync(t.Context(), api, GRU(), true); err != nil || len(f.mutations) != 0 {
		t.Fatalf("sync did not converge: %v %v", f.mutations, err)
	}
	for _, zone := range f.zones {
		if zone.Name == GRU().Zone.Name {
			zone.records[0].TTL = 60
			zone.records = append(zone.records, apiRecord{ID: "stale-record", Name: "old.gru.ts.internal", Type: "A", Content: "10.200.0.99", TTL: 300})
			if _, err := Sync(t.Context(), api, GRU(), true); err != nil || len(zone.records) != len(records) || zone.records[0].TTL != GRU().Zone.TTL {
				t.Fatalf("managed DNS drift did not converge: %v", err)
			}
		}
	}
	// An empty observation cannot revoke DNS during a manager/discovery outage.
	f.group(ids.servers).Peers = nil
	f.mutations = nil
	report, err := Sync(t.Context(), api, GRU(), true)
	if err != nil || len(f.mutations) != 0 || !strings.Contains(strings.Join(report.Warnings, "\n"), "no admitted server peers") {
		t.Fatalf("empty discovery erased retained DNS: %+v %v %v", report, f.mutations, err)
	}
}

func TestDirectPeerDNSRefusesAmbiguousOrInvalidAdmissionBeforeWrites(t *testing.T) {
	for _, scenario := range []string{"name", "address", "duplicate", "issuer"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFakeManager(t)
			ids := f.seedLegacy(t)
			switch scenario {
			case "name":
				f.peer(ids.server1).Name = "ts-fra-1"
			case "address":
				f.peer(ids.server1).IP = "203.0.113.20"
			case "duplicate":
				f.addPeer("ts-gru-1", "10.251.0.11", true, time.Now(), ids.servers)
			case "issuer":
				f.group(ids.servers).Issued = "jwt"
			}
			if _, err := Sync(t.Context(), f.api(t), GRU(), true); err == nil || len(f.mutations) != 0 {
				t.Fatalf("invalid admission reached writes: %v %v", f.mutations, err)
			}
		})
	}
}

func seedHistoricalFabric(f *fakeManager, home, spoke string) {
	for _, direction := range []struct{ name, description, source, destination string }{
		{"gru-servers-to-sjc-servers-fabric", "GRU servers → SJC servers: NATS leafnodes 7422, TerraBase peers 9443", home, spoke},
		{"sjc-servers-to-gru-servers-fabric", "SJC servers → GRU servers: NATS leafnodes 7422, TerraBase peers 9443", spoke, home},
	} {
		f.policies = append(f.policies, f.policyFrom(f.id("pol"), policyRequest{Name: direction.name, Description: direction.description, Enabled: true, Rules: []ruleRequest{{Name: direction.name, Description: direction.description, Enabled: true, Action: "accept", Protocol: "tcp", Ports: []string{"7422", "9443"}, Sources: []string{direction.source}, Destinations: []string{direction.destination}}}}))
	}
}

func TestHistoricalFabricConflictStopsBeforeAccountWrites(t *testing.T) {
	for _, ports := range [][]string{{"7422", "9443", "22"}, {"22"}} {
		t.Run(strings.Join(ports, "-"), func(t *testing.T) {
			f := newFakeManager(t)
			ids := f.seedLegacy(t)
			spoke := f.addGroup("sjc-servers")
			seedHistoricalFabric(f, ids.servers, spoke)
			f.policies[len(f.policies)-1].Rules[0].Ports = ports
			if _, err := Sync(t.Context(), f.api(t), GRU(), true); err == nil || !strings.Contains(err.Error(), "conflicting shape") || len(f.mutations) != 0 {
				t.Fatalf("custom fabric overwritten: %v %v", f.mutations, err)
			}
		})
	}
}

func TestImageInputCLIWritesAllRegionsWithoutPeerMaps(t *testing.T) {
	for _, region := range []struct{ cell, oci string }{{"GRU", "sa-saopaulo-1"}, {"SJC", "us-sanjose-1"}} {
		t.Run(region.cell, func(t *testing.T) {
			dir := t.TempDir()
			plan, out := filepath.Join(dir, "plan.json"), filepath.Join(dir, "netbird.json")
			wire, err := json.Marshal(map[string]any{"cell": region.cell, "region": region.oci, "hosts": []map[string]string{{"slot": "controller-a", "private_ip": "10.251.0.11"}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(plan, wire, 0o600); err != nil {
				t.Fatal(err)
			}
			secret := "ocid1.vaultsecret.oc1." + region.oci + ".example"
			if err := Run(t.Context(), []string{"image-input", "--plan", plan, "--setup-key-secret-id", secret, "--out", out}, io.Discard); err != nil {
				t.Fatal(err)
			}
			cfg, err := client.ValidateConfig(out)
			if err != nil || cfg.Region != region.oci || cfg.SetupKeySecretID != secret || len(cfg.PeerNames) != 0 {
				t.Fatalf("invalid automatic image input: %+v %v", cfg, err)
			}
		})
	}
}
