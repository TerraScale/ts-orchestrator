package bootstrapmaterial

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
)

// nextSecond waits for the next whole second: brokers take only a cell
// claim issued strictly later than the one it replaces.
func nextSecond() { time.Sleep(time.Until(time.Unix(time.Now().Unix()+1, 0))) }

func receipt(t *testing.T, mutate func(map[string]any)) ([]byte, string) {
	t.Helper()
	document := map[string]any{
		"schema_version": 1, "kind": PrivatePeerReceiptKind, "status": PrivatePeerReceiptPass,
		"readback_expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		"allowed_tcp_ports":   []int{4222, 7422},
		"cells": map[string]any{"gru": map[string]any{"subnet_cidr": "10.251.0.0/24", "vcn_id": "x"},
			"sjc": map[string]any{"subnet_cidr": "10.252.0.0/24"}},
		"dataplane_reachability": "not_tested",
	}
	if mutate != nil {
		mutate(document)
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	return wire, hex.EncodeToString(sum[:])
}

type linkedRegion struct {
	material, directory string
	record              InterRegionRecord
}

// linkedRegions issues gru's interregion material as the hub of a gru/sjc
// tree and sjc's as its child, with gru's interregion CA.
func linkedRegions(t *testing.T) (linkedRegion, linkedRegion, time.Time) {
	t.Helper()
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	sjcConfig := testConfig()
	sjcConfig.Region, sjcConfig.Cell, sjcConfig.ClusterID, sjcConfig.SubnetCIDR = "us-sanjose-1", "sjc", "00000000000000000000000002", "10.252.0.0/24"
	sjcConfig.Slots = []Slot{{"controller-a", "10.252.0.10"}, {"controller-b", "10.252.0.11"}, {"controller-c", "10.252.0.12"}}
	gru := linkedRegion{material: filepath.Join(root, "gru"), directory: filepath.Join(root, "gru-interregion")}
	sjc := linkedRegion{material: filepath.Join(root, "sjc"), directory: filepath.Join(root, "sjc-interregion")}
	for _, region := range []struct {
		directory string
		cfg       Config
	}{{gru.material, testConfig()}, {sjc.material, sjcConfig}} {
		if _, err := Generate(region.directory, region.cfg, now); err != nil {
			t.Fatal(err)
		}
	}
	nextSecond()
	topology := natscell.HubAndSpoke("gru", []string{"sjc"})
	var err error
	if gru.record, err = GenerateInterRegion(gru.material, gru.directory, InterRegionConfig{Topology: topology, ListenPort: 7422},
		InterRegionInputs{}, now); err != nil {
		t.Fatal(err)
	}
	if sjc.record, err = GenerateInterRegion(sjc.material, sjc.directory, InterRegionConfig{Topology: topology},
		hubCA(t, gru), now); err != nil {
		t.Fatal(err)
	}
	return gru, sjc, now
}

func hubCA(t *testing.T, hub linkedRegion) InterRegionInputs {
	t.Helper()
	cert, err := os.ReadFile(filepath.Join(hub.directory, "interregion-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return InterRegionInputs{CACert: cert, CAKeyFile: filepath.Join(hub.directory, "interregion-ca.key")}
}

// netbirdReadback is a reviewed NetBird inventory in which every gru
// controller has one connected gru-servers peer (slot a also a replaced,
// disconnected revision) and sjc's servers may reach gru's on 7422.
func netbirdReadback(t *testing.T, mutate func(*manager.Inventory)) Readback {
	t.Helper()
	servers := []string{"gru-servers"}
	inventory := manager.Inventory{Account: manager.InventoryAccount{NetworkRange: "10.200.0.0/16"},
		Peers: []manager.InventoryPeer{
			{Name: "ts-gru-1", IP: "10.200.0.11", ConnectionIP: "10.251.0.10", Connected: true, Groups: servers},
			{Name: "ts-gru-1-old", IP: "10.200.0.99", ConnectionIP: "10.251.0.10", Groups: servers},
			{Name: "ts-gru-2", IP: "10.200.0.12", ConnectionIP: "10.251.0.11", Connected: true, Groups: servers},
			{Name: "ts-gru-3", IP: "10.200.0.13", ConnectionIP: "10.251.0.12", Connected: true, Groups: servers},
			{Name: "ts-sjc-1", IP: "10.200.1.11", ConnectionIP: "10.252.0.10", Connected: true, Groups: []string{"sjc-servers"}},
		},
		Policies: []manager.InventoryPolicy{{Name: "sjc-servers-to-gru-servers-fabric", Enabled: true,
			Rules: []manager.InventoryRule{{Name: "sjc-servers-to-gru-servers-fabric", Enabled: true, Action: "accept",
				Protocol: "tcp", Ports: []string{"7422", "9443"}, Sources: []string{"sjc-servers"}, Destinations: servers}}}},
	}
	if mutate != nil {
		mutate(&inventory)
	}
	wire, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	return Readback{wire, digest(wire)}
}

// childCredentials is the child's private copy of the parent's
// leaf-<child>.creds.
func childCredentials(t *testing.T, parent linkedRegion, child string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(parent.directory, "leaf-"+child+".creds"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "leaf.creds")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
