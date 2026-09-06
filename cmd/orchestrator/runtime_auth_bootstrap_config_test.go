package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func TestAuthBootstrapAdmissionFile(t *testing.T) {
	grant := &pb.AuthGroupBootstrapGrant{Environment: "production", Cluster: "01ARZ3NDEKTSV4RRFFQ69G5FA0", GroupId: "01ARZ3NDEKTSV4RRFFQ69G5FA1", Tenant: "01ARZ3NDEKTSV4RRFFQ69G5FA2", Project: "01ARZ3NDEKTSV4RRFFQ69G5FA3", Database: "01ARZ3NDEKTSV4RRFFQ69G5FA4", Generation: 1, Regions: []string{"GRU"}, GenesisNode: 1}
	targets := []map[string]string{}
	for i := range 2 {
		member := "01ARZ3NDEKTSV4RRFFQ69G5FA" + string(rune('5'+i))
		identity := "spiffe://terrascale.tech/production/terrabase-member/" + grant.Cluster + "/" + member
		grant.Voters = append(grant.Voters, &pb.AuthGroupVoter{NodeId: uint64(i + 1), Member: member, SpiffeUri: identity, Region: "GRU"})
		targets = append(targets, map[string]string{"server_identity": identity, "principal": "spiffe://terrascale.tech/production/orchestrator/" + member})
	}
	raw, err := protojson.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	file := map[string]any{"version": 1, "targets": targets, "grants": []jsontext.Value{raw}}
	encoded, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	config, err := parseProductionAuthBootstrapConfig(encoded)
	if err != nil || len(config.Grants) != 1 || len(config.Targets) != 2 {
		t.Fatal("valid admitted file rejected", err)
	}
	file["extra"] = true
	encoded, _ = json.Marshal(file)
	if _, err := parseProductionAuthBootstrapConfig(encoded); err == nil {
		t.Fatal("unknown fields accepted")
	}
	delete(file, "extra")
	file["grants"] = []jsontext.Value{raw, raw}
	encoded, _ = json.Marshal(file)
	if _, err := parseProductionAuthBootstrapConfig(encoded); err == nil {
		t.Fatal("duplicate group accepted")
	}
	file["grants"] = []jsontext.Value{raw}
	file["targets"] = targets[:1]
	encoded, _ = json.Marshal(file)
	if _, err := parseProductionAuthBootstrapConfig(encoded); err == nil {
		t.Fatal("foreign voter accepted")
	}
	file["targets"] = targets
	grant.AuthorityRevision = 9
	raw, _ = protojson.Marshal(grant)
	file["grants"] = []jsontext.Value{raw}
	encoded, _ = json.Marshal(file)
	if _, err := parseProductionAuthBootstrapConfig(encoded); err == nil {
		t.Fatal("preassigned authority revision accepted")
	}
	if _, err := LoadProductionAuthBootstrap(""); err == nil {
		t.Fatal("missing file accepted")
	}
}
