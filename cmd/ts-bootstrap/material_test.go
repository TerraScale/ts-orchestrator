package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"
)

func TestControllerMaterialPublicPEMFeedsDelegationSigner(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := materialPublicPEM(base64.StdEncoding.EncodeToString(public))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseRootPublicKey(wire)
	if err != nil || !bytes.Equal(parsed, public) {
		t.Fatalf("delegation signer public PEM cannot be parsed: %v", err)
	}
}

func materialSHA(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func TestControllerPublicationGateRequiresFreshManualReadbackAndBudget(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	control := "ocid1.compartment.oc1..aaaaaa"
	network := "ocid1.compartment.oc1..dddddd"
	workload := "ocid1.compartment.oc1..bbbbbb"
	tenancy := "ocid1.tenancy.oc1..aaaaaa"
	cell := "gru"
	planSHA := strings.Repeat("a", 64)
	readback := manualFoundationReadback{SchemaVersion: 1, PlanSHA256: planSHA,
		TenancyID: tenancy, Cell: "GRU", OCIRegion: "sa-saopaulo-1", InspectedAt: now.Add(-time.Minute),
		ControlCompartmentID: control, NetworkCompartmentID: network, WorkloadCompartmentID: workload,
		VaultID: "ocid1.vault.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrrjahmb7sqvwq2hlh3sa75a6qbrp44mcdg4kuof7vcyr2it3qs5oq",
		KeyID:   "ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.aaaakey"}
	inventory := costInventory{SchemaVersion: 2, PlanSHA256: planSHA, TenancyID: tenancy,
		CapturedAt: now.Add(-2 * time.Minute), Regions: []string{"sa-saopaulo-1"}}
	inventory.PreviewCompartmentIDs.Control = control
	inventory.PreviewCompartmentIDs.Network = network
	inventory.PreviewCompartmentIDs.Workload = workload
	admission := costAdmission{SchemaVersion: 2, PlanSHA256: planSHA,
		AdmittedAt: now.Add(-time.Minute), ExpiresAt: now.Add(14 * time.Minute)}
	admission.PreviewCompartmentIDs = inventory.PreviewCompartmentIDs
	admission.Estimate.Currency, admission.Estimate.Total = "USD", "89.55"
	admission.Estimate.Limit, admission.Estimate.Headroom = "100", "10.45"
	check := func() (publicationGate, error) {
		t.Helper()
		inventoryWire, err := json.Marshal(inventory)
		if err != nil {
			t.Fatal(err)
		}
		readback.InventorySHA256 = materialSHA(inventoryWire)
		readbackWire, err := json.Marshal(readback)
		if err != nil {
			t.Fatal(err)
		}
		admission.InventorySHA256 = materialSHA(inventoryWire)
		admissionWire, err := json.Marshal(admission)
		if err != nil {
			t.Fatal(err)
		}
		return validatePublicationGate(readbackWire, inventoryWire, admissionWire,
			materialSHA(readbackWire), materialSHA(inventoryWire), materialSHA(admissionWire), planSHA, cell, now)
	}
	gate, err := check()
	if err != nil || gate.Target.CompartmentOCID != control || gate.Target.VaultOCID != readback.VaultID ||
		gate.Target.KMSKeyOCID != readback.KeyID || !gate.Deadline.Equal(readback.InspectedAt.Add(15*time.Minute)) {
		t.Fatalf("fresh manual foundation and cost admission rejected: gate=%+v err=%v", gate, err)
	}
	for _, test := range []struct{ cell, region string }{
		{"sfo", "us-sanjose-1"}, {"fra", "eu-frankfurt-1"},
	} {
		cell, readback.Cell, readback.OCIRegion = test.cell, strings.ToUpper(test.cell), test.region
		readback.VaultID = "ocid1.vault.oc1." + test.region + ".aaaaaa"
		readback.KeyID = "ocid1.key.oc1." + test.region + ".aaaaaa"
		inventory.Regions = []string{test.region}
		if _, err := check(); err != nil {
			t.Fatalf("%s mapped foundation rejected: %v", test.cell, err)
		}
		readback.Cell = "GRU"
		if _, err := check(); err == nil {
			t.Fatalf("%s foundation accepted with GRU cell", test.cell)
		}
		readback.Cell, readback.OCIRegion = strings.ToUpper(test.cell), "sa-saopaulo-1"
		if _, err := check(); err == nil {
			t.Fatalf("%s foundation accepted with GRU OCI region", test.cell)
		}
	}
	cell, readback.Cell, readback.OCIRegion = "gru", "GRU", "sa-saopaulo-1"
	readback.VaultID = "ocid1.vault.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrrjahmb7sqvwq2hlh3sa75a6qbrp44mcdg4kuof7vcyr2it3qs5oq"
	readback.KeyID = "ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.aaaakey"
	inventory.Regions = []string{"sa-saopaulo-1"}
	readback.PlanSHA256 = strings.Repeat("f", 64)
	if _, err := check(); err == nil {
		t.Fatal("readback for a different cost plan admitted")
	}
	readback.PlanSHA256 = planSHA
	readback.InspectedAt = now.Add(-time.Minute).In(time.FixedZone("UTC offset", 0))
	if _, err := check(); err != nil {
		t.Fatalf("UTC offset manual readback rejected: %v", err)
	}
	readback.InspectedAt = now.Add(-time.Minute).In(time.FixedZone("wrong region offset", 3600))
	if _, err := check(); err == nil {
		t.Fatal("non-UTC manual readback admitted")
	}
	readback.InspectedAt = now.Add(-16 * time.Minute)
	if _, err := check(); err == nil {
		t.Fatal("stale manual readback admitted")
	}
	readback.InspectedAt = now.Add(-time.Minute)
	readback.NetworkCompartmentID = control
	if _, err := check(); err == nil {
		t.Fatal("duplicate network compartment accepted")
	}
	readback.NetworkCompartmentID = network
	inventory.PreviewCompartmentIDs.Network = "ocid1.compartment.oc1..cccccc"
	if _, err := check(); err == nil {
		t.Fatal("wrong live network compartment accepted")
	}
	inventory.PreviewCompartmentIDs.Network = network
	inventory.CapturedAt = now.Add(-21 * time.Minute)
	if _, err := check(); err == nil {
		t.Fatal("stale cost inventory accepted")
	}
	inventory.CapturedAt = now.Add(-2 * time.Minute)
	admission.ExpiresAt = now.Add(-time.Second)
	if _, err := check(); err == nil {
		t.Fatal("expired cost admission accepted")
	}
	admission.ExpiresAt = now.Add(14 * time.Minute)
	admission.Estimate.Total = "100.01"
	admission.Estimate.Headroom = "-0.01"
	if _, err := check(); err == nil {
		t.Fatal("over-budget cost admission accepted")
	}
	admission.Estimate.Total, admission.Estimate.Headroom = "89.55", "10.45"
	inventory.PreviewCompartmentIDs.Control = "ocid1.compartment.oc1..cccccc"
	if _, err := check(); err == nil {
		t.Fatal("wrong control compartment accepted")
	}
}
