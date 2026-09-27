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

func TestControllerPublicationGateRequiresCompletedFreshFoundationAndBudget(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	control := "ocid1.compartment.oc1..aaaaaa"
	workload := "ocid1.compartment.oc1..bbbbbb"
	tenancy := "ocid1.tenancy.oc1..aaaaaa"
	planSHA := strings.Repeat("a", 64)
	foundation := foundationReceipt{SchemaVersion: 1, Status: "foundation-ready",
		SourceRevision: strings.Repeat("b", 40), StateRevision: strings.Repeat("c", 40),
		EncryptedStateSHA256: strings.Repeat("d", 64), EffectsSHA256: strings.Repeat("e", 64),
		CostPlanSHA256: planSHA, TenancyID: tenancy, OCIRegion: "sa-saopaulo-1",
		ReadbackAt: now.Add(-time.Minute).Format(time.RFC3339), ControlCompartmentID: control,
		WorkloadCompartmentID: workload,
		VaultID:               "ocid1.vault.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrrjahmb7sqvwq2hlh3sa75a6qbrp44mcdg4kuof7vcyr2it3qs5oq",
		KeyID:                 "ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.aaaakey"}
	inventory := costInventory{SchemaVersion: 2, PlanSHA256: planSHA, TenancyID: tenancy,
		CapturedAt: now.Add(-2 * time.Minute), Regions: []string{"sa-saopaulo-1"}}
	inventory.PreviewCompartmentIDs.Control = control
	inventory.PreviewCompartmentIDs.Network = "ocid1.compartment.oc1..dddddd"
	inventory.PreviewCompartmentIDs.Workload = workload
	admission := costAdmission{SchemaVersion: 2, PlanSHA256: planSHA,
		AdmittedAt: now.Add(-time.Minute), ExpiresAt: now.Add(14 * time.Minute)}
	admission.PreviewCompartmentIDs = inventory.PreviewCompartmentIDs
	admission.Estimate.Currency, admission.Estimate.Total = "USD", "89.55"
	admission.Estimate.Limit, admission.Estimate.Headroom = "100", "10.45"
	check := func() error {
		t.Helper()
		foundationWire, err := json.Marshal(foundation)
		if err != nil {
			t.Fatal(err)
		}
		inventoryWire, err := json.Marshal(inventory)
		if err != nil {
			t.Fatal(err)
		}
		admission.InventorySHA256 = materialSHA(inventoryWire)
		admissionWire, err := json.Marshal(admission)
		if err != nil {
			t.Fatal(err)
		}
		_, err = validatePublicationGate(foundationWire, inventoryWire, admissionWire,
			materialSHA(foundationWire), materialSHA(inventoryWire), materialSHA(admissionWire), planSHA, now)
		return err
	}
	if err := check(); err != nil {
		t.Fatalf("fresh completed foundation and cost admission rejected: %v", err)
	}
	foundation.CostPlanSHA256 = strings.Repeat("f", 64)
	if err := check(); err == nil {
		t.Fatal("foundation receipt for a different cost plan admitted")
	}
	foundation.CostPlanSHA256 = planSHA
	foundation.ReadbackAt = now.Add(-time.Minute).Format("2006-01-02T15:04:05+00:00")
	if err := check(); err != nil {
		t.Fatalf("UTC offset foundation readback rejected: %v", err)
	}
	foundation.ReadbackAt = now.Add(-time.Minute).Format(time.RFC3339)
	foundation.Status = "recovery-required"
	if err := check(); err == nil {
		t.Fatal("failed foundation admitted")
	}
	foundation.Status = "foundation-ready"
	foundation.ReadbackAt = now.Add(-16 * time.Minute).Format(time.RFC3339)
	if err := check(); err == nil {
		t.Fatal("stale foundation readback admitted")
	}
	foundation.ReadbackAt = now.Add(-time.Minute).Format(time.RFC3339)
	admission.ExpiresAt = now.Add(-time.Second)
	if err := check(); err == nil {
		t.Fatal("expired cost admission accepted")
	}
	admission.ExpiresAt = now.Add(14 * time.Minute)
	admission.Estimate.Total = "100.01"
	admission.Estimate.Headroom = "-0.01"
	if err := check(); err == nil {
		t.Fatal("over-budget cost admission accepted")
	}
	admission.Estimate.Total, admission.Estimate.Headroom = "89.55", "10.45"
	inventory.PreviewCompartmentIDs.Control = "ocid1.compartment.oc1..cccccc"
	if err := check(); err == nil {
		t.Fatal("wrong control compartment accepted")
	}
}
