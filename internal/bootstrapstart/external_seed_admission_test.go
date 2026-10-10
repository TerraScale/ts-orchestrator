package bootstrapstart

import (
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func TestExternalSeedProducedLedgerHistoryAdmitsInitial(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	anchorEnvelope, err := trust.DecodeEnvelope(fixture.gate.AnchorWire)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, fixture.gate.Roots, fixture.gate.Expected,
		*fixture.now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	identity := BakedIdentity{SchemaVersion: 1, DeploymentID: fixture.gate.Expected.DeploymentID,
		Environment: fixture.gate.Expected.Environment, Cell: fixture.gate.Expected.Cell}
	manifestWire := fixture.ledger.state.ManifestRecord.Bytes
	manifestEnvelope, err := trust.DecodeEnvelope(manifestWire)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := anchor.ManifestExpectation("controller-b", fixture.ledger.state.Intent.ImageOCID)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.VerifyManifest(manifestEnvelope, fixture.gate.Roots, expected,
		*fixture.now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := manifest.Profile("controller-b")
	if !ok {
		t.Fatal("signed seed manifest lacks launch profile")
	}
	anchored := anchor.Anchor()
	scope := bootstrap.BootstrapScope{DeploymentID: anchored.DeploymentID, Cell: string(anchored.Cell), Slot: "controller-b"}
	createKey := "reviewed-seed-create"
	reservation, err := BuildExternalSeedReservation(ExternalSeedReservationRequest{
		Identity: identity, Anchor: anchor, Manifest: manifest,
		ReviewedPlanSHA256: digestWire([]byte("reviewed plan")), CreateIdentity: createKey,
		LedgerPrivate: fixture.ledgerPrivate, Now: *fixture.now, ExpiresAt: fixture.now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("build CLI reservation records: %v", err)
	}
	intentWire, headWire := reservation.IntentWire, reservation.InitialHeadWire
	objects := &founderLedgerObjects{objects: make(map[string]founderStoredObject), now: *fixture.now}
	config, err := currentLedgerConfig(anchor, fixture.gate.Roots)
	if err != nil {
		t.Fatal(err)
	}
	config.VerificationNow = func() time.Time { return *fixture.now }
	ledger, err := bootstrap.NewLedger(objects, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.ReserveSlot(t.Context(), scope, intentWire, headWire); err != nil {
		t.Fatalf("publish signed seed reservation: %v", err)
	}
	reserved, err := ledger.ReadSlot(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	reservationWrites := objects.writes
	if _, err := ledger.ReserveSlot(t.Context(), scope, intentWire, headWire); err != nil ||
		objects.writes != reservationWrites {
		t.Fatalf("exact seed reservation replay changed ledger: writes=%d prior=%d err=%v",
			objects.writes, reservationWrites, err)
	}
	conflicting, err := BuildExternalSeedReservation(ExternalSeedReservationRequest{
		Identity: identity, Anchor: anchor, Manifest: manifest,
		ReviewedPlanSHA256: digestWire([]byte("reviewed plan")), CreateIdentity: "another-seed-create",
		LedgerPrivate: fixture.ledgerPrivate, Now: *fixture.now, ExpiresAt: fixture.now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("build valid conflicting reservation: %v", err)
	}
	if _, err := ledger.ReserveSlot(t.Context(), scope, conflicting.IntentWire, conflicting.InitialHeadWire); !errors.Is(err, bootstrap.ErrImmutableConflict) ||
		objects.writes != reservationWrites {
		t.Fatalf("conflicting seed reservation created another slot: writes=%d prior=%d err=%v",
			objects.writes, reservationWrites, err)
	}
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.seed-a"
	observed := InstanceObservation{InstanceOCID: instanceID, BootstrapCreateKey: createKey,
		CompartmentOCID: profile.CompartmentOCID, ImageOCID: reserved.Intent.ImageOCID, ETag: "seed-etag",
		AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain,
		Shape: profile.Shape, SubnetOCID: profile.SubnetOCID,
		NSGOCIDs:        slices.Clone(profile.NetworkSecurityGroupOCIDs),
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.seed-a", PrimaryPrivateIP: "10.0.0.3",
		PrimaryVNIC: true, LifecycleState: "RUNNING"}
	if len(observed.NSGOCIDs) != 2 {
		t.Fatalf("fixture must exercise the two-NSG OCI ordering case: %v", observed.NSGOCIDs)
	}
	slices.Reverse(observed.NSGOCIDs)
	reader := &founderAdmissionLedger{ledger: ledger}
	material, credentials := fixture.material, fixture.credentials
	gate := fixture.gate
	gate.Instances, gate.Ledgers = fakeInstanceObserver{observed}, reader
	gate.Descriptor = fixedDescriptor{slot: scope.Slot, instance: instanceID}
	if _, err := gate.AdmitInitial(t.Context()); err == nil || material.initialCalls != 0 {
		t.Fatalf("uncommitted seed reached initial admission: err=%v material=%d", err, material.initialCalls)
	}
	facts, err := VerifyExternalSeedObservation(anchor, manifest, reserved, observed, "10.0.0.3")
	if err != nil {
		t.Fatalf("exact OCI readback differs from signed reservation: %v", err)
	}
	completion, err := BuildExternalSeedCompletion(ExternalSeedCompletionRequest{
		Identity: identity, Anchor: anchor, Manifest: manifest, Roots: fixture.gate.Roots,
		State: reserved, Observation: observed, ObservedAt: *fixture.now,
		ExpectedPrivateIP: "10.0.0.3", RootPrivate: fixture.rootPrivate,
		LedgerPrivate: fixture.ledgerPrivate, Now: *fixture.now, ExpiresAt: fixture.now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("build CLI completion records: %v", err)
	}
	reused, err := BuildExternalSeedCompletion(ExternalSeedCompletionRequest{
		Identity: identity, Anchor: anchor, Manifest: manifest, Roots: fixture.gate.Roots,
		State: reserved, Observation: observed, ObservedAt: fixture.now.Add(10 * time.Minute),
		ExpectedPrivateIP: "10.0.0.3", RootPrivate: fixture.rootPrivate,
		LedgerPrivate: fixture.ledgerPrivate, ReuseReceiptWire: completion.ReceiptWire,
		Now: fixture.now.Add(10 * time.Minute), ExpiresAt: fixture.now.Add(2 * time.Hour)})
	if err != nil || !slices.Equal(reused.ReceiptWire, completion.ReceiptWire) {
		t.Fatalf("reuse exact root receipt: %v", err)
	}
	receiptEnvelope, err := trust.DecodeEnvelope(completion.ReceiptWire)
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range [][]byte{reused.ResultWire, reused.CompletedHeadWire} {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil || !envelope.ExpiresAt.Equal(receiptEnvelope.ExpiresAt) {
			t.Fatalf("reused receipt expiry did not cap completion record: %v", err)
		}
	}
	committed, err := ledger.RecordExternalSeed(t.Context(), scope, manifestWire, completion.ReceiptWire,
		facts, completion.ResultWire, completion.CompletedHeadWire)
	if err != nil || committed.ResultRecord == nil {
		t.Fatalf("publish signed seed completion: state=%+v err=%v", committed, err)
	}
	if !slices.Equal(reserved.Intent.NetworkSecurityGroupIDs, profile.NetworkSecurityGroupOCIDs) {
		t.Fatalf("signed intent changed the manifest NSG order: intent=%v manifest=%v",
			reserved.Intent.NetworkSecurityGroupIDs, profile.NetworkSecurityGroupOCIDs)
	}
	seedReceipt, err := bootstrap.ReceiptPayload(receiptEnvelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	signedProfileWire, err := trust.EncodePayload(profile)
	if err != nil || seedReceipt.ProfileSHA256 != digestWire(signedProfileWire) {
		t.Fatalf("receipt profile digest no longer binds signed NSG order: receipt=%s err=%v",
			seedReceipt.ProfileSHA256, err)
	}
	writes := objects.writes
	replayed, err := ledger.RecordExternalSeed(t.Context(), scope, manifestWire, completion.ReceiptWire,
		facts, completion.ResultWire, completion.CompletedHeadWire)
	if err != nil || replayed.Head.ResultDigest != committed.Head.ResultDigest || objects.writes != writes {
		t.Fatalf("exact seed completion replay changed ledger: writes=%d prior=%d err=%v",
			objects.writes, writes, err)
	}
	for _, test := range []struct {
		name string
		ids  []string
	}{
		{name: "missing", ids: slices.Clone(observed.NSGOCIDs[:1])},
		{name: "extra", ids: append(slices.Clone(observed.NSGOCIDs), "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.foreign")},
		{name: "duplicate", ids: []string{observed.NSGOCIDs[0], observed.NSGOCIDs[0]}},
	} {
		t.Run("reject_"+test.name+"_OCI_NSG_set", func(t *testing.T) {
			badObservation := observed
			badObservation.NSGOCIDs = test.ids
			badGate := gate
			badGate.Instances = fakeInstanceObserver{badObservation}
			if _, err := badGate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmission) {
				t.Fatalf("changed OCI NSG set reached admission: %v", err)
			}
			if material.initialCalls != 0 || credentials.calls != 0 {
				t.Fatalf("changed OCI NSG set reached side effects: material=%d credentials=%d",
					material.initialCalls, credentials.calls)
			}
			if _, err := badGate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("changed OCI NSG set left an accepted marker: %v", err)
			}
		})
	}
	marker, err := gate.AdmitInitial(t.Context())
	if err != nil || marker.Slot != scope.Slot || marker.InstanceOCID != instanceID ||
		marker.ResultSHA256 != digestWire(completion.ResultWire) || material.initialCalls != 1 || credentials.calls != 1 {
		t.Fatalf("produced ledger history did not reach Gate.AdmitInitial: marker=%+v material=%d credentials=%d err=%v",
			marker, material.initialCalls, credentials.calls, err)
	}
}
