package bootstrapstart

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func TestExternalSeedProducedLedgerHistoryAdmitsInitial(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	founderFixtureWithAdmissibleRelease(t, fixture)
	anchor := fixture.current.Anchor
	manifestWire := fixture.manifests["seed-a"]
	manifestEnvelope, err := trust.DecodeEnvelope(manifestWire)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := anchor.ManifestExpectation("seed-a", fixture.plan.Peers[0].ImageOCID)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.VerifyManifest(manifestEnvelope, fixture.baked.Roots, expected,
		fixture.now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := manifest.Profile("seed-a")
	if !ok {
		t.Fatal("signed seed manifest lacks launch profile")
	}
	anchored := anchor.Anchor()
	scope := bootstrap.BootstrapScope{DeploymentID: anchored.DeploymentID, Cell: string(anchored.Cell), Slot: "seed-a"}
	createKey := "reviewed-seed-create"
	reservation, err := BuildExternalSeedReservation(ExternalSeedReservationRequest{
		Identity: fixture.baked.Identity, Anchor: anchor, Manifest: manifest,
		ReviewedPlanSHA256: digestWire([]byte("reviewed plan")), CreateIdentity: createKey,
		LedgerPrivate: fixture.ledgerKey, Now: fixture.now, ExpiresAt: fixture.now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("build CLI reservation records: %v", err)
	}
	intentWire, headWire := reservation.IntentWire, reservation.InitialHeadWire
	objects := &founderLedgerObjects{objects: make(map[string]founderStoredObject), now: fixture.now}
	config, err := currentLedgerConfig(anchor, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	config.VerificationNow = func() time.Time { return fixture.now }
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
		Identity: fixture.baked.Identity, Anchor: anchor, Manifest: manifest,
		ReviewedPlanSHA256: digestWire([]byte("reviewed plan")), CreateIdentity: "another-seed-create",
		LedgerPrivate: fixture.ledgerKey, Now: fixture.now, ExpiresAt: fixture.now.Add(time.Hour)})
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
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.seed-a", PrimaryPrivateIP: fixture.plan.SeedPrivateIP,
		PrimaryVNIC: true, LifecycleState: "RUNNING"}
	reader := &founderAdmissionLedger{ledger: ledger}
	markerDirectory := filepath.Join(t.TempDir(), "marker")
	if err := os.Mkdir(markerDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(markerDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	material := new(countingMaterialChecker)
	credentials := new(founderAdmissionCredentials)
	gate := Gate{Roots: fixture.baked.Roots, AnchorWire: fixture.baked.AnchorWire,
		Expected:                     fixture.baked.Identity.AnchorExpectation(),
		LoadedControllerConfigSHA256: manifest.Manifest().ControllerConfigSHA256,
		Descriptor:                   fixedDescriptor{slot: scope.Slot, instance: instanceID},
		Instances:                    fakeInstanceObserver{observed}, Ledgers: reader, Binary: fixedBinaryChecker{},
		Material: material, Credentials: credentials,
		Markers:    MarkerStore{directory: markerDirectory, ownerUID: uint32(os.Getuid()), allowUnsafeAncestors: true},
		ClockCheck: func() error { return nil }, Now: func() time.Time { return fixture.now },
		InitialFounderFloor: func(_ context.Context, marker AcceptedInstall, _ time.Time) error {
			if marker.InstanceOCID != instanceID || marker.ResultSHA256 == "" {
				t.Fatal("seed floor received another instance or no result")
			}
			return nil
		}}
	if _, err := gate.AdmitInitial(t.Context()); err == nil || material.initialCalls != 0 {
		t.Fatalf("uncommitted seed reached initial admission: err=%v material=%d", err, material.initialCalls)
	}
	facts, err := VerifyExternalSeedObservation(anchor, manifest, reserved, observed, fixture.plan.SeedPrivateIP)
	if err != nil {
		t.Fatalf("exact OCI readback differs from signed reservation: %v", err)
	}
	completion, err := BuildExternalSeedCompletion(ExternalSeedCompletionRequest{
		Identity: fixture.baked.Identity, Anchor: anchor, Manifest: manifest, Roots: fixture.baked.Roots,
		State: reserved, Observation: observed, ObservedAt: fixture.now,
		ExpectedPrivateIP: fixture.plan.SeedPrivateIP, RootPrivate: fixture.root,
		LedgerPrivate: fixture.ledgerKey, Now: fixture.now, ExpiresAt: fixture.now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("build CLI completion records: %v", err)
	}
	reused, err := BuildExternalSeedCompletion(ExternalSeedCompletionRequest{
		Identity: fixture.baked.Identity, Anchor: anchor, Manifest: manifest, Roots: fixture.baked.Roots,
		State: reserved, Observation: observed, ObservedAt: fixture.now.Add(10 * time.Minute),
		ExpectedPrivateIP: fixture.plan.SeedPrivateIP, RootPrivate: fixture.root,
		LedgerPrivate: fixture.ledgerKey, ReuseReceiptWire: completion.ReceiptWire,
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
	writes := objects.writes
	replayed, err := ledger.RecordExternalSeed(t.Context(), scope, manifestWire, completion.ReceiptWire,
		facts, completion.ResultWire, completion.CompletedHeadWire)
	if err != nil || replayed.Head.ResultDigest != committed.Head.ResultDigest || objects.writes != writes {
		t.Fatalf("exact seed completion replay changed ledger: writes=%d prior=%d err=%v",
			objects.writes, writes, err)
	}
	marker, err := gate.AdmitInitial(t.Context())
	if err != nil || marker.Slot != scope.Slot || marker.InstanceOCID != instanceID ||
		marker.ResultSHA256 != digestWire(completion.ResultWire) || material.initialCalls != 1 || credentials.calls != 1 {
		t.Fatalf("produced ledger history did not reach Gate.AdmitInitial: marker=%+v material=%d credentials=%d err=%v",
			marker, material.initialCalls, credentials.calls, err)
	}
}
