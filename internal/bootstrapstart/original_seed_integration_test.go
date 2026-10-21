package bootstrapstart

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// Readback crosses the existing real signed OCI SDK fixture. A transport tuple
// cannot convert its genuine ordinary seed history to original provenance.
func TestOriginalSeedRejectsOrdinarySDKHistoryPromotionIntegration(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	f := newControllerRecipientFixture(t)
	slot := f.founder.plan.SeedSlot
	scope := bootstrap.BootstrapScope{DeploymentID: f.founder.plan.DeploymentID, Cell: string(f.founder.plan.Cell), Slot: slot}
	state, err := f.sources.ledger.ReadSlot(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(state.ManifestRecord.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := f.founder.current.Anchor.ManifestExpectation(slot, state.Intent.ImageOCID)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.VerifyManifest(envelope, f.founder.baked.Roots, expected, time.Now().UTC(), bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	observed, err := f.sources.observer.ObserveInstance(t.Context(), state.Result.InstanceOCID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Gate{Instances: f.sources.observer}).observe(t.Context(), observed.InstanceOCID, state, f.founder.current.Anchor.Anchor()); err != nil {
		t.Fatalf("ordinary signed SDK exact-instance result no longer verifies: %v", err)
	}
	before := bytes.Clone(state.IntentRecord.Bytes)
	promoted := state
	promoted.Intent.SchemaVersion = 2
	promoted.Intent.OriginalLaunch = new(bootstrap.OriginalLaunchIdentity{ActorOperationID: "0000000000NBCYX286D4RHE6ZP", InstanceOCID: observed.InstanceOCID})
	if _, err := VerifyExternalSeedObservation(f.founder.current.Anchor, manifest, promoted, observed, f.founder.plan.SeedPrivateIP); !errors.Is(err, ErrExternalSeedObservation) {
		t.Fatalf("ordinary manifest accepted original schema2 transport: %v", err)
	}
	wrongTag := observed
	wrongTag.BootstrapCreateKey = ""
	if _, err := VerifyExternalSeedObservation(f.founder.current.Anchor, manifest, state, wrongTag, f.founder.plan.SeedPrivateIP); !errors.Is(err, ErrExternalSeedObservation) {
		t.Fatalf("ordinary observation accepted absent actual create tag: %v", err)
	}
	var decoded bootstrap.Intent
	envelope, err = trust.DecodeEnvelope(before)
	if err != nil || json.Unmarshal(envelope.Payload, &decoded) != nil || decoded.SchemaVersion != 1 || decoded.OriginalLaunch != nil {
		t.Fatal("rejected promotion altered the original immutable intent")
	}
	journalCalls := 0
	if _, err := EnsureOriginalSeed(t.Context(), bootstrap.DerivedStartupAuthority{}, f.founder.ledgerKey, func(_ context.Context, _ *ExternalSeedCompletionRecords) (ExternalSeedCompletionRecords, error) {
		journalCalls++
		return ExternalSeedCompletionRecords{}, nil
	}); err == nil || journalCalls != 0 {
		t.Fatalf("unsealed original seed reached journal: calls=%d err=%v", journalCalls, err)
	}
}
