package bootstrapstart

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

func TestFounderFloorArtifactsMatchInitializedPeerFloor(t *testing.T) {
	fixture, caller, _, _ := newFounderRuntimeFixtureWithSetup(t, func(fixture *founderSignerFixture) {
		founderFixtureWithAdmissibleRelease(t, fixture)
	})
	row := fixture.plan.Peers[0]
	if err := caller.runPeer(t.Context(), row.Slot); err != nil {
		t.Fatal(err)
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	gate, _, _ := newFounderPeerGate(t, fixture, &founderAdmissionLedger{ledger: ledger}, row)
	accepted, err := gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	state, err := ledger.ReadSlot(t.Context(), bootstrap.BootstrapScope{
		DeploymentID: accepted.DeploymentID, Cell: accepted.Cell, Slot: accepted.Slot})
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := testFounderServiceIdentity()
	artifacts, err := BuildVerifiedPeerFloorArtifacts(t.Context(), fixture.baked, accepted,
		state, fixture.objects, uid, gid, fixture.now)
	if err != nil || len(artifacts) != 3 {
		t.Fatalf("verified peer floor artifacts: count=%d err=%v", len(artifacts), err)
	}
	actual, err := os.ReadFile(filepath.Join(fixture.peerFloor.directory,
		founderSelectionFloorName))
	if err != nil || !bytes.Equal(actual, artifacts[2].Bytes) ||
		artifacts[0].Path != FounderSelectionFloorDirectory || !artifacts[0].Directory ||
		artifacts[0].Mode != 0o700 || artifacts[1].Mode != 0o600 ||
		artifacts[2].Mode != 0o600 || artifacts[2].UID != uid || artifacts[2].GID != gid {
		t.Fatalf("artifact differs from runtime floor: artifacts=%+v err=%v", artifacts, err)
	}
	seedFixture := newFounderSelectionFixture(t)
	selectionWire := seedFixture.publish(t, seedFixture.selection)
	seedState := bootstrap.SlotState{Intent: bootstrap.Intent{Mode: bootstrap.IntentModeExternalSeed},
		Head:           bootstrap.SlotHead{ResultDigest: seedFixture.accepted.ResultSHA256},
		ResultRecord:   &bootstrap.StoredRecord{SHA256: seedFixture.accepted.ResultSHA256},
		ManifestRecord: &bootstrap.StoredRecord{SHA256: seedFixture.accepted.ManifestSHA256}}
	seedArtifacts, err := BuildVerifiedSeedFloorArtifacts(t.Context(), seedFixture.baked, seedFixture.accepted,
		seedState, seedFixture.objects, uid, gid, seedFixture.now)
	expectedSeedWire, encodeErr := encodeFounderSelectionFloor(1, digestWire(selectionWire))
	if err != nil || encodeErr != nil || len(seedArtifacts) != 3 ||
		!bytes.Equal(seedArtifacts[2].Bytes, expectedSeedWire) {
		t.Fatalf("verified seed floor artifact differs from selected generation: count=%d err=%v", len(seedArtifacts), err)
	}
}
