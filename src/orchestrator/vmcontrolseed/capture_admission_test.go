package vmcontrolseed

import (
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
)

func TestInitialCaptureAdmissionRefusesChangedRestartIntent(t *testing.T) {
	guests := []Guest{{ID: "gru-member-1", Address: "10.77.0.10", MembershipPublicKey: membershipPublic(t)}}
	declaration := PreliminaryCaptureDeclaration{MaxSnapshotBytes: 32 << 20, MaxTotalBytes: 128 << 20, Publication: &PreliminaryPublicationDeclaration{Identity: ociinstance.Config{Region: "sa-saopaulo-1"}}}
	materials, err := GenerateGRUWithPreliminaryCapture("capture-restart", guests, declaration)
	if err != nil {
		t.Fatal(err)
	}
	material := materials[guests[0].ID]
	defer material.Clear()
	if err := material.ValidatePreliminaryCapture(&declaration); err != nil {
		t.Fatal(err)
	}
	if err := material.ValidatePreliminaryCapture(nil); err == nil {
		t.Fatal("removed capture declaration reused privileged source admission")
	}
	changed := declaration
	changed.MaxTotalBytes *= 2
	if err := material.ValidatePreliminaryCapture(&changed); err == nil {
		t.Fatal("changed capacity reused source admission")
	}
	changed = declaration
	changed.Publication = nil
	if err := material.ValidatePreliminaryCapture(&changed); err == nil {
		t.Fatal("removed publication reused privileged source admission")
	}
	changed.Publication = &PreliminaryPublicationDeclaration{Identity: ociinstance.Config{Region: "us-ashburn-1"}}
	if err := material.ValidatePreliminaryCapture(&changed); err == nil {
		t.Fatal("changed provider identity reused source admission")
	}
	plain, err := GenerateGRU("plain-restart", guests)
	if err != nil {
		t.Fatal(err)
	}
	defer plain[guests[0].ID].Clear()
	if err := plain[guests[0].ID].ValidatePreliminaryCapture(nil); err != nil {
		t.Fatal(err)
	}
	if err := plain[guests[0].ID].ValidatePreliminaryCapture(&declaration); err == nil {
		t.Fatal("capture enabled without matching admitted capability")
	}
}
