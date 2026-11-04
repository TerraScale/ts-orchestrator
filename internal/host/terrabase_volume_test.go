//go:build linux

package host

import (
	"context"

	"path/filepath"

	"strings"

	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

// TestTerraBaseDataVolumeNeverFormatsExistingData formats only a device
// without any filesystem identity or signature whose sampled blocks are all
// zero; it mounts one clean ext4 filesystem and holds everything else.
func TestTerraBaseDataVolumeNeverFormatsExistingData(t *testing.T) {
	const uuid = "0f8fad5b-d9cb-469f-a165-70867728950e"
	for _, tc := range []struct {
		name  string
		probe volumeFilesystemProbe
		want  volumeInitAction
	}{
		{"mounted", volumeFilesystemProbe{Mounted: true, BlankSample: true}, volumeInitHold},
		{"mounted ext4", volumeFilesystemProbe{Mounted: true, FSUUID: uuid, FSType: "ext4", Signatures: true}, volumeInitHold},
		{"ext4", volumeFilesystemProbe{FSUUID: uuid, FSType: "ext4", Signatures: true}, volumeInitMount},
		{"ext4 blank sample", volumeFilesystemProbe{FSUUID: uuid, FSType: "ext4", Signatures: true, BlankSample: true}, volumeInitMount},
		{"ext4 with foreign signatures", volumeFilesystemProbe{FSUUID: uuid, FSType: "ext4", Signatures: true, ForeignSignatures: true}, volumeInitHold},
		{"ext4 without signatures", volumeFilesystemProbe{FSUUID: uuid, FSType: "ext4"}, volumeInitHold},
		{"ext4 without uuid", volumeFilesystemProbe{FSType: "ext4", Signatures: true}, volumeInitHold},
		{"xfs", volumeFilesystemProbe{FSUUID: uuid, FSType: "xfs", Signatures: true}, volumeInitHold},
		{"luks", volumeFilesystemProbe{FSUUID: uuid, FSType: "crypto_LUKS", Signatures: true}, volumeInitHold},
		{"uuid without type", volumeFilesystemProbe{FSUUID: uuid, Signatures: true, BlankSample: true}, volumeInitHold},
		{"signatures without type", volumeFilesystemProbe{Signatures: true, BlankSample: true}, volumeInitHold},
		{"non-zero sampled data", volumeFilesystemProbe{}, volumeInitHold},
		{"foreign signatures only", volumeFilesystemProbe{ForeignSignatures: true, BlankSample: true}, volumeInitHold},
		{"blank", volumeFilesystemProbe{BlankSample: true}, volumeInitFormat},
	} {
		action, err := terraBaseVolumeAction(tc.probe)
		if action != tc.want {
			t.Errorf("%s: action %d, want %d", tc.name, action, tc.want)
		}
		if (action == volumeInitHold) != (err != nil) {
			t.Errorf("%s: action %d with error %v", tc.name, action, err)
		}
	}
}

// The pending grant can be redelivered only to the original initializer and
// host registration; replacement hosts learn the UUID without format authority.
func TestTerraBaseDataVolumeFirstFormatIsFenced(t *testing.T) {
	c, _, _, _, _ := testController(t)
	member := Registration{Cell: "gru", Node: "gru-1-db-1", Roles: []string{terrabase.Role}, PublicKey: "first-host", Generation: 1,
		TerraBaseDataVolumeID: "ocid1.volume.oc1..first"}
	ask := func(r Registration, attempt string) (terraBaseFormatReply, error) {
		payload, _ := protocol.EncodeJSON(terraBaseFormatQuery{VolumeID: r.TerraBaseDataVolumeID, AttemptID: attempt})
		reply, err := c.serveTerraBaseFormat(t.Context(), request{Node: r.Node, Payload: payload}, r)
		if err != nil {
			return terraBaseFormatReply{}, err
		}
		return reply.(terraBaseFormatReply), nil
	}
	const attempt = "014D2PF2DBSQQG28T5CY4TQKFF"
	first, err := ask(member, attempt)
	if err != nil || !first.Granted || !hostvolume.ValidUUID(first.UUID) || first.AttemptID != attempt {
		t.Fatalf("first request = %+v, %v; want a grant with a UUID", first, err)
	}
	if again, err := ask(member, attempt); err != nil || !again.Granted || again.UUID != first.UUID || again.AttemptID != attempt {
		t.Fatalf("original initializer retry = %+v, %v; want the same grant", again, err)
	}
	replacement := member
	replacement.PublicKey = "replacement-host"
	newGeneration := member
	newGeneration.Generation++
	for _, r := range []Registration{replacement, newGeneration} {
		again, err := ask(r, attempt)
		if err != nil || again.Granted || again.UUID != first.UUID {
			t.Fatalf("later request from %s = %+v, %v; want a refusal naming %s", r.PublicKey, again, err, first.UUID)
		}
	}
	if again, err := ask(member, "7YVJX9GXJM688FXQ5TK1V58CGG"); err != nil || again.Granted || again.UUID != first.UUID {
		t.Fatalf("different initializer = %+v, %v; want a refusal", again, err)
	}
	other, err := ask(Registration{Cell: "gru", Node: "gru-1-db-2", Roles: []string{terrabase.Role},
		PublicKey: "other-host", Generation: 1, TerraBaseDataVolumeID: "ocid1.volume.oc1..other"}, attempt)
	if err != nil || !other.Granted || other.UUID == first.UUID {
		t.Fatalf("another member = %+v, %v; want its own grant", other, err)
	}
	for name, r := range map[string]Registration{
		"no terrabase role": {Cell: "gru", Node: "gru-1-db-3", Roles: []string{"host"}},
		"managed host":      {Cell: "gru", Node: "gru-1-db-3", Roles: []string{terrabase.Role}, ManagedOCI: &ManagedOCIBinding{}},
	} {
		if _, err := ask(r, attempt); err == nil {
			t.Fatalf("%s was granted a format", name)
		}
	}
}

// TestTerraBaseDataVolumeLossStopsTheRunningMember: a member keeps running
// only while its data volume mount verifies; otherwise it is stopped and
// reported failed.
func TestTerraBaseDataVolumeLossStopsTheRunningMember(t *testing.T) {
	runner := &memoryRunner{observed: map[string]Observation{terrabase.Role: {Role: terrabase.Role, Running: true}}}
	agent := &Agent{terraBase: map[string]terraBaseMember{terrabase.Role: {}}, runner: runner, cfg: AgentConfig{
		Node: "gru-1-db-1", TerraBaseRoot: filepath.Join(traversableTempDir(t), "terrabase"), WorkloadIdentity: testAgentIdentity(),
		TerraBaseDataVolume: true, VolumeInitSocket: filepath.Join(t.TempDir(), "absent.sock")}}
	report := agent.terraBaseRunningReport(t.Context(), Desired{Role: terrabase.Role})
	if report.State != "failed" || !strings.Contains(report.Error, "data volume") {
		t.Fatalf("report = %s %q, want failed for the data volume", report.State, report.Error)
	}
	if observed, _ := runner.Observe(t.Context(), terrabase.Role); observed.Running {
		t.Fatal("the member kept running without its data volume")
	}
	if _, tracked := agent.terraBase[terrabase.Role]; tracked {
		t.Fatal("the stopped member is still tracked")
	}
}

// failingRunner observes and stops a member like memoryRunner, failing on
// request.
type failingRunner struct {
	*memoryRunner
	observeErr, stopErr error
	stops               int
}

func (r *failingRunner) Observe(ctx context.Context, role string) (Observation, error) {
	if r.observeErr != nil {
		return Observation{}, r.observeErr
	}
	return r.memoryRunner.Observe(ctx, role)
}

func (r *failingRunner) Stop(ctx context.Context, role string) error {
	r.stops++
	if r.stopErr != nil {
		return r.stopErr
	}
	return r.memoryRunner.Stop(ctx, role)
}
