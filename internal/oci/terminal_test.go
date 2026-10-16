package oci

import (
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

func terminalFixture(t *testing.T) (*fleet, *fakeProvider, *fakeJournal, *fakeFencer, authority.TerminalIntent) {
	t.Helper()
	journal := newFakeJournal()
	fleet, provider, fencer, intent := terminalFixtureWithJournal(t, journal)
	return fleet, provider, journal, fencer, intent
}

func terminalFixtureWithJournal(t *testing.T, journal Journal) (*fleet, *fakeProvider, *fakeFencer, authority.TerminalIntent) {
	t.Helper()
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	api, err := newTestFleet(config, regionIntent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fleet := api.(*fleet)
	intent := authority.TerminalIntent{
		Cell: "gru", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", Region: string(config.Region),
		Owner: config.Owner, CompartmentID: config.CompartmentID, FleetGeneration: config.Generation,
		PlacementGeneration: 3, PlacementPayloadDigest: testEnsureRequest(entityid.Derive("test-operation", "unused")).BootPins.IntentPayloadDigest,
		OperationID: "0000000000YQ07YFE5HRZF55KH", Nonce: "00000000000040008000000000000001",
		DisposableWorkload: true, AcknowledgePermanentDataLoss: true, AuthorizeForcedStop: true,
	}
	for i, seat := range []string{"000000000082AXF7GZQT1D126Y", "0000000000XG8SBD7XGE97V28G"} {
		request := testEnsureRequest(entityid.Derive("test-operation", "terminal-host", seat))
		request.BootPins.SeatID = seat
		request.PrivateIP = "10.251.0.2" + string(rune('1'+i))
		host, err := fleet.EnsureHost(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		dataKey := terminalDigestToken("tv", intent.DatabaseID, intent.PartitionID, intent.Region, seat)
		volume, err := fleet.CreateRetainedVolume(t.Context(), VolumeCreateRequest{
			Name: "gru-1-db-1-data", DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
			MemberID: seat, CreateKey: dataKey, SizeGB: 50,
		})
		if err != nil {
			t.Fatal(err)
		}
		binding, found, err := journal.GetBootBinding(t.Context(), host.ID)
		if err != nil || !found {
			t.Fatalf("boot binding missing for %s: %v", host.ID, err)
		}
		intent.Targets = append(intent.Targets, authority.TerminalTarget{
			SeatID: seat, MemberID: entityid.Derive("test-terminal-member", seat),
			HostCreateKey: request.CreateKey, DataCreateKey: dataKey,
			InstanceID: host.ID, BootVolumeID: binding.BootVolumeID, DataVolumeID: volume.ID,
		})
	}
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}
	return fleet, provider, fencer, intent
}

func acceptTerminalFixture(t *testing.T, fencer *fakeFencer, intent authority.TerminalIntent) {
	t.Helper()
	payload, err := json.Marshal(intent, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	fencer.terminalEntry = authority.LogEntry{Kind: authority.MutationTerminalIntent,
		SubjectKey:  intent.DatabaseID + "." + intent.PartitionID,
		OperationID: intent.OperationID, Sequence: 42, Payload: payload}
}

func TestTerminalExactInventoryAndFinalReadback(t *testing.T) {
	fleet, provider, journal, fencer, intent := terminalFixture(t)
	blank := intent
	blank.Targets = append([]authority.TerminalTarget(nil), intent.Targets...)
	for i := range blank.Targets {
		blank.Targets[i].InstanceID, blank.Targets[i].BootVolumeID, blank.Targets[i].DataVolumeID = "", "", ""
	}
	resolved, err := fleet.DiscoverTerminalTargets(t.Context(), blank)
	if err != nil || len(resolved) != 2 || resolved[0] != intent.Targets[0] || resolved[1] != intent.Targets[1] {
		t.Fatalf("read-only terminal discovery did not recover exact ownership: %+v, %v", resolved, err)
	}
	if err := fleet.VerifyTerminalInventorySettled(t.Context(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.ReconcileTerminal(t.Context(), intent, 42); err == nil || provider.terminations != 0 {
		t.Fatalf("unaccepted marker reached OCI: terminations=%d err=%v", provider.terminations, err)
	}
	acceptTerminalFixture(t, fencer, intent)
	status, err := fleet.ReconcileTerminal(t.Context(), intent, 42)
	if err != nil || status.Phase != TerminalPhasePending || provider.terminations != 2 {
		t.Fatalf("first forced stop did not leave readback pending: %+v, %v", status, err)
	}
	for _, target := range intent.Targets {
		if _, ok := provider.bootVolumes[target.BootVolumeID]; !ok {
			t.Fatalf("boot volume %s was deleted before instance terminal readback", target.BootVolumeID)
		}
		if _, ok := provider.volumes[target.DataVolumeID]; !ok {
			t.Fatalf("data volume %s was deleted before instance terminal readback", target.DataVolumeID)
		}
	}
	for _, target := range intent.Targets {
		cloud := provider.instances[target.InstanceID]
		cloud.LifecycleState = "TERMINATED"
		provider.instances[target.InstanceID] = cloud
	}
	status, err = fleet.ReconcileTerminal(t.Context(), intent, 42)
	if err != nil || status.Phase != TerminalPhaseComplete {
		t.Fatalf("exact terminal readback did not complete: %+v, %v", status, err)
	}
	for _, target := range intent.Targets {
		if _, ok := provider.bootVolumes[target.BootVolumeID]; ok {
			t.Fatalf("boot volume %s survived", target.BootVolumeID)
		}
		if _, ok := provider.volumes[target.DataVolumeID]; ok {
			t.Fatalf("data volume %s survived", target.DataVolumeID)
		}
	}
	if len(journal.intents) != 10 {
		t.Fatalf("terminal operation intents missing: %d", len(journal.intents))
	}
	status, err = fleet.InspectTerminalStatus(t.Context(), intent)
	if err != nil || status.Phase != TerminalPhaseComplete {
		t.Fatalf("read-only terminal status did not confirm completion: %+v, %v", status, err)
	}
}

// Teardown trusts the journaled launch and boot binding, not the current
// allow-list: hosts of an image the cell no longer allows are still torn
// down, while a boot volume whose image differs from its binding holds.
func TestTerminalTearsDownHostsOfRevokedImages(t *testing.T) {
	fleet, provider, _, fencer, intent := terminalFixture(t)
	fleet.config.ImageID = "ocid1.image.oc1.sa-saopaulo-1.newer"
	if observed, err := fleet.Observe(t.Context()); err != nil || len(observed) != 0 {
		t.Fatalf("hosts of a revoked image are still members: %+v, %v", observed, err)
	}
	boot := provider.bootVolumes[intent.Targets[0].BootVolumeID]
	swapped := boot
	swapped.ImageID = fleet.config.ImageID
	provider.bootVolumes[boot.ID] = swapped
	if err := fleet.VerifyTerminalInventorySettled(t.Context(), intent); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("boot volume of another image than its binding: %v", err)
	}
	provider.bootVolumes[boot.ID] = boot
	if err := fleet.VerifyTerminalInventorySettled(t.Context(), intent); err != nil {
		t.Fatal(err)
	}
	acceptTerminalFixture(t, fencer, intent)
	if status, err := fleet.ReconcileTerminal(t.Context(), intent, 42); err != nil || provider.terminations != 2 {
		t.Fatalf("hosts of a revoked image were not stopped: %+v, %v", status, err)
	}
	for _, target := range intent.Targets {
		cloud := provider.instances[target.InstanceID]
		cloud.LifecycleState = "TERMINATED"
		provider.instances[target.InstanceID] = cloud
	}
	if status, err := fleet.ReconcileTerminal(t.Context(), intent, 42); err != nil || status.Phase != TerminalPhaseComplete {
		t.Fatalf("teardown of a revoked image's hosts did not complete: %+v, %v", status, err)
	}
}

func TestTerminalUnknownCreateAndForeignPinsHold(t *testing.T) {
	fleet, provider, journal, _, intent := terminalFixture(t)
	wrong := intent
	wrong.Targets = append([]authority.TerminalTarget(nil), intent.Targets...)
	wrong.Targets[0].DataVolumeID = "ocid1.volume.foreign"
	if err := fleet.VerifyTerminalInventorySettled(t.Context(), wrong); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("foreign data ID was admitted: %v", err)
	}
	request := testEnsureRequest(entityid.Derive("test-operation", "terminal-extra-host"))
	request.BootPins.SeatID = intent.Targets[0].SeatID
	operation := testLaunchIntent(request.CreateKey)
	if err := journal.RecordIntent(t.Context(), operation); err != nil {
		t.Fatal(err)
	}
	if err := fleet.VerifyTerminalInventorySettled(t.Context(), intent); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("unsettled host create attempt was admitted: %v", err)
	}
	delete(journal.intents, operationKey(operation))
	key := operationKey(OperationIntent{Action: actionVolumeCreate, Key: intent.Targets[0].DataCreateKey,
		Region: fleet.config.Region, Generation: fleet.config.Generation, Owner: fleet.config.Owner})
	result := journal.results[key]
	result.Unknown = true
	journal.results[key] = result
	if err := fleet.VerifyTerminalInventorySettled(t.Context(), intent); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("unknown data create result was admitted: %v", err)
	}
	if provider.terminations != 0 {
		t.Fatal("inventory verification mutated OCI")
	}
}
