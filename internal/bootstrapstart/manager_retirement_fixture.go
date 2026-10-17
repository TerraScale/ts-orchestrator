//go:build fixturetest

package bootstrapstart

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
)

type managerRetirementFixtureSources struct {
	key ed25519.PrivateKey
	sdk *managerRetirementSDKState
}

type managerRetirementSDKState struct {
	mu        sync.Mutex
	instances map[string]InstanceObservation
}

func (state *managerRetirementSDKState) lookup(request *http.Request) (InstanceObservation, bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	for id, observed := range state.instances {
		if request.URL.Path == "/20160918/instances/"+id || request.URL.Path == "/20160918/vnics/"+observed.PrimaryVNICOCID ||
			request.URL.Path == "/20160918/subnets/"+observed.SubnetOCID || request.URL.Path == "/20160918/vnicAttachments" && request.URL.Query().Get("instanceId") == id {
			observed.NSGOCIDs = slices.Clone(observed.NSGOCIDs)
			return observed, true
		}
	}
	return InstanceObservation{}, false
}

// CompleteManagedControllers completes both actual selected managed attempts
// through their signed candidate/receipt/result/progress and protected HEAD CAS.
// SDK facts remain behind the signed-request HTTP fixture, not a proof factory.
func (fixture *ControllerManagerStartupFixture) CompleteManagedControllers(t *testing.T) []InstanceObservation {
	t.Helper()
	selected, err := fixture.Reader.ReadCurrent(t.Context(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	result := []InstanceObservation{fixture.Instance}
	for _, row := range selected.Plan.Plan().Peers {
		result = append(result, fixture.completeManagedController(t, selected, row, false))
	}
	return result
}

// CompleteReplacementManagedController completes only the already root-retired
// current protected successor attempt, with a new instance and signed proofs.
func (fixture *ControllerManagerStartupFixture) CompleteReplacementManagedController(t *testing.T, slot string) InstanceObservation {
	t.Helper()
	selected, err := fixture.Reader.ReadCurrent(t.Context(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range selected.Plan.Plan().Peers {
		if row.Slot == slot {
			return fixture.completeManagedController(t, selected, row, true)
		}
	}
	t.Fatal("replacement slot absent from current signed founder plan")
	return InstanceObservation{}
}

func (fixture *ControllerManagerStartupFixture) completeManagedController(t *testing.T, selected CurrentFounderAuthority, row bootstrap.FounderPeerRow, replacement bool) InstanceObservation {
	t.Helper()
	ledger := fixture.recipientSources.ledger
	now := time.Now().UTC().Truncate(time.Second)
	scope := bootstrap.BootstrapScope{DeploymentID: fixture.Accepted.DeploymentID, Cell: fixture.Accepted.Cell, Slot: row.Slot}
	var intent bootstrap.Intent
	var intentWire []byte
	var head bootstrap.SlotHead
	if replacement {
		state, err := ledger.ReadSlot(t.Context(), scope)
		if err != nil || state.Intent.Attempt < 2 || state.Result != nil {
			t.Fatal("replacement fixture requires an incomplete root-retired protected HEAD", err)
		}
		intent, intentWire, head = state.Intent, state.IntentRecord.Bytes, state.Head
	} else {
		var err error
		intent, err = selected.Plan.InitialManagedPeerIntent(row.Slot, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	sign := func(domain string, payload any, issued, expires time.Time) []byte {
		t.Helper()
		return fixture.signManagerRetirementRecord(t, scope, domain, payload, issued, expires)
	}
	expires := selected.Plan.Plan().LaunchDeadline
	if !replacement {
		intentWire = sign("bootstrap-intent", intent, now, expires)
		head = bootstrap.SlotHead{SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.Accepted.Environment, Role: "controller", Slot: row.Slot,
			Attempt: intent.Attempt, Generation: intent.Generation, IntentDigest: digestWire(intentWire)}
		if _, err := ledger.ReserveSlot(t.Context(), scope, intentWire, sign("bootstrap-slot-head", head, now, expires)); err != nil {
			t.Fatal(err)
		}
	}
	refresh := func(ctx context.Context) (bootstrap.VerifiedFounderPeer, error) {
		current, err := fixture.Reader.ReadCurrent(ctx, time.Now().UTC())
		if err != nil {
			return bootstrap.VerifiedFounderPeer{}, err
		}
		recovery, err := ledger.ReadForManagedPeerRecovery(ctx, scope)
		if err != nil {
			return bootstrap.VerifiedFounderPeer{}, err
		}
		return current.Plan.AuthorizeFounderPeerRecovery(ctx, row.Slot, recovery, fixture.Roots, recovery.AuthorizationTime(), current.SelectionExpiresAt,
			trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew})
	}
	progress := func(value bootstrap.ManagedPeerProgress, issued, expires time.Time) ([]byte, error) {
		payload, err := trust.EncodePayload(value)
		if err != nil {
			return nil, err
		}
		envelope, err := trust.Sign(payload, trust.Scope{Domain: "bootstrap-progress", DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.Accepted.Environment, Role: "controller", Slot: scope.Slot}, issued, expires, fixture.retirementFixture.key)
		if err != nil {
			return nil, err
		}
		return trust.EncodeEnvelope(envelope)
	}
	instanceSuffix := row.Slot
	if replacement {
		instanceSuffix = fmt.Sprintf("%s-a%d", row.Slot, intent.Attempt)
	}
	observed := InstanceObservation{InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1." + instanceSuffix, BootstrapCreateKey: intent.CreateKey, CompartmentOCID: row.CompartmentOCID,
		ImageOCID: row.ImageOCID, ETag: "manager-retirement-" + row.Slot, AvailabilityDomain: row.AvailabilityDomain, FaultDomain: row.FaultDomain, Shape: row.Shape,
		SubnetOCID: row.SubnetOCID, NSGOCIDs: slices.Clone(row.NetworkSecurityGroupOCIDs), PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1." + instanceSuffix,
		PrimaryPrivateIP: row.PrivateIP, PrimaryVNIC: true, LifecycleState: "RUNNING"}
	fixture.retirementFixture.sdk.mu.Lock()
	fixture.retirementFixture.sdk.instances[observed.InstanceOCID] = observed
	fixture.retirementFixture.sdk.mu.Unlock()
	candidate := bootstrap.ManagedPeerCandidate{SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.Accepted.Environment, Role: "controller", Slot: row.Slot,
		Attempt: intent.Attempt, Generation: intent.Generation, IntentDigest: digestWire(intentWire), CreateKey: intent.CreateKey, FounderPlanSHA256: intent.FounderPlanSHA256,
		PeerRowDigest: intent.PeerRowDigest, ManifestDigest: intent.ManifestDigest, LaunchProfileDigest: intent.LaunchRequestDigest, InstanceOCID: observed.InstanceOCID}
	candidateWire := sign("bootstrap-candidate", candidate, now, expires)
	if err := ledger.RecordManagedPeerCandidate(t.Context(), scope, candidateWire, progress, refresh); err != nil {
		t.Fatal(err)
	}
	actual, err := fixture.Observer.ObserveInstance(t.Context(), observed.InstanceOCID)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().UTC().Truncate(time.Second)
	facts := bootstrap.InstanceFacts{DeploymentID: scope.DeploymentID, Environment: fixture.Accepted.Environment, ClusterID: fixture.Accepted.ClusterID, Cell: oci.Region(scope.Cell),
		OCIRegion: intent.OCIRegion, Role: "controller", Slot: row.Slot, InstanceOCID: actual.InstanceOCID, CompartmentOCID: actual.CompartmentOCID, ImageOCID: actual.ImageOCID,
		CreateKey: intent.CreateKey, IntentSHA256: digestWire(intentWire), Profile: bootstrap.LaunchProfile{Slot: row.Slot, CompartmentOCID: actual.CompartmentOCID,
			AvailabilityDomain: actual.AvailabilityDomain, FaultDomain: actual.FaultDomain, SubnetOCID: actual.SubnetOCID, NetworkSecurityGroupOCIDs: slices.Clone(actual.NSGOCIDs), Shape: actual.Shape}}
	startup, err := verifiedFounderManifestContext(t.Context(), selected, row.Slot, fixture.Roots, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	manifest, ok := startup.(bootstrap.VerifiedManifest)
	if !ok {
		t.Fatal("retirement fixture requires the actual legacy root-signed manifest")
	}
	receiptEnvelope, err := bootstrap.SignPeerReceipt(manifest, facts, now, expires, fixture.retirementFixture.key)
	if err != nil {
		t.Fatal(err)
	}
	receiptWire, err := trust.EncodeEnvelope(receiptEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	positive := bootstrap.Result{SchemaVersion: 1, Mode: bootstrap.IntentModeManaged, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.Accepted.Environment, Role: "controller", Slot: row.Slot,
		Attempt: intent.Attempt, Generation: intent.Generation, RegionIntentGeneration: intent.RegionIntentGeneration, IntentDigest: digestWire(intentWire), InstanceOCID: actual.InstanceOCID,
		ETag: actual.ETag, OCIRegion: intent.OCIRegion, CompartmentOCID: actual.CompartmentOCID, ImageOCID: actual.ImageOCID, Shape: actual.Shape,
		ObservedProfileDigest: intent.LaunchRequestDigest, PeerReceiptDigest: digestWire(receiptWire), CreateKey: intent.CreateKey, ObservedAt: observedAt}
	positiveWire := sign("bootstrap-result", positive, now, expires)
	head.CandidateDigest, head.ResultDigest = digestWire(candidateWire), digestWire(positiveWire)
	if _, err := ledger.RecordManagedPeer(t.Context(), scope, selected.ManifestWires[row.Slot], receiptWire, facts, positiveWire, sign("bootstrap-slot-head", head, now, expires), progress, refresh); err != nil {
		t.Fatal(err)
	}
	return actual
}

func (fixture *ControllerManagerStartupFixture) signManagerRetirementRecord(t *testing.T, scope bootstrap.BootstrapScope, domain string, payload any, issued, expires time.Time) []byte {
	t.Helper()
	wire, err := trust.EncodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(wire, trust.Scope{Domain: domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.Accepted.Environment, Role: "controller", Slot: scope.Slot}, issued, expires, fixture.retirementFixture.key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// SetControllerLifecycle changes only vendor facts behind the actual SDK HTTP
// boundary. No opaque proof can be created without re-reading these facts.
func (fixture *ControllerManagerStartupFixture) SetControllerLifecycle(instanceID, lifecycle string) error {
	if fixture == nil || fixture.retirementFixture == nil {
		return ErrInstanceObservation
	}
	state := fixture.retirementFixture.sdk
	state.mu.Lock()
	defer state.mu.Unlock()
	observed, ok := state.instances[instanceID]
	if !ok || lifecycle != "RUNNING" && lifecycle != "TERMINATING" && lifecycle != "TERMINATED" {
		return ErrInstanceObservation
	}
	observed.LifecycleState = lifecycle
	state.instances[instanceID] = observed
	return nil
}

// SignControllerRetirement signs the actual current managed slot, independently
// of its SDK lifecycle; the production proof must reject a signed RUNNING host.
func (fixture *ControllerManagerStartupFixture) SignControllerRetirement(t *testing.T, slot string) []byte {
	t.Helper()
	scope := bootstrap.BootstrapScope{DeploymentID: fixture.Accepted.DeploymentID, Cell: fixture.Accepted.Cell, Slot: slot}
	state, err := fixture.recipientSources.ledger.ReadSlot(t.Context(), scope)
	if err != nil || state.Result == nil {
		t.Fatal("actual managed slot unavailable", err)
	}
	response, err := fixture.Observer.compute.GetInstance(t.Context(), core.GetInstanceRequest{InstanceId: new(state.Result.InstanceOCID)})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(response.Instance)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	evidence, err := bootstrap.SlotRetirementCandidate(state, digestWire(wire), "actual-fixture-root", now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bootstrap.SignSlotRetirement(evidence, now, now.Add(time.Hour), fixture.Root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err = trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (fixture *ControllerManagerStartupFixture) AdvanceRetiredController(t *testing.T, slot string, wire []byte) {
	t.Helper()
	scope := bootstrap.BootstrapScope{DeploymentID: fixture.Accepted.DeploymentID, Cell: fixture.Accepted.Cell, Slot: slot}
	ledger := fixture.recipientSources.ledger
	state, err := ledger.ReadSlot(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	selected, err := fixture.Reader.ReadCurrent(t.Context(), now)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := selected.Plan.ReplacementManagedPeerIntent(slot, state, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	expires := selected.Plan.Plan().LaunchDeadline
	intentWire := fixture.signManagerRetirementRecord(t, scope, "bootstrap-intent", intent, now, expires)
	head, err := bootstrap.ReplacementSlotHead(state, intent, intentWire, wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AdvanceSlot(t.Context(), scope, state.HeadRecord.ETag, wire, intentWire, fixture.signManagerRetirementRecord(t, scope, "bootstrap-slot-head", head, now, expires)); err != nil {
		t.Fatal(err)
	}
}

func (fixture *ControllerManagerStartupFixture) ReadControllerManagerRetirement(ctx context.Context, slot string, wire []byte) (*ManagerRetirement, error) {
	if fixture == nil || fixture.retirementFixture == nil {
		return nil, fmt.Errorf("retirement fixture source unavailable")
	}
	return readControllerManagerRetirement(ctx, fixture.Reader, fixture.Accepted, slot, wire, fixture.recipientSources)
}
