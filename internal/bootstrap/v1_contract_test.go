package bootstrap

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func TestBootstrapAnchorRejectsNonV1ForCurrentAndHistoricalVerification(t *testing.T) {
	fixture := newBootstrapAnchorFixture(t)
	expected := BootstrapAnchorExpectation{DeploymentID: fixture.anchor.DeploymentID,
		Environment: fixture.anchor.Environment, Cell: fixture.anchor.Cell}
	for _, version := range []int{-1, 0, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			anchor := cloneBootstrapAnchor(fixture.anchor)
			anchor.SchemaVersion = version
			if _, err := SignBootstrapAnchor(anchor, fixture.now, fixture.now.Add(time.Hour), fixture.rootPrivate); !errors.Is(err, ErrBootstrapAnchorInvalid) {
				t.Fatalf("sign version %d: %v", version, err)
			}
			payload, err := trust.EncodePayload(anchor)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := trust.Sign(payload, bootstrapAnchorScope(anchor.DeploymentID, string(anchor.Cell), anchor.Environment),
				fixture.now, fixture.now.Add(time.Hour), fixture.rootPrivate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyBootstrapAnchor(envelope, fixture.roots, expected, fixture.now, BootstrapAnchorTrustPolicy()); !errors.Is(err, ErrBootstrapAnchorInvalid) {
				t.Fatalf("current version %d: %v", version, err)
			}
			if _, err := VerifyHistoricalBootstrapAnchor(envelope, fixture.roots, expected, fixture.now, BootstrapAnchorTrustPolicy()); !errors.Is(err, ErrBootstrapAnchorInvalid) {
				t.Fatalf("historical version %d: %v", version, err)
			}
		})
	}
}

func TestManifestRejectsNonV1WithoutDroppingCurrentFields(t *testing.T) {
	authority := newTestBootstrapAuthority(t)
	for _, version := range []int{-1, 0, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			manifest := cloneManifest(authority.manifest)
			manifest.SchemaVersion = version
			if err := manifest.Validate(); !errors.Is(err, ErrManifestInvalid) {
				t.Fatalf("manifest version %d: %v", version, err)
			}
		})
	}
}

func TestHistoricalLedgerRequiresCompleteCurrentGrant(t *testing.T) {
	fixture := newLedgerFixture(t)
	publicWire, err := trust.EncodeDelegatedPublicKey(fixture.authority.peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: 1,
		SubjectKeyID: keyID(t, fixture.authority.peerPublic), SubjectPublicKey: publicWire,
		Capabilities: fixture.ledger.config.Delegations[0].Capabilities()[:3]},
		fixture.now, fixture.now.Add(time.Hour), fixture.authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := trust.VerifyDelegationHistorical(grant, fixture.ledger.config.TrustRoots, fixture.ledger.config.TrustPolicy)
	if err != nil {
		t.Fatal(err)
	}
	config := fixture.ledger.config
	config.Delegations = []trust.VerifiedDelegation{verified}
	if _, err := NewLedger(fixture.client, config); err == nil {
		t.Fatal("current ledger accepted the retired three-domain grant")
	}
	if _, err := NewHistoricalLedger(fixture.client, config); err == nil {
		t.Fatal("historical ledger accepted the retired three-domain grant")
	}
	if err := validateInstancePrincipalLedgerConfig(config); err == nil {
		t.Fatal("Instance Principal pre-auth validation accepted the retired three-domain grant")
	}
}

func TestSlotReplacementRejectsNonV1InputsAndMissingManagedCandidate(t *testing.T) {
	fixture := newFounderPlanFixture(t)
	plan := fixture.verify(t)
	for _, version := range []int{-1, 0, 2, 3} {
		for _, field := range []string{"intent", "head", "result"} {
			t.Run(fmt.Sprintf("%s/%d", field, version), func(t *testing.T) {
				state := completedManagedSlotForRetirement()
				switch field {
				case "intent":
					state.Intent.SchemaVersion = version
				case "head":
					state.Head.SchemaVersion = version
				case "result":
					state.Result.SchemaVersion = version
				}
				if _, err := SlotRetirementCandidate(state, objectDigest([]byte("observed")), "root-fence", fixture.now); !errors.Is(err, ErrRetirementInvalid) {
					t.Fatalf("retirement accepted %s version %d: %v", field, version, err)
				}
				if _, err := plan.ReplacementManagedPeerIntent(state.Intent.Slot, state, []byte("retirement"), fixture.now); !errors.Is(err, ErrFounderPeerAuthorization) {
					t.Fatalf("replacement accepted %s version %d: %v", field, version, err)
				}
			})
		}
		state := completedManagedSlotForRetirement()
		intent := state.Intent
		intent.SchemaVersion, intent.Attempt, intent.Generation = version, 2, 2
		if _, err := ReplacementSlotHead(state, intent, []byte("intent"), []byte("retirement")); !errors.Is(err, ErrRetirementInvalid) {
			t.Fatalf("successor HEAD accepted intent version %d: %v", version, err)
		}
	}
	state := completedManagedSlotForRetirement()
	intent := state.Intent
	intent.Attempt, intent.Generation = 2, 2
	state.Head.CandidateDigest = ""
	if _, err := ReplacementSlotHead(state, intent, []byte("intent"), []byte("retirement")); !errors.Is(err, ErrRetirementInvalid) {
		t.Fatalf("successor HEAD accepted a managed predecessor without its candidate pin: %v", err)
	}
}

func TestLedgerSignedRecordsRejectNonV1ForCurrentAndHistoricalReads(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	intentWire, intent := fixture.intentBytes(t, scope, 1, "create-key", "retry-token")
	intentDigest := objectDigest(intentWire)
	result := fixture.result(scope, intent, intentDigest)
	result.PeerReceiptDigest = objectDigest([]byte("peer-receipt"))
	head := SlotHead{SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: fixture.environment, Role: roleController, Slot: scope.Slot,
		Attempt: 1, Generation: 1, IntentDigest: intentDigest}
	candidate := ManagedPeerCandidate{SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: fixture.environment, Role: roleController, Slot: scope.Slot, Attempt: 1, Generation: 1,
		IntentDigest: intentDigest, CreateKey: intent.CreateKey, FounderPlanSHA256: intent.FounderPlanSHA256,
		PeerRowDigest: intent.PeerRowDigest, ManifestDigest: intent.ManifestDigest,
		LaunchProfileDigest: intent.LaunchRequestDigest, InstanceOCID: result.InstanceOCID}
	progress := ManagedPeerProgress{SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: fixture.environment, Role: roleController, Slot: scope.Slot, Attempt: 1, Generation: 1,
		Sequence: 1, CandidateDigest: objectDigest([]byte("candidate")), Phase: ManagedPeerProgressCandidate}
	retirement := fixture.retirement(scope, SlotState{Intent: intent,
		Head:   SlotHead{Attempt: 1, Generation: 1, ResultDigest: objectDigest([]byte("result"))},
		Result: &result}, SlotRetirementDisposition)
	tests := []struct {
		domain  string
		payload func(int) any
		decode  func([]byte, bool) error
		wantErr error
	}{
		{domainBootstrapIntent, func(version int) any { value := intent; value.SchemaVersion = version; return value },
			func(wire []byte, current bool) error {
				_, _, err := fixture.ledger.decodeIntent(scope, wire, current)
				return err
			}, ErrInvalidRecord},
		{domainBootstrapHead, func(version int) any { value := head; value.SchemaVersion = version; return value },
			func(wire []byte, current bool) error {
				_, err := fixture.ledger.decodeHead(scope, wire, current)
				return err
			}, ErrInvalidRecord},
		{domainBootstrapResult, func(version int) any { value := result; value.SchemaVersion = version; return value },
			func(wire []byte, current bool) error {
				_, err := fixture.ledger.decodeResult(scope, wire, current)
				return err
			}, ErrInvalidRecord},
		{domainBootstrapCandidate, func(version int) any { value := candidate; value.SchemaVersion = version; return value },
			func(wire []byte, current bool) error {
				_, _, err := fixture.ledger.decodeManagedPeerCandidate(scope, wire, current)
				return err
			}, ErrInvalidRecord},
		{domainBootstrapProgress, func(version int) any { value := progress; value.SchemaVersion = version; return value },
			func(wire []byte, current bool) error {
				_, _, err := fixture.ledger.decodeManagedPeerProgress(scope, wire, current)
				return err
			}, ErrInvalidRecord},
		{domainSlotRetirement, func(version int) any { value := retirement; value.SchemaVersion = version; return value },
			func(wire []byte, current bool) error {
				_, _, err := fixture.ledger.decodeRetirement(scope, wire, current)
				return err
			}, ErrRetirementInvalid},
	}
	for _, test := range tests {
		t.Run(test.domain, func(t *testing.T) {
			for _, current := range []bool{false, true} {
				validWire := fixture.sign(t, scope, test.domain, test.payload(1), fixture.now)
				if err := test.decode(validWire, current); err != nil {
					t.Fatalf("valid v1 record rejected (current=%v): %v", current, err)
				}
				for _, version := range []int{-1, 0, 2, 3} {
					wire := fixture.sign(t, scope, test.domain, test.payload(version), fixture.now)
					if err := test.decode(wire, current); !errors.Is(err, test.wantErr) {
						t.Fatalf("version %d (current=%v): %v, want %v", version, current, err, test.wantErr)
					}
				}
			}
		})
	}
}
