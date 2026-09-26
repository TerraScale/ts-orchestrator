package fixturegen

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// ObservedController binds the signed offline history to the exact synthetic
// Compute observation that the packet's isolated simulator will serve.
type ObservedController struct {
	InstanceOCID      string
	CreateKey         string
	RetryToken        string
	ProviderRequestID string
	ETag              string
}

// SignedHistoryRecipe contains host-only signing inputs. The root and founder
// private keys must never be installed in a controller guest. The selector is
// verified only to authorize construction of the offline managed history; the
// completed restart path must not read it or require current selector access.
type SignedHistoryRecipe struct {
	Anchor                 bootstrap.VerifiedBootstrapAnchor
	FounderPlanWire        []byte
	ManifestWires          map[string][]byte
	FounderSelectionWire   []byte
	RootPrivateKey         ed25519.PrivateKey
	LedgerPrivateKey       ed25519.PrivateKey
	FounderPrivateKey      ed25519.PrivateKey
	Roots                  trust.Keyring
	Now                    time.Time
	ReviewedSeedPlanSHA256 string
	Observed               map[string]ObservedController
}

// Prepare signs one external seed and two schema-v2 managed peer histories
// through public trust, bootstrap, receipt, and founder-plan APIs. It leaves
// all Object Storage writes to BuildCompletedHistories and its public Ledger.
func (recipe SignedHistoryRecipe) Prepare(ledger *bootstrap.Ledger) (SeedHistory, []ManagedHistory, error) {
	if ledger == nil || !recipe.Anchor.IsVerified() || recipe.Now.IsZero() ||
		recipe.Now.Location() != time.UTC || recipe.Now.Nanosecond() != 0 ||
		len(recipe.RootPrivateKey) != ed25519.PrivateKeySize ||
		len(recipe.LedgerPrivateKey) != ed25519.PrivateKeySize ||
		len(recipe.FounderPrivateKey) != ed25519.PrivateKeySize || len(recipe.Roots) != 1 ||
		len(recipe.Observed) != 3 || !validDigest(recipe.ReviewedSeedPlanSHA256) {
		return SeedHistory{}, nil, errors.New("signed history recipe lacks current UTC clock, keys, or three observations")
	}
	anchor := recipe.Anchor.Anchor()
	if anchor.Environment != "production" || string(anchor.Cell) != "GRU" ||
		!slices.Equal(anchor.ControllerSlots, []string{"controller-a", "controller-b", "seed-a"}) {
		return SeedHistory{}, nil, errors.New("signed history recipe requires production GRU three-slot anchor")
	}
	policy := trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew}
	plan, err := bootstrap.VerifyFounderPlan(recipe.FounderPlanWire, recipe.Roots, recipe.Anchor.Wire(),
		recipe.ManifestWires, recipe.Now, policy)
	if err != nil {
		return SeedHistory{}, nil, fmt.Errorf("verify root-signed founder plan: %w", err)
	}
	planValue := plan.Plan()
	if planValue.SeedSlot != "seed-a" || len(planValue.Peers) != 2 ||
		planValue.Peers[0].Slot != "controller-a" || planValue.Peers[1].Slot != "controller-b" {
		return SeedHistory{}, nil, errors.New("signed founder plan does not name seed-a and both managed controller slots")
	}
	selectedUntil, err := recipe.verifyFounderSelection(plan)
	if err != nil {
		return SeedHistory{}, nil, err
	}
	planEnvelope, err := trust.DecodeEnvelope(recipe.FounderPlanWire)
	if err != nil {
		return SeedHistory{}, nil, err
	}
	imageOCID := planValue.Peers[0].ImageOCID
	seed, err := recipe.signSlot(anchor, plan, imageOCID, "seed-a", nil, selectedUntil, planEnvelope.ExpiresAt, policy, ledger)
	if err != nil {
		return SeedHistory{}, nil, fmt.Errorf("sign seed history: %w", err)
	}
	peers := make([]ManagedHistory, 0, 2)
	for _, row := range planValue.Peers {
		peer, err := recipe.signSlot(anchor, plan, imageOCID, row.Slot, &row,
			selectedUntil, planEnvelope.ExpiresAt, policy, ledger)
		if err != nil {
			return SeedHistory{}, nil, fmt.Errorf("sign managed history %s: %w", row.Slot, err)
		}
		peers = append(peers, peer.managed)
	}
	return seed.seed, peers, nil
}

type signedSlotHistory struct {
	seed    SeedHistory
	managed ManagedHistory
}

func (recipe SignedHistoryRecipe) signSlot(anchor bootstrap.BootstrapAnchor,
	plan bootstrap.VerifiedFounderPlan, imageOCID, slot string, row *bootstrap.FounderPeerRow,
	selectedUntil, planExpiresAt time.Time, policy trust.Policy, ledger *bootstrap.Ledger,
) (signedSlotHistory, error) {
	observation, ok := recipe.Observed[slot]
	if !ok || observation.InstanceOCID == "" || observation.CreateKey == "" ||
		observation.ETag == "" || observation.ProviderRequestID == "" ||
		(row != nil && observation.RetryToken == "") || (row == nil && observation.RetryToken != "") {
		return signedSlotHistory{}, fmt.Errorf("slot %q lacks exact Compute observation", slot)
	}
	manifestWire := recipe.ManifestWires[slot]
	manifestEnvelope, err := trust.DecodeEnvelope(manifestWire)
	if err != nil {
		return signedSlotHistory{}, err
	}
	manifest, err := bootstrap.VerifyManifest(manifestEnvelope, recipe.Roots, bootstrap.ManifestExpectation{
		DeploymentID: anchor.DeploymentID, Environment: anchor.Environment, ClusterID: anchor.ClusterID,
		Cell: anchor.Cell, Slot: slot, ImageOCID: imageOCID, StorageDomain: anchor.StorageDomain,
		ControllerSlots:  slices.Clone(anchor.ControllerSlots),
		IntentGeneration: anchor.InitialRegionIntentGeneration, IntentSHA256: anchor.InitialRegionIntentSHA256,
	}, recipe.Now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		return signedSlotHistory{}, err
	}
	profile, ok := manifest.Profile(slot)
	if !ok {
		return signedSlotHistory{}, errors.New("verified manifest lacks slot launch profile")
	}
	profileWire, err := trust.EncodePayload(profile)
	if err != nil {
		return signedSlotHistory{}, err
	}
	endsAt := recipe.Now.Add(time.Hour)
	for _, deadline := range []time.Time{recipe.Anchor.ExpiresAt(), manifestEnvelope.ExpiresAt,
		planExpiresAt, selectedUntil} {
		if deadline.Before(endsAt) {
			endsAt = deadline
		}
	}
	if !endsAt.After(recipe.Now.Add(time.Minute)) {
		return signedSlotHistory{}, errors.New("signed fixture has less than one minute of current authority")
	}
	scope := bootstrap.BootstrapScope{DeploymentID: anchor.DeploymentID, Cell: string(anchor.Cell), Slot: slot}
	profileDigest := historyDigest(profileWire)
	intent := bootstrap.Intent{
		SchemaVersion: 1, Mode: bootstrap.IntentModeExternalSeed,
		DeploymentID: anchor.DeploymentID, Cell: string(anchor.Cell), Environment: anchor.Environment,
		Role: "controller", Slot: slot, Attempt: 1, Generation: 1,
		ManifestDigest: manifest.Digest(), ReleaseReceiptDigest: manifest.Manifest().ReleaseReceiptSHA256,
		RegionIntentGeneration: anchor.InitialRegionIntentGeneration, ImageOCID: imageOCID,
		RegionIntentDigest: anchor.InitialRegionIntentSHA256, LaunchRequestDigest: profileDigest,
		ReviewedPlanDigest: recipe.ReviewedSeedPlanSHA256,
		CreateKey:          observation.CreateKey, CreatedAt: recipe.Now, OCIRegion: anchor.OCIRegion,
		CompartmentOCID: profile.CompartmentOCID, AvailabilityDomain: profile.AvailabilityDomain,
		FaultDomain: profile.FaultDomain, SubnetOCID: profile.SubnetOCID,
		NetworkSecurityGroupIDs: slices.Clone(profile.NetworkSecurityGroupOCIDs), Shape: profile.Shape, Node: slot,
	}
	if row != nil {
		rowDigest, err := bootstrap.FounderPeerRowDigest(*row)
		if err != nil {
			return signedSlotHistory{}, err
		}
		intent.SchemaVersion = 2
		intent.Mode = bootstrap.IntentModeManaged
		intent.ReviewedPlanDigest = ""
		intent.FounderPlanSHA256 = plan.Digest()
		intent.PeerRowDigest = rowDigest
		intent.RetryToken = observation.RetryToken
	}
	intentWire, err := signHistoryRecord(intent, "bootstrap-intent", scope, anchor.Environment,
		recipe.Now, endsAt, recipe.LedgerPrivateKey)
	if err != nil {
		return signedSlotHistory{}, err
	}
	head := bootstrap.SlotHead{SchemaVersion: intent.SchemaVersion, DeploymentID: scope.DeploymentID,
		Cell: scope.Cell, Environment: anchor.Environment, Role: "controller", Slot: slot,
		Attempt: 1, Generation: 1, IntentDigest: historyDigest(intentWire)}
	reservedHeadWire, err := signHistoryRecord(head, "bootstrap-slot-head", scope, anchor.Environment,
		recipe.Now, endsAt, recipe.LedgerPrivateKey)
	if err != nil {
		return signedSlotHistory{}, err
	}
	facts := bootstrap.InstanceFacts{DeploymentID: anchor.DeploymentID, Environment: anchor.Environment,
		ClusterID: anchor.ClusterID, Cell: anchor.Cell, OCIRegion: anchor.OCIRegion, Role: "controller", Slot: slot,
		InstanceOCID: observation.InstanceOCID, CompartmentOCID: profile.CompartmentOCID,
		ImageOCID: imageOCID, CreateKey: observation.CreateKey, IntentSHA256: historyDigest(intentWire),
		Profile: profile}
	var receiptEnvelope trust.Envelope
	if row == nil {
		receiptEnvelope, err = bootstrap.SignSeedReceipt(manifest, facts, recipe.Now, endsAt, recipe.RootPrivateKey)
	} else {
		receiptEnvelope, err = bootstrap.SignPeerReceipt(manifest, facts, recipe.Now, endsAt, recipe.FounderPrivateKey)
	}
	if err != nil {
		return signedSlotHistory{}, err
	}
	receiptWire, err := trust.EncodeEnvelope(receiptEnvelope)
	if err != nil {
		return signedSlotHistory{}, err
	}
	result := bootstrap.Result{SchemaVersion: 1, Mode: intent.Mode, DeploymentID: scope.DeploymentID,
		Cell: scope.Cell, Environment: anchor.Environment, Role: "controller", Slot: slot,
		Attempt: 1, Generation: 1, RegionIntentGeneration: intent.RegionIntentGeneration,
		IntentDigest: historyDigest(intentWire), InstanceOCID: observation.InstanceOCID,
		ProviderRequestID: observation.ProviderRequestID, ETag: observation.ETag,
		OCIRegion: anchor.OCIRegion, CompartmentOCID: profile.CompartmentOCID, ImageOCID: imageOCID,
		Shape: profile.Shape, ObservedProfileDigest: profileDigest, CreateKey: observation.CreateKey,
		ObservedAt: recipe.Now}
	if row == nil {
		result.SeedReceiptDigest = historyDigest(receiptWire)
	} else {
		result.PeerReceiptDigest = historyDigest(receiptWire)
	}
	resultWire, err := signHistoryRecord(result, "bootstrap-result", scope, anchor.Environment,
		recipe.Now, endsAt, recipe.LedgerPrivateKey)
	if err != nil {
		return signedSlotHistory{}, err
	}
	head.ResultDigest = historyDigest(resultWire)
	history := signedSlotHistory{}
	if row == nil {
		completedHeadWire, err := signHistoryRecord(head, "bootstrap-slot-head", scope, anchor.Environment,
			recipe.Now, endsAt, recipe.LedgerPrivateKey)
		if err != nil {
			return signedSlotHistory{}, err
		}
		history.seed = SeedHistory{Scope: scope, IntentWire: intentWire, ReservedHeadWire: reservedHeadWire,
			ManifestWire: manifestWire, ReceiptWire: receiptWire, Facts: facts, ResultWire: resultWire,
			CompletedHeadWire: completedHeadWire}
		return history, nil
	}
	candidate := bootstrap.ManagedPeerCandidate{SchemaVersion: 1, DeploymentID: scope.DeploymentID,
		Cell: scope.Cell, Environment: anchor.Environment, Role: "controller", Slot: slot,
		Attempt: 1, Generation: 1, IntentDigest: historyDigest(intentWire),
		CreateKey: observation.CreateKey, FounderPlanSHA256: plan.Digest(),
		PeerRowDigest: intent.PeerRowDigest, ManifestDigest: manifest.Digest(),
		LaunchProfileDigest: profileDigest, InstanceOCID: observation.InstanceOCID}
	candidateWire, err := signHistoryRecord(candidate, "bootstrap-candidate", scope, anchor.Environment,
		recipe.Now, endsAt, recipe.LedgerPrivateKey)
	if err != nil {
		return signedSlotHistory{}, err
	}
	head.CandidateDigest = historyDigest(candidateWire)
	completedHeadWire, err := signHistoryRecord(head, "bootstrap-slot-head", scope, anchor.Environment,
		recipe.Now, endsAt, recipe.LedgerPrivateKey)
	if err != nil {
		return signedSlotHistory{}, err
	}
	history.managed = ManagedHistory{Scope: scope, IntentWire: intentWire, ReservedHeadWire: reservedHeadWire,
		CandidateWire: candidateWire, ManifestWire: manifestWire, ReceiptWire: receiptWire,
		Facts: facts, ResultWire: resultWire, CompletedHeadWire: completedHeadWire,
		SignProgress: func(progress bootstrap.ManagedPeerProgress, issuedAt, expiresAt time.Time) ([]byte, error) {
			return signHistoryRecord(progress, "bootstrap-progress", scope, anchor.Environment,
				issuedAt, expiresAt, recipe.LedgerPrivateKey)
		},
		Refresh: func(ctx context.Context) (bootstrap.VerifiedFounderPeer, error) {
			recovery, err := ledger.ReadForManagedPeerRecovery(ctx, scope)
			if err != nil {
				return bootstrap.VerifiedFounderPeer{}, err
			}
			return plan.AuthorizePeerRecovery(slot, recovery, recipe.Roots,
				recovery.AuthorizationTime(), selectedUntil, policy)
		}}
	return history, nil
}

func (recipe SignedHistoryRecipe) verifyFounderSelection(plan bootstrap.VerifiedFounderPlan) (time.Time, error) {
	envelope, err := trust.DecodeEnvelope(recipe.FounderSelectionWire)
	if err != nil {
		return time.Time{}, err
	}
	anchor := recipe.Anchor.Anchor()
	expected := trust.Scope{Domain: bootstrapstart.FounderSelectionDomain,
		DeploymentID: anchor.DeploymentID, Cell: string(anchor.Cell), Environment: anchor.Environment,
		Role: "deployment-anchor", Slot: "region"}
	payload, err := trust.VerifyCurrent(envelope, expected, recipe.Roots, recipe.Now,
		bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return time.Time{}, fmt.Errorf("verify root-signed founder selection: %w", err)
	}
	var selected bootstrapstart.FounderSelection
	if len(payload) > 4096 || json.Unmarshal(payload, &selected, json.RejectUnknownMembers(true)) != nil {
		return time.Time{}, errors.New("founder selection payload is invalid")
	}
	canonical, err := trust.EncodePayload(selected)
	if err != nil || !bytes.Equal(canonical, payload) || selected.SchemaVersion != 1 ||
		selected.Generation == 0 || selected.DeploymentID != anchor.DeploymentID ||
		selected.Cell != string(anchor.Cell) || selected.Environment != anchor.Environment ||
		selected.PlanSHA256 != plan.Digest() || selected.AnchorSHA256 != recipe.Anchor.Digest() ||
		len(selected.Manifests) != 3 || !envelope.ExpiresAt.After(recipe.Now.Add(time.Minute)) {
		return time.Time{}, errors.New("founder selection differs from signed recipe inputs")
	}
	for index, slot := range anchor.ControllerSlots {
		pin := selected.Manifests[index]
		if pin.Slot != slot || pin.SHA256 != historyDigest(recipe.ManifestWires[slot]) {
			return time.Time{}, fmt.Errorf("founder selection manifest pin differs for %q", slot)
		}
	}
	return envelope.ExpiresAt, nil
}

func signHistoryRecord(payload any, domain string, scope bootstrap.BootstrapScope, environment string,
	issuedAt, expiresAt time.Time, key ed25519.PrivateKey,
) ([]byte, error) {
	wire, err := trust.EncodePayload(payload)
	if err != nil {
		return nil, err
	}
	envelope, err := trust.Sign(wire, trust.Scope{Domain: domain, DeploymentID: scope.DeploymentID,
		Cell: scope.Cell, Environment: environment, Role: "controller", Slot: scope.Slot},
		issuedAt, expiresAt, key)
	if err != nil {
		return nil, err
	}
	return trust.EncodeEnvelope(envelope)
}

func historyDigest(wire []byte) string {
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}
