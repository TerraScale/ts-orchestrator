package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/nats-io/nats.go/jetstream"
)

// Genuine signed broker delivery retains immutable policy before a deliberate
// application refusal. It proves descriptive continuity, never runtime admission.
func TestContainerOriginalProfileArchiveBrokerIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	js := testRolloutJetStream(t)
	channels, err := openChannelBucket(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	identity := cellspec.Identity{DeploymentID: entityid.New(), Cell: "gru", Environment: "production"}
	keys := newTestSpecTrust(t, t.TempDir(), identity)
	control, err := authority.Start(ctx, js, authority.Config{DeploymentID: identity.DeploymentID, Scope: identity.Cell, CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	specs, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: cellSpecBucket, History: 4, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	archiveKV, err := openNativeHistory(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	registry := &specRegistry{cell: identity.Cell, identity: identity}
	if err := registry.openRoots(keys.roots, trust.RootChain{Version: 1}, ""); err != nil {
		t.Fatal(err)
	}
	archive := &nativeHistory{kv: archiveKV, js: js, services: registry, fencer: control}
	profile := WorkloadProfile{Resources: placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 1 << 30}, Args: []string{"serve"}, Env: map[string]string{"MODE": "production"}}
	policy := workload.ServiceSpec{Role: "ts-auth", Environment: identity.Environment, Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3}, Scaling: &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.5}}}}
	signSpec := func(generation uint64, current WorkloadProfile) []byte {
		t.Helper()
		wire, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: generation, RequiresBinary: cellspec.BinaryLevel, Services: []cellspec.Service{{Role: policy.Role, Profile: current, Spec: &policy}}}, nil, keys.roots, time.Now(), time.Hour, keys.root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := specs.Put(ctx, cellSpecKey, wire); err != nil {
			t.Fatal(err)
		}
		return wire
	}
	originalSpec := signSpec(1, profile)
	releaseSigner := newFunctionPublicationSigner(t)
	target := release.ContainerTarget{Cell: "GRU", Environment: identity.Environment, Role: policy.Role, Architecture: "arm64"}
	var floors []release.SequenceFloor
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
		floors = append(floors, release.SequenceFloor{Cell: cell, IssuedAt: time.Now().UTC().Add(-time.Hour), EvidenceSHA256: strings.Repeat("d", 64)})
	}
	currentBundle, currentEvidence := genericRuntimeContainerRelease(t, releaseSigner, target, floors, 101, nil)
	originalBundle := currentBundle
	resign := func(wire []byte, issued, expires time.Time, key ed25519.PrivateKey) []byte {
		t.Helper()
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err = trust.Sign(envelope.Payload, envelope.Scope, issued, expires, key)
		if err != nil {
			t.Fatal(err)
		}
		result, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	now := time.Now().UTC().Truncate(time.Second)
	originalExpiry := now.Add(5 * time.Second)
	originalBundle.Delegation = resign(currentBundle.Delegation, now.Add(-time.Minute), originalExpiry, releaseSigner.root)
	claimEnvelope, err := trust.DecodeEnvelope(currentBundle.Claim)
	if err != nil {
		t.Fatal(err)
	}
	var expiredClaim release.ContainerClaim
	if err := json.Unmarshal(claimEnvelope.Payload, &expiredClaim); err != nil {
		t.Fatal(err)
	}
	qualificationEnvelope, err := trust.DecodeEnvelope(expiredClaim.Production.Qualification)
	if err != nil {
		t.Fatal(err)
	}
	var qualification release.ProductionQualification
	if err := json.Unmarshal(qualificationEnvelope.Payload, &qualification); err != nil {
		t.Fatal(err)
	}
	for i := range qualification.Evidence {
		qualification.Evidence[i].CompletedAt = now.Add(-time.Second)
	}
	signOriginal := func(value any, scope trust.Scope, key ed25519.PrivateKey) []byte {
		t.Helper()
		payload, err := trust.EncodePayload(value)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, scope, now, originalExpiry, key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	expiredClaim.Production.Qualification = signOriginal(qualification, qualificationEnvelope.Scope, releaseSigner.root)
	originalBundle.Claim = signOriginal(expiredClaim, claimEnvelope.Scope, releaseSigner.leaf)
	historical, err := release.VerifyContainerHistorical(originalBundle, releaseSigner.roots, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyProductionCurrent(expiredClaim.Production.Qualification, expiredClaim.Production.Delegation, releaseSigner.roots, qualification.Candidate, now); err != nil {
		t.Fatal("original qualification was not current before protected apply", err)
	}
	claim := historical.Claim()
	intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.New(), Source: delivery.ArtifactSource{Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256}, Cell: identity.Cell, Role: policy.Role, Environment: identity.Environment, Generation: 1, DesiredReplicas: 1, ConfigDigest: delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets), AuthorityEpoch: control.Current().Epoch, Container: &originalBundle}
	keyID, err := protocol.KeyID(keys.leaf.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	codec := delivery.Ed25519Codec{Cell: identity.Cell, Actor: "release", PrivateKey: keys.leaf, Lifetime: time.Minute, MaxLifetime: time.Minute, Trusted: map[string]delivery.TrustedSigner{keyID: {Actor: "release", PublicKey: keys.leaf.Public().(ed25519.PublicKey)}}}
	applied := make(chan error, 1)
	var reference string
	config := delivery.Config{Conn: js.Conn(), JS: js, Cell: identity.Cell, Replicas: 1, Signer: codec, Verifier: codec, Fencer: control, CaptureContainerProfile: archive.CaptureContainerProfile, Authorize: func(_ context.Context, actor string, proposed delivery.Intent) error {
		if actor != "release" || proposed.Role != policy.Role || proposed.Environment != identity.Environment {
			return delivery.ErrUnauthorized
		}
		return nil
	}, ContainerApply: func(ctx context.Context, admitted delivery.Intent) error {
		retained, captured, err := archive.deliveries.ContainerProvenance(ctx, admitted.OperationID)
		if err == nil {
			reference = captured
			var original []byte
			original, err = archive.originalContainerProfile(ctx, retained)
			if err == nil && !bytes.Equal(original, originalSpec) {
				err = errors.New("apply did not retain original full signed profile")
			}
		}
		if err == nil {
			// The actual protected operation exists before readiness/receipt.
			var selected containerIntentSelection
			selected, err = selectContainerIntent(ctx, js, archive.deliveries, admitted.OperationID)
			if err == nil && selected.intent.OperationID != admitted.OperationID {
				err = errors.New("in-progress operation lost its current actor authority")
			}
			if err == nil {
				var stateWire []byte
				stateWire, err = protocol.EncodeJSON(serviceReleaseState{Intent: new(admitted.Clone()), Actor: "release"})
				key := releasechannel.ServiceStatusKey(strings.ToUpper(admitted.Cell), admitted.Role)
				if err == nil {
					_, err = channels.Put(ctx, key, stateWire)
				}
				if err == nil {
					selected, err = selectContainerIntent(ctx, js, archive.deliveries, admitted.OperationID)
				}
				if err == nil {
					_, err = channels.Put(ctx, key, stateWire)
				}
				if err == nil && !errors.Is(selected.guard(ctx), containermaterial.ErrPending) {
					err = errors.New("replaced channel selector retained original admission")
				}
			}
		}
		applied <- err
		return delivery.ErrUnauthorized
	}}
	service, err := delivery.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	archive.deliveries = service
	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- service.Run(runCtx) }()
	defer func() { stopRun(); <-done }()
	if err := service.Submit(ctx, intent); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-applied:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("container apply was never reached", ctx.Err())
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		receipt, err := service.StatusFor(ctx, intent)
		if err == nil && receipt.Status == "held" {
			break
		}
		if err != nil && !errors.Is(err, delivery.ErrPending) {
			t.Fatal(err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("application refusal was not held", ctx.Err())
		}
	}
	for generation := uint64(2); generation <= 7; generation++ {
		changed := cloneNativeProfile(profile)
		changed.Resources.CPU = int(generation)
		signSpec(generation, changed)
	}
	recovered, err := delivery.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	retained, recoveredRef, err := recovered.ContainerProvenance(ctx, intent.OperationID)
	if err != nil || recoveredRef != reference {
		t.Fatal("restart lost exact original association", err)
	}
	original, err := archive.ReadContainerProfile(ctx, recoveredRef)
	if err != nil || !bytes.Equal(original, originalSpec) {
		t.Fatal("profile followed successor after history eviction", err)
	}
	verified, err := cellspec.VerifyHistorical(original, keys.roots, identity)
	if err != nil || !verified.RootSigned || len(verified.Services) != 1 || verified.Services[0].Profile.Resources.CPU != 1 || verified.Services[0].Spec.Replicas.Max != 3 {
		t.Fatal("original full signed runtime policy was not retained", err)
	}
	if fp, err := retained.Fingerprint(); err != nil {
		t.Fatal(err)
	} else if expected, _ := intent.Fingerprint(); fp != expected {
		t.Fatal("original operation changed")
	}
	for _, read := range []func(context.Context, string) (delivery.Intent, error){recovered.ContainerIntent, recovered.RetainedContainerIntent} {
		if _, err := read(ctx, intent.OperationID); !errors.Is(err, delivery.ErrUnauthorized) {
			t.Fatal("descriptive archive admitted held execution", err)
		}
	}
	if _, err := selectContainerIntent(ctx, js, recovered, intent.OperationID); !errors.Is(err, delivery.ErrUnauthorized) {
		t.Fatal("channel selector admitted held original provenance", err)
	}
	expiry := time.NewTimer(time.Until(originalExpiry))
	defer expiry.Stop()
	select {
	case <-expiry.C:
	case <-ctx.Done():
		t.Fatal("original proof did not reach its real expiry", ctx.Err())
	}
	if _, err := release.VerifyProductionCurrent(expiredClaim.Production.Qualification, expiredClaim.Production.Delegation, releaseSigner.roots, qualification.Candidate, time.Now().UTC()); err == nil {
		t.Fatal("original expired production qualification became current authority")
	}
	historicalRoots := maps.Clone(releaseSigner.roots)
	for id, key := range keys.roots {
		historicalRoots[id] = key
	}
	originalProof, err := containermaterial.VerifyProfile(original, historicalRoots, identity, retained)
	if err != nil {
		t.Fatal("actual protected archive lost its original profile", err)
	}
	if _, err := containermaterial.VerifyProfile(original, releaseSigner.roots, identity, retained); err == nil {
		t.Fatal("retired original profile signer became current authority")
	}
	workloadIntent, err := containermaterial.ServiceIntent(originalProof, target.Architecture)
	if err != nil {
		t.Fatal(err)
	}
	floorSHA, err := swarmruntime.HistoricalServiceIntentSHA256(workloadIntent, historical)
	if err != nil {
		t.Fatal(err)
	}
	currentService := cellspec.Service{Role: policy.Role, Profile: profile, Spec: &policy, Releasers: []string{"current-actor"}}
	currentSpec, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: 8, RequiresBinary: cellspec.BinaryLevel,
		Services: []cellspec.Service{currentService}}, nil, releaseSigner.roots, now, time.Hour, releaseSigner.root)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := release.VerifyContainerHistorical(currentBundle, releaseSigner.roots, target)
	if err != nil {
		t.Fatal(err)
	}
	bundleSHA, err := release.ContainerBundleSHA256(currentBundle)
	if err != nil {
		t.Fatal(err)
	}
	observation := rootoci.ContainerReleaseObservation{Found: true, Bundle: currentBundle, BundleSHA256: bundleSHA, Fingerprint: renewed.Fingerprint(), ExpiresAt: now.Add(time.Minute),
		Floor: &rootoci.ContainerReleaseFloor{Found: true, OperationID: retained.OperationID, Generation: retained.Generation, ReleaseSequence: claim.ReleaseSequence, ReleaseIdentity: historical.ReleaseIdentity(), IntentSHA256: floorSHA}}
	state := serviceReleaseState{Intent: new(retained.Clone()), State: releasechannel.StateRolling, Previous: "retained-native-baseline", Retained: []string{"retained-native-baseline"}}
	proposal, err := containerChannelRenewal(state, observation, originalProof, historical, renewed, currentSpec, releaseSigner.roots, retained.AuthorityEpoch+1)
	if err != nil || proposal.Generation != retained.Generation || proposal.OperationID == retained.OperationID || proposal.DesiredReplicas != retained.DesiredReplicas || state.Previous != "retained-native-baseline" || len(state.Retained) != 1 {
		t.Fatal("archived proof renewal reset original generation or rollback baseline", err)
	}
	candidate, err := containermaterial.VerifyProfile(currentSpec, releaseSigner.roots, identity, proposal)
	if err != nil || containermaterial.VerifyHistoricalContinuity(originalProof, historical, candidate, renewed) != nil {
		t.Fatal("protected archive did not cross full shared historical continuity", err)
	}
	verificationDeadline, _ := ctx.Deadline()
	currentRelease, err := release.VerifyContainerCurrent(ctx, currentBundle, releaseSigner.roots, target, time.Now().UTC(),
		earlier(verificationDeadline, observation.ExpiresAt).Add(-time.Nanosecond), currentEvidence, releaseSigner.allocations)
	if err != nil {
		t.Fatal("renewal did not independently authenticate current signed SDK allocation and evidence", err)
	}
	continued, err := containermaterial.ContinueProfile(originalProof, historical, candidate, currentRelease, time.Now().UTC())
	if err != nil {
		t.Fatal("protected archive did not continue under independently current authority", err)
	}
	continuedService, err := containermaterial.ServiceIntent(continued, target.Architecture)
	if err != nil || continuedService.OperationID != retained.OperationID || continuedService.Generation != retained.Generation || continued.Intent().OperationID != proposal.OperationID {
		t.Fatal("current continuation changed the original protected runtime operation or generation", err)
	}
	if _, err := containermaterial.ContinueProfile(continued, historical, candidate, currentRelease, time.Now().UTC()); err == nil {
		t.Fatal("continued archive proof rebound to a successor source")
	}
	if containermaterial.VerifyContinuity(originalProof, historical, candidate, currentRelease, currentRelease.ExpiresAt()) == nil {
		t.Fatal("expired independent current proof retained archive continuity")
	}
	if containermaterial.VerifyRuntimePolicy(containermaterial.Profile{}, candidate) == nil || containermaterial.VerifyRuntimePolicy(originalProof, containermaterial.Profile{}) == nil {
		t.Fatal("missing signed archive or current profile granted runtime continuity")
	}
	if _, err := containermaterial.ContinueProfile(originalProof, release.HistoricalContainer{}, candidate, release.VerifiedContainer{}, time.Now().UTC()); err == nil {
		t.Fatal("signed runtime policy alone granted current continuation")
	}
	for _, change := range []string{"resources", "rollout policy", "replica policy", "desired generation", "desired replicas"} {
		driftedService := currentService
		driftedService.Profile = cloneNativeProfile(profile)
		driftedService.Spec = new(policy)
		driftedIntent := proposal.Clone()
		switch change {
		case "resources":
			driftedService.Profile.Resources.CPU++
		case "rollout policy":
			driftedService.Spec.Rollout.MaxSurge++
		case "replica policy":
			driftedService.Spec.Replicas.Max++
		case "desired generation":
			driftedIntent.Generation++
		case "desired replicas":
			driftedIntent.DesiredReplicas++
		}
		driftedWire, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: 9, RequiresBinary: cellspec.BinaryLevel,
			Services: []cellspec.Service{driftedService}}, nil, releaseSigner.roots, now, time.Hour, releaseSigner.root)
		if err != nil {
			t.Fatal(err)
		}
		driftedProof, err := containermaterial.VerifyProfile(driftedWire, releaseSigner.roots, identity, driftedIntent)
		if err != nil || containermaterial.VerifyHistoricalContinuity(originalProof, historical, driftedProof, renewed) == nil {
			t.Fatalf("protected original archive accepted changed %s: %v", change, err)
		}
	}
	if _, err := containerChannelIntent(state, observation, renewed, currentService, identity.Cell, proposal.AuthorityEpoch, historicalRoots); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("renewed proof bypassed original protected floor continuity", err)
	}
	missingFloor := observation
	missingFloor.Floor = nil
	if _, err := containerChannelIntent(state, missingFloor, renewed, currentService, identity.Cell, proposal.AuthorityEpoch, historicalRoots); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("missing original floor invented a recovery generation", err)
	}
	if _, err := containerChannelIntent(serviceReleaseState{}, observation, renewed, currentService, identity.Cell, proposal.AuthorityEpoch, historicalRoots); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("protected floor without its original state invented a recovery generation", err)
	}
	swapped := originalBundle
	swapped.Delegation = resign(originalBundle.Delegation, now.Add(-time.Minute), now.Add(time.Minute), releaseSigner.root)
	swappedHistorical, err := release.VerifyContainerHistorical(swapped, historicalRoots, target)
	if err != nil || swappedHistorical.Fingerprint() != historical.Fingerprint() || swappedHistorical.BundleSHA256() == historical.BundleSHA256() {
		t.Fatal("full-bundle substitution did not retain the genuine original claim", err)
	}
	swappedIntent := retained.Clone()
	swappedIntent.Container = &swapped
	swappedProfile, err := containermaterial.VerifyProfile(original, historicalRoots, identity, swappedIntent)
	if err != nil || containermaterial.VerifyHistoricalContinuity(swappedProfile, historical, candidate, renewed) == nil {
		t.Fatal("shared continuity lost the protected original's exact full bundle", err)
	}
	newSequence := currentBundle
	newClaim := renewed.Claim()
	newClaim.ReleaseSequence++
	newClaimWire, err := trust.EncodePayload(newClaim)
	if err != nil {
		t.Fatal(err)
	}
	newEnvelope, err := trust.Sign(newClaimWire, claimEnvelope.Scope, now, now.Add(time.Hour), releaseSigner.leaf)
	if err != nil {
		t.Fatal(err)
	}
	newSequence.Claim, err = trust.EncodeEnvelope(newEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	var reservation struct {
		Schema      string                   `json:"schema"`
		Sequence    uint64                   `json:"sequence"`
		Identity    release.SequenceIdentity `json:"identity"`
		Migration   trust.Envelope           `json:"migration"`
		Reservation trust.Envelope           `json:"reservation"`
	}
	if err := protocol.DecodeStrict(currentBundle.Sequence, &reservation, trust.MaxPayloadBytes); err != nil {
		t.Fatal(err)
	}
	reservation.Sequence = newClaim.ReleaseSequence
	reservationPayload, err := trust.EncodePayload(struct {
		Sequence uint64                   `json:"sequence"`
		Identity release.SequenceIdentity `json:"identity"`
	}{reservation.Sequence, reservation.Identity})
	if err != nil {
		t.Fatal(err)
	}
	reservation.Reservation, err = trust.Sign(reservationPayload, reservation.Reservation.Scope, now, now.Add(time.Hour), releaseSigner.leaf)
	if err != nil {
		t.Fatal(err)
	}
	newSequence.Sequence, err = protocol.EncodeJSON(reservation)
	if err != nil {
		t.Fatal(err)
	}
	newHistorical, err := release.VerifyContainerHistorical(newSequence, releaseSigner.roots, target)
	if err != nil || newHistorical.ReleaseIdentity() != renewed.ReleaseIdentity() {
		t.Fatal("new sequence did not retain the same genuine immutable content identity", err)
	}
	newIntent := proposal.Clone()
	newIntent.Container = &newSequence
	newProfile, err := containermaterial.VerifyProfile(currentSpec, releaseSigner.roots, identity, newIntent)
	if err != nil || containermaterial.VerifyHistoricalContinuity(originalProof, historical, newProfile, newHistorical) == nil {
		t.Fatal("equal content identity admitted a different release sequence at the original generation", err)
	}
	state.Intent = new(proposal.Clone())
	retried, err := containerChannelIntent(state, observation, renewed, cellspec.Service{Role: policy.Role, Profile: profile, Spec: &policy}, identity.Cell, proposal.AuthorityEpoch, historicalRoots)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := proposal.Fingerprint()
	after, _ := retried.Fingerprint()
	if before != after {
		t.Fatal("rolling renewal retry changed its exact deterministic operation")
	}
	drifted := cloneNativeProfile(profile)
	drifted.Resources.CPU++
	driftSpec, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: 9, RequiresBinary: cellspec.BinaryLevel,
		Services: []cellspec.Service{{Role: policy.Role, Profile: drifted, Spec: &policy}}}, nil, releaseSigner.roots, now, time.Hour, releaseSigner.root)
	if err != nil {
		t.Fatal(err)
	}
	state.Intent = new(retained.Clone())
	if _, err := containerChannelRenewal(state, observation, originalProof, historical, renewed, driftSpec, releaseSigner.roots, proposal.AuthorityEpoch); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("same-generation renewal accepted original resource policy drift", err)
	}
	if _, err := archiveKV.Get(ctx, policy.Role); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatal("container archive created native role history", err)
	}
	record, err := archiveKV.Get(ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	var stored nativeStoredProfile
	if err := json.Unmarshal(record.Value(), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Provenance.Spec) != 1 {
		t.Fatal("signed spec archive is missing")
	}
	blob := stored.Provenance.Spec[0]
	if _, err := archiveKV.Put(ctx, blob, []byte("corrupt signed provenance")); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.ReadContainerProfile(ctx, reference); err == nil {
		t.Fatal("corrupt immutable profile hash accepted")
	}
	if _, err := archive.ReadContainerProfile(ctx, "profile."+strings.Repeat("0", 64)); err == nil {
		t.Fatal("missing archive resolved using matching current ConfigDigest")
	}
}
