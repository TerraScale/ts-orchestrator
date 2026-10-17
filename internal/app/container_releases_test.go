package app

import (
	"errors"
	"math"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/nats-io/nats.go/jetstream"
)

func TestContainerChannelUnavailableNeverFallsBackToNative(t *testing.T) {
	ctx := t.Context()
	r, kv, bucket, _ := servicePinsSignedFixture(t)
	identity := cellspec.Identity{DeploymentID: entityid.New(), Cell: r.cell, Environment: "canary"}
	keys := newTestSpecTrust(t, t.TempDir(), identity)
	registry := &specRegistry{cell: identity.Cell, identity: identity, fixed: map[string]WorkloadProfile{}, signedArtifactStore: delivery.DefaultArtifactStoreMaxBytes}
	if err := registry.openRoots(keys.roots, trust.RootChain{Version: 1}, ""); err != nil {
		t.Fatal(err)
	}
	var err error
	registry.kv, err = r.js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: cellSpecBucket, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	service := cellspec.Service{Role: tsauth.Role, Profile: cellspec.Profile{Resources: placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 1 << 30}},
		Spec: &workload.ServiceSpec{Role: tsauth.Role, Environment: identity.Environment, Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3}}}
	wire, err := os.ReadFile(keys.signRoot(t, t.TempDir(), cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: 1, RequiresBinary: cellspec.BinaryLevel, Services: []cellspec.Service{service}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.kv.Put(ctx, cellSpecKey, wire); err != nil {
		t.Fatal(err)
	}
	entry, err := registry.kv.Get(ctx, cellSpecKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.load(entry); err != nil {
		t.Fatal(err)
	}
	fencer, err := authority.Start(ctx, r.js, authority.Config{DeploymentID: identity.DeploymentID, Scope: identity.Cell, CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fencer.Close() })
	r.fencer, r.policy.services, r.environment = fencer, registry, identity.Environment
	// The native location exists, but a genuine root container connection does not.
	if err := r.pass(ctx, kv, tsauth.Role); !errors.Is(err, rootoci.ErrUnauthorized) {
		t.Fatal("unavailable container source reached the native channel", err)
	}
	if len(bucket.puts) != 0 {
		t.Fatal("unavailable container source published native status")
	}
	if _, revision, err := loadServiceRelease(ctx, kv, releasechannel.ServiceStatusKey("GRU", tsauth.Role)); err != nil || revision != 0 {
		t.Fatal("unavailable source changed persisted release state", revision, err)
	}
}

// This tests producer ordering against genuinely signed bundles and the SDK
// allocation store; root installation, socket admission and runtime apply are separate gates.
func TestContainerChannelPreservesFailedGeneration(t *testing.T) {
	signer := newFunctionPublicationSigner(t)
	target := release.ContainerTarget{Cell: "GRU", Environment: "canary", Role: "ts-auth", Architecture: runtime.GOARCH}
	var floors []release.SequenceFloor
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		floors = append(floors, release.SequenceFloor{Cell: cell, IssuedAt: time.Now().UTC().Add(-time.Hour), EvidenceSHA256: strings.Repeat("d", 64)})
	}
	bundle, _ := genericRuntimeContainerRelease(t, signer, target, floors, 101, nil)
	observation := func(bundle release.ContainerBundle) (rootoci.ContainerReleaseObservation, release.HistoricalContainer) {
		t.Helper()
		verified, err := release.VerifyContainerHistorical(bundle, signer.roots, target)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := release.ContainerBundleSHA256(bundle)
		if err != nil {
			t.Fatal(err)
		}
		return rootoci.ContainerReleaseObservation{Found: true, Bundle: bundle, BundleSHA256: digest, Fingerprint: verified.Fingerprint(), ExpiresAt: time.Now().Add(time.Minute), Floor: &rootoci.ContainerReleaseFloor{}}, verified
	}
	current, verified := observation(bundle)
	service := cellspec.Service{Role: target.Role, Profile: cellspec.Profile{}, Spec: &workload.ServiceSpec{Role: target.Role, Environment: target.Environment, Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3}}}
	legacy := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.New(),
		Source:         delivery.ArtifactSource{Repository: "https://example.invalid/native", Commit: strings.Repeat("a", 40), TreeDigest: strings.Repeat("b", 64)},
		ArtifactDigest: strings.Repeat("c", 64), ManifestDigest: strings.Repeat("d", 64), Cell: "gru", Role: target.Role, Environment: target.Environment,
		Generation: 7, DesiredReplicas: 1, ConfigDigest: delivery.ConfigDigestOf(nil, nil, nil), AuthorityEpoch: 1}
	state := serviceReleaseState{Intent: new(legacy), State: releasechannel.StateComplete}
	initial, err := containerChannelIntent(state, current, verified, service, "gru", 1, signer.roots)
	if err != nil || initial.Generation != 8 {
		t.Fatal("initial migration did not follow the retained generation", initial.Generation, err)
	}
	state.Intent, state.State = new(initial), releasechannel.StateRolling
	retry, err := containerChannelIntent(state, current, verified, service, "gru", 1, signer.roots)
	originalFingerprint, originalErr := initial.Fingerprint()
	retryFingerprint, retryErr := retry.Fingerprint()
	if err != nil || originalErr != nil || retryErr != nil || retryFingerprint != originalFingerprint {
		t.Fatal("retry changed the original operation or rollback generation", err)
	}
	if _, err := containerChannelIntent(state, current, verified, service, "gru", 2, signer.roots); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("successor authority recreated the failed release intent", err)
	}
	changed := service
	changed.Profile.Args = []string{"changed"}
	if _, err := containerChannelIntent(state, current, verified, changed, "gru", 1, signer.roots); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("same-release profile change reset rollback protection", err)
	}
	reissued := bundle
	envelope, err := trust.DecodeEnvelope(bundle.Claim)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err = trust.Sign(envelope.Payload, envelope.Scope, envelope.IssuedAt, envelope.ExpiresAt.Add(-time.Minute), signer.leaf)
	if err != nil {
		t.Fatal(err)
	}
	reissued.Claim, err = trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	renewed, renewedVerified := observation(reissued)
	if renewedVerified.ReleaseIdentity() != verified.ReleaseIdentity() {
		t.Fatal("reissued claim changed immutable release identity")
	}
	if _, err := containerChannelIntent(state, renewed, renewedVerified, service, "gru", 1, signer.roots); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("reissued proof replaced the original delivery intent", err)
	}
	missingFloor := current
	missingFloor.Floor = nil
	if _, err := containerChannelIntent(serviceReleaseState{}, missingFloor, verified, service, "gru", 2, signer.roots); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("missing original operation invented a recovery generation", err)
	}
	first, err := containerChannelIntent(serviceReleaseState{}, current, verified, service, "gru", 2, signer.roots)
	if err != nil || first.Generation != 1 {
		t.Fatal("genuine floor absence did not start at generation one", first.Generation, err)
	}
	nextBundle, _ := genericRuntimeContainerRelease(t, signer, target, floors, 102, bundle.Migration)
	next, nextVerified := observation(nextBundle)
	advanced, err := containerChannelIntent(state, next, nextVerified, service, "gru", 2, signer.roots)
	if err != nil || advanced.Generation != initial.Generation+1 {
		t.Fatal("new signed release did not advance generation", advanced.Generation, err)
	}
	state.Intent = new(advanced)
	if _, err := containerChannelIntent(state, current, verified, service, "gru", 2, signer.roots); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("older signed release moved the producer backward", err)
	}
	legacy.Generation = math.MaxUint64
	if _, err := containerChannelIntent(serviceReleaseState{Intent: new(legacy), State: releasechannel.StateComplete}, current, verified, service, "gru", 2, signer.roots); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatal("generation overflow admitted a new release", err)
	}
}
