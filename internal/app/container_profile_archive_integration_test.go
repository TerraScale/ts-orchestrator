package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
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
	now := time.Now().UTC().Add(-time.Second)
	claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "registry.example/terrascale/auth@sha256:" + strings.Repeat("a", 64), SourceRepository: "https://github.com/TerraScale/ts-auth", SourceRevision: strings.Repeat("b", 40), SourceTreeSHA256: strings.Repeat("c", 64), Cell: "GRU", Environment: identity.Environment, Role: policy.Role, Architecture: "arm64", ReleaseSequence: 101, SequenceMigrationSHA256: strings.Repeat("d", 64), QualificationSHA256: strings.Repeat("e", 64)}
	payload, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, release.ContainerScope(release.ContainerTarget{Cell: claim.Cell, Environment: identity.Environment, Role: policy.Role, Architecture: claim.Architecture}), now, now.Add(time.Hour), keys.leaf)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.New(), Source: delivery.ArtifactSource{Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256}, Cell: identity.Cell, Role: policy.Role, Environment: identity.Environment, Generation: 1, DesiredReplicas: 1, ConfigDigest: delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets), AuthorityEpoch: control.Current().Epoch, Container: &release.ContainerBundle{Claim: wire}}
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
