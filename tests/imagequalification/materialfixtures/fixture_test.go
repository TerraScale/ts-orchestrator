package materialfixtures

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// These ephemeral keys exercise source trust checks, never native acceptance.
func TestSignedMaterialFixtureBoundary(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	profile := cellspec.Profile{Args: []string{"/bin/sh", "-c", "exit 17"}, Resources: placement.Resources{CPU: 1, MemoryBytes: 32 << 20, DiskBytes: 1 << 30}}
	spec := cellspec.Spec{Schema: cellspec.Schema, Identity: cellspec.Identity{DeploymentID: entityid.Derive("fixture", "deployment"), Cell: "gru", Environment: "production"}, Generation: 1, RequiresBinary: 1, Services: []cellspec.Service{{Role: "ts-auth", Profile: profile}}}
	claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "registry.example/terrascale/auth@sha256:" + strings.Repeat("a", 64), SourceRevision: strings.Repeat("b", 40), SourceRepository: "https://github.com/TerraScale/ts-auth", SourceTreeSHA256: strings.Repeat("e", 64), Cell: "GRU", Environment: "production", Role: "ts-auth", Architecture: "arm64", ReleaseSequence: 101, SequenceMigrationSHA256: strings.Repeat("c", 64), QualificationSHA256: strings.Repeat("d", 64)}
	payload, err := trust.EncodePayload(claim)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, release.ContainerScope(release.ContainerTarget{Cell: "GRU", Environment: "production", Role: "ts-auth", Architecture: "arm64"}), now, now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	claimWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.Derive("fixture", "operation"), Source: delivery.ArtifactSource{Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256}, Cell: "gru", Role: "ts-auth", Environment: "production", Generation: 1, DesiredReplicas: 1, ConfigDigest: delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets), AuthorityEpoch: 1, Container: &release.ContainerBundle{Claim: claimWire}}
	input := Input{Spec: spec, Intent: intent, Roots: roots, RootPrivateKey: private, IssuedAt: now, Lifetime: time.Hour,
		Codec: delivery.Ed25519Codec{Cell: "gru", Actor: "release", PrivateKey: private, Trusted: map[string]delivery.TrustedSigner{keyID: {Actor: "release", PublicKey: public}}, Lifetime: time.Minute, MaxLifetime: time.Minute}}
	fixture, err := Sign(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := containermaterial.VerifyProfile(fixture.SignedProfile, roots, spec.Identity, intent)
	if err != nil || !proof.NoSecrets() {
		t.Fatal("signed no-secret authority rejected", err)
	}
	mapped, err := containermaterial.ServiceIntent(proof, "arm64")
	if err != nil || len(mapped.Container.Command) != 0 || strings.Join(mapped.Container.Args, " ") != "/bin/sh -c exit 17" {
		t.Fatal("signed process mapping changed", err)
	}
	changed := proof.Profile()
	changed.Args[0] = "/wrong"
	if proof.Profile().Args[0] != "/bin/sh" {
		t.Fatal("caller mutated opaque proof")
	}
	input.Intent.ConfigDigest = strings.Repeat("f", 64)
	if _, err := Sign(t.Context(), input); err == nil {
		t.Fatal("profile digest drift accepted")
	}
	input.Intent = intent
	input.Spec.Services[0].Profile.Secrets = map[string]vaultsecret.Ref{"KEY_FILE": {Vault: "ocid1.vault.oc1.sa-saopaulo-1.fixture", Name: "gru-ts-auth-key"}}
	input.Intent.ConfigDigest = delivery.ConfigDigestOf(profile.Args, profile.Env, input.Spec.Services[0].Profile.Secrets)
	if _, err := Sign(t.Context(), input); err == nil {
		t.Fatal("native no-secret fixture accepted a secret profile")
	}
}
