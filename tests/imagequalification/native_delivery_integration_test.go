package imagequalification

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestRetainedNativeDeliveryPreservesSignedAuthority(t *testing.T) {
	f := fixture(t)
	claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: f.prepared.approval.WorkloadImage,
		SourceRevision: strings.Repeat("b", 40), SourceRepository: "https://github.com/TerraScale/ts-auth", SourceTreeSHA256: strings.Repeat("c", 64),
		Cell: "GRU", Environment: "production", Role: "ts-auth", Architecture: "arm64", ReleaseSequence: 101,
		SequenceMigrationSHA256: strings.Repeat("d", 64), QualificationSHA256: strings.Repeat("e", 64)}
	payload, err := trust.EncodePayload(claim)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, release.ContainerScope(release.ContainerTarget{Cell: "GRU", Environment: "production", Role: "ts-auth", Architecture: "arm64"}), f.now, f.now.Add(time.Hour), f.private)
	if err != nil {
		t.Fatal(err)
	}
	claimWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.Derive("native", "operation"),
		Source: delivery.ArtifactSource{Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256},
		Cell:   "gru", Role: "ts-auth", Environment: "production", Generation: 1, DesiredReplicas: 1,
		ConfigDigest: strings.Repeat("f", 64), AuthorityEpoch: 1, Container: &release.ContainerBundle{Claim: claimWire}}
	keyID, err := protocol.KeyID(f.private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	codec := delivery.Ed25519Codec{Cell: "gru", Actor: "release", PrivateKey: f.private,
		Trusted:  map[string]delivery.TrustedSigner{keyID: {Actor: "release", PublicKey: f.private.Public().(ed25519.PublicKey)}},
		Lifetime: time.Minute, MaxLifetime: time.Minute}
	payload, err = protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := codec.Sign(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	signer := retainedIntentSigner{wire: wire, fingerprint: fingerprint}
	retained, err := signer.Sign(t.Context(), payload)
	if err != nil || !bytes.Equal(retained, wire) {
		t.Fatal("retained signer replaced original signed bytes", err)
	}
	if _, err := codec.Verify(t.Context(), retained); err != nil {
		t.Fatal("retained authority no longer verifies", err)
	}
	intent.OperationID = entityid.Derive("native", "different-operation")
	changed, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(t.Context(), changed); err == nil {
		t.Fatal("retained signer authorized a different operation")
	}
	retained[0] ^= 1
	if _, err := codec.Verify(t.Context(), wire); err != nil {
		t.Fatal("returned bytes mutated the retained authority", err)
	}
}
