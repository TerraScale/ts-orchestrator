package containermaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type continuitySequenceReader struct {
	release.SequenceObjectClient
	name  string
	wire  []byte
	reads int
}

func (reader *continuitySequenceReader) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if ctx.Err() != nil || request.NamespaceName == nil || *request.NamespaceName != "fixture" || request.BucketName == nil || *request.BucketName != "gru-1-head" || request.ObjectName == nil || *request.ObjectName != reader.name {
		return objectstorage.GetObjectResponse{}, fmt.Errorf("unexpected sequence read")
	}
	reader.reads++
	return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader(reader.wire))}, nil
}

func TestContinuationKeepsOriginalOperationWithIndependentCurrentQualification(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := func() (ed25519.PrivateKey, string) {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id, err := trust.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		return private, id
	}
	root, rootID := key()
	retiredRoot, retiredRootID := key()
	signer, signerID := key()
	roots := trust.Keyring{rootID: root.Public().(ed25519.PublicKey)}
	historicalRoots := trust.Keyring{rootID: root.Public().(ed25519.PublicKey), retiredRootID: retiredRoot.Public().(ed25519.PublicKey)}
	target := release.ContainerTarget{Cell: "GRU", Environment: "production", Role: "ts-auth", Architecture: "arm64"}
	sign := func(value any, scope trust.Scope, issued time.Time, private ed25519.PrivateKey) (trust.Envelope, []byte) {
		t.Helper()
		payload, err := trust.EncodePayload(value)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, scope, issued, issued.Add(time.Hour), private)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return envelope, wire
	}
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "fixture", Bucket: "gru-1-head", Region: "GRU",
		SignerKeyID: signerID, SignerPublicKey: base64.RawURLEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)), Role: target.Role, Environment: target.Environment, SequenceFloor: 100}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)})
	}
	migrationEnvelope, migrationWire := sign(migration, release.SequenceMigrationScope(target.Role, target.Environment), now.Add(-3*time.Hour), root)
	migrationSHA, err := trust.Fingerprint(migrationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	evidence := []byte("retained signed continuity qualification evidence")
	evidenceSHA := fmt.Sprintf("%x", sha256.Sum256(evidence))
	claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "registry.example/auth@sha256:" + strings.Repeat("a", 64),
		SourceRepository: "https://github.com/TerraScale/ts-auth", SourceRevision: strings.Repeat("b", 40), SourceTreeSHA256: strings.Repeat("c", 64),
		Cell: target.Cell, Environment: target.Environment, Role: target.Role, Architecture: target.Architecture,
		ReleaseSequence: 101, SequenceMigrationSHA256: migrationSHA, QualificationSHA256: strings.Repeat("a", 64)}
	makeBundle := func(claim release.ContainerClaim, issued time.Time) release.ContainerBundle {
		t.Helper()
		candidate := release.ProductionExpectation{SourceRevision: claim.SourceRevision, ArtifactSHA256: strings.Repeat("a", 64), QualificationSHA256: claim.QualificationSHA256,
			Cell: claim.Cell, Environment: claim.Environment, Role: claim.Role, Architecture: claim.Architecture, Runtime: release.ProductionRuntime}
		qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate, Evidence: []release.ProductionGateEvidence{
			{Gate: "runtime-ha", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: issued},
			{Gate: "workload-safety", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: issued}}}
		_, claim.Production.Qualification = sign(qualification, release.ProductionQualificationScope(candidate), issued, root)
		grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: signerID,
			SubjectPublicKey: base64.RawURLEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)), Capabilities: []trust.Capability{{
				Domain: release.ContainerClaimDomain, DeploymentID: release.ContainerScope(target).DeploymentID, Cell: target.Cell,
				Environment: target.Environment, Role: target.Role, Slots: []string{"linux-arm64"}, Actions: []string{"sign"}}}}, issued, issued.Add(time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		grantWire, err := trust.EncodeEnvelope(grant)
		if err != nil {
			t.Fatal(err)
		}
		_, claimWire := sign(claim, release.ContainerScope(target), issued, signer)
		family, err := claim.WorkerFamilyDigest()
		if err != nil {
			t.Fatal(err)
		}
		identity := release.SequenceIdentity{Role: claim.Role, Environment: claim.Environment, SourceRevision: claim.SourceRevision, ManifestSHA256: family}
		scope := release.SequenceMigrationScope(claim.Role, claim.Environment)
		scope.Domain, scope.Slot = "terrascale.release.sequence-reservation", "reservation"
		reservation, _ := sign(struct {
			Sequence uint64                   `json:"sequence"`
			Identity release.SequenceIdentity `json:"identity"`
		}{claim.ReleaseSequence, identity}, scope, issued, signer)
		sequence, err := protocol.EncodeJSON(struct {
			Schema      string                   `json:"schema"`
			Sequence    uint64                   `json:"sequence"`
			Identity    release.SequenceIdentity `json:"identity"`
			Migration   trust.Envelope           `json:"migration"`
			Reservation trust.Envelope           `json:"reservation"`
		}{"terrascale.release.sequence.v1", claim.ReleaseSequence, identity, migrationEnvelope, reservation})
		if err != nil {
			t.Fatal(err)
		}
		return release.ContainerBundle{Claim: claimWire, Delegation: grantWire, Migration: migrationWire, Sequence: sequence}
	}
	originalBundle := makeBundle(claim, now.Add(-2*time.Hour))
	currentBundle := makeBundle(claim, now)
	renewedReservation := bytes.Clone(currentBundle.Sequence)
	currentBundle.Sequence = bytes.Clone(originalBundle.Sequence)
	historical, err := release.VerifyContainerHistorical(originalBundle, historicalRoots, target)
	if err != nil {
		t.Fatal(err)
	}
	reader := &continuitySequenceReader{name: release.SequenceReservationObject(claim.Role, claim.Environment, migrationSHA, claim.ReleaseSequence), wire: currentBundle.Sequence}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	verified, err := release.VerifyContainerCurrent(ctx, currentBundle, roots, target, now, now.Add(30*time.Second), func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(evidence)), nil
	}, release.SequenceLocation{Client: reader, Namespace: "fixture", Bucket: "gru-1-head"})
	if err != nil || reader.reads == 0 {
		t.Fatal("independent current verifier did not authenticate signed sequence and evidence", err)
	}
	identity := cellspec.Identity{DeploymentID: entityid.New(), Cell: "gru", Environment: target.Environment}
	service := cellspec.Service{Role: target.Role, Profile: cellspec.Profile{Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30}},
		Spec: &workload.ServiceSpec{Role: target.Role, Environment: target.Environment, Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3}}}
	profile := func(bundle release.ContainerBundle, operation string, generation, epoch uint64, private ed25519.PrivateKey, keys trust.Keyring, issued time.Time) Profile {
		t.Helper()
		intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: operation, Source: delivery.ArtifactSource{
			Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256}, Cell: identity.Cell,
			Role: target.Role, Environment: target.Environment, Generation: 9, DesiredReplicas: 2, ConfigDigest: delivery.ConfigDigestOf(nil, nil, nil), AuthorityEpoch: epoch, Container: &bundle}
		wire, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: generation, RequiresBinary: 1, Services: []cellspec.Service{service}}, nil, keys, issued, time.Hour, private)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := VerifyProfile(wire, keys, identity, intent)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	original := profile(originalBundle, entityid.New(), 1, 1, retiredRoot, historicalRoots, now.Add(-4*time.Hour))
	current := profile(currentBundle, entityid.New(), 6, 2, root, roots, now)
	continued, err := ContinueProfile(original, historical, current, verified, now)
	if err != nil {
		t.Fatal("same immutable release rejected after expired original qualification and retired profile root", err)
	}
	expected, err := ServiceIntent(continued, target.Architecture)
	if err != nil || expected.OperationID != original.Intent().OperationID || continued.Intent().OperationID != current.Intent().OperationID ||
		continued.specSHA256 != current.specSHA256 || verifyExpected(continued, expected, verified) != nil {
		t.Fatal("continuation lost independent current authority or original runtime operation", err)
	}
	if _, err := ContinueProfile(continued, historical, current, verified, now); err == nil {
		t.Fatal("existing continued object rebound to a successor source")
	}
	if VerifyContinuity(original, historical, current, verified, verified.ExpiresAt()) == nil {
		t.Fatal("expired current qualification granted continuity")
	}
	swappedBundle := originalBundle
	swappedBundle.Sequence = renewedReservation
	swappedHistorical, err := release.VerifyContainerHistorical(swappedBundle, historicalRoots, target)
	if err != nil || swappedHistorical.Fingerprint() != historical.Fingerprint() || swappedHistorical.BundleSHA256() == historical.BundleSHA256() {
		t.Fatal("bundle substitution fixture did not retain the same authenticated claim", err)
	}
	wrongOriginal := profile(swappedBundle, original.Intent().OperationID, 1, 1, retiredRoot, historicalRoots, now.Add(-4*time.Hour))
	if VerifyContinuity(wrongOriginal, historical, current, verified, now) == nil {
		t.Fatal("historical token authenticated a different protected original bundle")
	}
}
