package rootrelease

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestEquivalentOperationKeepsExactSignedWorkload(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, SourceRevision: strings.Repeat("a", 40), SourceRepository: "https://example.com/service", SourceTreeSHA256: strings.Repeat("b", 64), Cell: "GRU", Environment: "production", Role: "ts-auth", Architecture: "amd64", Image: "example.com/service@sha256:" + strings.Repeat("c", 64), ReleaseSequence: 7, SequenceMigrationSHA256: strings.Repeat("d", 64), QualificationSHA256: strings.Repeat("e", 64)}
	payload, err := trust.EncodePayload(claim)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := trust.Sign(payload, release.ContainerScope(release.ContainerTarget{Cell: claim.Cell, Environment: claim.Environment, Role: claim.Role, Architecture: claim.Architecture}), now, now.Add(time.Minute), key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	original := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.Derive("operation", "original"), Container: &release.ContainerBundle{Claim: wire}, Source: delivery.ArtifactSource{Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256}, Cell: "gru", Role: claim.Role, Environment: claim.Environment, Generation: 3, DesiredReplicas: 1, ConfigDigest: strings.Repeat("f", 64), AuthorityEpoch: 4}
	request := original.Clone()
	request.OperationID = entityid.Derive("operation", "request")
	request.AuthorityEpoch++
	if !equivalentIntents(request, original) {
		t.Fatal("equivalent original operation was rejected")
	}
	request.Generation++
	if equivalentIntents(request, original) {
		t.Fatal("new generation reused original tasks")
	}
	request = original.Clone()
	request.ConfigDigest = strings.Repeat("a", 64)
	if equivalentIntents(request, original) {
		t.Fatal("different profile reused original tasks")
	}
}

func TestStatusReadbackRequiresExactOriginalWrite(t *testing.T) {
	status := releasechannel.ContainerStatus{OperationID: "original", Fingerprint: "claim", State: releasechannel.StateComplete, UpdatedAt: time.Now().UTC()}
	if !sameStatus(status, status) {
		t.Fatal("identical readback rejected")
	}
	for _, change := range []func(*releasechannel.ContainerStatus){func(s *releasechannel.ContainerStatus) { s.OperationID = "other" }, func(s *releasechannel.ContainerStatus) { s.UpdatedAt = s.UpdatedAt.Add(time.Second) }, func(s *releasechannel.ContainerStatus) { s.State = releasechannel.StateFailed }, func(s *releasechannel.ContainerStatus) { s.Fingerprint = "other" }} {
		other := status
		change(&other)
		if sameStatus(status, other) {
			t.Fatal("unknown write accepted another status")
		}
	}
}
