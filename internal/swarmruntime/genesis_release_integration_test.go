package swarmruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"

	"crypto/sha256"

	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"

	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The decorator only schedules a competing real RPC; all observations and the
// losing AlreadyExists response still come from the persistent Swarm manager.
type genesisWitnessCollision struct {
	api.ControlClient
	name         string
	replaceFloor bool
	collisions   int
}

func (c *genesisWitnessCollision) CreateConfig(ctx context.Context, request *api.CreateConfigRequest, options ...grpc.CallOption) (*api.CreateConfigResponse, error) {
	if request.Spec.Annotations.Name == c.name && c.collisions == 0 {
		spec := request.Spec.Copy()
		if c.replaceFloor {
			var witness genesisReleaseWitness
			if err := protocol.DecodeStrict(spec.Data, &witness, 64<<10); err != nil {
				return nil, err
			}
			witness.FloorID = entityid.Derive("competing-genesis-floor")
			wire, err := protocol.EncodeJSON(witness)
			if err != nil {
				return nil, err
			}
			spec.Data = wire
		}
		if _, err := c.ControlClient.CreateConfig(ctx, &api.CreateConfigRequest{Spec: spec}, options...); err != nil {
			return nil, err
		}
		c.collisions++
		response, err := c.ControlClient.CreateConfig(ctx, request, options...)
		if status.Code(err) != codes.AlreadyExists {
			return nil, fmt.Errorf("competing witness did not produce a real AlreadyExists: %w", err)
		}
		return response, err
	}
	return c.ControlClient.CreateConfig(ctx, request, options...)
}

type genesisFloorAuthority struct {
	now        time.Time
	root       ed25519.PrivateKey
	roots      trust.Keyring
	signer     ed25519.PrivateKey
	delegation trust.Envelope
	genesis    release.VerifiedWorkloadGenesis
}

func (f genesisFloorAuthority) container(t *testing.T, ctx context.Context, location release.SequenceLocation, architecture, source string) (ServiceIntent, release.VerifiedContainer) {
	t.Helper()
	index := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":42,"platform":{"os":"linux","architecture":"arm64"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":42,"platform":{"os":"linux","architecture":"amd64"}}]}`, strings.Repeat("a", 64), strings.Repeat("b", 64)))
	digest := strings.Repeat("a", 64)
	if architecture == "amd64" {
		digest = strings.Repeat("b", 64)
	}
	claim := release.ContainerClaim{Schema: release.ContainerGenesisClaimSchema, Image: "registry.example/platform/function-worker@sha256:" + digest,
		SourceRepository: "https://github.com/TerraScale/ts-orchestrator", SourceRevision: source, SourceTreeSHA256: strings.Repeat("e", 64), Cell: "GRU", Environment: "production",
		Role: "function-worker", Architecture: architecture, QualificationSHA256: fmt.Sprintf("%x", sha256.Sum256(index)), WorkloadGenesisSHA256: f.genesis.Fingerprint()}
	family, err := claim.WorkerFamilyDigest()
	if err != nil {
		t.Fatal(err)
	}
	sequence, allocation, err := location.AllocateWithEvidence(ctx, release.SequenceIdentity{Role: claim.Role, Environment: claim.Environment, SourceRevision: source, ManifestSHA256: family}, f.roots, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	claim.ReleaseSequence = sequence
	evidence := []byte("genesis fixture qualification bytes; not production qualification")
	candidate := release.ProductionExpectation{SourceRevision: source, ArtifactSHA256: digest, QualificationSHA256: claim.QualificationSHA256, Cell: "GRU", Environment: "production",
		Runtime: release.ProductionRuntime, Architecture: architecture, Role: claim.Role}
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: fmt.Sprintf("%x", sha256.Sum256(evidence)), Bytes: int64(len(evidence)), CompletedAt: f.now})
	}
	sign := func(value any, scope trust.Scope, key ed25519.PrivateKey) []byte {
		t.Helper()
		payload, err := trust.EncodePayload(value)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := trust.Sign(payload, scope, f.now, f.now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(signed)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	claim.Production.Qualification = sign(qualification, release.ProductionQualificationScope(candidate), f.root)
	target := release.ContainerTarget{Cell: "GRU", Environment: "production", Role: claim.Role, Architecture: architecture, Genesis: f.genesis}
	delegation, err := trust.EncodeEnvelope(f.delegation)
	if err != nil {
		t.Fatal(err)
	}
	bundle := release.ContainerBundle{Claim: sign(claim, release.ContainerScope(target), f.signer), Delegation: delegation, Sequence: allocation, Index: index}
	reader := func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(evidence)), nil
	}
	deadline, _ := ctx.Deadline()
	verified, err := release.VerifyContainerCurrent(ctx, bundle, f.roots, target, time.Now().UTC(), deadline, reader, location)
	if err != nil {
		t.Fatal(err)
	}
	return ServiceIntent{ID: entityid.Derive("function-worker-release", "production", "sa-saopaulo-1"), Role: claim.Role, Region: "sa-saopaulo-1", Environment: "production", Architecture: architecture}, verified
}
