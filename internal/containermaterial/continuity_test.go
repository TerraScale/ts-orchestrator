package containermaterial

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

func TestRuntimePolicyUsesIndependentlySignedCompleteService(t *testing.T) {
	public, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	roots := trust.Keyring{keyID: public}
	now := time.Now().UTC().Truncate(time.Second)
	identity := cellspec.Identity{DeploymentID: entityid.New(), Cell: "gru", Environment: "production"}
	service := cellspec.Service{Role: "ts-auth", Profile: cellspec.Profile{Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 1 << 30},
		Args: []string{"serve"}, Env: map[string]string{"MODE": "production"}},
		Spec: &workload.ServiceSpec{Role: "ts-auth", Environment: "production", Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 3}}}
	claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "registry.example/auth@sha256:" + strings.Repeat("a", 64),
		SourceRepository: "https://github.com/TerraScale/ts-auth", SourceRevision: strings.Repeat("b", 40), SourceTreeSHA256: strings.Repeat("c", 64),
		Cell: "GRU", Environment: identity.Environment, Role: service.Role, Architecture: "arm64", ReleaseSequence: 101,
		SequenceMigrationSHA256: strings.Repeat("d", 64), QualificationSHA256: strings.Repeat("a", 64)}
	payload, err := trust.EncodePayload(claim)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, release.ContainerScope(release.ContainerTarget{Cell: claim.Cell, Environment: claim.Environment, Role: claim.Role, Architecture: claim.Architecture}), now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.New(), Source: delivery.ArtifactSource{
		Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256}, Cell: identity.Cell, Role: service.Role,
		Environment: identity.Environment, Generation: 9, DesiredReplicas: 2, ConfigDigest: delivery.ConfigDigestOf(service.Profile.Args, service.Profile.Env, service.Profile.Secrets),
		AuthorityEpoch: 1, Container: &release.ContainerBundle{Claim: wire}}
	verify := func(service cellspec.Service, intent delivery.Intent, generation uint64) Profile {
		t.Helper()
		spec := cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: generation, RequiresBinary: 1, Services: []cellspec.Service{service}}
		wire, err := cellspec.Sign(spec, nil, roots, now, time.Hour, root)
		if err != nil {
			t.Fatal(err)
		}
		profile, err := VerifyProfile(wire, roots, identity, intent)
		if err != nil {
			t.Fatal(err)
		}
		return profile
	}
	original := verify(service, intent, 1)
	currentIntent := intent.Clone()
	currentIntent.OperationID, currentIntent.AuthorityEpoch = entityid.New(), 2
	currentService := service
	currentService.Releasers = []string{"current-actor"}
	current := verify(currentService, currentIntent, 6)
	if VerifyRuntimePolicy(original, current) != nil {
		t.Fatal("same signed runtime policy was rejected after independent spec/releaser/operation renewal")
	}
	for _, name := range []string{"resources outside config digest", "service rollout outside config digest", "service replica policy outside config digest", "desired generation", "desired replicas"} {
		t.Run(name, func(t *testing.T) {
			candidateService, candidateIntent := service, currentIntent.Clone()
			candidateService.Spec = new(*service.Spec)
			switch name {
			case "resources outside config digest":
				candidateService.Profile.Resources.CPU++
			case "service rollout outside config digest":
				candidateService.Spec.Rollout.MaxSurge++
			case "service replica policy outside config digest":
				candidateService.Spec.Replicas.Max++
			case "desired generation":
				candidateIntent.Generation++
			case "desired replicas":
				candidateIntent.DesiredReplicas++
			}
			if VerifyRuntimePolicy(original, verify(candidateService, candidateIntent, 7)) == nil {
				t.Fatal("changed signed runtime policy was accepted")
			}
		})
	}
	if VerifyRuntimePolicy(Profile{}, current) == nil || VerifyRuntimePolicy(original, Profile{}) == nil {
		t.Fatal("zero signed profile was accepted")
	}
	if _, err := ContinueProfile(original, release.HistoricalContainer{}, current, release.VerifiedContainer{}, now); err == nil {
		t.Fatal("signed policy alone granted a continuation without independent current and historical release proofs")
	}
}
