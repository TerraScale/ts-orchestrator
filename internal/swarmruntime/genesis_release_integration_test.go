package swarmruntime

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

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The fixture crosses signed OCI SDK allocation and persistent Swarm Raft RPCs.
// It creates no service or task and makes no native runtime/stop authority claim.
func TestGenesisReleaseFloorRaftIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	f := newGenesisFloorAuthority(t)
	location := serviceAllocationStore(t, "fixture", "gru-1-head")
	location.Genesis, location.Delegation = f.genesis, f.delegation
	if err := location.ImportGenesis(ctx, f.roots, "function-worker", "production", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	arm, first := f.container(t, ctx, location, "arm64", strings.Repeat("c", 40))
	amd, sibling := f.container(t, ctx, location, "amd64", strings.Repeat("c", 40))
	if first.Claim().ReleaseSequence != sibling.Claim().ReleaseSequence {
		t.Fatal("same signed family received different architecture allocations")
	}
	cfg := serviceConfig(t, "ts-gru-1", "manager")
	node, err := StartNode(ctx, cfg, serviceExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		if err := node.Stop(stop); err != nil {
			t.Errorf("stop genesis floor manager: %v", err)
		}
	})
	client, err := node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	functionIntent := FunctionServiceIntent{Environment: arm.Environment, Region: arm.Region, Architecture: arm.Architecture}
	verifyWorkerFloors := func(worker release.VerifiedContainer, current, retained bool) {
		t.Helper()
		if err := functionIntent.VerifyWorkerFloor(ctx, client, worker); (err == nil) != current {
			t.Fatalf("current function worker floor acceptance = %v, want %v: %v", err == nil, current, err)
		}
		if err := functionIntent.verifyRetainedWorkerFloor(ctx, client, worker); (err == nil) != retained {
			t.Fatalf("retained function worker floor acceptance = %v, want %v: %v", err == nil, retained, err)
		}
	}
	restart := func() {
		t.Helper()
		stop, done := context.WithTimeout(ctx, 15*time.Second)
		err := node.Stop(stop)
		done()
		if err != nil {
			t.Fatal(err)
		}
		node, err = StartNode(ctx, cfg, serviceExecutor{})
		if err != nil {
			t.Fatal(err)
		}
		client, err = node.ControlClient(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, field := range []string{"region", "environment", "role", "architecture"} {
		wrong := arm
		switch field {
		case "region":
			wrong.Region = "us-sanjose-1"
		case "environment":
			wrong.Environment = "staging"
		case "role":
			wrong.Role = "ts-auth"
		case "architecture":
			wrong.Architecture = "amd64"
		}
		if _, err := reserveReleaseFloor(ctx, client, wrong, first, f.roots, release.SequenceFloor{}, 0); err == nil {
			t.Fatalf("signed genesis admitted wrong %s", field)
		}
	}
	if _, err := reserveReleaseFloor(ctx, client, arm, first, f.roots, release.SequenceFloor{Cell: "GRU", RunNumber: 1}, 0); err == nil {
		t.Fatal("genesis imported a fabricated legacy floor")
	}
	listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{})
	if err != nil || len(listed.Configs) != 0 {
		t.Fatalf("refused scope or legacy floor wrote manager state: %+v %v", listed, err)
	}

	// Stop after the real CAS floor write, before the create-only witness write.
	floor, err := reserveReleaseFloorRecord(ctx, client, arm, first, f.roots, release.SequenceFloor{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := authenticateReleaseFloor(ctx, client, arm, first, f.roots, floor); err == nil {
		t.Fatal("floor without its origin witness authorized an effect")
	}
	verifyWorkerFloors(first, false, false)
	if witness, err := readGenesisReleaseWitness(ctx, client, arm, first); err != nil || witness != nil {
		t.Fatalf("floor-first boundary already had a witness: %+v %v", witness, err)
	}
	restart()
	recovered, err := readReleaseFloorRecord(ctx, client, arm, first, f.roots)
	if err != nil || recovered == nil || recovered.ID != floor.ID {
		t.Fatalf("manager restart lost the recoverable CAS floor: %+v %v", recovered, err)
	}
	if err := authenticateReleaseFloor(ctx, client, arm, first, f.roots, recovered); err == nil {
		t.Fatal("restart turned an unwitnessed floor into authority")
	}
	witnessName, err := genesisWitnessName(arm, first)
	if err != nil {
		t.Fatal(err)
	}
	collision := &genesisWitnessCollision{ControlClient: client, name: witnessName}
	floor, err = reserveReleaseFloor(ctx, collision, arm, first, f.roots, release.SequenceFloor{}, 0)
	if err != nil || collision.collisions != 1 || floor.ID != recovered.ID {
		t.Fatalf("compatible create collision did not read back the original floor: %+v %v", floor, err)
	}
	witness, err := readGenesisReleaseWitness(ctx, client, arm, first)
	if err != nil || witness == nil {
		t.Fatalf("recovery did not retain the origin witness: %+v %v", witness, err)
	}
	if err := authenticateReleaseFloor(ctx, client, arm, first, f.roots, floor); err != nil {
		t.Fatal("compatible collision was not authenticated: ", err)
	}
	verifyWorkerFloors(first, true, true)

	// A real competing writer wins the Config name with a different floor ID.
	if _, err := client.RemoveConfig(ctx, &api.RemoveConfigRequest{ConfigID: witness.ID}); err != nil {
		t.Fatal(err)
	}
	bad := &genesisWitnessCollision{ControlClient: client, name: witnessName, replaceFloor: true}
	if err := ensureGenesisReleaseWitness(ctx, bad, arm, first, floor); err == nil || bad.collisions != 1 {
		t.Fatalf("incompatible create collision escaped exact readback: %v", err)
	}
	conflicting, err := readGenesisReleaseWitness(ctx, client, arm, first)
	if err != nil || conflicting == nil {
		t.Fatalf("competing witness not retained by actual manager: %+v %v", conflicting, err)
	}
	if err := authenticateReleaseFloor(ctx, client, arm, first, f.roots, floor); err == nil {
		t.Fatal("competing floor ID authorized an effect")
	}
	verifyWorkerFloors(first, false, false)
	if _, err := client.RemoveConfig(ctx, &api.RemoveConfigRequest{ConfigID: conflicting.ID}); err != nil {
		t.Fatal(err)
	}
	if err := ensureGenesisReleaseWitness(ctx, client, arm, first, floor); err != nil {
		t.Fatal(err)
	}

	// The floor's data must retain the exact original scope, not just its name.
	changedOrigin := f.genesis.Origin()
	changedOrigin.InstallationID = entityid.Derive("foreign-genesis-installation")
	foreignData, err := protocol.EncodeJSON(genesisFloorEvidence{"terrascale.release.genesis-floor.v1", f.genesis.Fingerprint(), changedOrigin})
	if err != nil {
		t.Fatal(err)
	}
	foreignSpec := floor.Spec.Copy()
	foreignSpec.Data = foreignData
	if _, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: floor.ID, ConfigVersion: &floor.Meta.Version, Spec: foreignSpec}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("manager permitted in-place genesis origin replacement: %v", err)
	}
	amdFloor, err := reserveReleaseFloor(ctx, client, amd, sibling, f.roots, release.SequenceFloor{}, 0)
	if err != nil || amdFloor.ID == floor.ID {
		t.Fatalf("worker architecture floors were merged: %+v %v", amdFloor, err)
	}
	amdWitness, err := readGenesisReleaseWitness(ctx, client, amd, sibling)
	if err != nil || amdWitness == nil {
		t.Fatalf("AMD witness unavailable: %+v %v", amdWitness, err)
	}
	armWitness, err := readGenesisReleaseWitness(ctx, client, arm, first)
	if err != nil || armWitness == nil || armWitness.ID == amdWitness.ID {
		t.Fatalf("architecture witnesses were merged: %+v %v", armWitness, err)
	}
	if err := verifyGenesisReleaseWitness(amdWitness, floor, arm, first); err == nil {
		t.Fatal("AMD witness authenticated the ARM floor")
	}
	_, next := f.container(t, ctx, location, "arm64", strings.Repeat("d", 40))
	latest, err := reserveReleaseFloor(ctx, client, arm, next, f.roots, release.SequenceFloor{}, 0)
	if err != nil || latest.ID != floor.ID || next.Claim().ReleaseSequence <= first.Claim().ReleaseSequence {
		t.Fatalf("latest release failed to advance the permanent floor: %+v %v", latest, err)
	}
	verifyWorkerFloors(first, false, true)
	verifyWorkerFloors(next, true, true)
	restart()
	retained, err := readReleaseFloorRecord(ctx, client, arm, next, f.roots)
	if err != nil || retained == nil || !proto.Equal(retained, latest) {
		t.Fatalf("restart reset the latest permanent floor: %+v %v", retained, err)
	}
	if _, err := reserveReleaseFloor(ctx, client, arm, first, f.roots, release.SequenceFloor{}, 0); err == nil {
		t.Fatal("restart admitted rollback below the latest permanent floor")
	}
	if _, err := reserveReleaseFloor(ctx, client, amd, sibling, f.roots, release.SequenceFloor{}, 0); err != nil {
		t.Fatal("advancing ARM revoked the independent AMD floor: ", err)
	}
	witness, err = readGenesisReleaseWitness(ctx, client, arm, next)
	if err != nil || witness == nil {
		t.Fatalf("latest origin witness unavailable: %+v %v", witness, err)
	}
	if _, err := client.RemoveConfig(ctx, &api.RemoveConfigRequest{ConfigID: latest.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := readReleaseFloorRecord(ctx, client, arm, next, f.roots); err == nil {
		t.Fatal("missing established floor was treated as fresh genesis")
	}
	if _, err := reserveReleaseFloor(ctx, client, arm, next, f.roots, release.SequenceFloor{}, 0); err == nil {
		t.Fatal("missing established floor was recreated by admission")
	}
	verifyWorkerFloors(next, false, false)
	replacement, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: latest.Spec.Copy()})
	if err != nil || replacement.Config.ID == latest.ID {
		t.Fatalf("replacement did not exercise a new actual Config identity: %+v %v", replacement, err)
	}
	if _, err := readReleaseFloorRecord(ctx, client, arm, next, f.roots); err == nil {
		t.Fatal("byte-identical replacement escaped the established floor ID pin")
	}
	if err := authenticateReleaseFloor(ctx, client, arm, next, f.roots, replacement.Config); err == nil {
		t.Fatal("replacement floor authorized an effect")
	}
	verifyWorkerFloors(next, false, false)
	if _, err := client.RemoveConfig(ctx, &api.RemoveConfigRequest{ConfigID: replacement.Config.ID}); err != nil {
		t.Fatal(err)
	}
	foreignSpec = latest.Spec.Copy()
	foreignSpec.Data = foreignData
	if _, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: foreignSpec}); err != nil {
		t.Fatal(err)
	}
	if _, err := readReleaseFloorRecord(ctx, client, arm, next, f.roots); err == nil || !strings.Contains(err.Error(), "original genesis") {
		t.Fatalf("replacement with foreign original installation escaped origin validation: %v", err)
	}
	unchanged, err := readGenesisReleaseWitness(ctx, client, arm, next)
	if err != nil || !proto.Equal(witness, unchanged) {
		t.Fatalf("missing/replaced floor rewrote the permanent origin witness: %+v %v", unchanged, err)
	}
	services, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil || len(services.Services) != 0 {
		t.Fatalf("floor/witness fault injection created a service: %+v %v", services, err)
	}
}

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

func newGenesisFloorAuthority(t *testing.T) genesisFloorAuthority {
	t.Helper()
	public, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	f := genesisFloorAuthority{now: time.Now().UTC().Truncate(time.Second), root: root, roots: roots}
	installation := entityid.Derive("genesis-floor-installation")
	var origins []release.WorkloadGenesis
	var regions, authorities []any
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		deployment, cluster := entityid.Derive("genesis-floor-deployment", cell), entityid.Derive("genesis-floor-cluster", cell)
		regions = append(regions, map[string]any{"plan": map[string]any{"cell": cell}, "bootstrapMaterial": map[string]any{"installationId": installation,
			"config": map[string]any{"deploymentId": deployment, "clusterId": cluster, "cell": strings.ToLower(cell), "environment": "production"}}})
		for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
			origins = append(origins, release.WorkloadGenesis{Schema: release.WorkloadGenesisSchema, TenancyID: "ocid1.tenancy.oc1..genesisfloorfixture",
				InstallationID: installation, DeploymentID: deployment, ClusterID: cluster, Cell: cell, Environment: "production", Role: role, Namespace: "fixture", Bucket: "gru-1-head"})
		}
	}
	for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := trust.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		delegation := trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: base64.RawURLEncoding.EncodeToString(public)}
		for _, cell := range []string{"GRU", "SFO", "FRA"} {
			scope := release.ContainerScope(release.ContainerTarget{Cell: cell, Environment: "production", Role: role, Architecture: "arm64"})
			delegation.Capabilities = append(delegation.Capabilities, trust.Capability{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: cell,
				Environment: "production", Role: role, Slots: []string{"linux-amd64", "linux-arm64"}, Actions: []string{"sign"}})
		}
		signed, err := trust.SignDelegation(delegation, f.now, f.now.Add(time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(signed)
		if err != nil {
			t.Fatal(err)
		}
		authorities = append(authorities, map[string]any{"role": role, "environment": "production", "cells": []string{"GRU", "SFO", "FRA"}, "architectures": []string{"amd64", "arm64"}, "delegationWire": wire})
		if role == "function-worker" {
			f.signer, f.delegation = key, signed
		}
	}
	scope := trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: origins[0].DeploymentID, Cell: "GRU", Environment: "production", Role: "foundation", Slot: origins[0].ClusterID}
	payload, err := trust.EncodePayload(map[string]any{"schemaVersion": 3, "generation": 1, "tenancyId": origins[0].TenancyID, "installationId": installation,
		"workloadGenesis": origins, "regions": regions, "releaseAuthorities": authorities})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := trust.Sign(payload, scope, f.now, f.now.Add(24*time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	f.genesis, err = release.VerifyWorkloadGenesis(wire, roots, scope, origins[2])
	if err != nil {
		t.Fatal(err)
	}
	wrongScope := scope
	wrongScope.Slot = entityid.Derive("foreign-genesis-cluster")
	if _, err := release.VerifyWorkloadGenesis(wire, roots, wrongScope, origins[2]); err == nil {
		t.Fatal("same root signature crossed original foundation scope")
	}
	return f
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
