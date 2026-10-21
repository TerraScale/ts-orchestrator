package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
	"google.golang.org/grpc"
)

// The root signature, SDK CAS, signed NATS session, ordered owner and persistent
// SwarmKit control store are real. Executor and recipient probe are simulated;
// this does not qualify native execution, foundation transport or UNIT retirement.
func TestGenericGenesisOwnerAndPersistentFloorIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	signer := newFunctionPublicationSigner(t)
	target, original, wire, scope := genericGenesisOriginal(t, &signer)
	for _, origin := range original {
		verified, err := release.VerifyWorkloadGenesis(wire, signer.roots, scope, origin)
		if err != nil || verified.Fingerprint() != target.Genesis.Fingerprint() {
			t.Fatalf("full nine-origin grant did not share one authenticated fingerprint: %v", err)
		}
	}
	if _, err := release.VerifyWorkloadGenesis(wire, trust.Keyring{}, scope, target.Genesis.Origin()); err == nil {
		t.Fatal("original proof accepted without its independently pinned root")
	}
	changed := target.Genesis.Origin()
	changed.Namespace = "foreign"
	if _, err := release.VerifyWorkloadGenesis(wire, signer.roots, scope, changed); err == nil {
		t.Fatal("original proof accepted a different permanent home")
	}
	originalEnvelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	var incomplete map[string]any
	if err := json.Unmarshal(originalEnvelope.Payload, &incomplete); err != nil {
		t.Fatal(err)
	}
	incomplete["workloadGenesis"] = original[:8]
	if _, err := release.VerifyWorkloadGenesis(genericGenesisSign(t, incomplete, scope, signer.root), signer.roots, scope, target.Genesis.Origin()); err == nil {
		t.Fatal("a root-signed eight-origin fragment replaced the complete original proof")
	}
	auth := newAuthenticatedNATS(t, "gru")
	broker, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	fencer, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: target.Genesis.Origin().DeploymentID, Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fencer.Close() })
	executor := &genericRuntimeExecutor{controllers: map[string]*genericRuntimeTask{}}
	session := startGenericRuntimeHostSession(t, ctx, auth, broker, fencer, target.Role, target.Environment, executor)
	guard := func(check context.Context) error {
		current, err := release.VerifyWorkloadGenesis(wire, signer.roots, scope, target.Genesis.Origin())
		if err != nil {
			return err
		}
		if current.Fingerprint() != target.Genesis.Fingerprint() {
			return errors.New("original genesis changed")
		}
		if err := session.verify(check); err != nil {
			return err
		}
		return fencer.Guard(check, fencer.Current().Epoch)
	}
	if err := session.hosts.GuardContainerOwner(ctx, target.Environment, target.Role); err == nil {
		t.Fatal("empty native inventory created runtime authority")
	}
	ownerKey := "gru." + target.Environment + "." + target.Role
	rejected := errors.New("genesis final guard rejected")
	guardCalls := 0
	if err := session.hosts.ClaimGenesisContainer(ctx, target.Genesis, func(check context.Context) error {
		if err := guard(check); err != nil {
			return err
		}
		guardCalls++
		if guardCalls > 1 {
			return rejected
		}
		return nil
	}); !errors.Is(err, rejected) {
		t.Fatal("genesis owner ignored the final ordered verifier guard", err)
	}
	if _, err := fencer.ReadHostMutation(ctx, authority.MutationRuntimeOwner, ownerKey); !errors.Is(err, authority.ErrNotFound) {
		t.Fatal("rejected genesis claim changed the real ordered owner log", err)
	}
	if err := session.hosts.ClaimGenesisContainer(ctx, target.Genesis, guard); err != nil {
		t.Fatal(err)
	}
	owner, err := fencer.ReadHostMutation(ctx, authority.MutationRuntimeOwner, ownerKey)
	if err != nil || owner.Sequence == 0 {
		t.Fatalf("genesis owner was not committed to the real ordered log: %v", err)
	}
	var ownerData struct {
		WorkloadGenesisSHA256 string                  `json:"workload_genesis_sha256"`
		Genesis               release.WorkloadGenesis `json:"genesis"`
		Targets               []any                   `json:"targets"`
		Stopped               []any                   `json:"stopped"`
	}
	// This test inspects the evidence without constructing a stopped receipt.
	if err := protocol.DecodeTolerant(owner.Payload, &ownerData, protocol.DefaultMaxJSONBytes); err != nil {
		t.Fatal(err)
	}
	if ownerData.WorkloadGenesisSHA256 != target.Genesis.Fingerprint() || ownerData.Genesis != target.Genesis.Origin() || len(ownerData.Targets) != 0 || len(ownerData.Stopped) != 0 {
		t.Fatal("prospective owner substituted native inventory or stopped receipts for the full root origin")
	}
	if err := session.hosts.ClaimGenesisContainer(ctx, target.Genesis, guard); err != nil {
		t.Fatal(err)
	}
	replayedOwner, err := fencer.ReadHostMutation(ctx, authority.MutationRuntimeOwner, ownerKey)
	if err != nil || replayedOwner.Sequence != owner.Sequence || !bytes.Equal(replayedOwner.Payload, owner.Payload) {
		t.Fatal("identical genesis replay rewrote permanent owner", err)
	}
	native := host.Desired{Cell: "gru", Node: session.registration.Node, Environment: target.Environment, Role: target.Role, Digest: strings.Repeat("a", 64), Generation: 1, AuthorityEpoch: fencer.Current().Epoch}
	if _, err := session.hosts.ApplyDesired(ctx, native); err == nil {
		t.Fatal("prospective owner allowed the first native admission")
	}
	if desired, err := session.hosts.ListDesired(ctx, target.Role); err != nil || len(desired) != 0 {
		t.Fatal("genesis manufactured native desired history", err)
	}
	select {
	case <-session.nativeRunner.stopEntered:
		t.Fatal("prospective owner fabricated a native stop")
	default:
	}
	config := genericRuntimeNodeConfig(t, "genesis-manager", "manager")
	config.Admission.FounderID = config.Admission.HostID
	manager, err := swarmruntime.StartNode(ctx, config, executor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if err := manager.Stop(stopCtx); err != nil {
			t.Errorf("stop genesis manager: %v", err)
		}
	})
	executor.mu.Lock()
	executor.nodeID = manager.ID()
	executor.mu.Unlock()
	client, err := manager.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := swarmruntime.AdmitNode(ctx, client, manager.ID(), config.Admission); err != nil {
		t.Fatal(err)
	}
	first, evidence := genericGenesisContainer(t, signer, target, 1)
	verified, err := release.VerifyContainerCurrent(ctx, first, signer.roots, target, time.Now().UTC(), time.Now().UTC().Add(time.Minute), evidence, signer.allocations)
	if err != nil {
		t.Fatal(err)
	}
	ownerGuard, err := session.hosts.HandoffGenesisToContainer(ctx, verified, guard)
	if err != nil {
		t.Fatal(err)
	}
	intent := swarmruntime.ServiceIntent{ID: entityid.Derive("genesis-service", target.Role), OperationID: entityid.New(), Role: target.Role, Region: "sa-saopaulo-1", Environment: target.Environment, Architecture: target.Architecture, Replicas: 1, Generation: 1, Container: &api.ContainerSpec{Image: verified.Claim().Image, User: "65532:65532"}, Resources: &api.ResourceRequirements{Reservations: &api.Resources{NanoCPUs: 100_000_000, MemoryBytes: 32 << 20, Generic: []*api.GenericResource{genericresource.NewDiscrete(swarmruntime.DiskResource, 64<<20)}}, Limits: &api.Resources{NanoCPUs: 100_000_000, MemoryBytes: 32 << 20, Generic: []*api.GenericResource{genericresource.NewDiscrete(swarmruntime.DiskResource, 64<<20)}}}}
	probe := func(check context.Context, task *api.Task) error {
		if err := session.verify(check); err != nil {
			return err
		}
		node, err := client.GetNode(check, &api.GetNodeRequest{NodeID: task.NodeID})
		if err != nil {
			return err
		}
		if node.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != config.Admission.InstanceID || task.NodeID != manager.ID() {
			return errors.New("task recipient differs from admitted manager")
		}
		return check.Err()
	}
	crash := &genericGenesisServiceCrash{ControlClient: client}
	if _, err := swarmruntime.ApplySignedService(ctx, crash, intent, first, signer.roots, release.SequenceFloor{}, evidence, probe, signer.allocations, ownerGuard); !errors.Is(err, errGenericGenesisCrash) {
		t.Fatalf("first service effect did not stop after durable witness: %v", err)
	}
	floor, found, err := swarmruntime.ReadServiceReleaseFloor(ctx, client, intent, verified, signer.roots)
	if err != nil || !found || floor.ReleaseSequence != 1 {
		t.Fatalf("crash lost the reserved first genesis floor: %+v %v", floor, err)
	}
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil || len(listed.Services) != 0 {
		t.Fatal("service effect preceded the injected post-witness crash", err)
	}
	configs, err := client.ListConfigs(ctx, &api.ListConfigsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var witness *api.Config
	for _, record := range configs.Configs {
		if strings.HasPrefix(record.Spec.Annotations.Name, "ts-release-origin-") {
			witness = record
		}
	}
	if witness == nil || !bytes.Contains(witness.Spec.Data, []byte(target.Genesis.Fingerprint())) {
		t.Fatal("no durable original-origin witness preceded service effects")
	}
	var witnessData struct {
		Schema                string                  `json:"schema"`
		WorkloadGenesisSHA256 string                  `json:"workload_genesis_sha256"`
		Origin                release.WorkloadGenesis `json:"origin"`
		FloorID               string                  `json:"floor_id"`
		FloorName             string                  `json:"floor_name"`
		ServiceID             string                  `json:"service_id"`
		Architecture          string                  `json:"architecture,omitempty"`
	}
	if err := protocol.DecodeStrict(witness.Spec.Data, &witnessData, protocol.DefaultMaxJSONBytes); err != nil {
		t.Fatal(err)
	}
	var witnessedFloor *api.Config
	for _, record := range configs.Configs {
		if record.ID == witnessData.FloorID {
			witnessedFloor = record
		}
	}
	if witnessedFloor == nil || witnessedFloor.Spec.Annotations.Name != witnessData.FloorName || witnessData.Origin != target.Genesis.Origin() || witnessData.ServiceID != intent.ID || witnessData.WorkloadGenesisSHA256 != target.Genesis.Fingerprint() {
		t.Fatal("first-use witness did not pin the exact persisted floor and original scope")
	}

	restoredHosts, err := host.NewController(ctx, session.controllerConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoredHosts.GuardContainerOwner(ctx, target.Environment, target.Role); err != nil {
		t.Fatal("controller replacement lost original owner", err)
	}
	if _, err := restoredHosts.ApplyDesired(ctx, native); err == nil {
		t.Fatal("controller replacement reopened native admission")
	}
	stopCtx, stop := context.WithTimeout(ctx, 15*time.Second)
	err = manager.Stop(stopCtx)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := swarmruntime.StartNode(ctx, config, executor)
	if err != nil {
		t.Fatal(err)
	}
	manager = replacement
	client, err = manager.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	executor.mu.Lock()
	executor.nodeID = manager.ID()
	executor.mu.Unlock()
	resumedFloor, found, err := swarmruntime.ReadServiceReleaseFloor(ctx, client, intent, verified, signer.roots)
	if err != nil || !found || resumedFloor != floor {
		t.Fatal("actual manager restart lost the original reserved floor", err)
	}
	ownerGuard, err = restoredHosts.HandoffGenesisToContainer(ctx, verified, guard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := swarmruntime.ApplySignedService(ctx, client, intent, first, signer.roots, release.SequenceFloor{}, evidence, probe, signer.allocations, ownerGuard); err != nil {
		t.Fatal("resume genuine first genesis sequence", err)
	}
	second, secondEvidence := genericGenesisContainer(t, signer, target, 2)
	next := intent
	next.Generation = 2
	next.OperationID = entityid.New()
	nextProof, err := release.VerifyContainerCurrent(ctx, second, signer.roots, target, time.Now().UTC(), time.Now().UTC().Add(time.Minute), secondEvidence, signer.allocations)
	if err != nil {
		t.Fatal(err)
	}
	next.Container = &api.ContainerSpec{Image: nextProof.Claim().Image, User: "65532:65532"}
	if _, err := swarmruntime.ApplySignedService(ctx, client, next, second, signer.roots, release.SequenceFloor{}, secondEvidence, probe, signer.allocations, ownerGuard); err != nil {
		t.Fatal("advance genuine genesis sequence", err)
	}
	before, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil || len(before.Services) != 1 {
		t.Fatal("expected one actual generic service", err)
	}
	if _, err := swarmruntime.ApplySignedService(ctx, client, intent, first, signer.roots, release.SequenceFloor{}, evidence, probe, signer.allocations, ownerGuard); err == nil {
		t.Fatal("old sequence replay bypassed the durable floor")
	}
	equivocation := second
	envelope, err := trust.DecodeEnvelope(second.Claim)
	if err != nil {
		t.Fatal(err)
	}
	var claim release.ContainerClaim
	if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
		t.Fatal(err)
	}
	claim.SourceTreeSHA256 = strings.Repeat("f", 64)
	equivocation.Claim = genericGenesisSign(t, claim, envelope.Scope, signer.leaf)
	if _, err := release.VerifyContainerCurrent(ctx, equivocation, signer.roots, target, time.Now().UTC(), time.Now().UTC().Add(time.Minute), secondEvidence, signer.allocations); err == nil {
		t.Fatal("equivocating release reused the genuine allocated sequence")
	}
	if _, err := swarmruntime.ApplySignedService(ctx, client, next, equivocation, signer.roots, release.SequenceFloor{}, secondEvidence, probe, signer.allocations, ownerGuard); err == nil {
		t.Fatal("equivocation mutated persistent generic service")
	}
	configs, err = client.ListConfigs(ctx, &api.ListConfigsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var retained *api.Config
	for _, record := range configs.Configs {
		if record.Spec.Annotations.Labels["terrascale.release-genesis"] == target.Genesis.Fingerprint() {
			retained = record
		}
	}
	if retained == nil {
		t.Fatal("no established genesis floor")
	}
	corrupt := retained.Spec.Copy()
	corrupt.Annotations.Labels["terrascale.release-genesis"] = strings.Repeat("0", 64)
	if _, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: retained.ID, ConfigVersion: &retained.Meta.Version, Spec: corrupt}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := swarmruntime.ReadServiceReleaseFloor(ctx, client, next, nextProof, signer.roots); err == nil {
		t.Fatal("corrupt established genesis floor was accepted")
	}
	if _, err := swarmruntime.ApplySignedService(ctx, client, next, second, signer.roots, release.SequenceFloor{}, secondEvidence, probe, signer.allocations, ownerGuard); err == nil {
		t.Fatal("corrupt floor allowed generic service effects")
	}
	if _, err := client.RemoveConfig(ctx, &api.RemoveConfigRequest{ConfigID: retained.ID}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := swarmruntime.ReadServiceReleaseFloor(ctx, client, next, nextProof, signer.roots); err == nil {
		t.Fatal("retained original witness allowed missing established floor")
	}
	if _, err := swarmruntime.ApplySignedService(ctx, client, next, second, signer.roots, release.SequenceFloor{}, secondEvidence, probe, signer.allocations, ownerGuard); err == nil {
		t.Fatal("missing established floor was silently recreated")
	}
	after, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: before.Services[0].ID})
	if err != nil || after.Service.Meta.Version != before.Services[0].Meta.Version {
		t.Fatal("rejected replay/equivocation/corrupt/missing floor changed actual service", err)
	}
}

var errGenericGenesisCrash = errors.New("injected crash after durable genesis witness before service effect")

type genericGenesisServiceCrash struct{ api.ControlClient }

func (client *genericGenesisServiceCrash) CreateService(context.Context, *api.CreateServiceRequest, ...grpc.CallOption) (*api.CreateServiceResponse, error) {
	return nil, errGenericGenesisCrash
}

func genericGenesisSign(t *testing.T, value any, scope trust.Scope, key ed25519.PrivateKey) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	payload, err := trust.EncodePayload(value)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, scope, now.Add(-time.Second), now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func genericGenesisOriginal(t *testing.T, signer *functionPublicationSigner) (release.ContainerTarget, []release.WorkloadGenesis, []byte, trust.Scope) {
	t.Helper()
	return genericGenesisOriginalRole(t, signer, "ts-auth")
}

func genericGenesisOriginalRole(t *testing.T, signer *functionPublicationSigner, selectedRole string) (release.ContainerTarget, []release.WorkloadGenesis, []byte, trust.Scope) {
	t.Helper()
	if selectedRole != "ts-auth" && selectedRole != "function-worker" {
		t.Fatal("generic genesis fixture requires an allowed generic role")
	}
	installation := entityid.Derive("generic-genesis-installation")
	var origins []release.WorkloadGenesis
	var regions []any
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
		deployment, cluster := entityid.Derive("generic-genesis-deployment", cell), entityid.Derive("generic-genesis-cluster", cell)
		regions = append(regions, map[string]any{"plan": map[string]any{"cell": cell}, "bootstrapMaterial": map[string]any{"installationId": installation, "config": map[string]any{"deploymentId": deployment, "clusterId": cluster, "cell": strings.ToLower(cell), "environment": "production"}}})
		for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
			origins = append(origins, release.WorkloadGenesis{Schema: release.WorkloadGenesisSchema, TenancyID: "ocid1.tenancy.oc1..genericgenesis", InstallationID: installation, DeploymentID: deployment, ClusterID: cluster, Cell: cell, Environment: "production", Role: role, Namespace: signer.allocations.Namespace, Bucket: signer.allocations.Bucket})
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	public := signer.leaf.Public().(ed25519.PublicKey)
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	var authorities []any
	for _, role := range []string{"terrabase", "ts-auth", "function-worker"} {
		var capabilities []trust.Capability
		for _, cell := range []string{"GRU", "SJC", "FRA"} {
			scope := release.ContainerScope(release.ContainerTarget{Cell: cell, Environment: "production", Role: role, Architecture: runtime.GOARCH})
			capabilities = append(capabilities, trust.Capability{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: role, Slots: []string{"linux-amd64", "linux-arm64"}, Actions: []string{"sign"}})
		}
		delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded, Capabilities: capabilities}, now.Add(-time.Minute), now.Add(2*time.Hour), signer.root)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(delegation)
		if err != nil {
			t.Fatal(err)
		}
		authorities = append(authorities, map[string]any{"role": role, "environment": "production", "cells": []string{"GRU", "SJC", "FRA"}, "architectures": []string{"amd64", "arm64"}, "delegationWire": wire})
		if role == selectedRole {
			signer.delegation = delegation
		}
	}
	scope := trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: origins[0].DeploymentID, Cell: "GRU", Environment: "production", Role: "foundation", Slot: origins[0].ClusterID}
	wire := genericGenesisSign(t, map[string]any{"schemaVersion": 3, "generation": 1, "tenancyId": origins[0].TenancyID, "installationId": installation, "cleanupOwner": "generic-genesis-fixture", "regions": regions, "workloadGenesis": origins, "releaseAuthorities": authorities}, scope, signer.root)
	selected := origins[1]
	if selectedRole == "function-worker" {
		selected = origins[2]
	}
	proof, err := release.VerifyWorkloadGenesis(wire, signer.roots, scope, selected)
	if err != nil {
		t.Fatal(err)
	}
	signer.allocations.Genesis, signer.allocations.Delegation = proof, signer.delegation
	target := release.ContainerTarget{Cell: "GRU", Environment: "production", Role: selectedRole, Architecture: runtime.GOARCH, Genesis: proof}
	return target, origins, wire, scope
}

func genericGenesisContainer(t *testing.T, signer functionPublicationSigner, target release.ContainerTarget, sequence uint64) (release.ContainerBundle, func(context.Context, string) (io.ReadCloser, error)) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	scope := release.ContainerScope(target)
	delegationWire, err := trust.EncodeEnvelope(signer.delegation)
	if err != nil {
		t.Fatal(err)
	}
	evidence := []byte("retained local manager integration qualification evidence")
	evidenceSHA := sha256.Sum256(evidence)
	nativeSHA := sha256.Sum256(fmt.Appendf(nil, "local native image generation %d", sequence))
	nativeDigest := hex.EncodeToString(nativeSHA[:])
	index := fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":42,"platform":{"os":"linux","architecture":%q}}]}`, "sha256:"+nativeDigest, target.Architecture)
	indexDigest := sha256.Sum256(index)
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: release.ProductionExpectation{
		SourceRevision: fmt.Sprintf("%040x", sequence), ArtifactSHA256: nativeDigest, QualificationSHA256: hex.EncodeToString(indexDigest[:]), Cell: target.Cell,
		Environment: target.Environment, Runtime: release.ProductionRuntime, Architecture: target.Architecture, Role: target.Role}}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: hex.EncodeToString(evidenceSHA[:]), Bytes: int64(len(evidence)), CompletedAt: now})
	}
	sign := func(value any, scope trust.Scope, key ed25519.PrivateKey) []byte {
		t.Helper()
		payload, err := trust.EncodePayload(value)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, scope, now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	claim := release.ContainerClaim{Schema: release.ContainerGenesisClaimSchema, Image: "example.invalid/api@sha256:" + nativeDigest,
		SourceRepository: "https://example.invalid/api", SourceRevision: qualification.Candidate.SourceRevision, SourceTreeSHA256: strings.Repeat("e", 64),
		Cell: target.Cell, Environment: target.Environment, Role: target.Role, Architecture: target.Architecture, ReleaseSequence: sequence,
		WorkloadGenesisSHA256: target.Genesis.Fingerprint(), QualificationSHA256: qualification.Candidate.QualificationSHA256,
		Production: release.ProductionProof{Qualification: sign(qualification, release.ProductionQualificationScope(qualification.Candidate), signer.root)}}
	if err := signer.allocations.ImportGenesis(t.Context(), signer.roots, target.Role, target.Environment, now); err != nil {
		t.Fatal(err)
	}
	family, err := claim.WorkerFamilyDigest()
	if err != nil {
		t.Fatal(err)
	}
	allocated, sequenceWire, err := signer.allocations.AllocateWithEvidence(t.Context(), release.SequenceIdentity{Role: target.Role, Environment: target.Environment,
		SourceRevision: claim.SourceRevision, ManifestSHA256: family}, signer.roots, signer.leaf)
	if err != nil || allocated != claim.ReleaseSequence {
		t.Fatalf("allocate authentic shared sequence: got %d, want %d: %v", allocated, claim.ReleaseSequence, err)
	}
	return release.ContainerBundle{Claim: sign(claim, scope, signer.leaf), Delegation: delegationWire, Sequence: sequenceWire, Index: index},
		func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(evidence)), nil
		}
}
