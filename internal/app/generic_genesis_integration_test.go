package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
	"github.com/nats-io/nats.go/jetstream"
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
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
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
		for _, cell := range []string{"GRU", "SFO", "FRA"} {
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
		authorities = append(authorities, map[string]any{"role": role, "environment": "production", "cells": []string{"GRU", "SFO", "FRA"}, "architectures": []string{"amd64", "arm64"}, "delegationWire": wire})
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

// This exercises the app wrapper and real protected stores, not the production
// OCI discovery/recipient adapters, physical execution or the identity installer.
func TestGenericGenesisApplyRestartAndIdentityResetIntegration(t *testing.T) {
	for _, role := range []string{"ts-auth", "function-worker"} {
		t.Run(role, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 240*time.Second)
			defer cancel()
			signer := newFunctionPublicationSigner(t)
			target, _, original, scope := genericGenesisOriginalRole(t, &signer, role)
			auth := newAuthenticatedNATS(t, "gru")
			broker, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = broker.Close() })
			identity := cellspec.Identity{DeploymentID: target.Genesis.Origin().DeploymentID, Cell: "gru", Environment: target.Environment}
			fencer, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: identity.DeploymentID, Scope: identity.Cell, CandidateID: entityid.New(), Replicas: 1})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = fencer.Close() })
			executor := &genericRuntimeExecutor{controllers: map[string]*genericRuntimeTask{}}
			session, stopHosts := startGenericGenesisOwnedSession(t, ctx, auth, broker, fencer, target, original, scope, signer.roots, executor)
			ownerKey := identity.Cell + "." + identity.Environment + "." + role
			owner, err := fencer.ReadHostMutation(ctx, authority.MutationRuntimeOwner, ownerKey)
			if err != nil || owner.Sequence == 0 {
				t.Fatal("missing prospective owner before app apply", err)
			}
			assertOwner := func(reader *authority.Runtime) {
				t.Helper()
				current, err := reader.ReadHostMutation(ctx, authority.MutationRuntimeOwner, ownerKey)
				if err != nil || current.Sequence != owner.Sequence || current.Epoch != owner.Epoch || current.OperationID != owner.OperationID || !bytes.Equal(current.Payload, owner.Payload) {
					t.Fatal("app apply, restart or reset changed permanent genesis owner", err)
				}
			}
			keys := newTestSpecTrustWithRoot(t, t.TempDir(), identity, signer.root)
			specs := &specRegistry{cell: identity.Cell, identity: identity, fixed: map[string]WorkloadProfile{}, signedArtifactStore: delivery.DefaultArtifactStoreMaxBytes}
			if err := specs.openRoots(signer.roots, trust.RootChain{Version: 1}, ""); err != nil {
				t.Fatal(err)
			}
			specs.kv, err = broker.JetStream().CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: cellSpecBucket, History: 4, Storage: jetstream.FileStorage, Replicas: 1})
			if err != nil {
				t.Fatal(err)
			}
			profile := WorkloadProfile{Resources: placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 1 << 30}}
			policy := workload.ServiceSpec{Role: role, Environment: identity.Environment, Kind: workload.KindStateless,
				Replicas: workload.ReplicaBounds{Min: 1, Max: 2}, Scaling: &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.5}}}}
			profileWire, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: 1, RequiresBinary: cellspec.BinaryLevel,
				Services: []cellspec.Service{{Role: role, Profile: profile, Spec: &policy}}}, nil, keys.roots, time.Now(), time.Hour, keys.root)
			if err != nil {
				t.Fatal(err)
			}
			adoptProfile := func() {
				t.Helper()
				if _, err := specs.kv.Put(ctx, cellSpecKey, profileWire); err != nil {
					t.Fatal(err)
				}
				entry, err := specs.kv.Get(ctx, cellSpecKey)
				if err != nil {
					t.Fatal(err)
				}
				if err := specs.load(entry); err != nil {
					t.Fatal(err)
				}
			}
			adoptProfile()
			archiveKV, err := openNativeHistory(ctx, broker.JetStream(), 1)
			if err != nil {
				t.Fatal(err)
			}
			archive := &nativeHistory{kv: archiveKV, js: broker.JetStream(), services: specs, fencer: fencer}
			config := genericRuntimeNodeConfig(t, "genesis-apply-manager", "manager")
			config.Admission.FounderID = config.Admission.HostID
			manager, err := swarmruntime.StartNode(ctx, config, executor)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				stopCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
				defer stop()
				if err := manager.Stop(stopCtx); err != nil {
					t.Errorf("stop genesis apply manager: %v", err)
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
			currentBundle := first
			keyID, err := protocol.KeyID(signer.leaf.Public().(ed25519.PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			codec := delivery.Ed25519Codec{Cell: identity.Cell, Actor: "release", PrivateKey: signer.leaf, Lifetime: time.Minute, MaxLifetime: time.Minute,
				Trusted: map[string]delivery.TrustedSigner{keyID: {Actor: "release", PublicKey: signer.leaf.Public().(ed25519.PublicKey)}}}
			var controller *genericRuntime
			applied := make(chan error, 1)
			deliveries, err := delivery.Open(ctx, delivery.Config{Conn: broker.Conn(), JS: broker.JetStream(), Cell: identity.Cell, Replicas: 1,
				Signer: codec, Verifier: codec, Fencer: fencer, Writer: new(genericRuntimeLegacyWriter), CaptureContainerProfile: archive.CaptureContainerProfile,
				Authorize: func(_ context.Context, actor string, intent delivery.Intent) error {
					if actor != "release" || intent.Cell != identity.Cell || intent.Role != role || intent.Environment != identity.Environment {
						return delivery.ErrUnauthorized
					}
					return nil
				}, ContainerApply: func(check context.Context, intent delivery.Intent) error {
					err := controller.apply(check, intent)
					select {
					case applied <- err:
					default:
					}
					return err
				}})
			if err != nil {
				t.Fatal(err)
			}
			archive.deliveries = deliveries
			readTarget := target
			readTarget.Genesis = release.VerifiedWorkloadGenesis{}
			runtimeConfig := genericRuntimeConfig{Client: &genericGenesisServiceCrash{ControlClient: client}, ManagerID: manager.ID(), Authority: fencer, Specs: specs,
				Delivery: deliveries, OriginalProfile: archive.originalContainerProfile, Hosts: session.hosts, SessionGuard: session.verify,
				RetainedFloor: func(context.Context, string, string) (release.SequenceFloor, error) {
					return release.SequenceFloor{}, errors.New("genesis must not borrow a native release floor")
				},
				CurrentBundle: func(check context.Context, requestedRole, architecture string) (release.ContainerBundle, time.Time, error) {
					if requestedRole != role || architecture != target.Architecture {
						return release.ContainerBundle{}, time.Time{}, delivery.ErrUnauthorized
					}
					deadline, _ := check.Deadline()
					return currentBundle, deadline, check.Err()
				}, Allocations: func(check context.Context, operation string, requested release.ContainerBundle, roots trust.Keyring, requestedTarget release.ContainerTarget) (release.SequenceLocation, error) {
					current, err := deliveries.ContainerIntent(check, operation)
					if err != nil {
						return release.SequenceLocation{}, err
					}
					if requestedTarget != readTarget || current.Container == nil || current.Role != role || current.Environment != identity.Environment {
						return release.SequenceLocation{}, delivery.ErrUnauthorized
					}
					actual, err := release.ContainerBundleSHA256(*current.Container)
					wanted, wantedErr := release.ContainerBundleSHA256(requested)
					if err != nil || wantedErr != nil || actual != wanted {
						return release.SequenceLocation{}, delivery.ErrUnauthorized
					}
					genesis, err := release.VerifyWorkloadGenesis(original, roots, scope, target.Genesis.Origin())
					if err != nil {
						return release.SequenceLocation{}, err
					}
					requestedTarget.Genesis = genesis
					return currentContainerAllocations(check, signer.factory, requested, roots, requestedTarget)
				}, Evidence: func(check context.Context, operation, digest string) (io.ReadCloser, error) {
					if _, err := deliveries.ContainerIntent(check, operation); err != nil {
						return nil, err
					}
					return evidence(check, digest)
				}, Probe: func(check context.Context, task *api.Task) error {
					if err := session.verify(check); err != nil {
						return err
					}
					node, err := client.GetNode(check, &api.GetNodeRequest{NodeID: task.NodeID})
					if err != nil {
						return err
					}
					if task.NodeID != manager.ID() || node.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != config.Admission.InstanceID {
						return errors.New("simulated probe recipient differs from admitted manager")
					}
					return check.Err()
				}}
			controller, err = newGenericRuntime(runtimeConfig, autoscale.NewWindowStore(0, 0))
			if err != nil {
				t.Fatal(err)
			}
			runIntent := func(intent delivery.Intent) error {
				t.Helper()
				select {
				case <-applied:
				default:
				}
				runCtx, stop := context.WithCancel(ctx)
				done := make(chan error, 1)
				go func() { done <- deliveries.Run(runCtx) }()
				defer func() {
					stop()
					if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
						t.Errorf("stop genesis delivery: %v", err)
					}
				}()
				if err := deliveries.Submit(ctx, intent); err != nil {
					t.Fatal(err)
				}
				select {
				case result := <-applied:
					if result == nil {
						genericRuntimeEventually(t, ctx, func() bool {
							receipt, err := deliveries.StatusFor(ctx, intent)
							return err == nil && receipt.Status == "accepted"
						})
					}
					return result
				case <-ctx.Done():
					t.Fatal("actual app apply did not complete", ctx.Err())
					return ctx.Err()
				}
			}
			submit := func(bundle release.ContainerBundle, sequence uint64) (delivery.Intent, error) {
				t.Helper()
				verified, err := release.VerifyContainerCurrent(ctx, bundle, signer.roots, target, time.Now().UTC(), time.Now().UTC().Add(time.Minute), evidence, signer.allocations)
				if err != nil {
					t.Fatal(err)
				}
				claim := verified.Claim()
				intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.New(), Cell: identity.Cell, Environment: identity.Environment, Role: role,
					Source: delivery.ArtifactSource{Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256}, Generation: sequence, DesiredReplicas: 1,
					ConfigDigest: delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets), AuthorityEpoch: fencer.Current().Epoch, Container: new(bundle)}
				return intent, runIntent(intent)
			}
			firstIntent, err := submit(first, 1)
			if !errors.Is(err, errGenericGenesisCrash) {
				t.Fatalf("actual apply did not reach post-witness crash: %v", err)
			}
			firstProof, err := release.VerifyContainerCurrent(ctx, first, signer.roots, target, time.Now().UTC(), time.Now().UTC().Add(time.Minute), evidence, signer.allocations)
			if err != nil {
				t.Fatal(err)
			}
			expectedProof, err := containermaterial.VerifyProfile(profileWire, signer.roots, identity, firstIntent)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := containermaterial.ServiceIntent(expectedProof, target.Architecture)
			if err != nil {
				t.Fatal(err)
			}
			floor, found, err := swarmruntime.ReadServiceReleaseFloor(ctx, client, expected, firstProof, signer.roots)
			if err != nil || !found || floor.ReleaseSequence != 1 {
				t.Fatal("actual apply lost durable first floor", err)
			}
			if services, err := client.ListServices(ctx, &api.ListServicesRequest{}); err != nil || len(services.Services) != 0 {
				t.Fatal("service effect preceded durable-witness crash", err)
			}
			firstRecords := genericGenesisReleaseRecords(t, ctx, client)
			assertOwner(fencer)
			restartManager := func() {
				t.Helper()
				stopCtx, stop := context.WithTimeout(ctx, 15*time.Second)
				err := manager.Stop(stopCtx)
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
			}
			restartManager()
			genericGenesisAssertReleaseRecords(t, ctx, client, firstRecords)
			restoredHosts, err := host.NewController(ctx, session.controllerConfig)
			if err != nil {
				t.Fatal(err)
			}
			runtimeConfig.Client, runtimeConfig.ManagerID, runtimeConfig.Hosts = client, manager.ID(), restoredHosts
			controller, err = newGenericRuntime(runtimeConfig, autoscale.NewWindowStore(0, 0))
			if err != nil {
				t.Fatal(err)
			}
			// A signed profile written but not adopted is not current app authority.
			if _, err := specs.kv.Put(ctx, cellSpecKey, profileWire); err != nil {
				t.Fatal(err)
			}
			if err := controller.apply(ctx, firstIntent); !errors.Is(err, containermaterial.ErrPending) {
				t.Fatal("unadopted signed profile acquired app authority", err)
			}
			genericGenesisAssertReleaseRecords(t, ctx, client, firstRecords)
			if services, err := client.ListServices(ctx, &api.ListServicesRequest{}); err != nil || len(services.Services) != 0 {
				t.Fatal("unadopted signed profile created service", err)
			}
			adoptProfile()
			foreign := newFunctionPublicationSigner(t)
			if err := specs.openRoots(foreign.roots, trust.RootChain{Version: 1}, ""); err != nil {
				t.Fatal(err)
			}
			if err := controller.apply(ctx, firstIntent); err == nil {
				t.Fatal("current foreign root acquired original profile/release authority")
			}
			genericGenesisAssertReleaseRecords(t, ctx, client, firstRecords)
			if services, err := client.ListServices(ctx, &api.ListServicesRequest{}); err != nil || len(services.Services) != 0 {
				t.Fatal("foreign current root created service", err)
			}
			if err := specs.openRoots(signer.roots, trust.RootChain{Version: 1}, ""); err != nil {
				t.Fatal(err)
			}
			if err := controller.apply(ctx, firstIntent); err != nil {
				t.Fatal("actual apply could not resume first protected operation", err)
			}
			if err := runIntent(firstIntent); err != nil {
				t.Fatal("resumed protected delivery did not settle", err)
			}
			second, secondEvidence := genericGenesisContainer(t, signer, target, 2)
			currentBundle, evidence = second, secondEvidence
			secondIntent, err := submit(second, 2)
			if err != nil {
				t.Fatal("actual apply could not advance genesis release", err)
			}
			secondProof, err := release.VerifyContainerCurrent(ctx, second, signer.roots, target, time.Now().UTC(), time.Now().UTC().Add(time.Minute), evidence, signer.allocations)
			if err != nil {
				t.Fatal(err)
			}
			latest, found, err := swarmruntime.ReadServiceReleaseFloor(ctx, client, expected, secondProof, signer.roots)
			if err != nil || !found || latest.ReleaseSequence != 2 {
				t.Fatal("actual app wrapper did not retain latest release floor", err)
			}
			latestRecords := genericGenesisReleaseRecords(t, ctx, client)
			if err := controller.apply(ctx, firstIntent); err == nil {
				t.Fatal("old protected operation bypassed current channel/latest floor")
			}
			genericGenesisAssertReleaseRecords(t, ctx, client, latestRecords)
			assertOwner(fencer)
			if err := controller.apply(ctx, secondIntent); err != nil {
				t.Fatal("current app operation lost idempotence", err)
			}
			if desired, err := session.hosts.ListDesired(ctx, role); err != nil || len(desired) != 0 {
				t.Fatal("app wrapper manufactured native desired", err)
			}
			if native, err := session.nativeRunner.Observe(ctx, role); err != nil || native.Running {
				t.Fatal("prospective owner allowed simulated native execution", err)
			}
			select {
			case <-session.nativeRunner.stopEntered:
				t.Fatal("app wrapper fabricated a native stop receipt")
			default:
			}
			stopHosts()
			epoch := fencer.Current().Epoch
			if err := fencer.Close(); err != nil {
				t.Fatal(err)
			}
			reset, resetTarget := genericGenesisIdentityReset(t, ctx, broker.JetStream(), signer, identity, epoch)
			if completion, err := authority.IdentityResetCompletion(ctx, broker.JetStream(), reset, signer.roots, resetTarget, time.Now()); err != nil || completion == 0 {
				t.Fatal("typed reset did not complete", err)
			}
			replacementFencer, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: resetTarget.DeploymentID, Scope: identity.Cell, CandidateID: entityid.New(), Replicas: 1})
			if err != nil {
				t.Fatal(err)
			}
			fencer = replacementFencer
			assertOwner(fencer)
			resetHostsConfig := session.controllerConfig
			resetHostsConfig.HostMutations, resetHostsConfig.AuthorityGuard = fencer, fencer.Guard
			resetHostsConfig.AuthorityEpoch = func() uint64 { return fencer.Current().Epoch }
			resetHosts, err := host.NewController(ctx, resetHostsConfig)
			if err != nil {
				t.Fatal(err)
			}
			if err := resetHosts.GuardContainerOwner(ctx, identity.Environment, role); err != nil {
				t.Fatal("actual typed reset erased prospective owner", err)
			}
			native := host.Desired{Cell: identity.Cell, Node: session.registration.Node, Environment: identity.Environment, Role: role, Digest: strings.Repeat("a", 64), Generation: 1, AuthorityEpoch: fencer.Current().Epoch}
			if _, err := resetHosts.ApplyDesired(ctx, native); err == nil {
				t.Fatal("typed reset reopened native admission")
			}
			restartManager()
			genericGenesisAssertReleaseRecords(t, ctx, client, latestRecords)
			after, found, err := swarmruntime.ReadServiceReleaseFloor(ctx, client, expected, secondProof, signer.roots)
			if err != nil || !found || after != latest {
				t.Fatal("typed reset or second actual restart lost latest floor", err)
			}
		})
	}
}

func genericGenesisReleaseRecords(t *testing.T, ctx context.Context, client api.ControlClient) map[string]*api.Config {
	t.Helper()
	listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]*api.Config{}
	var floors, witnesses int
	for _, record := range listed.Configs {
		name := record.Spec.Annotations.Name
		if strings.HasPrefix(name, "ts-release-origin-") {
			witnesses++
			records[record.ID] = record
		} else if strings.HasPrefix(name, "ts-release-") {
			floors++
			records[record.ID] = record
		}
	}
	if witnesses != 1 || floors != 1 {
		t.Fatalf("expected one persisted floor and origin witness, found floors=%d witnesses=%d", floors, witnesses)
	}
	return records
}

func genericGenesisAssertReleaseRecords(t *testing.T, ctx context.Context, client api.ControlClient, expected map[string]*api.Config) {
	t.Helper()
	current := genericGenesisReleaseRecords(t, ctx, client)
	if len(current) != len(expected) {
		t.Fatal("restart/reset changed release record count")
	}
	for id, record := range expected {
		if !proto.Equal(current[id], record) {
			t.Fatalf("restart/reset changed exact release record %s", id)
		}
	}
}

// Own the top-level loops so the prospective owner precedes native recovery;
// stop them and close their fencer before the actual typed reset.
func startGenericGenesisOwnedSession(t *testing.T, ctx context.Context, auth *authenticatedNATS, broker *natscell.Runtime,
	fencer *authority.Runtime, target release.ContainerTarget, original []byte, scope trust.Scope, roots trust.Keyring, executor *genericRuntimeExecutor,
) (*genericRuntimeHostSession, func()) {
	t.Helper()
	responsePublic, responseKey := testEd25519(t, t.TempDir(), "genesis-response.key")
	public, private := testEd25519(t, t.TempDir(), "genesis-host.key")
	nkey, seed := testNKey(t)
	artifacts, err := broker.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	controllerConfig := host.ControllerConfig{Cell: "gru", Conn: broker.Conn(), JS: broker.JetStream(), Artifacts: artifacts, StateReplicas: 1,
		ResponseKey: responseKey, HostMutations: fencer, AuthorityEpoch: func() uint64 { return fencer.Current().Epoch }, AuthorityGuard: fencer.Guard,
		TaskLoadRoles: func(check context.Context, _ host.Registration) ([]string, error) {
			loads, err := executor.ReadTaskLoad(check)
			if err != nil {
				return nil, err
			}
			var roles []string
			for _, load := range loads {
				roles = append(roles, load.Role)
			}
			return roles, nil
		}}
	hosts, err := host.NewController(ctx, controllerConfig)
	if err != nil {
		t.Fatal(err)
	}
	guard := func(check context.Context) error {
		current, err := release.VerifyWorkloadGenesis(original, roots, scope, target.Genesis.Origin())
		if err != nil {
			return err
		}
		if current.Fingerprint() != target.Genesis.Fingerprint() {
			return errors.New("original root genesis changed")
		}
		return fencer.Guard(check, fencer.Current().Epoch)
	}
	if err := hosts.ClaimGenesisContainer(ctx, target.Genesis, guard); err != nil {
		t.Fatal(err)
	}
	owner, err := fencer.ReadHostMutation(ctx, authority.MutationRuntimeOwner, "gru."+target.Environment+"."+target.Role)
	if err != nil || owner.Sequence == 0 {
		t.Fatal("owner was not retained before host loops", err)
	}
	var provenance struct {
		WorkloadGenesisSHA256 string                  `json:"workload_genesis_sha256"`
		Genesis               release.WorkloadGenesis `json:"genesis"`
		Targets               []any                   `json:"targets"`
		Stopped               []any                   `json:"stopped"`
	}
	if err := protocol.DecodeTolerant(owner.Payload, &provenance, protocol.DefaultMaxJSONBytes); err != nil {
		t.Fatal(err)
	}
	if provenance.WorkloadGenesisSHA256 != target.Genesis.Fingerprint() || provenance.Genesis != target.Genesis.Origin() || len(provenance.Targets) != 0 || len(provenance.Stopped) != 0 {
		t.Fatal("prospective owner fabricated native inventory or stop provenance")
	}
	registration := host.Registration{Cell: "gru", Node: "gru-1-ctl-1", Environment: target.Environment, Roles: []string{target.Role}, Generation: 1,
		ID: entityid.Derive("host", "gru", "gru-1-ctl-1"), PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: nkey,
		FailureDomain: "fault-domain-1", Capacity: host.Capacity{CPU: 8, MemoryBytes: 8 << 30, DiskBytes: 16 << 30}}
	if _, err := hosts.Register(ctx, registration); err != nil {
		t.Fatal(err)
	}
	registered, err := fencer.ReadHostMutation(ctx, authority.MutationRegistration, "gru."+registration.Node)
	if err != nil || registered.Sequence <= owner.Sequence {
		t.Fatal("registration preceded prospective owner", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- hosts.Run(runCtx) }()
	stopController := sync.OnceFunc(func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("stop genesis host controller: %v", err)
		}
	})
	t.Cleanup(stopController)
	select {
	case <-hosts.Ready():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	transport, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Instance: registration.Node, URL: broker.Conn().ConnectedUrl(), ClientRole: "host", NKeySeedFile: seed})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	runner := &genericRuntimeNativeRunner{inMemoryRunner: new(inMemoryRunner), stopEntered: make(chan struct{}), allowStop: make(chan struct{})}
	t.Cleanup(runner.releaseStop)
	session := &genericRuntimeHostSession{nativeRunner: runner, hosts: hosts, registration: registration, controllerConfig: controllerConfig,
		config: host.AgentConfig{Cell: "gru", Node: registration.Node, Environment: target.Environment, Roles: registration.Roles, Conn: transport.Conn(), Identity: private,
			NATSUserPublicKey: nkey, ControllerPublicKey: responsePublic, Runner: runner, TaskLoad: executor, PollInterval: 100 * time.Millisecond,
			InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), WorkloadIdentity: testHostWorkloadIdentity(), ClockCheck: func() error { return nil }}}
	session.start(t, ctx, (*host.Agent).Run)
	stop := sync.OnceFunc(func() {
		session.stop(t)
		stopController()
	})
	t.Cleanup(stop)
	native := host.Desired{Cell: "gru", Node: registration.Node, Environment: target.Environment, Role: target.Role, Digest: strings.Repeat("a", 64), Generation: 1, AuthorityEpoch: fencer.Current().Epoch}
	if _, err := hosts.ApplyDesired(ctx, native); err == nil {
		t.Fatal("prospective owner allowed first native desired")
	}
	if desired, err := hosts.ListDesired(ctx, target.Role); err != nil || len(desired) != 0 {
		t.Fatal("prospective owner manufactured native desired", err)
	}
	select {
	case <-runner.stopEntered:
		t.Fatal("genesis fabricated native stop")
	default:
	}
	// The container phase uses production's session-only lifecycle; its workers
	// are joined by RunSession before this fixture begins the typed reset.
	session.stop(t)
	session.start(t, ctx, (*host.Agent).RunSession)
	return session, stop
}

// The fixture stops its own simulated writers. This is the real authority reset
// transaction; it does not qualify physical writer shutdown or host installation.
func genericGenesisIdentityReset(t *testing.T, ctx context.Context, js jetstream.JetStream, signer functionPublicationSigner, identity cellspec.Identity, epoch uint64) (trust.Envelope, authority.IdentityResetTarget) {
	t.Helper()
	rootKV, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: rootChainBucket, Storage: jetstream.FileStorage, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := protocol.EncodeJSON(trust.RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string][]byte{rootChainKey: chain, "material-generations": []byte(`{}`)} {
		if _, err := rootKV.Put(ctx, key, value); err != nil {
			t.Fatal(err)
		}
	}
	type replacement struct {
		pin   authority.IdentityResetRecord
		value []byte
	}
	var records []replacement
	for _, destination := range [][2]string{{cellSpecBucket, cellSpecKey}, {rootChainBucket, rootChainKey}, {rootChainBucket, "material-generations"}} {
		kv, err := js.KeyValue(ctx, destination[0])
		if err != nil {
			t.Fatal(err)
		}
		entry, err := kv.Get(ctx, destination[1])
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, replacement{authority.IdentityResetRecord{Action: authority.IdentityResetReplaceKV, Bucket: destination[0], Key: destination[1],
			PreviousRevision: entry.Revision(), PreviousSHA256: controllerSHA256(entry.Value()), SHA256: controllerSHA256(entry.Value())}, bytes.Clone(entry.Value())})
	}
	stream, err := js.Stream(ctx, authority.ControlStreamName)
	if err != nil {
		t.Fatal(err)
	}
	var hostRecords []replacement
	for _, inventory := range [][2]string{{authority.ControlStreamName, "ts.control.gru.host.>"}, {"KV_TS_HOST_STATE", "$KV.TS_HOST_STATE.>"}, {"KV_TS_HOST_ENROLLMENT", "$KV.TS_HOST_ENROLLMENT.>"}} {
		source, err := js.Stream(ctx, inventory[0])
		if errors.Is(err, jetstream.ErrStreamNotFound) && inventory[0] != authority.ControlStreamName {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		info, err := source.Info(ctx, jetstream.WithSubjectFilter(inventory[1]))
		if err != nil {
			t.Fatal(err)
		}
		for subject := range info.State.Subjects {
			if inventory[0] == authority.ControlStreamName {
				kind, _, _ := strings.Cut(strings.TrimPrefix(subject, "ts.control.gru.host."), ".")
				if kind != string(authority.MutationRegistration) && kind != string(authority.MutationDesired) && kind != string(authority.MutationRetirement) {
					continue
				}
			}
			raw, err := source.GetLastMsgForSubject(ctx, subject)
			if err != nil {
				t.Fatal(err)
			}
			pin := authority.IdentityResetRecord{PreviousRevision: raw.Sequence, PreviousSHA256: controllerSHA256(raw.Data)}
			var value []byte
			if inventory[0] == authority.ControlStreamName {
				var head struct {
					Version     int                        `json:"version"`
					Kind        authority.HostMutationKind `json:"kind"`
					Scope       string                     `json:"scope"`
					SubjectKey  string                     `json:"subject_key"`
					OperationID string                     `json:"operation_id"`
					Epoch       uint64                     `json:"epoch"`
					Payload     []byte                     `json:"payload"`
				}
				if err := protocol.DecodeStrict(raw.Data, &head, protocol.DefaultMaxJSONBytes); err != nil {
					t.Fatal(err)
				}
				if head.Kind != authority.MutationRegistration {
					t.Fatalf("unexpected native desired/retirement in genesis-only inventory: %s", subject)
				}
				var registration host.Registration
				if err := protocol.DecodeStrict(head.Payload, &registration, protocol.DefaultMaxJSONBytes); err != nil {
					t.Fatal(err)
				}
				registration.Generation++
				head.Payload, err = protocol.EncodeJSON(registration)
				if err != nil {
					t.Fatal(err)
				}
				head.Epoch, head.OperationID = epoch+1, entityid.Derive("host-mutation", controllerSHA256(head.Payload))
				value, err = protocol.EncodeJSON(head)
				if err != nil {
					t.Fatal(err)
				}
				pin.Action, pin.Bucket, pin.Key, pin.SHA256 = authority.IdentityResetAppendHostHead, authority.ControlStreamName, subject, controllerSHA256(value)
			} else {
				pin.Action, pin.Bucket = authority.IdentityResetDeleteKV, strings.TrimPrefix(inventory[0], "KV_")
				pin.Key = strings.TrimPrefix(subject, "$KV."+pin.Bucket+".")
				pin.PreviousOperation = raw.Header.Get("KV-Operation")
			}
			hostRecords = append(hostRecords, replacement{pin, value})
		}
	}
	slices.SortFunc(hostRecords, func(a, b replacement) int {
		return strings.Compare(a.pin.Bucket+"/"+a.pin.Key, b.pin.Bucket+"/"+b.pin.Key)
	})
	records = append(records, hostRecords...)
	floor, err := authority.ObserveIdentityResetFloor(ctx, js, identity.Cell, 1)
	if err != nil {
		t.Fatal(err)
	}
	reset := authority.IdentityReset{Version: 1, OperationID: entityid.New(), DeploymentID: entityid.New(), ClusterID: entityid.New(), Scope: identity.Cell, Environment: identity.Environment,
		CheckpointSHA256: controllerSHA256([]byte("bounded generic genesis reset checkpoint")), HostStatePlanSHA256: controllerSHA256([]byte("fixture writer lifecycle joined; typed inventory pinned")),
		LastSequence: floor.LastSequence, PreviousSequence: floor.PreviousSequence, PreviousSHA256: floor.PreviousSHA256, EpochFloor: epoch, Epoch: epoch + 1}
	var values [][]byte
	for _, record := range records {
		reset.Records = append(reset.Records, record.pin)
		values = append(values, record.value)
	}
	if err := reset.Validate(); err != nil {
		t.Fatal("actual typed reset fixture inventory is invalid", err)
	}
	target := authority.IdentityResetTarget{OperationID: reset.OperationID, DeploymentID: reset.DeploymentID, ClusterID: reset.ClusterID, Scope: reset.Scope, Environment: reset.Environment,
		CheckpointSHA256: reset.CheckpointSHA256, HostStatePlanSHA256: reset.HostStatePlanSHA256, Replicas: 1}
	now := time.Now().UTC()
	envelope, err := authority.SignIdentityReset(reset, now.Add(-time.Minute), now.Add(time.Hour-time.Minute), signer.root)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.VerifyIdentityResetPredecessors(ctx, js, reset, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ResetIdentityLease(ctx, js, envelope, signer.roots, target, now); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ReplaceIdentityRecords(ctx, js, envelope, signer.roots, target, values, now); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.CompleteIdentityReset(ctx, js, envelope, signer.roots, target, now); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.GetLastMsgForSubject(ctx, "ts.control.gru.host.runtime-owner.gru."+identity.Environment+"."+signer.allocations.Genesis.Origin().Role); err != nil {
		t.Fatal("completed reset lost genesis owner subject", err)
	}
	return envelope, target
}
