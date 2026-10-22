package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/capacity"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// This is a local authority simulation: signed profile/release, OCI SDK CAS,
// broker, manager, dispatcher, scheduler, task repair and HTTP are real. The
// supplied application probe substitutes the external OCI recipient source;
// native execution and the production recipient adapter remain separate gates.
// The local privileged observer proves applied history; authenticated Unix
// management transport remains separately qualified.
func TestGenericRuntimeSignedManagerIntegration(t *testing.T) {
	tier.Integration(t)
	// No test-owned deadline: the lab waits on real 30s session TTLs and 5s
	// usage intervals, which -race on a loaded runner stretches past any fixed
	// budget; go test -timeout bounds it.
	ctx := t.Context()
	auth := newAuthenticatedNATS(t, "gru")
	broker, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	// The fixture's 5-minute bridge ticket would fence the host transport
	// mid-run: this lab takes about 5 minutes idle and longer under -race load.
	if err := broker.Bridge().OpenUntil(1, auth.cellJWT, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	signer := newFunctionPublicationSigner(t)
	identity := cellspec.Identity{DeploymentID: entityid.New(), Cell: "gru", Environment: "canary"}
	keys := newTestSpecTrustWithRoot(t, t.TempDir(), identity, signer.root)
	fencer, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: identity.DeploymentID, Scope: identity.Cell, CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fencer.Close() })
	specs := &specRegistry{cell: identity.Cell, identity: identity, fixed: map[string]WorkloadProfile{},
		signedArtifactStore: delivery.DefaultArtifactStoreMaxBytes}
	if err := specs.openRoots(signer.roots, trust.RootChain{Version: 1}, ""); err != nil {
		t.Fatal(err)
	}
	specs.kv, err = broker.JetStream().CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: cellSpecBucket, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	profile := WorkloadProfile{Resources: placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 1 << 30}}
	policy := workload.ServiceSpec{Role: "api", Environment: identity.Environment, Kind: workload.KindStateless,
		Replicas: workload.ReplicaBounds{Min: 1, Max: 4}, Scaling: &autoscale.Policy{Signals: []autoscale.Signal{{Name: autoscale.SignalCPUUtilization, Target: 0.5}}}}
	originalPolicy := policy
	adopt := func(generation uint64, services []cellspec.Service) {
		t.Helper()
		file := keys.signRoot(t, t.TempDir(), cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: generation,
			RequiresBinary: cellspec.BinaryLevel, Services: services})
		wire, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := specs.kv.Put(ctx, cellSpecKey, wire); err != nil {
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
	adopt(1, []cellspec.Service{{Role: policy.Role, Profile: profile, Spec: &policy}})
	executor := &genericRuntimeExecutor{controllers: map[string]*genericRuntimeTask{}}
	session := startGenericRuntimeHostSession(t, ctx, auth, broker, fencer, policy.Role, identity.Environment, executor)
	managerConfig := genericRuntimeNodeConfig(t, "generic-manager", "manager")
	managerConfig.Admission.HostID, managerConfig.Admission.FounderID = "controller-a", "controller-a"
	manager := startGenericRuntimeNode(t, ctx, managerConfig, executor)
	executor.mu.Lock()
	executor.nodeID = manager.ID()
	executor.mu.Unlock()
	client, err := manager.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := swarmruntime.AdmitNode(ctx, client, manager.ID(), managerConfig.Admission); err != nil {
		t.Fatal(err)
	}
	observer, err := manager.LocalManagementObservation(ctx, identity.Environment)
	if err != nil {
		t.Fatal(err)
	}
	target := release.ContainerTarget{Cell: "GRU", Environment: identity.Environment, Role: policy.Role, Architecture: runtime.GOARCH}
	keyID, err := protocol.KeyID(signer.leaf.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	codec := delivery.Ed25519Codec{Cell: identity.Cell, Actor: "release", PrivateKey: signer.leaf, Lifetime: time.Minute, MaxLifetime: time.Minute,
		Trusted: map[string]delivery.TrustedSigner{keyID: {Actor: "release", PublicKey: signer.leaf.Public().(ed25519.PublicKey)}}}
	history := retainGenericRuntimeNativeRelease(t, ctx, broker.JetStream(), specs, fencer, codec, profile, policy.Role, identity.Environment, session.registration.Node)
	history.hosts = session.hosts
	retainedState, _, err := history.load(ctx, policy.Role)
	if err != nil {
		t.Fatal(err)
	}
	retainedBinding := nativeBindings(&retainedState)[0]
	nativeDesired := host.Desired{Cell: identity.Cell, Node: session.registration.Node, Environment: identity.Environment,
		Role: policy.Role, Digest: retainedBinding.Artifact.Digest, Generation: 1, AuthorityEpoch: fencer.Current().Epoch}
	if _, err := session.hosts.ApplyDesired(ctx, nativeDesired); err != nil {
		t.Fatal("admit retained native desired through ordered host authority", err)
	}
	genericRuntimeEventually(t, ctx, func() bool {
		statuses, err := session.hosts.ListHosts(ctx)
		if err != nil {
			return false
		}
		for _, status := range statuses {
			for _, report := range status.Reports {
				if status.Verified && report.Role == policy.Role && report.Generation == nativeDesired.Generation && report.Digest == nativeDesired.Digest && report.State == "running" {
					return true
				}
			}
		}
		return false
	})
	unboundData := []byte("independently signed native artifact absent retained profile history")
	unboundRecord, err := delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{Cell: identity.Cell, Role: policy.Role, Environment: identity.Environment,
		Source: delivery.ArtifactSource{Repository: "https://example.invalid/api", Commit: strings.Repeat("c", 40), TreeDigest: strings.Repeat("d", 64)}},
		controllerSHA256(unboundData), int64(len(unboundData)))
	if err != nil {
		t.Fatal(err)
	}
	unboundClaim, err := codec.SignArtifact(ctx, unboundRecord)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := history.deliveries.AdmitClaim(ctx, bytes.NewReader(unboundData), unboundClaim); err != nil {
		t.Fatal(err)
	}
	unboundDesired := nativeDesired
	unboundDesired.Generation++
	unboundDesired.Digest = unboundRecord.Digest
	if _, err := session.hosts.ApplyDesired(ctx, unboundDesired); err != nil {
		t.Fatal(err)
	}
	if _, err := history.retainedContainerFloor(ctx, policy.Role, identity.Environment); err == nil || !strings.Contains(err.Error(), "current native desired lacks authenticated retained release and profile coverage") {
		t.Fatal("signed but unbound native artifact acquired an incomplete migration floor", err)
	}
	nativeDesired.Generation = unboundDesired.Generation + 1
	if _, err := session.hosts.ApplyDesired(ctx, nativeDesired); err != nil {
		t.Fatal(err)
	}
	// The real signed agent drives the simulated process runner; this proves
	// the handoff protocol, not OS process cessation or native custody.
	legacyFloor, err := history.retainedContainerFloor(ctx, policy.Role, identity.Environment)
	if err != nil {
		t.Fatal(err)
	}
	type retainedNativeRecord struct {
		revision uint64
		data     string
	}
	nativeEvidence := func() map[string]retainedNativeRecord {
		t.Helper()
		state, _, err := history.load(ctx, policy.Role)
		if err != nil {
			t.Fatal(err)
		}
		records := map[string]retainedNativeRecord{}
		retain := func(key string) {
			t.Helper()
			message, err := nativeLeaderGet(ctx, history.js, nativeHistoryBucket, key)
			if err != nil {
				t.Fatal(err)
			}
			records[key] = retainedNativeRecord{revision: message.Sequence, data: string(message.Data)}
		}
		retain(policy.Role)
		for _, binding := range nativeBindings(&state) {
			retain(binding.ProfileRecord)
			wire, err := history.immutable(ctx, binding.ProfileRecord)
			if err != nil {
				t.Fatal(err)
			}
			var stored nativeStoredProfile
			if err := protocol.DecodeStrict(wire, &stored, nativeHistoryMaxBytes); err != nil {
				t.Fatal(err)
			}
			for _, refs := range [][]string{stored.Provenance.Spec, stored.Provenance.Manifest, stored.Provenance.Config, stored.Provenance.MaterialChain, stored.Provenance.Identity} {
				for _, key := range refs {
					retain(key)
				}
			}
			claim, err := history.deliveries.RetainedArtifactClaim(ctx, binding.Artifact.Digest, policy.Role, identity.Environment)
			if err != nil {
				t.Fatal(err)
			}
			records["claim."+binding.Artifact.Digest] = retainedNativeRecord{data: string(claim)}
		}
		return records
	}
	originalNativeEvidence := nativeEvidence()
	floors := []release.SequenceFloor{legacyFloor}
	for _, cell := range []string{"sjc", "fra"} {
		regionalCodec := codec
		regionalCodec.Cell = cell
		floors = append(floors, retainGenericRuntimeRegionalClaim(t, ctx, regionalCodec, policy.Role, identity.Environment))
	}
	bundle, evidence := genericRuntimeContainerRelease(t, signer, target, floors, 101, nil)
	channelLocation := releasechannel.Location{Client: signer.allocations.Client, Namespace: signer.allocations.Namespace, Bucket: signer.allocations.Bucket}
	publishChannel := func(bundle release.ContainerBundle) {
		t.Helper()
		if err := releasechannel.PublishContainer(ctx, channelLocation, bundle, signer.roots, target, time.Now().UTC(), time.Now().UTC().Add(2*time.Minute), evidence, signer.allocations); err != nil {
			t.Fatal("publish actual signed container channel through SDK CAS", err)
		}
	}
	publishChannel(bundle)
	var claim release.ContainerClaim
	envelope, err := trust.DecodeEnvelope(bundle.Claim)
	if err != nil || protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes) != nil {
		t.Fatal("decode independently signed container claim", err)
	}
	intent := delivery.Intent{SchemaVersion: delivery.SchemaVersion, OperationID: entityid.New(), Cell: identity.Cell, Environment: identity.Environment,
		Role: policy.Role, Generation: 1, DesiredReplicas: 1, AuthorityEpoch: fencer.Current().Epoch, Container: &bundle,
		ConfigDigest: delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets), Source: delivery.ArtifactSource{
			Repository: claim.SourceRepository, Commit: claim.SourceRevision, TreeDigest: claim.SourceTreeSHA256}}
	var healthy atomic.Bool
	healthy.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" || r.Header.Get("X-Task-ID") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(server.Close)
	var deliveries *delivery.Service
	probeClient := client
	verifyTask := func(ctx context.Context, task *api.Task, allocation bool) error {
		if err := session.verify(ctx); err != nil {
			return err
		}
		node, err := probeClient.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
		if err != nil || node.Node.Spec.Annotations.Name != managerConfig.Admission.HostID || node.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != managerConfig.Admission.InstanceID {
			return errors.New("task recipient differs from current signed host session")
		}
		entry, err := specs.kv.Get(ctx, cellSpecKey)
		if err != nil {
			return err
		}
		taskIntent, err := deliveries.ContainerIntent(ctx, task.ServiceAnnotations.Labels[swarmruntime.LabelOperationID])
		if err != nil {
			return err
		}
		proof, err := containermaterial.VerifyProfile(entry.Value(), specs.roots.current(), identity, taskIntent)
		if err != nil {
			return err
		}
		expected, err := containermaterial.ServiceIntent(proof, runtime.GOARCH)
		if err != nil {
			return err
		}
		verified, err := release.VerifyContainerCurrent(ctx, *taskIntent.Container, specs.roots.current(), target, time.Now().UTC(), time.Now().UTC().Add(time.Minute), evidence, signer.allocations)
		if err != nil {
			return err
		}
		verify := swarmruntime.VerifyRegistryTask
		if allocation {
			verify = swarmruntime.VerifyTaskAllocation
		}
		if err := verify(ctx, probeClient, task, expected, verified, specs.roots.current()); err != nil {
			return err
		}
		return session.verify(ctx)
	}
	probe := func(ctx context.Context, task *api.Task) error {
		if err := verifyTask(ctx, task, false); err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/readyz", nil)
		if err != nil {
			return err
		}
		request.Header.Set("X-Task-ID", task.ID)
		response, err := server.Client().Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("application readiness HTTP %d", response.StatusCode)
		}
		return verifyTask(ctx, task, false)
	}
	var controller *genericRuntime
	var activeRuntime atomic.Pointer[genericRuntime]
	writer := new(genericRuntimeLegacyWriter)
	var firstApplyError sync.Once
	deliveries, err = delivery.Open(ctx, delivery.Config{Conn: broker.Conn(), JS: broker.JetStream(), Cell: identity.Cell, Replicas: 1,
		Signer: codec, Verifier: codec, ArtifactVerifier: codec, Fencer: fencer, Writer: writer, CaptureContainerProfile: history.CaptureContainerProfile,
		AuthorizeArtifact: func(_ context.Context, actor string, record delivery.ArtifactRecord) error {
			if actor != "release" || record.Role != policy.Role || record.Environment != identity.Environment {
				return delivery.ErrUnauthorized
			}
			return nil
		},
		Authorize: func(_ context.Context, actor string, proposed delivery.Intent) error {
			if actor != "release" || proposed.Role != policy.Role || proposed.Environment != identity.Environment {
				return delivery.ErrUnauthorized
			}
			return nil
		}, ContainerApply: func(ctx context.Context, intent delivery.Intent) error {
			err := activeRuntime.Load().apply(ctx, intent)
			if err != nil {
				firstApplyError.Do(func() { t.Logf("first signed container apply refusal: %v", err) })
			}
			return err
		}})
	if err != nil {
		t.Fatal(err)
	}
	history.deliveries = deliveries
	signals := autoscale.NewWindowStore(0, 0)
	controller, err = newGenericRuntime(genericRuntimeConfig{Client: client, ManagerID: manager.ID(), Authority: fencer, Specs: specs,
		Delivery: deliveries, OriginalProfile: history.originalContainerProfile,
		CurrentBundle: func(ctx context.Context, role, architecture string) (release.ContainerBundle, time.Time, error) {
			if role != target.Role || architecture != target.Architecture {
				return release.ContainerBundle{}, time.Time{}, delivery.ErrUnauthorized
			}
			current, found, err := releasechannel.ReadContainerBundle(ctx, channelLocation, role, architecture)
			if err != nil || !found {
				return release.ContainerBundle{}, time.Time{}, errors.Join(containermaterial.ErrPending, err)
			}
			deadline, _ := ctx.Deadline()
			return current, deadline, ctx.Err()
		},
		Allocations: func(ctx context.Context, operationID string, requested release.ContainerBundle, roots trust.Keyring, requestedTarget release.ContainerTarget) (release.SequenceLocation, error) {
			current, err := deliveries.ContainerIntent(ctx, operationID)
			if err != nil {
				return release.SequenceLocation{}, err
			}
			if current.Container == nil || requestedTarget != target || current.Role != target.Role || current.Environment != target.Environment || strings.ToUpper(current.Cell) != target.Cell {
				return release.SequenceLocation{}, delivery.ErrUnauthorized
			}
			actual, actualErr := release.ContainerBundleSHA256(*current.Container)
			wanted, wantedErr := release.ContainerBundleSHA256(requested)
			if actualErr != nil || wantedErr != nil || actual != wanted {
				return release.SequenceLocation{}, delivery.ErrUnauthorized
			}
			return currentContainerAllocations(ctx, signer.factory, requested, roots, requestedTarget)
		}, Evidence: func(ctx context.Context, operationID, digest string) (io.ReadCloser, error) {
			current, err := deliveries.ContainerIntent(ctx, operationID)
			if err != nil {
				return nil, err
			}
			if current.Container == nil || current.Role != target.Role || current.Environment != target.Environment || strings.ToUpper(current.Cell) != target.Cell {
				return nil, delivery.ErrUnauthorized
			}
			currentEnvelope, err := trust.DecodeEnvelope(current.Container.Claim)
			if err != nil {
				return nil, err
			}
			if _, err := trust.Fingerprint(currentEnvelope); err != nil {
				return nil, err
			}
			return evidence(ctx, digest)
		}, Probe: probe, RetainedFloor: history.retainedContainerFloor, Hosts: session.hosts, SessionGuard: session.verify}, signals)
	if err != nil {
		t.Fatal(err)
	}
	activeRuntime.Store(controller)
	usageFixture := startGenericRuntimeUsage(t, ctx, session, history, client, observer, controller.owns,
		func(ctx context.Context, registration host.Registration, task *api.Task) error {
			if !reflect.DeepEqual(registration, session.registration) {
				return errors.New("allocation observation differs from the actual signed host")
			}
			if err := verifyTask(ctx, task, true); err != nil {
				return err
			}
			if err := probe(ctx, task); err != nil {
				return err
			}
			return fencer.Guard(ctx, fencer.Current().Epoch)
		})
	for name, mutate := range map[string]func(*release.ContainerBundle){
		"signature": func(candidate *release.ContainerBundle) {
			envelope, err := trust.DecodeEnvelope(candidate.Claim)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
			if err != nil {
				t.Fatal(err)
			}
			signature[0] ^= 1
			envelope.Signature = base64.RawURLEncoding.EncodeToString(signature)
			candidate.Claim, err = trust.EncodeEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
		},
		"allocation": func(candidate *release.ContainerBundle) { candidate.Sequence = nil },
	} {
		candidate := intent.Clone()
		mutate(candidate.Container)
		if _, err := release.VerifyContainerCurrent(ctx, *candidate.Container, specs.roots.current(), target,
			time.Now().UTC(), time.Now().UTC().Add(time.Minute), evidence, signer.allocations); err == nil {
			t.Fatalf("%s refusal depended only on the absent delivery operation", name)
		}
		if err := controller.apply(ctx, candidate); err == nil {
			t.Fatalf("%s refusal admitted an unauthenticated release", name)
		}
	}
	if listed, err := client.ListServices(ctx, &api.ListServicesRequest{}); err != nil || len(listed.Services) != 0 {
		t.Fatalf("refused release mutated manager services: %+v %v", listed, err)
	}
	runCtx, stopConsumer := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- deliveries.Run(runCtx) }()
	t.Cleanup(func() {
		stopConsumer()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("stop signed delivery consumer: %v", err)
		}
	})
	if err := deliveries.Submit(ctx, intent); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.nativeRunner.stopEntered:
	case <-ctx.Done():
		t.Fatal("signed agent did not receive native withdrawal", ctx.Err())
	}
	if err := session.hosts.GuardContainerOwner(ctx, identity.Environment, policy.Role); err == nil {
		t.Fatal("native withdrawal was mistaken for completed stop ownership")
	}
	pendingOwner, err := fencer.ReadHostMutation(ctx, authority.MutationRuntimeOwner, identity.Cell+"."+identity.Environment+"."+policy.Role)
	if err != nil || pendingOwner.Sequence == 0 {
		t.Fatal("withdrawal preceded durable native admission fence", err)
	}
	withdrawals, err := session.hosts.ListDesired(ctx, policy.Role)
	if err != nil || len(withdrawals) != 1 || !withdrawals[0].Withdrawn || withdrawals[0].Generation != nativeDesired.Generation+1 || withdrawals[0].Digest != "" {
		t.Fatalf("handoff did not retain exact higher-generation withdrawal: %+v %v", withdrawals, err)
	}
	if simulated, err := session.nativeRunner.Observe(ctx, policy.Role); err != nil || !simulated.Running {
		t.Fatal("blocked simulated Stop unexpectedly ceased its native observation", err)
	}
	if listed, err := client.ListServices(ctx, &api.ListServicesRequest{}); err != nil || len(listed.Services) != 0 {
		t.Fatalf("container service preceded authenticated native stopped receipt: %+v %v", listed, err)
	}
	if receipt, err := deliveries.Status(ctx, intent.OperationID); err == nil && receipt.Status == "accepted" {
		t.Fatal("container delivery accepted while native Stop was incomplete")
	}
	reopened := nativeDesired
	reopened.Generation = withdrawals[0].Generation + 1
	if _, err := session.hosts.ApplyDesired(ctx, reopened); err == nil {
		t.Fatal("higher native generation bypassed permanent runtime ownership")
	}
	if _, err := session.hosts.ApplyDesired(ctx, nativeDesired); err == nil {
		t.Fatal("idempotent native desired bypassed permanent runtime ownership")
	}
	rawDesired, err := protocol.EncodeJSON(reopened)
	if err != nil {
		t.Fatal(err)
	}
	withdrawalHead, err := fencer.ReadHostMutation(ctx, authority.MutationDesired, identity.Cell+"."+session.registration.Node+"."+policy.Role)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fencer.CommitHostMutation(ctx, fencer.Current().Epoch, authority.MutationDesired,
		withdrawalHead.SubjectKey, entityid.New(), withdrawalHead.Sequence, rawDesired); err == nil {
		t.Fatal("raw ordered desired admission bypassed permanent runtime owner fence")
	}
	if _, err := fencer.CommitHostMutation(ctx, fencer.Current().Epoch, authority.MutationRuntimeOwner,
		pendingOwner.SubjectKey, entityid.New(), pendingOwner.Sequence, pendingOwner.Payload); err == nil {
		t.Fatal("runtime owner accepted unverified mutation route")
	}
	resumeHosts, err := host.NewController(ctx, session.controllerConfig)
	if err != nil {
		t.Fatal(err)
	}
	resumeConfig := controller.config
	resumeConfig.Hosts = resumeHosts
	pendingResume, err := newGenericRuntime(resumeConfig, signals)
	if err != nil {
		t.Fatal(err)
	}
	if err := pendingResume.apply(ctx, intent); err == nil {
		t.Fatal("controller replacement promoted an already-withdrawn target without its stopped receipt")
	}
	resumedOwner, err := fencer.ReadHostMutation(ctx, authority.MutationRuntimeOwner, pendingOwner.SubjectKey)
	if err != nil || resumedOwner.Sequence != pendingOwner.Sequence || !bytes.Equal(resumedOwner.Payload, pendingOwner.Payload) {
		t.Fatal("pending resume replaced original native inventory or authorization provenance", err)
	}
	session.nativeRunner.releaseStop()
	genericRuntimeEventually(t, ctx, func() bool {
		receipt, err := deliveries.Status(ctx, intent.OperationID)
		return err == nil && receipt.Status == "accepted"
	})
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil || len(listed.Services) != 1 {
		t.Fatalf("signed application submission: %+v %v", listed, err)
	}
	if err := session.hosts.GuardContainerOwner(ctx, identity.Environment, policy.Role); err != nil {
		t.Fatal("accepted service lacks durable authenticated stopped ownership", err)
	}
	completedOwner, err := fencer.ReadHostMutation(ctx, authority.MutationRuntimeOwner, pendingOwner.SubjectKey)
	if err != nil || completedOwner.Sequence <= pendingOwner.Sequence {
		t.Fatal("native stopped ownership was not durably completed", err)
	}
	restoredHosts, err := host.NewController(ctx, session.controllerConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoredHosts.GuardContainerOwner(ctx, identity.Environment, policy.Role); err != nil {
		t.Fatal("new controller lost durable native stopped ownership", err)
	}
	if _, err := restoredHosts.ApplyDesired(ctx, reopened); err == nil {
		t.Fatal("controller replacement reopened permanently fenced native ownership")
	}
	// Native ownership is complete; the container phase uses the production session-only lifecycle.
	session.stop(t)
	session.start(t, ctx, (*host.Agent).RunSession)
	serviceID := listed.Services[0].ID
	altered := intent.Clone()
	altered.Container.Sequence = nil
	if err := controller.apply(ctx, altered); err == nil {
		t.Fatal("accepted operation admitted a different full container bundle")
	}
	operationRefusal, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
	if err != nil || operationRefusal.Service.Meta.Version != listed.Services[0].Meta.Version {
		t.Fatalf("operation-bound bundle refusal changed actual manager service: %v", err)
	}
	ready := func(replicas uint64) swarmruntime.ServiceObservation {
		t.Helper()
		var view swarmruntime.ServiceObservation
		genericRuntimeEventually(t, ctx, func() bool {
			var err error
			view, err = swarmruntime.ObserveService(ctx, client, serviceID, probe)
			return err == nil && view.ReadyReplicas == replicas && view.RequestedReplicas == replicas
		})
		return view
	}
	if err := controller.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	first := ready(1)
	initialUsage := usageFixture.wait(t, ctx, genericRuntimeReadyTaskIDs(first), 3, 0)
	if initialUsage.Observation.CoveredSequence == 0 || initialUsage.Observation.Requests[policy.Role] != (hostload.Request{CPUCores: float64(profile.Resources.CPU), MemoryBytes: profile.Resources.MemoryBytes}) {
		t.Fatal("three stable signed load requests lost their prior manager interval or original signed resources")
	}
	usageFixture.assertExpiredAndThrottled(t, ctx, initialUsage)
	usageFixture.mu.Lock()
	escaped := usageFixture.guarded
	usageFixture.mu.Unlock()
	if escaped == nil || escaped.Err() == nil || !errors.Is(fencer.Guard(escaped, fencer.Current().Epoch), authority.ErrFenced) {
		t.Fatal("task/SDK callback retained authority after its verified commit ended")
	}
	scaleTarget := autoscale.Target{Cell: identity.Cell, Environment: identity.Environment, Role: policy.Role}
	scaleCtx, cancelScale := context.WithTimeout(ctx, 45*time.Second)
	scaleDone := make(chan struct{})
	var scaleErr error
	go func() {
		scaleErr = controller.Run(scaleCtx)
		close(scaleDone)
	}()
	stopScale := sync.OnceValue(func() error {
		cancelScale()
		select {
		case <-scaleDone:
			if !errors.Is(scaleErr, context.Canceled) {
				return fmt.Errorf("stop generic scaling loop: %w", scaleErr)
			}
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("generic scaling loop did not stop within five seconds")
		}
	})
	t.Cleanup(func() {
		if err := stopScale(); err != nil {
			t.Error(err)
		}
	})
	// Record load only after Run completes its startup pass, so its production
	// ticker must drive the replica change rather than the immediate evaluation.
	genericRuntimeEventually(t, scaleCtx, func() bool {
		select {
		case <-scaleDone:
			t.Fatalf("generic scaling loop stopped before its startup pass: %v", scaleErr)
		default:
		}
		result, ok := controller.scaler.Last()[scaleTarget]
		return ok && result.Decision.From == 1 && result.Decision.To == 1 &&
			result.Reason == autoscale.ReasonNoSignalData && len(result.Readings) == 1 && result.Readings[0].Samples == 0
	})
	signals.Record(scaleTarget, autoscale.SignalCPUUtilization, autoscale.Sample{At: time.Now(), Value: 1})
	genericRuntimeEventually(t, scaleCtx, func() bool {
		select {
		case <-scaleDone:
			t.Fatalf("generic scaling loop stopped before its scheduled scale-up: %v", scaleErr)
		default:
		}
		result, ok := controller.scaler.Last()[scaleTarget]
		return ok && result.Decision.From == 1 && result.Decision.To == 2 &&
			result.Reason == autoscale.ReasonScaleUp && len(result.Readings) == 1 &&
			result.Readings[0].Samples == 1 && result.Readings[0].Value == 1
	})
	// Join before waiting for ready tasks, which may outlast another scale tick.
	if err := stopScale(); err != nil {
		t.Fatal(err)
	}
	scaled := ready(2)
	scaledUsage := usageFixture.wait(t, ctx, genericRuntimeReadyTaskIDs(scaled), 1, 0)
	if scaledUsage.Observation.Requests[policy.Role] != (hostload.Request{CPUCores: 2 * float64(profile.Resources.CPU), MemoryBytes: 2 * profile.Resources.MemoryBytes}) {
		t.Fatal("actual replica CAS did not change the journal's aggregate signed requests")
	}
	view, err := newManagerWorkloadView(client, manager.ID(), fencer, controller.scaler, specs, probe)
	if err != nil {
		t.Fatal(err)
	}
	if result, ok := view.Last()[policy.Role]; !ok || result.Replicas != 2 || result.Target != 2 || len(result.Readings) != 1 {
		t.Fatalf("manager observation lost replica CAS or signed scaling readings: %+v", result)
	}
	genericRuntimeAssertSample(t, autoscaleSamples(view), observability.HistAutoscaleReplicas, 2)
	genericRuntimeAssertSample(t, autoscaleSamples(view), observability.HistAutoscaleGoal, 2)
	current, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
	if err != nil || current.Service.Spec.Task.Resources.Limits.NanoCPUs != int64(profile.Resources.CPU)*1_000_000_000 || current.Service.Spec.Task.Resources.Reservations.MemoryBytes != profile.Resources.MemoryBytes {
		t.Fatalf("replica CAS lost signed resources: %+v %v", current, err)
	}
	if disk, err := swarmruntime.DiskBytes(current.Service.Spec.Task.Resources); err != nil || disk != profile.Resources.DiskBytes {
		t.Fatalf("replica CAS lost exact signed disk reservation/limit: %d %v", disk, err)
	}
	staleVersion := current.Service.Meta.Version
	staleSpec := current.Service.Spec.Copy()
	if err := executor.fail(first.Tasks[0].TaskID); err != nil {
		t.Fatal(err)
	}
	genericRuntimeEventually(t, ctx, func() bool {
		view, err := swarmruntime.ObserveService(ctx, client, serviceID, probe)
		if err != nil || view.ReadyReplicas != 2 {
			return false
		}
		for _, task := range view.Tasks {
			if task.TaskID == first.Tasks[0].TaskID && task.State == "RUNNING" {
				return false
			}
		}
		return true
	})
	beforeReplay := ready(2)
	current, err = client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
	if err != nil {
		t.Fatal(err)
	}
	replayVersion := current.Service.Meta.Version
	replay := intent.Clone()
	replay.OperationID = entityid.New()
	if err := deliveries.Submit(ctx, replay); err != nil {
		t.Fatal(err)
	}
	genericRuntimeEventually(t, ctx, func() bool {
		receipt, err := deliveries.Status(ctx, replay.OperationID)
		return err == nil && receipt.Status == "accepted"
	})
	afterReplay := ready(2)
	current, err = client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
	if err != nil || current.Service.Meta.Version != replayVersion || current.Service.Spec.Annotations.Labels[swarmruntime.LabelOperationID] != intent.OperationID ||
		!slices.Equal(genericRuntimeReadyTaskIDs(beforeReplay), genericRuntimeReadyTaskIDs(afterReplay)) {
		t.Fatalf("equivalent signed replay changed healthy task authority, scale or locator: %+v %v", current, err)
	}
	rollout := func(sequence uint64) delivery.Intent {
		t.Helper()
		candidate, _ := genericRuntimeContainerRelease(t, signer, target, floors, sequence, bundle.Migration)
		var claim release.ContainerClaim
		envelope, err := trust.DecodeEnvelope(candidate.Claim)
		if err != nil || protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes) != nil {
			t.Fatal("decode next signed container release", err)
		}
		next := intent.Clone()
		next.OperationID, next.Generation, next.Container = entityid.New(), sequence-100, &candidate
		next.Source.Commit = claim.SourceRevision
		publishChannel(candidate)
		return next
	}
	next := rollout(102)
	if err := controller.apply(ctx, intent); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatalf("replaced signed current channel admitted the previous delivery: %v", err)
	}
	afterChannelReplacement, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
	if err != nil || afterChannelReplacement.Service.Meta.Version != replayVersion {
		t.Fatalf("signed current channel replacement refusal changed actual manager service: %v", err)
	}
	if err := deliveries.Submit(ctx, next); err != nil {
		t.Fatal(err)
	}
	genericRuntimeEventually(t, ctx, func() bool {
		receipt, err := deliveries.Status(ctx, next.OperationID)
		return err == nil && receipt.Status == "accepted"
	})
	rolledForward := ready(2)
	if len(rolledForward.Tasks) == 0 {
		t.Fatal("signed rollout has no actual manager task assignments")
	}
	forwardUsage := usageFixture.wait(t, ctx, genericRuntimeReadyTaskIDs(rolledForward), 1, 0)
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: serviceID, ServiceVersion: &staleVersion, Spec: staleSpec}); err == nil {
		t.Fatal("manager accepted pre-rollout stale service CAS")
	}
	rejected := rollout(103)
	rejectedClaim, err := trust.DecodeEnvelope(rejected.Container.Claim)
	if err != nil {
		t.Fatal(err)
	}
	var rejectedImage release.ContainerClaim
	if err := protocol.DecodeStrict(rejectedClaim.Payload, &rejectedImage, trust.MaxPayloadBytes); err != nil {
		t.Fatal(err)
	}
	executor.mu.Lock()
	executor.rejectImage = rejectedImage.Image
	executor.mu.Unlock()
	if err := deliveries.Submit(ctx, rejected); err != nil {
		t.Fatal(err)
	}
	genericRuntimeEventually(t, ctx, func() bool {
		service, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
		return err == nil && service.Service.UpdateStatus != nil && service.Service.UpdateStatus.State == api.UpdateStatus_ROLLBACK_COMPLETED &&
			service.Service.Spec.Annotations.Labels[swarmruntime.LabelOperationID] == next.OperationID
	})
	rolledBack := ready(2)
	rollbackBoundary := usageFixture.points(t, ctx)
	rollbackUsage := usageFixture.wait(t, ctx, genericRuntimeReadyTaskIDs(rolledBack), 1, rollbackBoundary[len(rollbackBoundary)-1].Entry.Sequence)
	if rollbackUsage.Entry.Sequence <= forwardUsage.Entry.Sequence || len(rollbackUsage.Observation.Tasks) != 2 ||
		rollbackUsage.Observation.Tasks[0].ReleaseSHA256 != forwardUsage.Observation.Tasks[0].ReleaseSHA256 {
		t.Fatal("rollback rewrote signed release history")
	}
	intervals, err := usageFixture.load.managedExpectedUsage(history, usageFixture.usage, controller.owns)(ctx, forwardUsage.Entry.CreatedAt, rollbackUsage.Entry.CreatedAt)
	if err != nil || !slices.ContainsFunc(intervals, func(interval hostload.UsageInterval) bool { return interval.Unknown != "" }) {
		t.Fatal("failed release and rollback lost their unknown allocation gap", err)
	}
	if err := controller.apply(ctx, rejected); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("rolled-back release replay was not refused: %v", err)
	}
	if err := controller.apply(ctx, intent); err == nil {
		t.Fatal("pre-rollout release crossed durable monotonic floor after rollback")
	}
	if receipt, err := deliveries.Status(ctx, rejected.OperationID); err == nil && receipt.Status == "accepted" {
		t.Fatal("application-rejected release received accepted delivery receipt")
	}
	recovery := rollout(104)
	if err := deliveries.Submit(ctx, recovery); err != nil {
		t.Fatal(err)
	}
	genericRuntimeEventually(t, ctx, func() bool {
		receipt, err := deliveries.Status(ctx, recovery.OperationID)
		return err == nil && receipt.Status == "accepted"
	})
	recovered := ready(2)
	recoveryUsage := usageFixture.wait(t, ctx, genericRuntimeReadyTaskIDs(recovered), 1, 0)
	if recoveryUsage.Entry.Sequence <= rollbackUsage.Entry.Sequence ||
		recoveryUsage.Observation.Tasks[0].ReleaseSHA256 == rollbackUsage.Observation.Tasks[0].ReleaseSHA256 {
		t.Fatal("recovery failed to retain distinct rollback and successor releases")
	}
	current, err = client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
	if err != nil || current.Service.Spec.Task.Resources.Limits.NanoCPUs != int64(profile.Resources.CPU)*1_000_000_000 || current.Service.Spec.Task.Resources.Reservations.MemoryBytes != profile.Resources.MemoryBytes {
		t.Fatalf("rollout/rollback/recovery changed exact signed resource request: %+v %v", current, err)
	}
	if disk, err := swarmruntime.DiskBytes(current.Service.Spec.Task.Resources); err != nil || disk != profile.Resources.DiskBytes {
		t.Fatalf("rollout/rollback/recovery changed exact signed disk budget: %d %v", disk, err)
	}
	if err := controller.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	healthy.Store(false)
	if err := controller.scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if result := controller.scaler.Last()[scaleTarget]; result.Reason != "unready-replicas" || result.Replicas != 2 {
		t.Fatalf("HTTP failure authorized scaling: %+v", result)
	}
	if result, ok := view.Last()[policy.Role]; !ok || result.Reason != "unready-replicas" || len(result.Readings) != 0 || result.Decision != nil {
		t.Fatalf("HTTP failure retained stale observation readings: %+v", result)
	}
	for _, sample := range autoscaleSamples(view) {
		if sample.Metric == observability.HistAutoscaleSignal {
			t.Fatal("HTTP failure published a stale numeric history signal")
		}
	}
	healthy.Store(true)
	session.stop(t)
	usageFixture.assertRestarts(t, ctx)
	if err := controller.refresh(ctx); err == nil || len(controller.scaler.Last()) != 0 {
		t.Fatalf("ended authenticated session retained scaling authority: %+v %v", controller.scaler.Last(), err)
	}
	session.start(t, ctx, (*host.Agent).RunSession)
	ready(2)
	if err := controller.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	current, err = client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
	if err != nil {
		t.Fatal(err)
	}
	stalePolicy := current.Service.Spec.Copy()
	stalePolicy.GetReplicated().Replicas = 3
	adopt(2, []cellspec.Service{{Role: policy.Role, Profile: profile, Spec: &policy}})
	if _, err := (genericScaleClient{ControlClient: client, runtime: controller}).UpdateService(ctx,
		&api.UpdateServiceRequest{ServiceID: serviceID, ServiceVersion: &current.Service.Meta.Version, Spec: stalePolicy}); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatalf("policy changed after refresh but stale replica mutation was admitted: %v", err)
	}
	ready(2)
	policy.Replicas = workload.ReplicaBounds{}
	policy.Scaling = nil
	adopt(3, []cellspec.Service{{Role: policy.Role, Profile: profile, Spec: &policy}})
	if err := controller.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := controller.scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	ready(0)
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		t.Fatal("read actual manager join authority", err)
	}
	address, err := manager.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	peers := make([]*swarmruntime.Node, 0, 2)
	for index := range 2 {
		config := genericRuntimeNodeConfig(t, fmt.Sprintf("generic-peer-%d", index), "manager")
		config.Admission.FounderID = managerConfig.Admission.FounderID
		config.Admission.ManagerAddress, config.Admission.JoinToken = address, clusters.Clusters[0].RootCA.JoinTokens.Manager
		peers = append(peers, startGenericRuntimeNode(t, ctx, config, executor))
	}
	genericRuntimeEventually(t, ctx, func() bool {
		nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil {
			return false
		}
		var managers int
		for _, node := range nodes.Nodes {
			if node.ManagerStatus != nil && node.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE {
				managers++
			}
		}
		return managers == 3
	})
	stopCtx, stopManager := context.WithTimeout(ctx, 15*time.Second)
	if err := manager.Stop(stopCtx); err != nil {
		stopManager()
		t.Fatal(err)
	}
	stopManager()
	client, err = peers[0].ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var leaderID string
	genericRuntimeEventually(t, ctx, func() bool {
		nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil {
			return false
		}
		for _, node := range nodes.Nodes {
			if node.ManagerStatus != nil && node.ManagerStatus.Leader && node.ID != manager.ID() {
				leaderID = node.ID
				return true
			}
		}
		return false
	})
	followerConfig := controller.config
	followerConfig.Client = client
	follower, err := newGenericRuntime(followerConfig, signals)
	if err != nil {
		t.Fatal(err)
	}
	if err := follower.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := follower.scaler.Tick(ctx); err != nil || len(follower.scaler.Last()) != 0 {
		t.Fatalf("former leader evaluated policy after actual election: %+v %v", follower.scaler.Last(), err)
	}
	formerView, err := newManagerWorkloadView(client, manager.ID(), fencer, follower.scaler, specs, probe)
	if err != nil {
		t.Fatal(err)
	}
	if formerView.Leading() || len(autoscaleSamples(formerView)) != 0 {
		t.Fatal("former manager leader published current history after actual election")
	}
	resumedConfig := controller.config
	resumedConfig.Client, resumedConfig.ManagerID = client, leaderID
	controller, err = newGenericRuntime(resumedConfig, signals)
	if err != nil {
		t.Fatal(err)
	}
	activeRuntime.Store(controller)
	if err := controller.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := controller.scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	ready(0)
	durableFloors, err := client.ListConfigs(ctx, &api.ListConfigsRequest{})
	if err != nil || len(durableFloors.Configs) == 0 {
		t.Fatal("actual election lost durable release ordering", err)
	}
	adopt(4, []cellspec.Service{{Role: originalPolicy.Role, Profile: profile, Spec: &originalPolicy}})
	beforeRefusal, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
	if err != nil {
		t.Fatal(err)
	}
	readOriginal := controller.config.OriginalProfile
	originalReads := 0
	changedProfile := profile
	changedProfile.Resources.CPU++
	controller.config.OriginalProfile = func(ctx context.Context, intent delivery.Intent) ([]byte, error) {
		originalReads++
		wire, err := readOriginal(ctx, intent)
		if err == nil {
			adopt(5, []cellspec.Service{{Role: originalPolicy.Role, Profile: changedProfile, Spec: &originalPolicy}})
		}
		return wire, err
	}
	if err := controller.apply(ctx, recovery); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatalf("signed source replacement during original profile read admitted mutation: %v", err)
	}
	if originalReads != 1 {
		t.Fatal("source replacement did not reach original archive read")
	}
	controller.config.OriginalProfile = readOriginal
	if err := controller.apply(ctx, recovery); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatalf("changed signed resources with unchanged config admitted mutation: %v", err)
	}
	changedPolicy := originalPolicy
	changedPolicy.Replicas.Max++
	adopt(6, []cellspec.Service{{Role: changedPolicy.Role, Profile: profile, Spec: &changedPolicy}})
	if err := controller.apply(ctx, recovery); !errors.Is(err, containermaterial.ErrPending) {
		t.Fatalf("changed signed service policy with unchanged config admitted mutation: %v", err)
	}
	afterRefusal, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
	if err != nil || afterRefusal.Service.Meta.Version != beforeRefusal.Service.Meta.Version {
		t.Fatalf("refused original profile continuity changed actual service: %v", err)
	}
	adopt(7, nil)
	if err := controller.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	genericRuntimeEventually(t, ctx, func() bool {
		listed, err := client.ListServices(ctx, &api.ListServicesRequest{})
		return err == nil && len(listed.Services) == 0
	})
	if writer.writes.Load() != 0 {
		t.Fatalf("migrated role wrote legacy per-host desired state %d times", writer.writes.Load())
	}
	if _, err := history.retainedContainerFloor(ctx, policy.Role, identity.Environment); err == nil || !strings.Contains(err.Error(), "retained native role is no longer approved") {
		t.Fatalf("removed role retained current native release authority: %v", err)
	}
	if !maps.Equal(originalNativeEvidence, nativeEvidence()) {
		t.Fatal("generic drain/removal changed original native history, profile, provenance or signed claim")
	}
}

func genericRuntimeAssertSample(t *testing.T, samples []observability.Sample, metric string, want float64) {
	t.Helper()
	for _, sample := range samples {
		if sample.Metric == metric && sample.Value == want {
			return
		}
	}
	t.Fatalf("manager history missing %s=%v: %+v", metric, want, samples)
}

func genericRuntimeReadyTaskIDs(view swarmruntime.ServiceObservation) []string {
	var ids []string
	for _, task := range view.Tasks {
		if task.Ready {
			ids = append(ids, task.TaskID)
		}
	}
	slices.Sort(ids)
	return ids
}

type genericRuntimeUsage struct {
	mu      sync.Mutex
	escaped context.Context
	guarded context.Context
	err     error
	session *genericRuntimeHostSession
	history *nativeHistory
	load    *hostTelemetry
	usage   *runtimeObservability
	owns    func(string) bool
	loads   chan protocol.Envelope
}

func startGenericRuntimeUsage(t *testing.T, ctx context.Context, session *genericRuntimeHostSession, history *nativeHistory,
	client api.ControlClient, observer swarmruntime.ManagementObservationClient, owns func(string) bool,
	verify func(context.Context, host.Registration, *api.Task) error,
) *genericRuntimeUsage {
	t.Helper()
	f := &genericRuntimeUsage{session: session, history: history, owns: owns, loads: make(chan protocol.Envelope, 32),
		load:  &hostTelemetry{fencer: history.fencer, load: hostload.NewAggregator(hostload.AggregatorConfig{})},
		usage: &runtimeObservability{usage: capacity.NewStore(session.registration.Cell)}}
	f.usage.usage.SetExpected(f.load.managedExpectedUsage(history, f.usage, owns))
	subject, err := protocol.AgentObservationSubject(session.registration.Cell, session.registration.NATSUserPublicKey, "load")
	if err != nil {
		t.Fatal(err)
	}
	subscription, err := history.js.Conn().Subscribe(subject, func(message *nats.Msg) {
		var envelope protocol.Envelope
		if protocol.DecodeStrict(message.Data, &envelope, 64<<10) == nil {
			select {
			case f.loads <- envelope:
			default:
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = subscription.Unsubscribe() })
	if err := history.js.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	session.hosts.SetLoadObservationSink(func(requestCtx context.Context, origin hostload.Origin, report hostload.Report) error {
		var guarded context.Context
		err := f.load.recordManaged(requestCtx, history, f.usage, client, observer, owns,
			func(check context.Context, registration host.Registration, task *api.Task) error {
				if err := verify(check, registration, task); err != nil {
					return err
				}
				guarded = check
				return nil
			}, origin, report)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.err = err
		if err == nil && guarded != nil {
			f.guarded = guarded
		}
		if err == nil && f.escaped == nil {
			f.escaped = context.WithoutCancel(requestCtx)
		}
		return err
	})
	t.Cleanup(func() {
		if t.Failed() {
			f.mu.Lock()
			defer f.mu.Unlock()
			t.Logf("last actual signed load observation: %v", f.err)
		}
	})
	return f
}

func (f *genericRuntimeUsage) points(t *testing.T, ctx context.Context) []host.CommittedUsage {
	t.Helper()
	points, err := f.session.hosts.UsageObservations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return points
}

func (f *genericRuntimeUsage) wait(t *testing.T, ctx context.Context, tasks []string, count int, after uint64) host.CommittedUsage {
	t.Helper()
	var point host.CommittedUsage
	genericRuntimeEventually(t, ctx, func() bool {
		matched := 0
		for _, candidate := range f.points(t, ctx) {
			if candidate.Entry.Sequence <= after {
				continue
			}
			var ids []string
			for _, task := range candidate.Observation.Tasks {
				ids = append(ids, task.Task.TaskID)
			}
			slices.Sort(ids)
			if slices.Equal(ids, tasks) {
				point = candidate
				matched++
			}
		}
		return matched >= count && (count < 3 || point.Observation.CoveredSequence != 0)
	})
	return point
}

func (f *genericRuntimeUsage) assertExpiredAndThrottled(t *testing.T, ctx context.Context, point host.CommittedUsage) {
	t.Helper()
	before := f.points(t, ctx)
	f.mu.Lock()
	escaped := f.escaped
	f.mu.Unlock()
	verified := false
	if escaped == nil {
		t.Fatal("actual signed load callback was not observed")
	}
	if _, err := f.session.hosts.CommitUsageObservation(escaped, point.Observation, func(context.Context) error {
		verified = true
		return nil
	}); err == nil || verified {
		t.Fatal("expired signed load callback reached the verifier or appended another valid observation")
	}
	var original protocol.Envelope
	for len(f.loads) > 0 {
		original = <-f.loads
	}
	if original.Kind != "host.load" {
		t.Fatal("the real Agent did not send an observable signed load request")
	}
	// Host request fencing follows the current session, independently of the usage journal's authority epoch.
	sessionKey := "session." + f.session.registration.Cell + "." + f.session.registration.Node
	record, err := nativeLeaderGet(ctx, f.history.js, "TS_HOST_STATE", sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil || record.Sequence == 0 || record.Subject != "$KV.TS_HOST_STATE."+sessionKey ||
		record.Header.Get("KV-Operation") != "" || record.Header.Get(jetstream.MarkerReasonHeader) != "" {
		t.Fatal("current authenticated host session state is unavailable")
	}
	var currentSession struct {
		RegistrationGeneration uint64    `json:"registration_generation"`
		SessionID              string    `json:"session_id"`
		Epoch                  uint64    `json:"epoch"`
		ExpiresAt              time.Time `json:"expires_at"`
		LastNonce              string    `json:"last_nonce"`
		LastIssuedAt           time.Time `json:"last_issued_at"`
	}
	if err := protocol.DecodeStrict(record.Data, &currentSession, 64<<10); err != nil {
		t.Fatal(err)
	}
	if currentSession.RegistrationGeneration != f.session.registration.Generation || currentSession.SessionID != point.Observation.SessionID ||
		currentSession.Epoch == 0 || !time.Now().Before(currentSession.ExpiresAt) {
		t.Fatal("signed load observation differs from the current authenticated host session")
	}
	lifetime := original.ExpiresAt.Sub(original.IssuedAt)
	if err := protocol.VerifyEnvelope(original, protocol.EnvelopeScope{Region: original.Region, Kind: "host.load", Actor: f.session.registration.Node,
		OperationID: original.OperationID, Epoch: currentSession.Epoch}, f.session.config.Identity.Public().(ed25519.PublicKey), time.Now().UTC(),
		protocol.VerifyPolicy{MaxLifetime: lifetime, ClockSkew: time.Second}); err != nil {
		t.Fatal(err)
	}
	// Send a fresh signature under the actual Agent's current session. Replaying
	// its nonce would exercise replay rejection instead of journal throttling.
	var payload map[string]jsontext.Value
	if err := json.Unmarshal(original.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(entityid.New()))
	nonce, now := hex.EncodeToString(digest[:16]), time.Now().UTC()
	payload["nonce"], _ = json.Marshal(nonce)
	payload["issued_at"], _ = json.Marshal(now)
	wire, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	operation := entityid.Derive("host-request", nonce)
	signed, err := protocol.SignEnvelope(wire, protocol.EnvelopeScope{Region: original.Region, Kind: "host.load", Actor: original.Actor,
		OperationID: operation, Epoch: currentSession.Epoch}, now, now.Add(lifetime), f.session.config.Identity)
	if err != nil {
		t.Fatal(err)
	}
	wire, err = protocol.EncodeJSON(signed)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := protocol.AgentObservationSubject(original.Region, f.session.registration.NATSUserPublicKey, "load")
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	message, err := f.session.config.Conn.RequestWithContext(requestCtx, subject, wire)
	if err != nil {
		t.Fatal(err)
	}
	var response protocol.Envelope
	if err := protocol.DecodeStrict(message.Data, &response, 512<<10); err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyEnvelope(response, protocol.EnvelopeScope{Region: original.Region, Kind: "host.response.load", Actor: "controller",
		OperationID: operation, Epoch: currentSession.Epoch}, f.session.config.ControllerPublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: lifetime, ClockSkew: time.Second}); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Nonce     string `json:"nonce"`
		Node      string `json:"node"`
		SessionID string `json:"session_id"`
		Operation string `json:"operation"`
		Epoch     uint64 `json:"epoch"`
		Error     string `json:"error"`
		Payload   struct {
			Accepted bool `json:"accepted"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(response.Payload, &reply); err != nil || reply.Nonce != nonce || reply.Node != f.session.registration.Node ||
		reply.SessionID != point.Observation.SessionID || reply.Epoch != currentSession.Epoch || reply.Operation != "load" || reply.Error != "" || reply.Payload.Accepted {
		t.Fatalf("fresh signed load inside the minimum interval was not throttled: %+v %v", reply, err)
	}
	if after := f.points(t, ctx); !reflect.DeepEqual(before, after) {
		t.Fatal("expired or throttled signed load grew or rewrote the durable usage journal")
	}
}

func (f *genericRuntimeUsage) assertRestarts(t *testing.T, ctx context.Context) {
	t.Helper()
	points := f.points(t, ctx)
	if len(points) < 6 {
		t.Fatal("actual signed journal has insufficient rollout history")
	}
	from := points[0].Entry.CreatedAt.Truncate(time.Millisecond)
	to := points[len(points)-1].Entry.CreatedAt.Truncate(time.Millisecond).Add(time.Millisecond)
	query := func(usage *runtimeObservability) capacity.Usage {
		t.Helper()
		token := controllerSHA256([]byte(entityid.New()))
		listener, err := observability.NewTokenServer(observability.Config{ListenAddress: "127.0.0.1:9463"}, token,
			observability.ServerDeps{Registry: observability.NewRegistry(false), Health: new(observability.Health)})
		if err != nil {
			t.Fatal(err)
		}
		listener.HandleAuthenticated("GET /v1/usage", usage.usage.Handler(usage.usage.Expected))
		server := httptest.NewServer(listener)
		defer server.Close()
		values := url.Values{"region": {f.session.registration.Cell}, "from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)}}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/usage?"+values.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, bearer := range []string{"", "Bearer invalid"} {
			request.Header.Set("Authorization", bearer)
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatal("usage listener accepted missing or incorrect bearer credentials")
			}
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		var result capacity.Usage
		if err != nil || response.StatusCode != http.StatusOK || json.Unmarshal(body, &result) != nil {
			t.Fatalf("actual usage HTTP failed: status=%d body=%s error=%v", response.StatusCode, body, err)
		}
		return result
	}
	original := query(f.usage)
	if original.Complete || len(original.Gaps) == 0 || len(original.Replicas) != 1 || len(original.Services) != 1 || original.Services[0].CPU.Request != nil {
		t.Fatalf("task/replica/rollback gaps became a partial numeric service total: %+v", original)
	}
	request := original.Replicas[0].CPU.Request
	var sum, memorySum, minimum, maximum float64
	var firstRequestAt, lastRequestAt time.Time
	var samples int
	sawOne, sawTwo := false, false
	for _, point := range points {
		if value, exists := point.Observation.Requests[f.session.registration.Roles[0]]; exists {
			sum += value.CPUCores
			memorySum += float64(value.MemoryBytes)
			if samples == 0 {
				minimum = value.CPUCores
				firstRequestAt = point.Entry.CreatedAt.Truncate(time.Millisecond)
			}
			lastRequestAt = point.Entry.CreatedAt.Truncate(time.Millisecond)
			minimum, maximum = min(minimum, value.CPUCores), max(maximum, value.CPUCores)
			sawOne = sawOne || value.CPUCores == 1
			sawTwo = sawTwo || value.CPUCores == 2
			samples++
		}
	}
	if !sawOne || !sawTwo || request == nil || request.Complete || request.Samples != samples || request.Min != minimum || request.Max != maximum || math.Abs(request.Mean-sum/float64(samples)) > 1e-9 ||
		!request.From.Equal(firstRequestAt) || !request.To.Equal(lastRequestAt) {
		t.Fatalf("usage HTTP rewrote original signed requests or server timestamps: %+v", request)
	}
	memory := original.Replicas[0].Memory.Request
	if memory == nil || memory.Complete || memory.Samples != samples || math.Abs(memory.Mean-memorySum/float64(samples)) > 1e-3 ||
		original.Replicas[0].CPU.Usage != nil || original.Replicas[0].Memory.Usage != nil {
		t.Fatal("usage HTTP changed historical memory requests or invented native process measurements")
	}
	for restart := range 2 {
		controller, err := host.NewController(ctx, f.session.controllerConfig)
		if err != nil {
			t.Fatal(err)
		}
		history := &nativeHistory{kv: f.history.kv, js: f.history.js, services: f.history.services,
			deliveries: f.history.deliveries, hosts: controller, fencer: f.history.fencer}
		load := &hostTelemetry{fencer: history.fencer, load: hostload.NewAggregator(hostload.AggregatorConfig{})}
		usage := &runtimeObservability{usage: capacity.NewStore(f.session.registration.Cell)}
		usage.usage.SetExpected(load.managedExpectedUsage(history, usage, f.owns))
		restored, err := load.restoreManagedUsage(ctx, controller, usage)
		if err != nil || !reflect.DeepEqual(restored, points) {
			t.Fatalf("restart%d changed original task/release proof, requests or journal timestamps: %v", restart+1, err)
		}
		if actual := query(usage); !reflect.DeepEqual(original, actual) {
			t.Fatalf("restart%d changed capacity HTTP history or erased unknown gaps: before=%+v after=%+v", restart+1, original, actual)
		}
	}
}

type genericRuntimeNativeRunner struct {
	*inMemoryRunner
	stopEntered chan struct{}
	allowStop   chan struct{}
	entered     sync.Once
	released    sync.Once
}

func (runner *genericRuntimeNativeRunner) Stop(ctx context.Context, role string) error {
	runner.entered.Do(func() { close(runner.stopEntered) })
	select {
	case <-runner.allowStop:
		return runner.inMemoryRunner.Stop(ctx, role)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runner *genericRuntimeNativeRunner) releaseStop() {
	runner.released.Do(func() { close(runner.allowStop) })
}

type genericRuntimeHostSession struct {
	nativeRunner     *genericRuntimeNativeRunner
	mu               sync.Mutex
	config           host.AgentConfig
	registration     host.Registration
	hosts            *host.Controller
	controllerConfig host.ControllerConfig
	agent            *host.Agent
	ctx              context.Context
	cancel           context.CancelFunc
	done             chan error
}

func startGenericRuntimeHostSession(t *testing.T, ctx context.Context, auth *authenticatedNATS, broker *natscell.Runtime,
	fencer *authority.Runtime, role, environment string, taskLoad host.TaskLoadSource,
) *genericRuntimeHostSession {
	t.Helper()
	responsePublic, responseKey := testEd25519(t, t.TempDir(), "generic-response.key")
	public, private := testEd25519(t, t.TempDir(), "generic-host.key")
	nkey, seed := testNKey(t)
	artifacts, err := broker.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	controllerConfig := host.ControllerConfig{Cell: "gru", Conn: broker.Conn(), JS: broker.JetStream(), Artifacts: artifacts,
		StateReplicas: 1, ResponseKey: responseKey, HostMutations: fencer, AuthorityEpoch: func() uint64 { return fencer.Current().Epoch }, AuthorityGuard: fencer.Guard,
		TaskLoadRoles: func(ctx context.Context, _ host.Registration) ([]string, error) {
			loads, err := taskLoad.ReadTaskLoad(ctx)
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
	registration := host.Registration{Cell: "gru", Node: "gru-1-ctl-1", Environment: environment, Roles: []string{role}, Generation: 1,
		ID: entityid.Derive("host", "gru", "gru-1-ctl-1"), PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: nkey,
		FailureDomain: "fault-domain-1", Capacity: host.Capacity{CPU: 8, MemoryBytes: 8 << 30, DiskBytes: 16 << 30}}
	if _, err := hosts.Register(ctx, registration); err != nil {
		t.Fatal(err)
	}
	hostCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- hosts.Run(hostCtx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("stop current host controller: %v", err)
		}
	})
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
	nativeRunner := &genericRuntimeNativeRunner{inMemoryRunner: new(inMemoryRunner), stopEntered: make(chan struct{}), allowStop: make(chan struct{})}
	t.Cleanup(nativeRunner.releaseStop)
	session := &genericRuntimeHostSession{nativeRunner: nativeRunner, hosts: hosts, controllerConfig: controllerConfig, registration: registration, config: host.AgentConfig{Cell: "gru", Node: registration.Node,
		Environment: environment, Roles: registration.Roles, Conn: transport.Conn(), Identity: private, NATSUserPublicKey: nkey, ControllerPublicKey: responsePublic,
		Runner: nativeRunner, TaskLoad: taskLoad, PollInterval: 100 * time.Millisecond, InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), WorkloadIdentity: testHostWorkloadIdentity(),
		ClockCheck: func() error { return nil }}}
	session.start(t, ctx, (*host.Agent).Run)
	t.Cleanup(func() { session.stop(t) })
	return session
}

func (session *genericRuntimeHostSession) start(t *testing.T, ctx context.Context, run func(*host.Agent, context.Context) error) {
	t.Helper()
	ready := make(chan struct{})
	config := session.config
	config.Initialized = func() { close(ready) }
	agent, err := host.NewAgent(config)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	session.mu.Lock()
	session.agent, session.ctx, session.cancel, session.done = agent, runCtx, cancel, done
	session.mu.Unlock()
	go func() { done <- run(agent, runCtx) }()
	select {
	case <-ready:
	case err := <-done:
		done <- err // stop still joins this exit
		t.Fatal("signed host session ended before it initialized: ", err)
	case <-ctx.Done():
		t.Fatal("signed host session did not initialize: ", ctx.Err())
	}
	genericRuntimeEventually(t, ctx, func() bool { return session.verify(ctx) == nil })
}

func (session *genericRuntimeHostSession) stop(t *testing.T) {
	t.Helper()
	session.mu.Lock()
	cancel, done := session.cancel, session.done
	session.cancel, session.done = nil, nil
	session.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("stop signed host session: %v", err)
	}
}

func (session *genericRuntimeHostSession) verify(ctx context.Context) error {
	session.mu.Lock()
	current, agent := session.ctx, session.agent
	session.mu.Unlock()
	if current == nil || current.Err() != nil {
		return errors.New("authenticated host session has ended")
	}
	statuses, err := session.hosts.ListHosts(ctx)
	if err != nil || len(statuses) != 1 || !statuses[0].Verified || !time.Now().Before(statuses[0].SessionExpiresAt) {
		return errors.New("current signed host registration/session unavailable")
	}
	return agent.VerifyOwnRegistration(statuses[0].Registration, session.config.ControllerPublicKey)
}

type genericRuntimeLegacyWriter struct{ writes atomic.Int64 }

func retainGenericRuntimeNativeRelease(t *testing.T, ctx context.Context, js jetstream.JetStream, specs *specRegistry,
	fencer *authority.Runtime, codec delivery.Ed25519Codec, profile WorkloadProfile, role, environment, retainedNode string,
) *nativeHistory {
	t.Helper()
	deliveries, err := delivery.Open(ctx, delivery.Config{Conn: js.Conn(), JS: js, Cell: specs.cell, Replicas: 1, ArtifactSigner: codec, ArtifactVerifier: codec,
		AuthorizeArtifact: func(_ context.Context, actor string, record delivery.ArtifactRecord) error {
			if actor != "release" || record.Role != role || record.Environment != environment {
				return delivery.ErrUnauthorized
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("retained native executable bytes before generic-service migration")
	record, err := delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{Cell: specs.cell, Role: role, Environment: environment,
		Source: delivery.ArtifactSource{Repository: "https://example.invalid/api", Commit: strings.Repeat("a", 40), TreeDigest: strings.Repeat("b", 64)}},
		controllerSHA256(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := codec.SignArtifact(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := deliveries.AdmitClaim(ctx, bytes.NewReader(data), claim); err != nil {
		t.Fatal(err)
	}
	entry, err := specs.kv.Get(ctx, cellSpecKey)
	if err != nil {
		t.Fatal(err)
	}
	intent := nativeIntent(record, nativeRelease{Role: role, Replicas: 1, Profile: profile}, 1)
	intent.SchemaVersion, intent.OperationID, intent.AuthorityEpoch = delivery.SchemaVersion, entityid.New(), fencer.Current().Epoch
	binding, err := nativeBinding(intent, record, profile, nativeProfileProvenance{Spec: entry.Value()})
	if err != nil {
		t.Fatal(err)
	}
	binding.Deadline = time.Now().UTC().Add(time.Minute)
	kv, err := openNativeHistory(ctx, js, 1)
	if err != nil {
		t.Fatal(err)
	}
	history := &nativeHistory{kv: kv, js: js, services: specs, deliveries: deliveries, fencer: fencer}
	if err := history.save(ctx, fencer.Current().Epoch, role, nativeReleaseHistory{Schema: 1, Good: []nativeGoodRelease{{Binding: binding, GoodAt: time.Now().UTC(), Nodes: []string{retainedNode}}}}, 0); err != nil {
		t.Fatal(err)
	}
	return history
}

// Remote floors retain independently signed native claims and bytes locally;
// they do not qualify remote regional controllers or production OCI recipients.
func retainGenericRuntimeRegionalClaim(t *testing.T, ctx context.Context, codec delivery.Ed25519Codec, role, environment string) release.SequenceFloor {
	t.Helper()
	data := []byte("retained native executable for " + codec.Cell)
	record, err := delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{Cell: codec.Cell, Role: role, Environment: environment,
		Source: delivery.ArtifactSource{Repository: "https://example.invalid/api", Commit: strings.Repeat("a", 40), TreeDigest: strings.Repeat("b", 64)}},
		controllerSHA256(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := codec.SignArtifact(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	archive := t.TempDir()
	for name, wire := range map[string][]byte{"claim": claim, "artifact": data} {
		if err := os.WriteFile(filepath.Join(archive, name), wire, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	claim, err = os.ReadFile(filepath.Join(archive, "claim"))
	if err != nil {
		t.Fatal(err)
	}
	verified, actor, err := codec.VerifyArchivedArtifact(ctx, claim)
	if err != nil || actor != "release" || verified != record {
		t.Fatalf("verify independent retained regional claim: %+v %q %v", verified, actor, err)
	}
	data, err = os.ReadFile(filepath.Join(archive, "artifact"))
	if err != nil || controllerSHA256(data) != verified.Digest || int64(len(data)) != verified.Size {
		t.Fatal("retained regional artifact differs from signed claim", err)
	}
	issued, err := releasechannel.ClaimIssuedAt(claim)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(claim)
	return release.SequenceFloor{Cell: strings.ToUpper(codec.Cell), IssuedAt: issued, EvidenceSHA256: hex.EncodeToString(digest[:])}
}

func genericRuntimeContainerRelease(t *testing.T, signer functionPublicationSigner, target release.ContainerTarget,
	floors []release.SequenceFloor, sequence uint64, migrationWire []byte,
) (release.ContainerBundle, func(context.Context, string) (io.ReadCloser, error)) {
	t.Helper()
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
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: signer.allocations.Namespace, Bucket: signer.allocations.Bucket,
		Region: "GRU", SignerKeyID: keyID, SignerPublicKey: encoded, Role: target.Role, Environment: target.Environment, SequenceFloor: 100}
	migration.Regions = floors
	var migrationEnvelope trust.Envelope
	if len(migrationWire) == 0 {
		migrationEnvelope, err = release.SignSequenceMigration(migration, now, signer.root)
		if err != nil {
			t.Fatal(err)
		}
		migrationWire, err = trust.EncodeEnvelope(migrationEnvelope)
	} else {
		migrationEnvelope, err = trust.DecodeEnvelope(migrationWire)
	}
	if err != nil {
		t.Fatal(err)
	}
	migrationSHA, err := trust.Fingerprint(migrationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	scope := release.ContainerScope(target)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment,
			Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(2*time.Hour), signer.root)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
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
	claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "example.invalid/api@sha256:" + nativeDigest,
		SourceRepository: "https://example.invalid/api", SourceRevision: qualification.Candidate.SourceRevision, SourceTreeSHA256: strings.Repeat("e", 64),
		Cell: target.Cell, Environment: target.Environment, Role: target.Role, Architecture: target.Architecture, ReleaseSequence: sequence,
		SequenceMigrationSHA256: migrationSHA, QualificationSHA256: qualification.Candidate.QualificationSHA256,
		Production: release.ProductionProof{Qualification: sign(qualification, release.ProductionQualificationScope(qualification.Candidate), signer.root)}}
	if err := signer.allocations.ImportMigration(t.Context(), migrationEnvelope, signer.roots, target.Role, target.Environment, now); err != nil {
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
	return release.ContainerBundle{Claim: sign(claim, scope, signer.leaf), Delegation: delegationWire, Migration: migrationWire, Sequence: sequenceWire, Index: index},
		func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(evidence)), nil
		}
}

func (writer *genericRuntimeLegacyWriter) ApplyDesired(context.Context, host.Desired) (host.Receipt, error) {
	writer.writes.Add(1)
	return host.Receipt{}, errors.New("migrated role reached legacy desired writer")
}

type genericRuntimeExecutor struct {
	mu          sync.Mutex
	controllers map[string]*genericRuntimeTask
	rejectImage string
	nodeID      string
}

func (*genericRuntimeExecutor) Describe(context.Context) (*api.NodeDescription, error) {
	return &api.NodeDescription{Platform: &api.Platform{OS: "linux", Architecture: runtime.GOARCH}, Resources: &api.Resources{NanoCPUs: 8_000_000_000, MemoryBytes: 8 << 30,
		Generic: []*api.GenericResource{genericresource.NewDiscrete(swarmruntime.DiskResource, 16<<30)}}}, nil
}
func (*genericRuntimeExecutor) Configure(context.Context, *api.Node) error         { return nil }
func (*genericRuntimeExecutor) SetNetworkBootstrapKeys([]*api.EncryptionKey) error { return nil }
func (executor *genericRuntimeExecutor) Controller(task *api.Task) (swarmexec.Controller, error) {
	spec, err := swarmruntime.DecodeContainer(task)
	if err != nil {
		return nil, err
	}
	executor.mu.Lock()
	controller := &genericRuntimeTask{done: make(chan struct{}), reject: spec.Image == executor.rejectImage, assignment: task.Copy()}
	executor.controllers[task.ID] = controller
	executor.mu.Unlock()
	return controller, nil
}

// Local controller pins are genuine assignments; this simulated executor has
// no native cgroup measurements, so resource usage stays explicitly unknown.
func (executor *genericRuntimeExecutor) ReadTaskLoad(ctx context.Context) ([]hostload.RoleUsage, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	roles := make(map[string]hostload.RoleUsage)
	for _, id := range slices.Sorted(maps.Keys(executor.controllers)) {
		controller := executor.controllers[id]
		controller.mu.Lock()
		task := controller.assignment.Copy()
		removed := controller.removed
		controller.mu.Unlock()
		if removed || executor.nodeID == "" || task.NodeID != executor.nodeID {
			continue
		}
		select {
		case <-controller.done:
			continue
		default:
		}
		fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
		if err != nil {
			return nil, err
		}
		role := task.ServiceAnnotations.Labels[swarmruntime.LabelRole]
		usage := roles[role]
		usage.Role = role
		usage.Tasks = append(usage.Tasks, hostload.TaskPin{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID, Fingerprint: fingerprint})
		roles[role] = usage
	}
	var result []hostload.RoleUsage
	for _, role := range slices.Sorted(maps.Keys(roles)) {
		result = append(result, roles[role])
	}
	return result, ctx.Err()
}

func (executor *genericRuntimeExecutor) fail(id string) error {
	executor.mu.Lock()
	controller := executor.controllers[id]
	executor.mu.Unlock()
	if controller == nil {
		return errors.New("running task controller is absent")
	}
	controller.failed.Store(true)
	controller.stop()
	return nil
}

type genericRuntimeTask struct {
	mu         sync.Mutex
	assignment *api.Task
	removed    bool
	done       chan struct{}
	once       sync.Once
	failed     atomic.Bool
	reject     bool
}

func (task *genericRuntimeTask) Update(_ context.Context, assignment *api.Task) error {
	task.mu.Lock()
	defer task.mu.Unlock()
	task.assignment = assignment.Copy()
	return nil
}
func (task *genericRuntimeTask) Prepare(context.Context) error {
	if task.reject {
		task.stop()
		return errors.New("application rejected candidate release")
	}
	return nil
}
func (*genericRuntimeTask) Start(context.Context) error { return nil }
func (task *genericRuntimeTask) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-task.done:
		if task.failed.Load() {
			return errors.New("application task failed")
		}
		return nil
	}
}
func (task *genericRuntimeTask) stop()                           { task.once.Do(func() { close(task.done) }) }
func (task *genericRuntimeTask) Shutdown(context.Context) error  { task.stop(); return nil }
func (task *genericRuntimeTask) Terminate(context.Context) error { task.stop(); return nil }
func (task *genericRuntimeTask) Remove(context.Context) error {
	task.mu.Lock()
	defer task.mu.Unlock()
	task.removed = true
	return nil
}
func (task *genericRuntimeTask) Close() error {
	task.mu.Lock()
	defer task.mu.Unlock()
	task.removed = true
	return nil
}

func genericRuntimeNodeConfigAdmission(name, role string) swarmruntime.Admission {
	return swarmruntime.Admission{Region: "sa-saopaulo-1", HostID: name, InstanceID: "ocid1.instance.integration." + name, FounderID: "generic-manager", Role: role}
}

func genericRuntimeNodeConfig(t *testing.T, name, role string) swarmruntime.NodeConfig {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return swarmruntime.NodeConfig{StateDir: t.TempDir(), ListenAddress: address, AdvertiseAddress: address, Admission: genericRuntimeNodeConfigAdmission(name, role)}
}

func startGenericRuntimeNode(t *testing.T, ctx context.Context, config swarmruntime.NodeConfig, executor swarmexec.Executor) *swarmruntime.Node {
	t.Helper()
	node, err := swarmruntime.StartNode(ctx, config, executor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if err := node.Stop(stopCtx); err != nil {
			t.Errorf("stop actual manager: %v", err)
		}
	})
	return node
}

func genericRuntimeEventually(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	for {
		if ready() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual manager did not converge: ", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}
