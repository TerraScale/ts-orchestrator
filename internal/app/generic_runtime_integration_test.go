package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	swarmexec "github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
)

// This is a local authority simulation: signed profile/release, OCI SDK CAS,
// broker, manager, dispatcher, scheduler, task repair and HTTP are real. The
// supplied application probe substitutes the external OCI recipient source;
// native execution and the production recipient adapter remain separate gates.
func TestGenericRuntimeSignedManagerIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 240*time.Second)
	defer cancel()
	auth := newAuthenticatedNATS(t, "gru")
	broker, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
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
	session := startGenericRuntimeHostSession(t, ctx, auth, broker, fencer, policy.Role, identity.Environment)
	executor := &genericRuntimeExecutor{controllers: map[string]*genericRuntimeTask{}}
	managerConfig := genericRuntimeNodeConfig(t, "generic-manager", "manager")
	managerConfig.Admission.HostID, managerConfig.Admission.FounderID = session.registration.ID, session.registration.ID
	manager := startGenericRuntimeNode(t, ctx, managerConfig, executor)
	client, err := manager.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := swarmruntime.AdmitNode(ctx, client, manager.ID(), managerConfig.Admission); err != nil {
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
	legacyFloor, err := history.retainedContainerFloor(ctx, policy.Role, identity.Environment)
	if err != nil {
		t.Fatal(err)
	}
	floors := []release.SequenceFloor{legacyFloor}
	for _, cell := range []string{"sfo", "fra"} {
		regionalCodec := codec
		regionalCodec.Cell = cell
		floors = append(floors, retainGenericRuntimeRegionalClaim(t, ctx, regionalCodec, policy.Role, identity.Environment))
	}
	bundle, evidence := genericRuntimeContainerRelease(t, signer, target, floors, 101, nil)
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
	probe := func(ctx context.Context, task *api.Task) error {
		if err := session.verify(ctx); err != nil {
			return err
		}
		node, err := probeClient.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
		if err != nil || node.Node.Spec.Annotations.Name != session.registration.ID || node.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != managerConfig.Admission.InstanceID {
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
		if err := swarmruntime.VerifyRegistryTask(ctx, probeClient, task, expected, verified, specs.roots.current()); err != nil {
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
		if err := swarmruntime.VerifyRegistryTask(ctx, probeClient, task, expected, verified, specs.roots.current()); err != nil {
			return err
		}
		return session.verify(ctx)
	}
	var controller *genericRuntime
	var activeRuntime atomic.Pointer[genericRuntime]
	writer := new(genericRuntimeLegacyWriter)
	deliveries, err = delivery.Open(ctx, delivery.Config{Conn: broker.Conn(), JS: broker.JetStream(), Cell: identity.Cell, Replicas: 1,
		Signer: codec, Verifier: codec, Fencer: fencer, Writer: writer,
		Authorize: func(_ context.Context, actor string, proposed delivery.Intent) error {
			if actor != "release" || proposed.Role != policy.Role || proposed.Environment != identity.Environment {
				return delivery.ErrUnauthorized
			}
			return nil
		}, ContainerApply: func(ctx context.Context, intent delivery.Intent) error {
			return activeRuntime.Load().apply(ctx, intent)
		}})
	if err != nil {
		t.Fatal(err)
	}
	signals := autoscale.NewWindowStore(0, 0)
	controller, err = newGenericRuntime(genericRuntimeConfig{Client: client, ManagerID: manager.ID(), Authority: fencer, Specs: specs,
		Delivery: deliveries, Factory: signer.factory, Evidence: func(ctx context.Context, _ string, digest string) (io.ReadCloser, error) {
			return evidence(ctx, digest)
		}, Probe: probe, RetainedFloor: history.retainedContainerFloor, SessionGuard: session.verify}, signals)
	if err != nil {
		t.Fatal(err)
	}
	activeRuntime.Store(controller)
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
	genericRuntimeEventually(t, ctx, func() bool {
		receipt, err := deliveries.Status(ctx, intent.OperationID)
		return err == nil && receipt.Status == "accepted"
	})
	listed, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil || len(listed.Services) != 1 {
		t.Fatalf("signed application submission: %+v %v", listed, err)
	}
	serviceID := listed.Services[0].ID
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
	first := ready(1)
	if err := controller.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	scaleTarget := autoscale.Target{Cell: identity.Cell, Environment: identity.Environment, Role: policy.Role}
	signals.Record(scaleTarget, autoscale.SignalCPUUtilization, autoscale.Sample{At: time.Now(), Value: 1})
	if err := controller.scaler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	ready(2)
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
		return next
	}
	next := rollout(102)
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
	ready(2)
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
	ready(2)
	current, err = client.GetService(ctx, &api.GetServiceRequest{ServiceID: serviceID})
	if err != nil || current.Service.Spec.Task.Resources.Limits.NanoCPUs != int64(profile.Resources.CPU)*1_000_000_000 || current.Service.Spec.Task.Resources.Reservations.MemoryBytes != profile.Resources.MemoryBytes {
		t.Fatalf("rollout/rollback/recovery changed exact signed resource request: %+v %v", current, err)
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
	if err := controller.refresh(ctx); err == nil || len(controller.scaler.Last()) != 0 {
		t.Fatalf("ended authenticated session retained scaling authority: %+v %v", controller.scaler.Last(), err)
	}
	session.start(t, ctx)
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
	floors, err := client.ListConfigs(ctx, &api.ListConfigsRequest{})
	if err != nil || len(floors.Configs) == 0 {
		t.Fatal("actual election lost durable release ordering", err)
	}
	adopt(4, nil)
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
	retained, err := history.retainedContainerFloor(ctx, policy.Role, identity.Environment)
	if err != nil || retained != legacyFloor {
		t.Fatalf("generic drain/removal changed original native release evidence: %+v %v", retained, err)
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

type genericRuntimeHostSession struct {
	mu           sync.Mutex
	config       host.AgentConfig
	registration host.Registration
	hosts        *host.Controller
	agent        *host.Agent
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan error
}

func startGenericRuntimeHostSession(t *testing.T, ctx context.Context, auth *authenticatedNATS, broker *natscell.Runtime,
	fencer *authority.Runtime, role, environment string,
) *genericRuntimeHostSession {
	t.Helper()
	responsePublic, responseKey := testEd25519(t, t.TempDir(), "generic-response.key")
	public, private := testEd25519(t, t.TempDir(), "generic-host.key")
	nkey, seed := testNKey(t)
	artifacts, err := broker.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := host.NewController(ctx, host.ControllerConfig{Cell: "gru", Conn: broker.Conn(), JS: broker.JetStream(), Artifacts: artifacts,
		StateReplicas: 1, ResponseKey: responseKey, HostMutations: fencer, AuthorityEpoch: func() uint64 { return fencer.Current().Epoch }, AuthorityGuard: fencer.Guard})
	if err != nil {
		t.Fatal(err)
	}
	registration := host.Registration{Cell: "gru", Node: "generic-manager", Environment: environment, Roles: []string{role}, Generation: 1,
		ID: entityid.Derive("host", "gru", "generic-manager"), PublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: nkey,
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
	session := &genericRuntimeHostSession{hosts: hosts, registration: registration, config: host.AgentConfig{Cell: "gru", Node: registration.Node,
		Environment: environment, Roles: registration.Roles, Conn: transport.Conn(), Identity: private, NATSUserPublicKey: nkey, ControllerPublicKey: responsePublic,
		Runner: &inMemoryRunner{}, InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), WorkloadIdentity: testHostWorkloadIdentity(),
		ClockCheck: func() error { return nil }}}
	session.start(t, ctx)
	t.Cleanup(func() { session.stop(t) })
	return session
}

func (session *genericRuntimeHostSession) start(t *testing.T, ctx context.Context) {
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
	go func() { done <- agent.RunSession(runCtx) }()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("signed host session did not initialize: ", ctx.Err())
	}
	if err := session.verify(ctx); err != nil {
		t.Fatal(err)
	}
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
}

func (*genericRuntimeExecutor) Describe(context.Context) (*api.NodeDescription, error) {
	return &api.NodeDescription{Platform: &api.Platform{OS: "linux", Architecture: runtime.GOARCH}, Resources: &api.Resources{NanoCPUs: 8_000_000_000, MemoryBytes: 8 << 30}}, nil
}
func (*genericRuntimeExecutor) Configure(context.Context, *api.Node) error         { return nil }
func (*genericRuntimeExecutor) SetNetworkBootstrapKeys([]*api.EncryptionKey) error { return nil }
func (executor *genericRuntimeExecutor) Controller(task *api.Task) (swarmexec.Controller, error) {
	spec, err := swarmruntime.DecodeContainer(task)
	if err != nil {
		return nil, err
	}
	executor.mu.Lock()
	controller := &genericRuntimeTask{done: make(chan struct{}), reject: spec.Image == executor.rejectImage}
	executor.controllers[task.ID] = controller
	executor.mu.Unlock()
	return controller, nil
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
	done   chan struct{}
	once   sync.Once
	failed atomic.Bool
	reject bool
}

func (*genericRuntimeTask) Update(context.Context, *api.Task) error { return nil }
func (task *genericRuntimeTask) Prepare(context.Context) error {
	if task.reject {
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
func (*genericRuntimeTask) Remove(context.Context) error         { return nil }
func (*genericRuntimeTask) Close() error                         { return nil }

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
