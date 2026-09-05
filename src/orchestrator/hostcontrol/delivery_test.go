package hostcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nats-io/nats.go"
	"strings"
	"sync"
	"sync/atomic"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

func releaseFixture(t *testing.T, version, digest string) Release {
	t.Helper()
	component, err := hostmanifest.NewComponentSpec(hostmanifest.ComponentSpec{Name: "terrabase", Version: version, Sha256: digest, ArtifactURL: "https://releases.example/terrabase", SignatureURL: "https://releases.example/terrabase.sig", User: "terrabase", DataVolume: "/var/lib/terrabase", CPUWeight: 100, MemoryMaxBytes: 1 << 30, IOWeight: 100})
	if err != nil {
		t.Fatal(err)
	}
	return Release{Manifest: hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{component}}, ExpectedManifestSHA: strings.Repeat("a", 64), Architecture: runtimeplan.HostArchitectureX64}
}
func deliveryPlan(t *testing.T, digest string) []byte {
	t.Helper()
	allocation, _ := runtimeplan.NewRuntimeAllocationId("terrabase")
	artifact, _ := runtimeplan.NewArtifactDigest(digest)
	plan, err := runtimeplan.NewHostRuntimePlan(runtimeplan.AdmittedRoleTerraBaseMember, runtimeplan.RuntimeDriverNativeSystemd, allocation, artifact, runtimeplan.HostArchitectureX64, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := plan.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func fencedContext(t *testing.T, check delivery.FenceChecker) context.Context {
	t.Helper()
	if check == nil {
		check = func(delivery.OperationFence) error { return nil }
	}
	ctx, err := delivery.WithExecutionFence(context.Background(), delivery.OperationFence{OperationID: "operation-1", RequestDigest: strings.Repeat("b", 64), OwnerID: "controller-1", Generation: 1}, check)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestDeliveryConvergesExactManifestAndReplayUsesFreshFacts(t *testing.T) {
	connection, node := authenticatedConnections(t)
	client := testClient(t, connection, nil)
	release := releaseFixture(t, "1.0", strings.Repeat("c", 64))
	plan := deliveryPlan(t, strings.Repeat("c", 64))
	desiredDigest, _ := hostmanifest.HostManifestSha256(release.Manifest)
	var mu sync.Mutex
	current := statusFacts("")
	var applyCount, deployCount, drainCount atomic.Int32
	subscribe(t, node, "ts.orch.v1.gru.agent.*.command.*", func(message *nats.Msg) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(message.Subject, ".drain-status"):
			var command hostagent.NodeStatusRequest
			_ = json.Unmarshal(message.Data, &command)
			report := current
			report.CommandId = command.CommandId
			respondJSON(message, report)
		case strings.HasSuffix(message.Subject, ".apply-manifest"):
			applyCount.Add(1)
			var command hostmanifest.ApplyManifestCommand
			_ = json.Unmarshal(message.Data, &command)
			if command.ExpectedManifestSha256 != current.Facts.ManifestSha256 {
				respondJSON(message, hostagent.NewCommandEnvelopeError("CAS conflict"))
				return
			}
			digest, _ := hostmanifest.HostManifestSha256(command.Manifest)
			current.Facts.ManifestSha256 = digest
			spec := command.Manifest.Components[0]
			current.Facts.Components = []hostagent.ComponentFact{{Name: spec.Name, Version: "0.9", Desired: spec.Version, Installed: true, UnitActive: false}}
			receipt, _ := hostagent.NewManifestReceipt(command.CommandId, "gru-1", true, digest, "")
			respondJSON(message, receipt)
		case strings.HasSuffix(message.Subject, ".deploy"):
			deployCount.Add(1)
			var command hostagent.DeployCommand
			_ = json.Unmarshal(message.Data, &command)
			current.Facts.Components[0].Version = command.Version
			current.Facts.Components[0].UnitActive = true
			current.Quiesced = false
			receipt, _ := hostagent.NewDeployReceipt(command.CommandId, "gru-1", true, command.Version, "")
			respondJSON(message, receipt)
		case strings.HasSuffix(message.Subject, ".drain"):
			drainCount.Add(1)
			var command hostagent.DrainCommand
			_ = json.Unmarshal(message.Data, &command)
			current.State = hostagent.NodeStateServing
			if command.Drain {
				current.State = hostagent.NodeStateDraining
			}
			current.Facts.State = current.State
			current.Quiesced = command.Drain
			for i := range current.Facts.Components {
				current.Facts.Components[i].UnitActive = !command.Drain
			}
			receipt, _ := hostagent.NewDrainReceipt(command.CommandId, "gru-1", command.Drain, command.Drain, "")
			respondJSON(message, receipt)
		}
	})
	control, err := NewDeliveryControl(DeliveryConfig{Client: client, ResolveRelease: func(context.Context, string, runtimeplan.HostRuntimePlan) (Release, error) { return release, nil }, Timeout: time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx := fencedContext(t, nil)
	for range 2 {
		if err := control.Converge(ctx, "gru-1", plan); err != nil {
			t.Fatal(err)
		}
	}
	if applyCount.Load() != 1 || deployCount.Load() != 1 || drainCount.Load() != 0 {
		t.Fatalf("replay remutated host: manifest%d deploy%d drain%d", applyCount.Load(), deployCount.Load(), drainCount.Load())
	}
	if err := control.Cordon(ctx, "gru-1", false); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if current.Facts.ManifestSha256 != desiredDigest || current.Facts.Components[0].Version != "1.0" || current.State != hostagent.NodeStateServing {
		t.Fatalf("host did not converge: %+v", current)
	}
	mu.Unlock()
	// Rollback receives an explicit admitted rollback release, drains again,
	// CASes the complete desired manifest and deploys that exact version.
	release = releaseFixture(t, "0.9", strings.Repeat("d", 64))
	release.ExpectedManifestSHA = desiredDigest
	if err := control.Converge(ctx, "gru-1", deliveryPlan(t, strings.Repeat("d", 64))); err != nil {
		t.Fatal(err)
	}
	if applyCount.Load() != 2 || deployCount.Load() != 2 || drainCount.Load() != 2 {
		t.Fatalf("rollback effects: manifest%d deploy%d drain%d", applyCount.Load(), deployCount.Load(), drainCount.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if current.Facts.Components[0].Version != "0.9" || !current.Facts.Components[0].UnitActive {
		t.Fatal("rollback did not activate exact release")
	}
}

func TestDeliveryRefusesMissingFenceWrongMappingAndLostAuthority(t *testing.T) {
	connection, node := authenticatedConnections(t)
	client := testClient(t, connection, nil)
	release := releaseFixture(t, "1.0", strings.Repeat("c", 64))
	plan := deliveryPlan(t, strings.Repeat("c", 64))
	var mutations atomic.Int32
	subscribe(t, node, "ts.orch.v1.gru.agent.*.command.*", func(message *nats.Msg) {
		if strings.HasSuffix(message.Subject, ".drain-status") {
			var command hostagent.NodeStatusRequest
			_ = json.Unmarshal(message.Data, &command)
			respondJSON(message, statusFacts(command.CommandId))
		} else {
			mutations.Add(1)
		}
	})
	control, err := NewDeliveryControl(DeliveryConfig{Client: client, ResolveRelease: func(context.Context, string, runtimeplan.HostRuntimePlan) (Release, error) { return release, nil }, Timeout: time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := control.Cordon(context.Background(), "gru-1", true); err == nil {
		t.Fatal("cordon without execution fence")
	}
	if err := control.Converge(context.Background(), "gru-1", plan); err == nil {
		t.Fatal("converge without execution fence")
	}
	if err := control.Converge(fencedContext(t, func(delivery.OperationFence) error { return errors.New("fence lost") }), "gru-1", plan); err == nil {
		t.Fatal("converge despite lost fence")
	}
	release.Manifest.Components[0].Sha256 = strings.Repeat("d", 64)
	if err := control.Converge(fencedContext(t, nil), "gru-1", plan); err == nil {
		t.Fatal("converge mismatched release digest")
	}
	if mutations.Load() != 0 {
		t.Fatal("refused operation published a mutation")
	}
}

func TestDeliveryRechecksOperationFenceAtPublication(t *testing.T) {
	connection, node := authenticatedConnections(t)
	var live atomic.Bool
	live.Store(true)
	client := testClient(t, connection, func(context.Context, Host) error { live.Store(false); return nil })
	var publications atomic.Int32
	subscribe(t, node, "ts.orch.v1.gru.agent.*.command.*", func(*nats.Msg) { publications.Add(1) })
	control, err := NewDeliveryControl(DeliveryConfig{Client: client, ResolveRelease: func(context.Context, string, runtimeplan.HostRuntimePlan) (Release, error) {
		return Release{}, errors.New("not used")
	}, Timeout: time.Second, PollInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx := fencedContext(t, func(delivery.OperationFence) error {
		if !live.Load() {
			return errors.New("operation taken over")
		}
		return nil
	})
	if err := control.Cordon(ctx, "gru-1", true); err == nil {
		t.Fatal("published after operation takeover")
	}
	if publications.Load() != 0 {
		t.Fatal("revoked operation reached NATS")
	}
}
