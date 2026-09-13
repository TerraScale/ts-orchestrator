package ocireconcile

import "terrascale.tech/orchestrator/src/orchestrator/provider"

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

type pollingStageObservation struct{ Ready bool }

type pollingStageReconciler struct {
	passes     int
	readyAfter int
}

func (r *pollingStageReconciler) Observe(context.Context, string) (pollingStageObservation, error) {
	r.passes++
	readyAfter := r.readyAfter
	if readyAfter == 0 {
		readyAfter = 2
	}
	return pollingStageObservation{Ready: r.passes >= readyAfter}, nil
}

func (*pollingStageReconciler) Reconcile(context.Context, string, pollingStageObservation) (OCIPlan, error) {
	return OCIPlan{}, nil
}

func (*pollingStageReconciler) Apply(context.Context, string, pollingStageObservation, OCIPlan) error {
	return nil
}

func (r *pollingStageReconciler) bootstrapConverged(value, _ any) (bool, error) {
	return value.(pollingStageObservation).Ready, nil
}

func TestConvergeStagePollsEmptyPendingPlans(t *testing.T) {
	reconciler := &pollingStageReconciler{}
	if err := convergeStage(context.Background(), "poll", reconciler, "declared", nil, BootstrapConvergenceConfig{Deadline: time.Second, MaxPasses: 4, PollInitial: time.Millisecond, PollMaximum: 2 * time.Millisecond}); err != nil {
		t.Fatalf("convergeStage failed: %v", err)
	}
	if reconciler.passes != 2 {
		t.Fatalf("observe passes = %d, want 2", reconciler.passes)
	}
}

func TestConvergeStageDeadlineIsRetryableAndPreservesCause(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	reconciler := &pollingStageReconciler{readyAfter: 1000}
	err := convergeStage(ctx, "deadline", reconciler, "declared", nil, BootstrapConvergenceConfig{
		Deadline: 500 * time.Millisecond, MaxPasses: 100, PollInitial: time.Millisecond, PollMaximum: 2 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("convergeStage unexpectedly converged")
	}
	var unknown *provider.ProviderOutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("deadline error = %v, want retryable unknown outcome", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error = %v, want context deadline cause", err)
	}
	if strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("deadline error leaked provider detail: %v", err)
	}
}

func TestBootstrapConvergenceConfigRejectsInvalidBounds(t *testing.T) {
	request := bootstrapTestRequest(t)
	request.Convergence.PollMaximum = time.Millisecond
	request.Convergence.PollInitial = 2 * time.Millisecond
	if err := request.validate(); err == nil {
		t.Fatal("invalid polling bounds accepted")
	}
	if got := classifyBootstrapOutcome(&provider.ProviderOutcomeUnknownError{Message: "accepted"}); got.Error() != "accepted" {
		t.Fatalf("known unknown outcome was rewritten: %v", got)
	}
	request.Convergence = BootstrapConvergenceConfig{MaxPasses: bootstrapMaximumPasses + 1}
	if err := request.validate(); err == nil {
		t.Fatal("unbounded pass budget accepted")
	}
}

func TestBootstrapCredentialsFromEnvFailsLoudly(t *testing.T) {
	_, err := BootstrapCredentialsFromEnv(func(string) (string, bool) { return "", false })
	if err == nil {
		t.Fatal("missing credentials accepted")
	}
	message := err.Error()
	for _, name := range []string{OCITenancyEnvironment, OCIUserEnvironment, OCIFingerprintEnvironment, OCIPrivateKeyEnvironment, OCIRegionEnvironment} {
		if !strings.Contains(message, name) {
			t.Fatalf("error %q does not name %s", message, name)
		}
	}
	credentials, err := BootstrapCredentialsFromEnv(func(name string) (string, bool) {
		switch name {
		case OCITenancyEnvironment:
			return "ocid1.tenancy.oc1.aaaa", true
		case OCIUserEnvironment:
			return "ocid1.user.oc1.aaaa", true
		case OCIFingerprintEnvironment:
			return strings.Repeat("ab", 16), true
		case OCIPrivateKeyEnvironment:
			return "/etc/oci/key.pem", true
		case OCIRegionEnvironment:
			return "sa-saopaulo-1", true
		default:
			return "", false
		}
	})
	if err != nil {
		t.Fatalf("complete credentials rejected: %v", err)
	}
	if got := credentials.SigningKeyID(); got != "ocid1.tenancy.oc1.aaaa/ocid1.user.oc1.aaaa/"+strings.Repeat("ab", 16) {
		t.Fatalf("SigningKeyID() = %q", got)
	}
}

func bootstrapTestRequest(t *testing.T) BootstrapRequest {
	t.Helper()
	region, err := DefaultBootstrapRegion()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := testTSNodeCloudInit("1.0.0", strings.Repeat("a", 64), "https://git.terrascale.tech/releases/ts-node-1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return BootstrapRequest{
		HostCloudInit:   map[int]string{1: seed, 2: seed},
		WorkerCloudInit: map[int]string{1: seed, 2: seed},
		Region:          region,
		CompartmentName: "terrascale",
		ImageID:         "ocid1.image.oc1.x",
		Convergence:     BootstrapConvergenceConfig{Deadline: time.Second, MaxPasses: 8, PollInitial: time.Millisecond, PollMaximum: 4 * time.Millisecond},
	}
}

// allGatewayFakes composes one fake per service with shared compute state so
// the stages feed each other exactly like the real gateways do.
type allGatewayFakes struct {
	network *fakeNetworkGateway
	compute *fakeComputeGateway
	block   *fakeBlockGateway
	object  *fakeObjectGateway
	vault   *fakeVaultGateway
}

func newAllGatewayFakes() *allGatewayFakes {
	return &allGatewayFakes{
		network: &fakeNetworkGateway{rules: map[string][]ObservedSecurityRule{}},
		compute: &fakeComputeGateway{},
		block:   &fakeBlockGateway{},
		object:  &fakeObjectGateway{namespace: "ts-ns", buckets: map[string]ObservedBucket{}},
		vault:   &fakeVaultGateway{activate: true},
	}
}

func (f *allGatewayFakes) gateways() BootstrapGateways {
	return BootstrapGateways{Network: f.network, Compute: f.compute, Block: f.block, Object: f.object, Vault: f.vault}
}

func TestRunOCIBootstrapConvergesFromEmpty(t *testing.T) {
	request := bootstrapTestRequest(t)
	fakes := newAllGatewayFakes()
	var log strings.Builder
	if err := RunOCIBootstrap(context.Background(), request, fakes.gateways(), &log); err != nil {
		t.Fatalf("bootstrap failed: %v\nprogress:\n%s", err, log.String())
	}
	if len(fakes.compute.members) != int(request.Region.Members.Count+request.Region.Workers.Count) {
		t.Fatalf("compute hosts = %d, want %d", len(fakes.compute.members), request.Region.Members.Count+request.Region.Workers.Count)
	}
	if len(fakes.block.volumes) != int(request.Region.Members.Count) || len(fakes.block.attachments) != int(request.Region.Members.Count) {
		t.Fatalf("volumes = %d, attachments = %d, want two of each", len(fakes.block.volumes), len(fakes.block.attachments))
	}
	if len(fakes.object.buckets) != len(request.Region.Buckets) {
		t.Fatalf("buckets = %d, want %d", len(fakes.object.buckets), len(request.Region.Buckets))
	}
	for name, bucket := range fakes.object.buckets {
		if !bucket.Versioning || len(bucket.LifecycleRules) == 0 {
			t.Fatalf("bucket %s = %+v, want versioned with lifecycle rules", name, bucket)
		}
	}
	if fakes.vault.vault == nil || len(fakes.vault.keys) != len(request.Region.VaultKeys) {
		t.Fatalf("vault = %+v, keys = %d, want one vault with %d keys", fakes.vault.vault, len(fakes.vault.keys), len(request.Region.VaultKeys))
	}
	if len(fakes.network.subnets) != len(request.Region.Network.Subnets) || len(fakes.network.nsgs) != len(request.Region.Network.SecurityGroups) {
		t.Fatalf("subnets = %d, nsgs = %d", len(fakes.network.subnets), len(fakes.network.nsgs))
	}
	for _, launch := range fakes.compute.launches {
		decoded := launch.CloudInitBase64
		if decoded == "" {
			t.Fatal("launched member carries no cloud-init")
		}
	}
}

func TestRunOCIBootstrapIsIdempotent(t *testing.T) {
	request := bootstrapTestRequest(t)
	fakes := newAllGatewayFakes()
	ctx := context.Background()
	if err := RunOCIBootstrap(ctx, request, fakes.gateways(), nil); err != nil {
		t.Fatalf("first bootstrap failed: %v", err)
	}
	launches := len(fakes.compute.launches)
	creates := len(fakes.block.volumes)
	if err := RunOCIBootstrap(ctx, request, fakes.gateways(), nil); err != nil {
		t.Fatalf("second bootstrap failed: %v", err)
	}
	if len(fakes.compute.launches) != launches || len(fakes.block.volumes) != creates {
		t.Fatalf("second bootstrap created resources: launches %d→%d, volumes %d→%d", launches, len(fakes.compute.launches), creates, len(fakes.block.volumes))
	}
}

func TestRunOCIBootstrapRefusesIncompleteRequest(t *testing.T) {
	request := bootstrapTestRequest(t)
	request.ImageID = ""
	if err := RunOCIBootstrap(context.Background(), request, newAllGatewayFakes().gateways(), nil); err == nil {
		t.Fatal("bootstrap without an image accepted")
	}
	request = bootstrapTestRequest(t)
	request.HostCloudInit = nil
	err := RunOCIBootstrap(context.Background(), request, newAllGatewayFakes().gateways(), nil)
	if err == nil {
		t.Fatal("bootstrap without a ts-node release accepted")
	}
	var argument *errs.Argument
	if !errors.As(err, &argument) {
		t.Fatalf("bootstrap request error = %v, want argument error", err)
	}
}

func TestDefaultBootstrapRegionMatchesEstateHome(t *testing.T) {
	region, err := DefaultBootstrapRegion()
	if err != nil {
		t.Fatal(err)
	}
	spec := estate.Default()
	if region.Code != spec.HomeRegion || region.Members.Count < provider.PlacementMinimumMemberHosts {
		t.Fatalf("bootstrap region = %+v, want the estate home region with two members", region)
	}
}
