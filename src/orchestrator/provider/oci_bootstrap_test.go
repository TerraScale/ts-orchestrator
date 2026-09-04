package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

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
	return BootstrapRequest{
		Region:          region,
		CompartmentName: "terrascale",
		ImageID:         "ocid1.image.oc1.x",
		TSNodeVersion:   "1.0.0",
		TSNodeSHA256:    strings.Repeat("a", 64),
		TSNodeURL:       "https://git.terrascale.tech/releases/ts-node-1.0.0",
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
	if len(fakes.compute.members) != int(request.Region.Members.Count) {
		t.Fatalf("members = %d, want %d", len(fakes.compute.members), request.Region.Members.Count)
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
	request.TSNodeURL = "not-a-url"
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
	if region.Code != spec.HomeRegion || region.Members.Count < PlacementMinimumMemberHosts {
		t.Fatalf("bootstrap region = %+v, want the estate home region with two members", region)
	}
}
