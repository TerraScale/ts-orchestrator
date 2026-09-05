package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

func testComputeRegion() estate.Region {
	region := testNetworkRegion()
	region.Members = estate.MemberPool{
		Count:         2,
		PrimaryShape:  "VM.Standard.A1.Flex",
		FallbackShape: "VM.Standard.E5.Flex",
		OCPUs:         2,
		MemoryGiB:     12,
		BootVolumeGiB: 50,
		DataVolumeGiB: 200,
	}
	return region
}

func testComputeDeclared(t *testing.T) ComputeDeclared {
	t.Helper()
	cloudInit, err := testTSNodeCloudInit("v1", strings.Repeat("a", 64), "https://git.terrascale.tech/TerraScale/ts-orchestrator/releases/download/v1/ts-node")
	if err != nil {
		t.Fatal(err)
	}
	return ComputeDeclared{Region: testComputeRegion(), ImageID: "ocid1.image.oc1.arm64", FallbackImageID: "ocid1.image.oc1.amd64", CloudInitByMember: map[int]string{1: cloudInit, 2: cloudInit}}
}

// fakeComputeGateway models member instances with shape capacity behavior.
type fakeComputeGateway struct {
	members      []ObservedMember
	ads          []string
	noCapacity   map[string]bool // shape → out of capacity
	quotaReject  bool
	launches     []MemberLaunchSpec
	starts       []string
	terminations []string
	nextSuffix   int
}

func (f *fakeComputeGateway) ListAvailabilityDomains(ctx context.Context) ([]string, error) {
	if len(f.ads) > 0 {
		return f.ads, nil
	}
	return []string{"AD-1", "AD-2"}, nil
}

func (f *fakeComputeGateway) ListMembers(ctx context.Context) ([]ObservedMember, error) {
	return f.members, nil
}

func (f *fakeComputeGateway) LaunchMember(ctx context.Context, spec MemberLaunchSpec) (ObservedMember, error) {
	f.launches = append(f.launches, spec)
	if f.quotaReject {
		return ObservedMember{}, &OCIQuotaError{Code: "LimitExceeded"}
	}
	if f.noCapacity[spec.Shape] {
		return ObservedMember{}, &OCIShapeCapacityError{Shape: spec.Shape}
	}
	f.nextSuffix++
	launched := ObservedMember{ID: "ocid1.instance.oc1.x." + string(rune('a'+f.nextSuffix)), DisplayName: spec.DisplayName, Index: spec.Index, Shape: spec.Shape, LifecycleState: "RUNNING", AvailabilityDomain: spec.AvailabilityDomain, FreeformTags: testMemberOwnershipTags("gru")}
	f.members = append(f.members, launched)
	return launched, nil
}

func (f *fakeComputeGateway) StartMember(ctx context.Context, instanceID string) error {
	f.starts = append(f.starts, instanceID)
	for i := range f.members {
		if f.members[i].ID == instanceID {
			f.members[i].LifecycleState = "RUNNING"
		}
	}
	return nil
}

func (f *fakeComputeGateway) TerminateMember(ctx context.Context, instanceID string) error {
	f.terminations = append(f.terminations, instanceID)
	remaining := f.members[:0]
	for _, member := range f.members {
		if member.ID != instanceID {
			remaining = append(remaining, member)
		}
	}
	f.members = remaining
	return nil
}

func (f *fakeComputeGateway) addMember(id string, index int, shape, state string) {
	f.members = append(f.members, ObservedMember{ID: id, DisplayName: MemberDisplayName("gru", index), Index: index, Shape: shape, LifecycleState: state, AvailabilityDomain: "AD-1", FreeformTags: testMemberOwnershipTags("gru")})
}

func testMemberOwnershipTags(region string) map[string]string {
	return map[string]string{OCIManagedTag: ManagedMemberTagValue, OCIScopeTag: region}
}

func testOwnedMember(region string, index int, shape, state, availabilityDomain string) ObservedMember {
	return ObservedMember{
		ID: "ocid1.instance.oc1.x." + strconv.Itoa(index), DisplayName: MemberDisplayName(region, index),
		Index: index, Shape: shape, LifecycleState: state, AvailabilityDomain: availabilityDomain,
		FreeformTags: testMemberOwnershipTags(region),
	}
}

func testComputeObserved() ComputeObserved {
	vcn := &ObservedVCN{ID: "ocid1.vcn.oc1.x", DisplayName: "terrascale-gru", CIDR: "10.0.0.0/16", LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "vcn")}
	return ComputeObserved{
		AvailabilityDomains: []string{"AD-1", "AD-2"},
		Subnets:             []ObservedSubnet{{ID: "ocid1.subnet.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", CIDR: "10.0.1.0/24", LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "subnet")}},
		NSGs:                []ObservedNSG{{ID: "ocid1.networksecuritygroup.oc1.x", VCNID: vcn.ID, DisplayName: "gru-members", LifecycleState: "AVAILABLE", FreeformTags: networkOwnershipTags("gru", "networksecuritygroup")}},
	}
}

func TestComputeReconcilePlans(t *testing.T) {
	declared := testComputeDeclared(t)
	cases := []struct {
		name      string
		observed  ComputeObserved
		wantKinds []OCIActionKind
	}{
		{
			name:      "empty region plans both members",
			observed:  testComputeObserved(),
			wantKinds: []OCIActionKind{OCIActionLaunchMember, OCIActionLaunchMember},
		},
		{
			name: "converged region plans nothing",
			observed: func() ComputeObserved {
				observed := testComputeObserved()
				observed.Members = []ObservedMember{
					testOwnedMember("gru", 1, "VM.Standard.A1.Flex", "RUNNING", "AD-1"),
					testOwnedMember("gru", 2, "VM.Standard.E5.Flex", "RUNNING", "AD-2"),
				}
				return observed
			}(),
			wantKinds: nil,
		},
		{
			name: "stopped member plans a start",
			observed: func() ComputeObserved {
				observed := testComputeObserved()
				observed.Members = []ObservedMember{
					testOwnedMember("gru", 1, "VM.Standard.A1.Flex", "RUNNING", "AD-1"),
					testOwnedMember("gru", 2, "VM.Standard.A1.Flex", "STOPPED", "AD-2"),
				}
				return observed
			}(),
			wantKinds: []OCIActionKind{OCIActionStartMember},
		},
		{
			name: "undeclared shape plans a replace",
			observed: func() ComputeObserved {
				observed := testComputeObserved()
				observed.Members = []ObservedMember{
					testOwnedMember("gru", 1, "VM.Standard.E5.Flex", "RUNNING", "AD-1"),
					testOwnedMember("gru", 2, "VM.Standard.X9.Flex", "RUNNING", "AD-2"),
				}
				return observed
			}(),
			wantKinds: []OCIActionKind{OCIActionTerminateMember, OCIActionLaunchMember},
		},
		{
			name: "member beyond the pool terminates",
			observed: func() ComputeObserved {
				observed := testComputeObserved()
				observed.Members = []ObservedMember{
					testOwnedMember("gru", 1, "VM.Standard.A1.Flex", "RUNNING", "AD-1"),
					testOwnedMember("gru", 2, "VM.Standard.A1.Flex", "RUNNING", "AD-1"),
					testOwnedMember("gru", 3, "VM.Standard.A1.Flex", "RUNNING", "AD-1"),
				}
				return observed
			}(),
			wantKinds: []OCIActionKind{OCIActionTerminateMember},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler := &ComputeReconciler{Compute: &fakeComputeGateway{}, Network: &fakeNetworkGateway{}}
			plan, err := reconciler.Reconcile(context.Background(), declared, tc.observed)
			if err != nil {
				t.Fatalf("Reconcile() failed: %v", err)
			}
			got := plan.Kinds()
			if len(got) != len(tc.wantKinds) {
				t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
			}
			for i := range got {
				if got[i] != tc.wantKinds[i] {
					t.Fatalf("Reconcile() kinds = %v, want %v", got, tc.wantKinds)
				}
			}
		})
	}
}

func TestComputeApplyPreservesUnownedAndStaleMembers(t *testing.T) {
	declared := testComputeDeclared(t)
	owned := testOwnedMember("gru", 3, declared.Region.Members.PrimaryShape, "RUNNING", "AD-1")
	foreign := owned
	foreign.FreeformTags = nil
	foreign.Shape = "VM.Standard.X9.Flex"
	gateway := &fakeComputeGateway{members: []ObservedMember{foreign}}
	reconciler := &ComputeReconciler{Compute: gateway, Network: &fakeNetworkGateway{}}
	reconcilePlan, err := reconciler.Reconcile(context.Background(), declared, ComputeObserved{Members: []ObservedMember{foreign}, Subnets: testComputeObserved().Subnets, NSGs: testComputeObserved().NSGs})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range reconcilePlan.Actions {
		if action.Kind() == OCIActionTerminateMember {
			t.Fatalf("unowned member produced termination action: %v", reconcilePlan.Kinds())
		}
	}
	plan := OCIPlan{Actions: []OCIAction{TerminateMemberAction{InstanceID: owned.ID}}}
	err = reconciler.Apply(context.Background(), declared, ComputeObserved{Members: []ObservedMember{owned}}, plan)
	if err == nil {
		t.Fatal("stale/unowned member termination was accepted")
	}
	if len(gateway.terminations) != 0 {
		t.Fatalf("termination calls = %v, want none", gateway.terminations)
	}
}

func TestComputeApplyFallsBackFromA1ToE5(t *testing.T) {
	declared := testComputeDeclared(t)
	gateway := &fakeComputeGateway{noCapacity: map[string]bool{"VM.Standard.A1.Flex": true}}
	reconciler := &ComputeReconciler{Compute: gateway, Network: &fakeNetworkGateway{}}
	ctx := context.Background()
	plan, err := reconciler.Reconcile(ctx, declared, testComputeObserved())
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Apply(ctx, declared, testComputeObserved(), plan); err != nil {
		t.Fatalf("Apply with A1 exhaustion failed: %v", err)
	}
	if len(gateway.launches) != 4 {
		t.Fatalf("launch attempts = %d, want two primary+fallback pairs", len(gateway.launches))
	}
	for i, spec := range gateway.launches {
		wantShape := "VM.Standard.A1.Flex"
		wantImage := "ocid1.image.oc1.arm64"
		if i%2 == 1 {
			wantShape = "VM.Standard.E5.Flex"
			wantImage = "ocid1.image.oc1.amd64"
		}
		if spec.Shape != wantShape {
			t.Fatalf("launch %d shape = %s, want %s", i, spec.Shape, wantShape)
		}
		if spec.ImageID != wantImage {
			t.Fatalf("launch %d image = %s, want %s (arch must follow the shape)", i, spec.ImageID, wantImage)
		}
	}
}

func TestComputeApplyRefusesCrossArchFallbackWithoutImage(t *testing.T) {
	declared := testComputeDeclared(t)
	declared.FallbackImageID = ""
	gateway := &fakeComputeGateway{noCapacity: map[string]bool{"VM.Standard.A1.Flex": true}}
	reconciler := &ComputeReconciler{Compute: gateway, Network: &fakeNetworkGateway{}}
	ctx := context.Background()
	plan, err := reconciler.Reconcile(ctx, declared, testComputeObserved())
	if err != nil {
		t.Fatal(err)
	}
	err = reconciler.Apply(ctx, declared, testComputeObserved(), plan)
	var invalid *InvalidDataError
	if !errors.As(err, &invalid) {
		t.Fatalf("Apply without an amd64 image = %v, want InvalidDataError", err)
	}
	if len(gateway.launches) != 1 {
		t.Fatalf("launch attempts = %d, want exactly one primary attempt (never boot arm64 on E5)", len(gateway.launches))
	}
}

func TestComputeApplySameArchFallbackReusesPrimaryImage(t *testing.T) {
	declared := testComputeDeclared(t)
	declared.Region.Members.PrimaryShape = "VM.Standard.E5.Flex"
	declared.Region.Members.FallbackShape = "VM.Standard.E4.Flex"
	declared.FallbackImageID = ""
	gateway := &fakeComputeGateway{noCapacity: map[string]bool{"VM.Standard.E5.Flex": true}}
	reconciler := &ComputeReconciler{Compute: gateway, Network: &fakeNetworkGateway{}}
	ctx := context.Background()
	plan, err := reconciler.Reconcile(ctx, declared, testComputeObserved())
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Apply(ctx, declared, testComputeObserved(), plan); err != nil {
		t.Fatalf("Apply with same-arch fallback failed: %v", err)
	}
	if len(gateway.launches) != 4 {
		t.Fatalf("launch attempts = %d, want two primary+fallback pairs", len(gateway.launches))
	}
	for i, spec := range gateway.launches {
		if spec.ImageID != declared.ImageID {
			t.Fatalf("launch %d image = %s, want the primary image reused on the same arch", i, spec.ImageID)
		}
	}
	if gateway.launches[1].Shape != "VM.Standard.E4.Flex" {
		t.Fatalf("fallback launch shape = %s, want VM.Standard.E4.Flex", gateway.launches[1].Shape)
	}
}

func TestComputeReconcileRefusesSubFloorAndUnknownArch(t *testing.T) {
	declared := testComputeDeclared(t)
	declared.Region.Members.Count = 1
	reconciler := &ComputeReconciler{Compute: &fakeComputeGateway{}, Network: &fakeNetworkGateway{}}
	if _, err := reconciler.Reconcile(context.Background(), declared, testComputeObserved()); err == nil {
		t.Fatal("sub-floor member pool accepted")
	}
	declared = testComputeDeclared(t)
	declared.Region.Members.PrimaryShape = "VM.Standard.X9.Flex"
	if _, err := reconciler.Reconcile(context.Background(), declared, testComputeObserved()); err == nil {
		t.Fatal("unknown-architecture primary shape accepted")
	}
	declared = testComputeDeclared(t)
	declared.Region.Members.FallbackShape = "BM.Standard.A1.Flex"
	if _, err := reconciler.Reconcile(context.Background(), declared, testComputeObserved()); err == nil {
		t.Fatal("unknown-architecture fallback shape accepted")
	}
}

func TestShapeArch(t *testing.T) {
	cases := []struct {
		shape string
		arch  string
		ok    bool
	}{
		{"VM.Standard.A1.Flex", MemberArchArm64, true},
		{"VM.Standard.A1.2", MemberArchArm64, true},
		{"VM.Standard.E5.Flex", MemberArchAMD64, true},
		{"VM.Standard.E4.Flex", MemberArchAMD64, true},
		{"VM.Standard.E2.2", MemberArchAMD64, true},
		{"VM.Standard.X9.Flex", "", false},
		{"BM.Standard.A1.Flex", "", false},
		{"VM.Standard.E", "", false},
		{"VM.Standard.Even.Flex", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		arch, ok := ShapeArch(tc.shape)
		if arch != tc.arch || ok != tc.ok {
			t.Fatalf("ShapeArch(%q) = %q, %v; want %q, %v", tc.shape, arch, ok, tc.arch, tc.ok)
		}
	}
}

func TestComputeApplyQuotaIsNotSwallowed(t *testing.T) {
	declared := testComputeDeclared(t)
	gateway := &fakeComputeGateway{quotaReject: true}
	reconciler := &ComputeReconciler{Compute: gateway, Network: &fakeNetworkGateway{}}
	ctx := context.Background()
	plan, err := reconciler.Reconcile(ctx, declared, testComputeObserved())
	if err != nil {
		t.Fatal(err)
	}
	err = reconciler.Apply(ctx, declared, testComputeObserved(), plan)
	var quota *OCIQuotaError
	if !errors.As(err, &quota) {
		t.Fatalf("Apply under quota rejection = %v, want quota error", err)
	}
}

func TestComputeApplyConvergesIdempotently(t *testing.T) {
	declared := testComputeDeclared(t)
	gateway := &fakeComputeGateway{}
	network := &fakeNetworkGateway{rules: map[string][]ObservedSecurityRule{}}
	reconciler := &ComputeReconciler{Compute: gateway, Network: network}
	ctx := context.Background()
	// Seed the network the launches depend on.
	vcn, err := network.CreateVCN(ctx, "terrascale-gru", declared.Region.Network.CIDR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := network.CreateSubnet(ctx, vcn.ID, "gru-members", "10.0.1.0/24"); err != nil {
		t.Fatal(err)
	}
	if _, err := network.CreateNSG(ctx, vcn.ID, "gru-members"); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 3; pass++ {
		observed, err := reconciler.Observe(ctx, declared)
		if err != nil {
			t.Fatalf("observe failed: %v", err)
		}
		plan, err := reconciler.Reconcile(ctx, declared, observed)
		if err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}
		if plan.Empty() {
			if len(gateway.members) != 2 {
				t.Fatalf("members = %d, want 2", len(gateway.members))
			}
			if len(gateway.launches) != 2 {
				t.Fatalf("total launches = %d, want exactly 2 (idempotent)", len(gateway.launches))
			}
			return
		}
		// The fake launch result must join the observed member set.
		if err := reconciler.Apply(ctx, declared, observed, plan); err != nil {
			t.Fatalf("apply failed: %v", err)
		}
	}
	t.Fatal("compute did not converge in three passes")
}

func TestComputePendingFailedAndDuplicateMembers(t *testing.T) {
	declared := testComputeDeclared(t)
	reconciler := &ComputeReconciler{Compute: &fakeComputeGateway{}, Network: &fakeNetworkGateway{}}
	observed := testComputeObserved()
	observed.Members = []ObservedMember{
		testOwnedMember("gru", 1, declared.Region.Members.PrimaryShape, "PROVISIONING", "AD-1"),
		testOwnedMember("gru", 2, declared.Region.Members.PrimaryShape, "RUNNING", "AD-2"),
	}
	plan, err := reconciler.Reconcile(context.Background(), declared, observed)
	if err != nil || !plan.Empty() {
		t.Fatalf("pending member reconcile = %v, %v; want empty retry plan", plan.Kinds(), err)
	}
	converged, err := reconciler.bootstrapConverged(observed, declared)
	if err != nil || converged {
		t.Fatalf("pending member convergence = %v, %v; want false", converged, err)
	}
	failed := observed
	failed.Members[0].LifecycleState = "FAILED"
	if _, err := reconciler.Reconcile(context.Background(), declared, failed); err == nil {
		t.Fatal("failed member accepted")
	}
	duplicate := observed
	duplicate.Members = append(duplicate.Members, duplicate.Members[1])
	if _, err := reconciler.Reconcile(context.Background(), declared, duplicate); err == nil {
		t.Fatal("duplicate member slot accepted")
	}
}

func TestTSNodeCloudInitInstallsOnlyTSNode(t *testing.T) {
	sha := strings.Repeat("0123456789abcdef", 4)
	key := strings.Repeat("ab", 32)
	encoded, err := testTSNodeCloudInit("1.2.3", sha, "https://git.terrascale.tech/releases/ts-node", "https://git.terrascale.tech/releases/ts-node.sig", key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	document := string(raw)
	if !strings.HasPrefix(document, "#cloud-config") {
		t.Fatal("cloud-init must be a cloud-config document")
	}
	for _, forbidden := range []string{"apt", "ssh-", "PRIVATE KEY", "apt-get", "yum", "docker", "podman"} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("cloud-init installs more than ts-node: found %q", forbidden)
		}
	}
	for _, required := range []string{sha, "ts-node.sig", "/etc/terrascale/ts-node.pub", "openssl, pkeyutl, -verify", "/opt/terrascale/ts-node/1.2.3/ts-node", "sha256sum -c", "terrascale-ts-node.service", "User=root", "Group=root", "ProtectSystem=strict", "ReadWritePaths=/var/lib/terrascale", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "SystemCallFilter=@system-service", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "CPUWeight=100", "MemoryMax=536870912", "IOWeight=100"} {
		if !strings.Contains(document, required) {
			t.Fatalf("cloud-init lacks %q", required)
		}
	}
	if !strings.Contains(document, "BEGIN PUBLIC KEY") || !strings.Contains(document, "User=root") {
		t.Fatal("cloud-init must provision the pinned key and canonical host authority")
	}
	if strings.Contains(document, "PRIVATE KEY") {
		t.Fatal("cloud-init must never contain private key material")
	}
	if _, err := testTSNodeCloudInit("bad version", sha, "https://example.com/x"); err == nil {
		t.Fatal("invalid version accepted")
	}
	if _, err := testTSNodeCloudInit("1.2.3", "not-a-digest", "https://example.com/x"); err == nil {
		t.Fatal("invalid digest accepted")
	}
	if _, err := testTSNodeCloudInit("1.2.3", sha, "http://insecure.example.com/x"); err == nil {
		t.Fatal("non-https artifact URL accepted")
	}
	if _, err := testTSNodeCloudInit("1.2.3", sha, "https://example.com/x", "https://example.com/x.sig", strings.Repeat("not-a-key", 4)); err == nil {
		t.Fatal("invalid Ed25519 trust key accepted")
	}
	if _, err := testTSNodeCloudInit("1.2.3", sha, "https://example.com/x", "http://example.com/x.sig", key); err == nil {
		t.Fatal("non-https signature URL accepted")
	}
}

func TestOCIMemberGatewayLaunchContract(t *testing.T) {
	var requestBody map[string]any
	var retryToken string
	transport := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/20160918/instances" {
			t.Fatalf("unexpected launch request %s %s", request.Method, request.URL.String())
		}
		retryToken = request.Header.Get("opc-retry-token")
		if err := json.NewDecoder(request.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		return testHTTPResponse(http.StatusOK, `{"id":"ocid1.instance.oc1.x","displayName":"terrascale-gru-1","lifecycleState":"PROVISIONING","shape":"VM.Standard.A1.Flex","availabilityDomain":"AD-1"}`, http.Header{}), nil
	})
	gateway, err := NewOCIMemberGateway(transport, "ocid1.compartment.oc1.x", "ocid1.image.oc1.x")
	if err != nil {
		t.Fatal(err)
	}
	member, err := gateway.LaunchMember(context.Background(), MemberLaunchSpec{
		DisplayName: "terrascale-gru-1", Index: 1, Shape: "VM.Standard.A1.Flex",
		ImageID: "ocid1.image.oc1.arm64",
		OCPUs:   2, MemoryGiB: 12, SubnetID: "ocid1.subnet.oc1.x",
		NSGIDs: []string{"ocid1.networksecuritygroup.oc1.x"}, AvailabilityDomain: "AD-1", CloudInitBase64: testComputeDeclared(t).CloudInitByMember[1],
	})
	if err != nil || member.ID != "ocid1.instance.oc1.x" || member.Index != 1 {
		t.Fatalf("LaunchMember = %+v, %v", member, err)
	}
	if retryToken != "terrascale-gru-1" {
		t.Fatalf("opc-retry-token = %q, want the display name", retryToken)
	}
	if requestBody["shape"] != "VM.Standard.A1.Flex" || requestBody["availabilityDomain"] != "AD-1" {
		t.Fatalf("launch payload shape/AD = %+v", requestBody)
	}
	vnic := requestBody["createVnicDetails"].(map[string]any)
	if vnic["assignPublicIp"] != false || vnic["subnetId"] != "ocid1.subnet.oc1.x" {
		t.Fatalf("launch vnic = %+v", vnic)
	}
	source := requestBody["sourceDetails"].(map[string]any)
	if source["imageId"] != "ocid1.image.oc1.arm64" {
		t.Fatalf("launch source = %+v; the spec image must win over the gateway default", source)
	}
	metadata := requestBody["metadata"].(map[string]any)
	if metadata["user_data"] != testComputeDeclared(t).CloudInitByMember[1] {
		t.Fatalf("launch user_data = %+v", metadata)
	}
	tags := requestBody["freeformTags"].(map[string]any)
	if tags[MemberIndexTag] != "1" || tags["terrascale-managed"] != ManagedMemberTagValue {
		t.Fatalf("launch tags = %+v", tags)
	}
	if _, present := requestBody["metadata"].(map[string]any)["ssh_authorized_keys"]; present {
		t.Fatal("launch must not install SSH keys")
	}
	// Without a spec image the gateway boots its own declared image.
	requestBody = nil
	if _, err := gateway.LaunchMember(context.Background(), MemberLaunchSpec{
		DisplayName: "terrascale-gru-2", Index: 2, Shape: "VM.Standard.E5.Flex",
		OCPUs: 2, MemoryGiB: 12, SubnetID: "ocid1.subnet.oc1.x", CloudInitBase64: testComputeDeclared(t).CloudInitByMember[1],
	}); err != nil {
		t.Fatal(err)
	}
	source = requestBody["sourceDetails"].(map[string]any)
	if source["imageId"] != "ocid1.image.oc1.x" {
		t.Fatalf("launch source = %+v; the gateway image is the default", source)
	}
	if _, err := gateway.LaunchMember(context.Background(), MemberLaunchSpec{
		DisplayName: "terrascale-gru-3", Index: 3, Shape: "VM.Standard.A1.Flex",
		ImageID: "not-an-image",
		OCPUs:   2, MemoryGiB: 12, SubnetID: "ocid1.subnet.oc1.x", CloudInitBase64: testComputeDeclared(t).CloudInitByMember[1],
	}); err == nil {
		t.Fatal("invalid boot image accepted")
	}
}

func testTSNodeCloudInit(version, digest, artifact string, trust ...string) (string, error) {
	signature, key := artifact+".sig", strings.Repeat("ab", 32)
	if len(trust) > 0 {
		signature = trust[0]
	}
	if len(trust) > 1 {
		key = trust[1]
	}
	return TSNodeCloudInit(version, digest, artifact, signature, key, []BootstrapHostFile{{Path: "/etc/terrascale/ts-node.json", Content: []byte("{}"), Private: true}, {Path: "/var/lib/terrascale/ts-node/manifest.json", Content: []byte("{}"), Private: true}})
}
