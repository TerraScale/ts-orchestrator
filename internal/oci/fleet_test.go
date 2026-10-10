package oci

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestEnsureHostRecoversLostLaunchResponse(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.launchErrorAfterCreate = errors.New("response dropped")
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	fleet, err := newTestFleet(config, intent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	want, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-create-01")))
	if err != nil {
		t.Fatalf("EnsureHost after lost response: %v", err)
	}
	if provider.launches != 1 || want.ID == "" || want.Node == "" || want.State != "PROVISIONING" {
		t.Fatalf("unexpected recovered host: launches=%d host=%+v", provider.launches, want)
	}
	request := testEnsureRequest(entityid.Derive("test-operation", "node-create-01"))
	if want.Shape != request.Shape || want.WholeOCPUs != request.WholeOCPUs || want.MemoryInGBs != request.MemoryInGBs ||
		want.PlacementProfileDigest != request.PlacementProfileDigest || want.PlacementGeneration != request.PlacementGeneration {
		t.Fatalf("EnsureHost did not return the verified immutable placement profile: host=%+v request=%+v", want, request)
	}
	if len(provider.launchRequests) != 2 || !sameLaunchProfile(provider.launchRequests[0], provider.launchRequests[1]) ||
		provider.launchRequests[0].RetryToken != provider.launchRequests[1].RetryToken {
		t.Fatalf("lost-response replay changed the signed tuple or retry token: requests=%+v", provider.launchRequests)
	}

	again, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-create-01")))
	if err != nil {
		t.Fatalf("idempotent EnsureHost: %v", err)
	}
	if provider.launches != 1 || again.ID != want.ID || again.Node != want.Node {
		t.Fatalf("retry created or changed host: launches=%d first=%+v retry=%+v", provider.launches, want, again)
	}
}

// A release re-signs the fleet under a new owner and generation, and the
// replacement host gets a new create key and node. The fleet launches the
// caller's static name unchanged and keeps the release identity in the tags;
// placement's side is TestPlacementLaunchNameIsStableAcrossReleases.
func TestEnsureHostKeepsStaticNameAcrossReleases(t *testing.T) {
	var launches []LaunchRequest
	for i, owner := range []string{"ts-preview-gru-20260929-r4", "ts-preview-gru-20261004-r5"} {
		config, intent := testRegionConfig()
		intent.Generation += uint64(i)
		config.Owner, config.Generation = owner, intent.Generation
		provider := newFakeProvider(config)
		fleet, err := newTestFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fleet.EnsureHost(t.Context(), testEnsureRequest(entityid.Derive("test-operation", fmt.Sprintf("node-release-%d", i)))); err != nil {
			t.Fatal(err)
		}
		launches = append(launches, provider.launchRequests[0])
	}
	before, after := launches[0], launches[1]
	if before.DisplayName != "gru-1-db-1" || after.DisplayName != before.DisplayName ||
		before.Node == after.Node || before.FreeformTags[tagOwner] != "ts-preview-gru-20260929-r4" ||
		after.FreeformTags[tagOwner] != "ts-preview-gru-20261004-r5" || after.FreeformTags[tagGeneration] != "8" {
		t.Fatalf("release changed the host name or lost its tagged identity: before=%+v after=%+v", before, after)
	}
}

func TestFleetRejectsNamesOutsideItsCellBeforeAnyEffect(t *testing.T) {
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	fleet, err := newTestFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "orchestrator-host-0123456789abcdef01234567", "gru-controller-a", "gru-1-ctl-1", "sfo-1-db-1", "gru-1-db-1-data"} {
		request := testEnsureRequest(entityid.Derive("test-operation", "node-bad-name"))
		request.Name = name
		if _, err := fleet.EnsureHost(t.Context(), request); err == nil {
			t.Fatalf("host name %q was accepted", name)
		}
	}
	for _, name := range []string{"", "ts-member-data-0123456789ab", "gru-1-db-1", "sfo-1-db-1-data"} {
		request := VolumeCreateRequest{Name: name, DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: entityid.Derive("test-operation", "data-bad-name"), SizeGB: 50}
		if _, err := fleet.CreateRetainedVolume(t.Context(), request); err == nil {
			t.Fatalf("volume name %q was accepted", name)
		}
	}
	if provider.launchCalls != 0 || provider.volumeCreateCalls != 0 {
		t.Fatalf("an out-of-scheme name reached OCI: launches=%d volumes=%d", provider.launchCalls, provider.volumeCreateCalls)
	}
}

func TestEnsureHostHoldsChangedBootPinsAndImageAcrossRetry(t *testing.T) {
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	fleet, err := newTestFleet(config, regionIntent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := testEnsureRequest(entityid.Derive("test-operation", "node-immutable-boot"))
	if _, err := fleet.EnsureHost(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.BootPins.RuntimeManifestDigest = strings.Repeat("e", 64)
	if _, err := fleet.EnsureHost(t.Context(), changed); err == nil || provider.launches != 1 {
		t.Fatalf("changed runtime pin reused launch key: launches=%d err=%v", provider.launches, err)
	}
	changedConfig := config
	changedConfig.ImageID = "ocid1.image.oc1.sa-saopaulo-1.changed"
	restarted, err := newTestFleet(changedConfig, regionIntent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.EnsureHost(t.Context(), request); err == nil || provider.launches != 1 {
		t.Fatalf("changed image pin reused launch key: launches=%d err=%v", provider.launches, err)
	}
	if observed, err := restarted.Observe(t.Context()); err != nil || len(observed) != 0 {
		t.Fatalf("image-drifted fleet observed original host: observed=%+v err=%v", observed, err)
	}
}

type allowListImageVerifier struct {
	fakeImageVerifier
	allowed []string
	launch  string
	// version is the cell spec version; chosen runs after a launch image is
	// chosen, to change the spec before the provider launch.
	version string
	chosen  func()
	// held counts launches inside the cell spec fence.
	held int
}

func (v *allowListImageVerifier) HostImages() ([]string, string) { return v.allowed, v.launch }

func (v *allowListImageVerifier) QualifiedLaunchImage(ctx context.Context, region Region, pin string) (string, string, error) {
	image := pin
	if v.launch != "" && slices.Contains(v.allowed, v.launch) {
		image = v.launch
	}
	version := v.version
	err := v.VerifyImageQualified(ctx, region, image)
	if v.chosen != nil {
		v.chosen()
	}
	return image, version, err
}

func (v *allowListImageVerifier) AdmitLaunch(ctx context.Context, region Region, imageID, version string) (func(), error) {
	if version != "" && version != v.version {
		return nil, errors.New("cell spec changed")
	}
	if err := v.VerifyImageQualified(ctx, region, imageID); err != nil {
		return nil, err
	}
	v.held++
	return func() { v.held-- }, nil
}

// revokingVerifier qualifies the launch image when the fleet chooses it and
// refuses it afterwards, as when the cell spec revokes it before the launch.
type revokingVerifier struct{ allowListImageVerifier }

func (v *revokingVerifier) QualifiedLaunchImage(context.Context, Region, string) (string, string, error) {
	return v.launch, v.version, nil
}

func (v *revokingVerifier) AdmitLaunch(_ context.Context, _ Region, imageID, _ string) (func(), error) {
	if imageID == v.launch {
		return nil, errors.New("image revoked")
	}
	return func() {}, nil
}

// An image revoked between its choice and the provider launch never boots.
func TestEnsureHostRequalifiesTheImageBeforeTheProviderLaunch(t *testing.T) {
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	newer := "ocid1.image.oc1.sa-saopaulo-1.newer"
	verifier := &revokingVerifier{allowListImageVerifier{allowed: []string{newer}, launch: newer}}
	fleet, err := NewFleetWithImageVerifier(config, regionIntent, provider, newFakeJournal(),
		&fakeFencer{snapshot: writableSnapshot()}, nil, nil, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.EnsureHost(t.Context(), testEnsureRequest(entityid.Derive("test-operation", "node-revoked-launch"))); !errors.Is(err, ErrImageNotQualified) ||
		provider.launchCalls != 0 {
		t.Fatalf("a revoked launch image reached OCI: calls=%d err=%v", provider.launchCalls, err)
	}
}

// A new launch runs only under the cell spec version that chose its image:
// a spec change in between stops it before OCI, and the retry replays the
// journaled image under one fresh read.
func TestEnsureHostNeverMixesCellSpecVersions(t *testing.T) {
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	newer := "ocid1.image.oc1.sa-saopaulo-1.newer"
	verifier := &allowListImageVerifier{allowed: []string{newer}, launch: newer, version: "7"}
	verifier.chosen = func() { verifier.version = "8" }
	fleet, err := NewFleetWithImageVerifier(config, regionIntent, provider, newFakeJournal(),
		&fakeFencer{snapshot: writableSnapshot()}, nil, nil, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.EnsureHost(t.Context(), testEnsureRequest(entityid.Derive("test-operation", "node-version-change"))); !errors.Is(err, ErrImageNotQualified) ||
		provider.launchCalls != 0 {
		t.Fatalf("a launch chosen under another spec version reached OCI: calls=%d err=%v", provider.launchCalls, err)
	}
	verifier.chosen = nil
	// The provider launch runs inside the cell spec fence, which the fleet
	// releases once the launch returns.
	heldDuringLaunch := 0
	provider.launchObservationMutation = func(*CloudInstance) { heldDuringLaunch = verifier.held }
	replayed, err := fleet.EnsureHost(t.Context(), testEnsureRequest(entityid.Derive("test-operation", "node-version-change")))
	if err != nil || replayed.ImageID != newer || provider.launchCalls != 1 || heldDuringLaunch != 1 || verifier.held != 0 {
		t.Fatalf("replay under one version = %+v, %v (calls %d, held %d then %d)", replayed, err, provider.launchCalls,
			heldDuringLaunch, verifier.held)
	}
}

// After the cell pins a newer image, a host launched from the earlier image
// stays a member only while the cell's signed allow-list names that image,
// and takes its retained volume only while that image, not the launch
// image, qualifies now.
func TestFleetKeepsHostsOfAllowedEarlierImages(t *testing.T) {
	ctx := t.Context()
	config, provider, journal, _, host, volume := newAttachTestState(t)
	_, regionIntent := testRegionConfig()
	newer := config
	newer.ImageID = "ocid1.image.oc1.sa-saopaulo-1.newer"
	unrelated := "ocid1.image.oc1.sa-saopaulo-1.unrelated"
	refusing := func(image, launch string) *allowListImageVerifier {
		return &allowListImageVerifier{fakeImageVerifier: fakeImageVerifier{refuse: image},
			allowed: []string{unrelated, config.ImageID}, launch: launch}
	}
	for _, test := range []struct {
		name             string
		verifier         ImageQualificationVerifier
		member, attaches bool
	}{
		{"no allow-list", &fakeImageVerifier{}, false, false},
		{"other images allowed", &allowListImageVerifier{allowed: []string{unrelated}}, false, false},
		{"earlier image no longer qualifies", refusing(config.ImageID, ""), true, false},
		{"launch image does not qualify", refusing(unrelated, unrelated), true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fleet, err := NewFleetWithImageVerifier(newer, regionIntent, provider, journal,
				&fakeFencer{snapshot: writableSnapshot()}, nil, nil, test.verifier)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := fleet.Observe(ctx)
			if err != nil || test.member != (len(observed) == 1) ||
				test.member && (observed[0].ID != host.ID || observed[0].ImageID != config.ImageID) {
				t.Fatalf("Observe = %+v, %v; want member %t", observed, err, test.member)
			}
			_, err = fleet.AttachRetainedVolume(ctx, VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ",
				VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-earlier-image")})
			want := ErrForeignResource
			if test.member {
				want = ErrImageNotQualified
			}
			if test.attaches != (err == nil) || !test.attaches && !errors.Is(err, want) {
				t.Fatalf("AttachRetainedVolume = %v; want attaches %t", err, test.attaches)
			}
		})
	}
	if provider.attachCalls != 1 {
		t.Fatalf("attach calls = %d; only the qualified host attaches", provider.attachCalls)
	}
}

// New hosts boot the cell spec's launch image once it qualifies, without a
// new signed fleet config; a journaled launch keeps its own image on retry.
func TestEnsureHostBootsTheCellSpecLaunchImage(t *testing.T) {
	ctx := t.Context()
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	newer := "ocid1.image.oc1.sa-saopaulo-1.newer"
	verifier := &allowListImageVerifier{}
	fleet, err := NewFleetWithImageVerifier(config, regionIntent, provider, journal,
		&fakeFencer{snapshot: writableSnapshot()}, nil, nil, verifier)
	if err != nil {
		t.Fatal(err)
	}
	launching := fleet.(interface{ verifyLaunchImage(context.Context) error })
	// Every new launch qualifies its image when it chooses it and again right
	// before the provider launch, the signed pin included.
	earlier, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-before-launch-image")))
	if err != nil || earlier.ImageID != config.ImageID || !slices.Equal(verifier.images, []string{config.ImageID, config.ImageID}) {
		t.Fatalf("pinned launch = %+v, %v; verified %v", earlier, err, verifier.images)
	}
	verifier.images = nil

	// A launch image outside the allow-list is ignored.
	verifier.launch = newer
	if err := launching.verifyLaunchImage(ctx); err != nil || !slices.Equal(verifier.images, []string{config.ImageID}) {
		t.Fatalf("unlisted launch image was verified: %v %v", verifier.images, err)
	}
	verifier.images = nil
	verifier.allowed = []string{config.ImageID, newer}
	verifier.err = errors.New("receipt expired")
	if _, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-unqualified-launch"))); !errors.Is(err, ErrImageNotQualified) ||
		provider.launchCalls != 1 {
		t.Fatalf("unqualified launch image reached OCI: calls=%d err=%v", provider.launchCalls, err)
	}
	verifier.err = nil
	launched, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-launch-image")))
	if err != nil || launched.ImageID != newer || provider.launchRequests[len(provider.launchRequests)-1].ImageID != newer ||
		!slices.Contains(verifier.images, newer) {
		t.Fatalf("launch image host = %+v, %v; verified %v", launched, err, verifier.images)
	}
	if err := launching.verifyLaunchImage(ctx); err != nil || verifier.images[len(verifier.images)-1] != newer {
		t.Fatalf("volume creation gate did not verify the launch image: %v %v", verifier.images, err)
	}

	// Retrying the earlier launch keeps its pinned image; nothing relaunches.
	again, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-before-launch-image")))
	if err != nil || again.ID != earlier.ID || again.ImageID != config.ImageID || provider.launches != 2 {
		t.Fatalf("retry after the launch image moved = %+v, %v (launches %d)", again, err, provider.launches)
	}
	if observed, err := fleet.Observe(ctx); err != nil || len(observed) != 2 {
		t.Fatalf("hosts of both images = %+v, %v", observed, err)
	}

	// A spec-image launch journaled before OCI saw it qualifies again before
	// its replay, and keeps its image after the launch image moves.
	provider.launchErrorBeforeCreate = errors.New("OCI unavailable")
	if _, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-replayed-launch"))); err == nil {
		t.Fatal("launch with OCI unavailable succeeded")
	}
	provider.launchErrorBeforeCreate = nil
	calls := provider.launchCalls
	newest := "ocid1.image.oc1.sa-saopaulo-1.newest"
	verifier.allowed, verifier.launch = []string{config.ImageID, newer, newest}, newest
	verifier.err = errors.New("OCI image deleted")
	if _, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-replayed-launch"))); !errors.Is(err, ErrImageNotQualified) ||
		provider.launchCalls != calls {
		t.Fatalf("replay of an unqualified journaled image reached OCI: calls=%d err=%v", provider.launchCalls-calls, err)
	}
	verifier.err, verifier.images = nil, nil
	replayed, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-replayed-launch")))
	if err != nil || replayed.ImageID != newer || !slices.Equal(verifier.images, []string{newer}) {
		t.Fatalf("replayed spec-image launch = %+v, %v; verified %v", replayed, err, verifier.images)
	}

	// Once its image is revoked, a retry cannot reuse it and holds.
	verifier.allowed = []string{newer}
	moved := config
	moved.ImageID = "ocid1.image.oc1.sa-saopaulo-1.moved"
	restarted, err := NewFleetWithImageVerifier(moved, regionIntent, provider, journal,
		&fakeFencer{snapshot: writableSnapshot()}, nil, nil, verifier)
	if err != nil {
		t.Fatal(err)
	}
	var hold *CreateRecoveryHoldError
	if _, err := restarted.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-before-launch-image"))); !errors.As(err, &hold) || provider.launches != 3 {
		t.Fatalf("retry of a revoked image's launch: launches=%d err=%v", provider.launches, err)
	}
}

func TestObserveWithholdsLegacyLaunchWithoutBootDescriptor(t *testing.T) {
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	createKey := entityid.Derive("test-operation", "node-legacy-unbound")
	operation := testLaunchIntent(createKey)
	operation.BootDescriptor, operation.BootDescriptorSHA256 = "", ""
	if err := journal.RecordIntent(t.Context(), operation); err != nil {
		t.Fatal(err)
	}
	instanceID := "ocid1.instance.oc1..legacy-unbound"
	provider.instances[instanceID] = CloudInstance{
		ID: instanceID, CompartmentID: config.CompartmentID, AvailabilityDomain: config.AvailabilityDomain,
		FaultDomain: operation.FaultDomain, Shape: operation.Shape, Ocpus: new(float32(operation.WholeOCPUs)),
		MemoryInGBs: new(float32(operation.MemoryInGBs)), LifecycleState: "RUNNING", ETag: "legacy-etag",
		ImageID: config.ImageID, ConsistentVolumeNamingEnabled: new(true),
		FreeformTags: placementProfileTags(hostTags(config, createKey), operation.PlacementProfileDigest, operation.PlacementGeneration),
	}
	if err := journal.RecordResult(t.Context(), OperationResult{Intent: operation, ResourceID: instanceID, ETag: "legacy-etag"}); err != nil {
		t.Fatal(err)
	}
	fleet, err := newTestFleet(config, regionIntent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if observed, err := fleet.Observe(t.Context()); err != nil || len(observed) != 0 {
		t.Fatalf("old unbound host was observed: observed=%+v err=%v", observed, err)
	}
	if _, err := fleet.EnsureHost(t.Context(), testEnsureRequest(createKey)); err == nil || provider.launches != 0 {
		t.Fatalf("old unbound launch was retried or adopted: launches=%d err=%v", provider.launches, err)
	}
}

func TestEnsureHostRejectsSameCreateKeyComputeProfileDrift(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := testEnsureRequest(entityid.Derive("test-operation", "node-profile-drift"))
	if _, err := fleet.EnsureHost(ctx, request); err != nil {
		t.Fatal(err)
	}
	request.MemoryInGBs++
	if _, err := fleet.EnsureHost(ctx, request); err == nil {
		t.Fatal("same create key accepted a different immutable compute tuple")
	}
	request.MemoryInGBs--
	request.PrivateIP = "10.251.0.22"
	if _, err := fleet.EnsureHost(ctx, request); err == nil {
		t.Fatal("same create key accepted a different private IP")
	}
	if provider.launchCalls != 1 || len(provider.launchRequests) != 1 {
		t.Fatalf("profile drift reached the provider: launchCalls=%d requests=%+v", provider.launchCalls, provider.launchRequests)
	}
}

func TestEnsureHostRejectsMissingSignedComputeProfileBeforePersistence(t *testing.T) {
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fleet.EnsureHost(t.Context(), EnsureRequest{Name: "gru-1-db-1", CreateKey: entityid.Derive("test-operation", "node-unsigned"), PrivateIP: "10.251.0.21", FaultDomain: "FAULT-DOMAIN-1"})
	if !errors.Is(err, ErrPlacementProfileMismatch) {
		t.Fatalf("missing signed profile was not held: %v", err)
	}
	if provider.launchCalls != 0 || len(journal.intents) != 0 {
		t.Fatalf("unsigned request reached provider or journal: launches=%d intents=%d", provider.launchCalls, len(journal.intents))
	}
}

func TestOCIShapeRejectionCannotConfirmOrAdoptInstance(t *testing.T) {
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.launchErrorBeforeCreate = errors.New("OCI shape configuration rejected")
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := testEnsureRequest(entityid.Derive("test-operation", "node-provider-shape-rejection"))
	_, err = fleet.EnsureHost(t.Context(), request)
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("provider shape rejection was not held as an unknown outcome: %v", err)
	}
	if provider.launchCalls != 2 || len(provider.instances) != 0 || len(journal.instances) != 0 {
		t.Fatalf("provider rejection resulted in a false positive or ownership: calls=%d cloud=%+v owned=%+v",
			provider.launchCalls, provider.instances, journal.instances)
	}
	storedIntent, found, err := journal.GetOperation(t.Context(), OperationScope{
		Action: actionLaunch, Key: request.CreateKey, Region: config.Region,
		Generation: config.Generation, Owner: config.Owner,
	})
	result, resultFound, resultErr := journal.GetResult(t.Context(), storedIntent)
	if err != nil || resultErr != nil || !found || !resultFound || !result.Unknown || result.ResourceID != "" {
		t.Fatalf("provider rejection was durably confirmed: found=%v resultFound=%v result=%+v errors=(%v, %v)",
			found, resultFound, result, err, resultErr)
	}
	observed, err := fleet.Observe(t.Context())
	if err != nil || len(observed) != 0 {
		t.Fatalf("provider rejection produced an adoptable instance: observed=%+v err=%v", observed, err)
	}
}

func TestEnsureHostWithholdsNilOrMismatchedObservedSizing(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*CloudInstance)
	}{
		{name: "nil OCPU", mutate: func(instance *CloudInstance) { instance.Ocpus = nil }},
		{name: "nil memory", mutate: func(instance *CloudInstance) { instance.MemoryInGBs = nil }},
		{name: "wrong OCPU", mutate: func(instance *CloudInstance) { instance.Ocpus = new(float32(2)) }},
		{name: "wrong memory", mutate: func(instance *CloudInstance) { instance.MemoryInGBs = new(float32(8)) }},
		{name: "wrong shape", mutate: func(instance *CloudInstance) { instance.Shape = "VM.Standard.E5.Flex.Other" }},
		{name: "wrong private IP", mutate: func(instance *CloudInstance) { instance.PrivateIP = "10.251.0.22" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, intent := testRegionConfig()
			provider := newFakeProvider(config)
			provider.launchObservationMutation = test.mutate
			journal := newFakeJournal()
			fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = fleet.EnsureHost(t.Context(), testEnsureRequest(entityid.Derive("test-operation", "node-bad-observed-profile")))
			if !errors.Is(err, ErrPlacementProfileMismatch) || !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("mismatched observed sizing was not held as unknown: %v", err)
			}
			operation, found, getErr := journal.GetOperation(t.Context(), OperationScope{
				Action: actionLaunch, Key: entityid.Derive("test-operation", "node-bad-observed-profile"), Region: config.Region,
				Generation: config.Generation, Owner: config.Owner,
			})
			result, resultFound, resultErr := journal.GetResult(t.Context(), operation)
			if getErr != nil || resultErr != nil || !found || !resultFound || !result.Unknown || len(journal.instances) != 0 {
				t.Fatalf("mismatched instance became confirmed ownership: operation=%+v found=%v result=%+v resultFound=%v owned=%+v errors=(%v, %v)",
					operation, found, result, resultFound, journal.instances, getErr, resultErr)
			}
		})
	}
}

func TestStaleLeaderCannotLaunch(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot(), guardErr: authority.ErrFenced}
	fleet, err := newTestFleet(config, intent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-create-02")))
	if !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("expected stale leader fence, got %v", err)
	}
	if provider.launches != 0 || len(journal.intents) != 0 {
		t.Fatalf("fenced candidate mutated state: launches=%d intents=%d", provider.launches, len(journal.intents))
	}
}

func TestEnsureHostRefusesForeignResourceWithSameCreateKey(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	foreign := CloudInstance{
		ID: "ocid1.instance.foreign", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, FaultDomain: "FAULT-DOMAIN-1",
		LifecycleState: "RUNNING", ETag: "e1",
		FreeformTags: map[string]string{
			tagManagedBy: managedByValue, tagOwner: "another-owner", tagRegion: string(config.Region),
			tagGeneration: fmt.Sprint(config.Generation), tagResource: resourceMemberHost,
			tagCreateKey: entityid.Derive("test-operation", "shared-create-key"), tagHostNode: "host-foreign",
		},
	}
	provider.instances[foreign.ID] = foreign
	fleet, err := newTestFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "shared-create-key")))
	if !errors.Is(err, ErrForeignResource) {
		t.Fatalf("expected ownership refusal, got %v", err)
	}
	if provider.launches != 0 {
		t.Fatalf("foreign collision was followed by a launch (%d)", provider.launches)
	}
}

func TestEnsureHostIgnoresTerminatedHostOfAnotherFleet(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	tags := hostTags(config, entityid.Derive("test-operation", "shared-create-key"))
	tags[tagOwner] = "previous-cell"
	provider.instances["ocid1.instance.previous"] = CloudInstance{
		ID: "ocid1.instance.previous", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, FaultDomain: "FAULT-DOMAIN-1",
		LifecycleState: "TERMINATED", ETag: "e1", FreeformTags: tags,
	}
	fleet, err := newTestFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "shared-create-key")))
	if err != nil || provider.launches != 1 || host.ID == "ocid1.instance.previous" {
		t.Fatalf("terminated host of another fleet blocked the launch: host=%+v launches=%d err=%v", host, provider.launches, err)
	}
}

func TestEnsureHostDoesNotAdoptMatchingTagsWithoutJournalProof(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	createKey := entityid.Derive("test-operation", "node-seeded-unowned")
	provider.instances["ocid1.instance.seeded"] = CloudInstance{
		ID: "ocid1.instance.seeded", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, FaultDomain: "FAULT-DOMAIN-1",
		LifecycleState: "RUNNING", ETag: "seed-etag", FreeformTags: hostTags(config, createKey),
	}
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fleet.EnsureHost(ctx, testEnsureRequest(createKey))
	if !errors.Is(err, ErrForeignResource) {
		t.Fatalf("unowned matching-tag instance was adopted instead of refused: %v", err)
	}
	if len(journal.instances) != 0 || provider.launches != 0 {
		t.Fatalf("matching tags triggered a launch or established ownership: launches=%d ownership=%+v", provider.launches, journal.instances)
	}
}

func TestEnsureHostHoldsExpiredUnknownCreateWithoutProviderCall(t *testing.T) {
	ctx := t.Context()
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal, err := NewKVJournal(testJournalBucket(t))
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := newTestFleet(config, regionIntent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	operation := testLaunchIntent(entityid.Derive("test-operation", "node-expired-unknown"))
	operation.CreatedAt = time.Now().Add(-maxCreateRetryAge - time.Minute).UTC()
	if err := journal.RecordIntent(ctx, operation); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, OperationResult{Intent: operation, Unknown: true}); err != nil {
		t.Fatal(err)
	}

	_, err = fleet.EnsureHost(ctx, ensureRequestForIntent(operation))
	if !errors.Is(err, ErrCreateRecoveryHold) {
		t.Fatalf("expired unknown host create was not held for operator reconciliation: %v", err)
	}
	hold, ok := errors.AsType[*CreateRecoveryHoldError](err)
	if !ok || hold.CreateKey != operation.CreateKey {
		t.Fatalf("expired unknown host create returned no actionable typed hold: %#v", err)
	}
	if provider.launchCalls != 0 {
		t.Fatalf("expired token attempted another OCI host create: %d", provider.launchCalls)
	}
	stored, found, err := journal.GetResult(ctx, operation)
	if err != nil || !found || !stored.Unknown || !stored.Intent.CreatedAt.Equal(operation.CreatedAt) {
		t.Fatalf("retry changed the original durable intent: found=%v stored=%+v err=%v", found, stored, err)
	}
}

func TestFakeJournalRetryPreservesOriginalIntentTimestamp(t *testing.T) {
	journal := newFakeJournal()
	intent := testLaunchIntent(entityid.Derive("test-operation", "node-fake-journal-timestamp"))
	if err := journal.RecordIntent(t.Context(), intent); err != nil {
		t.Fatal(err)
	}

	retry := intent
	retry.CreatedAt = intent.CreatedAt.Add(time.Hour)
	if err := journal.RecordIntent(t.Context(), retry); err != nil {
		t.Fatalf("same operation retry was rejected: %v", err)
	}
	if stored := journal.intents[operationKey(intent)]; !stored.CreatedAt.Equal(intent.CreatedAt) {
		t.Fatalf("retry refreshed immutable original timestamp: got %s, want %s", stored.CreatedAt, intent.CreatedAt)
	}

	conflict := retry
	conflict.SizeGB = 100
	if err := journal.RecordIntent(t.Context(), conflict); err == nil {
		t.Fatal("reused operation key with changed profile was accepted")
	}
}

func TestCreateRetainedVolumeHoldsExpiredUnknownWithoutProviderCall(t *testing.T) {
	ctx := t.Context()
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal, err := NewKVJournal(testJournalBucket(t))
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := newTestFleet(config, regionIntent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	operation := OperationIntent{
		Action: actionVolumeCreate, Key: "0000000000VJ9SVET0Z23MT1N9", Region: config.Region,
		Generation: config.Generation, Owner: config.Owner, CreateKey: "0000000000VJ9SVET0Z23MT1N9",
		AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50,
		CreatedAt: time.Now().Add(-maxCreateRetryAge - time.Minute).UTC(),
	}
	if err := journal.RecordIntent(ctx, operation); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, OperationResult{Intent: operation, Unknown: true}); err != nil {
		t.Fatal(err)
	}

	_, err = fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: operation.CreateKey, SizeGB: operation.SizeGB})
	if !errors.Is(err, ErrCreateRecoveryHold) {
		t.Fatalf("expired unknown volume create was not held for operator reconciliation: %v", err)
	}
	if provider.volumeCreateCalls != 0 {
		t.Fatalf("expired token attempted another OCI volume create: %d", provider.volumeCreateCalls)
	}
}

func TestCreateRetainedVolumeHoldsExpiredUnconfirmedIntentWithoutProviderCall(t *testing.T) {
	ctx := t.Context()
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal, err := NewKVJournal(testJournalBucket(t))
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := newTestFleet(config, regionIntent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	operation := OperationIntent{
		Action: actionVolumeCreate, Key: "0000000000YQAEJG3H71Y7JJFQ", Region: config.Region,
		Generation: config.Generation, Owner: config.Owner, CreateKey: "0000000000YQAEJG3H71Y7JJFQ",
		AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50,
		CreatedAt: time.Now().Add(-maxCreateRetryAge - time.Minute).UTC(),
	}
	if err := journal.RecordIntent(ctx, operation); err != nil {
		t.Fatal(err)
	}

	_, err = fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: operation.CreateKey, SizeGB: operation.SizeGB})
	if !errors.Is(err, ErrCreateRecoveryHold) {
		t.Fatalf("expired unconfirmed volume create was not held for operator reconciliation: %v", err)
	}
	if provider.volumeCreateCalls != 0 {
		t.Fatalf("expired unconfirmed intent attempted an OCI volume create: %d", provider.volumeCreateCalls)
	}
}

func TestConfirmedMissingHostRequiresOperatorReconciliation(t *testing.T) {
	ctx := t.Context()
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal, err := NewKVJournal(testJournalBucket(t))
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := newTestFleet(config, regionIntent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := testEnsureRequest(entityid.Derive("test-operation", "node-confirmed-missing"))
	created, err := fleet.EnsureHost(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	delete(provider.instances, created.ID)

	_, err = fleet.EnsureHost(ctx, request)
	if !errors.Is(err, ErrCreateRecoveryHold) {
		t.Fatalf("confirmed missing host was recreated instead of held: %v", err)
	}
	if provider.launchCalls != 1 {
		t.Fatalf("confirmed missing resource caused another OCI host create: %d", provider.launchCalls)
	}
}

func TestConfirmedMissingVolumeRequiresOperatorReconciliation(t *testing.T) {
	ctx := t.Context()
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal, err := NewKVJournal(testJournalBucket(t))
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := newTestFleet(config, regionIntent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000MDM31EDA5G71P2X0", SizeGB: 50}
	created, err := fleet.CreateRetainedVolume(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	delete(provider.volumes, created.ID)

	_, err = fleet.CreateRetainedVolume(ctx, request)
	if !errors.Is(err, ErrCreateRecoveryHold) {
		t.Fatalf("confirmed missing volume was recreated instead of held: %v", err)
	}
	if provider.volumeCreateCalls != 1 {
		t.Fatalf("confirmed missing resource caused another OCI volume create: %d", provider.volumeCreateCalls)
	}
}

func TestEnsureHostReturnsCurrentETagWithoutRewritingCreateReceipt(t *testing.T) {
	ctx := t.Context()
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal, err := NewKVJournal(testJournalBucket(t))
	if err != nil {
		t.Fatal(err)
	}
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	fleet, err := newTestFleet(config, regionIntent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := testEnsureRequest(entityid.Derive("test-operation", "node-etag-recovery"))
	first, err := fleet.EnsureHost(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := fleet.Cordon(ctx, first.ID, first.ETag); err != nil {
		t.Fatal(err)
	}

	// A new Fleet models a controller restart against the same OCI provider and
	// durable regional journal.
	restarted, err := newTestFleet(config, regionIntent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.EnsureHost(ctx, request)
	if err != nil {
		t.Fatalf("confirmed host recovery after ETag change: %v", err)
	}
	if recovered.ID != first.ID || recovered.ETag != first.ETag+"-next" || provider.launchCalls != 1 {
		t.Fatalf("restart returned stale identity or relaunched host: first=%+v recovered=%+v calls=%d",
			first, recovered, provider.launchCalls)
	}
	operation := testLaunchIntent(request.CreateKey)
	confirmed, found, err := journal.GetResult(ctx, operation)
	if err != nil || !found || confirmed.ResourceID != first.ID || confirmed.ETag != first.ETag {
		t.Fatalf("re-observation rewrote the immutable launch receipt: found=%v receipt=%+v err=%v", found, confirmed, err)
	}
}

func TestCreateRetainedVolumeRecoversLostResponseAndIsIdempotent(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.volumeCreateErrorAfterCreate = errors.New("response dropped")
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	request := VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000W65572DYTNARBJNA", SizeGB: 50}
	created, err := fleet.CreateRetainedVolume(ctx, request)
	if err != nil {
		t.Fatalf("CreateRetainedVolume after lost response: %v", err)
	}
	if created.ID == "" || created.Region != config.Region || created.Generation != config.Generation ||
		created.Owner != config.Owner || created.AvailabilityDomain != config.AvailabilityDomain || created.SizeGB != request.SizeGB {
		t.Fatalf("recovered volume has incomplete identity: %+v", created)
	}
	if provider.volumeCreates != 1 || provider.volumeCreateCalls != 2 {
		t.Fatalf("lost response was not safely replayed: creates=%d calls=%d", provider.volumeCreates, provider.volumeCreateCalls)
	}
	identity := ResourceIdentity{
		ID: created.ID, Region: created.Region, Generation: created.Generation,
		Owner: created.Owner, CreateKey: created.CreateKey,
		AvailabilityDomain: created.AvailabilityDomain, SizeGB: created.SizeGB,
	}
	if owned, err := journal.IsOwnedVolume(ctx, identity); err != nil || !owned {
		t.Fatalf("confirmed volume is not journal-owned: owned=%v err=%v", owned, err)
	}

	retried, err := fleet.CreateRetainedVolume(ctx, request)
	if err != nil || retried.ID != created.ID || provider.volumeCreates != 1 || provider.volumeCreateCalls != 2 {
		t.Fatalf("same create key did not remain idempotent: first=%+v retry=%+v creates=%d calls=%d err=%v",
			created, retried, provider.volumeCreates, provider.volumeCreateCalls, err)
	}
}

func TestCreateRetainedVolumeRejectsForeignScopeAndDuplicateCreateKeys(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.volumes["ocid1.volume.foreign"] = CloudVolume{
		ID: "ocid1.volume.foreign", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50, VPUsPerGB: 10, LifecycleState: "AVAILABLE",
		FreeformTags: map[string]string{
			tagManagedBy: managedByValue, tagOwner: "another-owner", tagRegion: string(config.Region),
			tagGeneration: fmt.Sprint(config.Generation), tagResource: resourceMemberData,
			tagCreateKey: "0000000000CE6GXQ81RAFB44ZH", tagVolumeSize: "50",
		},
	}
	fleet, err := newTestFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000CE6GXQ81RAFB44ZH", SizeGB: 50}); !errors.Is(err, ErrForeignResource) {
		t.Fatalf("foreign tagged volume was not refused: %v", err)
	}
	if provider.volumeCreates != 0 {
		t.Fatalf("foreign tagged volume triggered an OCI create: %d", provider.volumeCreates)
	}

	config, intent = testRegionConfig()
	provider = newFakeProvider(config)
	key := entityid.Derive("test-create", "data-volume-seeded-unowned")
	provider.volumes["ocid1.volume.seeded"] = CloudVolume{
		ID: "ocid1.volume.seeded", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50, VPUsPerGB: 10, LifecycleState: "AVAILABLE",
		FreeformTags: volumeTags(config, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: key, SizeGB: 50}),
	}
	fleet, err = newTestFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: key, SizeGB: 50}); !errors.Is(err, ErrRetainedVolumeUnknown) {
		t.Fatalf("unowned matching-tag volume was adopted instead of refused: %v", err)
	}
	if provider.volumeCreates != 0 {
		t.Fatalf("unowned matching-tag volume triggered a create: %d", provider.volumeCreates)
	}

	config, intent = testRegionConfig()
	provider = newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err = newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000WY2W2F7JE4R2MJGZ", SizeGB: 64})
	if err != nil {
		t.Fatal(err)
	}
	duplicate := provider.volumes[created.ID]
	duplicate.ID = "ocid1.volume.duplicate"
	provider.volumes[duplicate.ID] = duplicate
	if _, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000WY2W2F7JE4R2MJGZ", SizeGB: 64}); !errors.Is(err, ErrDuplicateCreateKey) {
		t.Fatalf("duplicate create key selected an arbitrary volume: %v", err)
	}
}

func TestCreateRetainedVolumeRejectsObservedPerformanceTierDrift(t *testing.T) {
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.afterVolumeCreate = func() {
		for id, volume := range provider.volumes {
			volume.VPUsPerGB = 20
			provider.volumes[id] = volume
		}
	}
	fleet, err := newTestFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fleet.CreateRetainedVolume(t.Context(), VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000DGTZMG30FH0XZNAQ", SizeGB: 50})
	if !errors.Is(err, ErrForeignResource) {
		t.Fatalf("retained volume with unbudgeted tier was accepted: %v", err)
	}
}

func TestCreateRetainedVolumeEnforcesFleetSizeCeilingBeforeOCI(t *testing.T) {
	config, intent := testRegionConfig()
	config.MaxDataVolumeGB = 50
	provider := newFakeProvider(config)
	fleet, err := newTestFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.CreateRetainedVolume(t.Context(), VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000CAS89NNGQQJPDNKV", SizeGB: 51}); err == nil {
		t.Fatal("volume above the preview fleet ceiling reached creation")
	}
	if provider.volumeCreateCalls != 0 {
		t.Fatalf("oversize volume reached OCI provider: %d calls", provider.volumeCreateCalls)
	}
}

func TestCreateRetainedVolumePinsProfileBeforeMutation(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	fleet, err := newTestFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []VolumeCreateRequest{
		{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "00000000002TKRQZ3PM8RG049S", SizeGB: 49},
		{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000PTPQ7VR5V3B30JC3", SizeGB: 50, AvailabilityDomain: "another-AD"},
	} {
		if _, err := fleet.CreateRetainedVolume(ctx, request); err == nil {
			t.Fatalf("invalid volume profile was accepted: %+v", request)
		}
	}
	if provider.volumeCreates != 0 {
		t.Fatalf("invalid profile reached OCI: %d creates", provider.volumeCreates)
	}
}

func TestCreateRetainedVolumeDoesNotReplayAfterAuthorityIsFenced(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.volumeCreateErrorAfterCreate = errors.New("response dropped")
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	provider.afterVolumeCreate = func() { fencer.guardErr = authority.ErrFenced }
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000QYRPKGEP473C6ZJJ", SizeGB: 50})
	if !errors.Is(err, authority.ErrFenced) || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("lost response was replayed after authority fencing: %v", err)
	}
	if provider.volumeCreateCalls != 1 || len(journal.volumes) != 0 {
		t.Fatalf("fenced retry mutated or confirmed ownership: calls=%d owned=%+v", provider.volumeCreateCalls, journal.volumes)
	}
}

func TestCreateRetainedVolumeKeepsUnconfirmedOutcomeUnowned(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	provider.volumeCreateErrorAfterCreate = errors.New("first response dropped")
	provider.volumeRetryReplayError = errors.New("retry response dropped")
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000Z6QY4XVPVTCQA09C", SizeGB: 50}
	if _, err := fleet.CreateRetainedVolume(ctx, request); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("ambiguous provider outcome was not held: %v", err)
	}
	intentRecord := OperationIntent{
		Action: actionVolumeCreate, Key: request.CreateKey, Region: config.Region,
		Generation: config.Generation, Owner: config.Owner, CreateKey: request.CreateKey,
		AvailabilityDomain: config.AvailabilityDomain, SizeGB: request.SizeGB, CreatedAt: time.Now().UTC(),
	}
	result, found, err := journal.GetResult(ctx, intentRecord)
	if err != nil || !found || !result.Unknown || len(journal.volumes) != 0 {
		t.Fatalf("ambiguous volume was incorrectly confirmed: found=%v result=%+v owned=%+v err=%v",
			found, result, journal.volumes, err)
	}
	var ambiguousVolumeID string
	for id, volume := range provider.volumes {
		if volume.FreeformTags[tagCreateKey] == request.CreateKey {
			ambiguousVolumeID = id
		}
	}
	if ambiguousVolumeID == "" {
		t.Fatal("test provider did not retain the ambiguous volume")
	}

	host, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-unconfirmed-volume")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.AttachRetainedVolume(ctx, VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ",
		VolumeID: ambiguousVolumeID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-unconfirmed-volume"),
	}); !errors.Is(err, ErrRetainedVolumeUnknown) {
		t.Fatalf("unconfirmed retained volume was attachable: %v", err)
	}
}

func TestTerminateRequiresNoAttachedVolumeAndVerifiedWriterStop(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	writerStop := &fakeWriterStop{}
	fleet, err := newTestFleet(config, intent, provider, journal, fencer, nil, writerStop)
	if err != nil {
		t.Fatal(err)
	}
	host, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-create-03")))
	if err != nil {
		t.Fatal(err)
	}
	provider.attachments["attachment-1"] = CloudAttachment{
		ID: "attachment-1", VolumeID: "volume-1", InstanceID: host.ID,
		LifecycleState: "ATTACHED", ETag: "a1", Device: "/dev/oracleoci/oraclevdb",
		IsReadOnly: boolPointer(false), IsShareable: boolPointer(false), IsPvEncryptionInTransitEnabled: boolPointer(true),
	}

	err = fleet.Terminate(ctx, host.ID, host.ETag, WriterStopEvidence("verified"))
	if err == nil || !strings.Contains(err.Error(), "detach and retain") {
		t.Fatalf("termination with attached retained volume should be held, got %v", err)
	}
	if provider.terminations != 0 || writerStop.instanceChecks != 0 {
		t.Fatalf("unsafe termination path ran: terminations=%d writerChecks=%d", provider.terminations, writerStop.instanceChecks)
	}

	delete(provider.attachments, "attachment-1")
	writerStop.instanceErr = ErrWriterStopUnverified
	err = fleet.Terminate(ctx, host.ID, host.ETag, WriterStopEvidence("invalid"))
	if !errors.Is(err, ErrWriterStopUnverified) {
		t.Fatalf("termination without proof should fail closed, got %v", err)
	}
	if provider.terminations != 0 {
		t.Fatalf("invalid proof still terminated the host: %d", provider.terminations)
	}
}

func TestRetainedVolumeAttachRequiresDurableOwnership(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-create-04")))
	if err != nil {
		t.Fatal(err)
	}
	volumeKey := "data-volume-01"
	provider.volumes["ocid1.volume.retained"] = CloudVolume{
		ID: "ocid1.volume.retained", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, SizeGB: 50, VPUsPerGB: 10,
		LifecycleState: "AVAILABLE", FreeformTags: map[string]string{
			tagManagedBy: managedByValue, tagOwner: config.Owner, tagRegion: string(config.Region),
			tagGeneration: fmt.Sprint(config.Generation), tagResource: resourceMemberData, tagCreateKey: volumeKey,
			tagVolumeSize: "50",
		},
	}

	_, err = fleet.AttachRetainedVolume(ctx, VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ",
		VolumeID: "ocid1.volume.retained", InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-volume-01"),
	})
	if !errors.Is(err, ErrForeignResource) {
		t.Fatalf("untagged/unjournaled volume must not be adopted, got %v", err)
	}
	if provider.attachCalls != 0 {
		t.Fatalf("unowned volume was attached: %d", provider.attachCalls)
	}
}

func TestRetainedVolumeAttachPersistsDeviceAndRecoversAmbiguousOutcome(t *testing.T) {
	ctx := t.Context()
	config, provider, journal, fleet, host, volume := newAttachTestState(t)
	available := true
	provider.devices[host.ID] = []CloudDevice{
		{Name: "/dev/oracleoci/oraclevdaa", IsAvailable: &available},
		{Name: "/dev/oracleoci/oraclevdc", IsAvailable: &available},
		{Name: "/dev/oracleoci/oraclevdb", IsAvailable: &available},
	}
	provider.afterAttach = func(provider *fakeProvider, _ string) {
		provider.attachmentListErr = errors.New("attachment observation unavailable")
	}
	request := VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-durable-device")}
	if _, err := fleet.AttachRetainedVolume(ctx, request); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("lost attachment observation was not reported as ambiguous: %v", err)
	}
	scope := OperationScope{
		Action: actionVolumeAttach, Key: request.IdempotencyKey, Region: config.Region,
		Generation: config.Generation, Owner: config.Owner,
	}
	intent, found, err := journal.GetOperation(ctx, scope)
	if err != nil || !found {
		t.Fatalf("durable attachment intent was not recoverable: found=%v intent=%+v err=%v", found, intent, err)
	}
	if intent.Device != "/dev/oracleoci/oraclevdb" || intent.IsReadOnly || intent.IsShareable || !intent.IsPvEncryptionInTransitEnabled {
		t.Fatalf("attachment path or fixed policy was not durably selected: %+v", intent)
	}
	result, found, err := journal.GetResult(ctx, intent)
	if err != nil || !found || !result.Unknown {
		t.Fatalf("ambiguous attachment result was not durably recorded: found=%v result=%+v err=%v", found, result, err)
	}

	// A controller restart sees a different free-device list, but must recover
	// the original path and the existing exact attachment from the journal.
	available = true
	provider.devices[host.ID] = []CloudDevice{{Name: "/dev/oracleoci/oraclevdc", IsAvailable: &available}}
	restarted, err := newTestFleet(config, mustTestRegionIntent(t), provider, journal,
		&fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	attachment, err := restarted.AttachRetainedVolume(ctx, request)
	if err != nil {
		t.Fatalf("ambiguous attachment did not recover: %v", err)
	}
	if attachment.Device != intent.Device || attachment.State != "ATTACHED" ||
		attachment.IsReadOnly || attachment.IsShareable || !attachment.IsPvEncryptionInTransitEnabled || provider.attachCalls != 1 {
		t.Fatalf("recovery changed the original path or flags: attachment=%+v calls=%d", attachment, provider.attachCalls)
	}
	observed, err := restarted.Observe(ctx)
	if err != nil || len(observed) != 1 || len(observed[0].Attachments) != 1 || observed[0].Attachments[0] != attachment {
		t.Fatalf("confirmed attachment projection was not returned by Observe: observed=%+v err=%v", observed, err)
	}
}

func TestRetainedVolumeAttachHoldsExistingAttachmentWithoutOperation(t *testing.T) {
	ctx := t.Context()
	_, provider, journal, fleet, host, volume := newAttachTestState(t)
	provider.attachments["attachment-unbound"] = CloudAttachment{
		ID: "attachment-unbound", VolumeID: volume.ID, InstanceID: host.ID,
		LifecycleState: "ATTACHED", ETag: "unbound-etag", Device: "/dev/oracleoci/oraclevdb",
		IsReadOnly: boolPointer(false), IsShareable: boolPointer(false), IsPvEncryptionInTransitEnabled: boolPointer(true),
	}
	request := VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-existing-without-op")}
	if _, err := fleet.AttachRetainedVolume(ctx, request); !errors.Is(err, ErrAttachmentRecoveryHold) {
		t.Fatalf("unbound existing attachment was adopted: %v", err)
	}
	if provider.attachCalls != 0 {
		t.Fatalf("unbound attachment triggered another attach: %d", provider.attachCalls)
	}
	observed, err := fleet.Observe(ctx)
	if err != nil || len(observed) != 0 {
		t.Fatalf("Observe exposed an attachment without a durable operation: observed=%+v err=%v", observed, err)
	}
	if _, found, err := journal.GetOperation(ctx, OperationScope{
		Action: actionVolumeAttach, Key: request.IdempotencyKey, Region: host.Region,
		Generation: host.Generation, Owner: host.Owner,
	}); err != nil || found {
		t.Fatalf("an unbound attachment was wrapped in a new durable operation: found=%v err=%v", found, err)
	}
}

func TestRetainedVolumeAttachRecoversExactAttachmentFromIntentWithoutResult(t *testing.T) {
	ctx := t.Context()
	config, provider, journal, fleet, host, volume := newAttachTestState(t)
	request := VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-intent-only-recovery")}
	intent := OperationIntent{
		Action: actionVolumeAttach, Key: request.IdempotencyKey, Region: config.Region,
		Generation: config.Generation, Owner: config.Owner, ResourceID: host.ID, CreateKey: host.CreateKey,
		ExpectedETag: host.ETag, VolumeID: volume.ID, Device: "/dev/oracleoci/oraclevdc",
		IsReadOnly: false, IsShareable: false, IsPvEncryptionInTransitEnabled: true,
		CreatedAt: time.Now().UTC(),
	}
	if err := journal.RecordIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	provider.attachments["attachment-from-intent"] = CloudAttachment{
		ID: "attachment-from-intent", VolumeID: volume.ID, InstanceID: host.ID,
		LifecycleState: "ATTACHED", ETag: "attached-etag", Device: intent.Device,
		IsReadOnly: boolPointer(false), IsShareable: boolPointer(false), IsPvEncryptionInTransitEnabled: boolPointer(true),
	}
	attachment, err := fleet.AttachRetainedVolume(ctx, request)
	if err != nil {
		t.Fatalf("fresh durable intent did not recover the already-observed exact attachment: %v", err)
	}
	if attachment.ID != "attachment-from-intent" || attachment.Device != intent.Device || provider.attachCalls != 0 {
		t.Fatalf("intent-only recovery selected or created a different attachment: %+v calls=%d", attachment, provider.attachCalls)
	}
	result, found, err := journal.GetResult(ctx, intent)
	if err != nil || !found || result.Unknown || result.ResourceID != attachment.ID || result.ETag != attachment.ETag {
		t.Fatalf("exact recovered attachment did not become a durable positive result: found=%v result=%+v err=%v", found, result, err)
	}
}

func TestRetainedVolumeAttachHoldsExpiredPendingAndUnknownIntents(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		name := "pending"
		if unknown {
			name = "unknown"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			config, provider, journal, fleet, host, volume := newAttachTestState(t)
			request := VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-expired", name)}
			intent := OperationIntent{
				Action: actionVolumeAttach, Key: request.IdempotencyKey, Region: config.Region,
				Generation: config.Generation, Owner: config.Owner, ResourceID: host.ID, CreateKey: host.CreateKey,
				ExpectedETag: host.ETag, VolumeID: volume.ID, Device: "/dev/oracleoci/oraclevdb",
				IsReadOnly: false, IsShareable: false, IsPvEncryptionInTransitEnabled: true,
				CreatedAt: time.Now().Add(-maxCreateRetryAge - time.Minute).UTC(),
			}
			if err := journal.RecordIntent(ctx, intent); err != nil {
				t.Fatal(err)
			}
			if unknown {
				if err := journal.RecordResult(ctx, OperationResult{Intent: intent, Unknown: true}); err != nil {
					t.Fatal(err)
				}
			}
			_, err := fleet.AttachRetainedVolume(ctx, request)
			if !errors.Is(err, ErrCreateRecoveryHold) {
				t.Fatalf("expired %s attachment intent was replayed instead of held: %v", name, err)
			}
			hold, ok := errors.AsType[*CreateRecoveryHoldError](err)
			if !ok || hold.CreateKey != request.IdempotencyKey {
				t.Fatalf("expired %s attachment intent returned no typed recovery hold: %#v", name, err)
			}
			if provider.attachCalls != 0 || provider.deviceListCalls != 0 {
				t.Fatalf("expired %s intent reached OCI or reselected a path: attachCalls=%d deviceLists=%d", name, provider.attachCalls, provider.deviceListCalls)
			}
		})
	}
}

func TestRetainedVolumeAttachConfirmsExactObservationAfterRetryWindow(t *testing.T) {
	ctx := t.Context()
	config, provider, journal, fleet, host, volume := newAttachTestState(t)
	request := VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-expired-observed")}
	intent := OperationIntent{
		Action: actionVolumeAttach, Key: request.IdempotencyKey, Region: config.Region,
		Generation: config.Generation, Owner: config.Owner, ResourceID: host.ID, CreateKey: host.CreateKey,
		ExpectedETag: host.ETag, VolumeID: volume.ID, Device: "/dev/oracleoci/oraclevdb",
		IsReadOnly: false, IsShareable: false, IsPvEncryptionInTransitEnabled: true,
		CreatedAt: time.Now().Add(-maxCreateRetryAge - time.Minute).UTC(),
	}
	if err := journal.RecordIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, OperationResult{Intent: intent, Unknown: true}); err != nil {
		t.Fatal(err)
	}
	provider.attachments["attachment-expired-observed"] = CloudAttachment{
		ID: "attachment-expired-observed", VolumeID: volume.ID, InstanceID: host.ID,
		LifecycleState: "ATTACHED", ETag: "attachment-etag", Device: intent.Device,
		IsReadOnly: boolPointer(false), IsShareable: boolPointer(false), IsPvEncryptionInTransitEnabled: boolPointer(true),
	}
	attachment, err := fleet.AttachRetainedVolume(ctx, request)
	if err != nil {
		t.Fatalf("exact observed attachment was not confirmed after expiry: %v", err)
	}
	if attachment.ID != "attachment-expired-observed" || provider.attachCalls != 0 || provider.deviceListCalls != 0 {
		t.Fatalf("post-expiry confirmation caused a new effect or selection: attachment=%+v calls=%d deviceLists=%d",
			attachment, provider.attachCalls, provider.deviceListCalls)
	}
	result, found, err := journal.GetResult(ctx, intent)
	if err != nil || !found || result.Unknown || result.ResourceID != attachment.ID || result.ETag != attachment.ETag {
		t.Fatalf("exact post-expiry observation was not made durable: found=%v result=%+v err=%v", found, result, err)
	}
}

func TestRetainedVolumeAttachRechecksRetryWindowAfterAuthorityGuard(t *testing.T) {
	ctx := t.Context()
	config, provider, journal, _, host, volume := newAttachTestState(t)
	_, regionIntent := testRegionConfig()
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	fleetValue, err := newTestFleet(config, regionIntent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	implementation := fleetValue.(*fleet)
	now := time.Now().UTC()
	implementation.now = func() time.Time { return now }
	var finalGuardReached bool
	fencer.onGuard = func() {
		if fencer.guards == 2 {
			now = now.Add(maxCreateRetryAge)
			finalGuardReached = true
		}
	}

	_, err = fleetValue.AttachRetainedVolume(ctx, VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ",
		VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-expires-during-guard"),
	})
	if !errors.Is(err, ErrCreateRecoveryHold) {
		t.Fatalf("attachment that expired during authority guard was not held: %v", err)
	}
	if !finalGuardReached || fencer.guards != 2 {
		t.Fatalf("attachment did not pass through the final authority guard: reached=%v guards=%d", finalGuardReached, fencer.guards)
	}
	if provider.attachCalls != 0 || provider.deviceListCalls != 1 {
		t.Fatalf("expired attachment called OCI or reselected its device: attachCalls=%d deviceLists=%d", provider.attachCalls, provider.deviceListCalls)
	}
	intent, found, err := journal.GetOperation(ctx, OperationScope{
		Action: actionVolumeAttach, Key: entityid.Derive("test-attach", "attach-expires-during-guard"), Region: host.Region,
		Generation: host.Generation, Owner: host.Owner,
	})
	if err != nil || !found || !validDevicePath(intent.Device) {
		t.Fatalf("expired operation did not retain its selected durable device: found=%v intent=%+v err=%v", found, intent, err)
	}
}

func TestRetainedVolumeOperationsHoldWithoutImageVerifier(t *testing.T) {
	ctx := t.Context()
	config, provider, journal, _, host, volume := newAttachTestState(t)
	nilVerifierFleet, err := NewFleet(config, mustTestRegionIntent(t), provider, journal,
		&fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nilVerifierFleet.CreateRetainedVolume(ctx, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000FMHEFZNR056ZVCDX", SizeGB: 50}); !errors.Is(err, ErrImageQualificationUnavailable) {
		t.Fatalf("volume creation without image evidence was not held: %v", err)
	}
	if _, err := nilVerifierFleet.AttachRetainedVolume(ctx, VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ",
		VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-no-qualification"),
	}); !errors.Is(err, ErrImageQualificationUnavailable) {
		t.Fatalf("volume attachment without image evidence was not held: %v", err)
	}
	if provider.volumeCreateCalls != 1 || provider.attachCalls != 0 {
		t.Fatalf("unqualified fleet reached OCI: volumeCalls=%d attachCalls=%d", provider.volumeCreateCalls, provider.attachCalls)
	}
}

// A new launch of the signed pin needs current qualification too: without a
// qualification source, or with the pin refused, nothing reaches OCI.
func TestEnsureHostHoldsAnUnqualifiedPin(t *testing.T) {
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	unverified, err := NewFleet(config, regionIntent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unverified.EnsureHost(t.Context(), testEnsureRequest(entityid.Derive("test-operation", "node-unverified-pin"))); !errors.Is(err, ErrImageQualificationUnavailable) {
		t.Fatalf("launch without image evidence: %v", err)
	}
	refusing, err := NewFleetWithImageVerifier(config, regionIntent, provider, newFakeJournal(),
		&fakeFencer{snapshot: writableSnapshot()}, nil, nil, &fakeImageVerifier{refuse: config.ImageID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refusing.EnsureHost(t.Context(), testEnsureRequest(entityid.Derive("test-operation", "node-refused-pin"))); !errors.Is(err, ErrImageNotQualified) {
		t.Fatalf("launch of a refused pin: %v", err)
	}
	if provider.launchCalls != 0 {
		t.Fatalf("an unqualified pin reached OCI: calls=%d", provider.launchCalls)
	}
}

func TestFleetVerifyHostImageIsPublicReadinessGate(t *testing.T) {
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fencer := &fakeFencer{snapshot: writableSnapshot()}
	verifier := &fakeImageVerifier{}
	fleet, err := NewFleetWithImageVerifier(config, intent, provider, journal, fencer, nil, nil, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := fleet.VerifyHostImage(t.Context(), config.ImageID); err != nil {
		t.Fatalf("qualified pinned image was held: %v", err)
	}
	if !slices.Equal(verifier.images, []string{config.ImageID}) {
		t.Fatalf("readiness checked wrong image: %v", verifier.images)
	}
	verifier.err = errors.New("image readback changed")
	if err := fleet.VerifyHostImage(t.Context(), config.ImageID); !errors.Is(err, ErrImageNotQualified) {
		t.Fatalf("changed image was accepted: %v", err)
	}
	withoutVerifier, err := NewFleet(config, intent, provider, journal, fencer, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := withoutVerifier.VerifyHostImage(t.Context(), config.ImageID); !errors.Is(err, ErrImageQualificationUnavailable) {
		t.Fatalf("absent image verifier was accepted: %v", err)
	}
	if provider.launches != 0 || provider.volumeCreateCalls != 0 {
		t.Fatal("image readiness gate mutated OCI")
	}
}

func TestRetainedVolumeAttachRequiresPinnedImageAndConsistentNaming(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*CloudInstance)
	}{
		{name: "wrong image", mutate: func(instance *CloudInstance) { instance.ImageID = "ocid1.image.other" }},
		{name: "missing launch option", mutate: func(instance *CloudInstance) { instance.ConsistentVolumeNamingEnabled = nil }},
		{name: "disabled launch option", mutate: func(instance *CloudInstance) { instance.ConsistentVolumeNamingEnabled = boolPointer(false) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			_, provider, _, fleet, host, volume := newAttachTestState(t)
			instance := provider.instances[host.ID]
			test.mutate(&instance)
			provider.instances[host.ID] = instance
			_, err := fleet.AttachRetainedVolume(ctx, VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ",
				VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-unqualified-host"),
			})
			if !errors.Is(err, ErrImageNotQualified) || provider.attachCalls != 0 {
				t.Fatalf("ineligible host reached attachment: err=%v calls=%d", err, provider.attachCalls)
			}
		})
	}
}

func TestRetainedVolumeAttachConfirmsTheSettledAttachment(t *testing.T) {
	ctx := t.Context()
	_, provider, journal, fleet, host, volume := newAttachTestState(t)
	attachment, err := fleet.AttachRetainedVolume(ctx, VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ",
		VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-settles"),
	})
	if err != nil || attachment.ETag != "a1" || attachment.State != "ATTACHED" || provider.attachCalls != 1 {
		t.Fatalf("settled attachment = %+v, %v (calls %d)", attachment, err, provider.attachCalls)
	}
	operation, found, err := journal.GetOperation(ctx, OperationScope{
		Action: actionVolumeAttach, Key: entityid.Derive("test-attach", "attach-settles"), Region: host.Region,
		Generation: host.Generation, Owner: host.Owner,
	})
	if err != nil || !found {
		t.Fatalf("attach intent missing: %v", err)
	}
	if result, found, err := journal.GetResult(ctx, operation); err != nil || !found || result.Unknown || result.ETag != "a1" {
		t.Fatalf("settled attachment result = %+v, %v", result, err)
	}
	observed, err := fleet.Observe(ctx)
	if err != nil || len(observed) != 1 || len(observed[0].Attachments) != 1 || observed[0].Attachments[0].ID != attachment.ID {
		t.Fatalf("host with its confirmed attachment was withheld: %+v, %v", observed, err)
	}
}

func TestRetainedVolumeAttachScopesItsRetryTokenToTheFleet(t *testing.T) {
	config, provider, _, fleet, host, volume := newAttachTestState(t)
	if _, err := fleet.AttachRetainedVolume(t.Context(), VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ",
		VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-shared-key"),
	}); err != nil {
		t.Fatal(err)
	}
	scoped := retryToken(strings.Join([]string{config.Owner, string(config.Region), fmt.Sprint(config.Generation), entityid.Derive("test-attach", "attach-shared-key")}, ":"))
	if _, ok := provider.attachRetryTokens[scoped]; !ok || len(provider.attachRetryTokens) != 1 {
		t.Fatalf("attach used an unscoped OCI retry token: %v", provider.attachRetryTokens)
	}
}

func setAttachmentSettle(f Fleet, timeout time.Duration) {
	f.(*fleet).attachmentSettle = timeout
}

func TestRetainedVolumeAttachRejectsIncompleteObservedPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*CloudAttachment)
	}{
		{name: "missing readonly flag", mutate: func(attachment *CloudAttachment) { attachment.IsReadOnly = nil }},
		{name: "wrong device", mutate: func(attachment *CloudAttachment) { attachment.Device = "/dev/oracleoci/oraclevdc" }},
		{name: "never settles", mutate: func(attachment *CloudAttachment) { attachment.LifecycleState = "ATTACHING" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			_, provider, journal, fleet, host, volume := newAttachTestState(t)
			setAttachmentSettle(fleet, 50*time.Millisecond)
			provider.afterAttach = func(provider *fakeProvider, attachmentID string) {
				attachment := provider.attachments[attachmentID]
				test.mutate(&attachment)
				provider.attachments[attachmentID] = attachment
			}
			_, err := fleet.AttachRetainedVolume(ctx, VolumeAttachRequest{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ",
				VolumeID: volume.ID, InstanceID: host.ID, IdempotencyKey: entityid.Derive("test-attach", "attach-invalid-observation"),
			})
			if !errors.Is(err, ErrOutcomeUnknown) || provider.attachCalls != 1 {
				t.Fatalf("incomplete attachment observation was accepted: err=%v calls=%d", err, provider.attachCalls)
			}
			operation, found, lookupErr := journal.GetOperation(ctx, OperationScope{
				Action: actionVolumeAttach, Key: entityid.Derive("test-attach", "attach-invalid-observation"), Region: host.Region,
				Generation: host.Generation, Owner: host.Owner,
			})
			if lookupErr != nil || !found {
				t.Fatalf("invalid observation lost its durable intent: found=%v err=%v", found, lookupErr)
			}
			result, found, resultErr := journal.GetResult(ctx, operation)
			if resultErr != nil || !found || !result.Unknown {
				t.Fatalf("invalid observation was not kept unknown: found=%v result=%+v err=%v", found, result, resultErr)
			}
		})
	}
}

func TestObserveReturnsOnlyDurablyOwnedInstancesAndTerminalState(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-create-05")))
	if err != nil {
		t.Fatal(err)
	}
	current := provider.instances[host.ID]
	current.LifecycleState = "TERMINATED"
	provider.instances[host.ID] = current

	observed, err := fleet.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) != 1 || observed[0].State != "TERMINATED" || observed[0].Node != host.Node {
		t.Fatalf("terminal owned host was not preserved as an observation: %+v", observed)
	}
	if observed[0].PlacementProfileDigest != host.PlacementProfileDigest ||
		observed[0].PlacementGeneration != host.PlacementGeneration || observed[0].Shape != host.Shape ||
		observed[0].WholeOCPUs != host.WholeOCPUs || observed[0].MemoryInGBs != host.MemoryInGBs {
		t.Fatalf("Observe did not return the verified immutable placement profile: observed=%+v initial=%+v", observed[0], host)
	}
}

func TestObserveWithholdsOwnedInstanceAfterComputeProfileDrift(t *testing.T) {
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, err := fleet.EnsureHost(t.Context(), testEnsureRequest(entityid.Derive("test-operation", "node-observe-profile-drift")))
	if err != nil {
		t.Fatal(err)
	}
	cloud := provider.instances[host.ID]
	cloud.MemoryInGBs = new(float32(8))
	provider.instances[host.ID] = cloud

	observed, err := fleet.Observe(t.Context())
	if err != nil || len(observed) != 0 {
		t.Fatalf("Observe returned a host after its pinned profile changed: observed=%+v err=%v", observed, err)
	}
}

func TestObserveSkipsUnverifiedIdentitiesWithoutBlockingOwnedInstances(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "node-owned-observation")))
	if err != nil {
		t.Fatal(err)
	}
	foreignConfig := config
	foreignConfig.Generation--
	provider.instances["ocid1.instance.old-generation"] = CloudInstance{
		ID: "ocid1.instance.old-generation", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, FaultDomain: "FAULT-DOMAIN-1",
		LifecycleState: "RUNNING", ETag: "old-etag", FreeformTags: hostTags(foreignConfig, "node-old-generation"),
	}
	provider.instances["ocid1.instance.tag-only"] = CloudInstance{
		ID: "ocid1.instance.tag-only", CompartmentID: config.CompartmentID,
		AvailabilityDomain: config.AvailabilityDomain, FaultDomain: "FAULT-DOMAIN-1",
		LifecycleState: "RUNNING", ETag: "tag-only-etag", FreeformTags: hostTags(config, "node-tag-only"),
	}

	observed, err := fleet.Observe(ctx)
	if err != nil {
		t.Fatalf("unverified instance blocked owned fleet observation: %v", err)
	}
	if len(observed) != 1 || observed[0].ID != owned.ID || len(journal.instances) != 1 || provider.launches != 1 {
		t.Fatalf("observation returned or mutated an unverified host: observed=%+v owned=%+v launches=%d",
			observed, journal.instances, provider.launches)
	}
}

func TestObserveWithholdsOnlyUnverifiedRetainedVolumeHost(t *testing.T) {
	providerFailure := errors.New("OCI retained volume read failed")
	tests := []struct {
		name      string
		prepare   func(*fakeProvider, Instance, RetainedVolume) Provider
		wantError bool
	}{
		{
			name: "foreign attachment scope",
			prepare: func(provider *fakeProvider, bad Instance, _ RetainedVolume) Provider {
				provider.attachments["attachment-foreign-scope"] = observeTestAttachment("attachment-foreign-scope", "", bad.ID)
				return provider
			},
		},
		{
			name: "foreign retained volume",
			prepare: func(provider *fakeProvider, bad Instance, owned RetainedVolume) Provider {
				foreign := provider.volumes[owned.ID]
				foreign.ID = "ocid1.volume.foreign-observe"
				foreign.VPUsPerGB++
				provider.volumes[foreign.ID] = foreign
				provider.attachments["attachment-foreign-volume"] = observeTestAttachment("attachment-foreign-volume", foreign.ID, bad.ID)
				return provider
			},
		},
		{
			name: "unowned tag-shaped retained volume",
			prepare: func(provider *fakeProvider, bad Instance, owned RetainedVolume) Provider {
				unowned := provider.volumes[owned.ID]
				unowned.ID = "ocid1.volume.unowned-observe"
				provider.volumes[unowned.ID] = unowned
				provider.attachments["attachment-unowned-volume"] = observeTestAttachment("attachment-unowned-volume", unowned.ID, bad.ID)
				return provider
			},
		},
		{
			name: "unconfirmed attachment",
			prepare: func(provider *fakeProvider, bad Instance, owned RetainedVolume) Provider {
				provider.attachments["attachment-unconfirmed"] = observeTestAttachment("attachment-unconfirmed", owned.ID, bad.ID)
				return provider
			},
		},
		{
			name: "GetVolume provider failure",
			prepare: func(provider *fakeProvider, bad Instance, owned RetainedVolume) Provider {
				provider.attachments["attachment-volume-read"] = observeTestAttachment("attachment-volume-read", owned.ID, bad.ID)
				return &observeFailingGetProvider{fakeProvider: provider, volumeID: owned.ID, failure: providerFailure}
			},
			wantError: true,
		},
		{
			name: "GetVolumeAttachment provider failure",
			prepare: func(provider *fakeProvider, bad Instance, owned RetainedVolume) Provider {
				provider.attachments["attachment-read"] = observeTestAttachment("attachment-read", owned.ID, bad.ID)
				return &observeFailingGetProvider{fakeProvider: provider, attachmentID: "attachment-read", failure: providerFailure}
			},
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			config, intent := testRegionConfig()
			provider := newFakeProvider(config)
			journal := newFakeJournal()
			setup, err := newTestFleet(config, intent, provider, journal,
				&fakeFencer{snapshot: writableSnapshot()}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			bad, err := setup.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "observe-attachment-bad")))
			if err != nil {
				t.Fatal(err)
			}
			goodRequest := testEnsureRequest(entityid.Derive("test-operation", "observe-attachment-good"))
			goodRequest.PrivateIP = "10.251.0.22"
			good, err := setup.EnsureHost(ctx, goodRequest)
			if err != nil {
				t.Fatal(err)
			}
			owned, err := setup.CreateRetainedVolume(ctx, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "00000000004CCHBA53BNA84CNX", SizeGB: 50})
			if err != nil {
				t.Fatal(err)
			}
			readOnlyJournal := &observeReadOnlyJournal{fakeJournal: journal}
			readProvider := test.prepare(provider, bad, owned)
			fleet, err := newTestFleet(config, intent, readProvider, readOnlyJournal,
				&fakeFencer{snapshot: writableSnapshot()}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := fleet.Observe(ctx)
			if test.wantError {
				if !errors.Is(err, providerFailure) || errors.Is(err, ErrForeignResource) || len(observed) != 0 {
					t.Fatalf("provider read failure was withheld: observed=%+v err=%v", observed, err)
				}
			} else if err != nil || len(observed) != 1 || observed[0].ID != good.ID {
				t.Fatalf("unverified attachment hid healthy host or exposed bad host: observed=%+v err=%v", observed, err)
			}
			if provider.launches != 2 || provider.attachCalls != 0 || provider.volumeCreates != 1 ||
				provider.terminations != 0 || readOnlyJournal.writes != 0 || len(journal.attachments) != 0 {
				t.Fatalf("Observe mutated or adopted resources: launches=%d attaches=%d volumes=%d terminations=%d journal writes=%d owned attachments=%d",
					provider.launches, provider.attachCalls, provider.volumeCreates, provider.terminations,
					readOnlyJournal.writes, len(journal.attachments))
			}
		})
	}
}

func observeTestAttachment(id, volumeID, instanceID string) CloudAttachment {
	return CloudAttachment{
		ID: id, VolumeID: volumeID, InstanceID: instanceID, LifecycleState: "ATTACHED",
		ETag: "observe-etag", Device: "/dev/oracleoci/oraclevdb",
		IsReadOnly: boolPointer(false), IsShareable: boolPointer(false),
		IsPvEncryptionInTransitEnabled: boolPointer(true),
	}
}

type observeFailingGetProvider struct {
	*fakeProvider
	volumeID     string
	attachmentID string
	failure      error
}

func (provider *observeFailingGetProvider) GetVolume(ctx context.Context, id string) (CloudVolume, error) {
	if id == provider.volumeID {
		return CloudVolume{}, provider.failure
	}
	return provider.fakeProvider.GetVolume(ctx, id)
}

func (provider *observeFailingGetProvider) GetVolumeAttachment(ctx context.Context, id string) (CloudAttachment, error) {
	if id == provider.attachmentID {
		return CloudAttachment{}, provider.failure
	}
	return provider.fakeProvider.GetVolumeAttachment(ctx, id)
}

func TestObserveAllowsEnsureHostToRecoverDurableUnknownLaunch(t *testing.T) {
	ctx := t.Context()
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, intent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	createKey := entityid.Derive("test-operation", "node-durable-unknown")
	operation := testLaunchIntent(createKey)
	operation.Region = config.Region
	operation.Generation = config.Generation
	operation.Owner = config.Owner
	operation.CreatedAt = time.Now().UTC()
	if err := journal.RecordIntent(ctx, operation); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(ctx, OperationResult{Intent: operation, Unknown: true}); err != nil {
		t.Fatal(err)
	}
	instanceID := "ocid1.instance.unknown-launch"
	provider.instances[instanceID] = CloudInstance{
		ID: instanceID, PrivateIP: operation.PrivateIP, CompartmentID: config.CompartmentID, AvailabilityDomain: config.AvailabilityDomain,
		FaultDomain: "FAULT-DOMAIN-1", Shape: operation.Shape, Ocpus: new(float32(operation.WholeOCPUs)),
		MemoryInGBs: new(float32(operation.MemoryInGBs)), LifecycleState: "PROVISIONING", ETag: "unknown-etag",
		ImageID: config.ImageID, Metadata: map[string]string{hostboot.MetadataKey: operation.BootDescriptor},
		FreeformTags: placementProfileTags(hostTags(config, createKey), operation.PlacementProfileDigest, operation.PlacementGeneration),
	}
	provider.launchRetryTokens[retryToken(strings.Join([]string{
		config.Owner, string(config.Region), fmt.Sprint(config.Generation), createKey,
	}, ":"))] = instanceID

	observed, err := fleet.Observe(ctx)
	if err != nil || len(observed) != 0 {
		t.Fatalf("unconfirmed launch should be withheld without blocking Observe: observed=%+v err=%v", observed, err)
	}
	recovered, err := fleet.EnsureHost(ctx, ensureRequestForIntent(operation))
	if err != nil || recovered.ID != instanceID {
		t.Fatalf("durable unknown launch was not recovered through retry-token proof: recovered=%+v err=%v", recovered, err)
	}
	observed, err = fleet.Observe(ctx)
	if err != nil || len(observed) != 1 || observed[0].ID != instanceID {
		t.Fatalf("confirmed launch was not returned as an owned observation: observed=%+v err=%v", observed, err)
	}
}

func testRegionConfig() (RegionConfig, RegionIntent) {
	intent := RegionIntent{
		SchemaVersion: 1, Generation: 7, BootstrapRegion: RegionGRU,
		Regions: []RegionMapping{{Cell: RegionGRU, OCIRegion: "sa-saopaulo-1"}},
	}
	return RegionConfig{
		Region: RegionGRU, Generation: intent.Generation,
		Endpoint:                "https://iaas.sa-saopaulo-1.oraclecloud.com",
		CompartmentID:           "ocid1.compartment.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImageCompartmentID:      "ocid1.compartment.oc1..bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		AvailabilityDomain:      "sa-saopaulo-1-AD-1",
		FaultDomains:            []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		SubnetID:                "ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		ImageID:                 "ocid1.image.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BootVolumeGB:            50,
		BootVolumeVPUsPerGB:     10,
		DataVolumeVPUsPerGB:     10,
		MaxDataVolumeGB:         32768,
		Shape:                   "VM.Standard.E5.Flex", Owner: "orchestrator",
	}, intent
}

func testEnsureRequest(createKey string) EnsureRequest {
	return EnsureRequest{
		Name: "gru-1-db-1", CreateKey: createKey, PrivateIP: "10.251.0.21", FaultDomain: "FAULT-DOMAIN-1", Shape: "VM.Standard.E5.Flex",
		WholeOCPUs: 1, MemoryInGBs: 6, PlacementProfileDigest: strings.Repeat("a", 64), PlacementGeneration: 3,
		BootPins: HostBootPins{
			DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", SeatID: "0000000000M4R4NE7RJXQ9M8NM",
			HostAttempt: 1, IntentPayloadDigest: strings.Repeat("b", 64),
			CanonicalRosterDigest: strings.Repeat("c", 64), RuntimeManifestDigest: strings.Repeat("d", 64),
		},
	}
}

func ensureRequestForIntent(intent OperationIntent) EnsureRequest {
	descriptor, err := hostboot.Parse([]byte(intent.BootDescriptor))
	if err != nil {
		panic(err)
	}
	return EnsureRequest{
		Name: "gru-1-db-1", CreateKey: intent.CreateKey, PrivateIP: intent.PrivateIP, FaultDomain: intent.FaultDomain, Shape: intent.Shape,
		WholeOCPUs: intent.WholeOCPUs, MemoryInGBs: intent.MemoryInGBs,
		PlacementProfileDigest: intent.PlacementProfileDigest, PlacementGeneration: intent.PlacementGeneration,
		BootPins: HostBootPins{
			DatabaseID: descriptor.DatabaseID, PartitionID: descriptor.PartitionID, SeatID: descriptor.SeatID,
			HostAttempt: descriptor.HostAttempt, IntentPayloadDigest: descriptor.IntentPayloadDigest,
			CanonicalRosterDigest: descriptor.CanonicalRosterDigest, RuntimeManifestDigest: descriptor.RuntimeManifestDigest,
		},
	}
}

func sameLaunchProfile(a, b LaunchRequest) bool {
	return a.CreateKey == b.CreateKey && a.Node == b.Node && a.PrivateIP == b.PrivateIP && a.FaultDomain == b.FaultDomain &&
		a.Shape == b.Shape && a.WholeOCPUs == b.WholeOCPUs && a.MemoryInGBs == b.MemoryInGBs &&
		a.PlacementProfileDigest == b.PlacementProfileDigest && a.PlacementGeneration == b.PlacementGeneration &&
		a.ImageID == b.ImageID && a.BootDescriptor == b.BootDescriptor &&
		maps.Equal(a.FreeformTags, b.FreeformTags)
}

func writableSnapshot() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		CandidateID: "00000000008VQHCQFMKQSH41D6", Leader: true, Ready: true, Epoch: 4, Revision: 9,
		ExpiresAt: time.Now().Add(time.Minute), ObservedAt: time.Now(),
	}
}

type fakeFencer struct {
	snapshot      authority.Snapshot
	guardErr      error
	guards        int
	onGuard       func()
	terminalEntry authority.LogEntry
}

func (f *fakeFencer) Current() authority.Snapshot { return f.snapshot }
func (f *fakeFencer) ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error) {
	if f.terminalEntry.Sequence == 0 {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	return f.terminalEntry, nil
}
func (f *fakeFencer) BeginActiveWorkloadEffect(ctx context.Context, epoch uint64, scope authority.WorkloadScope) (func(), error) {
	if scope.DatabaseID == "" || scope.PartitionID == "" {
		return nil, errors.New("missing test workload scope")
	}
	if err := f.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	return func() {}, nil
}
func (f *fakeFencer) Guard(context.Context, uint64) error {
	f.guards++
	if f.onGuard != nil {
		f.onGuard()
	}
	return f.guardErr
}

type fakeJournal struct {
	terminations map[string]RegionConfig
	intents      map[string]OperationIntent
	results      map[string]OperationResult
	instances    map[string]ResourceIdentity
	volumes      map[string]ResourceIdentity
	attachments  map[string]AttachmentIdentity
	bootBindings map[string]BootBinding
}

func newFakeJournal() *fakeJournal {
	return &fakeJournal{
		terminations: make(map[string]RegionConfig),
		intents:      make(map[string]OperationIntent), results: make(map[string]OperationResult),
		instances: make(map[string]ResourceIdentity),
		volumes:   make(map[string]ResourceIdentity), attachments: make(map[string]AttachmentIdentity),
		bootBindings: make(map[string]BootBinding),
	}
}

func (j *fakeJournal) RecordVolumeTermination(_ context.Context, config RegionConfig, id string) error {
	j.terminations[id] = config
	return nil
}

func (j *fakeJournal) RecordBootBinding(_ context.Context, binding BootBinding) error {
	if existing, ok := j.bootBindings[binding.InstanceID]; ok && existing != binding {
		return errors.New("boot binding conflict")
	}
	j.bootBindings[binding.InstanceID] = binding
	return nil
}

func (j *fakeJournal) GetBootBinding(_ context.Context, instanceID string) (BootBinding, bool, error) {
	binding, ok := j.bootBindings[instanceID]
	return binding, ok, nil
}

func (j *fakeJournal) ListOperations(context.Context) ([]OperationRecord, error) {
	items := make([]OperationRecord, 0, len(j.intents))
	for key, intent := range j.intents {
		items = append(items, OperationRecord{Intent: intent, Result: j.results[key]})
	}
	return items, nil
}

func (j *fakeJournal) RecordIntent(_ context.Context, intent OperationIntent) error {
	key := operationKey(intent)
	if current, exists := j.intents[key]; exists {
		if !sameIntent(current, intent) {
			return errors.New("operation key conflict")
		}
		return nil
	}
	j.intents[key] = intent
	return nil
}

func (j *fakeJournal) RecordResult(_ context.Context, result OperationResult) error {
	key := operationKey(result.Intent)
	intent, ok := j.intents[key]
	if !ok {
		return errors.New("missing intent")
	}
	result.Intent = intent
	if result.RecordedAt.IsZero() {
		result.RecordedAt = time.Now().UTC()
	}
	j.results[key] = result
	if result.Unknown || result.ResourceID == "" {
		return nil
	}
	identity := ResourceIdentity{
		ID: result.ResourceID, Region: result.Intent.Region, Generation: result.Intent.Generation,
		Owner: result.Intent.Owner, CreateKey: result.Intent.CreateKey,
	}
	switch result.Intent.Action {
	case actionLaunch:
		j.instances[identity.ID] = identity
	case actionVolumeCreate:
		identity.AvailabilityDomain = result.Intent.AvailabilityDomain
		identity.SizeGB = result.Intent.SizeGB
		j.volumes[identity.ID] = identity
	case actionVolumeAttach:
		identity := attachmentIdentityFromResult(result)
		j.attachments[identity.ID] = identity
	case actionVolumeResize:
		identity.ID = result.Intent.VolumeID
		identity.AvailabilityDomain = result.Intent.AvailabilityDomain
		previous := identity
		previous.SizeGB = result.Intent.PreviousSizeGB
		identity.SizeGB = result.Intent.SizeGB
		if current := j.volumes[identity.ID]; current != previous && current != identity {
			return errors.New("resize predecessor ownership mismatch")
		}
		j.volumes[identity.ID] = identity
	}
	return nil
}

func (j *fakeJournal) GetResult(_ context.Context, intent OperationIntent) (OperationResult, bool, error) {
	key := operationKey(intent)
	storedIntent, exists := j.intents[key]
	if !exists {
		return OperationResult{}, false, nil
	}
	result, found := j.results[key]
	if !found {
		result.Intent = storedIntent
		return result, false, nil
	}
	result.Intent = storedIntent
	return result, true, nil
}

func (j *fakeJournal) GetOperation(_ context.Context, scope OperationScope) (OperationIntent, bool, error) {
	intent := OperationIntent{
		Action: scope.Action, Key: scope.Key, Region: scope.Region,
		Generation: scope.Generation, Owner: scope.Owner,
	}
	stored, exists := j.intents[operationKey(intent)]
	if !exists {
		return OperationIntent{}, false, nil
	}
	if stored.Action != scope.Action || stored.Key != scope.Key || stored.Region != scope.Region ||
		stored.Generation != scope.Generation || stored.Owner != scope.Owner {
		return OperationIntent{}, false, errors.New("operation scope conflict")
	}
	return stored, true, nil
}

func (j *fakeJournal) IsOwnedInstance(_ context.Context, identity ResourceIdentity) (bool, error) {
	return j.instances[identity.ID] == identity, nil
}

func (j *fakeJournal) IsOwnedVolume(_ context.Context, identity ResourceIdentity) (bool, error) {
	return j.volumes[identity.ID] == identity, nil
}

func (j *fakeJournal) IsOwnedAttachment(_ context.Context, identity AttachmentIdentity) (bool, error) {
	return j.attachments[identity.ID] == identity, nil
}

type fakeWriterStop struct {
	volumeErr      error
	instanceErr    error
	volumeChecks   int
	instanceChecks int
}

func (v *fakeWriterStop) VerifyVolumeWriterStopped(context.Context, Region, string, string, WriterStopEvidence) error {
	v.volumeChecks++
	return v.volumeErr
}
func (v *fakeWriterStop) VerifyInstanceWritersStopped(context.Context, Region, string, WriterStopEvidence) error {
	v.instanceChecks++
	return v.instanceErr
}

type fakeImageVerifier struct {
	err    error
	images []string
	// refuse fails only this image.
	refuse string
}

func (v *fakeImageVerifier) VerifyImageQualified(_ context.Context, _ Region, imageID string) error {
	v.images = append(v.images, imageID)
	if imageID == v.refuse {
		return errors.New("image refused")
	}
	return v.err
}

func newTestFleet(
	config RegionConfig,
	intent RegionIntent,
	provider Provider,
	journal Journal,
	fencer authority.Fencer,
	drainRequester DrainRequester,
	writerStop WriterStopVerifier,
) (Fleet, error) {
	return NewFleetWithImageVerifier(config, intent, provider, journal, fencer, drainRequester, writerStop, &fakeImageVerifier{})
}

// Keep the SDK GetInstance adapter in this regression path. A boot mismatch
// must be withheld as one foreign host without hiding an unrelated OCI error.
func TestObserveWithholdsOnlySDKBootDrift(t *testing.T) {
	config, intent := testRegionConfig()
	setupProvider := newFakeProvider(config)
	journal := newFakeJournal()
	setup, err := newTestFleet(config, intent, setupProvider, journal,
		&fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	badRequest := testEnsureRequest(entityid.Derive("test-operation", "sdk-boot-drift"))
	bad, err := setup.EnsureHost(t.Context(), badRequest)
	if err != nil {
		t.Fatal(err)
	}
	goodRequest := testEnsureRequest(entityid.Derive("test-operation", "sdk-healthy"))
	goodRequest.PrivateIP = "10.251.0.22"
	good, err := setup.EnsureHost(t.Context(), goodRequest)
	if err != nil {
		t.Fatal(err)
	}
	readback := &observeSDKReadback{config: config, instances: map[string]CloudInstance{
		bad.ID: setupProvider.instances[bad.ID], good.ID: setupProvider.instances[good.ID],
	}, badBootID: bad.ID, getInstanceCalls: make(map[string]int)}
	base := common.BaseClient{Host: "https://sdk.test.invalid", BasePath: "20160918",
		UserAgent: "oci-observe-test", Signer: observeSDKSigner{}, HTTPClient: readback}
	adapter := &sdkProvider{config: config, compute: core.ComputeClient{BaseClient: base},
		storage: core.BlockstorageClient{BaseClient: base},
		network: core.VirtualNetworkClient{BaseClient: base}}
	provider := &observeSDKProvider{sdkProvider: adapter,
		listed: []CloudInstance{setupProvider.instances[bad.ID], setupProvider.instances[good.ID]}}
	readOnlyJournal := &observeReadOnlyJournal{fakeJournal: journal}
	fleet, err := newTestFleet(config, intent, provider, readOnlyJournal,
		&fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := fleet.Observe(t.Context())
	if err != nil || len(observed) != 1 || observed[0].ID != good.ID {
		t.Fatalf("SDK boot drift hid healthy host: observed=%+v err=%v", observed, err)
	}
	if readback.getInstanceCalls[bad.ID] != 1 || readback.getInstanceCalls[good.ID] != 1 ||
		readback.mutations != 0 || readOnlyJournal.writes != 0 {
		t.Fatalf("Observe skipped SDK reobservation or mutated state: calls=%v OCI writes=%d journal writes=%d",
			readback.getInstanceCalls, readback.mutations, readOnlyJournal.writes)
	}
	providerFailure := errors.New("OCI GetInstance transport failed")
	readback.failInstanceID, readback.failure = good.ID, providerFailure
	if _, err := fleet.Observe(t.Context()); !errors.Is(err, providerFailure) || errors.Is(err, ErrForeignResource) {
		t.Fatalf("genuine SDK provider error was withheld: %v", err)
	}
	if readback.mutations != 0 || readOnlyJournal.writes != 0 {
		t.Fatalf("failed Observe mutated state: OCI writes=%d journal writes=%d", readback.mutations, readOnlyJournal.writes)
	}
}

type observeSDKProvider struct {
	*sdkProvider
	listed []CloudInstance
}

func (provider *observeSDKProvider) ListInstances(_ context.Context, compartmentID string) ([]CloudInstance, error) {
	if compartmentID != provider.config.CompartmentID {
		return nil, ErrForeignResource
	}
	return slices.Clone(provider.listed), nil
}

func (*observeSDKProvider) ListVolumeAttachments(context.Context, string, string) ([]CloudAttachment, error) {
	return nil, nil
}

type observeReadOnlyJournal struct {
	*fakeJournal
	writes int
}

func (journal *observeReadOnlyJournal) RecordIntent(context.Context, OperationIntent) error {
	journal.writes++
	return errors.New("Observe attempted to write an intent")
}

func (journal *observeReadOnlyJournal) RecordResult(context.Context, OperationResult) error {
	journal.writes++
	return errors.New("Observe attempted to write a result")
}

func (journal *observeReadOnlyJournal) RecordVolumeTermination(context.Context, RegionConfig, string) error {
	journal.writes++
	return errors.New("Observe attempted to write termination proof")
}

type observeSDKSigner struct{}

func (observeSDKSigner) Sign(*http.Request) error { return nil }

type observeSDKReadback struct {
	config           RegionConfig
	instances        map[string]CloudInstance
	badBootID        string
	failInstanceID   string
	failure          error
	getInstanceCalls map[string]int
	mutations        int
}

func (readback *observeSDKReadback) Do(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodGet {
		readback.mutations++
		return nil, errors.New("unexpected OCI mutation")
	}
	var payload any
	var etag string
	path := request.URL.Path
	switch {
	case strings.HasPrefix(path, "/20160918/instances/"):
		id := strings.TrimPrefix(path, "/20160918/instances/")
		readback.getInstanceCalls[id]++
		if id == readback.failInstanceID {
			return nil, readback.failure
		}
		instance, found := readback.instances[id]
		if !found {
			return nil, fmt.Errorf("unknown test instance %s", id)
		}
		etag = instance.ETag
		payload = map[string]any{"id": instance.ID, "compartmentId": instance.CompartmentID,
			"availabilityDomain": instance.AvailabilityDomain, "faultDomain": instance.FaultDomain,
			"shape": instance.Shape, "shapeConfig": map[string]any{"ocpus": instance.Ocpus,
				"memoryInGBs": instance.MemoryInGBs}, "lifecycleState": instance.LifecycleState,
			"imageId": instance.ImageID, "metadata": instance.Metadata, "freeformTags": instance.FreeformTags}
	case strings.HasSuffix(path, "/bootVolumeAttachments"):
		id := request.URL.Query().Get("instanceId")
		if _, found := readback.instances[id]; !found {
			return nil, fmt.Errorf("unknown test boot attachment instance %s", id)
		}
		payload = []map[string]any{{"bootVolumeId": "ocid1.bootvolume." + id,
			"instanceId": id, "compartmentId": readback.config.CompartmentID,
			"availabilityDomain": readback.config.AvailabilityDomain, "lifecycleState": "ATTACHED"}}
	case strings.HasPrefix(path, "/20160918/bootVolumes/"):
		id := strings.TrimPrefix(path, "/20160918/bootVolumes/")
		instanceID := strings.TrimPrefix(id, "ocid1.bootvolume.")
		if _, found := readback.instances[instanceID]; !found {
			return nil, fmt.Errorf("unknown test boot volume %s", id)
		}
		size := int64(readback.config.BootVolumeGB)
		if instanceID == readback.badBootID {
			size++
		}
		payload = map[string]any{"id": id, "compartmentId": readback.config.CompartmentID,
			"imageId": readback.config.ImageID, "sizeInGBs": size,
			"vpusPerGB": readback.config.BootVolumeVPUsPerGB}
	case strings.HasSuffix(path, "/vnicAttachments"):
		id := request.URL.Query().Get("instanceId")
		if _, found := readback.instances[id]; !found {
			return nil, fmt.Errorf("unknown test VNIC attachment instance %s", id)
		}
		payload = []map[string]any{{"vnicId": "ocid1.vnic." + id, "instanceId": id,
			"subnetId": readback.config.SubnetID, "lifecycleState": "ATTACHED"}}
	case strings.HasPrefix(path, "/20160918/vnics/"):
		id := strings.TrimPrefix(path, "/20160918/vnics/")
		instanceID := strings.TrimPrefix(id, "ocid1.vnic.")
		instance, found := readback.instances[instanceID]
		if !found {
			return nil, fmt.Errorf("unknown test VNIC %s", id)
		}
		payload = map[string]any{"id": id, "subnetId": readback.config.SubnetID,
			"privateIp": instance.PrivateIP, "nsgIds": readback.config.NetworkSecurityGroupIDs,
			"skipSourceDestCheck": false, "lifecycleState": "AVAILABLE"}
	default:
		return nil, fmt.Errorf("unexpected OCI test request %s", request.URL)
	}
	wire, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	if etag != "" {
		header.Set("etag", etag)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: header,
		Body: io.NopCloser(bytes.NewReader(wire)), Request: request}, nil
}

func newAttachTestState(t *testing.T) (RegionConfig, *fakeProvider, *fakeJournal, Fleet, Instance, RetainedVolume) {
	t.Helper()
	ctx := t.Context()
	config, regionIntent := testRegionConfig()
	provider := newFakeProvider(config)
	journal := newFakeJournal()
	fleet, err := newTestFleet(config, regionIntent, provider, journal, &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	host, err := fleet.EnsureHost(ctx, testEnsureRequest(entityid.Derive("test-operation", "attach-test-host")))
	if err != nil {
		t.Fatal(err)
	}
	volume, err := fleet.CreateRetainedVolume(ctx, VolumeCreateRequest{Name: "gru-1-db-1-data", DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000HE4W7FRNR204Q6TQ", CreateKey: "0000000000SXHAFTXWBNBVG4JP", SizeGB: 50})
	if err != nil {
		t.Fatal(err)
	}
	return config, provider, journal, fleet, host, volume
}

func mustTestRegionIntent(_ *testing.T) RegionIntent {
	_, intent := testRegionConfig()
	return intent
}

type fakeProvider struct {
	config                       RegionConfig
	instances                    map[string]CloudInstance
	launchRetryTokens            map[string]string
	launchRequests               []LaunchRequest
	launchObservationMutation    func(*CloudInstance)
	launchErrorBeforeCreate      error
	devices                      map[string][]CloudDevice
	volumes                      map[string]CloudVolume
	bootVolumes                  map[string]CloudBootVolume
	volumeRetryTokens            map[string]string
	attachments                  map[string]CloudAttachment
	attachRetryTokens            map[string]string
	attachmentListErr            error
	afterAttach                  func(*fakeProvider, string)
	launches                     int
	launchCalls                  int
	launchErrorAfterCreate       error
	volumeCreates                int
	volumeCreateCalls            int
	volumeCreateErrorAfterCreate error
	volumeRetryReplayError       error
	afterVolumeCreate            func()
	attachCalls                  int
	deviceListCalls              int
	attachErrorAfterCreate       error
	attachReplayError            error
	terminations                 int
	backupPolicies               []CloudBackupPolicy
	backupPolicyRetryTokens      map[string]string
	backupPolicyAssignments      map[string]string
	backupPolicyCreates          int
	volumeCreateRequests         []VolumeCreateRequest
	volumeBackups                []CloudVolumeBackup
}

func newFakeProvider(config RegionConfig) *fakeProvider {
	return &fakeProvider{
		config: config, instances: make(map[string]CloudInstance), launchRetryTokens: make(map[string]string),
		devices: make(map[string][]CloudDevice),
		volumes: make(map[string]CloudVolume), volumeRetryTokens: make(map[string]string),
		bootVolumes: make(map[string]CloudBootVolume),
		attachments: make(map[string]CloudAttachment), attachRetryTokens: make(map[string]string),
	}
}

func (p *fakeProvider) ListInstances(_ context.Context, compartmentID string) ([]CloudInstance, error) {
	if compartmentID != p.config.CompartmentID {
		return nil, ErrForeignResource
	}
	instances := make([]CloudInstance, 0, len(p.instances))
	for _, instance := range p.instances {
		instances = append(instances, cloneCloudInstance(instance))
	}
	return instances, nil
}

func (p *fakeProvider) GetInstance(_ context.Context, id string) (CloudInstance, error) {
	instance, ok := p.instances[id]
	if !ok {
		return CloudInstance{}, fakeNotFound{}
	}
	return cloneCloudInstance(instance), nil
}

func (p *fakeProvider) LaunchInstance(_ context.Context, request LaunchRequest) (CloudInstance, error) {
	p.launchCalls++
	p.launchRequests = append(p.launchRequests, request)
	if p.launchErrorBeforeCreate != nil {
		return CloudInstance{}, p.launchErrorBeforeCreate
	}
	if id, exists := p.launchRetryTokens[request.RetryToken]; exists {
		return cloneCloudInstance(p.instances[id]), nil
	}
	p.launches++
	id := fmt.Sprintf("ocid1.instance.new-%d", p.launches)
	instance := CloudInstance{
		ID: id, PrivateIP: request.PrivateIP, CompartmentID: p.config.CompartmentID, AvailabilityDomain: p.config.AvailabilityDomain,
		FaultDomain: request.FaultDomain, Shape: request.Shape, Ocpus: new(float32(request.WholeOCPUs)),
		MemoryInGBs: new(float32(request.MemoryInGBs)), LifecycleState: "PROVISIONING", ETag: "e1", ImageID: request.ImageID,
		ConsistentVolumeNamingEnabled: new(true),
		Metadata:                      map[string]string{hostboot.MetadataKey: request.BootDescriptor, "terrascale_host_node": request.Node},
		FreeformTags:                  cloneStringMap(request.FreeformTags),
	}
	if p.launchObservationMutation != nil {
		p.launchObservationMutation(&instance)
	}
	p.instances[id] = instance
	p.launchRetryTokens[request.RetryToken] = id
	launchErr := p.launchErrorAfterCreate
	p.launchErrorAfterCreate = nil
	return cloneCloudInstance(instance), launchErr
}

func (p *fakeProvider) UpdateInstanceTags(_ context.Context, id, etag string, tags map[string]string) (CloudInstance, error) {
	instance, ok := p.instances[id]
	if !ok {
		return CloudInstance{}, fakeNotFound{}
	}
	if instance.ETag != etag {
		return CloudInstance{}, ErrStaleETag
	}
	instance.FreeformTags = cloneStringMap(tags)
	instance.ETag = etag + "-next"
	p.instances[id] = instance
	return cloneCloudInstance(instance), nil
}

func (p *fakeProvider) TerminateInstance(_ context.Context, id, etag string) error {
	instance, ok := p.instances[id]
	if !ok {
		return fakeNotFound{}
	}
	if instance.ETag != etag {
		return ErrStaleETag
	}
	instance.LifecycleState = "TERMINATING"
	instance.ETag = etag + "-term"
	p.instances[id] = instance
	p.terminations++
	return nil
}

func (p *fakeProvider) TerminateTerminalInstance(ctx context.Context, id, etag string) error {
	return p.TerminateInstance(ctx, id, etag)
}

func (p *fakeProvider) GetAttachedBootVolume(_ context.Context, instanceID string) (CloudBootVolume, error) {
	instance, ok := p.instances[instanceID]
	if !ok {
		return CloudBootVolume{}, fakeNotFound{}
	}
	id := "ocid1.bootvolume." + strings.TrimPrefix(instanceID, "ocid1.instance.")
	if boot, ok := p.bootVolumes[id]; ok {
		return boot, nil
	}
	boot := CloudBootVolume{ID: id, CompartmentID: p.config.CompartmentID,
		AvailabilityDomain: p.config.AvailabilityDomain, ImageID: instance.ImageID,
		SizeGB: int64(p.config.BootVolumeGB), VPUsPerGB: int64(p.config.BootVolumeVPUsPerGB),
		LifecycleState: "AVAILABLE", ETag: "boot-etag"}
	p.bootVolumes[id] = boot
	return boot, nil
}

func (p *fakeProvider) GetBootVolume(_ context.Context, id string) (CloudBootVolume, error) {
	boot, ok := p.bootVolumes[id]
	if !ok {
		return CloudBootVolume{}, fakeNotFound{}
	}
	return boot, nil
}

func (p *fakeProvider) ListBootVolumeAttachments(_ context.Context, id string) ([]CloudBootAttachment, error) {
	for instanceID, instance := range p.instances {
		if id == "ocid1.bootvolume."+strings.TrimPrefix(instanceID, "ocid1.instance.") {
			if instance.LifecycleState == "TERMINATED" {
				return nil, nil
			}
			return []CloudBootAttachment{{InstanceID: instanceID, BootVolumeID: id, LifecycleState: "ATTACHED"}}, nil
		}
	}
	return nil, nil
}

func (p *fakeProvider) DeleteBootVolume(_ context.Context, id, etag string) error {
	boot, ok := p.bootVolumes[id]
	if !ok {
		return fakeNotFound{}
	}
	if boot.ETag != etag {
		return ErrStaleETag
	}
	delete(p.bootVolumes, id)
	return nil
}

func (p *fakeProvider) DeleteVolume(_ context.Context, id, etag string) error {
	volume, ok := p.volumes[id]
	if !ok {
		return fakeNotFound{}
	}
	if volume.ETag != etag {
		return ErrStaleETag
	}
	delete(p.volumes, id)
	return nil
}

func (p *fakeProvider) ListVolumeAttachments(_ context.Context, compartmentID, instanceID string) ([]CloudAttachment, error) {
	if compartmentID != p.config.CompartmentID {
		return nil, ErrForeignResource
	}
	if p.attachmentListErr != nil {
		err := p.attachmentListErr
		p.attachmentListErr = nil
		return nil, err
	}
	var attachments []CloudAttachment
	for _, attachment := range p.attachments {
		if instanceID == "" || attachment.InstanceID == instanceID {
			attachments = append(attachments, attachment)
		}
	}
	return attachments, nil
}

func (p *fakeProvider) ListInstanceDevices(_ context.Context, instanceID string) ([]CloudDevice, error) {
	p.deviceListCalls++
	devices, exists := p.devices[instanceID]
	if exists {
		return cloneCloudDevices(devices), nil
	}
	available := true
	return []CloudDevice{
		{Name: "/dev/oracleoci/oraclevdb", IsAvailable: &available},
		{Name: "/dev/oracleoci/oraclevdc", IsAvailable: &available},
	}, nil
}

func (p *fakeProvider) GetVolumeAttachment(_ context.Context, id string) (CloudAttachment, error) {
	attachment, ok := p.attachments[id]
	if !ok {
		return CloudAttachment{}, fakeNotFound{}
	}
	return attachment, nil
}

func (p *fakeProvider) AttachVolume(_ context.Context, request CloudVolumeAttachRequest) (CloudAttachment, error) {
	if id, exists := p.attachRetryTokens[request.RetryToken]; exists {
		return p.attachments[id], p.attachReplayError
	}
	p.attachCalls++
	readOnly, shareable, encryption := request.IsReadOnly, request.IsShareable, request.IsPvEncryptionInTransitEnabled
	attachment := CloudAttachment{
		ID: fmt.Sprintf("attachment-%d", p.attachCalls), VolumeID: request.VolumeID,
		InstanceID: request.InstanceID, LifecycleState: "ATTACHED", ETag: "a1", Device: request.Device,
		IsReadOnly: &readOnly, IsShareable: &shareable, IsPvEncryptionInTransitEnabled: &encryption,
	}
	// Like OCI, the response describes the attachment while it is ATTACHING,
	// under an ETag that changes once it settles.
	response := attachment
	response.LifecycleState, response.ETag = "ATTACHING", "a0"
	p.attachments[attachment.ID] = attachment
	p.attachRetryTokens[request.RetryToken] = attachment.ID
	if p.afterAttach != nil {
		p.afterAttach(p, attachment.ID)
		p.afterAttach = nil
	}
	attachErr := p.attachErrorAfterCreate
	p.attachErrorAfterCreate = nil
	return response, attachErr
}

func (p *fakeProvider) DetachVolume(_ context.Context, id, etag string) error {
	attachment, ok := p.attachments[id]
	if !ok {
		return fakeNotFound{}
	}
	if attachment.ETag != etag {
		return ErrStaleETag
	}
	delete(p.attachments, id)
	return nil
}

func (p *fakeProvider) GetVolume(_ context.Context, id string) (CloudVolume, error) {
	volume, ok := p.volumes[id]
	if !ok {
		return CloudVolume{}, fakeNotFound{}
	}
	volume.FreeformTags = cloneStringMap(volume.FreeformTags)
	return volume, nil
}

func (p *fakeProvider) ListVolumes(_ context.Context, compartmentID, availabilityDomain string) ([]CloudVolume, error) {
	if compartmentID != p.config.CompartmentID || availabilityDomain != p.config.AvailabilityDomain {
		return nil, ErrForeignResource
	}
	var volumes []CloudVolume
	for _, volume := range p.volumes {
		if volume.AvailabilityDomain == availabilityDomain {
			volume.FreeformTags = cloneStringMap(volume.FreeformTags)
			volumes = append(volumes, volume)
		}
	}
	return volumes, nil
}

func (p *fakeProvider) CreateVolume(_ context.Context, request VolumeCreateRequest, tags map[string]string, retry string) (CloudVolume, error) {
	p.volumeCreateCalls++
	if id, exists := p.volumeRetryTokens[retry]; exists {
		return p.volumes[id], p.volumeRetryReplayError
	}
	p.volumeCreates++
	p.volumeCreateRequests = append(p.volumeCreateRequests, request)
	id := fmt.Sprintf("ocid1.volume.created-%d", p.volumeCreates)
	volume := CloudVolume{
		ID: id, CompartmentID: p.config.CompartmentID, AvailabilityDomain: request.AvailabilityDomain,
		SizeGB: request.SizeGB, VPUsPerGB: int64(p.config.DataVolumeVPUsPerGB),
		LifecycleState: "PROVISIONING", ETag: "volume-etag", FreeformTags: cloneStringMap(tags),
	}
	p.volumes[id] = volume
	p.volumeRetryTokens[retry] = id
	createErr := p.volumeCreateErrorAfterCreate
	p.volumeCreateErrorAfterCreate = nil
	if p.afterVolumeCreate != nil {
		p.afterVolumeCreate()
	}
	volume.FreeformTags = cloneStringMap(volume.FreeformTags)
	return volume, createErr
}

func cloneCloudInstance(instance CloudInstance) CloudInstance {
	instance.FreeformTags = maps.Clone(instance.FreeformTags)
	instance.Metadata = maps.Clone(instance.Metadata)
	if instance.Ocpus != nil {
		instance.Ocpus = new(*instance.Ocpus)
	}
	if instance.MemoryInGBs != nil {
		instance.MemoryInGBs = new(*instance.MemoryInGBs)
	}
	if instance.ConsistentVolumeNamingEnabled != nil {
		instance.ConsistentVolumeNamingEnabled = boolPointer(*instance.ConsistentVolumeNamingEnabled)
	}
	return instance
}

func cloneCloudDevices(devices []CloudDevice) []CloudDevice {
	cloned := make([]CloudDevice, len(devices))
	for index, device := range devices {
		cloned[index].Name = device.Name
		if device.IsAvailable != nil {
			cloned[index].IsAvailable = boolPointer(*device.IsAvailable)
		}
	}
	return cloned
}

func boolPointer(value bool) *bool { return &value }

type fakeNotFound struct{}

func (fakeNotFound) Error() string          { return "not found" }
func (fakeNotFound) GetHTTPStatusCode() int { return 404 }
