package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type founderStoredObject struct {
	wire     []byte
	etag     string
	modified time.Time
}

type founderLedgerObjects struct {
	objects      map[string]founderStoredObject
	now          time.Time
	rejectSuffix string
	rejectPart   string
	afterGet     func(string)
	writes       int
}

func (store *founderLedgerObjects) PutObject(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	if request.NamespaceName == nil || request.BucketName == nil || request.ObjectName == nil ||
		request.OpcSseKmsKeyId == nil || request.PutObjectBody == nil {
		return objectstorage.PutObjectResponse{}, errors.New("incomplete founder ledger write")
	}
	wire, err := io.ReadAll(request.PutObjectBody)
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	_ = request.PutObjectBody.Close()
	if request.ContentLength == nil || *request.ContentLength != int64(len(wire)) ||
		request.OpcContentSha256 == nil || *request.OpcContentSha256 != base64Digest(wire) {
		return objectstorage.PutObjectResponse{}, errors.New("founder ledger write changed content")
	}
	if store.rejectSuffix != "" && strings.HasSuffix(*request.ObjectName, store.rejectSuffix) ||
		store.rejectPart != "" && strings.Contains(*request.ObjectName, store.rejectPart) {
		return objectstorage.PutObjectResponse{}, errors.New("injected founder ledger write failure")
	}
	key := *request.BucketName + "/" + *request.ObjectName
	previous, exists := store.objects[key]
	if request.IfNoneMatch != nil && *request.IfNoneMatch == "*" && exists ||
		request.IfMatch != nil && (!exists || previous.etag != *request.IfMatch) {
		return objectstorage.PutObjectResponse{}, founderStorageError(http.StatusPreconditionFailed)
	}
	if request.IfNoneMatch == nil && request.IfMatch == nil {
		return objectstorage.PutObjectResponse{}, errors.New("unconditional founder ledger write")
	}
	hash := sha256.Sum256(wire)
	etag := `"` + hex.EncodeToString(hash[:8]) + `"`
	store.objects[key] = founderStoredObject{wire: bytes.Clone(wire), etag: etag, modified: store.now}
	store.writes++
	return objectstorage.PutObjectResponse{ETag: new(etag)}, nil
}

func (store *founderLedgerObjects) GetObject(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if request.NamespaceName == nil || request.BucketName == nil || request.ObjectName == nil {
		return objectstorage.GetObjectResponse{}, errors.New("incomplete founder ledger read")
	}
	object, ok := store.objects[*request.BucketName+"/"+*request.ObjectName]
	if !ok {
		return objectstorage.GetObjectResponse{}, founderStorageError(http.StatusNotFound)
	}
	headers := make(http.Header)
	headers.Set("Date", store.now.Format(http.TimeFormat))
	length := int64(len(object.wire))
	modified := common.SDKTime{Time: object.modified}
	if store.afterGet != nil {
		store.afterGet(*request.ObjectName)
	}
	return objectstorage.GetObjectResponse{RawResponse: &http.Response{Header: headers},
		Content: io.NopCloser(bytes.NewReader(object.wire)), ContentLength: &length,
		ETag: new(object.etag), LastModified: &modified}, nil
}

type founderStorageError int

func (err founderStorageError) Error() string           { return http.StatusText(int(err)) }
func (err founderStorageError) GetHTTPStatusCode() int  { return int(err) }
func (err founderStorageError) GetMessage() string      { return err.Error() }
func (err founderStorageError) GetCode() string         { return "FounderTest" }
func (err founderStorageError) GetOpcRequestID() string { return "founder-test" }

func base64Digest(wire []byte) string {
	hash := sha256.Sum256(wire)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func signFounderLedgerValue(t *testing.T, key []byte, domain string, scope bootstrap.BootstrapScope,
	value any, now time.Time,
) []byte {
	t.Helper()
	payload, err := trust.EncodePayload(value)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: domain, DeploymentID: scope.DeploymentID,
		Cell: scope.Cell, Environment: "production", Role: "controller", Slot: scope.Slot},
		now.Add(-time.Minute), now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func newFounderRuntimeFixture(t *testing.T) (*founderSignerFixture, *founderCaller, *founderLedgerObjects, *founderFakeOCI) {
	return newFounderRuntimeFixtureWithSetup(t, nil)
}

// newUnreservedFounderRuntimeFixture leaves every planned peer slot empty, as
// on a freshly admitted seed.
func newUnreservedFounderRuntimeFixture(t *testing.T) (*founderSignerFixture, *founderCaller, *founderLedgerObjects, *founderFakeOCI) {
	return newFounderRuntimeFixtureWithReservation(t, nil, false)
}

func newFounderRuntimeFixtureWithSetup(t *testing.T, setup func(*founderSignerFixture)) (*founderSignerFixture, *founderCaller, *founderLedgerObjects, *founderFakeOCI) {
	return newFounderRuntimeFixtureWithReservation(t, setup, true)
}

func newFounderRuntimeFixtureWithReservation(t *testing.T, setup func(*founderSignerFixture), reserve bool,
) (*founderSignerFixture, *founderCaller, *founderLedgerObjects, *founderFakeOCI) {
	t.Helper()
	fixture := newFounderSignerFixture(t)
	qualifyFounderRuntimeFixture(t, fixture)
	if setup != nil {
		setup(fixture)
	}
	objects := &founderLedgerObjects{objects: make(map[string]founderStoredObject), now: fixture.now}
	config, err := currentLedgerConfig(fixture.current.Anchor, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	config.VerificationNow = func() time.Time { return fixture.now }
	ledger, err := bootstrap.NewLedger(objects, config)
	if err != nil {
		t.Fatal(err)
	}
	fake := &founderFakeOCI{rows: make(map[string]bootstrap.FounderPeerRow), now: fixture.now}
	for _, row := range fixture.plan.Peers {
		fake.rows[row.Slot] = row
	}
	caller := &founderCaller{reader: fixture.reader(t), roots: fixture.baked.Roots,
		accepted: fixture.accepted, signers: fixture.store, now: func() time.Time { return fixture.now },
		adapter:   &FounderOCI{region: oci.RegionGRU, material: testLaunchMaterial, compute: fake, network: fake, volume: fake},
		placement: testSeedPlacement,
		openLedger: func(context.Context, CurrentFounderAuthority, trust.Keyring) (*bootstrap.Ledger, error) {
			return ledger, nil
		}}
	for _, row := range fixture.plan.Peers {
		if !reserve {
			break
		}
		snapshot, err := caller.fresh(t.Context(), row.Slot)
		if !errors.Is(err, errFounderPeerUnreserved) {
			t.Fatalf("fresh %s slot is not unreserved: %v", row.Slot, err)
		}
		if err := caller.reservePeer(t.Context(), snapshot, row.Slot); err != nil {
			t.Fatalf("reserve founder %s: %v", row.Slot, err)
		}
	}
	return fixture, caller, objects, fake
}

func founderRuntimeImageWires(t *testing.T, fixture *founderSignerFixture) ([]byte, []byte) {
	t.Helper()
	imageID := fixture.plan.Peers[0].ImageOCID
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	publicWire, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	const revision = "0123456789abcdef0123456789abcdef01234567"
	grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: keyID, SubjectPublicKey: publicWire, Capabilities: []trust.Capability{{
			Domain: release.ImageDomain, DeploymentID: entityid.Derive("build", revision), Cell: "GRU", Environment: "production",
			Role: "oci-image", Slots: []string{imageID}, Actions: []string{"sign"},
		}}}, fixture.now.Add(-10*time.Minute), fixture.now.Add(2*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	imageReceipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: revision,
		GoVersion: release.DefaultGoVersion, Architecture: "amd64", BinaryBytes: 13,
		BinarySHA256: strings.Repeat("a", 64), BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base",
		QualificationSHA256: strings.Repeat("e", 64),
		BaseImageRegion:     "GRU", BaseImageSHA256: strings.Repeat("b", 64),
		KernelRelease: "6.1.0-test+1", KernelSHA256: strings.Repeat("c", 64),
		ImageFormat: "qcow2", ImageBytes: 1024, ImageSHA256: strings.Repeat("d", 64),
		OCIImageOCID: imageID, OCIRegion: "GRU"}
	imageReceipt = qualifiedImageFixture(t, imageReceipt, "production", fixture.root, fixture.now.Add(-time.Minute))
	imageEnvelope, err := release.SignImageReceipt(imageReceipt, "production", grant, fixture.baked.Roots,
		private, fixture.now.Add(-time.Minute), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	imageWire, err := trust.EncodeEnvelope(imageEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(grant)
	if err != nil {
		t.Fatal(err)
	}
	return imageWire, grantWire
}

func founderFixtureWithAdmissibleRelease(t *testing.T, fixture *founderSignerFixture) {
	t.Helper()
	anchorEnvelope, err := trust.DecodeEnvelope(fixture.anchorWire)
	if err != nil {
		t.Fatal(err)
	}
	var anchor bootstrap.BootstrapAnchor
	if err := protocol.DecodeStrict(anchorEnvelope.Payload, &anchor, bootstrap.MaxBootstrapAnchorBytes); err != nil {
		t.Fatal(err)
	}
	anchor.ControllerSlots = []string{"controller-a", "controller-b", "controller-c"}
	anchor.LedgerDelegationWire = signTestDelegation(t, fixture.root, fixture.ledgerKey.Public().(ed25519.PublicKey),
		[]string{"bootstrap-slot-head", "bootstrap-intent", "bootstrap-result", "bootstrap-candidate", "bootstrap-progress"},
		anchor.ControllerSlots, fixture.now.Add(-time.Hour), fixture.now.Add(24*time.Hour))
	anchorEnvelope, err = bootstrap.SignBootstrapAnchor(anchor, fixture.now.Add(-time.Minute), fixture.now.Add(23*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	fixture.anchorWire = envelopeWire(t, anchorEnvelope)
	fixture.baked.AnchorWire = bytes.Clone(fixture.anchorWire)
	fixture.accepted.Slot, fixture.accepted.SeedSlot = "controller-c", "controller-c"
	fixture.accepted.AnchorSHA256 = digest(fixture.anchorWire)
	fixture.plan.SeedSlot, fixture.plan.ControllerSlots = "controller-c", anchor.ControllerSlots
	fixture.plan.AnchorSHA256, fixture.selection.AnchorSHA256 = digest(fixture.anchorWire), digest(fixture.anchorWire)
	for i := range fixture.selection.Manifests {
		if fixture.selection.Manifests[i].Slot == "seed-a" {
			fixture.selection.Manifests[i].Slot = "controller-c"
		}
	}
	for i := range fixture.plan.Peers {
		for j := range fixture.plan.Peers[i].RouteEndpoints {
			if fixture.plan.Peers[i].RouteEndpoints[j].Slot == "seed-a" {
				fixture.plan.Peers[i].RouteEndpoints[j].Slot = "controller-c"
			}
		}
		slot := fixture.plan.Peers[i].Slot
		fixture.plan.Peers[i].TLSMaterial = bootstrap.FounderTLSMaterialDigests{
			ClientCA: digest([]byte("ca.pem")), ClientCertificate: digest([]byte(slot + "-tls-cert.pem")),
			ClientPrivateKey: digest([]byte(slot + "-tls-key.pem")), RouteCA: digest([]byte("ca.pem")),
			RouteCertificate: digest([]byte(slot + "-tls-cert.pem")), RoutePrivateKey: digest([]byte(slot + "-tls-key.pem")),
		}
	}
	imageWire, grantWire := founderRuntimeImageWires(t, fixture)
	manifests := make(map[string][]byte, 3)
	for slot, wire := range fixture.manifests {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			t.Fatal(err)
		}
		var manifest bootstrap.Manifest
		if err := protocol.DecodeStrict(envelope.Payload, &manifest, bootstrap.MaxManifestBytes); err != nil {
			t.Fatal(err)
		}
		if slot == "seed-a" {
			slot = "controller-c"
		}
		manifest.Slot, manifest.SeedSlot, manifest.ControllerSlots = slot, "controller-c", anchor.ControllerSlots
		for i := range manifest.Profiles {
			if manifest.Profiles[i].Slot == "seed-a" {
				manifest.Profiles[i].Slot = "controller-c"
			}
		}
		offline := manifest.Secrets
		manifest.Secrets = acceptedReferences(slot)
		for _, ref := range offline {
			if ref.Purpose == bootstrap.SecretSeedFounder || ref.Purpose == bootstrap.SecretSeedLedgerSigner {
				ref.Slot = slot
				manifest.Secrets = append(manifest.Secrets, ref)
			}
		}
		manifest.ReleaseReceiptSHA256 = digestWire(imageWire)
		manifest.ReleaseImageReceiptWire = imageWire
		manifest.ReleaseDelegationWire = grantWire
		manifest.ControllerFiles = nil
		addTestControllerConfig(&manifest)
		envelope, err = bootstrap.SignManifest(manifest, fixture.now.Add(-time.Minute),
			fixture.now.Add(22*time.Hour), fixture.root)
		if err != nil {
			t.Fatal(err)
		}
		manifests[slot], err = trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
	}
	fixture.manifests = manifests
	fixture.accepted.ManifestSHA256 = digestWire(fixture.manifests[fixture.accepted.Slot])
	fixture.plan.SeedManifestSHA256 = fixture.accepted.ManifestSHA256
	for index := range fixture.plan.Peers {
		fixture.plan.Peers[index].ManifestSHA256 = digestWire(fixture.manifests[fixture.plan.Peers[index].Slot])
	}
	payload, err := trust.EncodePayload(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	planEnvelope, err := trust.Sign(payload, trust.Scope{Domain: bootstrap.FounderPlanDomain,
		DeploymentID: fixture.plan.DeploymentID, Cell: string(fixture.plan.Cell),
		Environment: fixture.plan.Environment, Role: "controller", Slot: fixture.plan.SeedSlot},
		fixture.now.Add(-time.Minute), fixture.now.Add(22*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	fixture.planWire, err = trust.EncodeEnvelope(planEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	fixture.selection.Generation = 2
	fixture.selection.PlanSHA256 = digestWire(fixture.planWire)
	for index := range fixture.selection.Manifests {
		fixture.selection.Manifests[index].SHA256 = digestWire(fixture.manifests[fixture.selection.Manifests[index].Slot])
	}
	fixture.publish(t, fixture.selection)
	fixture.current, err = fixture.reader(t).ReadCurrent(t.Context(), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
}

func founderFixtureWithShortLaunchDeadline(t *testing.T, fixture *founderSignerFixture) {
	t.Helper()
	founderFixtureWithAdmissibleRelease(t, fixture)
	fixture.plan.LaunchDeadline = fixture.now.Add(3 * time.Minute)
	payload, err := trust.EncodePayload(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: bootstrap.FounderPlanDomain,
		DeploymentID: fixture.plan.DeploymentID, Cell: string(fixture.plan.Cell),
		Environment: fixture.plan.Environment, Role: "controller", Slot: fixture.plan.SeedSlot},
		fixture.now.Add(-time.Minute), fixture.now.Add(22*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	fixture.planWire, err = trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	fixture.selection.Generation++
	fixture.selection.PlanSHA256 = digestWire(fixture.planWire)
	fixture.publish(t, fixture.selection)
	fixture.current, err = fixture.reader(t).ReadCurrent(t.Context(), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFounderRuntimeCompletesTwoPlannedPeersAndRestartIsIdempotent(t *testing.T) {
	_, caller, _, fake := newFounderRuntimeFixture(t)
	for _, slot := range []string{"controller-a", "controller-b"} {
		if err := caller.runPeer(t.Context(), slot); err != nil {
			t.Fatalf("complete %s: %v", slot, err)
		}
		launches, observations := fake.launches, fake.observations
		if err := caller.runPeer(t.Context(), slot); err != nil {
			t.Fatalf("restart %s: %v", slot, err)
		}
		if fake.launches != launches || fake.observations != observations {
			t.Fatal("restart repeated launch or observation effects")
		}
	}
	if fake.launches != 2 || fake.observations < 2 {
		t.Fatalf("three-controller founding effects: launches=%d observations=%d", fake.launches, fake.observations)
	}
}

func TestFounderRuntimeReservesUnreservedPeersBeforeLaunch(t *testing.T) {
	fixture, caller, _, fake := newUnreservedFounderRuntimeFixture(t)
	for range 2 {
		for _, row := range fixture.plan.Peers {
			if err := caller.runPeer(t.Context(), row.Slot); err != nil {
				t.Fatalf("found %s from an empty slot: %v", row.Slot, err)
			}
		}
	}
	if fake.launches != len(fixture.plan.Peers) || fake.observations != len(fixture.plan.Peers) {
		t.Fatalf("founding from empty slots: launches=%d observations=%d", fake.launches, fake.observations)
	}
}

func TestFounderRuntimeCandidateOnlyRestartObservesWithoutRelaunch(t *testing.T) {
	fixture, caller, _, fake := newFounderRuntimeFixture(t)
	const slot = "controller-a"
	snapshot, err := caller.fresh(t.Context(), slot)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewFounderOCIAttempt(snapshot.peer, snapshot.now)
	if err != nil {
		t.Fatal(err)
	}
	instanceID, err := caller.adapter.Launch(t.Context(), attempt, caller.peerRefresh(slot))
	if err != nil {
		t.Fatal(err)
	}
	if err := caller.pinCandidate(t.Context(), snapshot, slot, instanceID); err != nil {
		t.Fatal(err)
	}
	if fake.launches != 1 || fake.observations != 0 {
		t.Fatalf("candidate-only setup performed unexpected effects: launches=%d observations=%d",
			fake.launches, fake.observations)
	}
	if err := caller.runPeer(t.Context(), slot); err != nil {
		t.Fatalf("candidate-only recovery: %v", err)
	}
	if fake.launches != 1 || fake.observations != 1 {
		t.Fatalf("candidate-only recovery relaunched or missed exact observation: launches=%d observations=%d",
			fake.launches, fake.observations)
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	state, err := ledger.ReadSlot(t.Context(), bootstrap.BootstrapScope{
		DeploymentID: fixture.accepted.DeploymentID, Cell: fixture.accepted.Cell, Slot: slot})
	if err != nil || state.Result == nil || state.Candidate == nil ||
		state.Result.InstanceOCID != state.Candidate.InstanceOCID ||
		state.Head.CandidateDigest != state.CandidateRecord.SHA256 {
		t.Fatalf("completed candidate binding invalid: state=%+v err=%v", state, err)
	}
}

func TestFounderRuntimeQuarantinedLateResultRepairsPinnedCandidate(t *testing.T) {
	fixture, caller, objects, fake := newFounderRuntimeFixture(t)
	const slot = "controller-a"
	if err := caller.runPeer(t.Context(), slot); err != nil {
		t.Fatalf("initial founder completion: %v", err)
	}
	later := fixture.now.Add(6 * time.Minute)
	changed := false
	for key, object := range objects.objects {
		if strings.Contains(key, "/result-") && strings.HasSuffix(key, ".json") {
			object.modified = later
			objects.objects[key] = object
			changed = true
		}
	}
	if !changed {
		t.Fatal("completed founder peer had no immutable result object")
	}
	fixture.now, objects.now, fake.now = later, later, later
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	scope := bootstrap.BootstrapScope{DeploymentID: fixture.accepted.DeploymentID,
		Cell: fixture.accepted.Cell, Slot: slot}
	if _, err := ledger.ReadSlot(t.Context(), scope); !errors.Is(err, bootstrap.ErrManagedPeerProofQuarantined) {
		t.Fatalf("late result was not quarantined for historical admission: %v", err)
	}
	observationsBeforeRepair := fake.observations
	if err := caller.runPeer(t.Context(), slot); err != nil {
		t.Fatalf("repair quarantined founder result: %v", err)
	}
	if fake.launches != 1 || fake.observations <= observationsBeforeRepair {
		t.Fatalf("quarantine repair relaunched or missed reobservation: launches=%d observations=%d",
			fake.launches, fake.observations)
	}
	state, err := ledger.ReadSlot(t.Context(), scope)
	if err != nil || state.Result == nil || !state.Result.ObservedAt.Equal(later) {
		t.Fatalf("quarantine repair did not publish a fresh signed result: state=%+v err=%v", state, err)
	}
}

func TestFounderRuntimeCompletedCellRestartDoesNotNeedCurrentLaunchPlan(t *testing.T) {
	fixture, caller, _, fake := newFounderRuntimeFixture(t)
	for _, row := range fixture.plan.Peers {
		if err := caller.runPeer(t.Context(), row.Slot); err != nil {
			t.Fatalf("complete %s: %v", row.Slot, err)
		}
	}
	if _, err := fixture.reader(t).ReadCurrent(t.Context(), fixture.now.Add(2*time.Hour)); err == nil {
		t.Fatal("fixture selected launch authority did not expire")
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	reads := make(map[string]int, len(fixture.objects.reads))
	for key, count := range fixture.objects.reads {
		reads[key] = count
	}
	launches, observations, imageReads := fake.launches, fake.observations, fake.imageReads
	completed := func(ctx context.Context, _ BakedInputs, accepted AcceptedInstall) (bool, error) {
		return founderPeersComplete(ctx, fixture.current.Anchor.Anchor(), accepted, ledger)
	}
	if err := runAdmittedFounder(t.Context(), fixture.baked, fixture.accepted, 1000, 1000,
		fixture.floor, completed, testSeedPlacement); err != nil {
		t.Fatalf("completed cell restart required an expired launch plan: %v", err)
	}
	if fake.launches != launches || fake.observations != observations || fake.imageReads != imageReads {
		t.Fatal("completed cell restart touched founder OCI")
	}
	for key, count := range reads {
		if fixture.objects.reads[key] != count {
			t.Fatal("completed cell restart read the expired selector")
		}
	}
}

func TestFounderRuntimeCompletedCellRequiresExistingCanonicalFloor(t *testing.T) {
	for _, damage := range []string{"missing floor", "invalid floor", "missing lock"} {
		t.Run(damage, func(t *testing.T) {
			fixture := newFounderSignerFixture(t)
			floorPath := filepath.Join(fixture.floor.directory, founderSelectionFloorName)
			switch damage {
			case "missing floor":
				if err := os.Remove(floorPath); err != nil {
					t.Fatal(err)
				}
			case "invalid floor":
				if err := os.WriteFile(floorPath, []byte(`{"schemaVersion":1}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing lock":
				if err := os.Remove(filepath.Join(fixture.floor.directory, founderSelectionLockName)); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			completed := func(context.Context, BakedInputs, AcceptedInstall) (bool, error) {
				called = true
				return true, nil
			}
			if err := runAdmittedFounder(t.Context(), fixture.baked, fixture.accepted, 1000, 1000,
				fixture.floor, completed, testSeedPlacement); !errors.Is(err, ErrFounderSelectionFloor) || called {
				t.Fatalf("%s bypassed durable floor: %v called=%v", damage, err, called)
			}
		})
	}
}

type founderSupersedingHead struct {
	SlotReader
	slot string
}

func (reader founderSupersedingHead) ReadSlot(ctx context.Context, scope bootstrap.BootstrapScope) (bootstrap.SlotState, error) {
	state, err := reader.SlotReader.ReadSlot(ctx, scope)
	if err != nil || scope.Slot != reader.slot {
		return state, err
	}
	state.Head.Attempt++
	state.Head.Generation++
	state.Head.ResultDigest = ""
	state.Result = nil
	state.ResultRecord = nil
	state.PeerReceipt = nil
	state.PeerReceiptRecord = nil
	return state, nil
}

func TestFounderRuntimeSupersedingPendingHEADCannotSkipFounding(t *testing.T) {
	fixture, caller, _, _ := newFounderRuntimeFixture(t)
	for _, row := range fixture.plan.Peers {
		if err := caller.runPeer(t.Context(), row.Slot); err != nil {
			t.Fatal(err)
		}
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := founderPeersComplete(t.Context(), fixture.current.Anchor.Anchor(), fixture.accepted,
		founderSupersedingHead{SlotReader: ledger, slot: fixture.plan.Peers[0].Slot})
	if err != nil || complete {
		t.Fatalf("new pending HEAD was bypassed by old completion: complete=%v err=%v", complete, err)
	}
}

type founderMalformedPositiveHead struct {
	SlotReader
	slot string
}

func (reader founderMalformedPositiveHead) ReadSlot(ctx context.Context, scope bootstrap.BootstrapScope) (bootstrap.SlotState, error) {
	state, err := reader.SlotReader.ReadSlot(ctx, scope)
	if err == nil && scope.Slot == reader.slot {
		state.PeerReceipt = nil
		state.PeerReceiptRecord = nil
	}
	return state, err
}

func TestFounderRuntimeMalformedPositiveHEADCannotSkipFounding(t *testing.T) {
	fixture, caller, _, _ := newFounderRuntimeFixture(t)
	for _, row := range fixture.plan.Peers {
		if err := caller.runPeer(t.Context(), row.Slot); err != nil {
			t.Fatal(err)
		}
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := founderPeersComplete(t.Context(), fixture.current.Anchor.Anchor(), fixture.accepted,
		founderMalformedPositiveHead{SlotReader: ledger, slot: fixture.plan.Peers[0].Slot})
	if complete || !errors.Is(err, ErrFounderRuntime) {
		t.Fatalf("malformed positive HEAD skipped founding: complete=%v err=%v", complete, err)
	}
}

func TestFounderRuntimeHistoricalCompletionRequiresExactBakedAnchor(t *testing.T) {
	fixture := newFounderSignerFixture(t)
	accepted := fixture.accepted
	accepted.AnchorSHA256 = strings.Repeat("b", 64)
	if complete, err := completedAdmittedFounder(t.Context(), fixture.baked, accepted); complete ||
		!errors.Is(err, ErrFounderRuntime) {
		t.Fatalf("wrong accepted anchor reached historical ledger: complete=%v err=%v", complete, err)
	}
}

type founderAdmissionLedger struct {
	ledger  *bootstrap.Ledger
	onFirst func()
	reads   int
}

type founderAdmissionCredentials struct{ calls int }

func (checker *founderAdmissionCredentials) VerifyLiveCredentials(_ context.Context, expected MaterialPins,
	_ AcceptedIdentity,
) error {
	checker.calls++
	if len(expected.Digests) == 0 {
		return ErrLiveCredentials
	}
	return nil
}

func (checker *founderAdmissionCredentials) VerifyInitialLiveCredentials(ctx context.Context, expected MaterialPins,
	_ bootstrap.VerifiedManifest,
) error {
	return checker.VerifyLiveCredentials(ctx, expected, AcceptedIdentity{})
}

func (reader *founderAdmissionLedger) OpenCurrentLedger(_ context.Context, anchor bootstrap.VerifiedBootstrapAnchor,
	_ trust.Keyring,
) (AdmissionLedger, error) {
	if !anchor.IsVerified() {
		return nil, ErrAdmission
	}
	return reader, nil
}

func (reader *founderAdmissionLedger) OpenHistoricalLedger(_ context.Context, anchor bootstrap.HistoricalBootstrapAnchor,
	_ trust.Keyring,
) (AdmissionLedger, error) {
	if !anchor.IsVerified() {
		return nil, ErrAdmission
	}
	return reader, nil
}

func (reader *founderAdmissionLedger) PublishAcceptedInstall(ctx context.Context, scope bootstrap.BootstrapScope,
	marker []byte,
) error {
	return reader.ledger.PublishAcceptedInstall(ctx, scope, marker)
}

func (reader *founderAdmissionLedger) ReadSlot(ctx context.Context, scope bootstrap.BootstrapScope) (bootstrap.SlotState, error) {
	state, err := reader.ledger.ReadSlot(ctx, scope)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	reader.reads++
	if reader.reads == 1 && reader.onFirst != nil {
		reader.onFirst()
	}
	return state, nil
}

func newFounderPeerGate(t *testing.T, fixture *founderSignerFixture, reader *founderAdmissionLedger,
	row bootstrap.FounderPeerRow,
) (Gate, *countingMaterialChecker, *founderAdmissionCredentials) {
	t.Helper()
	return newFounderPeerGateForInstance(t, fixture, reader, row, "ocid1.instance.oc1.sa-saopaulo-1."+row.Slot)
}

func newFounderPeerGateForInstance(t *testing.T, fixture *founderSignerFixture, reader *founderAdmissionLedger,
	row bootstrap.FounderPeerRow, instanceID string,
) (Gate, *countingMaterialChecker, *founderAdmissionCredentials) {
	t.Helper()
	material := new(countingMaterialChecker)
	credentials := new(founderAdmissionCredentials)
	markerDirectory := filepath.Join(t.TempDir(), "marker")
	if err := os.Mkdir(markerDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(markerDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	peerFloorDirectory := filepath.Join(t.TempDir(), "peer-floor")
	if err := os.Mkdir(peerFloorDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	serviceUID, serviceGID := testFounderServiceIdentity()
	if os.Geteuid() == 0 {
		if err := os.Chown(peerFloorDirectory, int(serviceUID), int(serviceGID)); err != nil {
			t.Fatal(err)
		}
	}
	peerFloor := &FounderSelectionFloorStore{directory: peerFloorDirectory,
		ownerUID: serviceUID, allowUnsafeAncestors: true}
	fixture.peerFloor = peerFloor
	prepared := admissionPreparedIdentity(t, row.Slot)
	trustStore := admissionTrustStore(t, fixture.baked.Roots)
	manifestEnvelope, err := trust.DecodeEnvelope(fixture.current.ManifestWires[row.Slot])
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.ManifestPayload(manifestEnvelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	writeAdmissionLaunchInputs(t, trustStore, manifest)
	continuation := &FounderPeerContinuation{floor: peerFloor,
		serviceUID: serviceUID, serviceGID: serviceGID,
		now: func() time.Time { return fixture.now }}
	gate := Gate{Roots: fixture.baked.Roots, AnchorWire: fixture.baked.AnchorWire,
		Expected:                     fixture.baked.Identity.AnchorExpectation(),
		LoadedControllerConfigSHA256: testControllerConfigDigestFromManifestWire(t, fixture.current.ManifestWires[row.Slot]),
		Descriptor:                   fixedDescriptor{slot: row.Slot, instance: instanceID},
		Instances: fakeInstanceObserver{InstanceObservation{InstanceOCID: instanceID,
			CompartmentOCID: row.CompartmentOCID, ImageOCID: row.ImageOCID,
			AvailabilityDomain: row.AvailabilityDomain, FaultDomain: row.FaultDomain, Shape: row.Shape,
			SubnetOCID: row.SubnetOCID, NSGOCIDs: row.NetworkSecurityGroupOCIDs,
			PrimaryVNICOCID:  "ocid1.vnic.oc1.sa-saopaulo-1." + row.Slot,
			PrimaryPrivateIP: row.PrivateIP, PrimaryVNIC: true, LifecycleState: "RUNNING"}},
		Ledgers: reader, Binary: fixedBinaryChecker{}, Material: material, Credentials: credentials,
		ObserveIdentity: func(AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
			return prepared.Broker, prepared.Store, nil
		},
		InitialIdentity: func(bootstrap.Manifest) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
			return prepared.Broker, prepared.Store, nil
		},
		trustStore: &trustStore,
		Markers:    MarkerStore{directory: markerDirectory, ownerUID: uint32(os.Getuid()), allowUnsafeAncestors: true},
		ClockCheck: func() error { return nil }, Now: func() time.Time { return fixture.now },
		InitialPeerFloor: func(ctx context.Context, marker AcceptedInstall, state bootstrap.SlotState,
			now time.Time,
		) error {
			selectionReader, err := NewCurrentFounderAuthorityReader(fixture.baked, marker,
				fixture.objects, peerFloor)
			if err != nil {
				return err
			}
			continuation.reader = selectionReader
			return continuation.Initialize(ctx, marker, state, now)
		}}
	return gate, material, credentials
}

func TestFounderRuntimePeerGateWaitsForRealLedgerCompletion(t *testing.T) {
	fixture, caller, _, fake := newFounderRuntimeFixtureWithSetup(t, func(fixture *founderSignerFixture) {
		founderFixtureWithAdmissibleRelease(t, fixture)
	})
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	row := fixture.plan.Peers[0]
	reader := &founderAdmissionLedger{ledger: ledger}
	gate, material, credentials := newFounderPeerGate(t, fixture, reader, row)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var retryDeadline *time.Timer
	defer func() {
		if retryDeadline != nil {
			retryDeadline.Stop()
		}
	}()
	reader.onFirst = func() {
		if material.initialCalls != 0 || credentials.calls != 0 {
			t.Fatal("pending peer reached material or credential effects")
		}
		founderCtx, stopFounder := context.WithTimeout(t.Context(), initialAdmissionWaitLimit)
		defer stopFounder()
		if err := caller.runPeer(founderCtx, row.Slot); err != nil {
			t.Fatalf("complete peer after first Gate read: %v", err)
		}
		// The first ReadSlot synchronously commits the peer. Start the retry
		// deadline only after that potentially slow signed ledger work finishes.
		retryDeadline = time.AfterFunc(30*time.Second, cancel)
	}
	accepted, err := gate.admitInitialWhenReady(ctx, time.Millisecond)
	if err != nil {
		t.Fatalf("peer did not recover after founder committed: %v", err)
	}
	if reader.reads != 2 || accepted.Slot != row.Slot || accepted.SeedSlot != fixture.plan.SeedSlot ||
		material.initialCalls != 1 || credentials.calls != 1 || fake.launches != 1 || fake.observations != 1 {
		t.Fatalf("peer did not cross the exact completion gate: marker=%+v reads=%d material=%d credentials=%d launches=%d observations=%d",
			accepted, reader.reads, material.initialCalls, credentials.calls, fake.launches, fake.observations)
	}
	stored, err := gate.Markers.ReadIdentity()
	if err != nil || stored.Slot != row.Slot || stored.SeedSlot != fixture.plan.SeedSlot {
		t.Fatalf("persisted peer marker = %+v, %v", stored, err)
	}
}

func TestFounderRuntimePeerGateWaitsForQuarantineRepair(t *testing.T) {
	fixture, caller, objects, fake := newFounderRuntimeFixtureWithSetup(t, func(fixture *founderSignerFixture) {
		founderFixtureWithAdmissibleRelease(t, fixture)
	})
	row := fixture.plan.Peers[0]
	if err := caller.runPeer(t.Context(), row.Slot); err != nil {
		t.Fatalf("initial founder completion: %v", err)
	}
	later := fixture.now.Add(6 * time.Minute)
	changed := false
	for key, object := range objects.objects {
		if strings.Contains(key, "/result-") && strings.HasSuffix(key, ".json") {
			object.modified = later
			objects.objects[key] = object
			changed = true
		}
	}
	if !changed {
		t.Fatal("completed founder peer had no immutable result object")
	}
	fixture.now, objects.now, fake.now = later, later, later
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	reader := &founderAdmissionLedger{ledger: ledger}
	gate, material, credentials := newFounderPeerGate(t, fixture, reader, row)
	if _, err := gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmissionPending) ||
		!errors.Is(err, bootstrap.ErrManagedPeerProofQuarantined) {
		t.Fatalf("quarantined peer Gate admission was not pending: %v", err)
	}
	if material.initialCalls != 0 || credentials.calls != 0 {
		t.Fatal("quarantined peer reached material or credential effects")
	}
	if _, err := gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("quarantined peer left an accepted marker: %v", err)
	}
	observationsBeforeRepair := fake.observations
	if err := caller.runPeer(t.Context(), row.Slot); err != nil {
		t.Fatalf("repair quarantined founder result: %v", err)
	}
	accepted, err := gate.AdmitInitial(t.Context())
	if err != nil || accepted.Slot != row.Slot || material.initialCalls != 1 || credentials.calls != 1 ||
		fake.launches != 1 || fake.observations <= observationsBeforeRepair {
		t.Fatalf("repaired peer Gate admission: accepted=%+v err=%v material=%d credentials=%d launches=%d observations=%d",
			accepted, err, material.initialCalls, credentials.calls, fake.launches, fake.observations)
	}
}

func TestFounderRuntimeTimelyCompletedPeersRemainAdmittedAfterProgressExpiry(t *testing.T) {
	fixture, caller, objects, fake := newFounderRuntimeFixtureWithSetup(t, func(fixture *founderSignerFixture) {
		founderFixtureWithAdmissibleRelease(t, fixture)
	})
	for _, row := range fixture.plan.Peers {
		if err := caller.runPeer(t.Context(), row.Slot); err != nil {
			t.Fatalf("complete %s: %v", row.Slot, err)
		}
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	row := fixture.plan.Peers[0]
	gate, material, credentials := newFounderPeerGate(t, fixture,
		&founderAdmissionLedger{ledger: ledger}, row)
	initial, err := gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatalf("initial completed peer admission: %v", err)
	}
	launches, observations, imageReads, writes := fake.launches, fake.observations, fake.imageReads, objects.writes
	fixture.now = fixture.now.Add(6 * time.Minute)
	objects.now, fake.now = fixture.now, fixture.now
	for _, peer := range fixture.plan.Peers {
		state, err := ledger.ReadSlot(t.Context(), bootstrap.BootstrapScope{
			DeploymentID: fixture.accepted.DeploymentID, Cell: fixture.accepted.Cell, Slot: peer.Slot})
		if err != nil || state.Head.ResultDigest == "" {
			t.Fatalf("timely completed peer %q was not historical evidence after progress expiry: state=%+v err=%v",
				peer.Slot, state, err)
		}
	}
	complete, err := founderPeersComplete(t.Context(), fixture.current.Anchor.Anchor(), fixture.accepted, ledger)
	if err != nil || !complete {
		t.Fatalf("timely completed founder cell required new work after progress expiry: complete=%v err=%v", complete, err)
	}
	restarted, err := gate.AdmitRestart(t.Context())
	if err != nil || restarted.Slot != initial.Slot || material.restartCalls != 1 || credentials.calls != 2 {
		t.Fatalf("completed peer restart admission: marker=%+v err=%v material=%d credentials=%d",
			restarted, err, material.restartCalls, credentials.calls)
	}
	completed := func(ctx context.Context, _ BakedInputs, accepted AcceptedInstall) (bool, error) {
		return founderPeersComplete(ctx, fixture.current.Anchor.Anchor(), accepted, ledger)
	}
	if err := runAdmittedFounder(t.Context(), fixture.baked, fixture.accepted, 1000, 1000,
		fixture.floor, completed, testSeedPlacement); err != nil {
		t.Fatalf("completed seed founder restart: %v", err)
	}
	for _, peer := range fixture.plan.Peers {
		if err := caller.runPeer(t.Context(), peer.Slot); err != nil {
			t.Fatalf("idempotent completed peer restart %q: %v", peer.Slot, err)
		}
	}
	if fake.launches != launches || fake.observations != observations ||
		fake.imageReads != imageReads || objects.writes != writes {
		t.Fatalf("completed peer restart performed founder effects: launches=%d→%d observations=%d→%d image reads=%d→%d writes=%d→%d",
			launches, fake.launches, observations, fake.observations, imageReads, fake.imageReads, writes, objects.writes)
	}
}

func TestFounderRuntimeCompletedPeerRestartAfterLaunchDeadline(t *testing.T) {
	fixture, caller, objects, fake := newFounderRuntimeFixtureWithSetup(t, func(fixture *founderSignerFixture) {
		founderFixtureWithShortLaunchDeadline(t, fixture)
	})
	for _, row := range fixture.plan.Peers {
		if err := caller.runPeer(t.Context(), row.Slot); err != nil {
			t.Fatalf("complete %s before launch deadline: %v", row.Slot, err)
		}
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	row := fixture.plan.Peers[0]
	gate, _, _ := newFounderPeerGate(t, fixture, &founderAdmissionLedger{ledger: ledger}, row)
	if _, err := gate.AdmitInitial(t.Context()); err != nil {
		t.Fatalf("initial peer admission: %v", err)
	}
	launches, observations, writes := fake.launches, fake.observations, objects.writes
	fixture.now = fixture.now.Add(6 * time.Minute)
	objects.now, fake.now = fixture.now, fixture.now
	if !fixture.now.After(fixture.plan.LaunchDeadline) {
		t.Fatal("fixture did not advance beyond launch deadline")
	}
	if complete, err := founderPeersComplete(t.Context(), fixture.current.Anchor.Anchor(), fixture.accepted,
		ledger); err != nil || !complete {
		t.Fatalf("completed founder cell after launch deadline: complete=%v err=%v", complete, err)
	}
	if _, err := gate.AdmitRestart(t.Context()); err != nil {
		t.Fatalf("completed peer restart under current selected proof after launch deadline: %v", err)
	}
	if fake.launches != launches || fake.observations != observations || objects.writes != writes {
		t.Fatalf("completed peer restart after launch deadline performed founder effects: launches=%d→%d observations=%d→%d writes=%d→%d",
			launches, fake.launches, observations, fake.observations, writes, objects.writes)
	}
}

func TestFounderRuntimeFirstInstallHoldsAfterReceiptExpiry(t *testing.T) {
	fixture, caller, objects, fake := newFounderRuntimeFixtureWithSetup(t, func(fixture *founderSignerFixture) {
		founderFixtureWithShortLaunchDeadline(t, fixture)
	})
	row := fixture.plan.Peers[0]
	if err := caller.runPeer(t.Context(), row.Slot); err != nil {
		t.Fatalf("complete founder peer before deadline: %v", err)
	}
	fixture.now = fixture.now.Add(6 * time.Minute)
	objects.now, fake.now = fixture.now, fixture.now
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	state, err := ledger.ReadSlot(t.Context(), bootstrap.BootstrapScope{
		DeploymentID: fixture.accepted.DeploymentID, Cell: fixture.accepted.Cell, Slot: row.Slot})
	if err != nil || state.Head.ResultDigest == "" || state.PeerReceiptRecord == nil {
		t.Fatalf("timely peer completion disappeared after receipt expiry: state=%+v err=%v", state, err)
	}
	receiptEnvelope, err := trust.DecodeEnvelope(state.PeerReceiptRecord.Bytes)
	if err != nil || !fixture.now.After(receiptEnvelope.ExpiresAt) {
		t.Fatalf("fixture receipt was not expired: expires=%v now=%v err=%v",
			receiptEnvelope.ExpiresAt, fixture.now, err)
	}
	gate, material, credentials := newFounderPeerGate(t, fixture,
		&founderAdmissionLedger{ledger: ledger}, row)
	if _, err := gate.AdmitInitial(t.Context()); err == nil {
		t.Fatal("first install used historical completion after its material receipt expired")
	}
	if material.initialCalls != 0 || credentials.calls != 0 {
		t.Fatal("expired first-install receipt reached material or credential effects")
	}
	if _, err := gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired first-install receipt left accepted marker: %v", err)
	}
}

func TestFounderRuntimeFirstInstallHoldsIfReceiptExpiresDuringFloorPublication(t *testing.T) {
	fixture, caller, objects, fake := newFounderRuntimeFixtureWithSetup(t, func(fixture *founderSignerFixture) {
		founderFixtureWithAdmissibleRelease(t, fixture)
	})
	row := fixture.plan.Peers[0]
	if err := caller.runPeer(t.Context(), row.Slot); err != nil {
		t.Fatal(err)
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	gate, material, credentials := newFounderPeerGate(t, fixture,
		&founderAdmissionLedger{ledger: ledger}, row)
	provisionFloor := gate.InitialPeerFloor
	gate.InitialPeerFloor = func(ctx context.Context, marker AcceptedInstall, state bootstrap.SlotState,
		at time.Time,
	) error {
		if err := provisionFloor(ctx, marker, state, at); err != nil {
			return err
		}
		fixture.now = fixture.now.Add(6 * time.Minute)
		objects.now, fake.now = fixture.now, fixture.now
		return nil
	}
	if _, err := gate.AdmitInitial(t.Context()); err == nil {
		t.Fatal("first install published marker after receipt expired during floor provision")
	}
	if material.initialCalls != 1 || credentials.calls != 1 {
		t.Fatalf("fixture did not reach floor after material and credential checks: material=%d credentials=%d",
			material.initialCalls, credentials.calls)
	}
	if _, err := gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired floor publication left accepted marker: %v", err)
	}
}

func TestFounderRuntimeLateCompletionCannotFirstAdmitAfterLaunchDeadline(t *testing.T) {
	fixture, caller, objects, fake := newFounderRuntimeFixtureWithSetup(t, func(fixture *founderSignerFixture) {
		founderFixtureWithShortLaunchDeadline(t, fixture)
	})
	row := fixture.plan.Peers[0]
	if err := caller.runPeer(t.Context(), row.Slot); err != nil {
		t.Fatalf("complete founder peer before simulated late storage: %v", err)
	}
	late := fixture.now.Add(4 * time.Minute)
	changed := false
	for key, object := range objects.objects {
		if strings.Contains(key, "/result-") && strings.HasSuffix(key, ".json") {
			object.modified = late
			objects.objects[key] = object
			changed = true
		}
	}
	if !changed {
		t.Fatal("completed founder peer had no immutable result object")
	}
	fixture.now, objects.now, fake.now = late, late, late
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	gate, material, credentials := newFounderPeerGate(t, fixture,
		&founderAdmissionLedger{ledger: ledger}, row)
	if _, err := gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmissionPending) {
		t.Fatalf("late/quarantined result reached first admission: %v", err)
	}
	if material.initialCalls != 0 || credentials.calls != 0 {
		t.Fatal("late/quarantined result reached material or credential effects")
	}
	if _, err := gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("late/quarantined result left accepted marker: %v", err)
	}
}

func TestFounderRuntimeMissingSignerCannotTouchOCI(t *testing.T) {
	fixture, caller, _, fake := newFounderRuntimeFixture(t)
	if err := os.Remove(filepath.Join(fixture.store.directory, "founder-ledger.key")); err != nil {
		t.Fatal(err)
	}
	if err := caller.runPeer(t.Context(), "controller-a"); !errors.Is(err, ErrFounderSigner) {
		t.Fatalf("missing ledger signer was not held: %v", err)
	}
	if fake.launches != 0 || fake.observations != 0 || fake.imageReads != 0 {
		t.Fatal("founder OCI was touched without both exact signers")
	}
}

func TestFounderRuntimeLaterLedgerReadCrossesSelectionExpiryWithoutEffects(t *testing.T) {
	fixture, caller, objects, fake := newFounderRuntimeFixture(t)
	writes := objects.writes
	advanced := false
	objects.afterGet = func(name string) {
		if !advanced && strings.HasSuffix(name, "/intent.json") {
			objects.now = fixture.now.Add(2 * time.Hour)
			advanced = true
		}
	}
	if err := caller.runPeer(t.Context(), "controller-a"); !errors.Is(err, ErrFounderRuntime) {
		t.Fatalf("stale intent server Date authorized expired selection: %v", err)
	}
	if !advanced || objects.writes != writes || fake.imageReads != 0 || fake.launches != 0 || fake.observations != 0 {
		t.Fatalf("late server time reached founder effects: advanced=%v writes=%d/%d imageReads=%d launches=%d observations=%d",
			advanced, objects.writes, writes, fake.imageReads, fake.launches, fake.observations)
	}
}

func TestFounderRuntimeStaleObservationReobservesExactInstanceBeforeResult(t *testing.T) {
	fixture, caller, objects, fake := newFounderRuntimeFixture(t)
	const slot = "controller-a"
	snapshot, err := caller.fresh(t.Context(), slot)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewFounderOCIAttempt(snapshot.peer, snapshot.now)
	if err != nil {
		t.Fatal(err)
	}
	instanceID, err := caller.adapter.Launch(t.Context(), attempt, caller.peerRefresh(slot))
	if err != nil {
		t.Fatal(err)
	}
	if err := caller.pinCandidate(t.Context(), snapshot, slot, instanceID); err != nil {
		t.Fatal(err)
	}
	snapshot, err = caller.fresh(t.Context(), slot)
	if err != nil {
		t.Fatal(err)
	}
	observationAttempt, err := NewFounderOCIObservationAttempt(snapshot.peer, snapshot.now)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := caller.adapter.Observe(t.Context(), observationAttempt, caller.peerRefresh(slot), instanceID)
	if err != nil {
		t.Fatal(err)
	}
	observed.observedMono = time.Now().Add(-bootstrap.ManagedPeerObservationMaxAge - time.Second)
	fixture.now = fixture.now.Add(2 * time.Second)
	fake.now = fixture.now
	objects.now = fake.now
	if err := caller.completePeer(t.Context(), slot, observed); err != nil {
		t.Fatalf("stale exact observation did not reobserve: %v", err)
	}
	if fake.launches != 1 || fake.observations != 2 {
		t.Fatalf("stale observation relaunched or skipped reobservation: launches=%d observations=%d",
			fake.launches, fake.observations)
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	state, err := ledger.ReadSlot(t.Context(), bootstrap.BootstrapScope{
		DeploymentID: fixture.accepted.DeploymentID, Cell: fixture.accepted.Cell, Slot: slot})
	if err != nil || state.Result == nil || !state.Result.ObservedAt.Equal(fake.now) {
		t.Fatalf("positive result relabeled old observation: result=%+v err=%v", state.Result, err)
	}
}

func TestFounderRuntimeResultKeepsActualOCIObservationDate(t *testing.T) {
	fixture, caller, _, fake := newFounderRuntimeFixture(t)
	fake.now = fixture.now.Add(-2 * time.Second)
	if err := caller.runPeer(t.Context(), "controller-a"); err != nil {
		t.Fatalf("complete founder peer with earlier OCI observation Date: %v", err)
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	state, err := ledger.ReadSlot(t.Context(), bootstrap.BootstrapScope{
		DeploymentID: fixture.accepted.DeploymentID, Cell: fixture.accepted.Cell, Slot: "controller-a"})
	if err != nil || state.Result == nil || state.ResultRecord == nil {
		t.Fatalf("read completed peer result: state=%+v err=%v", state, err)
	}
	envelope, err := trust.DecodeEnvelope(state.ResultRecord.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Result.ObservedAt.Equal(fake.now) || !envelope.IssuedAt.Equal(fixture.now) {
		t.Fatalf("result changed OCI observation Date or signing time: observed=%v issued=%v",
			state.Result.ObservedAt, envelope.IssuedAt)
	}
}

func TestFounderRuntimeTrustedAgeGateReobservesPinnedInstance(t *testing.T) {
	fixture, caller, objects, fake := newFounderRuntimeFixture(t)
	advanced := false
	fake.afterBoot = func() {
		if !advanced {
			fixture.now = fixture.now.Add(12 * time.Second)
			objects.now = fixture.now
			fake.now = objects.now
			advanced = true
		}
	}
	if err := caller.runPeer(t.Context(), "controller-a"); err != nil {
		t.Fatalf("complete peer after trusted age crossed the result write gate: %v", err)
	}
	if !advanced || fake.launches != 1 || fake.observations != 2 {
		t.Fatalf("stale result did not reobserve exact instance: advanced=%v launches=%d observations=%d",
			advanced, fake.launches, fake.observations)
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	state, err := ledger.ReadSlot(t.Context(), bootstrap.BootstrapScope{
		DeploymentID: fixture.accepted.DeploymentID, Cell: fixture.accepted.Cell, Slot: "controller-a"})
	if err != nil || state.Result == nil || !state.Result.ObservedAt.Equal(fake.now) {
		t.Fatalf("trusted-age retry reused stale OCI observation: result=%+v err=%v", state.Result, err)
	}
}

func TestFounderRuntimeChangedInstanceAfterStaleObservationCannotComplete(t *testing.T) {
	_, caller, objects, fake := newFounderRuntimeFixture(t)
	const slot = "controller-a"
	snapshot, err := caller.fresh(t.Context(), slot)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewFounderOCIAttempt(snapshot.peer, snapshot.now)
	if err != nil {
		t.Fatal(err)
	}
	instanceID, err := caller.adapter.Launch(t.Context(), attempt, caller.peerRefresh(slot))
	if err != nil {
		t.Fatal(err)
	}
	if err := caller.pinCandidate(t.Context(), snapshot, slot, instanceID); err != nil {
		t.Fatal(err)
	}
	// A previously observed candidate has aged out before result writing. The
	// recovery path must reread the pinned instance instead of using these facts.
	row := attempt.request.Row
	observed := FounderOCIObservation{
		InstanceOCID: instanceID, InstanceETag: "founder-instance-etag-" + slot,
		PrimaryVNICID: "ocid1.vnic.oc1.sa-saopaulo-1." + slot,
		BootVolumeID:  "ocid1.bootvolume.oc1.sa-saopaulo-1." + slot,
		CompartmentID: row.CompartmentOCID, ImageID: row.ImageOCID,
		PrivateIP: row.PrivateIP, Shape: row.Shape, WholeOCPUs: row.WholeOCPUs,
		MemoryInGB: row.MemoryInGB, BootVolumeGB: row.BootVolumeGB, BootVPUsPerGB: 10,
		ObservedAt:   snapshot.now,
		observedMono: time.Now().Add(-bootstrap.ManagedPeerObservationMaxAge - time.Second),
	}
	fake.instanceChanged = true
	writes := objects.writes
	if err := caller.completePeer(t.Context(), slot, observed); err == nil {
		t.Fatal("changed instance produced a positive result from stale facts")
	}
	if fake.launches != 1 || fake.observations == 0 || objects.writes != writes {
		t.Fatalf("changed instance touched founder ledger or relaunched: launches=%d observations=%d writes=%d/%d",
			fake.launches, fake.observations, objects.writes, writes)
	}
}

func TestFounderRuntimeMissingOCIObservationDateCannotComplete(t *testing.T) {
	_, caller, objects, fake := newFounderRuntimeFixture(t)
	fake.omitBootDate = true
	writes := objects.writes
	if err := caller.runPeer(t.Context(), "controller-a"); err == nil {
		t.Fatal("OCI observation without server Date produced a positive result")
	}
	if fake.launches != 1 || fake.observations == 0 || objects.writes != writes+2 {
		t.Fatalf("missing observation Date touched founder ledger or relaunched: launches=%d observations=%d writes=%d/%d",
			fake.launches, fake.observations, objects.writes, writes)
	}
}

func TestFounderRuntimeOCIContextEndsWithSelectedAuthority(t *testing.T) {
	fixture, caller, _, fake := newFounderRuntimeFixture(t)
	snapshot, err := caller.fresh(t.Context(), "controller-a")
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewFounderOCIAttempt(snapshot.peer, snapshot.now)
	if err != nil {
		t.Fatal(err)
	}
	effectCtx, cancel, err := caller.adapter.beforeEffect(t.Context(), attempt, caller.peerRefresh("controller-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, ok := effectCtx.Deadline()
	imageEnvelope, err := trust.DecodeEnvelope(snapshot.peer.Manifest().ReleaseImageReceiptWire)
	if err != nil {
		t.Fatal(err)
	}
	trustedRemaining := earliestFounderTime(fixture.current.SelectionExpiresAt, imageEnvelope.ExpiresAt).
		Sub(snapshot.recovery.ServerDate().Add(time.Second))
	if !ok || time.Until(deadline) > trustedRemaining+time.Second ||
		time.Until(deadline) < trustedRemaining-5*time.Second {
		t.Fatalf("OCI effect context was not bounded by selected image authority: remaining=%v trusted=%v",
			time.Until(deadline), trustedRemaining)
	}
	if fake.imageReads != 0 || fake.launches != 0 || fake.observations != 0 {
		t.Fatal("effect context construction touched OCI")
	}
}

func TestFounderRuntimeWrongSignerCannotTouchOCI(t *testing.T) {
	fixture, caller, _, fake := newFounderRuntimeFixture(t)
	if err := os.WriteFile(filepath.Join(fixture.store.directory, "founder-ledger.key"), fixture.peerKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := caller.runPeer(t.Context(), "controller-a"); !errors.Is(err, ErrFounderSigner) {
		t.Fatalf("wrong ledger signer was not held: %v", err)
	}
	if fake.launches != 0 || fake.observations != 0 || fake.imageReads != 0 {
		t.Fatal("founder OCI was touched with wrong-role signer material")
	}
}

func TestFounderRuntimeStagedResultRestartReplaysWithoutOCI(t *testing.T) {
	_, caller, objects, fake := newFounderRuntimeFixture(t)
	objects.rejectPart = "/result-"
	if err := caller.runPeer(t.Context(), "controller-a"); err == nil {
		t.Fatal("result write failure did not stop founding")
	}
	launches := fake.launches
	if launches != 1 {
		t.Fatalf("first attempt launches = %d", launches)
	}
	objects.rejectPart = ""
	if err := caller.runPeer(t.Context(), "controller-a"); err != nil {
		t.Fatalf("receipt-only restart: %v", err)
	}
	if fake.launches != launches || fake.observations != 1 {
		t.Fatalf("staged result restart repeated OCI despite exact persisted proof: launches=%d observations=%d", fake.launches, fake.observations)
	}
}

func TestFounderRuntimeResultReadyRestartReplaysExactResultWithoutOCI(t *testing.T) {
	_, caller, objects, fake := newFounderRuntimeFixture(t)
	objects.rejectSuffix = "/head.json"
	if err := caller.runPeer(t.Context(), "controller-a"); err == nil {
		t.Fatal("HEAD update failure did not stop founding")
	}
	var resultWire []byte
	for key, object := range objects.objects {
		if strings.Contains(key, "/result-") && strings.HasSuffix(key, ".json") {
			resultWire = bytes.Clone(object.wire)
		}
	}
	if len(resultWire) == 0 || fake.launches != 1 || fake.observations != 1 {
		t.Fatalf("failed HEAD stage did not leave exact result: result=%d launches=%d observations=%d",
			len(resultWire), fake.launches, fake.observations)
	}
	objects.rejectSuffix = ""
	if err := caller.runPeer(t.Context(), "controller-a"); err != nil {
		t.Fatalf("result-ready restart: %v", err)
	}
	if fake.launches != 1 || fake.observations != 1 {
		t.Fatalf("result-ready restart touched OCI: launches=%d observations=%d", fake.launches, fake.observations)
	}
	found := false
	for key, object := range objects.objects {
		if strings.Contains(key, "/result-") && strings.HasSuffix(key, ".json") {
			found = bytes.Equal(object.wire, resultWire)
		}
	}
	if !found {
		t.Fatal("result-ready restart replaced exact persisted result bytes")
	}
}

func TestFounderRuntimeSupersededSelectionStopsBeforeLaunch(t *testing.T) {
	fixture, caller, _, fake := newFounderRuntimeFixture(t)
	fake.afterImage = func() {
		fixture.resignSelectedAnchorAndPlan(t)
		selection := fixture.selection
		selection.Generation = 2
		selection.PlanSHA256 = digestWire(fixture.planWire)
		selection.AnchorSHA256 = digestWire(fixture.anchorWire)
		fixture.publish(t, selection)
		fake.afterImage = nil
	}
	if err := caller.runPeer(t.Context(), "controller-a"); err == nil {
		t.Fatal("superseded selected plan authorized old intent launch")
	}
	if fake.launches != 0 || fake.observations != 0 {
		t.Fatalf("superseded plan allowed OCI effect: launches=%d observations=%d", fake.launches, fake.observations)
	}
}

type founderFakeOCI struct {
	rows            map[string]bootstrap.FounderPeerRow
	now             time.Time
	instanceChanged bool
	omitBootDate    bool
	launches        int
	observations    int
	imageReads      int
	afterImage      func()
	afterBoot       func()
}

func (fake *founderFakeOCI) rowForInstance(id string) (bootstrap.FounderPeerRow, bool) {
	for slot, row := range fake.rows {
		base := "ocid1.instance.oc1.sa-saopaulo-1." + slot
		if id == base || strings.HasPrefix(id, base+"-a") && founderFakeReplacementSuffix(slot, id[len(base)+1:]) {
			return row, true
		}
	}
	return bootstrap.FounderPeerRow{}, false
}

// founderFakeAttempt returns the replacement attempt marker ("a2") from a
// replacement retry token; attempt one carries no marker.
func founderFakeAttempt(slot, token string) string {
	rest, ok := strings.CutPrefix(token, "replace-"+slot+"-")
	if !ok {
		return ""
	}
	marker, _, found := strings.Cut(rest, "-")
	if !found || !founderFakeReplacementSuffix(slot, marker) {
		return ""
	}
	return marker
}

func founderFakeReplacementSuffix(_ string, marker string) bool {
	if len(marker) < 2 || marker[0] != 'a' {
		return false
	}
	for _, digit := range marker[1:] {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func (fake *founderFakeOCI) GetImage(_ context.Context, request core.GetImageRequest) (core.GetImageResponse, error) {
	fake.imageReads++
	if fake.afterImage != nil {
		fake.afterImage()
	}
	for _, row := range fake.rows {
		if request.ImageId != nil && *request.ImageId == row.ImageOCID {
			return core.GetImageResponse{Image: core.Image{Id: new(row.ImageOCID),
				CompartmentId: new(row.ImageCompartmentOCID), LifecycleState: core.ImageLifecycleStateAvailable}}, nil
		}
	}
	return core.GetImageResponse{}, errors.New("unknown founder image")
}

func (fake *founderFakeOCI) LaunchInstance(_ context.Context, request core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error) {
	if request.DisplayName == nil || request.OpcRetryToken == nil {
		return core.LaunchInstanceResponse{}, errors.New("unpinned founder launch")
	}
	var row bootstrap.FounderPeerRow
	for slot, candidate := range fake.rows {
		if name, _ := naming.RegionCell("GRU").ControllerSlot(slot); name == *request.DisplayName {
			row = candidate
		}
	}
	if row.Slot == "" {
		return core.LaunchInstanceResponse{}, errors.New("unknown founder slot")
	}
	fake.launches++
	id := "ocid1.instance.oc1.sa-saopaulo-1." + row.Slot
	if attempt := founderFakeAttempt(row.Slot, *request.OpcRetryToken); attempt != "" {
		id += "-" + attempt
	}
	return core.LaunchInstanceResponse{Instance: core.Instance{
		Id:            new(id),
		CompartmentId: new(row.CompartmentOCID), ImageId: new(row.ImageOCID)}}, nil
}

func (fake *founderFakeOCI) GetInstance(_ context.Context, request core.GetInstanceRequest) (core.GetInstanceResponse, error) {
	if request.InstanceId == nil {
		return core.GetInstanceResponse{}, errors.New("missing founder instance")
	}
	row, ok := fake.rowForInstance(*request.InstanceId)
	if !ok {
		return core.GetInstanceResponse{}, errors.New("unknown founder instance")
	}
	fake.observations++
	lifecycle := core.InstanceLifecycleStateRunning
	if fake.instanceChanged {
		lifecycle = core.InstanceLifecycleStateTerminated
	}
	return core.GetInstanceResponse{Instance: core.Instance{
		Id: request.InstanceId, CompartmentId: new(row.CompartmentOCID), ImageId: new(row.ImageOCID),
		AvailabilityDomain: new(row.AvailabilityDomain), FaultDomain: new(row.FaultDomain), Shape: new(row.Shape),
		LifecycleState: lifecycle,
		ShapeConfig: &core.InstanceShapeConfig{Ocpus: new(float32(row.WholeOCPUs)),
			MemoryInGBs: new(float32(row.MemoryInGB))},
		Metadata: map[string]string{"terrascale-bootstrap": `{"schemaVersion":1,"slot":"` + row.Slot + `"}`},
	}, Etag: new("founder-instance-etag-" + row.Slot)}, nil
}

func (fake *founderFakeOCI) ListVnicAttachments(_ context.Context, request core.ListVnicAttachmentsRequest) (core.ListVnicAttachmentsResponse, error) {
	if request.InstanceId == nil {
		return core.ListVnicAttachmentsResponse{}, errors.New("missing founder instance")
	}
	row, ok := fake.rowForInstance(*request.InstanceId)
	if !ok {
		return core.ListVnicAttachmentsResponse{}, errors.New("unknown founder instance")
	}
	return core.ListVnicAttachmentsResponse{Items: []core.VnicAttachment{{
		VnicId: new("ocid1.vnic.oc1.sa-saopaulo-1." + row.Slot), InstanceId: request.InstanceId,
		CompartmentId: new(row.CompartmentOCID), SubnetId: new(row.SubnetOCID),
		LifecycleState: core.VnicAttachmentLifecycleStateAttached,
	}}}, nil
}

func (fake *founderFakeOCI) GetVnic(_ context.Context, request core.GetVnicRequest) (core.GetVnicResponse, error) {
	if request.VnicId == nil {
		return core.GetVnicResponse{}, errors.New("missing founder VNIC")
	}
	for slot, row := range fake.rows {
		if *request.VnicId == "ocid1.vnic.oc1.sa-saopaulo-1."+slot {
			return core.GetVnicResponse{Vnic: core.Vnic{
				Id: request.VnicId, CompartmentId: new("ocid1.compartment.oc1..network"),
				AvailabilityDomain: new(row.AvailabilityDomain), SubnetId: new(row.SubnetOCID),
				PrivateIp: new(row.PrivateIP), IsPrimary: new(true),
				LifecycleState: core.VnicLifecycleStateAvailable,
				NsgIds:         row.NetworkSecurityGroupOCIDs,
			}}, nil
		}
	}
	return core.GetVnicResponse{}, errors.New("unknown founder VNIC")
}

func (fake *founderFakeOCI) GetSubnet(_ context.Context, request core.GetSubnetRequest) (core.GetSubnetResponse, error) {
	for _, row := range fake.rows {
		if value(request.SubnetId) == row.SubnetOCID {
			return core.GetSubnetResponse{Subnet: core.Subnet{
				Id: request.SubnetId, CompartmentId: new("ocid1.compartment.oc1..network"),
				VcnId:          new("ocid1.vcn.oc1.sa-saopaulo-1.founder"),
				LifecycleState: core.SubnetLifecycleStateAvailable,
			}}, nil
		}
	}
	return core.GetSubnetResponse{}, errors.New("unknown founder subnet")
}

func (fake *founderFakeOCI) ListBootVolumeAttachments(_ context.Context, request core.ListBootVolumeAttachmentsRequest) (core.ListBootVolumeAttachmentsResponse, error) {
	if request.InstanceId == nil {
		return core.ListBootVolumeAttachmentsResponse{}, errors.New("missing founder instance")
	}
	row, ok := fake.rowForInstance(*request.InstanceId)
	if !ok {
		return core.ListBootVolumeAttachmentsResponse{}, errors.New("unknown founder instance")
	}
	return core.ListBootVolumeAttachmentsResponse{Items: []core.BootVolumeAttachment{{
		BootVolumeId: new("ocid1.bootvolume.oc1.sa-saopaulo-1." + row.Slot),
		InstanceId:   request.InstanceId, CompartmentId: new(row.CompartmentOCID),
		AvailabilityDomain: new(row.AvailabilityDomain),
		LifecycleState:     core.BootVolumeAttachmentLifecycleStateAttached,
	}}}, nil
}

func (fake *founderFakeOCI) GetBootVolume(_ context.Context, request core.GetBootVolumeRequest) (core.GetBootVolumeResponse, error) {
	if request.BootVolumeId == nil {
		return core.GetBootVolumeResponse{}, errors.New("missing founder boot volume")
	}
	for slot, row := range fake.rows {
		if *request.BootVolumeId == "ocid1.bootvolume.oc1.sa-saopaulo-1."+slot {
			headers := make(http.Header)
			if !fake.omitBootDate {
				headers.Set("Date", fake.now.Format(http.TimeFormat))
			}
			if fake.afterBoot != nil {
				fake.afterBoot()
			}
			return core.GetBootVolumeResponse{RawResponse: &http.Response{Header: headers}, BootVolume: core.BootVolume{
				Id: request.BootVolumeId, CompartmentId: new(row.CompartmentOCID),
				AvailabilityDomain: new(row.AvailabilityDomain), ImageId: new(row.ImageOCID),
				SizeInGBs: new(int64(row.BootVolumeGB)), VpusPerGB: new(int64(10)),
				LifecycleState: core.BootVolumeLifecycleStateAvailable,
			}}, nil
		}
	}
	return core.GetBootVolumeResponse{}, errors.New("unknown founder boot volume")
}

// testSeedPlacement puts the fixture seed in the fault domain its plan leaves
// free: the sorted peer slots take FAULT-DOMAIN-1 and FAULT-DOMAIN-2.
func testSeedPlacement(context.Context) (bootstrap.ControllerPlacement, error) {
	return bootstrap.ControllerPlacement{AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-3"}, nil
}
