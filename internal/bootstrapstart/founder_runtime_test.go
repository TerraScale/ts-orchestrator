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

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
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

func newFounderRuntimeFixture(t *testing.T) (*founderSignerFixture, *founderCaller, *founderLedgerObjects, *founderFakeOCI) {
	return newFounderRuntimeFixtureWithSetup(t, nil)
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
	_ bootstrap.StartupAuthority,
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
