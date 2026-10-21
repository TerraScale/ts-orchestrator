package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type fixedDescriptor struct {
	slot, instance string
}

func (source fixedDescriptor) FetchDescriptor(context.Context) (Descriptor, error) {
	return Descriptor{SchemaVersion: 1, Slot: source.slot}, nil
}

func (source fixedDescriptor) FetchInstanceID(context.Context) (string, error) {
	return source.instance, nil
}

type countingLedgerOpener struct {
	state                      bootstrap.SlotState
	currentCalls, historyCalls int
	onCurrent                  func(int)
	published                  [][]byte
	onPublish                  func([]byte) error
}

func (opener *countingLedgerOpener) ReadSlot(context.Context, bootstrap.BootstrapScope) (bootstrap.SlotState, error) {
	return opener.state, nil
}

func (opener *countingLedgerOpener) PublishAcceptedInstall(_ context.Context, _ bootstrap.BootstrapScope,
	marker []byte,
) error {
	opener.published = append(opener.published, bytes.Clone(marker))
	if opener.onPublish != nil {
		return opener.onPublish(marker)
	}
	return nil
}

func (opener *countingLedgerOpener) OpenCurrentLedger(_ context.Context, anchor bootstrap.VerifiedBootstrapAnchor,
	_ trust.Keyring,
) (AdmissionLedger, error) {
	if !anchor.IsVerified() {
		return nil, ErrLedgerGrant
	}
	opener.currentCalls++
	if opener.onCurrent != nil {
		opener.onCurrent(opener.currentCalls)
	}
	return opener, nil
}

func TestManagedPeerInitialAdmissionWaitsForPositiveHEAD(t *testing.T) {
	fixture := newPeerAdmissionFlowFixture(t)
	complete := fixture.ledger.state
	pending := complete
	pending.Head.ResultDigest = ""
	pending.ManifestRecord = nil
	pending.Result = nil
	pending.ResultRecord = nil
	pending.PeerReceiptRecord = nil
	fixture.ledger.state = pending
	fixture.ledger.onCurrent = func(call int) {
		if call == 2 {
			if fixture.material.initialCalls != 0 || fixture.credentials.calls != 0 {
				t.Fatal("pending peer reached material or credential effects")
			}
			fixture.ledger.state = complete
		}
	}
	// This checks retry ordering, not crypto throughput on a loaded race host.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	marker, err := fixture.gate.admitInitialWhenReady(ctx, time.Millisecond)
	if err != nil || marker.Slot != complete.Intent.Slot || fixture.ledger.currentCalls != 2 {
		t.Fatalf("pending peer admission did not resume after signed result: marker=%+v calls=%d err=%v",
			marker, fixture.ledger.currentCalls, err)
	}
}

func TestManagedPeerPendingClassifierPreservesMalformedPositiveResult(t *testing.T) {
	fixture := newPeerAdmissionFlowFixture(t)
	state := fixture.ledger.state
	state.Head.ResultDigest = ""
	state.ManifestRecord = nil
	state.Result = nil
	state.ResultRecord = nil
	state.PeerReceiptRecord = nil
	fixture.ledger.state = state
	if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmissionPending) {
		t.Fatalf("managed peer before signed result: %v", err)
	}
	if fixture.material.initialCalls != 0 || fixture.credentials.calls != 0 {
		t.Fatal("pending peer reached material or credential effects")
	}
	state.Head.ResultDigest = strings.Repeat("e", 64)
	fixture.ledger.state = state
	if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmission) || errors.Is(err, ErrAdmissionPending) {
		t.Fatalf("positive HEAD missing manifest was classified as pending: %v", err)
	}
}

func (opener *countingLedgerOpener) OpenHistoricalLedger(_ context.Context, anchor bootstrap.HistoricalBootstrapAnchor,
	_ trust.Keyring,
) (AdmissionLedger, error) {
	if !anchor.IsVerified() {
		return nil, ErrLedgerGrant
	}
	opener.historyCalls++
	return opener, nil
}

type fixedBinaryChecker struct{}

func (fixedBinaryChecker) VerifyCurrent(image release.VerifiedImage) (RunningBinary, error) {
	pin := image.Receipt()
	return RunningBinary{SHA256: pin.BinarySHA256, Bytes: pin.BinaryBytes, Architecture: pin.Architecture}, nil
}
func (fixedBinaryChecker) VerifyAccepted(pin identityrekey.BinaryPin) (RunningBinary, error) {
	return RunningBinary{SHA256: pin.SHA256, Bytes: pin.Size, Architecture: pin.Architecture}, nil
}

func (fixedBinaryChecker) VerifySelfUpdated(selfupdate.Layout, trust.Keyring, release.UpdateExpectation,
) (RunningBinary, error) {
	return RunningBinary{}, ErrRunningBinaryMismatch
}

type countingMaterialChecker struct {
	initialCalls, restartCalls int
	onPrepare                  func(CurrentProofVerifier) error
	restartErr                 error
}

func (checker *countingMaterialChecker) PrepareInitial(_ context.Context, _ bootstrap.StartupAuthority,
	_ bootstrap.VerifiedReceipt, _ map[string]string, verifyCurrent CurrentProofVerifier,
) error {
	checker.initialCalls++
	if checker.onPrepare != nil {
		return checker.onPrepare(verifyCurrent)
	}
	return nil
}

func (checker *countingMaterialChecker) RestartPins(accepted AcceptedIdentity, _ trust.Keyring,
) (MaterialPins, error) {
	wire, err := EncodeAcceptedIdentity(accepted)
	if err != nil {
		return MaterialPins{}, err
	}
	pins := ManifestPins(acceptedMaterialDigests(accepted))
	pins.acceptance, err = accepted.AcceptanceSHA256()
	if err != nil {
		return MaterialPins{}, err
	}
	pins.slot = accepted.Slot
	pins.acceptedSHA256 = digest(wire)
	pins.references = accepted.MaterialReferences
	return pins, nil
}

func (checker *countingMaterialChecker) VerifyRestart(context.Context, AcceptedIdentity,
	MaterialPins,
) error {
	checker.restartCalls++
	return checker.restartErr
}

type countingCredentialChecker struct {
	calls    int
	err      error
	onVerify func()
}

type stagedSecretMaterializer struct {
	calls int
}

func (materializer *stagedSecretMaterializer) MaterializeCurrent(_ context.Context, _ bootstrap.StartupAuthority,
	_ bootstrap.VerifiedReceipt, reference bootstrap.SecretReference, directory string, _ func(time.Time) error,
) error {
	materializer.calls++
	content := []byte(reference.TargetFile)
	return os.WriteFile(filepath.Join(directory, reference.TargetFile), content, 0o600)
}

func (checker *countingCredentialChecker) VerifyInitialLiveCredentials(_ context.Context, expected MaterialPins, _ bootstrap.StartupAuthority) error {
	return checker.verify(expected)
}
func (checker *countingCredentialChecker) VerifyLiveCredentials(_ context.Context, expected MaterialPins, _ AcceptedIdentity) error {
	return checker.verify(expected)
}
func (checker *countingCredentialChecker) verify(expected MaterialPins) error {
	checker.calls++
	if checker.onVerify != nil {
		checker.onVerify()
	}
	if len(expected.Digests) == 0 {
		return ErrLiveCredentials
	}
	return checker.err
}

type admissionFlowFixture struct {
	gate          Gate
	ledger        *countingLedgerOpener
	material      *countingMaterialChecker
	credentials   *countingCredentialChecker
	now           *time.Time
	rootPrivate   ed25519.PrivateKey
	ledgerPrivate ed25519.PrivateKey
	// bakedBinary is the executable the signed image receipt names.
	bakedBinary string
}

// qualifiedImageFixture signs test-only qualification independently of the image publisher.
func qualifiedImageFixture(t *testing.T, image release.ImageReceipt, environment string, root ed25519.PrivateKey, at time.Time) release.ImageReceipt {
	t.Helper()
	record := release.ProductionQualification{Schema: release.ProductionQualificationSchema,
		Candidate: release.ProductionExpectation{SourceRevision: image.SourceRevision, ArtifactSHA256: image.ImageSHA256,
			QualificationSHA256: image.QualificationSHA256, Cell: image.OCIRegion, Environment: environment,
			Runtime: release.ProductionRuntime, Architecture: image.Architecture, Role: "orchestrator"}}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		evidence := []byte("test-only " + gate + " image evidence")
		record.Evidence = append(record.Evidence, release.ProductionGateEvidence{Gate: gate,
			SHA256: digest(evidence), Bytes: int64(len(evidence)), CompletedAt: at.Add(-time.Second)})
	}
	payload, err := trust.EncodePayload(record)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := trust.Sign(payload, release.ProductionQualificationScope(record.Candidate), at, at.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	image.Production = &release.ProductionProof{Qualification: envelopeWire(t, proof)}
	return image
}

func newAdmissionFlowFixture(t *testing.T) admissionFlowFixture {
	return newAdmissionFlowFixtureForRole(t, false)
}

func newPeerAdmissionFlowFixture(t *testing.T) admissionFlowFixture {
	return newAdmissionFlowFixtureForRole(t, true)
}

func newAdmissionFlowFixtureForRole(t *testing.T, peer bool) admissionFlowFixture {
	t.Helper()
	anchor, _, roots, rootPrivate, anchorWire := verifiedAnchorFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	var ledgerPrivate ed25519.PrivateKey
	{
		anchored := anchor.Anchor()
		anchored.ControllerSlots = []string{"controller-a", "controller-b", "controller-c"}
		ledgerPublic, private, err := ed25519.GenerateKey(rand.Reader)
		ledgerPrivate = private
		if err != nil {
			t.Fatal(err)
		}
		anchored.LedgerDelegationWire = signTestDelegation(t, rootPrivate, ledgerPublic,
			[]string{"bootstrap-slot-head", "bootstrap-intent", "bootstrap-result", "bootstrap-candidate", "bootstrap-progress"},
			anchored.ControllerSlots, now.Add(-time.Hour), now.Add(2*time.Hour))
		envelope, err := bootstrap.SignBootstrapAnchor(anchored, now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		anchorWire = envelopeWire(t, envelope)
		anchor, err = bootstrap.VerifyBootstrapAnchor(envelope, roots, bootstrap.BootstrapAnchorExpectation{
			DeploymentID: anchored.DeploymentID, Environment: anchored.Environment, Cell: anchored.Cell},
			now, bootstrap.BootstrapAnchorTrustPolicy())
		if err != nil {
			t.Fatal(err)
		}
	}
	imageID := "ocid1.image.oc1.sa-saopaulo-1.image-a"
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.example"
	compartmentID := "ocid1.compartment.oc1..example"
	profile := bootstrap.LaunchProfile{Slot: "controller-b", CompartmentOCID: compartmentID,
		AvailabilityDomain: "SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-1",
		SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.subnet-a", Shape: "VM.Standard.E5.Flex",
		NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.nsg-a", "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.nsg-b"}}
	releasePublic, releasePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	releaseID, err := trust.KeyID(releasePublic)
	if err != nil {
		t.Fatal(err)
	}
	releasePublicWire, err := trust.EncodeDelegatedPublicKey(releasePublic)
	if err != nil {
		t.Fatal(err)
	}
	const revision = "0123456789abcdef0123456789abcdef01234567"
	bakedBytes := elfFixture("baked orchestrator")
	bakedBinary := filepath.Join(t.TempDir(), "terrascale-orchestrator")
	if err := os.WriteFile(bakedBinary, bakedBytes, 0o555); err != nil {
		t.Fatal(err)
	}
	releaseGrant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: releaseID, SubjectPublicKey: releasePublicWire, Capabilities: []trust.Capability{{
			Domain: release.ImageDomain, DeploymentID: entityid.Derive("build", revision), Cell: "GRU", Environment: "production",
			Role: "oci-image", Slots: []string{imageID}, Actions: []string{"sign"},
		}}}, now.Add(-10*time.Minute), now.Add(2*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	imageReceipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: revision,
		GoVersion: release.DefaultGoVersion, Architecture: "amd64", BinaryBytes: int64(len(bakedBytes)),
		BinarySHA256: digest(bakedBytes), QualificationSHA256: strings.Repeat("e", 64),
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU",
		BaseImageSHA256: strings.Repeat("b", 64), KernelRelease: "6.1.0-test+1",
		KernelSHA256: strings.Repeat("c", 64), ImageFormat: "qcow2", ImageBytes: 1024,
		ImageSHA256: strings.Repeat("d", 64), OCIImageOCID: imageID, OCIRegion: "GRU"}
	imageReceipt = qualifiedImageFixture(t, imageReceipt, "production", rootPrivate, now.Add(-time.Minute))
	signedImage, err := release.SignImageReceipt(imageReceipt, "production", releaseGrant, roots,
		releasePrivate, now.Add(-time.Minute), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	imageWire := envelopeWire(t, signedImage)
	releaseGrantWire := envelopeWire(t, releaseGrant)
	anchored := anchor.Anchor()
	manifest := bootstrap.Manifest{SchemaVersion: bootstrap.ManifestSchemaVersion,
		DeploymentID: anchored.DeploymentID, Environment: anchored.Environment,
		ClusterID: anchored.ClusterID, Cell: anchored.Cell, OCIRegion: anchored.OCIRegion,
		IntentGeneration: anchored.InitialRegionIntentGeneration, IntentSHA256: anchored.InitialRegionIntentSHA256,
		ControllerRole: "controller", Slot: "controller-b", SeedSlot: "controller-b", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"},
		Profiles: []bootstrap.LaunchProfile{profile}, ImageOCID: imageID, ImageArchitecture: "linux-amd64",
		ReleaseReceiptSHA256: digest(imageWire), ReleaseImageReceiptWire: imageWire,
		ReleaseDelegationWire: releaseGrantWire, StorageDomain: anchored.StorageDomain,
		Secrets: []bootstrap.SecretReference{{Purpose: bootstrap.SecretController, Slot: "controller-b",
			SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.controller", VersionNumber: 1,
			SHA256: digest([]byte("credential fixture")), MaxBytes: 128, TargetFile: "controller.creds"},
			{Purpose: bootstrap.SecretRegionalShared,
				SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.regional", VersionNumber: 1,
				SHA256: digest([]byte("regional fixture")), MaxBytes: 128, TargetFile: "regional.creds"}}}
	manifest.Secrets = acceptedReferences(manifest.Slot)
	manifest.Profiles = nil
	for _, slot := range manifest.ControllerSlots {
		copy := profile
		copy.Slot = slot
		manifest.Profiles = append(manifest.Profiles, copy)
	}
	if peer {
		manifest.SeedSlot = "controller-a"
	}
	peerPublic, peerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerSlots := slices.DeleteFunc(slices.Clone(manifest.ControllerSlots), func(slot string) bool { return slot == manifest.SeedSlot })
	delegationWire := signTestDelegation(t, rootPrivate, peerPublic, []string{"terrascale.bootstrap.peer-receipt"}, peerSlots, now.Add(-10*time.Minute), now.Add(2*time.Hour))
	delegation, err := trust.DecodeEnvelope(delegationWire)
	if err != nil {
		t.Fatal(err)
	}
	manifest.PeerReceiptDelegation = &delegation
	addTestControllerConfig(&manifest)
	manifestEnvelope, err := bootstrap.SignManifest(manifest, now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	manifestWire := envelopeWire(t, manifestEnvelope)
	manifestExpected, err := anchor.ManifestExpectation("controller-b", imageID)
	if err != nil {
		t.Fatal(err)
	}
	verifiedManifest, err := bootstrap.VerifyManifest(manifestEnvelope, roots, manifestExpected, now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	state := bootstrap.SlotState{
		Head: bootstrap.SlotHead{Attempt: 1, Generation: 1, ResultDigest: strings.Repeat("e", 64)},
		Intent: bootstrap.Intent{Mode: bootstrap.IntentModeExternalSeed,
			DeploymentID: anchored.DeploymentID, Environment: anchored.Environment,
			Cell: string(anchored.Cell), Role: "controller", Slot: "controller-b", ImageOCID: imageID,
			ManifestDigest: verifiedManifest.Digest(), ReleaseReceiptDigest: digest(imageWire),
			CompartmentOCID: compartmentID, CreateKey: "0000000000DQTHYRQR02X2ABFT", OCIRegion: anchored.OCIRegion,
			AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain,
			SubnetOCID: profile.SubnetOCID, Shape: profile.Shape,
			NetworkSecurityGroupIDs: profile.NetworkSecurityGroupOCIDs},
		IntentRecord:   bootstrap.StoredRecord{SHA256: strings.Repeat("f", 64)},
		ManifestRecord: &bootstrap.StoredRecord{Bytes: manifestWire, SHA256: verifiedManifest.Digest()},
		Result: &bootstrap.Result{InstanceOCID: instanceID, ImageOCID: imageID,
			CompartmentOCID: compartmentID, CreateKey: "0000000000DQTHYRQR02X2ABFT", Shape: profile.Shape},
		ResultRecord: &bootstrap.StoredRecord{SHA256: strings.Repeat("e", 64)},
	}
	if peer {
		state.Intent.Mode = bootstrap.IntentModeManaged
		state.Intent.SchemaVersion = 2
	}
	observation := InstanceObservation{InstanceOCID: instanceID, CompartmentOCID: compartmentID, ImageOCID: imageID,
		AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain,
		Shape: profile.Shape, SubnetOCID: profile.SubnetOCID, NSGOCIDs: profile.NetworkSecurityGroupOCIDs,
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.vnic-a", PrimaryPrivateIP: "10.0.0.3",
		PrimaryVNIC: true, LifecycleState: "RUNNING"}
	observed, err := (Gate{Instances: fakeInstanceObserver{observation}}).observe(t.Context(), instanceID, state, anchored)
	if err != nil {
		t.Fatal(err)
	}
	var receiptEnvelope trust.Envelope
	if peer {
		receiptEnvelope, err = bootstrap.SignPeerReceipt(verifiedManifest, observed.Facts,
			now.Add(-time.Minute), now.Add(time.Hour), peerPrivate)
	} else {
		receiptEnvelope, err = bootstrap.SignSeedReceipt(verifiedManifest, observed.Facts,
			now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	}
	if err != nil {
		t.Fatal(err)
	}
	receiptWire := envelopeWire(t, receiptEnvelope)
	if peer {
		state.PeerReceiptRecord = &bootstrap.StoredRecord{Bytes: receiptWire, SHA256: digest(receiptWire)}
	} else {
		state.SeedReceiptRecord = &bootstrap.StoredRecord{Bytes: receiptWire, SHA256: digest(receiptWire)}
	}
	markerDirectory := filepath.Join(t.TempDir(), "marker")
	if err := os.Mkdir(markerDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(markerDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	prepared := admissionPreparedIdentity(t, "controller-b")
	trustStore := admissionTrustStore(t, roots)
	writeAdmissionLaunchInputs(t, trustStore, manifest)
	ledger := &countingLedgerOpener{state: state}
	material := &countingMaterialChecker{}
	credentials := &countingCredentialChecker{}
	gate := Gate{Roots: roots, AnchorWire: anchorWire, Expected: bootstrap.BootstrapAnchorExpectation{
		DeploymentID: anchored.DeploymentID, Environment: anchored.Environment, Cell: anchored.Cell},
		LoadedControllerConfigSHA256: manifest.ControllerConfigSHA256,
		Descriptor:                   fixedDescriptor{slot: "controller-b", instance: instanceID}, Instances: fakeInstanceObserver{observation},
		Ledgers: ledger, Binary: fixedBinaryChecker{}, Material: material, Credentials: credentials,
		ObserveIdentity: func(AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
			return prepared.Broker, prepared.Store, nil
		},
		InitialIdentity: func(bootstrap.Manifest) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
			return prepared.Broker, prepared.Store, nil
		},
		trustStore:          &trustStore,
		Markers:             MarkerStore{directory: markerDirectory, ownerUID: uint32(os.Getuid()), allowUnsafeAncestors: true},
		ClockCheck:          func() error { return nil },
		Now:                 func() time.Time { return now },
		InitialFounderFloor: func(context.Context, AcceptedInstall, time.Time) error { return nil },
		InitialPeerFloor: func(context.Context, AcceptedInstall, bootstrap.SlotState, time.Time) error {
			return nil
		},
	}
	return admissionFlowFixture{gate: gate, ledger: ledger, material: material, credentials: credentials, now: &now,
		rootPrivate: rootPrivate, ledgerPrivate: ledgerPrivate, bakedBinary: bakedBinary}
}

func admissionPreparedIdentity(t *testing.T, slot string) AcceptedIdentity {
	t.Helper()
	prepared := acceptedIdentityFixture(t)
	serverWire := []byte("gru-1-ctl-" + map[string]string{"controller-a": "1", "controller-b": "2", "controller-c": "3"}[slot] + "\n")
	nodeWire := []byte(`{"version":1,"cell":"gru","instance":"` + slot + `","node_id":"NODE0001"}`)
	for name, wire := range map[string][]byte{"server-name": serverWire, "node-identity.json": nodeWire} {
		if err := os.WriteFile(filepath.Join(prepared.Store.Directory, name), wire, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prepared.Store.ServerName, prepared.Store.RaftNodeID = strings.TrimSpace(string(serverWire)), "NODE0001"
	prepared.Store.ServerNameSHA256, prepared.Store.NodeIdentitySHA256 = digest(serverWire), digest(nodeWire)
	return prepared
}

func writeAdmissionLaunchInputs(t *testing.T, store bakedStore, manifest bootstrap.Manifest) {
	t.Helper()
	for name, wire := range map[string][]byte{HostEnrollmentFilename: hostEnrollmentFixture(t), OperatorSSHKeyFilename: []byte(testOperatorSSHKey),
		ManagedHostImageReceiptFilename: manifest.ReleaseImageReceiptWire, ManagedHostImageDelegationFilename: manifest.ReleaseDelegationWire} {
		writeBakedFixture(t, filepath.Join(store.directory, name), wire)
	}
}

func addTestControllerConfig(manifest *bootstrap.Manifest) {
	config := []byte(`{"nats":{},"controller":{}}`)
	manifest.ControllerConfig = config
	manifest.ControllerConfigSHA256 = digest(config)
	for _, name := range bootstrap.ControllerConfigFileNames {
		body := []byte(`{}`)
		if name == "oci-region.json" {
			body, _ = protocol.EncodeJSON(oci.RegionConfig{Region: manifest.Cell, ImageID: manifest.ImageOCID, Shape: "VM.Standard.E5.Flex"})
		}
		manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{
			Name: name, SHA256: digest(body), Bytes: body,
		})
	}
}

func TestAdmissionRejectsLoadedConfigBeforeMaterial(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	fixture.gate.LoadedControllerConfigSHA256 = digest([]byte("different loaded config"))
	if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmission) {
		t.Fatalf("mismatched loaded controller config reached admission: %v", err)
	}
	if fixture.material.initialCalls != 0 || fixture.credentials.calls != 0 {
		t.Fatal("mismatched loaded controller config reached material or credential effects")
	}
}

func testControllerConfigDigestFromManifestWire(t *testing.T, wire []byte) string {
	t.Helper()
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.ManifestPayload(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return manifest.ControllerConfigSHA256
}

func envelopeWire(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestGateInitialAndRestartThroughFakeAdapters(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	history, err := fixture.gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := fixture.gate.Markers.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeAcceptedIdentity(accepted)
	if err != nil || len(fixture.ledger.published) != 1 || !bytes.Equal(wire, fixture.ledger.published[0]) {
		t.Fatal("initial publication is not exact accepted v1 bytes")
	}
	if accepted.OperationID != entityid.Derive("accepted-install", history.ManifestSHA256, history.ReceiptSHA256) || accepted.InstanceOCID != history.InstanceOCID {
		t.Fatal("fresh identity lost verified operation/physical inputs")
	}
	formation, err := fixture.gate.Markers.ReadInitialFormation()
	if err != nil || !sameInitialFormation(formation, history) {
		t.Fatal("genuine initial formation was not separately preserved")
	}
	if _, err := DecodeAcceptedIdentity(fixture.ledger.published[0]); err != nil {
		t.Fatal("exported record is not solely accepted identity")
	}
	if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmission) {
		t.Fatal("second first install allowed")
	}
	// Corrupt the deleted ledger boundary; accepted restart cannot consult it.
	fixture.ledger.state = bootstrap.SlotState{}
	currentCalls := fixture.ledger.currentCalls
	restarted, err := fixture.gate.AdmitRestart(t.Context())
	if err != nil || restarted.OperationID != accepted.OperationID {
		t.Fatalf("accepted restart: %+v, %v", restarted, err)
	}
	if fixture.ledger.currentCalls != currentCalls || fixture.ledger.historyCalls != 0 || len(fixture.ledger.published) != 1 {
		t.Fatal("restart touched retired history")
	}
	if fixture.material.restartCalls != 1 || fixture.credentials.calls != 2 {
		t.Fatal("restart skipped material/credentials")
	}
}

func admissionTrustStore(t *testing.T, roots trust.Keyring) bakedStore {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "bootstrap")
	rootDir := filepath.Join(directory, "trust-roots")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{directory, rootDir} {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	index := 0
	for _, key := range roots {
		index++
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		writeBakedFixture(t, filepath.Join(rootDir, fmt.Sprintf("%03d.pem", index)), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	return bakedStore{directory: directory, chainFile: filepath.Join(directory, "root-chain.json"), ownerUID: uint32(os.Getuid()), ownerGID: uint32(os.Getgid()), allowUnsafeAncestors: true}
}

func TestGateClockFailureStopsAdmissionBeforeLedgerOrMaterial(t *testing.T) {
	for _, name := range []string{"missing", "unhealthy"} {
		t.Run(name, func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			if name == "missing" {
				fixture.gate.ClockCheck = nil
			} else {
				fixture.gate.ClockCheck = func() error { return errors.New("clock unsynchronized") }
			}
			if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmission) {
				t.Fatalf("initial gate with %s clock = %v", name, err)
			}
			if fixture.ledger.currentCalls != 0 || fixture.material.initialCalls != 0 || fixture.credentials.calls != 0 {
				t.Fatalf("clock failure reached adapters: ledger=%d material=%d credentials=%d",
					fixture.ledger.currentCalls, fixture.material.initialCalls, fixture.credentials.calls)
			}
			if _, err := fixture.gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("clock failure left an accepted marker: %v", err)
			}
		})
	}
}

func TestGateClockLossStopsMaterialAndMarkerEffects(t *testing.T) {
	for _, phase := range []string{"material", "credentials", "pre-marker"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			healthy := true
			checks := 0
			fixture.gate.ClockCheck = func() error {
				checks++
				if !healthy || phase == "pre-marker" && checks == 4 {
					return errors.New("clock lost synchronization")
				}
				return nil
			}
			if phase == "material" {
				fixture.material.onPrepare = func(verifyCurrent CurrentProofVerifier) error {
					healthy = false
					return verifyCurrent(time.Time{})
				}
			}
			if phase == "credentials" {
				fixture.credentials.onVerify = func() { healthy = false }
			}
			if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmission) {
				t.Fatalf("clock loss at %s = %v", phase, err)
			}
			if fixture.material.initialCalls != 1 || phase == "material" && fixture.credentials.calls != 0 {
				t.Fatalf("clock loss at %s reached later material/credential effect: material=%d credentials=%d",
					phase, fixture.material.initialCalls, fixture.credentials.calls)
			}
			if _, err := fixture.gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("clock loss at %s left a marker: %v", phase, err)
			}
		})
	}
}

func TestGateRechecksCurrentProofBetweenObservationAndEachMaterialEffect(t *testing.T) {
	for _, expireAfter := range []int{0, 1} {
		fixture := newAdmissionFlowFixture(t)
		checks := 0
		fixture.material.onPrepare = func(verifyCurrent CurrentProofVerifier) error {
			for range 2 {
				if checks == expireAfter {
					*fixture.now = fixture.now.Add(2 * time.Hour)
				}
				checks++
				if err := verifyCurrent(*fixture.now); err != nil {
					return err
				}
			}
			return nil
		}
		if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmission) {
			t.Fatalf("proof expired after %d material checks: %v", expireAfter, err)
		}
		if fixture.credentials.calls != 0 {
			t.Fatalf("expired proof reached live credential check after %d material checks", expireAfter)
		}
		if _, err := fixture.gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired proof left an accepted marker after %d material checks: %v", expireAfter, err)
		}
	}
}

func TestMaterialStoreStopsBeforeSecondSecretWhenCurrentProofExpires(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to install a credential owned by a distinct service UID")
	}
	fixture := newAdmissionFlowFixture(t)
	anchorEnvelope, err := proofEnvelope(fixture.gate.AnchorWire)
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.gate.clock()
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, fixture.gate.Roots, fixture.gate.Expected,
		now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	state := fixture.ledger.state
	observed, err := fixture.gate.observe(t.Context(), state.Result.InstanceOCID, state, anchor.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	manifest, receipt, _, err := fixture.gate.initialProofs(t.Context(), state, anchor, observed, now)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	installed, err := os.MkdirTemp("/dev/shm", "ts774-initial-material-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(installed) })
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	const serviceID = 23456
	if err := os.Chown(installed, serviceID, serviceID); err != nil {
		t.Fatal(err)
	}
	vault := &stagedSecretMaterializer{}
	store := MaterialStore{vault: vault, installedDirectory: installed, stagingDirectory: staging,
		serviceUID: serviceID, serviceGID: serviceID, allowUnsafeAncestors: true}
	checks := 0
	verifyCurrent := func(time.Time) error {
		checks++
		if checks == 3 {
			return ErrAdmission
		}
		return nil
	}
	materials := expectedMaterials(manifest.Manifest(), receipt.Slot())
	if err := store.PrepareInitial(t.Context(), manifest, receipt, materials, verifyCurrent); !errors.Is(err, ErrAdmission) {
		t.Fatalf("expired proof before second Vault read = %v", err)
	}
	if checks != 3 || vault.calls != 1 {
		t.Fatalf("secret read after authority expired: checks=%d reads=%d", checks, vault.calls)
	}
	if _, err := os.Stat(filepath.Join(installed, manifest.Manifest().Secrets[0].TargetFile)); err != nil {
		t.Fatalf("first exact secret was not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installed, manifest.Manifest().Secrets[1].TargetFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second secret installed after expiry: %v", err)
	}
}

// adoptedMaterialChecker returns the pins of an adopted generation and keeps
// the pins VerifyRestart is given.
type adoptedMaterialChecker struct {
	*countingMaterialChecker
	pins, verified MaterialPins
}

func (checker *adoptedMaterialChecker) RestartPins(AcceptedIdentity, trust.Keyring,
) (MaterialPins, error) {
	return checker.pins, nil
}

func (checker *adoptedMaterialChecker) VerifyRestart(ctx context.Context, accepted AcceptedIdentity,
	pins MaterialPins,
) error {
	checker.verified = pins
	return checker.countingMaterialChecker.VerifyRestart(ctx, accepted, pins)
}

// Full and local restart admission accept the controller config an adopted
// generation pins for the slot, bound to the accepted installation.
func TestRestartAdmissionFollowsTheGenerationsControllerConfig(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	_, err := fixture.gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := fixture.gate.Markers.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	acceptance, err := accepted.AcceptanceSHA256()
	if err != nil {
		t.Fatal(err)
	}
	manifestWire := fixture.ledger.state.ManifestRecord.Bytes
	envelope, err := trust.DecodeEnvelope(manifestWire)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.ManifestPayload(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"nats":{"cell":"gru"},"controller":{"candidate_id":"controller-b"}}`)
	adopted := func(acceptanceSHA256 string) *adoptedMaterialChecker {
		expected := bootstrap.MaterialGenerationExpectation{DeploymentID: manifest.DeploymentID,
			Environment: manifest.Environment, ClusterID: manifest.ClusterID, Cell: manifest.Cell,
			ControllerSlots: manifest.ControllerSlots}
		material := generationtest.New(t, time.Now()).WithoutIssuers(t).
			With(map[string][]byte{"controller-controller-a.json": config, "controller-controller-b.json": config, "controller-controller-c.json": config})
		generation := material.Generation(expected, 1, "")
		for i := range generation.ControllerConfigs {
			generation.ControllerConfigs[i].AcceptanceSHA256 = acceptanceSHA256
		}
		signed, err := bootstrap.SignMaterialGeneration(generation, time.Now().Add(-time.Minute), time.Now().Add(time.Hour),
			fixture.rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := bootstrap.VerifyAdoptedMaterialGenerationChain([]trust.Envelope{signed}, fixture.gate.Roots, expected)
		if err != nil {
			t.Fatal(err)
		}
		pins, err := fixture.material.RestartPins(accepted, fixture.gate.Roots)
		if err != nil {
			t.Fatal(err)
		}
		pins.Generation = &verified[0]
		return &adoptedMaterialChecker{countingMaterialChecker: fixture.material, pins: pins}
	}
	restart := func(material MaterialChecker, loaded []byte) (full, local error) {
		gate := fixture.gate
		gate.Material = material
		gate.LoadedControllerConfigSHA256, gate.LoadedControllerConfig = digest(loaded), loaded
		_, full = gate.AdmitRestart(t.Context())
		_, local = gate.AdmitRestartLocal(t.Context())
		return full, local
	}
	bound := adopted(acceptance)
	if full, local := restart(bound, config); full != nil || local != nil {
		t.Fatalf("the generation's config: full %v, local %v", full, local)
	}
	if !bytes.Equal(bound.verified.config, config) {
		t.Fatal("the loaded config did not reach the generation check")
	}
	for name, test := range map[string]struct {
		material MaterialChecker
		loaded   []byte
	}{
		"the manifest's old config":            {bound, manifest.ControllerConfig},
		"a config matching neither":            {bound, []byte(`{"nats":{},"controller":{"0000000000V4MRM46HP1SNGDYW":true}}`)},
		"a config bound to another acceptance": {adopted(digest([]byte("another acceptance"))), config},
		"a new config without a generation":    {fixture.material, config},
	} {
		if full, local := restart(test.material, test.loaded); !errors.Is(full, ErrAdmission) ||
			!errors.Is(local, ErrAdmission) {
			t.Errorf("%s: full %v, local %v", name, full, local)
		}
	}
}

func TestInitialAdmissionRejectsChangedReceiptHashBeforeEffects(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	fixture.ledger.state.SeedReceiptRecord.SHA256 = digest([]byte("another receipt"))
	if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmission) {
		t.Fatalf("foreign receipt wire hash admitted: %v", err)
	}
	if fixture.material.initialCalls != 0 || fixture.credentials.calls != 0 {
		t.Fatal("receipt hash mismatch reached effects")
	}
}

func TestInitialAdmissionRechecksJournalAndProofBeforeIdentityPreparation(t *testing.T) {
	for _, phase := range []string{"journal during material", "proof during identity preparation"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			initialIdentity := fixture.gate.InitialIdentity
			preparations := 0
			fixture.gate.InitialIdentity = func(manifest bootstrap.Manifest) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
				preparations++
				broker, store, err := initialIdentity(manifest)
				if phase == "proof during identity preparation" {
					*fixture.now = fixture.now.Add(2 * time.Hour)
				}
				return broker, store, err
			}
			if phase == "journal during material" {
				fixture.material.onPrepare = func(check CurrentProofVerifier) error {
					if err := os.WriteFile(filepath.Join(fixture.gate.Markers.directory, identityRekeyJournalName), []byte(`{}`), 0o644); err != nil {
						t.Fatal(err)
					}
					return check(time.Time{})
				}
			}
			if _, err := fixture.gate.AdmitInitial(t.Context()); err == nil {
				t.Fatal("changed initial authority published an installation")
			}
			if phase == "journal during material" && preparations != 0 {
				t.Fatal("rekey journal reached fresh store preparation")
			}
			if _, err := fixture.gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed initial authority left accepted bytes: %v", err)
			}
		})
	}
}

func TestInitialAdmissionRecoversOnlyExactCurrentFormationAfterPublicationCrash(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	observe := fixture.gate.ObserveIdentity
	fixture.gate.ObserveIdentity = func(AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, ErrAcceptedIdentity
	}
	if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAcceptedIdentity) {
		t.Fatalf("publication interruption: %v", err)
	}
	formation, err := fixture.gate.Markers.ReadInitialFormation()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(fixture.gate.Markers.directory, initialFormationName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interruption published accepted bytes: %v", err)
	}
	fixture.gate.ObserveIdentity = observe
	*fixture.now = fixture.now.Add(time.Minute)
	recovered, err := fixture.gate.AdmitInitial(t.Context())
	if err != nil || !sameInitialFormation(formation, recovered) {
		t.Fatalf("exact current recovery: %+v, %v", recovered, err)
	}
	after, err := os.ReadFile(filepath.Join(fixture.gate.Markers.directory, initialFormationName))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("recovery replaced genuine formation history")
	}
	accepted, err := fixture.gate.Markers.ReadIdentity()
	if err != nil || !accepted.AcceptedAt.Equal(*fixture.now) || accepted.OperationID != entityid.Derive("accepted-install", recovered.ManifestSHA256, recovered.ReceiptSHA256) {
		t.Fatalf("recovery did not construct accepted bytes from current proofs: %+v, %v", accepted, err)
	}
}

func TestInitialAdmissionRecoveryRefusesDifferentOrExpiredCurrentProofsBeforeEffects(t *testing.T) {
	for _, name := range []string{"different receipt", "expired current proof"} {
		t.Run(name, func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			fixture.gate.ObserveIdentity = func(AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
				return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, ErrAcceptedIdentity
			}
			if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAcceptedIdentity) {
				t.Fatal(err)
			}
			formation, err := fixture.gate.Markers.ReadInitialFormation()
			if err != nil {
				t.Fatal(err)
			}
			if name == "different receipt" {
				formation.ReceiptSHA256 = digest([]byte("another root receipt"))
				wire, err := protocol.EncodeJSON(formation)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fixture.gate.Markers.directory, initialFormationName), wire, 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				*fixture.now = fixture.now.Add(2 * time.Hour)
			}
			calls, credentials := fixture.material.initialCalls, fixture.credentials.calls
			if _, err := fixture.gate.AdmitInitial(t.Context()); err == nil {
				t.Fatal("formation history replaced current proof")
			}
			if fixture.material.initialCalls != calls || fixture.credentials.calls != credentials {
				t.Fatal("invalid recovery reached material or credentials")
			}
			if _, err := fixture.gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid recovery published accepted installation: %v", err)
			}
		})
	}
}

func TestInitialAcceptedExportRetriesExactBytesBeforeRuntimeAcceptance(t *testing.T) {
	for _, interruption := range []string{"export failure", "lost export reply", "crash after export"} {
		t.Run(interruption, func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			interrupted := errors.New("publication interrupted")
			observe := fixture.gate.ObserveIdentity
			exported := false
			fixture.gate.ObserveIdentity = func(record AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
				if exported {
					return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, interrupted
				}
				return observe(record)
			}
			fixture.ledger.onPublish = func([]byte) error {
				if _, err := fixture.gate.Markers.ReadIdentity(); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("runtime acceptance preceded export")
				}
				if interruption == "crash after export" {
					exported = true
					return nil
				}
				return interrupted
			}
			_, err := fixture.gate.AdmitInitial(t.Context())
			if err == nil || interruption != "crash after export" && !errors.Is(err, interrupted) {
				t.Fatalf("interruption = %v", err)
			}
			pending, err := fixture.gate.Markers.readInitialExport()
			if err != nil {
				t.Fatal(err)
			}
			pendingWire, err := EncodeAcceptedIdentity(pending)
			if err != nil || !bytes.Equal(pendingWire, fixture.ledger.published[0]) {
				t.Fatal("export did not use durable exact pending bytes")
			}
			fixture.gate.ObserveIdentity = observe
			fixture.ledger.onPublish = nil
			*fixture.now = fixture.now.Add(time.Minute)
			if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
				t.Fatal(err)
			}
			accepted, err := fixture.gate.Markers.ReadIdentity()
			if err != nil || !accepted.AcceptedAt.Equal(pending.AcceptedAt) {
				t.Fatalf("retry changed acceptance: %v", err)
			}
			wire, err := EncodeAcceptedIdentity(accepted)
			if err != nil || len(fixture.ledger.published) != 2 || !bytes.Equal(wire, pendingWire) || !bytes.Equal(wire, fixture.ledger.published[1]) {
				t.Fatal("retry changed exported bytes")
			}
			if _, err := fixture.gate.Markers.readInitialExport(); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("completed pending export remains: %v", err)
			}
		})
	}
}

func TestInitialAcceptedExportRecoversAfterCredentialMemoryLoss(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	fixture.ledger.onPublish = func([]byte) error { return errors.New("export interrupted") }
	if _, err := fixture.gate.AdmitInitial(t.Context()); err == nil {
		t.Fatal("export interruption accepted")
	}
	pending, err := fixture.gate.Markers.readInitialExport()
	if err != nil {
		t.Fatal(err)
	}
	ready := false
	observe := fixture.gate.ObserveIdentity
	fixture.gate.ObserveIdentity = func(record AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		if !ready {
			return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, os.ErrNotExist
		}
		return observe(record)
	}
	fixture.material.onPrepare = func(verify CurrentProofVerifier) error {
		if err := verify(time.Time{}); err != nil {
			return err
		}
		ready = true
		return nil
	}
	fixture.ledger.onPublish = nil
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
		t.Fatalf("empty credential memory blocked pending acceptance: %v", err)
	}
	accepted, err := fixture.gate.Markers.ReadIdentity()
	if err != nil || !accepted.AcceptedAt.Equal(pending.AcceptedAt) {
		t.Fatalf("recovery changed acceptance: %v", err)
	}
}

func TestInitialAcceptedExportRejectsForeignMalformedOrExpiredRecoveryBeforeEffects(t *testing.T) {
	for _, fault := range []string{"foreign", "malformed", "future acceptance", "expired proofs"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			fixture.ledger.onPublish = func([]byte) error { return errors.New("unavailable") }
			if _, err := fixture.gate.AdmitInitial(t.Context()); err == nil {
				t.Fatal("export failure accepted")
			}
			pending, err := fixture.gate.Markers.readInitialExport()
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "foreign":
				pending.OperationID = entityid.Derive("foreign export", "another installation")
			case "future acceptance":
				pending.AcceptedAt = pending.AcceptedAt.Add(time.Minute)
			case "expired proofs":
				*fixture.now = fixture.now.Add(2 * time.Hour)
			}
			wire, err := EncodeAcceptedIdentity(pending)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "malformed" {
				wire = []byte(`{}`)
			}
			if err := os.WriteFile(filepath.Join(fixture.gate.Markers.directory, initialExportName), wire, 0o644); err != nil {
				t.Fatal(err)
			}
			material, credentials, publications := fixture.material.initialCalls, fixture.credentials.calls, len(fixture.ledger.published)
			if _, err := fixture.gate.AdmitInitial(t.Context()); err == nil {
				t.Fatal("invalid pending export recovered")
			}
			if material != fixture.material.initialCalls || credentials != fixture.credentials.calls || publications != len(fixture.ledger.published) {
				t.Fatal("invalid recovery reached effects")
			}
		})
	}
}
