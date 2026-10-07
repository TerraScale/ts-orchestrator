package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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
}

func (opener *countingLedgerOpener) ReadSlot(context.Context, bootstrap.BootstrapScope) (bootstrap.SlotState, error) {
	return opener.state, nil
}

func (opener *countingLedgerOpener) PublishAcceptedInstall(_ context.Context, _ bootstrap.BootstrapScope,
	marker []byte,
) error {
	opener.published = append(opener.published, marker)
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

func (fixedBinaryChecker) VerifyCurrent(release.VerifiedImage) (RunningBinary, error) {
	return RunningBinary{SHA256: strings.Repeat("c", 64)}, nil
}

func (fixedBinaryChecker) VerifyHistorical(release.HistoricalImage) (RunningBinary, error) {
	return RunningBinary{SHA256: strings.Repeat("c", 64)}, nil
}

func (fixedBinaryChecker) VerifySelfUpdated(selfupdate.Layout, trust.Keyring, release.UpdateExpectation,
) (RunningBinary, error) {
	return RunningBinary{}, ErrRunningBinaryMismatch
}

type countingMaterialChecker struct {
	initialCalls, restartCalls int
	onPrepare                  func(CurrentProofVerifier) error
}

func (checker *countingMaterialChecker) PrepareInitial(_ context.Context, _ bootstrap.VerifiedManifest,
	_ bootstrap.VerifiedReceipt, _ map[string]string, verifyCurrent CurrentProofVerifier,
) error {
	checker.initialCalls++
	if checker.onPrepare != nil {
		return checker.onPrepare(verifyCurrent)
	}
	return nil
}

func (checker *countingMaterialChecker) RestartPins(manifest bootstrap.HistoricalManifest, _ trust.Keyring, _ string,
) (MaterialPins, error) {
	return ManifestPins(expectedMaterials(manifest.Manifest(), manifest.Manifest().Slot)), nil
}

func (checker *countingMaterialChecker) VerifyRestart(context.Context, bootstrap.HistoricalManifest,
	MaterialPins,
) error {
	checker.restartCalls++
	return nil
}

type countingCredentialChecker struct {
	calls    int
	err      error
	onVerify func()
}

type stagedSecretMaterializer struct {
	calls int
}

func (materializer *stagedSecretMaterializer) MaterializeCurrent(_ context.Context, _ bootstrap.VerifiedManifest,
	_ bootstrap.VerifiedReceipt, reference bootstrap.SecretReference, directory string, _ func(time.Time) error,
) error {
	materializer.calls++
	content := []byte("credential fixture")
	if reference.TargetFile == "regional.creds" {
		content = []byte("regional fixture")
	}
	return os.WriteFile(filepath.Join(directory, reference.TargetFile), content, 0o600)
}

func (checker *countingCredentialChecker) VerifyLiveCredentials(_ context.Context, expected MaterialPins,
	_ bootstrap.Manifest,
) error {
	checker.calls++
	if checker.onVerify != nil {
		checker.onVerify()
	}
	if expected.Digests["controller.creds"] == "" {
		return ErrLiveCredentials
	}
	return checker.err
}

type countingContinuationChecker struct{ calls int }

func (checker *countingContinuationChecker) VerifyCurrentContinuation(context.Context, AcceptedInstall,
	InstanceObservation, bootstrap.SlotState,
) error {
	checker.calls++
	return nil
}

type admissionFlowFixture struct {
	gate        Gate
	ledger      *countingLedgerOpener
	material    *countingMaterialChecker
	credentials *countingCredentialChecker
	now         *time.Time
	rootPrivate ed25519.PrivateKey
	// bakedBinary is the executable the signed image receipt names.
	bakedBinary string
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
	if peer {
		anchored := anchor.Anchor()
		anchored.ControllerSlots = []string{"controller-b", "seed-a"}
		ledgerPublic, _, err := ed25519.GenerateKey(rand.Reader)
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
		NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.nsg-a"}}
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
			Domain: release.ImageDomain, DeploymentID: revision, Cell: "GRU", Environment: "production",
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
		ControllerRole: "controller", Slot: "controller-b", SeedSlot: "controller-b", ControllerSlots: []string{"controller-b"},
		Profiles: []bootstrap.LaunchProfile{profile}, ImageOCID: imageID, ImageArchitecture: "linux-amd64",
		ReleaseReceiptSHA256: digest(imageWire), ReleaseImageReceiptWire: imageWire,
		ReleaseDelegationWire: releaseGrantWire, StorageDomain: anchored.StorageDomain,
		Secrets: []bootstrap.SecretReference{{Purpose: bootstrap.SecretController, Slot: "controller-b",
			SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.controller", VersionNumber: 1,
			SHA256: digest([]byte("credential fixture")), MaxBytes: 128, TargetFile: "controller.creds"},
			{Purpose: bootstrap.SecretRegionalShared,
				SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.regional", VersionNumber: 1,
				SHA256: digest([]byte("regional fixture")), MaxBytes: 128, TargetFile: "regional.creds"}}}
	var peerPrivate ed25519.PrivateKey
	if peer {
		manifest.SeedSlot = "seed-a"
		manifest.ControllerSlots = []string{"controller-b", "seed-a"}
		seedProfile := profile
		seedProfile.Slot = "seed-a"
		manifest.Profiles = append(manifest.Profiles, seedProfile)
		peerPublic, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		peerPrivate = private
		delegationWire := signTestDelegation(t, rootPrivate, peerPublic,
			[]string{"terrascale.bootstrap.peer-receipt"}, []string{"controller-b"},
			now.Add(-10*time.Minute), now.Add(2*time.Hour))
		delegation, err := trust.DecodeEnvelope(delegationWire)
		if err != nil {
			t.Fatal(err)
		}
		manifest.PeerReceiptDelegation = &delegation
	}
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
			CompartmentOCID: compartmentID, CreateKey: "create-a", OCIRegion: anchored.OCIRegion,
			AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain,
			SubnetOCID: profile.SubnetOCID, Shape: profile.Shape,
			NetworkSecurityGroupIDs: profile.NetworkSecurityGroupOCIDs},
		IntentRecord:   bootstrap.StoredRecord{SHA256: strings.Repeat("f", 64)},
		ManifestRecord: &bootstrap.StoredRecord{Bytes: manifestWire, SHA256: verifiedManifest.Digest()},
		Result: &bootstrap.Result{InstanceOCID: instanceID, ImageOCID: imageID,
			CompartmentOCID: compartmentID, CreateKey: "create-a", Shape: profile.Shape},
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
	ledger := &countingLedgerOpener{state: state}
	material := &countingMaterialChecker{}
	credentials := &countingCredentialChecker{}
	gate := Gate{Roots: roots, AnchorWire: anchorWire, Expected: bootstrap.BootstrapAnchorExpectation{
		DeploymentID: anchored.DeploymentID, Environment: anchored.Environment, Cell: anchored.Cell},
		LoadedControllerConfigSHA256: manifest.ControllerConfigSHA256,
		Descriptor:                   fixedDescriptor{slot: "controller-b", instance: instanceID}, Instances: fakeInstanceObserver{observation},
		Ledgers: ledger, Binary: fixedBinaryChecker{}, Material: material, Credentials: credentials,
		Markers:             MarkerStore{directory: markerDirectory, ownerUID: uint32(os.Getuid()), allowUnsafeAncestors: true},
		ClockCheck:          func() error { return nil },
		Now:                 func() time.Time { return now },
		InitialFounderFloor: func(context.Context, AcceptedInstall, time.Time) error { return nil },
		InitialPeerFloor: func(context.Context, AcceptedInstall, bootstrap.SlotState, time.Time) error {
			return nil
		},
	}
	return admissionFlowFixture{gate: gate, ledger: ledger, material: material, credentials: credentials, now: &now,
		rootPrivate: rootPrivate, bakedBinary: bakedBinary}
}

func addTestControllerConfig(manifest *bootstrap.Manifest) {
	config := []byte(`{"nats":{},"controller":{}}`)
	manifest.ControllerConfig = config
	manifest.ControllerConfigSHA256 = digest(config)
	for _, name := range bootstrap.ControllerConfigFileNames {
		body := []byte(`{}`)
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
	marker, err := fixture.gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatalf("initial admission: %v", err)
	}
	if marker.Slot != "controller-b" || fixture.ledger.currentCalls != 1 || fixture.ledger.historyCalls != 0 ||
		fixture.material.initialCalls != 1 || fixture.credentials.calls != 1 {
		t.Fatalf("initial gate did not reach exact adapters: marker=%+v ledger=%+v material=%+v credentials=%+v",
			marker, fixture.ledger, fixture.material, fixture.credentials)
	}
	wire, err := protocol.EncodeJSON(marker)
	if err != nil || len(fixture.ledger.published) != 1 || !bytes.Equal(fixture.ledger.published[0], wire) {
		t.Fatalf("initial admission did not publish its exact marker: %d published, %v", len(fixture.ledger.published), err)
	}
	if _, err := fixture.gate.AdmitInitial(t.Context()); !errors.Is(err, ErrAdmission) {
		t.Fatalf("accepted marker did not fence second install: %v", err)
	}
	restarted, err := fixture.gate.AdmitRestart(t.Context())
	if err != nil || restarted.AnchorSHA256 != marker.AnchorSHA256 || fixture.ledger.historyCalls != 1 ||
		fixture.material.restartCalls != 1 || fixture.credentials.calls != 2 {
		t.Fatalf("restart gate = %+v, %v; ledger=%+v material=%+v credentials=%+v",
			restarted, err, fixture.ledger, fixture.material, fixture.credentials)
	}
	if len(fixture.ledger.published) != 2 || !bytes.Equal(fixture.ledger.published[1], wire) {
		t.Fatal("restart admission did not republish its exact marker")
	}
	fixture.ledger.state.Head.Generation++
	if _, err := fixture.gate.AdmitRestart(t.Context()); !errors.Is(err, ErrAdmission) {
		t.Fatalf("changed signed slot HEAD accepted on restart: %v", err)
	}
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
			if _, err := fixture.gate.Markers.Read(); !errors.Is(err, os.ErrNotExist) {
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
			if _, err := fixture.gate.Markers.Read(); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("clock loss at %s left a marker: %v", phase, err)
			}
		})
	}
}

func TestGateClockLossStopsRestartContinuationAndReturn(t *testing.T) {
	for _, phase := range []string{"entry", "before-continuation", "after-continuation", "return"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newAdmissionFlowFixture(t)
			if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
				t.Fatal(err)
			}
			continuation := new(countingContinuationChecker)
			fixture.gate.Continuation = continuation
			if phase == "before-continuation" || phase == "after-continuation" {
				*fixture.now = fixture.now.Add(2 * time.Hour)
			}
			checks := 0
			fixture.gate.ClockCheck = func() error {
				checks++
				if phase == "entry" || phase == "before-continuation" && checks == 3 ||
					phase == "after-continuation" && checks == 4 || phase == "return" && checks == 3 {
					return errors.New("clock lost synchronization")
				}
				return nil
			}
			if _, err := fixture.gate.AdmitRestart(t.Context()); !errors.Is(err, ErrAdmission) {
				t.Fatalf("restart with clock lost at %s = %v", phase, err)
			}
			if phase == "before-continuation" && continuation.calls != 0 ||
				phase == "after-continuation" && continuation.calls != 1 {
				t.Fatalf("restart continuation calls after %s clock loss = %d", phase, continuation.calls)
			}
		})
	}
}

func TestGateRejectsFailedLiveCredentialsBeforeMarkerAndExpiredRestart(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	fixture.credentials.err = errors.New("invalid service credential")
	if _, err := fixture.gate.AdmitInitial(t.Context()); err == nil {
		t.Fatal("invalid live credentials accepted")
	}
	if _, err := fixture.gate.Markers.Read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed credentials left an accepted marker: %v", err)
	}
	fixture.credentials.err = nil
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
		t.Fatal(err)
	}
	*fixture.now = fixture.now.Add(2 * time.Hour)
	if _, err := fixture.gate.AdmitRestart(t.Context()); !errors.Is(err, ErrAdmission) {
		t.Fatalf("historical install without current continuation accepted: %v", err)
	}
}

func TestGateMarkedSeedRestartUsesCurrentContinuationAfterOriginalExpiry(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	marker, err := fixture.gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if marker.Slot != marker.SeedSlot {
		t.Fatalf("fixture did not install seed: %+v", marker)
	}
	continuation := new(countingContinuationChecker)
	fixture.gate.Continuation = continuation
	*fixture.now = fixture.now.Add(2 * time.Hour)
	if _, err := fixture.gate.AdmitRestart(t.Context()); err != nil {
		t.Fatalf("marked seed with current continuation: %v", err)
	}
	if continuation.calls != 1 || fixture.material.restartCalls != 1 || fixture.credentials.calls != 2 {
		t.Fatalf("seed restart skipped current or installed-state checks: continuation=%d material=%d credentials=%d",
			continuation.calls, fixture.material.restartCalls, fixture.credentials.calls)
	}
}

func TestGateMarkedSeedRechecksOriginalProofAfterSlowRestart(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
		t.Fatal(err)
	}
	continuation := new(countingContinuationChecker)
	fixture.gate.Continuation = continuation
	base := *fixture.now
	reads := 0
	fixture.gate.Now = func() time.Time {
		reads++
		if reads >= 3 {
			return base.Add(2 * time.Hour)
		}
		return base
	}
	if _, err := fixture.gate.AdmitRestart(t.Context()); err != nil {
		t.Fatalf("current proof expired during restart but continuation was valid: %v", err)
	}
	if continuation.calls != 1 {
		t.Fatalf("final proof recheck did not consult continuation: %d calls", continuation.calls)
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
		if _, err := fixture.gate.Markers.Read(); !errors.Is(err, os.ErrNotExist) {
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
	manifest, receipt, _, err := fixture.gate.initialProofs(state, anchor, observed, now)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	installed := filepath.Join(root, "installed")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(installed, 0o700); err != nil {
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
	if _, err := os.Stat(filepath.Join(installed, "controller.creds")); err != nil {
		t.Fatalf("first exact secret was not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installed, "regional.creds")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second secret installed after expiry: %v", err)
	}
}

// adoptedMaterialChecker returns the pins of an adopted generation and keeps
// the pins VerifyRestart is given.
type adoptedMaterialChecker struct {
	*countingMaterialChecker
	pins, verified MaterialPins
}

func (checker *adoptedMaterialChecker) RestartPins(bootstrap.HistoricalManifest, trust.Keyring, string,
) (MaterialPins, error) {
	return checker.pins, nil
}

func (checker *adoptedMaterialChecker) VerifyRestart(ctx context.Context, manifest bootstrap.HistoricalManifest,
	pins MaterialPins,
) error {
	checker.verified = pins
	return checker.countingMaterialChecker.VerifyRestart(ctx, manifest, pins)
}

// Full and local restart admission accept the controller config an adopted
// schema-2 generation pins for the slot, bound to the accepted manifest, and
// the current proofs still hold, so no continuation is needed (TS-668).
func TestRestartAdmissionFollowsTheGenerationsControllerConfig(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	marker, err := fixture.gate.AdmitInitial(t.Context())
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
	adopted := func(manifestSHA256 string) *adoptedMaterialChecker {
		expected := bootstrap.MaterialGenerationExpectation{DeploymentID: manifest.DeploymentID,
			Environment: manifest.Environment, ClusterID: manifest.ClusterID, Cell: manifest.Cell,
			ControllerSlots: manifest.ControllerSlots}
		material := generationtest.New(t, time.Now()).SchemaTwo(t).WithoutIssuers(t).
			With(map[string][]byte{"controller-controller-b.json": config})
		generation := material.Generation(expected, 1, "")
		generation.ControllerConfigs[0].ManifestSHA256 = manifestSHA256
		signed, err := bootstrap.SignMaterialGeneration(generation, time.Now().Add(-time.Minute), time.Now().Add(time.Hour),
			fixture.rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := bootstrap.VerifyAdoptedMaterialGenerationChain([]trust.Envelope{signed}, fixture.gate.Roots, expected)
		if err != nil {
			t.Fatal(err)
		}
		return &adoptedMaterialChecker{countingMaterialChecker: fixture.material, pins: MaterialPins{
			Digests: expectedMaterials(manifest, manifest.Slot), Generation: &verified[0], slot: manifest.Slot}}
	}
	restart := func(material MaterialChecker, loaded []byte) (full, local error) {
		gate := fixture.gate
		gate.Material, gate.Continuation = material, nil
		gate.LoadedControllerConfigSHA256, gate.LoadedControllerConfig = digest(loaded), loaded
		_, full = gate.AdmitRestart(t.Context())
		_, local = gate.AdmitRestartLocal(t.Context(), manifestWire)
		return full, local
	}
	bound := adopted(marker.ManifestSHA256)
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
		"the manifest's old config":          {bound, manifest.ControllerConfig},
		"a config matching neither":          {bound, []byte(`{"nats":{},"controller":{"other":true}}`)},
		"a config bound to another manifest": {adopted(digest([]byte("another manifest"))), config},
		"a new config without a generation":  {fixture.material, config},
	} {
		if full, local := restart(test.material, test.loaded); !errors.Is(full, ErrAdmission) ||
			!errors.Is(local, ErrAdmission) {
			t.Errorf("%s: full %v, local %v", name, full, local)
		}
	}
}
