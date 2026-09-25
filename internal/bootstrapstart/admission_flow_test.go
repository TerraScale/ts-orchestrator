package bootstrapstart

import (
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
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
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

type fixedSlotReader struct{ state bootstrap.SlotState }

func (reader fixedSlotReader) ReadSlot(context.Context, bootstrap.BootstrapScope) (bootstrap.SlotState, error) {
	return reader.state, nil
}

type countingLedgerOpener struct {
	state                      bootstrap.SlotState
	currentCalls, historyCalls int
}

func (opener *countingLedgerOpener) OpenCurrentLedger(_ context.Context, anchor bootstrap.VerifiedBootstrapAnchor,
	_ trust.Keyring,
) (SlotReader, error) {
	if !anchor.IsVerified() {
		return nil, ErrLedgerGrant
	}
	opener.currentCalls++
	return fixedSlotReader{opener.state}, nil
}

func (opener *countingLedgerOpener) OpenHistoricalLedger(_ context.Context, anchor bootstrap.HistoricalBootstrapAnchor,
	_ trust.Keyring,
) (SlotReader, error) {
	if !anchor.IsVerified() {
		return nil, ErrLedgerGrant
	}
	opener.historyCalls++
	return fixedSlotReader{opener.state}, nil
}

type fixedBinaryChecker struct{}

func (fixedBinaryChecker) VerifyCurrent(release.VerifiedImage) (RunningBinary, error) {
	return RunningBinary{SHA256: strings.Repeat("c", 64)}, nil
}

func (fixedBinaryChecker) VerifyHistorical(release.HistoricalImage) (RunningBinary, error) {
	return RunningBinary{SHA256: strings.Repeat("c", 64)}, nil
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

func (checker *countingMaterialChecker) VerifyRestart(context.Context, bootstrap.HistoricalManifest,
	map[string]string,
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

func (checker *countingCredentialChecker) VerifyLiveCredentials(_ context.Context, expected map[string]string) error {
	checker.calls++
	if checker.onVerify != nil {
		checker.onVerify()
	}
	if expected["controller.creds"] == "" {
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
}

func newAdmissionFlowFixture(t *testing.T) admissionFlowFixture {
	t.Helper()
	anchor, _, roots, rootPrivate, anchorWire := verifiedAnchorFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	imageID := "ocid1.image.oc1.sa-saopaulo-1.image-a"
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.example"
	compartmentID := "ocid1.compartment.oc1..example"
	profile := bootstrap.LaunchProfile{Slot: "broker-a", CompartmentOCID: compartmentID,
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
	releaseGrant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: releaseID, SubjectPublicKey: releasePublicWire, Capabilities: []trust.Capability{{
			Domain: release.ImageDomain, DeploymentID: revision, Cell: "GRU", Environment: "production",
			Role: "oci-image", Slots: []string{imageID}, Actions: []string{"sign"},
		}}}, now.Add(-10*time.Minute), now.Add(2*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	imageReceipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: revision,
		GoVersion: release.DefaultGoVersion, Architecture: "amd64", BinaryBytes: 13, BinarySHA256: strings.Repeat("a", 64),
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
		ControllerRole: "controller", Slot: "broker-a", SeedSlot: "broker-a", ControllerSlots: []string{"broker-a"},
		Profiles: []bootstrap.LaunchProfile{profile}, ImageOCID: imageID, ImageArchitecture: "linux-amd64",
		ReleaseReceiptSHA256: digest(imageWire), ReleaseImageReceiptWire: imageWire,
		ReleaseDelegationWire: releaseGrantWire, StorageDomain: anchored.StorageDomain,
		Secrets: []bootstrap.SecretReference{{Purpose: bootstrap.SecretController, Slot: "broker-a",
			SecretOCID: "ocid1.secret.oc1.sa-saopaulo-1.controller", VersionNumber: 1,
			SHA256: digest([]byte("credential fixture")), MaxBytes: 128, TargetFile: "controller.creds"},
			{Purpose: bootstrap.SecretRegionalShared,
				SecretOCID: "ocid1.secret.oc1.sa-saopaulo-1.regional", VersionNumber: 1,
				SHA256: digest([]byte("regional fixture")), MaxBytes: 128, TargetFile: "regional.creds"}}}
	manifestEnvelope, err := bootstrap.SignManifest(manifest, now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	manifestWire := envelopeWire(t, manifestEnvelope)
	manifestExpected, err := anchor.ManifestExpectation("broker-a", imageID)
	if err != nil {
		t.Fatal(err)
	}
	verifiedManifest, err := bootstrap.VerifyManifest(manifestEnvelope, roots, manifestExpected, now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	state := bootstrap.SlotState{
		Head: bootstrap.SlotHead{Attempt: 1, Generation: 1, ResultDigest: strings.Repeat("e", 64)},
		Intent: bootstrap.Intent{DeploymentID: anchored.DeploymentID, Environment: anchored.Environment,
			Cell: string(anchored.Cell), Role: "controller", Slot: "broker-a", ImageOCID: imageID,
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
	observation := InstanceObservation{InstanceOCID: instanceID, CompartmentOCID: compartmentID, ImageOCID: imageID,
		AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain,
		Shape: profile.Shape, SubnetOCID: profile.SubnetOCID, NSGOCIDs: profile.NetworkSecurityGroupOCIDs,
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.vnic-a", PrimaryPrivateIP: "10.0.0.3",
		PrimaryVNIC: true, LifecycleState: "RUNNING"}
	observed, err := (Gate{Instances: fakeInstanceObserver{observation}}).observe(t.Context(), instanceID, state, anchored)
	if err != nil {
		t.Fatal(err)
	}
	receiptEnvelope, err := bootstrap.SignSeedReceipt(verifiedManifest, observed.Facts,
		now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	receiptWire := envelopeWire(t, receiptEnvelope)
	state.SeedReceiptRecord = &bootstrap.StoredRecord{Bytes: receiptWire, SHA256: digest(receiptWire)}
	markerDirectory := filepath.Join(t.TempDir(), "marker")
	if err := os.Mkdir(markerDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	ledger := &countingLedgerOpener{state: state}
	material := &countingMaterialChecker{}
	credentials := &countingCredentialChecker{}
	gate := Gate{Roots: roots, AnchorWire: anchorWire, Expected: bootstrap.BootstrapAnchorExpectation{
		DeploymentID: anchored.DeploymentID, Environment: anchored.Environment, Cell: anchored.Cell},
		Descriptor: fixedDescriptor{slot: "broker-a", instance: instanceID}, Instances: fakeInstanceObserver{observation},
		Ledgers: ledger, Binary: fixedBinaryChecker{}, Material: material, Credentials: credentials,
		Markers:    MarkerStore{directory: markerDirectory, ownerUID: uint32(os.Getuid()), allowUnsafeAncestors: true},
		ClockCheck: func() error { return nil },
		Now:        func() time.Time { return now },
	}
	return admissionFlowFixture{gate: gate, ledger: ledger, material: material, credentials: credentials, now: &now}
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
	if marker.Slot != "broker-a" || fixture.ledger.currentCalls != 1 || fixture.ledger.historyCalls != 0 ||
		fixture.material.initialCalls != 1 || fixture.credentials.calls != 1 {
		t.Fatalf("initial gate did not reach exact adapters: marker=%+v ledger=%+v material=%+v credentials=%+v",
			marker, fixture.ledger, fixture.material, fixture.credentials)
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
