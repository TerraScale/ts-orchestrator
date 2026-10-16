package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

var ErrAdmission = errors.New("controller bootstrap admission failed")
var ErrAdmissionPending = errors.New("managed controller peer is awaiting its signed positive bootstrap result")

const initialAdmissionWaitLimit = 4 * time.Minute
const initialAdmissionRetryInterval = 2 * time.Second

// InstanceObservation is assembled only from OCI GetInstance and the attached
// primary VNIC. The IMDS identity merely selects which instance to observe.
type InstanceObservation struct {
	InstanceOCID       string
	BootstrapCreateKey string
	CompartmentOCID    string
	ImageOCID          string
	ETag               string
	AvailabilityDomain string
	FaultDomain        string
	Shape              string
	SubnetOCID         string
	NSGOCIDs           []string
	PrimaryVNICOCID    string
	PrimaryPrivateIP   string
	PrimaryVNIC        bool
	LifecycleState     string
	// Filled by Gate from signed anchor and intent fields after OCI comparison.
	Facts bootstrap.InstanceFacts
}

type DescriptorSource interface {
	FetchDescriptor(context.Context) (Descriptor, error)
	FetchInstanceID(context.Context) (string, error)
}

type InstanceObserver interface {
	ObserveInstance(context.Context, string) (InstanceObservation, error)
}

type SlotReader interface {
	ReadSlot(context.Context, bootstrap.BootstrapScope) (bootstrap.SlotState, error)
}

// AdmissionLedger reads current formation proofs and exports exact accepted bytes.
type AdmissionLedger interface {
	SlotReader
	PublishAcceptedInstall(context.Context, bootstrap.BootstrapScope, []byte) error
}

type LedgerOpener interface {
	OpenCurrentLedger(context.Context, bootstrap.VerifiedBootstrapAnchor, trust.Keyring) (AdmissionLedger, error)
}

type BinaryChecker interface {
	VerifyCurrent(release.VerifiedImage) (RunningBinary, error)
	VerifyAccepted(identityrekey.BinaryPin) (RunningBinary, error)
	VerifySelfUpdated(selfupdate.Layout, trust.Keyring, release.UpdateExpectation) (RunningBinary, error)
}

type MaterialChecker interface {
	PrepareInitial(context.Context, bootstrap.VerifiedManifest, bootstrap.VerifiedReceipt, map[string]string, CurrentProofVerifier) error
	// RestartPins reads the install's adopted material generation, if any,
	// and returns what its credential directory must hold (TS-568).
	RestartPins(AcceptedIdentity, trust.Keyring) (MaterialPins, error)
	VerifyRestart(context.Context, AcceptedIdentity, MaterialPins) error
}

// CurrentProofVerifier rechecks the root anchor, its ledger grant, manifest,
// release image, and exact-instance receipt at an effect boundary.
type CurrentProofVerifier func(time.Time) error

type LiveCredentialChecker interface {
	VerifyInitialLiveCredentials(context.Context, MaterialPins, bootstrap.VerifiedManifest) error
	VerifyLiveCredentials(context.Context, MaterialPins, AcceptedIdentity) error
}

// Gate admits fresh formation from current image proofs, and accepted restarts
// from the independently loaded root-owned installation and fixed trust roots.
type Gate struct {
	derivedStartup               *bootstrap.DerivedStartupAuthority
	Roots                        trust.Keyring
	AnchorWire                   []byte
	Expected                     bootstrap.BootstrapAnchorExpectation
	LoadedControllerConfigSHA256 string
	Descriptor                   DescriptorSource
	Instances                    InstanceObserver
	Ledgers                      LedgerOpener
	Binary                       BinaryChecker
	Material                     MaterialChecker
	Credentials                  LiveCredentialChecker
	ObserveIdentity              IdentityObservation
	InitialIdentity              func(bootstrap.Manifest) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error)
	Markers                      MarkerStore
	ClockCheck                   func() error
	Now                          func() time.Time
	InitialFounderFloor          func(context.Context, AcceptedInstall, time.Time) error
	InitialPeerFloor             func(context.Context, AcceptedInstall, bootstrap.SlotState, time.Time) error
	// SelfUpdate is the root-owned self-update release root. Restart
	// admission also accepts its current release under a binary-update
	// receipt; the zero value accepts only the accepted binary baseline.
	SelfUpdate selfupdate.Layout
	// LoadedControllerConfig is the loaded config's exact bytes. An adopted
	// generation pins them in place of the accepted baseline (TS-668).
	LoadedControllerConfig []byte
	// Tests inject the fixed trust-tree seam; production always loads fixed paths.
	trustStore *bakedStore
}

type executableBinaryChecker struct{}

func (executableBinaryChecker) VerifyCurrent(image release.VerifiedImage) (RunningBinary, error) {
	return VerifyCurrentRunningBinary(image)
}

func (executableBinaryChecker) VerifyAccepted(pin identityrekey.BinaryPin) (RunningBinary, error) {
	return VerifyAcceptedRunningBinary(pin)
}

func (executableBinaryChecker) VerifySelfUpdated(layout selfupdate.Layout, roots trust.Keyring,
	expected release.UpdateExpectation,
) (RunningBinary, error) {
	return verifySelfUpdatedBinary("/proc/self/exe", layout, roots, expected)
}

func (gate Gate) prerequisites() error {
	if len(gate.Roots) == 0 || len(gate.AnchorWire) == 0 || gate.Descriptor == nil ||
		gate.Instances == nil || (gate.Ledgers == nil && gate.derivedStartup == nil) || gate.Material == nil || gate.Credentials == nil ||
		gate.Markers.directory == "" || gate.ClockCheck == nil ||
		gate.InitialIdentity == nil || gate.ObserveIdentity == nil ||
		!markerDigestRE.MatchString(gate.LoadedControllerConfigSHA256) {
		return fmt.Errorf("%w: trusted input or required verifier is absent", ErrAdmission)
	}
	return nil
}

func (gate Gate) clock() time.Time {
	if gate.Now != nil {
		return gate.Now().Round(0).UTC()
	}
	return time.Now().Round(0).UTC()
}

func (gate Gate) checkedNow() (time.Time, error) {
	if gate.ClockCheck == nil {
		return time.Time{}, fmt.Errorf("%w: NTP clock health check is absent", ErrAdmission)
	}
	if err := gate.ClockCheck(); err != nil {
		return time.Time{}, fmt.Errorf("%w: NTP clock health: %v", ErrAdmission, err)
	}
	return gate.clock(), nil
}

func (gate Gate) binaryChecker() BinaryChecker {
	if gate.Binary != nil {
		return gate.Binary
	}
	return executableBinaryChecker{}
}

// verifyRestartBinary pins the running executable to the accepted baseline.
// Only an executable that differs from it may
// instead be the self-update current release.
func (gate Gate) verifyRestartBinary(accepted AcceptedIdentity, roots trust.Keyring) error {
	binary, err := gate.binaryChecker().VerifyAccepted(accepted.Binary)
	if err == nil && binary.SHA256 == accepted.Binary.SHA256 && binary.Bytes == accepted.Binary.Size &&
		binary.Architecture == accepted.Binary.Architecture {
		return nil
	}
	if err == nil {
		err = ErrRunningBinaryMismatch
	}
	if errors.Is(err, ErrRunningBinaryMismatch) && gate.SelfUpdate.Root != "" {
		_, err = gate.binaryChecker().VerifySelfUpdated(gate.SelfUpdate, roots, release.UpdateExpectation{
			Environment: accepted.Environment, Cell: accepted.Cell, Architecture: accepted.Binary.Architecture,
		})
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: installed executable differs: %v", ErrAdmission, err)
}

func (gate Gate) locate(ctx context.Context) (bootstrap.BootstrapScope, string, error) {
	descriptor, err := gate.Descriptor.FetchDescriptor(ctx)
	if err != nil {
		return bootstrap.BootstrapScope{}, "", fmt.Errorf("read local bootstrap descriptor: %w", err)
	}
	if descriptor.SchemaVersion != 1 || !descriptorSlotRE.MatchString(descriptor.Slot) {
		return bootstrap.BootstrapScope{}, "", ErrInvalidDescriptor
	}
	instanceID, err := gate.Descriptor.FetchInstanceID(ctx)
	if err != nil {
		return bootstrap.BootstrapScope{}, "", fmt.Errorf("read local instance ID: %w", err)
	}
	if !instanceIDRE.MatchString(instanceID) {
		return bootstrap.BootstrapScope{}, "", ErrInvalidDescriptor
	}
	return bootstrap.BootstrapScope{
		DeploymentID: gate.Expected.DeploymentID, Cell: string(gate.Expected.Cell), Slot: descriptor.Slot,
	}, instanceID, nil
}

func (gate Gate) observe(ctx context.Context, instanceID string, state bootstrap.SlotState,
	anchor bootstrap.BootstrapAnchor,
) (InstanceObservation, error) {
	observed, err := gate.Instances.ObserveInstance(ctx, instanceID)
	if err != nil {
		return InstanceObservation{}, fmt.Errorf("observe exact OCI instance and primary VNIC: %w", err)
	}
	if state.Result == nil || state.ResultRecord == nil || state.Head.ResultDigest == "" ||
		state.Head.ResultDigest != state.ResultRecord.SHA256 ||
		observed.InstanceOCID != instanceID || state.Result.InstanceOCID != instanceID ||
		observed.ImageOCID != state.Intent.ImageOCID || observed.ImageOCID != state.Result.ImageOCID ||
		observed.CompartmentOCID != state.Intent.CompartmentOCID ||
		observed.CompartmentOCID != state.Result.CompartmentOCID ||
		observed.AvailabilityDomain != state.Intent.AvailabilityDomain ||
		observed.FaultDomain != state.Intent.FaultDomain ||
		observed.Shape != state.Intent.Shape || observed.Shape != state.Result.Shape ||
		observed.SubnetOCID != state.Intent.SubnetOCID ||
		!sameOCIDSet(observed.NSGOCIDs, state.Intent.NetworkSecurityGroupIDs) ||
		state.Intent.DeploymentID != anchor.DeploymentID || state.Intent.Environment != anchor.Environment ||
		state.Intent.Cell != string(anchor.Cell) || state.Intent.OCIRegion != anchor.OCIRegion ||
		state.Result.CreateKey != state.Intent.CreateKey ||
		observed.LifecycleState != "RUNNING" || !observed.PrimaryVNIC ||
		!strings.HasPrefix(observed.PrimaryVNICOCID, "ocid1.vnic.") ||
		!validPrivateIPv4(observed.PrimaryPrivateIP) {
		return InstanceObservation{}, fmt.Errorf("%w: local instance, OCI observation, and signed slot result differ", ErrAdmission)
	}
	observed.Facts = bootstrap.InstanceFacts{
		DeploymentID: anchor.DeploymentID, Environment: anchor.Environment, ClusterID: anchor.ClusterID,
		Cell: anchor.Cell, OCIRegion: anchor.OCIRegion, Role: state.Intent.Role, Slot: state.Intent.Slot,
		InstanceOCID: observed.InstanceOCID, CompartmentOCID: observed.CompartmentOCID,
		ImageOCID: observed.ImageOCID, CreateKey: state.Intent.CreateKey,
		IntentSHA256: state.IntentRecord.SHA256,
		Profile: bootstrap.LaunchProfile{
			Slot: state.Intent.Slot, CompartmentOCID: observed.CompartmentOCID,
			AvailabilityDomain: observed.AvailabilityDomain, FaultDomain: observed.FaultDomain,
			SubnetOCID: observed.SubnetOCID,
			// OCI reports NSG membership without a stable order. The exact set
			// was checked above; keep the signed order for receipt verification.
			NetworkSecurityGroupOCIDs: slices.Clone(state.Intent.NetworkSecurityGroupIDs),
			Shape:                     observed.Shape,
		},
	}
	return observed, nil
}

func sameOCIDSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left, right = slices.Clone(left), slices.Clone(right)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

func (gate Gate) currentSlot(ctx context.Context, anchor bootstrap.VerifiedBootstrapAnchor,
	scope bootstrap.BootstrapScope,
) (bootstrap.SlotState, AdmissionLedger, error) {
	var ledger AdmissionLedger
	var err error
	if gate.derivedStartup != nil {
		if gate.derivedStartup.AnchorDigest() != anchor.Digest() {
			return bootstrap.SlotState{}, nil, ErrAdmission
		}
		var derivedLedger *bootstrap.Ledger
		derivedLedger, err = gate.derivedStartup.OpenLedger(ctx, gate.Roots)
		if err == nil {
			ledger = admissionLedger{ledger: derivedLedger}
		}
	} else {
		ledger, err = gate.Ledgers.OpenCurrentLedger(ctx, anchor, gate.Roots)
	}
	if err != nil {
		return bootstrap.SlotState{}, nil, fmt.Errorf("open signed slot ledger: %w", err)
	}
	state, err := readSlot(ctx, ledger, scope)
	return state, ledger, err
}

// publishAcceptedInstall exports the sole root-owned accepted record.
func publishAcceptedInstall(ctx context.Context, ledger AdmissionLedger, scope bootstrap.BootstrapScope,
	accepted AcceptedIdentity,
) error {
	wire, err := EncodeAcceptedIdentity(accepted)
	if err != nil {
		return err
	}
	if err := ledger.PublishAcceptedInstall(ctx, scope, wire); err != nil {
		return fmt.Errorf("%w: publish accepted-install marker: %w", ErrAdmission, err)
	}
	return nil
}

func readSlot(ctx context.Context, ledger SlotReader, scope bootstrap.BootstrapScope) (bootstrap.SlotState, error) {
	if ledger == nil {
		return bootstrap.SlotState{}, fmt.Errorf("%w: signed slot ledger is absent", ErrAdmission)
	}
	state, err := ledger.ReadSlot(ctx, scope)
	if err != nil {
		if errors.Is(err, bootstrap.ErrManagedPeerProofQuarantined) {
			return bootstrap.SlotState{}, fmt.Errorf("%w: %w", ErrAdmissionPending, err)
		}
		return bootstrap.SlotState{}, fmt.Errorf("read signed slot ledger: %w", err)
	}
	if state.Intent.Mode == bootstrap.IntentModeManaged && state.Head.ResultDigest == "" {
		return bootstrap.SlotState{}, ErrAdmissionPending
	}
	if state.ManifestRecord == nil || len(state.ManifestRecord.Bytes) == 0 {
		return bootstrap.SlotState{}, fmt.Errorf("%w: signed manifest is absent from exact slot ledger", ErrAdmission)
	}
	if state.Result == nil || state.ResultRecord == nil {
		return bootstrap.SlotState{}, fmt.Errorf("%w: signed positive slot result is absent", ErrAdmission)
	}
	return state, nil
}

// AdmitInitialWhenReady waits only for a verified managed peer slot whose
// positive result has not yet reached HEAD, or whose historical completion is
// quarantined pending fresh proof. Every attempt repeats the complete current
// admission; malformed records and all other failures return at once.
func (gate Gate) AdmitInitialWhenReady(ctx context.Context) (AcceptedInstall, error) {
	ctx, cancel := context.WithTimeout(ctx, initialAdmissionWaitLimit)
	defer cancel()
	return gate.admitInitialWhenReady(ctx, initialAdmissionRetryInterval)
}

func (gate Gate) admitInitialWhenReady(ctx context.Context, retryInterval time.Duration) (AcceptedInstall, error) {
	if retryInterval <= 0 {
		return AcceptedInstall{}, ErrAdmission
	}
	for {
		accepted, err := gate.AdmitInitial(ctx)
		if err == nil || !errors.Is(err, ErrAdmissionPending) {
			return accepted, err
		}
		select {
		case <-ctx.Done():
			return AcceptedInstall{}, ctx.Err()
		case <-time.After(retryInterval):
		}
	}
}

func proofEnvelope(body []byte) (trust.Envelope, error) {
	if len(body) == 0 {
		return trust.Envelope{}, ErrAdmission
	}
	return trust.DecodeEnvelope(body)
}

func digest(body []byte) string {
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

func expectedMaterials(manifest bootstrap.Manifest, slot string) map[string]string {
	materials := make(map[string]string)
	for _, reference := range slotReferences(manifest, slot) {
		materials[reference.TargetFile] = reference.SHA256
	}
	return materials
}

// slotReferences are the manifest secrets slot's credential directory holds.
func slotReferences(manifest bootstrap.Manifest, slot string) []bootstrap.SecretReference {
	var references []bootstrap.SecretReference
	for _, reference := range manifest.Secrets {
		if (reference.Slot == "" || reference.Slot == slot) &&
			(reference.Purpose != bootstrap.SecretSeedFounder && reference.Purpose != bootstrap.SecretSeedLedgerSigner ||
				slot == manifest.SeedSlot) {
			references = append(references, reference)
		}
	}
	return references
}

func (gate Gate) initialProofs(ctx context.Context, state bootstrap.SlotState, anchor bootstrap.VerifiedBootstrapAnchor,
	observed InstanceObservation, now time.Time,
) (bootstrap.StartupAuthority, bootstrap.VerifiedReceipt, release.VerifiedImage, error) {
	if state.Intent.ManifestDigest != state.ManifestRecord.SHA256 || state.Intent.ReleaseReceiptDigest == "" {
		return nil, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, ErrAdmission
	}
	expected, err := anchor.ManifestExpectation(state.Intent.Slot, state.Intent.ImageOCID)
	if err != nil {
		return nil, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, err
	}
	manifestEnvelope, err := proofEnvelope(state.ManifestRecord.Bytes)
	if err != nil {
		return nil, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, err
	}
	var manifest bootstrap.StartupAuthority
	if gate.derivedStartup != nil {
		if !bytes.Equal(state.ManifestRecord.Bytes, gate.derivedStartup.Wire()) || gate.derivedStartup.VerifyCurrent(ctx, now) != nil {
			return nil, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, ErrAdmission
		}
		manifest = *gate.derivedStartup
	} else {
		manifest, err = bootstrap.VerifyManifest(manifestEnvelope, gate.Roots, expected, now, bootstrap.ManifestTrustPolicy())
	}
	if err != nil || manifest.Digest() != state.Intent.ManifestDigest {
		return nil, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, fmt.Errorf("%w: current signed manifest differs from intent: %v", ErrAdmission, err)
	}
	payload := manifest.Manifest()
	if payload.ReleaseReceiptSHA256 != state.Intent.ReleaseReceiptDigest ||
		payload.ImageOCID != state.Intent.ImageOCID || len(payload.ReleaseImageReceiptWire) == 0 {
		return nil, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, ErrAdmission
	}
	image, err := release.VerifyImageCurrent(payload.ReleaseImageReceiptWire, payload.ReleaseDelegationWire,
		gate.Roots, release.ImageExpectation{Environment: payload.Environment, LogicalRegion: string(payload.Cell),
			OCIImageOCID: payload.ImageOCID, Architecture: strings.TrimPrefix(payload.ImageArchitecture, "linux-")}, now)
	if err != nil {
		return nil, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, fmt.Errorf("verify current release image: %w", err)
	}
	receiptRecord := state.SeedReceiptRecord
	seed := state.Intent.Slot == payload.SeedSlot
	if !seed {
		receiptRecord = state.PeerReceiptRecord
	}
	if receiptRecord == nil || len(receiptRecord.Bytes) == 0 {
		return nil, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, ErrAdmission
	}
	if receiptRecord.SHA256 != digest(receiptRecord.Bytes) {
		return nil, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, ErrAdmission
	}
	receiptEnvelope, err := proofEnvelope(receiptRecord.Bytes)
	if err != nil {
		return nil, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, err
	}
	var receipt bootstrap.VerifiedReceipt
	if seed {
		receipt, err = bootstrap.VerifySeedReceipt(receiptEnvelope, manifest, gate.Roots, observed.Facts, now, bootstrap.ManifestTrustPolicy())
	} else {
		receipt, err = bootstrap.VerifyPeerReceipt(receiptEnvelope, manifest, observed.Facts, now, bootstrap.ManifestTrustPolicy())
	}
	if err != nil {
		return nil, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, fmt.Errorf("verify current exact-instance receipt: %w", err)
	}
	return manifest, receipt, image, nil
}

// AdmitInitial is the root-run first-install transaction. It writes the marker
// only after all current proofs, exact OCI identity, binary, material, and live
// authority checks have completed. A pre-existing marker always fails closed.
func (gate Gate) AdmitInitial(ctx context.Context) (AcceptedInstall, error) {
	if err := gate.requireInitialJournalAbsent(); err != nil {
		return AcceptedInstall{}, err
	}
	if err := gate.prerequisites(); err != nil {
		return AcceptedInstall{}, err
	}
	now, err := gate.checkedNow()
	if err != nil {
		return AcceptedInstall{}, err
	}
	if _, err := gate.Markers.ReadIdentity(); err == nil || !errors.Is(err, os.ErrNotExist) {
		return AcceptedInstall{}, fmt.Errorf("%w: first install requires an absent marker: %v", ErrAdmission, err)
	}
	prior, priorErr := gate.Markers.ReadInitialFormation()
	if priorErr != nil && !errors.Is(priorErr, os.ErrNotExist) {
		return AcceptedInstall{}, fmt.Errorf("read current initial formation recovery state: %w", priorErr)
	}
	pending, pendingErr := gate.Markers.readInitialExport()
	if pendingErr != nil && !errors.Is(pendingErr, os.ErrNotExist) || pendingErr == nil && priorErr != nil {
		return AcceptedInstall{}, fmt.Errorf("%w: invalid initial export recovery state: %v", ErrAdmission, pendingErr)
	}
	anchorEnvelope, err := proofEnvelope(gate.AnchorWire)
	if err != nil {
		return AcceptedInstall{}, err
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, gate.Roots, gate.Expected, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return AcceptedInstall{}, fmt.Errorf("verify current baked anchor: %w", err)
	}
	ctx, stop := context.WithDeadline(ctx, anchor.ExpiresAt())
	defer stop()
	scope, instanceID, err := gate.locate(ctx)
	if err != nil {
		return AcceptedInstall{}, err
	}
	state, ledger, err := gate.currentSlot(ctx, anchor, scope)
	if err != nil {
		return AcceptedInstall{}, err
	}
	observed, err := gate.observe(ctx, instanceID, state, anchor.Anchor())
	if err != nil {
		return AcceptedInstall{}, err
	}
	manifest, receipt, image, err := gate.initialProofs(ctx, state, anchor, observed, now)
	if err != nil {
		return AcceptedInstall{}, err
	}
	payload := manifest.Manifest()
	if !slices.Equal(payload.ControllerSlots, []string{"controller-a", "controller-b", "controller-c"}) ||
		!slices.Contains(payload.ControllerSlots, scope.Slot) || !slices.Contains(payload.ControllerSlots, payload.SeedSlot) {
		return AcceptedInstall{}, fmt.Errorf("%w: fresh installation requires the reviewed controller topology", ErrAdmission)
	}
	// A first install has no adopted generation: the manifest pins the config.
	if manifest.Manifest().ControllerConfigSHA256 != gate.LoadedControllerConfigSHA256 {
		return AcceptedInstall{}, fmt.Errorf("%w: loaded controller config differs from signed ledger manifest", ErrAdmission)
	}
	binary, err := gate.binaryChecker().VerifyCurrent(image)
	if err != nil {
		return AcceptedInstall{}, err
	}
	materials := expectedMaterials(manifest.Manifest(), scope.Slot)
	if len(materials) == 0 {
		return AcceptedInstall{}, fmt.Errorf("%w: no controller materials authorized", ErrAdmission)
	}
	receiptRecord := state.SeedReceiptRecord
	if state.Intent.Slot != manifest.Manifest().SeedSlot {
		receiptRecord = state.PeerReceiptRecord
	}
	manifestEnvelope, manifestErr := proofEnvelope(state.ManifestRecord.Bytes)
	receiptEnvelope, receiptErr := proofEnvelope(receiptRecord.Bytes)
	if manifestErr != nil || receiptErr != nil {
		return AcceptedInstall{}, ErrAdmission
	}
	marker := AcceptedInstall{
		SchemaVersion: 1, AnchorSHA256: anchor.Digest(), ManifestSHA256: state.ManifestRecord.SHA256,
		ReceiptSHA256: receiptRecord.SHA256, ImageReceiptSHA256: digest(manifest.Manifest().ReleaseImageReceiptWire),
		DeploymentID: scope.DeploymentID, Cell: scope.Cell, Slot: scope.Slot,
		SeedSlot:  manifest.Manifest().SeedSlot,
		ImageOCID: state.Intent.ImageOCID, InstanceOCID: instanceID,
		PrimaryVNICOCID: observed.PrimaryVNICOCID, PrimaryPrivateIP: observed.PrimaryPrivateIP,
		HeadAttempt: state.Head.Attempt, HeadGeneration: state.Head.Generation,
		ResultSHA256: state.ResultRecord.SHA256, BinarySHA256: binary.SHA256,
		MaterialSHA256: materials, AcceptedAt: now,
		ManagedMaterial: manifest.Manifest().ManagedMaterial,
	}
	if priorErr == nil {
		marker.AcceptedAt = prior.AcceptedAt
		if !sameInitialFormation(marker, prior) ||
			!coveredAt(anchor.IssuedAt(), anchor.ExpiresAt(), prior.AcceptedAt) ||
			!coveredAt(manifestEnvelope.IssuedAt, manifestEnvelope.ExpiresAt, prior.AcceptedAt) ||
			!coveredAt(image.IssuedAt(), image.ExpiresAt(), prior.AcceptedAt) ||
			!coveredAt(receiptEnvelope.IssuedAt, receiptEnvelope.ExpiresAt, prior.AcceptedAt) {
			return AcceptedInstall{}, fmt.Errorf("%w: initial formation recovery differs from verified current installation", ErrAdmission)
		}
	}
	launchStore := bakedStore{directory: BakedDirectory}
	if gate.trustStore != nil {
		launchStore = *gate.trustStore
	}
	launchPins, err := launchStore.measureInitialLaunchMaterial(manifest, gate.Roots, now)
	if err != nil {
		return AcceptedInstall{}, fmt.Errorf("measure current public host launch inputs: %w", err)
	}
	verifyCurrent := func(_ time.Time) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := gate.requireInitialJournalAbsent(); err != nil {
			return err
		}
		at, err := gate.checkedNow()
		if err != nil {
			return err
		}
		currentAnchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, gate.Roots, gate.Expected,
			at, bootstrap.BootstrapAnchorTrustPolicy())
		if err != nil || currentAnchor.Digest() != anchor.Digest() {
			return fmt.Errorf("%w: current baked anchor or ledger grant expired: %v", ErrAdmission, err)
		}
		_, _, _, err = gate.initialProofs(ctx, state, currentAnchor, observed, at)
		if err != nil {
			return fmt.Errorf("%w: current manifest, image, or instance receipt expired: %v", ErrAdmission, err)
		}
		currentPins, err := launchStore.measureInitialLaunchMaterial(manifest, gate.Roots, at)
		if err != nil || !maps.Equal(launchPins, currentPins) {
			return fmt.Errorf("%w: current public host launch inputs changed or expired: %v", ErrAdmission, err)
		}
		return nil
	}
	if err := verifyCurrent(time.Time{}); err != nil {
		return AcceptedInstall{}, err
	}
	if pendingErr == nil {
		if pending.AcceptedAt.After(now) {
			return AcceptedInstall{}, ErrAdmission
		}
		rebuilt, err := AcceptedIdentityFromInitial(InitialAcceptedIdentityInputs{
			OperationID: entityid.Derive("accepted-install", manifest.Digest(), receiptRecord.SHA256),
			Manifest:    manifest, Receipt: receipt, Image: image, Observed: observed, Binary: binary,
			Broker: pending.Broker, Store: pending.Store, LaunchMaterialSHA256: launchPins,
			AcceptedAt: pending.AcceptedAt, VerifyCurrent: verifyCurrent,
		})
		if err != nil {
			return AcceptedInstall{}, err
		}
		if err := sameInitialExport(pending, rebuilt); err != nil {
			return AcceptedInstall{}, err
		}
		if err := verifyAcceptedStoreFiles(pending.Store); err != nil {
			return AcceptedInstall{}, err
		}
	}
	if err := gate.Material.PrepareInitial(ctx, manifest, receipt, materials, verifyCurrent); err != nil {
		return AcceptedInstall{}, fmt.Errorf("prepare current controller materials: %w", err)
	}
	if pendingErr == nil {
		if err := VerifyAcceptedLocalIdentity(pending, gate.ObserveIdentity); err != nil {
			return AcceptedInstall{}, err
		}
	}
	if err := gate.Credentials.VerifyInitialLiveCredentials(ctx, ManifestPins(materials), manifest); err != nil {
		return AcceptedInstall{}, fmt.Errorf("verify live controller credentials: %w", err)
	}
	acceptedAt, err := gate.checkedNow()
	if err != nil {
		return AcceptedInstall{}, err
	}
	if !coveredAt(anchor.IssuedAt(), anchor.ExpiresAt(), acceptedAt) ||
		!coveredAt(manifestEnvelope.IssuedAt, manifestEnvelope.ExpiresAt, acceptedAt) ||
		!coveredAt(image.IssuedAt(), image.ExpiresAt(), acceptedAt) ||
		!coveredAt(receiptEnvelope.IssuedAt, receiptEnvelope.ExpiresAt, acceptedAt) {
		return AcceptedInstall{}, fmt.Errorf("%w: signed proofs do not cover final acceptance time", ErrAdmission)
	}
	if err := ctx.Err(); err != nil {
		return AcceptedInstall{}, fmt.Errorf("%w: initial admission ended before acceptance: %w", ErrAdmission, err)
	}
	if priorErr != nil {
		marker.AcceptedAt = acceptedAt
	}

	if err := verifyCurrent(time.Time{}); err != nil {
		return AcceptedInstall{}, err
	}
	if state.Intent.Slot == manifest.Manifest().SeedSlot {
		if gate.InitialFounderFloor == nil {
			return AcceptedInstall{}, fmt.Errorf("%w: initial seed founder floor provisioner is absent", ErrAdmission)
		}
		if state.Intent.Mode != bootstrap.IntentModeExternalSeed || state.Head.Attempt != 1 ||
			state.Head.Generation != 1 {
			return AcceptedInstall{}, fmt.Errorf("%w: seed floor requires the first external-seed attempt", ErrAdmission)
		}
		if err := gate.InitialFounderFloor(ctx, marker, acceptedAt); err != nil {
			return AcceptedInstall{}, fmt.Errorf("%w: provision initial seed founder floor: %v", ErrAdmission, err)
		}
	} else if state.Intent.Mode == bootstrap.IntentModeManaged {
		if gate.InitialPeerFloor == nil {
			return AcceptedInstall{}, fmt.Errorf("%w: initial managed peer floor provisioner is absent", ErrAdmission)
		}
		if err := gate.InitialPeerFloor(ctx, marker, state, acceptedAt); err != nil {
			return AcceptedInstall{}, fmt.Errorf("%w: provision initial peer founder floor: %v", ErrAdmission, err)
		}
	}
	if err := verifyCurrent(time.Time{}); err != nil {
		return AcceptedInstall{}, err
	}
	finalAt, err := gate.checkedNow()
	if err != nil {
		return AcceptedInstall{}, err
	}
	if !coveredAt(anchor.IssuedAt(), anchor.ExpiresAt(), finalAt) ||
		!coveredAt(manifestEnvelope.IssuedAt, manifestEnvelope.ExpiresAt, finalAt) ||
		!coveredAt(image.IssuedAt(), image.ExpiresAt(), finalAt) ||
		!coveredAt(receiptEnvelope.IssuedAt, receiptEnvelope.ExpiresAt, finalAt) {
		return AcceptedInstall{}, fmt.Errorf("%w: signed proofs do not cover final marker publication time", ErrAdmission)
	}
	if err := ctx.Err(); err != nil {
		return AcceptedInstall{}, fmt.Errorf("%w: initial admission ended before marker publication: %w", ErrAdmission, err)
	}
	if err := verifyCurrent(finalAt); err != nil {
		return AcceptedInstall{}, err
	}
	broker, store, err := gate.InitialIdentity(manifest.Manifest())
	if err != nil {
		return AcceptedInstall{}, fmt.Errorf("prepare fresh installation identity: %w", err)
	}
	finalAt, err = gate.checkedNow()
	if err != nil {
		return AcceptedInstall{}, err
	}
	if priorErr != nil {
		marker.AcceptedAt = finalAt
	}
	acceptanceAt := finalAt
	if pendingErr == nil {
		if pending.AcceptedAt.After(finalAt) || !coveredAt(anchor.IssuedAt(), anchor.ExpiresAt(), pending.AcceptedAt) ||
			!coveredAt(manifestEnvelope.IssuedAt, manifestEnvelope.ExpiresAt, pending.AcceptedAt) ||
			!coveredAt(image.IssuedAt(), image.ExpiresAt(), pending.AcceptedAt) ||
			!coveredAt(receiptEnvelope.IssuedAt, receiptEnvelope.ExpiresAt, pending.AcceptedAt) {
			return AcceptedInstall{}, fmt.Errorf("%w: pending export acceptance is outside current proofs", ErrAdmission)
		}
		acceptanceAt = pending.AcceptedAt
	}
	accepted, err := AcceptedIdentityFromInitial(InitialAcceptedIdentityInputs{
		OperationID: entityid.Derive("accepted-install", manifest.Digest(), receiptRecord.SHA256),
		Manifest:    manifest, Receipt: receipt, Image: image, Observed: observed, Binary: binary,
		Broker: broker, Store: store, LaunchMaterialSHA256: launchPins,
		AcceptedAt: acceptanceAt, VerifyCurrent: verifyCurrent,
	})
	if err != nil {
		return AcceptedInstall{}, fmt.Errorf("normalize fresh accepted installation: %w", err)
	}
	if pendingErr == nil {
		if err := sameInitialExport(pending, accepted); err != nil {
			return AcceptedInstall{}, fmt.Errorf("%w: current installation differs from pending export: %w", ErrAdmission, err)
		}
	}
	if err := gate.requireInitialJournalAbsent(); err != nil {
		return AcceptedInstall{}, err
	}
	if err := gate.publishInitialFormation(marker); err != nil {
		return AcceptedInstall{}, err
	}
	if err := verifyCurrent(finalAt); err != nil {
		return AcceptedInstall{}, err
	}
	if err := gate.Markers.stageInitialExport(accepted, gate.ObserveIdentity); err != nil {
		return AcceptedInstall{}, fmt.Errorf("stage accepted-install export: %w", err)
	}
	if err := publishAcceptedInstall(ctx, ledger, scope, accepted); err != nil {
		return AcceptedInstall{}, err
	}
	if err := verifyCurrent(time.Time{}); err != nil {
		return AcceptedInstall{}, err
	}
	if err := gate.Markers.WriteNewIdentity(accepted, gate.ObserveIdentity); err != nil {
		return AcceptedInstall{}, fmt.Errorf("persist accepted-install marker: %w", err)
	}
	if err := gate.Markers.clearInitialExport(); err != nil {
		return AcceptedInstall{}, fmt.Errorf("clear completed initial export: %w", err)
	}
	return marker, nil
}

func sameInitialFormation(left, right AcceptedInstall) bool {
	a, err := protocol.EncodeJSON(left)
	if err != nil {
		return false
	}
	b, err := protocol.EncodeJSON(right)
	return err == nil && bytes.Equal(a, b)
}

func (gate Gate) publishInitialFormation(marker AcceptedInstall) error {
	err := gate.Markers.WriteInitialFormation(marker)
	if errors.Is(err, os.ErrExist) {
		prior, readErr := gate.Markers.ReadInitialFormation()
		if readErr != nil {
			return readErr
		}
		if sameInitialFormation(prior, marker) {
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("%w: publish current initial formation: %w", ErrAdmission, err)
	}
	return nil
}

func (gate Gate) requireInitialJournalAbsent() error {
	if _, err := gate.Markers.readIdentityRekeyJournal(); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: first installation requires an absent identity-rekey journal: %w", ErrAdmission,
			errors.Join(ErrIdentityRekeyJournal, err))
	}
	return nil
}

// AdmitRestart checks installed identity locally and authenticates its current
// OCI instance/VNIC observation before permitting ordinary controller runtime.
func (gate Gate) AdmitRestart(ctx context.Context) (AcceptedIdentity, error) {
	if gate.Instances == nil {
		return AcceptedIdentity{}, fmt.Errorf("%w: authenticated OCI instance observer is absent", ErrAdmission)
	}
	if _, err := gate.checkedNow(); err != nil {
		return AcceptedIdentity{}, err
	}
	accepted, err := gate.AdmitRestartLocal(ctx)
	if err != nil {
		return AcceptedIdentity{}, err
	}
	observed, err := gate.Instances.ObserveInstance(ctx, accepted.InstanceOCID)
	if err != nil {
		return AcceptedIdentity{}, fmt.Errorf("observe accepted OCI instance: %w", err)
	}
	if observed.InstanceOCID != accepted.InstanceOCID || observed.ImageOCID != accepted.ImageOCID ||
		observed.PrimaryVNICOCID != accepted.PrimaryVNICOCID || observed.PrimaryPrivateIP != accepted.PrimaryPrivateIP ||
		!observed.PrimaryVNIC || observed.LifecycleState != "RUNNING" {
		return AcceptedIdentity{}, fmt.Errorf("%w: authenticated OCI physical identity differs from accepted installation", ErrAdmission)
	}
	if _, err := gate.checkedNow(); err != nil {
		return AcceptedIdentity{}, err
	}
	if err := ctx.Err(); err != nil {
		return AcceptedIdentity{}, err
	}
	if err := gate.checkAcceptedUnchanged(accepted); err != nil {
		return AcceptedIdentity{}, err
	}
	return accepted, nil
}

// restartConfig binds loaded bytes to the accepted baseline or its verified renewal.
func (gate Gate) restartConfig(pins *MaterialPins, accepted AcceptedIdentity) error {
	want, err := pins.controllerConfigSHA256(accepted)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAdmission, err)
	}
	if want != gate.LoadedControllerConfigSHA256 ||
		len(gate.LoadedControllerConfig) != 0 && digest(gate.LoadedControllerConfig) != want {
		return fmt.Errorf("%w: loaded controller config differs from accepted installation", ErrAdmission)
	}
	pins.config = gate.LoadedControllerConfig
	return nil
}

func coveredAt(issuedAt, expiresAt, acceptedAt time.Time) bool {
	return !acceptedAt.Before(issuedAt) && acceptedAt.Before(expiresAt)
}
