package bootstrapstart

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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

// AdmissionLedger reads the signed slot and makes the accepted install's
// public marker available to the offline root that signs install continuity.
type AdmissionLedger interface {
	SlotReader
	PublishAcceptedInstall(context.Context, bootstrap.BootstrapScope, []byte) error
}

type LedgerOpener interface {
	OpenCurrentLedger(context.Context, bootstrap.VerifiedBootstrapAnchor, trust.Keyring) (AdmissionLedger, error)
	OpenHistoricalLedger(context.Context, bootstrap.HistoricalBootstrapAnchor, trust.Keyring) (AdmissionLedger, error)
}

type BinaryChecker interface {
	VerifyCurrent(release.VerifiedImage) (RunningBinary, error)
	VerifyHistorical(release.HistoricalImage) (RunningBinary, error)
	VerifySelfUpdated(selfupdate.Layout, trust.Keyring, release.UpdateExpectation) (RunningBinary, error)
}

type MaterialChecker interface {
	PrepareInitial(context.Context, bootstrap.VerifiedManifest, bootstrap.VerifiedReceipt, map[string]string, CurrentProofVerifier) error
	// RestartPins reads the install's adopted material generation, if any,
	// and returns what its credential directory must hold (TS-568).
	RestartPins(bootstrap.HistoricalManifest, trust.Keyring, string) (MaterialPins, error)
	VerifyRestart(context.Context, bootstrap.HistoricalManifest, MaterialPins) error
}

// CurrentProofVerifier rechecks the root anchor, its ledger grant, manifest,
// release image, and exact-instance receipt at an effect boundary.
type CurrentProofVerifier func(time.Time) error

type LiveCredentialChecker interface {
	VerifyLiveCredentials(context.Context, MaterialPins, bootstrap.Manifest) error
}

// CurrentContinuationChecker verifies an independently current renewal chain
// for an accepted historical install. Valid TLS/JWT files alone cannot renew
// an expired root manifest or authorize managed cloud effects.
type CurrentContinuationChecker interface {
	VerifyCurrentContinuation(context.Context, AcceptedInstall, InstanceObservation, bootstrap.SlotState) error
}

// Gate owns the pre-NATS admission sequence. Roots, anchor bytes and expected
// local deployment identity must come from the baked image, never the IMDS
// descriptor or a mutable instance tag.
type Gate struct {
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
	Continuation                 CurrentContinuationChecker
	Markers                      MarkerStore
	ClockCheck                   func() error
	Now                          func() time.Time
	InitialFounderFloor          func(context.Context, AcceptedInstall, time.Time) error
	InitialPeerFloor             func(context.Context, AcceptedInstall, bootstrap.SlotState, time.Time) error
	// SelfUpdate is the root-owned self-update release root. Restart
	// admission also accepts its current release under a binary-update
	// receipt; the zero value accepts only the image receipt binary.
	SelfUpdate selfupdate.Layout
	// LoadedControllerConfig is the loaded config's exact bytes. An adopted
	// schema-2 generation pins them in place of the manifest's (TS-668).
	LoadedControllerConfig []byte
}

type executableBinaryChecker struct{}

func (executableBinaryChecker) VerifyCurrent(image release.VerifiedImage) (RunningBinary, error) {
	return VerifyCurrentRunningBinary(image)
}

func (executableBinaryChecker) VerifyHistorical(image release.HistoricalImage) (RunningBinary, error) {
	return VerifyHistoricalRunningBinary(image)
}

func (executableBinaryChecker) VerifySelfUpdated(layout selfupdate.Layout, roots trust.Keyring,
	expected release.UpdateExpectation,
) (RunningBinary, error) {
	return verifySelfUpdatedBinary("/proc/self/exe", layout, roots, expected)
}

func (gate Gate) prerequisites() error {
	if len(gate.Roots) == 0 || len(gate.AnchorWire) == 0 || gate.Descriptor == nil ||
		gate.Instances == nil || gate.Ledgers == nil || gate.Material == nil || gate.Credentials == nil ||
		gate.Markers.directory == "" || gate.ClockCheck == nil ||
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

// verifyRestartBinary pins the running executable to the image receipt
// binary the marker accepted. Only an executable that differs from it may
// instead be the self-update current release.
func (gate Gate) verifyRestartBinary(image release.HistoricalImage, payload bootstrap.Manifest,
	marker AcceptedInstall,
) error {
	binary, err := gate.binaryChecker().VerifyHistorical(image)
	if err == nil && binary.SHA256 == marker.BinarySHA256 {
		return nil
	}
	if errors.Is(err, ErrRunningBinaryMismatch) && gate.SelfUpdate.Root != "" {
		_, err = gate.binaryChecker().VerifySelfUpdated(gate.SelfUpdate, gate.Roots, release.UpdateExpectation{
			Environment: payload.Environment, Cell: string(payload.Cell), Architecture: image.Receipt().Architecture,
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
	ledger, err := gate.Ledgers.OpenCurrentLedger(ctx, anchor, gate.Roots)
	if err != nil {
		return bootstrap.SlotState{}, nil, fmt.Errorf("open signed slot ledger: %w", err)
	}
	state, err := readSlot(ctx, ledger, scope)
	return state, ledger, err
}

func (gate Gate) historicalSlot(ctx context.Context, anchor bootstrap.HistoricalBootstrapAnchor,
	scope bootstrap.BootstrapScope,
) (bootstrap.SlotState, AdmissionLedger, error) {
	ledger, err := gate.Ledgers.OpenHistoricalLedger(ctx, anchor, gate.Roots)
	if err != nil {
		return bootstrap.SlotState{}, nil, fmt.Errorf("open historical signed slot ledger: %w", err)
	}
	state, err := readSlot(ctx, ledger, scope)
	return state, ledger, err
}

// publishAcceptedInstall publishes the exact accepted-install marker, which
// managed peers need the root to countersign before they can restart.
func publishAcceptedInstall(ctx context.Context, ledger AdmissionLedger, scope bootstrap.BootstrapScope,
	marker AcceptedInstall,
) error {
	wire, err := protocol.EncodeJSON(marker)
	if err != nil {
		return err
	}
	if err := ledger.PublishAcceptedInstall(ctx, scope, wire); err != nil {
		return fmt.Errorf("%w: publish accepted-install marker: %v", ErrAdmission, err)
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
		if reference.Purpose == bootstrap.SecretRegionalShared || reference.Purpose == bootstrap.SecretHostIssuer ||
			reference.Purpose == bootstrap.SecretController && reference.Slot == slot ||
			(reference.Purpose == bootstrap.SecretSeedFounder || reference.Purpose == bootstrap.SecretSeedLedgerSigner) &&
				slot == manifest.SeedSlot {
			references = append(references, reference)
		}
	}
	return references
}

func (gate Gate) initialProofs(state bootstrap.SlotState, anchor bootstrap.VerifiedBootstrapAnchor,
	observed InstanceObservation, now time.Time,
) (bootstrap.VerifiedManifest, bootstrap.VerifiedReceipt, release.VerifiedImage, error) {
	if state.Intent.ManifestDigest != state.ManifestRecord.SHA256 || state.Intent.ReleaseReceiptDigest == "" {
		return bootstrap.VerifiedManifest{}, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, ErrAdmission
	}
	expected, err := anchor.ManifestExpectation(state.Intent.Slot, state.Intent.ImageOCID)
	if err != nil {
		return bootstrap.VerifiedManifest{}, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, err
	}
	manifestEnvelope, err := proofEnvelope(state.ManifestRecord.Bytes)
	if err != nil {
		return bootstrap.VerifiedManifest{}, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, err
	}
	manifest, err := bootstrap.VerifyManifest(manifestEnvelope, gate.Roots, expected, now, bootstrap.ManifestTrustPolicy())
	if err != nil || manifest.Digest() != state.Intent.ManifestDigest {
		return bootstrap.VerifiedManifest{}, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, fmt.Errorf("%w: current signed manifest differs from intent: %v", ErrAdmission, err)
	}
	payload := manifest.Manifest()
	if payload.ReleaseReceiptSHA256 != state.Intent.ReleaseReceiptDigest ||
		payload.ImageOCID != state.Intent.ImageOCID || len(payload.ReleaseImageReceiptWire) == 0 {
		return bootstrap.VerifiedManifest{}, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, ErrAdmission
	}
	image, err := release.VerifyImageCurrent(payload.ReleaseImageReceiptWire, payload.ReleaseDelegationWire,
		gate.Roots, release.ImageExpectation{Environment: payload.Environment, LogicalRegion: string(payload.Cell),
			OCIImageOCID: payload.ImageOCID, Architecture: strings.TrimPrefix(payload.ImageArchitecture, "linux-")}, now)
	if err != nil {
		return bootstrap.VerifiedManifest{}, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, fmt.Errorf("verify current release image: %w", err)
	}
	receiptRecord := state.SeedReceiptRecord
	seed := state.Intent.Slot == payload.SeedSlot
	if !seed {
		receiptRecord = state.PeerReceiptRecord
	}
	if receiptRecord == nil || len(receiptRecord.Bytes) == 0 {
		return bootstrap.VerifiedManifest{}, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, ErrAdmission
	}
	receiptEnvelope, err := proofEnvelope(receiptRecord.Bytes)
	if err != nil {
		return bootstrap.VerifiedManifest{}, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, err
	}
	var receipt bootstrap.VerifiedReceipt
	if seed {
		receipt, err = bootstrap.VerifySeedReceipt(receiptEnvelope, manifest, gate.Roots, observed.Facts, now, bootstrap.ManifestTrustPolicy())
	} else {
		receipt, err = bootstrap.VerifyPeerReceipt(receiptEnvelope, manifest, observed.Facts, now, bootstrap.ManifestTrustPolicy())
	}
	if err != nil {
		return bootstrap.VerifiedManifest{}, bootstrap.VerifiedReceipt{}, release.VerifiedImage{}, fmt.Errorf("verify current exact-instance receipt: %w", err)
	}
	return manifest, receipt, image, nil
}

// AdmitInitial is the root-run first-install transaction. It writes the marker
// only after all current proofs, exact OCI identity, binary, material, and live
// authority checks have completed. A pre-existing marker always fails closed.
func (gate Gate) AdmitInitial(ctx context.Context) (AcceptedInstall, error) {
	if err := gate.prerequisites(); err != nil {
		return AcceptedInstall{}, err
	}
	now, err := gate.checkedNow()
	if err != nil {
		return AcceptedInstall{}, err
	}
	if _, err := gate.Markers.Read(); err == nil || !errors.Is(err, os.ErrNotExist) {
		return AcceptedInstall{}, fmt.Errorf("%w: first install requires an absent marker: %v", ErrAdmission, err)
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
	manifest, receipt, image, err := gate.initialProofs(state, anchor, observed, now)
	if err != nil {
		return AcceptedInstall{}, err
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
	verifyCurrent := func(_ time.Time) error {
		at, err := gate.checkedNow()
		if err != nil {
			return err
		}
		currentAnchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, gate.Roots, gate.Expected,
			at, bootstrap.BootstrapAnchorTrustPolicy())
		if err != nil || currentAnchor.Digest() != anchor.Digest() {
			return fmt.Errorf("%w: current baked anchor or ledger grant expired: %v", ErrAdmission, err)
		}
		_, _, _, err = gate.initialProofs(state, currentAnchor, observed, at)
		if err != nil {
			return fmt.Errorf("%w: current manifest, image, or instance receipt expired: %v", ErrAdmission, err)
		}
		return nil
	}
	if err := verifyCurrent(time.Time{}); err != nil {
		return AcceptedInstall{}, err
	}
	if err := gate.Material.PrepareInitial(ctx, manifest, receipt, materials, verifyCurrent); err != nil {
		return AcceptedInstall{}, fmt.Errorf("prepare current controller materials: %w", err)
	}
	if err := gate.Credentials.VerifyLiveCredentials(ctx, ManifestPins(materials), manifest.Manifest()); err != nil {
		return AcceptedInstall{}, fmt.Errorf("verify live controller credentials: %w", err)
	}
	receiptRecord := state.SeedReceiptRecord
	if state.Intent.Slot != manifest.Manifest().SeedSlot {
		receiptRecord = state.PeerReceiptRecord
	}
	acceptedAt, err := gate.checkedNow()
	if err != nil {
		return AcceptedInstall{}, err
	}
	manifestEnvelope, manifestErr := proofEnvelope(state.ManifestRecord.Bytes)
	receiptEnvelope, receiptErr := proofEnvelope(receiptRecord.Bytes)
	if manifestErr != nil || receiptErr != nil ||
		!coveredAt(anchor.IssuedAt(), anchor.ExpiresAt(), acceptedAt) ||
		!coveredAt(manifestEnvelope.IssuedAt, manifestEnvelope.ExpiresAt, acceptedAt) ||
		!coveredAt(image.IssuedAt(), image.ExpiresAt(), acceptedAt) ||
		!coveredAt(receiptEnvelope.IssuedAt, receiptEnvelope.ExpiresAt, acceptedAt) {
		return AcceptedInstall{}, fmt.Errorf("%w: signed proofs do not cover final acceptance time", ErrAdmission)
	}
	if err := ctx.Err(); err != nil {
		return AcceptedInstall{}, fmt.Errorf("%w: initial admission ended before acceptance: %w", ErrAdmission, err)
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
		MaterialSHA256: materials, AcceptedAt: acceptedAt,
		ManagedMaterial: manifest.Manifest().ManagedMaterial,
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
	marker.AcceptedAt = finalAt
	if err := gate.Markers.WriteNew(marker); err != nil {
		return AcceptedInstall{}, fmt.Errorf("persist accepted-install marker: %w", err)
	}
	if err := publishAcceptedInstall(ctx, ledger, scope, marker); err != nil {
		return AcceptedInstall{}, err
	}
	return marker, nil
}

// AdmitRestart accepts a historical install only when the root-owned marker
// matches the exact ledger attempt and live self-instance/VNIC observation.
// Current proof or a separate present-day continuation boundary is required;
// historical signatures and live credentials alone never authorize effects.
func (gate Gate) AdmitRestart(ctx context.Context) (AcceptedInstall, error) {
	if err := gate.prerequisites(); err != nil {
		return AcceptedInstall{}, err
	}
	if _, err := gate.checkedNow(); err != nil {
		return AcceptedInstall{}, err
	}
	marker, err := gate.Markers.Read()
	if err != nil {
		return AcceptedInstall{}, fmt.Errorf("read accepted-install marker: %w", err)
	}
	anchorEnvelope, err := proofEnvelope(gate.AnchorWire)
	if err != nil {
		return AcceptedInstall{}, err
	}
	anchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(anchorEnvelope, gate.Roots, gate.Expected,
		marker.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || anchor.Digest() != marker.AnchorSHA256 {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted anchor differs from baked root proof: %v", ErrAdmission, err)
	}
	scope, instanceID, err := gate.locate(ctx)
	if err != nil {
		return AcceptedInstall{}, err
	}
	if scope.DeploymentID != marker.DeploymentID || scope.Cell != marker.Cell ||
		scope.Slot != marker.Slot || instanceID != marker.InstanceOCID {
		return AcceptedInstall{}, fmt.Errorf("%w: local locator differs from accepted install", ErrAdmission)
	}
	state, ledger, err := gate.historicalSlot(ctx, anchor, scope)
	if err != nil {
		return AcceptedInstall{}, err
	}
	if state.Head.Attempt != marker.HeadAttempt || state.Head.Generation != marker.HeadGeneration ||
		state.ResultRecord == nil || state.ResultRecord.SHA256 != marker.ResultSHA256 ||
		state.ManifestRecord.SHA256 != marker.ManifestSHA256 ||
		state.Intent.ManifestDigest != marker.ManifestSHA256 ||
		state.Intent.ImageOCID != marker.ImageOCID ||
		state.Intent.ReleaseReceiptDigest != marker.ImageReceiptSHA256 {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted install differs from signed current slot", ErrAdmission)
	}
	// Peers restart only through a root-signed continuity for this exact
	// marker, so publish it before any continuity check.
	if err := publishAcceptedInstall(ctx, ledger, scope, marker); err != nil {
		return AcceptedInstall{}, err
	}
	observed, err := gate.observe(ctx, instanceID, state, anchor.Anchor())
	if err != nil {
		return AcceptedInstall{}, err
	}
	if observed.PrimaryVNICOCID != marker.PrimaryVNICOCID || observed.PrimaryPrivateIP != marker.PrimaryPrivateIP {
		return AcceptedInstall{}, fmt.Errorf("%w: primary VNIC identity changed", ErrAdmission)
	}
	anchored := anchor.Anchor()
	expected := bootstrap.ManifestExpectation{
		DeploymentID: anchored.DeploymentID, Environment: anchored.Environment,
		ClusterID: anchored.ClusterID, Cell: anchored.Cell, Slot: scope.Slot,
		ImageOCID: state.Intent.ImageOCID, StorageDomain: anchored.StorageDomain,
		ControllerSlots:  slices.Clone(anchored.ControllerSlots),
		IntentGeneration: anchored.InitialRegionIntentGeneration,
		IntentSHA256:     anchored.InitialRegionIntentSHA256,
	}
	manifestEnvelope, err := proofEnvelope(state.ManifestRecord.Bytes)
	if err != nil {
		return AcceptedInstall{}, err
	}
	manifest, err := bootstrap.VerifyHistoricalManifest(manifestEnvelope, gate.Roots, expected, bootstrap.ManifestTrustPolicy())
	if err != nil || manifest.Digest() != marker.ManifestSHA256 ||
		!coveredAt(manifestEnvelope.IssuedAt, manifestEnvelope.ExpiresAt, marker.AcceptedAt) {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted historical manifest is invalid: %v", ErrAdmission, err)
	}
	payload := manifest.Manifest()
	pins, err := gate.Material.RestartPins(manifest, gate.Roots, marker.PrimaryPrivateIP)
	if err != nil {
		return AcceptedInstall{}, fmt.Errorf("read installed controller material generation: %w", err)
	}
	if err := gate.restartConfig(&pins, payload, marker.ManifestSHA256); err != nil {
		return AcceptedInstall{}, err
	}
	if marker.SeedSlot != payload.SeedSlot {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted seed role differs from signed manifest", ErrAdmission)
	}
	if payload.ReleaseReceiptSHA256 != marker.ImageReceiptSHA256 ||
		digest(payload.ReleaseImageReceiptWire) != marker.ImageReceiptSHA256 ||
		payload.ImageOCID != marker.ImageOCID {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted release image differs", ErrAdmission)
	}
	image, err := release.VerifyImageHistorical(payload.ReleaseImageReceiptWire, payload.ReleaseDelegationWire,
		gate.Roots, release.ImageExpectation{Environment: payload.Environment, LogicalRegion: string(payload.Cell),
			OCIImageOCID: payload.ImageOCID, Architecture: strings.TrimPrefix(payload.ImageArchitecture, "linux-")})
	if err != nil || !coveredAt(image.IssuedAt(), image.ExpiresAt(), marker.AcceptedAt) {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted historical release image is invalid: %v", ErrAdmission, err)
	}
	receiptRecord := state.SeedReceiptRecord
	seed := scope.Slot == payload.SeedSlot
	if !seed {
		receiptRecord = state.PeerReceiptRecord
	}
	if receiptRecord == nil || receiptRecord.SHA256 != marker.ReceiptSHA256 {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted instance receipt differs", ErrAdmission)
	}
	receiptEnvelope, err := proofEnvelope(receiptRecord.Bytes)
	if err != nil {
		return AcceptedInstall{}, err
	}
	if !coveredAt(receiptEnvelope.IssuedAt, receiptEnvelope.ExpiresAt, marker.AcceptedAt) {
		return AcceptedInstall{}, fmt.Errorf("%w: instance receipt did not cover acceptance", ErrAdmission)
	}
	if seed {
		_, err = bootstrap.VerifyHistoricalSeedReceipt(receiptEnvelope, manifest, gate.Roots,
			observed.Facts, bootstrap.ManifestTrustPolicy())
	} else {
		_, err = bootstrap.VerifyHistoricalPeerReceipt(receiptEnvelope, manifest,
			observed.Facts, bootstrap.ManifestTrustPolicy())
	}
	if err != nil {
		return AcceptedInstall{}, fmt.Errorf("verify historical exact-instance receipt: %w", err)
	}
	if err := gate.verifyRestartBinary(image, payload, marker); err != nil {
		return AcceptedInstall{}, err
	}
	materials := expectedMaterials(payload, scope.Slot)
	if len(materials) == 0 || len(materials) != len(marker.MaterialSHA256) {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted material inventory differs", ErrAdmission)
	}
	for name, want := range materials {
		if marker.MaterialSHA256[name] != want {
			return AcceptedInstall{}, fmt.Errorf("%w: accepted material digest differs", ErrAdmission)
		}
	}
	if (payload.ManagedMaterial == nil) != (marker.ManagedMaterial == nil) ||
		payload.ManagedMaterial != nil && *payload.ManagedMaterial != *marker.ManagedMaterial {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted managed material domain differs", ErrAdmission)
	}
	if err := gate.Material.VerifyRestart(ctx, manifest, pins); err != nil {
		return AcceptedInstall{}, fmt.Errorf("verify installed controller materials: %w", err)
	}
	if err := gate.Credentials.VerifyLiveCredentials(ctx, pins, payload); err != nil {
		return AcceptedInstall{}, fmt.Errorf("verify live controller credentials: %w", err)
	}
	peerContinuation := !seed && state.Intent.Mode == bootstrap.IntentModeManaged
	now, err := gate.checkedNow()
	if err != nil {
		return AcceptedInstall{}, err
	}
	currentAnchor, currentErr := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, gate.Roots, gate.Expected,
		now, bootstrap.BootstrapAnchorTrustPolicy())
	currentProof := currentErr == nil && currentAnchor.Digest() == marker.AnchorSHA256
	if currentProof {
		_, _, _, currentErr = gate.initialProofs(state, currentAnchor, observed, now)
		currentProof = currentErr == nil
	}
	if !currentProof && !peerContinuation {
		if gate.Continuation == nil {
			return AcceptedInstall{}, fmt.Errorf("%w: historical install has no current continuation authority", ErrAdmission)
		}
		if _, err := gate.checkedNow(); err != nil {
			return AcceptedInstall{}, err
		}
		if err := gate.Continuation.VerifyCurrentContinuation(ctx, marker, observed, state); err != nil {
			return AcceptedInstall{}, fmt.Errorf("verify current controller continuation: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return AcceptedInstall{}, fmt.Errorf("%w: restart admission ended before acceptance: %w", ErrAdmission, err)
	}
	finalNow, err := gate.checkedNow()
	if err != nil {
		return AcceptedInstall{}, err
	}
	if currentProof && !peerContinuation {
		finalAnchor, proofErr := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, gate.Roots, gate.Expected,
			finalNow, bootstrap.BootstrapAnchorTrustPolicy())
		if proofErr == nil && finalAnchor.Digest() == marker.AnchorSHA256 {
			_, _, _, proofErr = gate.initialProofs(state, finalAnchor, observed, finalNow)
		}
		if proofErr != nil || finalAnchor.Digest() != marker.AnchorSHA256 {
			if gate.Continuation == nil {
				return AcceptedInstall{}, fmt.Errorf("%w: current proof expired before restart acceptance: %v", ErrAdmission, proofErr)
			}
			if err := gate.Continuation.VerifyCurrentContinuation(ctx, marker, observed, state); err != nil {
				return AcceptedInstall{}, fmt.Errorf("verify current controller continuation after proof expiry: %w", err)
			}
		}
	}
	if peerContinuation {
		if gate.Continuation == nil {
			return AcceptedInstall{}, fmt.Errorf("%w: managed peer has no current selected-plan continuation", ErrAdmission)
		}
		if err := gate.Continuation.VerifyCurrentContinuation(ctx, marker, observed, state); err != nil {
			return AcceptedInstall{}, fmt.Errorf("verify current managed-peer continuation: %w", err)
		}
	}
	return marker, nil
}

// restartConfig checks the loaded controller config against the digest the
// accepted install expects, the adopted generation's for the slot or the
// manifest's (MaterialPins.controllerConfigSHA256), and hands its bytes to
// the generation's file check.
func (gate Gate) restartConfig(pins *MaterialPins, manifest bootstrap.Manifest, manifestSHA256 string) error {
	want, err := pins.controllerConfigSHA256(manifest, manifestSHA256)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAdmission, err)
	}
	if want != gate.LoadedControllerConfigSHA256 {
		return fmt.Errorf("%w: loaded controller config differs from accepted manifest", ErrAdmission)
	}
	pins.config = gate.LoadedControllerConfig
	return nil
}

func coveredAt(issuedAt, expiresAt, acceptedAt time.Time) bool {
	return !acceptedAt.Before(issuedAt) && acceptedAt.Before(expiresAt)
}
