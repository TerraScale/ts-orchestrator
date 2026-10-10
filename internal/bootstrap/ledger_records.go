package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	roleController           = "controller"
	domainBootstrapIntent    = "bootstrap-intent"
	domainBootstrapResult    = "bootstrap-result"
	domainBootstrapHead      = "bootstrap-slot-head"
	domainBootstrapCandidate = "bootstrap-candidate"
	domainBootstrapProgress  = "bootstrap-progress"
	domainSlotRetirement     = "bootstrap-slot-retirement"
	domainSeedHandoff        = "seed-handoff"
)

// ManagedPeerObservationMaxAge bounds the time between the final exact OCI
// reobservation and the initial durable positive-result write.
const ManagedPeerObservationMaxAge = 10 * time.Second

type IntentMode string

const (
	IntentModeManaged      IntentMode = "managed"
	IntentModeExternalSeed IntentMode = "external-seed"
)

var (
	ErrRecordAuthorization         = errors.New("bootstrap ledger record is not authorized")
	ErrManagedPeerObservationStale = errors.New("managed peer OCI observation is outside its durable freshness window")
	ErrManagedPeerProofQuarantined = errors.New("managed-peer proof or HEAD is quarantined")
	ErrManagedPeerCandidatePinned  = errors.New("managed-peer candidate is pinned; another launch is forbidden")
	ErrInvalidRecord               = errors.New("bootstrap ledger record is invalid")
	ErrSlotHeadConflict            = errors.New("bootstrap slot HEAD changed concurrently")
	ErrSlotNotReserved             = errors.New("bootstrap slot is not reserved by the expected intent")
	ErrRetirementInvalid           = errors.New("bootstrap slot retirement evidence is invalid")
	ErrSlotAlreadyComplete         = errors.New("bootstrap slot already has a positive OCI result")
	ErrSlotResultPendingHead       = errors.New("bootstrap result exists but its slot HEAD update is unresolved")
	ErrSlotAdvancePendingHead      = errors.New("bootstrap next-attempt intent exists but its slot HEAD update is unresolved")
	ErrExternalSeedMode            = errors.New("external seed intent is not authorized for an OCI create")
	ErrManagedPeerReceiptRequired  = errors.New("managed slot completion requires a verified delegated peer receipt")

	sha256DigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	createTokenPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
)

// Intent is the immutable founder-signed OCI launch request. CreatedAt is
// signed once and must remain identical on every retry.
type Intent struct {
	SchemaVersion           int        `json:"schemaVersion"`
	Mode                    IntentMode `json:"mode"`
	DeploymentID            string     `json:"deploymentId"`
	Cell                    string     `json:"cell"`
	Environment             string     `json:"environment"`
	Role                    string     `json:"role"`
	Slot                    string     `json:"slot"`
	Attempt                 uint64     `json:"attempt"`
	Generation              uint64     `json:"generation"`
	ManifestDigest          string     `json:"manifestDigest"`
	ReleaseReceiptDigest    string     `json:"releaseReceiptDigest"`
	RegionIntentGeneration  uint64     `json:"regionIntentGeneration"`
	ImageOCID               string     `json:"imageOcid"`
	RegionIntentDigest      string     `json:"regionIntentDigest"`
	LaunchRequestDigest     string     `json:"launchRequestDigest"`
	ReviewedPlanDigest      string     `json:"reviewedPlanDigest,omitzero"`
	FounderPlanSHA256       string     `json:"founderPlanSha256,omitzero"`
	PeerRowDigest           string     `json:"peerRowDigest,omitzero"`
	RetirementDigest        string     `json:"retirementDigest,omitzero"`
	CreateKey               string     `json:"createKey"`
	RetryToken              string     `json:"retryToken,omitzero"`
	CreatedAt               time.Time  `json:"createdAt"`
	OCIRegion               string     `json:"ociRegion"`
	CompartmentOCID         string     `json:"compartmentOcid"`
	AvailabilityDomain      string     `json:"availabilityDomain"`
	FaultDomain             string     `json:"faultDomain"`
	SubnetOCID              string     `json:"subnetOcid"`
	NetworkSecurityGroupIDs []string   `json:"networkSecurityGroupIds"`
	Shape                   string     `json:"shape"`
	Node                    string     `json:"node"`
}

// Result is the immutable founder-signed positive OCI reobservation for one
// exact intent. It records no credentials or Vault secret material.
type Result struct {
	SchemaVersion          int        `json:"schemaVersion"`
	Mode                   IntentMode `json:"mode"`
	DeploymentID           string     `json:"deploymentId"`
	Cell                   string     `json:"cell"`
	Environment            string     `json:"environment"`
	Role                   string     `json:"role"`
	Slot                   string     `json:"slot"`
	Attempt                uint64     `json:"attempt"`
	Generation             uint64     `json:"generation"`
	RegionIntentGeneration uint64     `json:"regionIntentGeneration"`
	IntentDigest           string     `json:"intentDigest"`
	InstanceOCID           string     `json:"instanceOcid"`
	ProviderRequestID      string     `json:"providerRequestId,omitzero"`
	ETag                   string     `json:"etag"`
	OCIRegion              string     `json:"ociRegion"`
	CompartmentOCID        string     `json:"compartmentOcid"`
	ImageOCID              string     `json:"imageOcid"`
	Shape                  string     `json:"shape"`
	ObservedProfileDigest  string     `json:"observedProfileDigest"`
	PeerReceiptDigest      string     `json:"peerReceiptDigest,omitzero"`
	SeedReceiptDigest      string     `json:"seedReceiptDigest,omitzero"`
	CreateKey              string     `json:"createKey"`
	ObservedAt             time.Time  `json:"observedAt"`
}

// ManagedPeerCandidate is the immutable signed identity pin for the one
// instance that may have been created for a managed peer attempt. It grants
// observation of InstanceOCID only; it never grants another launch.
type ManagedPeerCandidate struct {
	SchemaVersion       int    `json:"schemaVersion"`
	DeploymentID        string `json:"deploymentId"`
	Cell                string `json:"cell"`
	Environment         string `json:"environment"`
	Role                string `json:"role"`
	Slot                string `json:"slot"`
	Attempt             uint64 `json:"attempt"`
	Generation          uint64 `json:"generation"`
	IntentDigest        string `json:"intentDigest"`
	CreateKey           string `json:"createKey"`
	FounderPlanSHA256   string `json:"founderPlanSha256"`
	PeerRowDigest       string `json:"peerRowDigest"`
	ManifestDigest      string `json:"manifestDigest"`
	LaunchProfileDigest string `json:"launchProfileDigest"`
	InstanceOCID        string `json:"instanceOcid"`
}

// ManagedPeerProgressPhase identifies the exact durable transition stage.
type ManagedPeerProgressPhase string

const (
	ManagedPeerProgressCandidate ManagedPeerProgressPhase = "candidate-pinned"
	ManagedPeerProgressReceipt   ManagedPeerProgressPhase = "receipt-staged"
	ManagedPeerProgressResult    ManagedPeerProgressPhase = "result-staged"
)

// ManagedPeerProgress is the signed CAS record that pins candidate identity
// and stages exact bounded proof bytes before their content-addressed writes.
type ManagedPeerProgress struct {
	SchemaVersion      int                      `json:"schemaVersion"`
	DeploymentID       string                   `json:"deploymentId"`
	Cell               string                   `json:"cell"`
	Environment        string                   `json:"environment"`
	Role               string                   `json:"role"`
	Slot               string                   `json:"slot"`
	Attempt            uint64                   `json:"attempt"`
	Generation         uint64                   `json:"generation"`
	Sequence           uint64                   `json:"sequence"`
	CandidateDigest    string                   `json:"candidateDigest"`
	Phase              ManagedPeerProgressPhase `json:"phase"`
	PendingProofKind   string                   `json:"pendingProofKind,omitzero"`
	PendingProofDigest string                   `json:"pendingProofDigest,omitzero"`
	PendingProofWire   []byte                   `json:"pendingProofWire,omitzero"`
}

// SlotHead is the signed mutable current-attempt pointer stored in the
// separately writable coordination bucket. Only ETag-guarded CAS changes it.
type SlotHead struct {
	SchemaVersion           int    `json:"schemaVersion"`
	DeploymentID            string `json:"deploymentId"`
	Cell                    string `json:"cell"`
	Environment             string `json:"environment"`
	Role                    string `json:"role"`
	Slot                    string `json:"slot"`
	Attempt                 uint64 `json:"attempt"`
	Generation              uint64 `json:"generation"`
	IntentDigest            string `json:"intentDigest"`
	ResultDigest            string `json:"resultDigest,omitzero"`
	CandidateDigest         string `json:"candidateDigest,omitzero"`
	PreviousAttempt         uint64 `json:"previousAttempt,omitzero"`
	PreviousGeneration      uint64 `json:"previousGeneration,omitzero"`
	PreviousIntentDigest    string `json:"previousIntentDigest,omitzero"`
	PreviousResultDigest    string `json:"previousResultDigest,omitzero"`
	PreviousCandidateDigest string `json:"previousCandidateDigest,omitzero"`
	RetirementDigest        string `json:"retirementDigest,omitzero"`
}

// RetirementEvidence is a signed, typed claim by the configured retirement
// authority. The ledger checks exact prior attempt/result/resource binding and
// signature scope; it does not invent provider truth beyond this evidence.
type RetirementEvidence struct {
	SchemaVersion            int       `json:"schemaVersion"`
	DeploymentID             string    `json:"deploymentId"`
	Cell                     string    `json:"cell"`
	Environment              string    `json:"environment"`
	Role                     string    `json:"role"`
	Slot                     string    `json:"slot"`
	PreviousAttempt          uint64    `json:"previousAttempt"`
	PreviousGeneration       uint64    `json:"previousGeneration"`
	PreviousResultDigest     string    `json:"previousResultDigest"`
	PriorInstanceOCID        string    `json:"priorInstanceOcid"`
	PriorCreateKey           string    `json:"priorCreateKey"`
	Disposition              string    `json:"disposition"`
	ObservedEvidenceDigest   string    `json:"observedEvidenceDigest"`
	FencingAuthority         string    `json:"fencingAuthority"`
	CoordinatorHandoffDigest string    `json:"coordinatorHandoffDigest,omitzero"`
	ObservedAt               time.Time `json:"observedAt"`
}

func (ledger *Ledger) signedPayload(body []byte, scope BootstrapScope, domain string, current bool) (trust.Envelope, []byte, error) {
	envelope, err := trust.DecodeEnvelope(body)
	if err != nil {
		return trust.Envelope{}, nil, fmt.Errorf("%w: decode signed envelope: %v", ErrInvalidRecord, err)
	}
	expected := trust.Scope{
		Domain: domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: ledger.config.Environment, Role: roleController, Slot: scope.Slot,
	}
	if envelope.Scope != expected {
		return trust.Envelope{}, nil, fmt.Errorf("%w: signed scope mismatch", ErrRecordAuthorization)
	}
	now := ledger.now()
	verify := func() ([]byte, error) {
		if current {
			if payload, err := trust.VerifyCurrent(envelope, expected, ledger.config.TrustRoots, now, ledger.config.TrustPolicy); err == nil {
				return payload, nil
			}
			for _, delegation := range ledger.config.Delegations {
				if payload, err := trust.VerifyDelegatedCurrent(envelope, expected, delegation, now, ledger.config.TrustPolicy); err == nil {
					return payload, nil
				}
			}
		} else {
			if payload, err := trust.VerifyHistorical(envelope, expected, ledger.config.TrustRoots, ledger.config.TrustPolicy); err == nil {
				return payload, nil
			}
			for _, delegation := range ledger.config.Delegations {
				if payload, err := trust.VerifyDelegatedHistorical(envelope, expected, delegation, ledger.config.TrustPolicy); err == nil {
					return payload, nil
				}
			}
		}
		return nil, ErrRecordAuthorization
	}
	payload, err := verify()
	if err != nil {
		return trust.Envelope{}, nil, fmt.Errorf("%w: domain %s", err, domain)
	}
	return envelope, payload, nil
}

func (ledger *Ledger) decodeIntent(scope BootstrapScope, body []byte, current bool) (Intent, trust.Envelope, error) {
	envelope, payload, err := ledger.signedPayload(body, scope, domainBootstrapIntent, current)
	if err != nil {
		return Intent{}, trust.Envelope{}, err
	}
	var intent Intent
	if err := decodeCanonicalPayload(payload, &intent); err != nil || !intent.matches(scope, ledger.config.Environment) {
		return Intent{}, trust.Envelope{}, fmt.Errorf("%w: intent payload does not match signed scope", ErrInvalidRecord)
	}
	if err := validateIntent(intent); err != nil {
		return Intent{}, trust.Envelope{}, err
	}
	if !intent.CreatedAt.Equal(envelope.IssuedAt) {
		return Intent{}, trust.Envelope{}, fmt.Errorf("%w: signed creation time differs from envelope issue time", ErrInvalidRecord)
	}
	if intent.RegionIntentGeneration != ledger.config.InitialRegionIntentGeneration ||
		intent.RegionIntentDigest != ledger.config.InitialRegionIntentSHA256 {
		return Intent{}, trust.Envelope{}, fmt.Errorf("%w: signed intent does not match the anchor-pinned initial region intent", ErrRecordAuthorization)
	}
	return intent, envelope, nil
}

func (ledger *Ledger) decodeResult(scope BootstrapScope, body []byte, current bool) (Result, error) {
	envelope, payload, err := ledger.signedPayload(body, scope, domainBootstrapResult, current)
	if err != nil {
		return Result{}, err
	}
	var result Result
	if err := decodeCanonicalPayload(payload, &result); err != nil || !result.matches(scope, ledger.config.Environment) {
		return Result{}, fmt.Errorf("%w: result payload does not match signed scope", ErrInvalidRecord)
	}
	if result.SchemaVersion != 1 || result.Mode != IntentModeManaged && result.Mode != IntentModeExternalSeed ||
		result.Attempt == 0 || result.Generation == 0 || result.RegionIntentGeneration == 0 || !validDigest(result.IntentDigest) ||
		!isOCID(result.InstanceOCID, "instance") || result.ETag == "" || !validOCIRegion(result.OCIRegion) ||
		!isOCID(result.CompartmentOCID, "compartment") || !isOCID(result.ImageOCID, "image") || result.Shape == "" ||
		!validDigest(result.ObservedProfileDigest) || !createTokenPattern.MatchString(result.CreateKey) || result.ObservedAt.IsZero() ||
		result.ObservedAt.Location() != time.UTC {
		return Result{}, fmt.Errorf("%w: result omits positive OCI identity or observation", ErrInvalidRecord)
	}
	if result.Mode == IntentModeManaged && (!validDigest(result.PeerReceiptDigest) || result.SeedReceiptDigest != "") ||
		result.Mode == IntentModeExternalSeed && (result.PeerReceiptDigest != "" || !validDigest(result.SeedReceiptDigest)) {
		return Result{}, fmt.Errorf("%w: result receipt binding does not match its mode", ErrInvalidRecord)
	}
	if result.ObservedAt.After(envelope.IssuedAt.Add(ledger.config.TrustPolicy.ClockSkew)) {
		return Result{}, fmt.Errorf("%w: result observation time is after its signed issue time", ErrInvalidRetryClock)
	}
	return result, nil
}

func (ledger *Ledger) decodeHead(scope BootstrapScope, body []byte, current bool) (SlotHead, error) {
	_, payload, err := ledger.signedPayload(body, scope, domainBootstrapHead, current)
	if err != nil {
		return SlotHead{}, err
	}
	var head SlotHead
	if err := decodeCanonicalPayload(payload, &head); err != nil || !head.matches(scope, ledger.config.Environment) {
		return SlotHead{}, fmt.Errorf("%w: HEAD payload does not match signed scope", ErrInvalidRecord)
	}
	if head.SchemaVersion != 1 || head.Attempt == 0 || head.Generation == 0 || !validDigest(head.IntentDigest) ||
		(head.ResultDigest != "" && !validDigest(head.ResultDigest)) {
		return SlotHead{}, fmt.Errorf("%w: malformed slot HEAD", ErrInvalidRecord)
	}
	if head.CandidateDigest != "" && !validDigest(head.CandidateDigest) ||
		head.PreviousCandidateDigest != "" && !validDigest(head.PreviousCandidateDigest) {
		return SlotHead{}, fmt.Errorf("%w: malformed candidate binding in slot HEAD", ErrInvalidRecord)
	}
	if head.Attempt == 1 {
		if head.Generation != 1 || head.PreviousAttempt != 0 || head.PreviousGeneration != 0 ||
			head.PreviousIntentDigest != "" || head.PreviousResultDigest != "" ||
			head.PreviousCandidateDigest != "" || head.RetirementDigest != "" {
			return SlotHead{}, fmt.Errorf("%w: initial slot HEAD has predecessor fields", ErrInvalidRecord)
		}
	} else if head.PreviousAttempt+1 != head.Attempt || head.PreviousGeneration+1 != head.Generation ||
		!validDigest(head.PreviousIntentDigest) || !validDigest(head.PreviousResultDigest) || !validDigest(head.RetirementDigest) {
		return SlotHead{}, fmt.Errorf("%w: advanced slot HEAD has invalid predecessor fields", ErrInvalidRecord)
	}
	return head, nil
}

func (ledger *Ledger) decodeManagedPeerCandidate(scope BootstrapScope, body []byte,
	current bool,
) (ManagedPeerCandidate, trust.Envelope, error) {
	envelope, payload, err := ledger.signedPayload(body, scope, domainBootstrapCandidate, current)
	if err != nil {
		return ManagedPeerCandidate{}, trust.Envelope{}, err
	}
	var candidate ManagedPeerCandidate
	if err := decodeCanonicalPayload(payload, &candidate); err != nil || !candidate.matches(scope, ledger.config.Environment) ||
		candidate.SchemaVersion != 1 || candidate.Attempt == 0 || candidate.Generation == 0 ||
		!validDigest(candidate.IntentDigest) || !createTokenPattern.MatchString(candidate.CreateKey) ||
		!validDigest(candidate.FounderPlanSHA256) || !validDigest(candidate.PeerRowDigest) ||
		!validDigest(candidate.ManifestDigest) || !validDigest(candidate.LaunchProfileDigest) ||
		!isOCID(candidate.InstanceOCID, "instance") {
		return ManagedPeerCandidate{}, trust.Envelope{}, fmt.Errorf("%w: managed-peer candidate is malformed or outside its signed scope", ErrInvalidRecord)
	}
	return candidate, envelope, nil
}

func (candidate ManagedPeerCandidate) matches(scope BootstrapScope, environment string) bool {
	return candidate.DeploymentID == scope.DeploymentID && candidate.Cell == scope.Cell &&
		candidate.Environment == environment && candidate.Role == roleController && candidate.Slot == scope.Slot
}

func validateManagedPeerCandidateForIntent(candidate ManagedPeerCandidate, intent Intent, intentDigest,
	founderPlanDigest, peerRowDigest, manifestDigest string,
) error {
	if intent.Mode != IntentModeManaged || intent.SchemaVersion != 1 || candidate.DeploymentID != intent.DeploymentID ||
		candidate.Cell != intent.Cell || candidate.Environment != intent.Environment || candidate.Role != intent.Role ||
		candidate.Slot != intent.Slot || candidate.Attempt != intent.Attempt || candidate.Generation != intent.Generation ||
		candidate.IntentDigest != intentDigest || candidate.CreateKey != intent.CreateKey ||
		candidate.FounderPlanSHA256 != intent.FounderPlanSHA256 || candidate.FounderPlanSHA256 != founderPlanDigest ||
		candidate.PeerRowDigest != intent.PeerRowDigest || candidate.PeerRowDigest != peerRowDigest ||
		candidate.ManifestDigest != intent.ManifestDigest || candidate.ManifestDigest != manifestDigest ||
		candidate.LaunchProfileDigest != intent.LaunchRequestDigest {
		return fmt.Errorf("%w: managed-peer candidate does not match the pinned launch intent", ErrRecordAuthorization)
	}
	return nil
}

func (ledger *Ledger) decodeManagedPeerProgress(scope BootstrapScope, body []byte,
	current bool,
) (ManagedPeerProgress, trust.Envelope, error) {
	envelope, payload, err := ledger.signedPayload(body, scope, domainBootstrapProgress, current)
	if err != nil {
		return ManagedPeerProgress{}, trust.Envelope{}, err
	}
	var progress ManagedPeerProgress
	if err := decodeCanonicalPayload(payload, &progress); err != nil || !progress.matches(scope, ledger.config.Environment) ||
		progress.SchemaVersion != 1 || progress.Attempt == 0 || progress.Generation == 0 || progress.Sequence == 0 ||
		!validDigest(progress.CandidateDigest) {
		return ManagedPeerProgress{}, trust.Envelope{}, fmt.Errorf("%w: managed-peer progress is malformed or outside its signed scope", ErrInvalidRecord)
	}
	switch progress.Phase {
	case ManagedPeerProgressCandidate:
		if progress.PendingProofKind != "" || progress.PendingProofDigest != "" || len(progress.PendingProofWire) != 0 {
			return ManagedPeerProgress{}, trust.Envelope{}, fmt.Errorf("%w: candidate progress cannot stage proof bytes", ErrInvalidRecord)
		}
	case ManagedPeerProgressReceipt, ManagedPeerProgressResult:
		wantKind := "receipt"
		if progress.Phase == ManagedPeerProgressResult {
			wantKind = "result"
		}
		if progress.PendingProofKind != wantKind || !validDigest(progress.PendingProofDigest) ||
			len(progress.PendingProofWire) == 0 || len(progress.PendingProofWire) > maxLedgerRecordBytes ||
			objectDigest(progress.PendingProofWire) != progress.PendingProofDigest {
			return ManagedPeerProgress{}, trust.Envelope{}, fmt.Errorf("%w: staged progress proof is incomplete or has a mismatched digest", ErrInvalidRecord)
		}
	default:
		return ManagedPeerProgress{}, trust.Envelope{}, fmt.Errorf("%w: unknown managed-peer progress phase %q", ErrInvalidRecord, progress.Phase)
	}
	return progress, envelope, nil
}

func (progress ManagedPeerProgress) matches(scope BootstrapScope, environment string) bool {
	return progress.DeploymentID == scope.DeploymentID && progress.Cell == scope.Cell &&
		progress.Environment == environment && progress.Role == roleController && progress.Slot == scope.Slot
}

func (ledger *Ledger) decodeRetirement(scope BootstrapScope, body []byte, current bool) (RetirementEvidence, trust.Envelope, error) {
	envelope, payload, err := ledger.signedPayload(body, scope, domainSlotRetirement, current)
	if err != nil {
		if envelope, payload, err = ledger.signedPayload(body, scope, domainSeedHandoff, current); err != nil {
			return RetirementEvidence{}, trust.Envelope{}, err
		}
	}
	var evidence RetirementEvidence
	if err := decodeCanonicalPayload(payload, &evidence); err != nil || !evidence.matches(scope, ledger.config.Environment) {
		return RetirementEvidence{}, trust.Envelope{}, fmt.Errorf("%w: retirement payload does not match signed scope", ErrRetirementInvalid)
	}
	now := ledger.now()
	if evidence.SchemaVersion != 1 || evidence.PreviousAttempt == 0 || evidence.PreviousGeneration == 0 ||
		!validDigest(evidence.PreviousResultDigest) || !isOCID(evidence.PriorInstanceOCID, "instance") ||
		evidence.PriorCreateKey == "" || !validDigest(evidence.ObservedEvidenceDigest) || evidence.FencingAuthority == "" ||
		evidence.ObservedAt.IsZero() || evidence.ObservedAt.Location() != time.UTC || evidence.ObservedAt.After(now.Add(ledger.config.TrustPolicy.ClockSkew)) ||
		current && now.Sub(evidence.ObservedAt) > ledger.config.TrustPolicy.MaxLifetime {
		return RetirementEvidence{}, trust.Envelope{}, ErrRetirementInvalid
	}
	if envelope.Scope.Domain == domainSeedHandoff {
		if evidence.Disposition != "seed-handoff" || !validDigest(evidence.CoordinatorHandoffDigest) {
			return RetirementEvidence{}, trust.Envelope{}, ErrRetirementInvalid
		}
	} else if evidence.Disposition != "instance-retired" || evidence.CoordinatorHandoffDigest != "" {
		return RetirementEvidence{}, trust.Envelope{}, ErrRetirementInvalid
	}
	return evidence, envelope, nil
}

func decodeCanonicalPayload(data []byte, destination any) error {
	if err := protocol.DecodeStrict(data, destination, maxLedgerRecordBytes); err != nil {
		return err
	}
	encoded, err := protocol.EncodeJSON(destination)
	if err != nil {
		return err
	}
	if !bytes.Equal(encoded, data) {
		return errors.New("bootstrap payload is not deterministic JSON")
	}
	return nil
}

func validateIntent(intent Intent) error {
	if intent.SchemaVersion != 1 || intent.Attempt == 0 || intent.Generation == 0 || intent.RegionIntentGeneration == 0 ||
		!validDigest(intent.ManifestDigest) || !validDigest(intent.ReleaseReceiptDigest) || !isOCID(intent.ImageOCID, "image") ||
		!validDigest(intent.RegionIntentDigest) || !validDigest(intent.LaunchRequestDigest) || !createTokenPattern.MatchString(intent.CreateKey) ||
		intent.CreatedAt.IsZero() || intent.CreatedAt.Location() != time.UTC ||
		!validOCIRegion(intent.OCIRegion) || !isOCID(intent.CompartmentOCID, "compartment") || intent.AvailabilityDomain == "" ||
		len(intent.AvailabilityDomain) > 128 || !regexp.MustCompile(`^FAULT-DOMAIN-[1-3]$`).MatchString(intent.FaultDomain) ||
		!isOCID(intent.SubnetOCID, "subnet") || len(intent.NetworkSecurityGroupIDs) > 16 || intent.Shape == "" || len(intent.Shape) > 128 ||
		!ledgerIDPattern.MatchString(intent.Node) {
		return fmt.Errorf("%w: intent omits a complete bounded OCI launch identity", ErrInvalidRecord)
	}
	if intent.Attempt == 1 && intent.RetirementDigest != "" ||
		intent.Attempt > 1 && !validDigest(intent.RetirementDigest) {
		return fmt.Errorf("%w: intent retirement binding does not match its attempt", ErrInvalidRecord)
	}
	switch intent.Mode {
	case IntentModeManaged:
		if !createTokenPattern.MatchString(intent.RetryToken) || intent.ReviewedPlanDigest != "" ||
			!validDigest(intent.FounderPlanSHA256) || !validDigest(intent.PeerRowDigest) {
			return fmt.Errorf("%w: managed intent requires a retry token and founder-plan/peer-row pins", ErrInvalidRecord)
		}
	case IntentModeExternalSeed:
		if intent.RetryToken != "" || !validDigest(intent.ReviewedPlanDigest) ||
			intent.FounderPlanSHA256 != "" || intent.PeerRowDigest != "" {
			return fmt.Errorf("%w: external seed intent requires a reviewed plan digest and omits the OCI retry token", ErrInvalidRecord)
		}
	default:
		return fmt.Errorf("%w: unknown bootstrap intent mode %q", ErrInvalidRecord, intent.Mode)
	}
	cellRegion, err := oci.Region(intent.Cell).OCIRegion()
	if err != nil || cellRegion != intent.OCIRegion {
		return fmt.Errorf("%w: OCI region does not match the signed controller cell", ErrInvalidRecord)
	}
	seen := make(map[string]struct{}, len(intent.NetworkSecurityGroupIDs))
	for _, id := range intent.NetworkSecurityGroupIDs {
		if !isOCID(id, "networksecuritygroup") {
			return fmt.Errorf("%w: invalid network security group identity", ErrInvalidRecord)
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("%w: duplicate network security group identity", ErrInvalidRecord)
		}
		seen[id] = struct{}{}
	}
	if !slices.IsSorted(intent.NetworkSecurityGroupIDs) {
		return fmt.Errorf("%w: network security group identities must be sorted", ErrInvalidRecord)
	}
	profile := LaunchProfile{
		Slot: intent.Slot, CompartmentOCID: intent.CompartmentOCID,
		AvailabilityDomain: intent.AvailabilityDomain, FaultDomain: intent.FaultDomain,
		SubnetOCID: intent.SubnetOCID, NetworkSecurityGroupOCIDs: intent.NetworkSecurityGroupIDs,
		Shape: intent.Shape,
	}
	if err := profile.validate(); err != nil {
		return fmt.Errorf("%w: intent launch profile is invalid: %v", ErrInvalidRecord, err)
	}
	profileDigest, err := launchProfileDigest(profile)
	if err != nil || profileDigest != intent.LaunchRequestDigest {
		return fmt.Errorf("%w: launch request digest does not match its canonical profile", ErrInvalidRecord)
	}
	return nil
}

func (intent Intent) matches(scope BootstrapScope, environment string) bool {
	return intent.DeploymentID == scope.DeploymentID && intent.Cell == scope.Cell && intent.Environment == environment &&
		intent.Role == roleController && intent.Slot == scope.Slot
}

func (result Result) matches(scope BootstrapScope, environment string) bool {
	return result.DeploymentID == scope.DeploymentID && result.Cell == scope.Cell && result.Environment == environment &&
		result.Role == roleController && result.Slot == scope.Slot
}

func (head SlotHead) matches(scope BootstrapScope, environment string) bool {
	return head.DeploymentID == scope.DeploymentID && head.Cell == scope.Cell && head.Environment == environment &&
		head.Role == roleController && head.Slot == scope.Slot
}

func (evidence RetirementEvidence) matches(scope BootstrapScope, environment string) bool {
	return evidence.DeploymentID == scope.DeploymentID && evidence.Cell == scope.Cell && evidence.Environment == environment &&
		evidence.Role == roleController && evidence.Slot == scope.Slot
}

func validDigest(value string) bool { return sha256DigestPattern.MatchString(value) }

func validOCIRegion(value string) bool {
	return catalog.IsOCIRegion(value)
}

func (ledger *Ledger) now() time.Time {
	if ledger.config.VerificationNow != nil {
		return ledger.config.VerificationNow().UTC()
	}
	return time.Now().UTC()
}

func objectDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func sameHead(a, b SlotHead) bool { return a == b }

func sameIntent(a, b Intent) bool {
	left, _ := protocol.EncodeJSON(a)
	right, _ := protocol.EncodeJSON(b)
	return bytes.Equal(left, right)
}

func sameResult(a, b Result) bool { return a == b }

func validIntentClock(intent Intent, record StoredRecord, tolerance time.Duration) error {
	if err := CheckRetryWindow(record); err != nil {
		return err
	}
	delta := record.LastModified.Sub(intent.CreatedAt)
	if delta < 0 {
		delta = -delta
	}
	if delta > tolerance+time.Second {
		return ErrInvalidRetryClock
	}
	return nil
}
