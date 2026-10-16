package bootstrapstart

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

var (
	ErrExternalSeedRecord = errors.New("external seed signed record authority is invalid")
	externalSeedDigestRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	externalSeedCreateRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
)

type ExternalSeedReservationRequest struct {
	Identity           BakedIdentity
	Anchor             bootstrap.VerifiedBootstrapAnchor
	Manifest           bootstrap.StartupAuthority
	ReviewedPlanSHA256 string
	CreateIdentity     string
	LedgerPrivate      ed25519.PrivateKey
	Now                time.Time
	ExpiresAt          time.Time
}

type ExternalSeedReservationRecords struct {
	IntentWire      []byte
	InitialHeadWire []byte
}

type ExternalSeedCompletionRequest struct {
	Identity          BakedIdentity
	Anchor            bootstrap.VerifiedBootstrapAnchor
	Manifest          bootstrap.StartupAuthority
	Roots             trust.Keyring
	State             bootstrap.SlotState
	Observation       InstanceObservation
	ObservedAt        time.Time
	ExpectedPrivateIP string
	RootPrivate       ed25519.PrivateKey
	LedgerPrivate     ed25519.PrivateKey
	ReuseReceiptWire  []byte
	Now               time.Time
	ExpiresAt         time.Time
}

type ExternalSeedCompletionRecords struct {
	ReceiptWire       []byte
	ResultWire        []byte
	CompletedHeadWire []byte
}

func externalSeedDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func signExternalSeedRecord(value any, domain, slot string, identity BakedIdentity,
	private ed25519.PrivateKey, anchor bootstrap.VerifiedBootstrapAnchor, authority bootstrap.StartupAuthority, now, expiresAt time.Time,
) ([]byte, error) {
	payload, err := trust.EncodePayload(value)
	if err != nil {
		return nil, err
	}
	scope := trust.Scope{Domain: domain, DeploymentID: identity.DeploymentID,
		Cell: string(identity.Cell), Environment: identity.Environment, Role: "controller", Slot: slot}
	envelope, err := trust.Sign(payload, scope, now, expiresAt, private)
	if err != nil {
		return nil, err
	}
	if derived, ok := authority.(bootstrap.DerivedStartupAuthority); ok {
		if err := derived.VerifyLedgerEnvelope(envelope, scope, now); err != nil {
			return nil, err
		}
	} else {
		grant, err := anchor.LedgerDelegation()
		if err != nil {
			return nil, err
		}
		if _, err := trust.VerifyDelegatedCurrent(envelope, scope, grant, now, bootstrap.ManifestTrustPolicy()); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrExternalSeedRecord, err)
		}
	}
	return trust.EncodeEnvelope(envelope)
}

// BuildExternalSeedReservation signs the exact immutable intent and initial
// HEAD that the operator publisher passes to Ledger.ReserveSlot.
func BuildExternalSeedReservation(request ExternalSeedReservationRequest) (ExternalSeedReservationRecords, error) {
	if request.Manifest == nil {
		return ExternalSeedReservationRecords{}, ErrExternalSeedRecord
	}
	anchor := request.Anchor.Anchor()
	manifest := request.Manifest.Manifest()
	if !request.Anchor.IsVerified() || request.Manifest.Digest() == "" ||
		request.Identity.DeploymentID != anchor.DeploymentID || request.Identity.Cell != anchor.Cell ||
		request.Identity.Environment != anchor.Environment || manifest.SeedSlot != manifest.Slot ||
		manifest.DeploymentID != anchor.DeploymentID || manifest.Cell != anchor.Cell ||
		manifest.Environment != anchor.Environment || manifest.OCIRegion != anchor.OCIRegion ||
		!slices.Contains(anchor.ControllerSlots, manifest.SeedSlot) ||
		!externalSeedDigestRE.MatchString(request.ReviewedPlanSHA256) ||
		!externalSeedCreateRE.MatchString(request.CreateIdentity) ||
		manifest.SeedSlot == "" || !request.ExpiresAt.After(request.Now) ||
		len(request.LedgerPrivate) != ed25519.PrivateKeySize {
		return ExternalSeedReservationRecords{}, ErrExternalSeedRecord
	}
	if err := verifyExternalLedgerKey(request.Manifest, request.Anchor, request.LedgerPrivate); err != nil {
		return ExternalSeedReservationRecords{}, err
	}
	profile, ok := request.Manifest.Profile(manifest.SeedSlot)
	if !ok {
		return ExternalSeedReservationRecords{}, ErrExternalSeedRecord
	}
	profileWire, err := trust.EncodePayload(profile)
	if err != nil {
		return ExternalSeedReservationRecords{}, err
	}
	intent := bootstrap.Intent{SchemaVersion: 1, Mode: bootstrap.IntentModeExternalSeed,
		DeploymentID: anchor.DeploymentID, Cell: string(anchor.Cell), Environment: anchor.Environment,
		Role: "controller", Slot: manifest.SeedSlot, Attempt: 1, Generation: 1,
		ManifestDigest: request.Manifest.Digest(), ReleaseReceiptDigest: manifest.ReleaseReceiptSHA256,
		RegionIntentGeneration: anchor.InitialRegionIntentGeneration, ImageOCID: manifest.ImageOCID,
		RegionIntentDigest: anchor.InitialRegionIntentSHA256, LaunchRequestDigest: externalSeedDigest(profileWire),
		ReviewedPlanDigest: request.ReviewedPlanSHA256, CreateKey: request.CreateIdentity,
		CreatedAt: request.Now, OCIRegion: anchor.OCIRegion, CompartmentOCID: profile.CompartmentOCID,
		AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain,
		SubnetOCID: profile.SubnetOCID, NetworkSecurityGroupIDs: slices.Clone(profile.NetworkSecurityGroupOCIDs),
		Shape: profile.Shape, Node: manifest.SeedSlot}
	intentWire, err := signExternalSeedRecord(intent, "bootstrap-intent", manifest.SeedSlot, request.Identity,
		request.LedgerPrivate, request.Anchor, request.Manifest, request.Now, request.ExpiresAt)
	if err != nil {
		return ExternalSeedReservationRecords{}, err
	}
	head := bootstrap.SlotHead{SchemaVersion: 1, DeploymentID: anchor.DeploymentID,
		Cell: string(anchor.Cell), Environment: anchor.Environment, Role: "controller",
		Slot: manifest.SeedSlot, Attempt: 1, Generation: 1, IntentDigest: externalSeedDigest(intentWire)}
	headWire, err := signExternalSeedRecord(head, "bootstrap-slot-head", manifest.SeedSlot, request.Identity,
		request.LedgerPrivate, request.Anchor, request.Manifest, request.Now, request.ExpiresAt)
	if err != nil {
		return ExternalSeedReservationRecords{}, err
	}
	return ExternalSeedReservationRecords{IntentWire: intentWire, InitialHeadWire: headWire}, nil
}

// BuildExternalSeedCompletion signs the root receipt and exact positive result
// for an OCI observation that matches the reserved first seed. ReuseReceiptWire
// keeps an already stored immutable root receipt during a fresh result retry.
func BuildExternalSeedCompletion(request ExternalSeedCompletionRequest) (ExternalSeedCompletionRecords, error) {
	if request.Manifest == nil {
		return ExternalSeedCompletionRecords{}, ErrExternalSeedRecord
	}
	anchor := request.Anchor.Anchor()
	if !request.Anchor.IsVerified() || request.Manifest.Digest() == "" ||
		request.Identity.DeploymentID != anchor.DeploymentID || request.Identity.Cell != anchor.Cell ||
		request.Identity.Environment != anchor.Environment || !request.ExpiresAt.After(request.Now) ||
		request.ObservedAt.IsZero() || request.ObservedAt.Location() != time.UTC ||
		request.ObservedAt.After(request.Now.Add(bootstrap.ManifestClockSkew)) ||
		request.Now.Sub(request.ObservedAt) > bootstrap.ExternalSeedObservationMaxAge ||
		len(request.LedgerPrivate) != ed25519.PrivateKeySize {
		return ExternalSeedCompletionRecords{}, ErrExternalSeedRecord
	}
	if err := verifyExternalLedgerKey(request.Manifest, request.Anchor, request.LedgerPrivate); err != nil {
		return ExternalSeedCompletionRecords{}, err
	}
	facts, err := VerifyExternalSeedObservation(request.Anchor, request.Manifest, request.State,
		request.Observation, request.ExpectedPrivateIP)
	if err != nil {
		return ExternalSeedCompletionRecords{}, err
	}
	receiptWire := slices.Clone(request.ReuseReceiptWire)
	if len(receiptWire) == 0 {
		var envelope trust.Envelope
		var signErr error
		if derived, ok := request.Manifest.(bootstrap.DerivedStartupAuthority); ok {
			envelope, signErr = bootstrap.SignDerivedReceipt(derived, facts, request.Now, request.ExpiresAt, request.LedgerPrivate)
		} else if legacy, ok := request.Manifest.(bootstrap.VerifiedManifest); ok {
			envelope, signErr = bootstrap.SignSeedReceipt(legacy, facts, request.Now, request.ExpiresAt, request.RootPrivate)
		} else {
			return ExternalSeedCompletionRecords{}, ErrExternalSeedRecord
		}
		if signErr != nil {
			return ExternalSeedCompletionRecords{}, signErr
		}
		receiptWire, err = trust.EncodeEnvelope(envelope)
		if err != nil {
			return ExternalSeedCompletionRecords{}, err
		}
	}
	receiptEnvelope, err := trust.DecodeEnvelope(receiptWire)
	if err != nil {
		return ExternalSeedCompletionRecords{}, err
	}
	if _, err := bootstrap.VerifySeedReceipt(receiptEnvelope, request.Manifest, request.Roots,
		facts, request.Now, bootstrap.ManifestTrustPolicy()); err != nil {
		return ExternalSeedCompletionRecords{}, err
	}
	resultExpiresAt := request.ExpiresAt
	if receiptEnvelope.ExpiresAt.Before(resultExpiresAt) {
		resultExpiresAt = receiptEnvelope.ExpiresAt
	}
	profileWire, err := trust.EncodePayload(facts.Profile)
	if err != nil {
		return ExternalSeedCompletionRecords{}, err
	}
	intent := request.State.Intent
	result := bootstrap.Result{SchemaVersion: 1, Mode: bootstrap.IntentModeExternalSeed,
		DeploymentID: intent.DeploymentID, Cell: intent.Cell, Environment: intent.Environment,
		Role: "controller", Slot: intent.Slot, Attempt: intent.Attempt, Generation: intent.Generation,
		RegionIntentGeneration: intent.RegionIntentGeneration,
		IntentDigest:           request.State.IntentRecord.SHA256, InstanceOCID: request.Observation.InstanceOCID,
		ETag: request.Observation.ETag, OCIRegion: intent.OCIRegion,
		CompartmentOCID: request.Observation.CompartmentOCID, ImageOCID: request.Observation.ImageOCID,
		Shape: request.Observation.Shape, ObservedProfileDigest: externalSeedDigest(profileWire),
		SeedReceiptDigest: externalSeedDigest(receiptWire), CreateKey: intent.CreateKey,
		ObservedAt: request.ObservedAt}
	resultWire, err := signExternalSeedRecord(result, "bootstrap-result", intent.Slot, request.Identity,
		request.LedgerPrivate, request.Anchor, request.Manifest, request.Now, resultExpiresAt)
	if err != nil {
		return ExternalSeedCompletionRecords{}, err
	}
	head := request.State.Head
	head.ResultDigest = externalSeedDigest(resultWire)
	headWire, err := signExternalSeedRecord(head, "bootstrap-slot-head", intent.Slot, request.Identity,
		request.LedgerPrivate, request.Anchor, request.Manifest, request.Now, resultExpiresAt)
	if err != nil {
		return ExternalSeedCompletionRecords{}, err
	}
	return ExternalSeedCompletionRecords{ReceiptWire: receiptWire, ResultWire: resultWire,
		CompletedHeadWire: headWire}, nil
}

func verifyExternalLedgerKey(authority bootstrap.StartupAuthority, anchor bootstrap.VerifiedBootstrapAnchor, private ed25519.PrivateKey) error {
	if len(private) != ed25519.PrivateKeySize {
		return ErrExternalSeedRecord
	}
	if derived, ok := authority.(bootstrap.DerivedStartupAuthority); ok {
		if derived.AnchorDigest() != anchor.Digest() {
			return ErrExternalSeedRecord
		}
		return derived.VerifyLedgerKey(private.Public().(ed25519.PublicKey))
	}
	grant, err := anchor.LedgerDelegation()
	if err != nil {
		return err
	}
	keyID, err := trust.KeyID(private.Public().(ed25519.PublicKey))
	if err != nil || keyID != grant.SubjectKeyID() {
		return ErrExternalSeedRecord
	}
	return nil
}
