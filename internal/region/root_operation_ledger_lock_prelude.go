package region

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const rootOperationLedgerLockDomain = "terrascale.foundation.ledger-lock"
const rootOperationLedgerLockPurpose = "initial-home-existing-ledger-rule-lock-v1"
const rootOperationLedgerLockLifetime = 23 * time.Hour
const rootOperationLedgerLockDelay = 15 * 24 * time.Hour
const rootOperationLedgerRetentionDays = 35
const rootOperationLedgerLockLimit = 16 << 10

var ErrFoundationLedgerProtectionPending = errors.New("foundation ledger protection is scheduled; final foundation authority is pending")

// RootOperationLedgerLockPrelude permits one exact existing-rule transition.
// It grants no rule creation, object write, namespace birth or journal authority.
type RootOperationLedgerLockPrelude struct {
	SchemaVersion        int                     `json:"schemaVersion"`
	Purpose              string                  `json:"purpose"`
	InstallationID       string                  `json:"installationId"`
	DeploymentID         string                  `json:"deploymentId"`
	ClusterID            string                  `json:"clusterId"`
	TenancyID            string                  `json:"tenancyId"`
	Cell                 string                  `json:"cell"`
	OperatorID           string                  `json:"operatorId"`
	Storage              bootstrap.StorageDomain `json:"storage"`
	CompartmentID        string                  `json:"compartmentId"`
	BucketID             string                  `json:"bucketId"`
	RuleID               string                  `json:"ruleId"`
	OriginalETag         string                  `json:"originalEtag"`
	OriginalDurationDays int64                   `json:"originalDurationDays"`
	OriginalLockedAt     time.Time               `json:"originalLockedAt,omitzero"`
	IssuedAt             time.Time               `json:"issuedAt"`
	DispatchDeadline     time.Time               `json:"dispatchDeadline"`
	LockedAt             time.Time               `json:"lockedAt"`
	DurationDays         int64                   `json:"durationDays"`
	RequestSHA256        string                  `json:"requestSha256"`
}

func (p RootOperationLedgerLockPrelude) validate() error {
	validID := func(value, kind string) bool {
		return strings.HasPrefix(value, "ocid1."+kind+".oc1..") && len(value) <= 255 && !strings.ContainsAny(value, "\x00 \t\r\n'\"")
	}
	if p.SchemaVersion != 1 || p.Purpose != rootOperationLedgerLockPurpose || !entityid.Valid(p.InstallationID) ||
		p.DeploymentID != entityid.Derive("foundation-deployment", p.InstallationID, "GRU") ||
		p.ClusterID != entityid.Derive("foundation-cluster", p.InstallationID, "GRU") || p.Cell != "GRU" ||
		!validID(p.TenancyID, "tenancy") || !validID(p.OperatorID, "user") || !sourceCompartmentPattern.MatchString(p.CompartmentID) ||
		p.Storage.Validate() != nil || p.Storage.HeadBucket != foundationDiscoveryBucket || p.Storage.LedgerBucket != "gru-1-ledger" ||
		!strings.HasPrefix(p.Storage.LedgerKMSKeyOCID, "ocid1.key.oc1."+foundationHomeRegion+".") ||
		!validAuxiliaryID("ledger_bucket", p.BucketID, foundationHomeRegion) || p.RuleID == "" || len(p.RuleID) > 512 ||
		strings.ContainsAny(p.RuleID, "/\\\x00\r\n") || p.OriginalETag == "" || len(p.OriginalETag) > 255 || strings.ContainsAny(p.OriginalETag, "\x00\r\n") ||
		p.OriginalDurationDays != rootOperationLedgerRetentionDays || p.DurationDays != rootOperationLedgerRetentionDays || !p.OriginalLockedAt.IsZero() ||
		p.IssuedAt.IsZero() || p.IssuedAt.Location() != time.UTC || p.IssuedAt.Nanosecond() != 0 ||
		!p.DispatchDeadline.Equal(p.IssuedAt.Add(rootOperationLedgerLockLifetime)) || p.DispatchDeadline.Location() != time.UTC ||
		!p.LockedAt.Equal(p.IssuedAt.Add(rootOperationLedgerLockDelay)) || p.LockedAt.Location() != time.UTC {
		return errors.New("ledger lock prelude lacks its exact original existing rule, operator, storage or fixed transition")
	}
	_, digest, err := rootOperationLedgerLockRequest(p)
	if err != nil || p.RequestSHA256 != digest {
		return errors.Join(errors.New("ledger lock prelude differs from its exact SDK update request"), err)
	}
	return nil
}

func (p RootOperationLedgerLockPrelude) scope() trust.Scope {
	return trust.Scope{Domain: rootOperationLedgerLockDomain, DeploymentID: p.DeploymentID, Cell: "GRU", Environment: "production", Role: "foundation", Slot: p.ClusterID}
}

func checkLedgerLockRootFloor(p RootOperationLedgerLockPrelude, chain trust.RootChain, genesis trust.Keyring) error {
	directory, err := openFoundationFloorDirectory()
	if err != nil {
		return err
	}
	defer directory.Close()
	digest := sha256.Sum256([]byte(p.TenancyID))
	floor, found, err := readFoundationFloor(int(directory.Fd()), hex.EncodeToString(digest[:])+".json", p.TenancyID, genesis)
	if err != nil || !found {
		return err
	}
	adopted, err := trust.DecodeRootChain(floor.ChainWire)
	if err != nil {
		return err
	}
	if floor.InstallationID != p.InstallationID || floor.DeploymentID != p.DeploymentID || floor.ClusterID != p.ClusterID || !chain.Extends(adopted) {
		return errors.New("ledger lock prelude differs from the independently adopted foundation lineage")
	}
	return nil
}

func verifyRootOperationLedgerLockPrelude(ctx context.Context, bundle RetainedFoundation, genesis trust.Keyring) (RootOperationLedgerLockPrelude, error) {
	if ctx == nil || len(genesis) == 0 || len(bundle.GrantWire) != 0 || len(bundle.AnchorWire) != 0 ||
		len(bundle.LedgerProtectionWire) == 0 || len(bundle.LedgerProtectionWire) > rootOperationLedgerLockLimit ||
		len(bundle.RootChainWire) == 0 || len(bundle.RootChainWire) > trust.MaxRootChainBytes {
		return RootOperationLedgerLockPrelude{}, errors.New("ledger lock prelude must be a separate bounded signed artifact without final grant or anchor")
	}
	if err := ctx.Err(); err != nil {
		return RootOperationLedgerLockPrelude{}, err
	}
	envelope, err := trust.DecodeEnvelope(bundle.LedgerProtectionWire)
	if err != nil {
		return RootOperationLedgerLockPrelude{}, err
	}
	var p RootOperationLedgerLockPrelude
	if err := json.Unmarshal(envelope.Payload, &p, json.RejectUnknownMembers(true)); err != nil {
		return RootOperationLedgerLockPrelude{}, err
	}
	if err := p.validate(); err != nil {
		return RootOperationLedgerLockPrelude{}, err
	}
	chain, err := trust.DecodeRootChain(bundle.RootChainWire)
	if err != nil {
		return RootOperationLedgerLockPrelude{}, err
	}
	lineage, err := trust.VerifyRootChain(genesis, foundationChainIdentity(p.DeploymentID), chain)
	if err != nil {
		return RootOperationLedgerLockPrelude{}, err
	}
	if _, err := trust.VerifyCurrent(envelope, p.scope(), lineage.Current, time.Now(), trust.Policy{MaxLifetime: rootOperationLedgerLockLifetime}); err != nil {
		return RootOperationLedgerLockPrelude{}, err
	}
	if bundle.TenancyID != p.TenancyID || bundle.Namespace != p.Storage.Namespace || !envelope.IssuedAt.Equal(p.IssuedAt) ||
		!envelope.ExpiresAt.Equal(p.DispatchDeadline) {
		return RootOperationLedgerLockPrelude{}, errors.New("ledger lock prelude envelope or locator differs from its original signed operation")
	}
	if err := checkLedgerLockRootFloor(p, chain, genesis); err != nil {
		return RootOperationLedgerLockPrelude{}, err
	}
	return p, ctx.Err()
}

type verifiedRootOperationLedgerLockPrelude struct {
	purpose  RootOperationLedgerLockPrelude
	original context.Context
	expires  time.Time
	bundle   RetainedFoundation
	genesis  trust.Keyring
}

func (operation verifiedRootOperationLedgerLockPrelude) guard(ctx context.Context) error {
	if ctx == nil || operation.original == nil || operation.expires.IsZero() || !time.Now().Before(operation.expires) {
		return errors.New("ledger lock operation has no current original finite call")
	}
	if err := operation.original.Err(); err != nil {
		return err
	}
	deadline, finite := operation.original.Deadline()
	if !finite || deadline.After(operation.expires) {
		return errors.New("ledger lock operation lost its original deadline")
	}
	p, err := verifyRootOperationLedgerLockPrelude(ctx, operation.bundle, operation.genesis)
	if err != nil {
		return err
	}
	if p != operation.purpose {
		return errors.New("ledger lock operation changed from its original signed purpose")
	}
	return ctx.Err()
}

// SignFoundationPreparation uses the existing offline ceremony for the current
// preparation stage; a prelude can never bypass final ready signing checks.
func SignFoundationPreparation(ctx context.Context, prepared FoundationPreparation, chainWire []byte, genesis trust.Keyring, private ed25519.PrivateKey, now time.Time) (RetainedFoundation, error) {
	if ctx == nil {
		return RetainedFoundation{}, errors.New("foundation signing requires its original context")
	}
	if err := ctx.Err(); err != nil {
		return RetainedFoundation{}, err
	}
	if prepared.LedgerProtection == nil {
		return SignFoundationDiscovery(ctx, prepared.Grant, prepared.Anchor, chainWire, genesis, private, now, now.Add(bootstrap.DefaultBootstrapAnchorValidity))
	}
	if !reflect.ValueOf(prepared.Grant).IsZero() || !reflect.ValueOf(prepared.Anchor).IsZero() {
		return RetainedFoundation{}, errors.New("ledger protection preparation cannot carry a final foundation candidate")
	}
	p := *prepared.LedgerProtection
	if err := p.validate(); err != nil {
		return RetainedFoundation{}, err
	}
	if now.Before(p.IssuedAt) || !now.Before(p.DispatchDeadline) {
		return RetainedFoundation{}, errors.New("ledger protection preparation is outside its original dispatch interval")
	}
	chain, err := trust.DecodeRootChain(chainWire)
	if err != nil {
		return RetainedFoundation{}, err
	}
	lineage, err := trust.VerifyRootChain(genesis, foundationChainIdentity(p.DeploymentID), chain)
	if err != nil {
		return RetainedFoundation{}, err
	}
	if len(private) != ed25519.PrivateKeySize {
		return RetainedFoundation{}, errors.New("foundation signing requires the existing offline root key")
	}
	public := private.Public().(ed25519.PublicKey)
	id, err := trust.KeyID(public)
	if err != nil || !bytes.Equal(lineage.Current[id], public) {
		return RetainedFoundation{}, errors.New("foundation signing key is outside the current root lineage")
	}
	if err := checkLedgerLockRootFloor(p, chain, genesis); err != nil {
		return RetainedFoundation{}, err
	}
	payload, err := trust.EncodePayload(p)
	if err != nil {
		return RetainedFoundation{}, err
	}
	envelope, err := trust.Sign(payload, p.scope(), p.IssuedAt, p.DispatchDeadline, private)
	if err != nil {
		return RetainedFoundation{}, err
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil || len(wire) > rootOperationLedgerLockLimit {
		return RetainedFoundation{}, errors.Join(errors.New("ledger protection prelude exceeds its document bound"), err)
	}
	bundle := RetainedFoundation{TenancyID: p.TenancyID, Namespace: p.Storage.Namespace, RootChainWire: bytes.Clone(chainWire), LedgerProtectionWire: wire}
	if _, err := verifyRootOperationLedgerLockPrelude(ctx, bundle, genesis); err != nil {
		return RetainedFoundation{}, err
	}
	return bundle, nil
}
