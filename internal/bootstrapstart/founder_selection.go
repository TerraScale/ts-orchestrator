package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const (
	FounderSelectionDomain   = "terrascale.bootstrap.founder-selection"
	founderSelectionMaxBytes = 4096
	founderObjectMaxBytes    = 64 << 10
)

var ErrFounderSelection = errors.New("current founder selection is invalid or unavailable")

// FounderSelection is a root-signed pointer, never a source of storage scope.
// The offline publisher publishes digest-addressed immutable objects first,
// then CAS-updates this one exact mutable object with increasing generation.
type FounderSelection struct {
	SchemaVersion int                  `json:"schemaVersion"`
	DeploymentID  string               `json:"deploymentId"`
	Cell          string               `json:"cell"`
	Environment   string               `json:"environment"`
	Generation    uint64               `json:"generation"`
	PlanSHA256    string               `json:"planSha256"`
	AnchorSHA256  string               `json:"anchorSha256"`
	Manifests     []FounderManifestPin `json:"manifests"`
}

type FounderManifestPin struct {
	Slot   string `json:"slot"`
	SHA256 string `json:"sha256"`
}

// FounderSelectionObjectReader is intentionally GET-only and exact-key-only.
type FounderSelectionObjectReader interface {
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
}

// CurrentFounderAuthority is a coherent, currently selected signed snapshot.
// SelectionSHA256 identifies the exact root-signed selector used by the caller.
type CurrentFounderAuthority struct {
	SelectionGeneration uint64
	SelectionSHA256     string
	SelectionExpiresAt  time.Time
	Plan                bootstrap.VerifiedFounderPlan
	Anchor              bootstrap.VerifiedBootstrapAnchor
	PlanWire            []byte
	AnchorWire          []byte
	ManifestWires       map[string][]byte
}

// CurrentFounderAuthorityReader uses only the accepted seed's baked anchor
// storage domain for discovery. It does not accept object names or endpoints
// from IMDS, the selector, a founder plan, or a caller.
type CurrentFounderAuthorityReader struct {
	baked             BakedInputs
	accepted          AcceptedInstall
	acceptedClusterID string
	domain            bootstrap.StorageDomain
	objects           FounderSelectionObjectReader
	floor             *FounderSelectionFloorStore
}

func NewCurrentFounderAuthorityReader(baked BakedInputs, accepted AcceptedInstall,
	objects FounderSelectionObjectReader, floor *FounderSelectionFloorStore,
) (*CurrentFounderAuthorityReader, error) {
	if objects == nil || floor == nil || accepted.validate() != nil ||
		accepted.DeploymentID != baked.Identity.DeploymentID || accepted.Cell != string(baked.Identity.Cell) ||
		len(baked.Roots) == 0 {
		return nil, ErrFounderSelection
	}
	envelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return nil, fmt.Errorf("%w: decode baked anchor: %v", ErrFounderSelection, err)
	}
	anchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(envelope, baked.Roots,
		baked.Identity.AnchorExpectation(), accepted.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || anchor.Digest() != accepted.AnchorSHA256 ||
		!slices.Contains(anchor.Anchor().ControllerSlots, accepted.Slot) {
		return nil, fmt.Errorf("%w: accepted seed does not match baked anchor: %v", ErrFounderSelection, err)
	}
	roots := make(trust.Keyring, len(baked.Roots))
	for keyID, public := range baked.Roots {
		roots[keyID] = bytes.Clone(public)
	}
	baked.Roots = roots
	baked.AnchorWire = bytes.Clone(baked.AnchorWire)
	return &CurrentFounderAuthorityReader{
		baked: baked, accepted: accepted, acceptedClusterID: anchor.Anchor().ClusterID,
		domain:  anchor.Anchor().StorageDomain,
		objects: objects, floor: floor,
	}, nil
}

// NewOCICurrentFounderAuthorityReader creates the production exact-key reader
// with the same pinned instance-principal transport as admission. Constructing
// it does not read a founder selector or authorize a cloud mutation.
func NewOCICurrentFounderAuthorityReader(baked BakedInputs, accepted AcceptedInstall,
	floor *FounderSelectionFloorStore,
) (*CurrentFounderAuthorityReader, error) {
	if floor == nil || accepted.validate() != nil {
		return nil, ErrFounderSelection
	}
	envelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return nil, err
	}
	historical, err := bootstrap.VerifyHistoricalBootstrapAnchor(envelope, baked.Roots,
		baked.Identity.AnchorExpectation(), accepted.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || historical.Digest() != accepted.AnchorSHA256 {
		return nil, ErrFounderSelection
	}
	config, err := historicalLedgerConfig(historical, baked.Roots)
	if err != nil {
		return nil, err
	}
	provider, err := newOCIAdmissionProvider(config)
	if err != nil {
		return nil, err
	}
	region, err := config.Cell.OCIRegion()
	if err != nil {
		return nil, err
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, err
	}
	client.SetRegion(region)
	client.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, err
	}
	return NewCurrentFounderAuthorityReader(baked, accepted, &client, floor)
}

// FounderSelectionObjectName is the only mutable selector key. The scope hash
// follows the ledger's stable hashed-key pattern without exposing slot names.
func FounderSelectionObjectName(domain bootstrap.StorageDomain, deploymentID, cell, environment string) string {
	scope := sha256.Sum256([]byte(cell + "\x00founder-selection\x00" + environment))
	return founderObjectPrefix(domain, deploymentID, hex.EncodeToString(scope[:])) + "/current.json"
}

// FounderImmutableObjectName derives a content-addressed key in the immutable
// ledger bucket. The signed selector supplies only the digest, never a path.
func FounderImmutableObjectName(domain bootstrap.StorageDomain, deploymentID, cell, environment, digest string) string {
	scope := sha256.Sum256([]byte(cell + "\x00founder-selection\x00" + environment))
	return founderObjectPrefix(domain, deploymentID, hex.EncodeToString(scope[:])) + "/sha256/" + digest + ".json"
}

func founderObjectPrefix(domain bootstrap.StorageDomain, deploymentID, scopeHash string) string {
	name := "bootstrap/v1/" + deploymentID + "/" + scopeHash + "/founder-selection"
	if domain.Prefix != "" {
		return domain.Prefix + "/" + name
	}
	return name
}

func (reader *CurrentFounderAuthorityReader) ReadCurrent(ctx context.Context, now time.Time) (CurrentFounderAuthority, error) {
	if reader == nil || reader.objects == nil || reader.floor == nil ||
		now.IsZero() || now.Location() != time.UTC {
		return CurrentFounderAuthority{}, ErrFounderSelection
	}
	started := time.Now()
	selectorKey := FounderSelectionObjectName(reader.domain, reader.baked.Identity.DeploymentID,
		string(reader.baked.Identity.Cell), reader.baked.Identity.Environment)
	firstWire, firstETag, err := reader.getExact(ctx, reader.domain.HeadBucket, selectorKey, founderSelectionMaxBytes)
	if err != nil {
		return CurrentFounderAuthority{}, err
	}
	selection, selectionDigest, selectionExpiresAt, err := reader.verifySelection(firstWire, now)
	if err != nil {
		return CurrentFounderAuthority{}, err
	}
	if err := reader.floor.Check(selection.Generation, selectionDigest); err != nil {
		return CurrentFounderAuthority{}, err
	}
	getImmutable := func(digest string) ([]byte, error) {
		name := FounderImmutableObjectName(reader.domain, selection.DeploymentID, selection.Cell, selection.Environment, digest)
		wire, _, err := reader.getExact(ctx, reader.domain.LedgerBucket, name, founderObjectMaxBytes)
		if err != nil {
			return nil, err
		}
		if digestWire(wire) != digest {
			return nil, fmt.Errorf("%w: immutable object digest differs from selector", ErrFounderSelection)
		}
		return wire, nil
	}
	planWire, err := getImmutable(selection.PlanSHA256)
	if err != nil {
		return CurrentFounderAuthority{}, err
	}
	anchorWire, err := getImmutable(selection.AnchorSHA256)
	if err != nil {
		return CurrentFounderAuthority{}, err
	}
	manifests := make(map[string][]byte, len(selection.Manifests))
	for _, pin := range selection.Manifests {
		wire, err := getImmutable(pin.SHA256)
		if err != nil {
			return CurrentFounderAuthority{}, err
		}
		manifests[pin.Slot] = wire
	}
	if err := reader.confirmSelector(ctx, selectorKey, firstWire, firstETag); err != nil {
		return CurrentFounderAuthority{}, err
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return CurrentFounderAuthority{}, fmt.Errorf("%w: decode selected anchor: %v", ErrFounderSelection, err)
	}
	currentNow := now.Add(time.Since(started))
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, reader.baked.Roots,
		reader.baked.Identity.AnchorExpectation(), currentNow, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || anchor.Digest() != selection.AnchorSHA256 || anchor.StorageDomain() != reader.domain ||
		anchor.Anchor().ClusterID != reader.acceptedClusterID {
		return CurrentFounderAuthority{}, fmt.Errorf("%w: selected anchor or discovery domain differs: %v", ErrFounderSelection, err)
	}
	plan, err := bootstrap.VerifyFounderPlan(planWire, reader.baked.Roots, anchorWire, manifests, currentNow,
		trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew})
	if err != nil {
		return CurrentFounderAuthority{}, fmt.Errorf("%w: selected founder proof: %v", ErrFounderSelection, err)
	}
	if plan.Plan().SeedSlot != reader.accepted.Slot ||
		plan.Plan().SeedManifestSHA256 != reader.accepted.ManifestSHA256 ||
		plan.Digest() != selection.PlanSHA256 {
		return CurrentFounderAuthority{}, fmt.Errorf("%w: selected plan does not match accepted seed", ErrFounderSelection)
	}
	if err := reader.floor.Observe(selection.Generation, selectionDigest); err != nil {
		return CurrentFounderAuthority{}, err
	}
	if err := reader.confirmSelector(ctx, selectorKey, firstWire, firstETag); err != nil {
		return CurrentFounderAuthority{}, err
	}
	if !now.Add(time.Since(started)).Before(selectionExpiresAt) {
		return CurrentFounderAuthority{}, fmt.Errorf("%w: selector expired during read", ErrFounderSelection)
	}
	return CurrentFounderAuthority{SelectionGeneration: selection.Generation, SelectionSHA256: selectionDigest,
		SelectionExpiresAt: selectionExpiresAt,
		Plan:               plan, Anchor: anchor, PlanWire: bytes.Clone(planWire), AnchorWire: bytes.Clone(anchorWire),
		ManifestWires: manifests}, nil
}

func (reader *CurrentFounderAuthorityReader) verifySelection(wire []byte, now time.Time) (FounderSelection, string, time.Time, error) {
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return FounderSelection{}, "", time.Time{}, fmt.Errorf("%w: decode selector: %v", ErrFounderSelection, err)
	}
	expected := trust.Scope{Domain: FounderSelectionDomain, DeploymentID: reader.baked.Identity.DeploymentID,
		Cell: string(reader.baked.Identity.Cell), Environment: reader.baked.Identity.Environment,
		Role: "deployment-anchor", Slot: "region"}
	payload, err := trust.VerifyCurrent(envelope, expected, reader.baked.Roots, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return FounderSelection{}, "", time.Time{}, fmt.Errorf("%w: verify current selector: %v", ErrFounderSelection, err)
	}
	var selection FounderSelection
	if len(payload) > founderSelectionMaxBytes || protocol.DecodeStrict(payload, &selection, founderSelectionMaxBytes) != nil {
		return FounderSelection{}, "", time.Time{}, ErrFounderSelection
	}
	canonical, err := protocol.EncodeJSON(selection)
	if err != nil || !bytes.Equal(canonical, payload) || selection.SchemaVersion != 1 || selection.Generation == 0 ||
		selection.DeploymentID != expected.DeploymentID || selection.Cell != expected.Cell ||
		selection.Environment != expected.Environment || len(selection.Manifests) != 3 ||
		!validFounderDigest(selection.PlanSHA256) || !validFounderDigest(selection.AnchorSHA256) {
		return FounderSelection{}, "", time.Time{}, ErrFounderSelection
	}
	for i, pin := range selection.Manifests {
		if !descriptorSlotRE.MatchString(pin.Slot) || !validFounderDigest(pin.SHA256) ||
			i > 0 && selection.Manifests[i-1].Slot >= pin.Slot {
			return FounderSelection{}, "", time.Time{}, ErrFounderSelection
		}
	}
	return selection, digestWire(wire), envelope.ExpiresAt, nil
}

func (reader *CurrentFounderAuthorityReader) confirmSelector(ctx context.Context, key string, wire []byte, etag string) error {
	currentWire, currentETag, err := reader.getExact(ctx, reader.domain.HeadBucket, key, founderSelectionMaxBytes)
	if err != nil || currentETag != etag || !bytes.Equal(currentWire, wire) {
		return fmt.Errorf("%w: selector changed or became unreadable during snapshot", ErrFounderSelection)
	}
	return nil
}

func (reader *CurrentFounderAuthorityReader) getExact(ctx context.Context, bucket, name string, maximum int64) ([]byte, string, error) {
	response, err := reader.objects.GetObject(ctx, objectstorage.GetObjectRequest{
		NamespaceName: new(reader.domain.Namespace), BucketName: new(bucket), ObjectName: new(name),
	})
	if err != nil {
		return nil, "", fmt.Errorf("%w: exact object read: %v", ErrFounderSelection, err)
	}
	if response.Content == nil || response.ContentLength == nil || *response.ContentLength < 1 ||
		*response.ContentLength > maximum || response.ETag == nil || strings.TrimSpace(*response.ETag) == "" {
		if response.Content != nil {
			response.Content.Close()
		}
		return nil, "", ErrFounderSelection
	}
	wire, readErr := io.ReadAll(io.LimitReader(response.Content, maximum+1))
	closeErr := response.Content.Close()
	if err := errors.Join(readErr, closeErr); err != nil || len(wire) != int(*response.ContentLength) {
		return nil, "", fmt.Errorf("%w: read exact object body: %v", ErrFounderSelection, err)
	}
	return wire, *response.ETag, nil
}

func validFounderDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil && strings.ToLower(digest) == digest
}

func digestWire(wire []byte) string {
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}
