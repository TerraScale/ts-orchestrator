package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var ErrFounderPublish = errors.New("founder continuity selector publication failed")

type FounderSelectionObjectWriter interface {
	FounderSelectionObjectReader
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
}

// ValidateInitialFounderSelectionCandidate checks the canonical generation-one
// selector payload before an offline root signs it.
func ValidateInitialFounderSelectionCandidate(payload []byte, identity BakedIdentity) (FounderSelection, error) {
	selection, err := decodeFounderSelectionPayload(payload, trust.Scope{
		DeploymentID: identity.DeploymentID, Cell: string(identity.Cell), Environment: identity.Environment,
	})
	if err != nil || selection.SchemaVersion != 1 || selection.Generation != 1 {
		return FounderSelection{}, ErrFounderSelection
	}
	return selection, nil
}

// PublishInitialFounderSelection writes the exact signed genesis objects before
// creating the selector. Every write is conditional and reconciled by an exact
// readback, so an uncertain response can only replay matching bytes. It never
// replaces an existing selector, including a later continuation selector.
func PublishInitialFounderSelection(ctx context.Context, anchor bootstrap.VerifiedBootstrapAnchor,
	identity BakedIdentity, roots trust.Keyring, selectionWire, planWire []byte,
	manifestWires map[string][]byte, objects FounderSelectionObjectWriter, now time.Time,
) error {
	if !anchor.IsVerified() || objects == nil || len(roots) == 0 ||
		len(manifestWires) != 3 || now.IsZero() || now.Location() != time.UTC {
		return ErrFounderPublish
	}
	anchorWire := anchor.Wire()
	anchorEnvelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return ErrFounderPublish
	}
	verifiedAnchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, roots,
		identity.AnchorExpectation(), now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || verifiedAnchor.Digest() != anchor.Digest() ||
		len(verifiedAnchor.Anchor().ControllerSlots) != 3 {
		return ErrFounderPublish
	}
	domain := verifiedAnchor.StorageDomain()
	started := time.Now()
	reader := &CurrentFounderAuthorityReader{baked: BakedInputs{Identity: identity, Roots: roots},
		domain: domain, objects: objects}
	selection, selectionSHA256, selectionExpiresAt, err := reader.verifySelection(selectionWire, now)
	if err != nil || selection.SchemaVersion != 1 || selection.Generation != 1 ||
		selection.AnchorSHA256 != verifiedAnchor.Digest() || selection.PlanSHA256 != digestWire(planWire) {
		return ErrFounderPublish
	}
	if selectionExpiresAt.After(verifiedAnchor.ExpiresAt()) {
		return ErrFounderPublish
	}
	for index, pin := range selection.Manifests {
		if pin.Slot != verifiedAnchor.Anchor().ControllerSlots[index] ||
			digestWire(manifestWires[pin.Slot]) != pin.SHA256 {
			return ErrFounderPublish
		}
	}
	plan, err := bootstrap.VerifyFounderPlan(planWire, roots, anchorWire, manifestWires, now,
		trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew})
	if err != nil || plan.Digest() != selection.PlanSHA256 {
		return fmt.Errorf("%w: selected founder plan is invalid: %v", ErrFounderPublish, err)
	}
	planEnvelope, err := trust.DecodeEnvelope(planWire)
	if err != nil || selectionExpiresAt.After(planEnvelope.ExpiresAt) {
		return ErrFounderPublish
	}
	for _, pin := range selection.Manifests {
		envelope, err := trust.DecodeEnvelope(manifestWires[pin.Slot])
		if err != nil || selectionExpiresAt.After(envelope.ExpiresAt) {
			return ErrFounderPublish
		}
	}
	for _, wire := range [][]byte{anchorWire, planWire} {
		key := FounderImmutableObjectName(domain, identity.DeploymentID, string(identity.Cell),
			identity.Environment, digestWire(wire))
		if err := publishExactObject(ctx, reader, objects, domain.LedgerBucket, key,
			domain.LedgerKMSKeyOCID, wire, "", true); err != nil {
			return err
		}
	}
	for _, pin := range selection.Manifests {
		wire := manifestWires[pin.Slot]
		key := FounderImmutableObjectName(domain, identity.DeploymentID, string(identity.Cell),
			identity.Environment, pin.SHA256)
		if err := publishExactObject(ctx, reader, objects, domain.LedgerBucket, key,
			domain.LedgerKMSKeyOCID, wire, "", true); err != nil {
			return err
		}
	}
	currentTime := now.Add(time.Since(started))
	if _, _, _, err := reader.verifySelection(selectionWire, currentTime); err != nil {
		return fmt.Errorf("%w: genesis selector expired before create: %v", ErrFounderPublish, err)
	}
	if _, err := bootstrap.VerifyFounderPlan(planWire, roots, anchorWire, manifestWires, currentTime,
		trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew}); err != nil {
		return fmt.Errorf("%w: founder plan expired before selector create: %v", ErrFounderPublish, err)
	}
	selectorKey := FounderSelectionObjectName(domain, identity.DeploymentID, string(identity.Cell), identity.Environment)
	if err := publishExactObject(ctx, reader, objects, domain.HeadBucket, selectorKey,
		domain.HeadKMSKeyOCID, selectionWire, "", true); err != nil {
		return err
	}
	currentWire, _, err := reader.getExact(ctx, domain.HeadBucket, selectorKey, founderSelectionMaxBytes)
	if err != nil || digestWire(currentWire) != selectionSHA256 || !bytes.Equal(currentWire, selectionWire) {
		return fmt.Errorf("%w: genesis selector differs after create: %v", ErrFounderPublish, err)
	}
	if _, _, _, err := reader.verifySelection(currentWire, now.Add(time.Since(started))); err != nil {
		return fmt.Errorf("%w: genesis selector expired after create: %v", ErrFounderPublish, err)
	}
	return nil
}

// PublishFounderContinuities publishes all three signed immutable proofs
// before CAS-updating the one exact selector key. The signed historical anchor
// must supply domain; the selector and proof cannot choose bucket or key scope.
func PublishFounderContinuities(ctx context.Context, anchor bootstrap.HistoricalBootstrapAnchor,
	identity BakedIdentity, roots trust.Keyring, selectionWire []byte, proofs map[string][]byte,
	objects FounderSelectionObjectWriter, now time.Time,
) error {
	if !anchor.IsVerified() || objects == nil || len(roots) == 0 || len(proofs) != 3 ||
		now.IsZero() || now.Location() != time.UTC {
		return ErrFounderPublish
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchor.Wire())
	if err != nil {
		return ErrFounderPublish
	}
	verifiedAnchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(anchorEnvelope, roots,
		identity.AnchorExpectation(), anchor.AcceptedAt(), bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || verifiedAnchor.Digest() != anchor.Digest() {
		return ErrFounderPublish
	}
	anchored := anchor.Anchor()
	domain := anchored.StorageDomain
	if domain.Validate() != nil || len(anchored.ControllerSlots) != 3 {
		return ErrFounderPublish
	}
	started := time.Now()
	reader := &CurrentFounderAuthorityReader{baked: BakedInputs{Identity: identity, Roots: roots},
		domain: domain, objects: objects}
	selection, selectionSHA256, selectionExpiresAt, err := reader.verifySelection(selectionWire, now)
	if err != nil || selection.SchemaVersion != 2 {
		return fmt.Errorf("%w: invalid current read-only selector: %v", ErrFounderPublish, err)
	}
	key := FounderSelectionObjectName(domain, identity.DeploymentID, string(identity.Cell), identity.Environment)
	previousWire, previousETag, err := reader.getExact(ctx, domain.HeadBucket, key, founderSelectionMaxBytes)
	if err != nil {
		return fmt.Errorf("%w: read existing selector before restricted CAS: %v", ErrFounderPublish, err)
	}
	expectedScope := trust.Scope{Domain: FounderSelectionDomain, DeploymentID: identity.DeploymentID,
		Cell: string(identity.Cell), Environment: identity.Environment, Role: "deployment-anchor", Slot: "region"}
	previousEnvelope, err := trust.DecodeEnvelope(previousWire)
	if err != nil {
		return ErrFounderPublish
	}
	previousPayload, err := trust.VerifyHistorical(previousEnvelope, expectedScope, roots, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return fmt.Errorf("%w: existing selector is not root-signed: %v", ErrFounderPublish, err)
	}
	previous, err := decodeFounderSelectionPayload(previousPayload, expectedScope)
	if err != nil || previous.Generation >= selection.Generation && !bytes.Equal(previousWire, selectionWire) {
		return ErrFounderPublish
	}
	for _, pin := range selection.Continuities {
		if !slices.Contains(anchored.ControllerSlots, pin.Slot) {
			return ErrFounderPublish
		}
		wire, ok := proofs[pin.Slot]
		if !ok || digestWire(wire) != pin.SHA256 {
			return ErrFounderPublish
		}
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return ErrFounderPublish
		}
		if selectionExpiresAt.After(envelope.ExpiresAt) {
			return fmt.Errorf("%w: selector outlives a selected continuity proof", ErrFounderPublish)
		}
		var claim bootstrap.InstallContinuity
		if err := protocol.DecodeStrict(envelope.Payload, &claim, bootstrap.MaxInstallContinuityBytes); err != nil {
			return ErrFounderPublish
		}
		if claim.Slot != pin.Slot || claim.SelectorGeneration != selection.Generation ||
			claim.DeploymentID != identity.DeploymentID || claim.Cell != identity.Cell ||
			claim.Environment != identity.Environment || claim.ClusterID != anchored.ClusterID ||
			claim.GenesisAnchorSHA256 != anchor.Digest() {
			return ErrFounderPublish
		}
		_, err = bootstrap.VerifyCurrentInstallContinuity(envelope, roots,
			bootstrap.InstallContinuityExpectation{Install: claim, SelectorGeneration: selection.Generation,
				SelectorSHA256: selectionSHA256, PinnedContinuitySHA256: pin.SHA256},
			now.Add(time.Since(started)), bootstrap.InstallContinuityTrustPolicy())
		if err != nil {
			return fmt.Errorf("%w: selected proof is invalid: %v", ErrFounderPublish, err)
		}
		immutableKey := FounderImmutableObjectName(domain, identity.DeploymentID, string(identity.Cell),
			identity.Environment, pin.SHA256)
		if err := publishExactObject(ctx, reader, objects, domain.LedgerBucket, immutableKey,
			domain.LedgerKMSKeyOCID, wire, "", true); err != nil {
			return err
		}
	}
	if _, _, _, err := reader.verifySelection(selectionWire, now.Add(time.Since(started))); err != nil {
		return fmt.Errorf("%w: selector expired before CAS: %v", ErrFounderPublish, err)
	}
	if !bytes.Equal(previousWire, selectionWire) {
		if err := publishExactObject(ctx, reader, objects, domain.HeadBucket, key,
			domain.HeadKMSKeyOCID, selectionWire, previousETag, false); err != nil {
			return err
		}
	}
	currentWire, _, err := reader.getExact(ctx, domain.HeadBucket, key, founderSelectionMaxBytes)
	if err != nil || !bytes.Equal(currentWire, selectionWire) {
		return fmt.Errorf("%w: selector differs after CAS: %v", ErrFounderPublish, err)
	}
	if _, _, _, err := reader.verifySelection(currentWire, now.Add(time.Since(started))); err != nil {
		return fmt.Errorf("%w: selector expired after CAS: %v", ErrFounderPublish, err)
	}
	return nil
}

func publishExactObject(ctx context.Context, reader *CurrentFounderAuthorityReader,
	objects FounderSelectionObjectWriter, bucket, key, kmsKey string, wire []byte, previousETag string,
	immutable bool,
) error {
	if len(wire) == 0 || (immutable && previousETag != "") || (!immutable && previousETag == "") {
		return ErrFounderPublish
	}
	hash := sha256.Sum256(wire)
	checksum := base64.StdEncoding.EncodeToString(hash[:])
	length := int64(len(wire))
	request := objectstorage.PutObjectRequest{NamespaceName: new(reader.domain.Namespace),
		BucketName: new(bucket), ObjectName: new(key),
		PutObjectBody: io.NopCloser(bytes.NewReader(wire)), ContentLength: new(length),
		OpcContentSha256: new(checksum), OpcSseKmsKeyId: new(kmsKey)}
	if immutable {
		request.IfNoneMatch = new("*")
	} else {
		request.IfMatch = new(previousETag)
	}
	_, putErr := objects.PutObject(ctx, request)
	current, _, readErr := reader.getExact(ctx, bucket, key, int64(max(founderSelectionMaxBytes, founderObjectMaxBytes)))
	if readErr != nil || !bytes.Equal(current, wire) {
		return fmt.Errorf("%w: conditional write outcome differs from exact reread: put=%v read=%v", ErrFounderPublish, putErr, readErr)
	}
	return nil
}
