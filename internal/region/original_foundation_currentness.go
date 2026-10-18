package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const originalFoundationPublicationPurpose = "original-foundation-currentness/v1"

// OriginalFoundationPublicationIntent authorizes only these two immutable
// public documents. It deliberately contains no digest of its own signed grant.
type OriginalFoundationPublicationIntent struct {
	SchemaVersion         int                     `json:"schemaVersion"`
	Purpose               string                  `json:"purpose"`
	TenancyID             string                  `json:"tenancyId"`
	InstallationID        string                  `json:"installationId"`
	OriginalUserID        string                  `json:"originalUserId"`
	Generation            uint64                  `json:"generation"`
	HomeRegion            string                  `json:"homeRegion"`
	Home                  bootstrap.StorageDomain `json:"home"`
	Objects               [2]string               `json:"objects"`
	OperationIDs          [3]string               `json:"operationIds"`
	ProducerIntentSHA256  [3]string               `json:"producerIntentSha256"`
	AdmissionRecipeSHA256 [3]string               `json:"admissionRecipeSha256"`
}

func originalPublicationRecipe(purposes [3]OriginalSourceProducerIntent, recipes [3]OriginalActorAdmissionReadIntent) (OriginalFoundationPublicationIntent, error) {
	q := purposes[0]
	intent := OriginalFoundationPublicationIntent{SchemaVersion: 1, Purpose: originalFoundationPublicationPurpose,
		TenancyID: q.TenancyID, InstallationID: q.InstallationID, OriginalUserID: q.OriginalUserID,
		Generation: q.Generation, HomeRegion: foundationHomeRegion, Home: q.Home,
		Objects: [2]string{foundationRootChainObject, strings.TrimSuffix(q.Home.Prefix, "/") + "/" + foundationGrantObject}}
	if q.Home.Validate() != nil || q.Home.HeadBucket != foundationDiscoveryBucket {
		return intent, ErrOriginalSourceProducerHold
	}
	for index, purpose := range purposes {
		if purpose.Cell != [3]string{"GRU", "SFO", "FRA"}[index] || purpose.TenancyID != q.TenancyID || purpose.InstallationID != q.InstallationID ||
			purpose.Generation != q.Generation || purpose.OriginalUserID != q.OriginalUserID || purpose.Home != q.Home || recipes[index].Home != q.Home {
			return intent, ErrOriginalSourceProducerHold
		}
		wire, err := json.Marshal(purpose, json.Deterministic(true))
		if err != nil {
			return intent, err
		}
		intent.ProducerIntentSHA256[index] = digestSource(wire)
		wire, err = json.Marshal(recipes[index], json.Deterministic(true))
		if err != nil {
			return intent, err
		}
		intent.AdmissionRecipeSHA256[index] = digestSource(wire)
		intent.OperationIDs[index] = purpose.OperationID
	}
	return intent, nil
}

func originalFoundationPublicationIntent(grant FoundationGrant, home bootstrap.StorageDomain) (OriginalFoundationPublicationIntent, error) {
	var purposes [3]OriginalSourceProducerIntent
	if requireOriginalSourceProducerPurposes(grant) != nil || grant.OriginalActorAdmissionReads == nil || validateOriginalAdmissionReadIntents(grant, home) != nil {
		return OriginalFoundationPublicationIntent{}, ErrOriginalSourceProducerHold
	}
	for index, cell := range [3]string{"GRU", "SFO", "FRA"} {
		for _, regional := range grant.Regions {
			if regional.Plan["cell"] == cell && regional.BootstrapMaterial != nil && regional.BootstrapMaterial.OriginalSourceProducer != nil {
				purposes[index] = *regional.BootstrapMaterial.OriginalSourceProducer
			}
		}
	}
	if purposes[0].Home != home {
		return OriginalFoundationPublicationIntent{}, ErrOriginalSourceProducerHold
	}
	return originalPublicationRecipe(purposes, *grant.OriginalActorAdmissionReads)
}

func validateOriginalFoundationPublicationIntent(grant FoundationGrant, home bootstrap.StorageDomain) error {
	// Historical signed documents never gain this prospective purpose.
	if grant.OriginalPublication == nil {
		return nil
	}
	expected, err := originalFoundationPublicationIntent(grant, home)
	if err != nil || !sameOriginalSourceValue(expected, grant.OriginalPublication) {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	return nil
}

type OriginalFoundationPublicationReadback struct {
	ETag          string    `json:"etag"`
	ContentSHA256 string    `json:"contentSha256"`
	VerifiedAt    time.Time `json:"verifiedAt"`
}

// OriginalFoundationPublication is a protected original-operator reservation
// and exact public-object readback. It grants no actor or startup capability.
type OriginalFoundationPublication struct {
	Intent               OriginalFoundationPublicationIntent       `json:"intent"`
	IntentSHA256         string                                    `json:"intentSha256"`
	GrantSHA256          string                                    `json:"grantSha256"`
	BundleSHA256         string                                    `json:"bundleSha256"`
	RootChainSHA256      string                                    `json:"rootChainSha256"`
	GRUIntentSHA256      string                                    `json:"gruIntentSha256"`
	Generation           uint64                                    `json:"generation"`
	OperationID          string                                    `json:"operationId"`
	BirthSHA256          [3]string                                 `json:"birthSha256"`
	AdmissionReadsSHA256 [3]string                                 `json:"admissionReadsSha256"`
	RequestSHA256        string                                    `json:"requestSha256"`
	PendingAt            time.Time                                 `json:"pendingAt"`
	Readbacks            *[2]OriginalFoundationPublicationReadback `json:"readbacks,omitempty"`
}

func (entry OriginalFoundationPublication) scopeOnly() OriginalFoundationPublication {
	entry.PendingAt, entry.Readbacks = time.Time{}, nil
	return entry
}

func originalPublicationScope(record FoundationRecord, intent OriginalFoundationPublicationIntent, rootChainSHA string) (OriginalFoundationPublication, error) {
	if completeOriginalFoundationAdmissionReads(record) != nil {
		return OriginalFoundationPublication{}, ErrOriginalSourceProducerHold
	}
	return originalPublicationScopeFromAdmissionReads(record, intent, rootChainSHA)
}

func originalPublicationScopeFromAdmissionReads(record FoundationRecord, intent OriginalFoundationPublicationIntent, rootChainSHA string) (OriginalFoundationPublication, error) {
	var entry OriginalFoundationPublication
	if !validFoundationDigest(rootChainSHA) {
		return entry, ErrOriginalSourceProducerHold
	}
	root := record.OriginalFoundationCompartments
	var purposes [3]OriginalSourceProducerIntent
	var recipes [3]OriginalActorAdmissionReadIntent
	for index, birth := range *record.OriginalSourceProducers {
		purposes[index], recipes[index] = birth.Intent, root.Regions[index].AdmissionReads.Recipe
	}
	expected, err := originalPublicationRecipe(purposes, recipes)
	if err != nil || !sameOriginalSourceValue(expected, intent) {
		return entry, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	wire, err := json.Marshal(intent, json.Deterministic(true))
	if err != nil {
		return entry, err
	}
	entry = OriginalFoundationPublication{Intent: intent, IntentSHA256: digestSource(wire), GrantSHA256: root.GrantSHA256,
		BundleSHA256: root.BundleSHA256, RootChainSHA256: rootChainSHA, GRUIntentSHA256: root.GRUIntentSHA256,
		Generation: root.Generation, OperationID: root.OperationID}
	for index, birth := range *record.OriginalSourceProducers {
		wire, err = json.Marshal(birth, json.Deterministic(true))
		if err != nil {
			return entry, err
		}
		entry.BirthSHA256[index] = digestSource(wire)
		wire, err = json.Marshal(root.Regions[index].AdmissionReads, json.Deterministic(true))
		if err != nil {
			return entry, err
		}
		entry.AdmissionReadsSHA256[index] = digestSource(wire)
	}
	wire, err = json.Marshal(entry, json.Deterministic(true))
	entry.RequestSHA256 = digestSource(wire)
	return entry, err
}

func originalPublicationAuthority(ctx context.Context, authority *HomeIAMAuthority) (FoundationRecord, string, OriginalFoundationPublication, time.Time, error) {
	var expected OriginalFoundationPublication
	if ctx == nil || authority == nil || authority.operator == nil {
		return FoundationRecord{}, "", expected, time.Time{}, ErrOriginalSourceProducerHold
	}
	lease, ok := ctx.Value(homeIAMLeaseKey{}).(*homeIAMLease)
	if !ok || lease == nil || lease.authority != authority || authority.Guard(ctx, 0) != nil {
		return FoundationRecord{}, "", expected, time.Time{}, ErrOriginalSourceProducerHold
	}
	record, etag, scopes, deadline, err := originalAdmissionReadPrerequisites(ctx, authority)
	if err != nil || completeOriginalFoundationAdmissionReads(record) != nil {
		return record, etag, expected, deadline, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	for index, scope := range scopes {
		if !sameOriginalSourceValue(scope, record.OriginalFoundationCompartments.Regions[index].AdmissionReads.scopeOnly()) {
			return record, etag, expected, deadline, ErrOriginalSourceProducerHold
		}
	}
	reader, ok := authority.resolver.Footprint.(*SignedFootprint)
	if !ok {
		return record, etag, expected, deadline, ErrOriginalSourceProducerHold
	}
	grant, _, err := reader.verifyOriginalDocument(authority.operator.bundle.GrantWire)
	if err != nil || grant.OriginalPublication == nil || validateOriginalFoundationPublicationIntent(grant, authority.domain) != nil {
		return record, etag, expected, deadline, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	expected, err = originalPublicationScopeFromAdmissionReads(record, *grant.OriginalPublication, digestSource(authority.operator.bundle.RootChainWire))
	if err != nil || expected.GrantSHA256 != digestSource(authority.operator.bundle.GrantWire) {
		return record, etag, expected, deadline, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	wire, err := json.Marshal(authority.operator.bundle, json.Deterministic(true))
	if err != nil || expected.BundleSHA256 != digestSource(wire) {
		return record, etag, expected, deadline, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	return record, etag, expected, deadline, nil
}

func originalPublicationReadback(ctx context.Context, authority *HomeIAMAuthority, name string, expected []byte) (OriginalFoundationPublicationReadback, error) {
	var proof OriginalFoundationPublicationReadback
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	policy := common.NoRetryPolicy()
	response, err := authority.objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{
		NamespaceName: new(authority.domain.Namespace), BucketName: new(foundationDiscoveryBucket), ObjectName: new(name),
		RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
	if err != nil {
		return proof, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	if response.Content == nil {
		return proof, ErrOriginalSourceProducerHold
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, int64(len(expected))+1))
	etag := deref(response.ETag)
	if err != nil || !bytes.Equal(wire, expected) || !originalPublicationETag(etag) {
		return proof, errors.Join(ErrOriginalSourceProducerHold, err)
	}
	return OriginalFoundationPublicationReadback{ETag: etag, ContentSHA256: digestSource(wire), VerifiedAt: time.Now().UTC()}, nil
}

func originalPublicationETag(etag string) bool {
	return etag != "" && len(etag) <= 1024 && !strings.ContainsAny(etag, "\x00\r\n")
}

func retainOriginalFoundationPublication(ctx context.Context, authority *HomeIAMAuthority) error {
	record, etag, expected, _, err := originalPublicationAuthority(ctx, authority)
	if err != nil {
		return err
	}
	entry := record.OriginalFoundationCompartments.Publication
	if entry == nil {
		initial := expected
		initial.PendingAt = time.Now().UTC()
		record.OriginalFoundationCompartments.Publication = &initial
		if err := checkpointOriginalCompartments(ctx, authority, &record, &etag); err != nil {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		entry = &initial
	} else if !sameOriginalSourceValue(entry.scopeOnly(), expected) {
		return ErrOriginalSourceProducerHold
	}
	guard := func(dispatchCtx context.Context) error {
		// Keep lease values while honoring the publication attempt's shorter lifetime.
		saved, _, currentScope, deadline, err := originalPublicationAuthority(originalProviderCheckpointContext(dispatchCtx, ctx), authority)
		if err != nil || !sameOriginalSourceValue(currentScope, expected) || !sameOriginalSourceValue(saved.OriginalFoundationCompartments.Publication, entry) {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		return ociclient.LimitAdmission(dispatchCtx, deadline)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	publicationCtx := ociclient.WithRequestGuard(ociclient.WithAuthority(ctx, guard), guard)
	var readbacks [2]OriginalFoundationPublicationReadback
	for index, wire := range [2][]byte{authority.operator.bundle.RootChainWire, authority.operator.bundle.GrantWire} {
		if entry.Readbacks == nil {
			// The caller owns the genuine HomeWrite lease. Acquiring it again is
			// not reentrant; use the existing immutable conditional publisher.
			if err := publishFoundationObject(publicationCtx, authority.objects, authority.domain.Namespace, expected.Intent.Objects[index], wire); err != nil {
				return errors.Join(ErrOriginalSourceProducerHold, err)
			}
		}
		readbacks[index], err = originalPublicationReadback(publicationCtx, authority, expected.Intent.Objects[index], wire)
		if err != nil {
			return err
		}
		if entry.Readbacks != nil && (readbacks[index].ETag != (*entry.Readbacks)[index].ETag || readbacks[index].ContentSHA256 != (*entry.Readbacks)[index].ContentSHA256) {
			return ErrOriginalSourceProducerHold
		}
	}
	if entry.Readbacks != nil {
		return nil
	}
	if err := guard(ctx); err != nil {
		return err
	}
	entry.Readbacks = &readbacks
	record.OriginalFoundationCompartments.Publication = entry
	return checkpointOriginalCompartments(ctx, authority, &record, &etag)
}

func (record FoundationRecord) validateOriginalFoundationPublication() error {
	root := record.OriginalFoundationCompartments
	if root == nil || root.Publication == nil {
		return nil
	}
	entry := root.Publication
	expected, err := originalPublicationScope(record, entry.Intent, entry.RootChainSHA256)
	if err != nil || !sameOriginalSourceValue(entry.scopeOnly(), expected) || entry.PendingAt.IsZero() || entry.PendingAt.Before(root.BornAt) || entry.PendingAt.After(record.UpdatedAt) {
		return errors.Join(ErrOriginalSourceProducerHold, err)
	}
	for _, regional := range root.Regions {
		if entry.PendingAt.Before(regional.AdmissionReads.VerifiedAt) {
			return ErrOriginalSourceProducerHold
		}
	}
	if entry.Readbacks != nil {
		for index, proof := range *entry.Readbacks {
			if !originalPublicationETag(proof.ETag) || proof.ContentSHA256 != [2]string{entry.RootChainSHA256, entry.GrantSHA256}[index] ||
				proof.VerifiedAt.IsZero() || proof.VerifiedAt.Before(entry.PendingAt) || proof.VerifiedAt.After(record.UpdatedAt) {
				return ErrOriginalSourceProducerHold
			}
		}
	}
	return nil
}

func (next FoundationRecord) retainOriginalFoundationPublication(previous FoundationRecord) error {
	before, after := previous.OriginalFoundationCompartments, next.OriginalFoundationCompartments
	if before == nil || before.Publication == nil {
		if after != nil && after.Publication != nil && (completeOriginalFoundationAdmissionReads(previous) != nil || after.Publication.Readbacks != nil) {
			return ErrOriginalSourceProducerHold
		}
		return nil
	}
	old := before.Publication
	if after == nil || after.Publication == nil || !sameOriginalSourceValue(old.scopeOnly(), after.Publication.scopeOnly()) ||
		!old.PendingAt.Equal(after.Publication.PendingAt) || old.Readbacks != nil && !sameOriginalSourceValue(old.Readbacks, after.Publication.Readbacks) {
		return ErrOriginalSourceProducerHold
	}
	return nil
}
