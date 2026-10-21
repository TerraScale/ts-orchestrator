package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// CapacityJournalPolicy retains the original signed purpose and every possible
// policy dispatch. A later grant cannot transfer or repair this reservation.
type CapacityJournalPolicy struct {
	Cells            []string               `json:"cells,omitempty"`
	OperationID      string                 `json:"operationId"`
	WriterSHA256     string                 `json:"writerSha256"`
	GrantSHA256      string                 `json:"grantSha256"`
	Generation       uint64                 `json:"generation"`
	PurposeSHA256    string                 `json:"purposeSha256"`
	ExpiresAt        time.Time              `json:"expiresAt"`
	Policy           FoundationWriterPolicy `json:"policy"`
	Attempts         []time.Time            `json:"attempts,omitempty"`
	ObservedPolicyID string                 `json:"observedPolicyId,omitempty"`
	ObservedAt       time.Time              `json:"observedAt,omitzero"`
}

// CapacityJournalWriter exposes only existing-record capacity deltas. The SDK
// store and independently verified instance/source remain inside the root.
type CapacityJournalWriter struct {
	original     context.Context
	authority    *HomeIAMAuthority
	resolver     FoundationResolver
	reader       *SignedFootprint
	store        *ObjectFoundationStore
	iam          *identity.IdentityClient
	grant        string
	generation   uint64
	purpose      string
	writer       string
	signedExpiry time.Time
	expires      time.Time
	policy       string
	cells        []string
	scope        string
}

// CapacityJournalWriter is lazy: startup does not install IAM or add reads.
func (r FoundationResolver) CapacityJournalWriter(ctx context.Context, authority *HomeIAMAuthority) (*CapacityJournalWriter, error) {
	reader, signed := r.Footprint.(*SignedFootprint)
	deadline, bounded := ctx.Deadline()
	if os.Geteuid() != 0 || !signed || reader == nil || !bounded || authority == nil || authority.operator != nil ||
		(!authority.runtime.IsVerified() && !authority.proof.IsVerified()) || authority.factory == nil ||
		reader.factory == nil || reader.retainedGrant != nil || reader.local.Cell != "GRU" ||
		authority.factory.Region() != "sa-saopaulo-1" || reader.factory.Region() != "sa-saopaulo-1" ||
		authority.domain != reader.storage || authority.resolver.Footprint != reader || authority.resolver.Store != r.Store {
		return nil, errors.New("capacity journal requires the original root HOME instance and signed SDK source")
	}
	store, err := r.ProtectedCapacityReaderStore(reader.factory)
	if err != nil {
		return nil, err
	}
	w := &CapacityJournalWriter{original: ctx, authority: authority, resolver: r, reader: reader, store: store, expires: deadline}
	grant, generation, purpose, expiry, cells, err := w.signedPurpose(ctx)
	if err != nil {
		return nil, err
	}
	w.grant, w.generation, w.purpose, w.signedExpiry, w.cells = grant, generation, purpose, expiry, slices.Clone(cells)
	if expiry.Before(w.expires) {
		w.expires = expiry
	}
	ctx, finish := w.boundedContext(ctx)
	defer finish()
	record, _, err := store.Load(ctx, "GRU")
	if err != nil || record.FoundationWriter == nil {
		return nil, errors.Join(ErrFoundationFenced, err)
	}
	w.writer, err = capacityWriterDigest(*record.FoundationWriter)
	if err != nil {
		return nil, err
	}
	if err := w.guardBirth(ctx); err != nil {
		return nil, err
	}
	factory, guarded, err := authority.GuardedFactory(ctx)
	if err != nil {
		return nil, err
	}
	home, err := factory.HomeRegion(guarded, authority.tenancyID)
	if err != nil {
		return nil, err
	}
	regional, err := factory.ForRegion(home)
	if err != nil {
		return nil, err
	}
	iam, err := regional.Identity()
	if err != nil {
		return nil, err
	}
	w.iam = &iam
	if err := w.install(ctx); err != nil {
		return nil, err
	}
	if err := w.Guard(ctx); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *CapacityJournalWriter) ExpiresAt() time.Time {
	if w == nil {
		return time.Time{}
	}
	return w.expires
}

func (w *CapacityJournalWriter) signedPurpose(ctx context.Context) (string, uint64, string, time.Time, []string, error) {
	wire, err := w.reader.readGrant(ctx)
	if err != nil {
		return "", 0, "", time.Time{}, nil, err
	}
	_, expiry, err := w.reader.verifyGrant(wire)
	if err != nil {
		return "", 0, "", time.Time{}, nil, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return "", 0, "", time.Time{}, nil, err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return "", 0, "", time.Time{}, nil, err
	}
	if len(grant.WorkerProfiles) == 0 || len(grant.WorkerProfiles) > 512 {
		return "", 0, "", time.Time{}, nil, ErrFoundationFenced
	}
	cells, profiles := map[string]bool{}, map[string]bool{}
	purpose := WorkerCapacityJournal{Purpose: CapacityJournalPurposeV1, Principal: CapacityJournalPrincipalV1, Delta: CapacityJournalDeltaV1}
	for _, profile := range grant.WorkerProfiles {
		key := profile.Cell + "/" + profile.Role + "/" + profile.Architecture + "/" + profile.Shape
		if profiles[key] || profile.CapacityJournal != purpose || ValidateWorkerProfile(grant, profile) != nil {
			return "", 0, "", time.Time{}, nil, ErrFoundationFenced
		}
		profiles[key], cells[profile.Cell] = true, true
	}
	if grant.InstallationID != w.authority.installationID || grant.TenancyID != w.authority.tenancyID ||
		digestSource(wire) != w.authority.grantDigest || grant.Generation != w.authority.grantGeneration {
		return "", 0, "", time.Time{}, nil, ErrFoundationFenced
	}
	targets, err := w.resolver.CapacityPoolCells(ctx)
	if err != nil || len(targets) != len(cells) {
		return "", 0, "", time.Time{}, nil, errors.Join(ErrFoundationFenced, err)
	}
	for _, cell := range targets {
		if !cells[cell] {
			return "", 0, "", time.Time{}, nil, ErrFoundationFenced
		}
	}
	current, err := w.reader.readGrant(ctx)
	if err != nil || !bytes.Equal(current, wire) {
		return "", 0, "", time.Time{}, nil, errors.Join(ErrFoundationFenced, err)
	}
	purposeWire, err := json.Marshal(purpose, json.Deterministic(true))
	return digestSource(wire), grant.Generation, digestSource(purposeWire), expiry, targets, err
}

func (w *CapacityJournalWriter) guardBirth(ctx context.Context) error {
	if w == nil || w.original == nil || w.authority == nil || w.reader == nil || w.store == nil || os.Geteuid() != 0 ||
		w.original.Err() != nil || !time.Now().Before(w.expires) {
		return ErrFoundationFenced
	}
	ctx, finish := w.boundedContext(ctx)
	defer finish()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := w.authority.VerifyFoundationWriter(ctx); err != nil {
		return err
	}
	admission := ctx
	ctx = ociclient.CheckpointContext(ctx)
	grant, generation, purpose, expiry, cells, err := w.signedPurpose(ctx)
	if err != nil || grant != w.grant || generation != w.generation || purpose != w.purpose || !expiry.Equal(w.signedExpiry) || !slices.Equal(cells, w.cells) {
		return errors.Join(ErrFoundationFenced, err)
	}
	// HOME must remain in the current authenticated foundation/source footprint,
	// even when it is absent from the worker target scope.
	homeAndTargets := slices.Clone(w.cells)
	if !slices.Contains(homeAndTargets, "GRU") {
		homeAndTargets = append(homeAndTargets, "GRU")
	}
	for _, cell := range homeAndTargets {
		record, err := w.resolver.Resolve(ctx, cell)
		if err != nil {
			return err
		}
		if cell != "GRU" {
			continue
		}
		pending := record.FoundationWriter
		if pending == nil || pending.Cell != "GRU" || pending.InstanceID != w.authority.instanceID ||
			pending.InstallationID != w.authority.installationID || pending.Namespace != w.reader.storage.Namespace ||
			pending.Bucket != w.reader.storage.HeadBucket || pending.BucketCompartment != w.authority.bucketCompartment ||
			pending.KMSKeyID != w.reader.storage.HeadKMSKeyOCID {
			return ErrFoundationFenced
		}
		digest, err := capacityWriterDigest(*pending)
		if err != nil || digest != w.writer {
			return errors.Join(ErrFoundationFenced, err)
		}
		if err := pending.validateCapacityJournal(); err != nil {
			return err
		}
	}
	if err := w.authority.Guard(ctx, 0); err != nil {
		return err
	}
	grant, generation, purpose, expiry, cells, err = w.signedPurpose(ctx)
	if err != nil || grant != w.grant || generation != w.generation || purpose != w.purpose || !expiry.Equal(w.signedExpiry) || !slices.Equal(cells, w.cells) {
		return errors.Join(ErrFoundationFenced, err)
	}
	if w.original.Err() != nil || !time.Now().Before(w.expires) {
		return ErrFoundationFenced
	}
	return ociclient.LimitAdmission(admission, w.expires)
}

func (w *CapacityJournalWriter) Guard(ctx context.Context) error {
	if w == nil || w.original == nil {
		return ErrFoundationFenced
	}
	ctx, finish := w.boundedContext(ctx)
	defer finish()
	if err := w.guardBirth(ctx); err != nil {
		return err
	}
	if w.iam == nil || w.policy == "" {
		return ErrFoundationFenced
	}
	record, _, err := w.store.Load(ociclient.CheckpointContext(ctx), "GRU")
	if err != nil {
		return err
	}
	pending := record.FoundationWriter
	p := capacityPolicyAt(pending, w.scope)
	if p == nil || p.Policy.PolicyID != w.policy ||
		p.ObservedPolicyID != w.policy || p.Policy.VerifiedAt.IsZero() {
		return ErrFoundationFenced
	}
	if err := (&SourceFounder{iam: *w.iam}).verifyPolicy(ociclient.CheckpointContext(ctx), SourcePolicyRecord{Request: p.Policy.Request, PolicyID: w.policy}); err != nil {
		return err
	}
	return w.guardBirth(ctx)
}

func (w *CapacityJournalWriter) boundedContext(ctx context.Context) (context.Context, func()) {
	bounded, cancel := context.WithDeadline(ctx, w.expires)
	stop := context.AfterFunc(w.original, cancel)
	return bounded, func() { stop(); cancel() }
}

func (w *CapacityJournalWriter) operationContext(ctx context.Context) (context.Context, func()) {
	return w.boundedContext(ociclient.CheckpointContext(ctx))
}

func (w *CapacityJournalWriter) Load(ctx context.Context, cell string) (FoundationRecord, string, error) {
	if w == nil || !slices.Contains(w.cells, cell) {
		return FoundationRecord{}, "", ErrFoundationFenced
	}
	if err := w.Guard(ctx); err != nil {
		return FoundationRecord{}, "", err
	}
	ctx, release := w.operationContext(ctx)
	defer release()
	record, etag, err := w.store.Load(ctx, cell)
	if err != nil {
		return FoundationRecord{}, "", err
	}
	if err := w.Guard(ctx); err != nil {
		return FoundationRecord{}, "", err
	}
	return record, etag, nil
}

func (w *CapacityJournalWriter) CompareAndSwap(ctx context.Context, record FoundationRecord, etag string) (string, error) {
	if w == nil || etag == "" || !slices.Contains(w.cells, record.Cell) {
		return "", ErrFoundationFenced
	}
	if err := w.Guard(ctx); err != nil {
		return "", err
	}
	// Freeze caller maps and pointers before admission rereads the protected head.
	wire, err := json.Marshal(record, json.Deterministic(true))
	if err != nil || len(wire) > foundationJournalLimit {
		return "", errors.Join(ErrFoundationFenced, err)
	}
	var next FoundationRecord
	if err := json.Unmarshal(wire, &next, json.RejectUnknownMembers(true)); err != nil {
		return "", err
	}
	ctx, release := w.operationContext(ctx)
	defer release()
	admit := func(ctx context.Context) error {
		if err := w.Guard(ctx); err != nil {
			return err
		}
		previous, observed, err := w.store.Load(ociclient.CheckpointContext(ctx), next.Cell)
		if err != nil {
			return err
		}
		if observed != etag {
			return ErrFoundationConflict
		}
		if err := validateCapacityOnlyDelta(previous, next); err != nil {
			return err
		}
		return w.Guard(ctx)
	}
	if err := admit(ctx); err != nil {
		return "", err
	}
	ctx = ociclient.WithAdmission(ctx, func(ctx context.Context) (func(), error) {
		if err := admit(ctx); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
	return w.store.CompareAndSwap(ctx, next, etag)
}

func capacityWriterDigest(record FoundationWriterRecord) (string, error) {
	record.CapacityJournal = nil
	record.CapacityJournalScopes = nil
	wire, err := json.Marshal(record, json.Deterministic(true))
	return digestSource(wire), err
}

func capacityJournalPolicy(record FoundationWriterRecord) (identity.CreatePolicyDetails, error) {
	return capacityPolicyDetails(record, []string{"GRU", "SJC", "FRA"}, "ts-capacity-journal-"+digestSource([]byte(record.InstallationID + "\x00" + record.InstanceID))[:32])
}

func capacityScopeID(writer, purpose string, cells []string) (string, error) {
	if len(cells) == 0 || !slices.IsSorted(cells) {
		return "", ErrFoundationFenced
	}
	for i, cell := range cells {
		entry, ok := catalog.Lookup(cell)
		if !ok || entry.Cell != cell || i > 0 && cells[i-1] == cell {
			return "", ErrFoundationFenced
		}
	}
	wire, err := json.Marshal(cells, json.Deterministic(true))
	return digestSource([]byte(writer + "\x00" + purpose + "\x00" + string(wire))), err
}

func capacityScopePolicy(record FoundationWriterRecord, purpose string, cells []string) (identity.CreatePolicyDetails, string, error) {
	writer, err := capacityWriterDigest(record)
	if err != nil {
		return identity.CreatePolicyDetails{}, "", err
	}
	scope, err := capacityScopeID(writer, purpose, cells)
	if err != nil {
		return identity.CreatePolicyDetails{}, "", err
	}
	details, err := capacityPolicyDetails(record, cells, "ts-capacity-journal-"+scope[:32])
	return details, scope, err
}

func capacityPolicyDetails(record FoundationWriterRecord, cells []string, name string) (identity.CreatePolicyDetails, error) {
	if record.Cell != "GRU" || !sourceInstancePattern.MatchString(record.InstanceID) ||
		!sourceCompartmentPattern.MatchString(record.BucketCompartment) || !sourceStoragePattern.MatchString(record.Bucket) {
		return identity.CreatePolicyDetails{}, ErrFoundationFenced
	}
	statements := make([]string, 0, len(cells))
	for _, cell := range cells {
		statements = append(statements, fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {request.principal.type='instance', request.principal.id='%s', target.bucket.name='%s', target.object.name='%s%s.json', any {request.permission='OBJECT_READ', request.permission='OBJECT_OVERWRITE'}}", record.BucketCompartment, record.InstanceID, record.Bucket, foundationObjectPrefix, cell))
	}
	return identity.CreatePolicyDetails{CompartmentId: new(record.BucketCompartment), Name: new(name), Description: new("Original HOME capacity-only protected journal updates"), Statements: statements, FreeformTags: map[string]string{}, DefinedTags: map[string]map[string]any{}}, nil
}

func capacityPolicyAt(record *FoundationWriterRecord, scope string) *CapacityJournalPolicy {
	if record == nil {
		return nil
	}
	if scope == "" {
		return record.CapacityJournal
	}
	p, ok := record.CapacityJournalScopes[scope]
	if !ok {
		return nil
	}
	return &p
}

func capacityPolicyCells(p *CapacityJournalPolicy) []string {
	if len(p.Cells) == 0 {
		return []string{"FRA", "GRU", "SJC"}
	}
	return p.Cells
}

func (w *CapacityJournalWriter) install(ctx context.Context) error {
	ctx, release, err := w.authority.HomeWrite(ociclient.CheckpointContext(ctx), 0)
	if err != nil {
		return err
	}
	defer release()
	ctx, finish := w.operationContext(ctx)
	defer finish()
	if err := w.guardBirth(ctx); err != nil {
		return err
	}
	record, _, err := w.store.Load(ctx, "GRU")
	if err != nil || record.FoundationWriter == nil {
		return errors.Join(ErrFoundationFenced, err)
	}
	details, scope, err := capacityScopePolicy(*record.FoundationWriter, w.purpose, w.cells)
	if err != nil {
		return err
	}
	if record.FoundationWriter.CapacityJournal != nil && slices.Equal(w.cells, []string{"FRA", "GRU", "SJC"}) {
		scope = ""
		details, err = capacityJournalPolicy(*record.FoundationWriter)
		if err != nil {
			return err
		}
	}
	w.scope = scope
	actor := &SourceFounder{iam: *w.iam}
	// A new signed scope may positively resolve old dispatches, never retry
	// them or replace an unknown outcome with a fresh reservation.
	keys := slices.Sorted(maps.Keys(record.FoundationWriter.CapacityJournalScopes))
	if record.FoundationWriter.CapacityJournal != nil {
		keys = append([]string{""}, keys...)
	}
	covered := map[string]bool{}
	for _, key := range keys {
		p := capacityPolicyAt(record.FoundationWriter, key)
		if key == scope {
			continue
		}
		if err := w.reconcilePolicy(ctx, key, p, actor); err != nil {
			return err
		}
		for _, cell := range capacityPolicyCells(p) {
			covered[cell] = true
		}
	}
	record, _, err = w.store.Load(ctx, "GRU")
	if err != nil || record.FoundationWriter == nil {
		return errors.Join(ErrFoundationFenced, err)
	}
	body, err := foundationWriterPolicyBody(details)
	if err != nil {
		return err
	}
	found, err := actor.findPolicy(ctx, details)
	if err != nil {
		return err
	}
	p := capacityPolicyAt(record.FoundationWriter, scope)
	if p == nil {
		if found != "" {
			return errors.New("discovered capacity IAM policy lacks its original protected reservation")
		}
		for _, cell := range w.cells {
			existing, _, err := w.store.Load(ctx, cell)
			if err != nil {
				return err
			}
			if !covered[cell] && (existing.CapacityLedger != nil || len(existing.CapacityCreates) != 0 || len(existing.CapacityPools) != 0 ||
				len(existing.PoolChildren) != 0 || len(existing.PoolQuarantines) != 0 || len(existing.PoolDrains) != 0) {
				return errors.New("unexplained capacity history cannot acquire replacement journal authority")
			}
		}
		operation := digestSource([]byte(w.writer + "\x00" + w.grant + "\x00" + w.purpose + "\x00" + scope))
		reserved := CapacityJournalPolicy{Cells: slices.Clone(w.cells), OperationID: operation, WriterSHA256: w.writer, GrantSHA256: w.grant,
			Generation: w.generation, PurposeSHA256: w.purpose, ExpiresAt: w.signedExpiry,
			Policy: FoundationWriterPolicy{Request: details, RequestDigest: digestSource(body),
				RetryToken: digestSource([]byte(operation + "\x00" + digestSource(body))), FirstAttemptAt: time.Now().UTC()}}
		if err := w.savePolicy(ctx, scope, nil, reserved); err != nil {
			return err
		}
		p = &reserved
	}
	if p.Policy.PolicyID != "" {
		if found != p.Policy.PolicyID || p.ObservedPolicyID != found {
			return errors.New("original capacity IAM policy identity changed")
		}
		if err := actor.verifyPolicy(ctx, SourcePolicyRecord{Request: p.Policy.Request, PolicyID: found}); err != nil {
			return err
		}
		w.policy = found
		return nil
	}
	if p.ObservedPolicyID != "" && found != p.ObservedPolicyID {
		return errors.New("observed original capacity IAM policy disappeared or changed")
	}
	if found != "" && len(p.Attempts) == 0 {
		return errors.New("discovered capacity IAM policy lacks an original dispatched request")
	}
	if found == "" {
		// A current purpose may observe an original outcome, never renew the
		// authority or deadline of an unresolved policy creation.
		if p.GrantSHA256 != w.grant || p.Generation != w.generation || p.PurposeSHA256 != w.purpose || !p.ExpiresAt.Equal(w.signedExpiry) {
			return errors.New("pending capacity IAM policy cannot acquire successor grant authority")
		}
		until := p.Policy.FirstAttemptAt.Add(bootstrapRetryLifetime)
		if p.ExpiresAt.Before(until) {
			until = p.ExpiresAt
		}
		if !time.Now().Before(until) || len(p.Attempts) >= 128 {
			return errors.New("original capacity IAM policy dispatch authority expired or exhausted")
		}
		next := *p
		next.Attempts = append(slices.Clone(p.Attempts), time.Now().UTC())
		if err := w.savePolicy(ctx, scope, p, next); err != nil {
			return err
		}
		p = &next
		createCtx := ociclient.WithAdmission(ctx, func(ctx context.Context) (func(), error) {
			if err := w.guardBirth(ctx); err != nil {
				return nil, err
			}
			current, _, err := w.store.Load(ociclient.CheckpointContext(ctx), "GRU")
			if err != nil || current.FoundationWriter == nil || !sameCapacityPolicy(capacityPolicyAt(current.FoundationWriter, scope), p) {
				return nil, errors.Join(ErrFoundationFenced, err)
			}
			if err := w.guardBirth(ctx); err != nil {
				return nil, err
			}
			if err := ociclient.LimitAdmission(ctx, until); err != nil {
				return nil, err
			}
			return func() {}, nil
		})
		noRetry := common.NoRetryPolicy()
		response, err := w.iam.CreatePolicy(ociclient.RequestContext(createCtx), identity.CreatePolicyRequest{
			CreatePolicyDetails: p.Policy.Request, OpcRetryToken: new(p.Policy.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
		if err != nil {
			return err
		}
		if response.Id == nil || !validAuxiliaryID("controller_usage_policy", *response.Id, "") {
			return errors.New("capacity IAM create omitted its original policy identity")
		}
		found = *response.Id
		observed := *p
		observed.ObservedPolicyID, observed.ObservedAt = found, time.Now().UTC()
		if err := w.savePolicy(ctx, scope, p, observed); err != nil {
			return err
		}
		p = &observed
	}
	if err := actor.verifyPolicy(ctx, SourcePolicyRecord{Request: p.Policy.Request, PolicyID: found}); err != nil {
		return err
	}
	verified := *p
	if verified.ObservedPolicyID == "" {
		verified.ObservedPolicyID, verified.ObservedAt = found, time.Now().UTC()
	}
	verified.Policy.PolicyID, verified.Policy.VerifiedAt = found, time.Now().UTC()
	if err := w.savePolicy(ctx, scope, p, verified); err != nil {
		return err
	}
	w.policy = found
	return nil
}

// Historical scopes can only append authenticated outcome evidence. No dispatch
// is issued under a successor grant, including when a response was lost.
func (w *CapacityJournalWriter) reconcilePolicy(ctx context.Context, scope string, p *CapacityJournalPolicy, actor *SourceFounder) error {
	found, err := actor.findPolicy(ctx, p.Policy.Request)
	if err != nil {
		return err
	}
	if found == "" || len(p.Attempts) == 0 || p.ObservedPolicyID != "" && p.ObservedPolicyID != found || p.Policy.PolicyID != "" && p.Policy.PolicyID != found {
		return errors.New("earlier capacity policy outcome is unresolved or changed")
	}
	if err := actor.verifyPolicy(ctx, SourcePolicyRecord{Request: p.Policy.Request, PolicyID: found}); err != nil {
		return err
	}
	if err := w.guardBirth(ctx); err != nil {
		return err
	}
	if p.Policy.PolicyID != "" {
		return nil
	}
	next := *p
	if next.ObservedPolicyID == "" {
		next.ObservedPolicyID, next.ObservedAt = found, time.Now().UTC()
	}
	next.Policy.PolicyID, next.Policy.VerifiedAt = found, time.Now().UTC()
	return w.savePolicy(ctx, scope, p, next)
}

func (w *CapacityJournalWriter) savePolicy(ctx context.Context, scope string, previous *CapacityJournalPolicy, next CapacityJournalPolicy) error {
	// Freeze all nested request maps/slices and dispatch evidence before admission.
	wire, err := json.Marshal(next, json.Deterministic(true))
	if err != nil {
		return err
	}
	var frozen CapacityJournalPolicy
	if err := json.Unmarshal(wire, &frozen, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	next = frozen
	if err := w.guardBirth(ctx); err != nil {
		return err
	}
	record, etag, err := w.store.Load(ociclient.CheckpointContext(ctx), "GRU")
	if err != nil || etag == "" || record.FoundationWriter == nil || !sameCapacityPolicy(capacityPolicyAt(record.FoundationWriter, scope), previous) {
		return errors.Join(ErrFoundationFenced, err)
	}
	writer := *record.FoundationWriter
	if scope == "" {
		writer.CapacityJournal = &next
	} else {
		writer.CapacityJournalScopes = maps.Clone(writer.CapacityJournalScopes)
		if writer.CapacityJournalScopes == nil {
			writer.CapacityJournalScopes = map[string]CapacityJournalPolicy{}
		}
		writer.CapacityJournalScopes[scope] = next
	}
	if err := writer.validate(); err != nil {
		return err
	}
	record.FoundationWriter, record.UpdatedAt = &writer, time.Now().UTC()
	ctx = ociclient.WithAdmission(ociclient.CheckpointContext(ctx), func(ctx context.Context) (func(), error) {
		if err := w.guardBirth(ctx); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
	_, err = w.store.CompareAndSwap(ctx, record, etag)
	return err
}

func sameCapacityPolicy(a, b *CapacityJournalPolicy) bool {
	x, err := json.Marshal(a, json.Deterministic(true))
	y, otherErr := json.Marshal(b, json.Deterministic(true))
	return err == nil && otherErr == nil && bytes.Equal(x, y)
}

func (record FoundationWriterRecord) validateCapacityJournal() error {
	if p := record.CapacityJournal; p != nil {
		if len(p.Cells) != 0 {
			return errors.New("legacy capacity policy cannot acquire a new scope")
		}
		if err := record.validateCapacityPolicy("", p); err != nil {
			return err
		}
	}
	for scope, p := range record.CapacityJournalScopes {
		if scope == "" || len(p.Cells) == 0 {
			return ErrFoundationFenced
		}
		if err := record.validateCapacityPolicy(scope, &p); err != nil {
			return err
		}
	}
	return nil
}

func (record FoundationWriterRecord) validateCapacityPolicy(scope string, p *CapacityJournalPolicy) error {
	writer, err := capacityWriterDigest(record)
	details, detailsErr := capacityJournalPolicy(record)
	if scope != "" {
		var computed string
		details, computed, detailsErr = capacityScopePolicy(record, p.PurposeSHA256, p.Cells)
		if computed != scope {
			return errors.New("capacity policy scope key differs from its exact cells")
		}
	}
	expected, wireErr := foundationWriterPolicyBody(details)
	actual, actualErr := foundationWriterPolicyBody(p.Policy.Request)
	purpose, purposeErr := json.Marshal(WorkerCapacityJournal{Purpose: CapacityJournalPurposeV1, Principal: CapacityJournalPrincipalV1, Delta: CapacityJournalDeltaV1}, json.Deterministic(true))
	operationInput := writer + "\x00" + p.GrantSHA256 + "\x00" + p.PurposeSHA256
	if scope != "" {
		operationInput += "\x00" + scope
	}
	operation := digestSource([]byte(operationInput))
	if err != nil || detailsErr != nil || wireErr != nil || actualErr != nil || purposeErr != nil || record.Policy == nil || record.Policy.PolicyID == "" ||
		p.WriterSHA256 != writer || !sourceDigest(p.GrantSHA256) || p.Generation < record.Generation || p.PurposeSHA256 != digestSource(purpose) ||
		p.OperationID != operation || !bytes.Equal(expected, actual) || p.Policy.RequestDigest != digestSource(actual) ||
		p.Policy.RetryToken != digestSource([]byte(operation+"\x00"+p.Policy.RequestDigest)) ||
		p.Policy.FirstAttemptAt.Before(record.Policy.VerifiedAt) || !p.ExpiresAt.After(p.Policy.FirstAttemptAt) ||
		len(p.Attempts) > 128 || (p.ObservedPolicyID == "") != p.ObservedAt.IsZero() ||
		p.ObservedPolicyID != "" && (!validAuxiliaryID("controller_usage_policy", p.ObservedPolicyID, "") || p.ObservedAt.Before(p.Policy.FirstAttemptAt)) ||
		p.ObservedPolicyID != "" && len(p.Attempts) == 0 ||
		p.Policy.PolicyID == "" && !p.Policy.VerifiedAt.IsZero() || p.Policy.PolicyID != "" &&
		(p.Policy.PolicyID != p.ObservedPolicyID || p.Policy.VerifiedAt.Before(p.ObservedAt)) {
		return errors.New("capacity policy differs from its original signed purpose or canonical request")
	}
	previous := p.Policy.FirstAttemptAt
	for _, at := range p.Attempts {
		if at.Before(previous) || !at.Before(p.ExpiresAt) || !at.Before(p.Policy.FirstAttemptAt.Add(bootstrapRetryLifetime)) {
			return errors.New("capacity policy dispatch history exceeds its original authority")
		}
		previous = at
	}
	if p.ObservedPolicyID != "" && p.ObservedAt.Before(previous) {
		return errors.New("capacity policy result predates its original dispatch history")
	}
	return nil
}

func (next FoundationRecord) retainCapacityJournal(previous FoundationRecord) error {
	if previous.FoundationWriter == nil {
		return nil
	}
	before := previous.FoundationWriter
	if before.CapacityJournal == nil && len(before.CapacityJournalScopes) == 0 {
		return nil
	}
	if next.FoundationWriter == nil {
		return errors.New("original capacity policy reservations cannot be removed")
	}
	after := next.FoundationWriter
	if err := retainCapacityPolicy(before.CapacityJournal, after.CapacityJournal); err != nil {
		return err
	}
	for scope, old := range before.CapacityJournalScopes {
		if err := retainCapacityPolicy(&old, capacityPolicyAt(after, scope)); err != nil {
			return err
		}
	}
	added := before.CapacityJournal == nil && after.CapacityJournal != nil
	for scope := range after.CapacityJournalScopes {
		if _, ok := before.CapacityJournalScopes[scope]; !ok {
			added = true
		}
	}
	if added {
		if before.CapacityJournal != nil && before.CapacityJournal.Policy.PolicyID == "" {
			return errors.New("unresolved original capacity policy blocks a new scope")
		}
		for _, p := range before.CapacityJournalScopes {
			if p.Policy.PolicyID == "" {
				return errors.New("unresolved capacity policy blocks a new scope")
			}
		}
	}
	return nil
}

func retainCapacityPolicy(old, current *CapacityJournalPolicy) error {
	if old == nil {
		return nil
	}
	if current == nil {
		return errors.New("original capacity policy reservation cannot be removed")
	}
	p := *current
	if len(p.Attempts) < len(old.Attempts) || !slices.Equal(p.Attempts[:len(old.Attempts)], old.Attempts) ||
		old.ObservedPolicyID != "" && (p.ObservedPolicyID != old.ObservedPolicyID || !p.ObservedAt.Equal(old.ObservedAt)) ||
		old.Policy.PolicyID != "" && (p.Policy.PolicyID != old.Policy.PolicyID || !p.Policy.VerifiedAt.Equal(old.Policy.VerifiedAt)) {
		return errors.New("original capacity policy outcome or dispatch history cannot be replaced")
	}
	p.Attempts, p.ObservedPolicyID, p.ObservedAt = old.Attempts, old.ObservedPolicyID, old.ObservedAt
	p.Policy.PolicyID, p.Policy.VerifiedAt = old.Policy.PolicyID, old.Policy.VerifiedAt
	expected, err := json.Marshal(old, json.Deterministic(true))
	actual, actualErr := json.Marshal(p, json.Deterministic(true))
	if err != nil || actualErr != nil || !bytes.Equal(expected, actual) {
		return errors.New("original capacity policy authority or request cannot be rebound")
	}
	return nil
}
