package region

import (
	"cmp"
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

func ocirAuthorityScope(ctx context.Context, resolver FoundationResolver, writer FoundationWriterRecord) ([]OCIRIssuerIntent, time.Time, error) {
	scopes, err := resolver.OCIRIssuers(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	intents := []OCIRIssuerIntent{}
	var expires time.Time
	for _, scope := range scopes {
		if scope.Intent().OCIRegion != catalog.OCIRegion(writer.Cell) {
			continue
		}
		if scope.GrantDigest() != writer.GrantSHA256 || scope.Generation() != writer.Generation || scope.InstallationID() != writer.InstallationID || !expires.IsZero() && !expires.Equal(scope.ExpiresAt()) {
			return nil, time.Time{}, ErrFoundationFenced
		}
		expires = scope.ExpiresAt()
		intents = append(intents, scope.Intent())
	}
	slices.SortFunc(intents, func(a, b OCIRIssuerIntent) int {
		if a.RepositoryCompartmentID != b.RepositoryCompartmentID {
			return cmp.Compare(a.RepositoryCompartmentID, b.RepositoryCompartmentID)
		}
		return cmp.Compare(a.RepositoryName, b.RepositoryName)
	})
	if len(intents) == 0 || len(intents) > 64 || !time.Now().Before(expires) {
		return nil, time.Time{}, ErrFoundationFenced
	}
	return intents, expires, nil
}

func sameOCIRAuthorityOrigin(a, b OCIRAuthorityRecord) bool {
	a.Policies, b.Policies = nil, nil
	return reflect.DeepEqual(a, b)
}

func (reservation OCIRAuthorityRecord) installed() bool {
	if len(reservation.Policies) == 0 {
		return false
	}
	for _, policy := range reservation.Policies {
		if policy.PolicyID == "" || policy.VerifiedAt.IsZero() {
			return false
		}
	}
	return true
}

func (reservation OCIRAuthorityRecord) recoveryDeadline() time.Time {
	if !reservation.installed() && reservation.DispatchExpiresAt.Before(reservation.AuthorityExpiresAt) {
		return reservation.DispatchExpiresAt
	}
	return reservation.AuthorityExpiresAt
}

// installOCIRAuthority is reachable only from authenticated OPERATOR provisioning.
// Existing POLICY_CREATE privilege is unchanged; this source boundary does not
// establish native IAM prevention of runtime self-grants.
func installOCIRAuthority(ctx context.Context, authority *HomeIAMAuthority, resolver FoundationResolver, bundle RetainedFoundation, cell string, receipt OriginalFoundationWriter) error {
	if ctx == nil || authority == nil || authority.operator == nil || receipt.cell != cell {
		return ErrFoundationFenced
	}
	ctx, cancelOperator := context.WithDeadline(ctx, authority.operator.deadline)
	defer cancelOperator()
	ctx, release, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	factory, ctx, err := authority.GuardedFactory(ctx)
	if err != nil {
		return err
	}
	material, err := resolver.BootstrapMaterial(ctx, cell)
	if err != nil {
		return err
	}
	ctx, cancelMaterial := context.WithDeadline(ctx, material.ExpiresAt())
	defer cancelMaterial()
	image, imageExpected, err := foundationWriterImage(ctx, resolver, material, cell)
	if err != nil {
		return err
	}
	ctx, cancelImage := context.WithDeadline(ctx, image.ExpiresAt())
	defer cancelImage()
	record, etag, err := resolver.Store.Load(ctx, cell)
	if err != nil {
		return err
	}
	writer := record.FoundationWriter
	if writer == nil || writer.validate() != nil || receipt.instance == "" || writer.InstanceID != receipt.instance || writer.RequestDigest != receipt.request || writer.GrantSHA256 != receipt.grant || receipt.grant != digestSource(bundle.GrantWire) || record.Stage != "reconciled" || record.LeaseID != "" || record.GrantSHA256 != writer.GrantSHA256 || record.Generation != writer.Generation || writer.Policy == nil || writer.Policy.PolicyID == "" || writer.Policy.VerifiedAt.IsZero() {
		return ErrFoundationFenced
	}
	if saved := writer.OCIRAuthority; saved != nil {
		bounded, cancelRetained := context.WithDeadline(ctx, saved.recoveryDeadline())
		defer cancelRetained()
		ctx = bounded
	}
	scope, expires, err := ocirAuthorityScope(ctx, resolver, *writer)
	if err != nil {
		return err
	}
	ctx, cancelScope := context.WithDeadline(ctx, expires)
	defer cancelScope()
	now := time.Now().UTC()
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("OCIR authority installation requires its original operator deadline")
	}
	for _, limit := range []time.Time{authority.operator.deadline, material.ExpiresAt(), image.ExpiresAt(), now.Add(bootstrapRetryLifetime), expires} {
		if limit.Before(deadline) {
			deadline = limit
		}
	}
	writerDigest, err := ocirWriterDigest(*writer)
	if err != nil {
		return err
	}
	scopeDigest, err := ocirAuthorityScopeDigest(scope)
	if err != nil {
		return err
	}
	pending := OCIRAuthorityRecord{FoundationOperation: record.OperationID, Epoch: record.Epoch, WriterSHA256: writerDigest, ScopeSHA256: scopeDigest, Scope: scope, FirstAttemptAt: now, DispatchExpiresAt: deadline.UTC(), AuthorityExpiresAt: expires.UTC()}
	if writer.OCIRAuthority != nil {
		pending = *writer.OCIRAuthority
		if pending.WriterSHA256 != writerDigest || pending.ScopeSHA256 != scopeDigest || !pending.AuthorityExpiresAt.Equal(expires) || pending.FoundationOperation != record.OperationID || pending.Epoch != record.Epoch {
			return ErrFoundationFenced
		}
	} else {
		pending.Policies, err = ocirAuthorityPolicies(*writer, pending)
		if err != nil {
			return err
		}
	}
	if err := pending.validate(*writer); err != nil {
		return err
	}
	cap := pending.recoveryDeadline()
	ctx, cancelAttempt := context.WithDeadline(ctx, cap)
	defer cancelAttempt()
	guard := func(ctx context.Context) error {
		if err := authority.Guard(ctx, 0); err != nil {
			return err
		}
		currentScope, currentExpiry, err := ocirAuthorityScope(ctx, resolver, *writer)
		if err != nil || !reflect.DeepEqual(scope, currentScope) || !currentExpiry.Equal(pending.AuthorityExpiresAt) {
			return errors.Join(ErrFoundationFenced, err)
		}
		current, _, err := resolver.Store.Load(ctx, cell)
		if err != nil {
			return err
		}
		if current.Stage != "reconciled" || current.LeaseID != "" || current.OperationID != pending.FoundationOperation || current.Epoch != pending.Epoch || current.Generation != writer.Generation || current.GrantSHA256 != writer.GrantSHA256 || !sameFoundationWriterOriginal(writer, current.FoundationWriter) || current.FoundationWriter.OCIRAuthority != nil && !sameOCIRAuthorityOrigin(pending, *current.FoundationWriter.OCIRAuthority) {
			return ErrFoundationFenced
		}
		if err := material.Revalidate(ctx); err != nil {
			return err
		}
		if _, _, err := foundationWriterImage(ctx, resolver, material, cell); err != nil {
			return err
		}
		if err := image.ValidFor(imageExpected, time.Now()); err != nil {
			return err
		}
		if err := ociclient.LimitAdmission(ctx, cap); err != nil {
			return err
		}
		return authority.Guard(ctx, 0)
	}
	if err := guard(ctx); err != nil {
		return err
	}
	if writer.OCIRAuthority == nil {
		copy := *writer
		copy.OCIRAuthority = &pending
		record.FoundationWriter = &copy
		record.UpdatedAt = time.Now().UTC()
		if _, err := resolver.Store.CompareAndSwap(ctx, record, etag); err != nil {
			return err
		}
	}
	home, err := factory.HomeRegion(ctx, bundle.TenancyID)
	if err != nil {
		return err
	}
	homeFactory, err := factory.ForRegion(home)
	if err != nil {
		return err
	}
	iam, err := homeFactory.Identity()
	if err != nil {
		return err
	}
	journal := &ocirAuthorityJournal{resolver: resolver, cell: cell, writer: *writer, original: pending, guard: guard, home: home}
	ctx = ociclient.WithAuthority(ctx, guard)
	ctx = ociclient.WithRequestGuard(ctx, guard)
	ctx = ociclient.WithAdmission(ctx, func(ctx context.Context) (func(), error) {
		if err := guard(ctx); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
	for index := range pending.Policies {
		current, _, err := journal.read(ctx)
		if err != nil {
			return err
		}
		policy := current.FoundationWriter.OCIRAuthority.Policies[index]
		id := policy.PolicyID
		if id == "" {
			for _, dispatch := range policy.Dispatches {
				if dispatch.ObservedID != "" {
					if id != "" && id != dispatch.ObservedID {
						return ErrFoundationFenced
					}
					id = dispatch.ObservedID
				}
			}
		}
		if id == "" {
			noRetry := common.NoRetryPolicy()
			effect := ociclient.WithWireAttempt(ctx, journal.begin(index))
			response, err := iam.CreatePolicy(ociclient.RequestContext(effect), identity.CreatePolicyRequest{CreatePolicyDetails: policy.Request, OpcRetryToken: new(policy.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
			if err != nil {
				return err
			}
			if response.Id == nil || !validAuxiliaryID("controller_usage_policy", *response.Id, "") {
				return ErrFoundationFenced
			}
			id = *response.Id
		}
		if err := verifyOCIRAuthorityPolicy(ctx, iam, policy, id); err != nil {
			return err
		}
		if policy.PolicyID == "" {
			if err := journal.update(ctx, func(saved *OCIRAuthorityRecord) error {
				actual := &saved.Policies[index]
				if actual.PolicyID != "" {
					return ErrFoundationFenced
				}
				actual.PolicyID, actual.VerifiedAt = id, time.Now().UTC()
				return nil
			}); err != nil {
				return err
			}
		}
		readback, _, err := journal.read(ctx)
		if err != nil || readback.FoundationWriter.OCIRAuthority.Policies[index].PolicyID != id {
			return errors.Join(ErrFoundationFenced, err)
		}
	}
	return guard(ctx)
}
