package region

import (
	"context"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

func verifyOCIRAuthorityPolicy(ctx context.Context, iam identity.IdentityClient, policy OCIRAuthorityPolicy, id string) error {
	response, err := iam.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(id)})
	if err != nil {
		return err
	}
	if response.Id == nil || *response.Id != id || !matchesOCIRAuthorityPolicy(policy.Request, response.Policy) || response.LifecycleState != identity.PolicyLifecycleStateActive {
		return ErrFoundationFenced
	}
	return nil
}

// VerifyOCIRAuthority checks the separate installed repository capability.
// Its signed authority expiry survives the shorter original install session.
func (authority *HomeIAMAuthority) VerifyOCIRAuthority(ctx context.Context, scope VerifiedOCIRIssuer) error {
	_, err := authority.OCIRAuthorityDeadline(ctx, scope)
	return err
}

// OCIRAuthorityDeadline carries the verified writer and repository capability
// minimum through the root caller's remaining protected reads and effects.
func (authority *HomeIAMAuthority) OCIRAuthorityDeadline(ctx context.Context, scope VerifiedOCIRIssuer) (time.Time, error) {
	if ctx == nil || authority == nil || authority.operator != nil || !scope.IsVerified() {
		return time.Time{}, ErrFoundationFenced
	}
	ctx, cancelScope := context.WithDeadline(ctx, scope.ExpiresAt())
	defer cancelScope()
	writerDeadline, err := authority.FoundationWriterDeadline(ctx)
	if err != nil {
		return time.Time{}, err
	}
	ctx, cancelWriter := context.WithDeadline(ctx, writerDeadline)
	defer cancelWriter()
	entry, ok := catalog.CellForOCIRegion(authority.factory.Region())
	if !ok || scope.Intent().OCIRegion != entry.OCIRegion || scope.TenancyID() != authority.tenancyID || scope.InstallationID() != authority.installationID || scope.GrantDigest() != authority.grantDigest || scope.Generation() != authority.grantGeneration {
		return time.Time{}, ErrFoundationFenced
	}
	record, _, err := authority.resolver.Store.Load(ctx, entry.Cell)
	if err != nil {
		return time.Time{}, err
	}
	writer := record.FoundationWriter
	if writer == nil || writer.InstanceID != authority.instanceID || writer.OCIRAuthority == nil || writer.validate() != nil || record.Stage != "reconciled" || record.LeaseID != "" || record.GrantSHA256 != scope.GrantDigest() || record.Generation != scope.Generation() {
		return time.Time{}, ErrFoundationFenced
	}
	installed := writer.OCIRAuthority
	ctx, cancelInstalled := context.WithDeadline(ctx, installed.AuthorityExpiresAt)
	defer cancelInstalled()
	current, expires, err := ocirAuthorityScope(ctx, authority.resolver, *writer)
	if err != nil {
		return time.Time{}, err
	}
	if installed.FoundationOperation != record.OperationID || installed.Epoch != record.Epoch || !reflect.DeepEqual(installed.Scope, current) || !slices.Contains(current, scope.Intent()) || !installed.AuthorityExpiresAt.Equal(expires) || !installed.AuthorityExpiresAt.Equal(scope.ExpiresAt()) || !time.Now().Before(installed.AuthorityExpiresAt) {
		return time.Time{}, ErrFoundationFenced
	}
	home, err := authority.factory.HomeRegion(ctx, authority.tenancyID)
	if err != nil {
		return time.Time{}, err
	}
	factory, err := authority.factory.ForRegion(home)
	if err != nil {
		return time.Time{}, err
	}
	iam, err := factory.Identity()
	if err != nil {
		return time.Time{}, err
	}
	for _, policy := range installed.Policies {
		if policy.PolicyID == "" || policy.VerifiedAt.IsZero() {
			return time.Time{}, ErrFoundationFenced
		}
		if err := verifyOCIRAuthorityPolicy(ctx, iam, policy, policy.PolicyID); err != nil {
			return time.Time{}, err
		}
	}
	guardDeadline, err := authority.guardDeadline(ctx, 0)
	if err != nil {
		return time.Time{}, err
	}
	ctx, cancelGuard := context.WithDeadline(ctx, guardDeadline)
	defer cancelGuard()
	deadline, _ := ctx.Deadline()
	if err := ociclient.LimitAdmission(ctx, deadline); err != nil {
		return time.Time{}, err
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return deadline, nil
}
