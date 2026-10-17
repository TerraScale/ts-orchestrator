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
	if ctx == nil || authority == nil || authority.operator != nil || !scope.IsVerified() {
		return ErrFoundationFenced
	}
	ctx, cancelScope := context.WithDeadline(ctx, scope.ExpiresAt())
	defer cancelScope()
	writerDeadline, err := authority.FoundationWriterDeadline(ctx)
	if err != nil {
		return err
	}
	ctx, cancelWriter := context.WithDeadline(ctx, writerDeadline)
	defer cancelWriter()
	entry, ok := catalog.CellForOCIRegion(authority.factory.Region())
	if !ok || scope.Intent().OCIRegion != entry.OCIRegion || scope.TenancyID() != authority.tenancyID || scope.InstallationID() != authority.installationID || scope.GrantDigest() != authority.grantDigest || scope.Generation() != authority.grantGeneration {
		return ErrFoundationFenced
	}
	record, _, err := authority.resolver.Store.Load(ctx, entry.Cell)
	if err != nil {
		return err
	}
	writer := record.FoundationWriter
	if writer == nil || writer.InstanceID != authority.instanceID || writer.OCIRAuthority == nil || writer.validate() != nil || record.Stage != "reconciled" || record.LeaseID != "" || record.GrantSHA256 != scope.GrantDigest() || record.Generation != scope.Generation() {
		return ErrFoundationFenced
	}
	installed := writer.OCIRAuthority
	ctx, cancelInstalled := context.WithDeadline(ctx, installed.AuthorityExpiresAt)
	defer cancelInstalled()
	current, expires, err := ocirAuthorityScope(ctx, authority.resolver, *writer)
	if err != nil {
		return err
	}
	if installed.FoundationOperation != record.OperationID || installed.Epoch != record.Epoch || !reflect.DeepEqual(installed.Scope, current) || !slices.Contains(current, scope.Intent()) || !installed.AuthorityExpiresAt.Equal(expires) || !installed.AuthorityExpiresAt.Equal(scope.ExpiresAt()) || !time.Now().Before(installed.AuthorityExpiresAt) {
		return ErrFoundationFenced
	}
	home, err := authority.factory.HomeRegion(ctx, authority.tenancyID)
	if err != nil {
		return err
	}
	factory, err := authority.factory.ForRegion(home)
	if err != nil {
		return err
	}
	iam, err := factory.Identity()
	if err != nil {
		return err
	}
	for _, policy := range installed.Policies {
		if policy.PolicyID == "" || policy.VerifiedAt.IsZero() {
			return ErrFoundationFenced
		}
		if err := verifyOCIRAuthorityPolicy(ctx, iam, policy, policy.PolicyID); err != nil {
			return err
		}
	}
	if err := authority.guardScope(ctx); err != nil {
		return err
	}
	return ociclient.LimitAdmission(ctx, installed.AuthorityExpiresAt)
}
