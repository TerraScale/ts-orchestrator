package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/artifacts"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

func (a *issuerAttempt) repository(ctx context.Context) error {
	intent := a.issuer.scope.Intent()
	request := artifacts.ListContainerRepositoriesRequest{CompartmentId: new(intent.RepositoryCompartmentID), DisplayName: new(intent.RepositoryName)}
	found := ""
	for range 32 {
		response, err := a.issuer.artifacts.ListContainerRepositories(ociclient.RequestContext(ctx), request)
		if err != nil {
			return ErrIssuer
		}
		for _, repo := range response.Items {
			if text(repo.DisplayName) != intent.RepositoryName || text(repo.CompartmentId) != intent.RepositoryCompartmentID || !strings.HasPrefix(text(repo.Id), "ocid1.containerrepo.") ||
				repo.IsPublic == nil || *repo.IsPublic ||
				repo.LifecycleState != artifacts.ContainerRepositoryLifecycleStateAvailable || found != "" {
				return ErrIssuer
			}
			found = text(repo.Id)
		}
		if response.OpcNextPage == nil {
			if found == "" || a.state.RepositoryID != "" && a.state.RepositoryID != found {
				return ErrIssuer
			}
			observed, err := a.issuer.artifacts.GetContainerRepository(ociclient.RequestContext(ctx), artifacts.GetContainerRepositoryRequest{RepositoryId: new(found)})
			if err != nil || text(observed.Id) != found || text(observed.CompartmentId) != intent.RepositoryCompartmentID || text(observed.DisplayName) != intent.RepositoryName ||
				observed.IsPublic == nil || *observed.IsPublic || observed.IsImmutable == nil || !*observed.IsImmutable || observed.LifecycleState != artifacts.ContainerRepositoryLifecycleStateAvailable {
				return ErrIssuer
			}
			a.state.RepositoryID = found
			return a.save(ctx, true)
		}
		request.Page = response.OpcNextPage
	}
	return ErrIssuer
}

func (a *issuerAttempt) retry(step string) string {
	sum := sha256.Sum256([]byte(a.state.OperationID + "\x00" + step))
	return hex.EncodeToString(sum[:])
}

func (a *issuerAttempt) tags() map[string]string {
	return map[string]string{"terrascale-issuer-operation": a.state.OperationID, "terrascale-installation": a.issuer.scope.InstallationID()}
}

func (a *issuerAttempt) owned(tags map[string]string) bool {
	for k, v := range a.tags() {
		if tags[k] != v {
			return false
		}
	}
	return true
}

func (a *issuerAttempt) statement() string {
	intent := a.issuer.scope.Intent()
	return "Allow group id " + a.state.GroupID + " to read repos in compartment id " + intent.RepositoryCompartmentID + " where target.repo.name = '" + intent.RepositoryName + "'"
}

func (a *issuerAttempt) ensureIdentity(ctx context.Context) (identity.User, error) {
	i := a.issuer
	intent := i.scope.Intent()
	var user identity.User
	if a.state.UserID == "" {
		// OCI's persisted request token, never a mutable name/tag match, recovers creation.
		err := a.call(ctx, true, func(ctx context.Context) error {
			response, err := i.identity.CreateUser(ctx, identity.CreateUserRequest{CompartmentId: new(i.scope.TenancyID()), Name: new(intent.PrincipalName), Email: new(intent.PrincipalEmail), Description: new("TerraScale OCIR pull identity"), FreeformTags: a.tags(), OpcRetryToken: new(a.retry("user"))})
			user = response.User
			return err
		})
		if err != nil {
			return identity.User{}, err
		}
		if !strings.HasPrefix(text(user.Id), "ocid1.user.") || text(user.Name) != intent.PrincipalName || text(user.CompartmentId) != i.scope.TenancyID() || !a.owned(user.FreeformTags) {
			return identity.User{}, ErrIssuer
		}
		a.state.UserID = text(user.Id)
		if err := a.save(ctx, true); err != nil {
			return identity.User{}, err
		}
	}
	response, err := i.identity.GetUser(ociclient.RequestContext(ctx), identity.GetUserRequest{UserId: new(a.state.UserID)})
	if err != nil {
		return identity.User{}, ErrIssuer
	}
	user = response.User
	if text(user.Id) != a.state.UserID || text(user.Name) != intent.PrincipalName || text(user.Email) != intent.PrincipalEmail ||
		text(user.CompartmentId) != i.scope.TenancyID() || user.LifecycleState != identity.UserLifecycleStateActive ||
		user.IdentityProviderId != nil || user.ExternalIdentifier != nil || !a.owned(user.FreeformTags) {
		return identity.User{}, ErrIssuer
	}
	if !pullCapabilities(user.Capabilities) {
		if response.Etag == nil || text(response.Etag) == "" {
			return identity.User{}, ErrIssuer
		}
		if err := a.call(ctx, true, func(ctx context.Context) error {
			_, err := i.identity.UpdateUserCapabilities(ctx, identity.UpdateUserCapabilitiesRequest{UserId: new(a.state.UserID), IfMatch: response.Etag,
				CanUseConsolePassword: new(false), CanUseApiKeys: new(false), CanUseAuthTokens: new(true), CanUseSmtpCredentials: new(false), CanUseDBCredentials: new(false), CanUseCustomerSecretKeys: new(false), CanUseOAuth2ClientCredentials: new(false)})
			return err
		}); err != nil {
			return identity.User{}, err
		}
		response, err = i.identity.GetUser(ociclient.RequestContext(ctx), identity.GetUserRequest{UserId: new(a.state.UserID)})
		if err != nil || !pullCapabilities(response.Capabilities) {
			return identity.User{}, ErrIssuer
		}
	}
	if a.state.GroupID == "" {
		var group identity.Group
		if err := a.call(ctx, true, func(ctx context.Context) error {
			response, err := i.identity.CreateGroup(ctx, identity.CreateGroupRequest{CompartmentId: new(i.scope.TenancyID()), Name: new(intent.PrincipalName + "-pull"), Description: new("TerraScale exact repository readers"), FreeformTags: a.tags(), OpcRetryToken: new(a.retry("group"))})
			group = response.Group
			return err
		}); err != nil {
			return identity.User{}, err
		}
		if !strings.HasPrefix(text(group.Id), "ocid1.group.") || text(group.Name) != intent.PrincipalName+"-pull" || text(group.CompartmentId) != i.scope.TenancyID() || !a.owned(group.FreeformTags) {
			return identity.User{}, ErrIssuer
		}
		a.state.GroupID = text(group.Id)
		if err := a.save(ctx, true); err != nil {
			return identity.User{}, err
		}
	}
	group, err := i.identity.GetGroup(ociclient.RequestContext(ctx), identity.GetGroupRequest{GroupId: new(a.state.GroupID)})
	if err != nil || text(group.Id) != a.state.GroupID || text(group.Name) != intent.PrincipalName+"-pull" || text(group.CompartmentId) != i.scope.TenancyID() || group.LifecycleState != identity.GroupLifecycleStateActive || !a.owned(group.FreeformTags) {
		return identity.User{}, ErrIssuer
	}
	if a.state.PolicyID == "" {
		var policy identity.Policy
		if err := a.call(ctx, true, func(ctx context.Context) error {
			response, err := i.identity.CreatePolicy(ctx, identity.CreatePolicyRequest{CompartmentId: new(intent.RepositoryCompartmentID), Name: new(intent.PrincipalName + "-pull"), Description: new("TerraScale read only one OCIR repository"), Statements: []string{a.statement()}, FreeformTags: a.tags(), OpcRetryToken: new(a.retry("policy"))})
			policy = response.Policy
			return err
		}); err != nil {
			return identity.User{}, err
		}
		if !strings.HasPrefix(text(policy.Id), "ocid1.policy.") || !a.validPolicy(policy) {
			return identity.User{}, ErrIssuer
		}
		a.state.PolicyID = text(policy.Id)
		if err := a.save(ctx, true); err != nil {
			return identity.User{}, err
		}
	}
	policy, err := i.identity.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(a.state.PolicyID)})
	if err != nil || text(policy.Id) != a.state.PolicyID || !a.validPolicy(policy.Policy) || policy.LifecycleState != identity.PolicyLifecycleStateActive {
		return identity.User{}, ErrIssuer
	}
	if err := a.membership(ctx); err != nil {
		return identity.User{}, err
	}
	return user, nil
}

func (a *issuerAttempt) validPolicy(policy identity.Policy) bool {
	intent := a.issuer.scope.Intent()
	return text(policy.CompartmentId) == intent.RepositoryCompartmentID && text(policy.Name) == intent.PrincipalName+"-pull" && slices.Equal(policy.Statements, []string{a.statement()}) && a.owned(policy.FreeformTags)
}

func pullCapabilities(c *identity.UserCapabilities) bool {
	return c != nil && c.CanUseAuthTokens != nil && *c.CanUseAuthTokens &&
		c.CanUseConsolePassword != nil && !*c.CanUseConsolePassword && c.CanUseApiKeys != nil && !*c.CanUseApiKeys &&
		c.CanUseSmtpCredentials != nil && !*c.CanUseSmtpCredentials && c.CanUseDbCredentials != nil && !*c.CanUseDbCredentials &&
		c.CanUseCustomerSecretKeys != nil && !*c.CanUseCustomerSecretKeys && c.CanUseOAuth2ClientCredentials != nil && !*c.CanUseOAuth2ClientCredentials
}

func (a *issuerAttempt) membership(ctx context.Context) error {
	// A dedicated user must not acquire another group's permissions.
	request := identity.ListUserGroupMembershipsRequest{CompartmentId: new(a.issuer.scope.TenancyID()), UserId: new(a.state.UserID)}
	found := ""
	for range 32 {
		response, err := a.issuer.identity.ListUserGroupMemberships(ociclient.RequestContext(ctx), request)
		if err != nil {
			return ErrIssuer
		}
		for _, membership := range response.Items {
			if text(membership.UserId) != a.state.UserID || text(membership.GroupId) != a.state.GroupID || text(membership.CompartmentId) != a.issuer.scope.TenancyID() ||
				membership.LifecycleState != identity.UserGroupMembershipLifecycleStateActive || text(membership.Id) == "" || found != "" {
				return ErrIssuer
			}
			found = text(membership.Id)
		}
		if response.OpcNextPage == nil {
			if found != "" {
				if a.state.MembershipID != "" && a.state.MembershipID != found {
					return ErrIssuer
				}
				a.state.MembershipID = found
				return a.save(ctx, true)
			}
			if a.state.MembershipID != "" {
				return ErrIssuer
			}
			if err := a.call(ctx, true, func(ctx context.Context) error {
				response, err := a.issuer.identity.AddUserToGroup(ctx, identity.AddUserToGroupRequest{UserId: new(a.state.UserID), GroupId: new(a.state.GroupID)})
				if err == nil && text(response.UserId) == a.state.UserID && text(response.GroupId) == a.state.GroupID && text(response.Id) != "" {
					a.state.MembershipID = text(response.Id)
				} else if err == nil {
					return ErrIssuer
				}
				return err
			}); err != nil {
				return err
			}
			return a.save(ctx, true)
		}
		request.Page = response.OpcNextPage
	}
	return ErrIssuer
}
