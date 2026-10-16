package confinement

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// Verified cannot be constructed from a signed assertion or resource tags.
type Verified struct {
	scope               Scope
	observer, candidate *ociclient.Factory
	evidence            string
	boundary            string
	endpoint            string
}

func (v Verified) Scope() Scope                { return clone(v.scope) }
func (v Verified) EvidenceSHA256() string      { return v.evidence }
func (v Verified) Factory() *ociclient.Factory { return v.candidate }

// Revalidate observes the complete boundary again, including before cleanup.
// The caller separately enforces the earlier creation deadline in its approval.
func (v Verified) Revalidate(ctx context.Context, scope Scope) error {
	if v.evidence == "" || hash(immutableScope(scope)) != hash(immutableScope(v.scope)) {
		return errors.New("unverified or mismatched confinement")
	}
	current, err := observe(ctx, v.observer, v.candidate, scope, v.endpoint, time.Now())
	if err != nil {
		return err
	}
	if current.boundary != v.boundary {
		return errors.New("OCI confinement changed after preparation")
	}
	return nil
}

// Observe requires an explicit inventory reader, never ambient operator config.
// No credential is created, persisted or printed by this observer.
func Observe(ctx context.Context, observer, candidate *ociclient.Factory, scope Scope) (Verified, error) {
	return observe(ctx, observer, candidate, scope, "", time.Now())
}

type policyFact struct {
	ID, Compartment string
	Statements      []string
}
type facts struct {
	Principal, Group, Fingerprint, Namespace string
	Compartments                             []string
	Policies                                 []policyFact
	Subnet                                   core.Subnet
	VCN                                      core.Vcn
	Route                                    core.RouteTable
	Security                                 []core.SecurityList
	Hosts                                    []core.Instance
	VNICs                                    []core.Vnic
}

func observe(ctx context.Context, observer, candidate *ociclient.Factory, s Scope, endpoint string, now time.Time) (Verified, error) {
	fail := func(err error) (Verified, error) { return Verified{}, fmt.Errorf("disposable confinement: %w", err) }
	if err := s.validate(now); err != nil {
		return fail(err)
	}
	if observer == nil || candidate == nil || observer.Region() != candidate.Region() {
		return fail(errors.New("explicit matching-region observer and candidate required"))
	}
	for _, factory := range []*ociclient.Factory{observer, candidate} {
		tenancy, err := factory.Provider().TenancyOCID()
		if err != nil || tenancy != s.Tenancy {
			return fail(errors.New("provider tenancy differs from approved tenancy"))
		}
	}
	userID, err := candidate.Provider().UserOCID()
	if err != nil || userID != s.Principal {
		return fail(errors.New("provider principal differs from approved principal"))
	}
	fingerprint, err := candidate.Provider().KeyFingerprint()
	if err != nil || fingerprint == "" {
		return fail(errors.New("candidate API signing key fingerprint required"))
	}
	auth, err := candidate.Provider().AuthType()
	if err != nil || (auth.AuthType != common.UserPrincipal && auth.AuthType != common.UnknownAuthenticationType) || auth.OboToken != nil {
		return fail(errors.New("candidate requires direct IAM API-key authentication"))
	}
	keyID, err := candidate.Provider().KeyID()
	if err != nil || keyID != s.Tenancy+"/"+s.Principal+"/"+fingerprint {
		return fail(errors.New("candidate signing identity differs from independently approved user"))
	}
	key, err := candidate.Provider().PrivateRSAKey()
	if err != nil || key == nil {
		return fail(errors.New("candidate RSA signing key required"))
	}
	// Freeze provider identity/key together; a refreshable provider must not swap
	// the checked user for operator authority between observation and a write.
	provider := common.NewRawConfigurationProvider(s.Tenancy, s.Principal, candidate.Region(), fingerprint, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	candidate, err = ociclient.New(provider, ociclient.Options{Region: candidate.Region()})
	if err != nil {
		return fail(err)
	}
	iam, err := observer.Identity()
	if err != nil {
		return fail(err)
	}
	network, err := observer.Network()
	if err != nil {
		return fail(err)
	}
	compute, err := observer.Compute()
	if err != nil {
		return fail(err)
	}
	objects, err := candidate.ObjectStorage()
	if err != nil {
		return fail(err)
	}
	ociclient.PinHost(&iam.BaseClient, endpoint)
	ociclient.PinHost(&network.BaseClient, endpoint)
	ociclient.PinHost(&compute.BaseClient, endpoint)
	ociclient.PinHost(&objects.BaseClient, endpoint)
	// An authenticated candidate request proves possession of its issued key.
	namespace, err := objects.GetNamespace(ctx, objectstorage.GetNamespaceRequest{})
	if err != nil {
		return fail(err)
	}
	if namespace.Value == nil || *namespace.Value != s.Namespace {
		return fail(errors.New("authenticated candidate namespace differs"))
	}
	f := facts{Principal: s.Principal, Group: s.Group, Fingerprint: fingerprint, Namespace: *namespace.Value}
	user, err := iam.GetUser(ctx, identity.GetUserRequest{UserId: new(s.Principal)})
	if err != nil {
		return fail(err)
	}
	if text(user.Id) != s.Principal || text(user.CompartmentId) != s.Tenancy || user.LifecycleState != identity.UserLifecycleStateActive || text(user.IdentityProviderId) != "" || text(user.ExternalIdentifier) != "" {
		return fail(errors.New("candidate is not the exact active local IAM user"))
	}
	keys, err := iam.ListApiKeys(ctx, identity.ListApiKeysRequest{UserId: new(s.Principal)})
	if err != nil {
		return fail(err)
	}
	if len(keys.Items) != 1 || text(keys.Items[0].UserId) != s.Principal || text(keys.Items[0].Fingerprint) != fingerprint || keys.Items[0].LifecycleState != identity.ApiKeyLifecycleStateActive {
		return fail(errors.New("candidate must have exactly its observed active API signing key"))
	}
	group, err := iam.GetGroup(ctx, identity.GetGroupRequest{GroupId: new(s.Group)})
	if err != nil {
		return fail(err)
	}
	if text(group.Id) != s.Group || text(group.CompartmentId) != s.Tenancy || group.LifecycleState != identity.GroupLifecycleStateActive || text(group.Name) == "" {
		return fail(errors.New("approved disposable group differs"))
	}
	memberships, err := pages(func(page *string) ([]identity.UserGroupMembership, *string, error) {
		r, e := iam.ListUserGroupMemberships(ctx, identity.ListUserGroupMembershipsRequest{CompartmentId: new(s.Tenancy), UserId: new(s.Principal), Page: page})
		return r.Items, r.OpcNextPage, e
	})
	if err != nil {
		return fail(err)
	}
	if len(memberships) != 1 || text(memberships[0].UserId) != s.Principal || text(memberships[0].GroupId) != s.Group || memberships[0].LifecycleState != identity.UserGroupMembershipLifecycleStateActive {
		return fail(errors.New("candidate memberships are not exactly the approved disposable group"))
	}
	dynamic, err := pages(func(page *string) ([]identity.DynamicGroup, *string, error) {
		r, e := iam.ListDynamicGroups(ctx, identity.ListDynamicGroupsRequest{CompartmentId: new(s.Tenancy), Page: page})
		return r.Items, r.OpcNextPage, e
	})
	if err != nil {
		return fail(err)
	}
	// shortcut: reject every dynamic group, add a complete OCI matching-rule
	// evaluator before qualifying in tenancies that contain production groups.
	if len(dynamic) != 0 {
		return fail(errors.New("dynamic groups could admit an unsigned qualification instance"))
	}
	compartments, err := pages(func(page *string) ([]identity.Compartment, *string, error) {
		r, e := iam.ListCompartments(ctx, identity.ListCompartmentsRequest{CompartmentId: new(s.Tenancy), CompartmentIdInSubtree: new(true), AccessLevel: identity.ListCompartmentsAccessLevelAny, Page: page})
		return r.Items, r.OpcNextPage, e
	})
	if err != nil {
		return fail(err)
	}
	f.Compartments = []string{s.Tenancy}
	found := false
	for _, compartment := range compartments {
		id := text(compartment.Id)
		if id == "" || slices.Contains(f.Compartments, id) {
			return fail(errors.New("incomplete or duplicated compartment inventory"))
		}
		f.Compartments = append(f.Compartments, id)
		if id == s.Compartment && compartment.LifecycleState == identity.CompartmentLifecycleStateActive {
			found = true
		}
	}
	if !found {
		return fail(errors.New("approved disposable compartment is not active in complete tenancy inventory"))
	}
	slices.Sort(f.Compartments)
	approved := false
	for _, compartment := range f.Compartments {
		policies, err := pages(func(page *string) ([]identity.Policy, *string, error) {
			r, e := iam.ListPolicies(ctx, identity.ListPoliciesRequest{CompartmentId: new(compartment), Page: page})
			return r.Items, r.OpcNextPage, e
		})
		if err != nil {
			return fail(err)
		}
		for _, policy := range policies {
			if text(policy.Id) == "" || text(policy.CompartmentId) != compartment || policy.LifecycleState != identity.PolicyLifecycleStateActive {
				return fail(errors.New("unknown policy identity or lifecycle"))
			}
			f.Policies = append(f.Policies, policyFact{text(policy.Id), compartment, slices.Clone(policy.Statements)})
			if text(policy.Id) == s.PolicyID {
				if approved || !slices.Equal(policy.Statements, s.PolicyStatements) {
					return fail(errors.New("observed approved policy statements differ"))
				}
				approved = true
				continue
			}
			for _, statement := range policy.Statements {
				if !unrelatedGroup(statement, s.Group) {
					return fail(errors.New("unknown or additional potentially applicable IAM policy"))
				}
			}
		}
	}
	if !approved {
		return fail(errors.New("approved confinement policy absent"))
	}
	slices.SortFunc(f.Policies, func(a, b policyFact) int { return strings.Compare(a.ID, b.ID) })
	if err := observeNetwork(ctx, network, s, &f); err != nil {
		return fail(err)
	}
	boundary := hash(f)
	if err := observeHosts(ctx, network, compute, s, &f); err != nil {
		return fail(err)
	}
	return Verified{scope: clone(s), observer: observer, candidate: candidate, evidence: hash(f), boundary: boundary, endpoint: endpoint}, nil
}

var unrelatedPolicy = regexp.MustCompile(`^Allow group id (ocid1\.group\.[a-zA-Z0-9.]+) to (inspect|read|use|manage) [a-z-]+ in (tenancy|compartment id ocid1\.compartment\.[a-zA-Z0-9.]+)$`)

func unrelatedGroup(statement, id string) bool {
	// Names, domains, compound subjects, conditions and unknown grammar fail.
	match := unrelatedPolicy.FindStringSubmatch(statement)
	return match != nil && match[1] != id
}

func text(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func pages[T any](fetch func(*string) ([]T, *string, error)) ([]T, error) {
	var items []T
	var page *string
	seen := map[string]bool{}
	for range 10000 {
		batch, next, err := fetch(page)
		if err != nil {
			return nil, err
		}
		items = append(items, batch...)
		if next == nil || *next == "" {
			return items, nil
		}
		if seen[*next] {
			return nil, errors.New("OCI pagination repeated; complete inventory not proven")
		}
		seen[*next] = true
		page = next
	}
	return nil, errors.New("OCI pagination exceeded finite inventory bound")
}
