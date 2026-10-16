package principal

import (
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
)

var errPending = errors.New("disposable identity operation is still propagating")

type attempt struct {
	producer *Producer
	verified VerifiedPreparation
	store    *store
	journal  *journal
	client   identity.IdentityClient
}

func (p *Producer) attempt(ctx context.Context, v VerifiedPreparation, workdir string, cleanup bool) (*attempt, error) {
	if err := p.check(ctx, v, cleanup); err != nil {
		return nil, err
	}
	if p.issuer == nil || p.issuer.Region() != v.preparation.IAMRegion {
		return nil, errors.New("issuer IAM region differs from signed preparation")
	}
	provider := p.issuer.Provider()
	tenancy, err := provider.TenancyOCID()
	if err != nil {
		return nil, errors.New("issuer tenancy unavailable")
	}
	user, err := provider.UserOCID()
	if err != nil {
		return nil, errors.New("issuer principal unavailable")
	}
	fingerprint, err := provider.KeyFingerprint()
	if err != nil {
		return nil, errors.New("issuer fingerprint unavailable")
	}
	prep := v.preparation
	if tenancy != prep.Tenancy || user != prep.IssuerPrincipal || fingerprint != prep.IssuerFingerprint {
		return nil, errors.New("issuer authenticated credential differs from signed preparation")
	}
	auth, err := provider.AuthType()
	if err != nil || (auth.AuthType != common.UserPrincipal && auth.AuthType != common.UnknownAuthenticationType) || auth.OboToken != nil {
		return nil, errors.New("issuer requires direct IAM API-key authentication")
	}
	keyID, err := provider.KeyID()
	if err != nil || keyID != prep.Tenancy+"/"+prep.IssuerPrincipal+"/"+prep.IssuerFingerprint {
		return nil, errors.New("issuer signing identity differs from signed preparation")
	}
	key, err := provider.PrivateRSAKey()
	if err != nil || key == nil || key.N == nil || key.N.BitLen() < 2048 {
		return nil, errors.New("issuer RSA signing key unavailable")
	}
	if err := key.Validate(); err != nil {
		return nil, errors.New("invalid issuer RSA signing key")
	}
	// Serialize once and freeze the signing key with its checked identity. A
	// refreshable source provider must never select a different request caller.
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	defer clear(keyPEM)
	block, _ := pem.Decode(keyPEM)
	frozenKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid issuer RSA signing key")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&frozenKey.PublicKey)
	if err != nil || fingerprintDER(publicDER) != prep.IssuerFingerprint {
		return nil, errors.New("issuer private key differs from signed API fingerprint")
	}
	frozen := common.NewRawConfigurationProvider(prep.Tenancy, prep.IssuerPrincipal, prep.IAMRegion, prep.IssuerFingerprint, string(keyPEM), nil)
	s, err := openStore(workdir)
	if err != nil {
		return nil, err
	}
	j, err := s.load(v, cleanup)
	if err != nil {
		s.close()
		return nil, err
	}
	client, err := identity.NewIdentityClientWithConfigurationProvider(frozen)
	if err != nil {
		s.close()
		return nil, err
	}
	client.SetRegion(prep.IAMRegion)
	p.issuer.Configure(&client.BaseClient, ociclient.ServiceIdentity)
	ociclient.PinHost(&client.BaseClient, p.endpoint)
	a := &attempt{producer: p, verified: v, store: s, journal: j, client: client}
	previous := a.client.Interceptor
	a.client.Interceptor = func(request *http.Request) error {
		if previous != nil {
			if err := previous(request); err != nil {
				return err
			}
		}
		isCreate := request.Method == http.MethodPost
		if err := p.check(request.Context(), v, !isCreate); err != nil {
			return err
		}
		if isCreate {
			token := request.Header.Get("opc-retry-token")
			var intent *operation
			for _, op := range j.Operations {
				if op.RetryToken == token {
					intent = op
					break
				}
			}
			if intent == nil || j.Cleaned || intent.Deleted || intent.DeleteIntent || !p.now().Before(intent.FirstAttempt.Add(23*time.Hour)) || p.now().Before(intent.FirstAttempt) {
				return errors.New("IAM write lacks current durable exact retry intent")
			}
		}
		if request.Method == http.MethodDelete {
			found := false
			for _, op := range j.Operations {
				if op.DeleteIntent && !op.Deleted && op.DeleteRequestID == request.Header.Get("opc-request-id") {
					found = true
					break
				}
			}
			if !found {
				return errors.New("IAM delete lacks durable exact revocation intent")
			}
		}
		return nil
	}
	ociclient.ConfigureRequestCancellation(&a.client.BaseClient)
	if err := a.authenticate(ctx); err != nil {
		s.close()
		return nil, err
	}
	return a, nil
}

func (a *attempt) authenticate(ctx context.Context) error {
	p := a.verified.preparation
	tenancy, err := a.client.GetTenancy(ociclient.RequestContext(ctx), identity.GetTenancyRequest{TenancyId: new(p.Tenancy)})
	if err != nil {
		return err
	}
	home, err := ociclient.TenancyHomeRegion(tenancy.HomeRegionKey)
	if err != nil || value(tenancy.Id) != p.Tenancy || home != p.IAMRegion {
		return errors.New("issuer tenancy home differs from independently signed IAM region")
	}
	u, err := a.client.GetUser(ociclient.RequestContext(ctx), identity.GetUserRequest{UserId: new(p.IssuerPrincipal)})
	if err != nil {
		return err
	}
	if value(u.Id) != p.IssuerPrincipal || value(u.CompartmentId) != p.Tenancy || u.LifecycleState != identity.UserLifecycleStateActive {
		return errors.New("issuer user is not the signed active tenancy principal")
	}
	keys, err := a.client.ListApiKeys(ociclient.RequestContext(ctx), identity.ListApiKeysRequest{UserId: new(p.IssuerPrincipal)})
	if err != nil {
		return err
	}
	for _, key := range keys.Items {
		if value(key.UserId) == p.IssuerPrincipal && value(key.Fingerprint) == p.IssuerFingerprint && key.LifecycleState == identity.ApiKeyLifecycleStateActive {
			return nil
		}
	}
	return errors.New("issuer API fingerprint is not currently active")
}

func (a *attempt) description() string { return "Disposable image qualification " + a.verified.digest }

func (a *attempt) create(ctx context.Context, name string, details any, call func(string) (string, error)) (string, error) {
	if err := a.producer.check(ctx, a.verified, false); err != nil {
		return "", err
	}
	if a.journal.Cleaning || a.journal.Cleaned {
		return "", errors.New("revoked principal run cannot provision again")
	}
	if err := a.authenticate(ctx); err != nil {
		return "", err
	}
	op, err := a.store.intent(a.verified, a.journal, name, details, a.producer.now())
	if err != nil {
		return "", err
	}
	if op.ID == "" {
		id, err := call(op.RetryToken)
		if err != nil {
			return "", err
		}
		if !validID(name, id) || name == "user" && id == a.verified.preparation.IssuerPrincipal {
			return "", errors.New("IAM create returned an invalid disposable resource identity")
		}
		op.ID = id
		if err := a.store.save(a.journal); err != nil {
			return "", err
		}
	}
	if err := a.wait(ctx, name); err != nil {
		return "", err
	}
	return op.ID, nil
}

// Prepare journals and creates the user, group, exact policy, key and membership
// through authenticated OCI SDK APIs. Resource execution still needs confinement.
func (p *Producer) Prepare(ctx context.Context, v VerifiedPreparation, workdir string) (Result, error) {
	a, err := p.attempt(ctx, v, workdir, false)
	if err != nil {
		return Result{}, err
	}
	defer a.store.close()
	private, err := a.store.read("private.pem", 16<<10)
	if err != nil {
		return Result{}, err
	}
	defer clear(private)
	key, err := privateKey(private)
	if err != nil {
		return Result{}, err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return Result{}, err
	}
	public, fingerprint, err := publicIdentity(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	prep := v.preparation
	if err != nil || public != prep.PublicKeyPEM || fingerprint != prep.PublicKeyFingerprint {
		return Result{}, errors.New("escrow private key differs from signed public identity")
	}
	if err := a.prepare(ctx, false); err != nil {
		return a.result(), err
	}
	result := a.result()
	provider := common.NewRawConfigurationProvider(prep.Tenancy, result.receipt.Principal, prep.OCIRegion, fingerprint, string(private), nil)
	result.factory, err = ociclient.New(provider, ociclient.Options{Region: prep.OCIRegion})
	if err != nil {
		return Result{}, err
	}
	result.prepared = true
	return result, nil
}

// recoverOnly replays only already journaled creates during cleanup; it never
// fills in steps which were not attempted by the original preparation.
func (a *attempt) prepare(ctx context.Context, recoverOnly bool) error {
	p := a.verified.preparation
	should := func(name string) bool {
		return !recoverOnly || a.journal.Operations[name] != nil && a.journal.Operations[name].ID == ""
	}
	if should("user") {
		details := identity.CreateUserDetails{CompartmentId: new(p.Tenancy), Name: new(p.PrincipalName), Description: new(a.description())}
		_, err := a.create(ctx, "user", details, func(token string) (string, error) {
			r, err := a.client.CreateUser(ociclient.RequestContext(ctx), identity.CreateUserRequest{CreateUserDetails: details, OpcRetryToken: new(token), OpcRequestId: new(token)})
			return value(r.Id), err
		})
		if err != nil {
			return err
		}
	}
	if should("group") {
		details := identity.CreateGroupDetails{CompartmentId: new(p.Tenancy), Name: new(p.GroupName), Description: new(a.description())}
		_, err := a.create(ctx, "group", details, func(token string) (string, error) {
			r, err := a.client.CreateGroup(ociclient.RequestContext(ctx), identity.CreateGroupRequest{CreateGroupDetails: details, OpcRetryToken: new(token), OpcRequestId: new(token)})
			return value(r.Id), err
		})
		if err != nil {
			return err
		}
	}
	if should("policy") {
		group := a.id("group")
		if group == "" {
			return errors.New("policy lacks actual created group identity")
		}
		details := identity.CreatePolicyDetails{CompartmentId: new(p.Tenancy), Name: new(p.PolicyName), Description: new(a.description()), Statements: confinement.RequiredStatements(p.scope(group))}
		_, err := a.create(ctx, "policy", details, func(token string) (string, error) {
			r, err := a.client.CreatePolicy(ociclient.RequestContext(ctx), identity.CreatePolicyRequest{CreatePolicyDetails: details, OpcRetryToken: new(token), OpcRequestId: new(token)})
			return value(r.Id), err
		})
		if err != nil {
			return err
		}
	}
	if should("key") {
		user := a.id("user")
		if user == "" {
			return errors.New("API key lacks actual created user identity")
		}
		details := identity.CreateApiKeyDetails{Key: new(p.PublicKeyPEM)}
		request := struct {
			User    string                       `json:"user"`
			Details identity.CreateApiKeyDetails `json:"details"`
		}{user, details}
		_, err := a.create(ctx, "key", request, func(token string) (string, error) {
			r, err := a.client.UploadApiKey(ociclient.RequestContext(ctx), identity.UploadApiKeyRequest{UserId: new(user), CreateApiKeyDetails: details, OpcRetryToken: new(token), OpcRequestId: new(token)})
			if err == nil && (value(r.UserId) != user || value(r.KeyValue) != p.PublicKeyPEM) {
				return "", errors.New("uploaded key response differs from exact signed key and user")
			}
			return value(r.Fingerprint), err
		})
		if err != nil {
			return err
		}
	}
	if should("membership") {
		// Verify the exact active policy again immediately before granting access.
		if err := a.wait(ctx, "policy"); err != nil {
			return err
		}
		details := identity.AddUserToGroupDetails{UserId: new(a.id("user")), GroupId: new(a.id("group"))}
		if value(details.UserId) == "" || value(details.GroupId) == "" {
			return errors.New("membership lacks observed user and group")
		}
		_, err := a.create(ctx, "membership", details, func(token string) (string, error) {
			r, err := a.client.AddUserToGroup(ociclient.RequestContext(ctx), identity.AddUserToGroupRequest{AddUserToGroupDetails: details, OpcRetryToken: new(token), OpcRequestId: new(token)})
			if err == nil && (value(r.UserId) != value(details.UserId) || value(r.GroupId) != value(details.GroupId) || value(r.CompartmentId) != p.Tenancy) {
				return "", errors.New("membership response differs from exact prepared identities")
			}
			return value(r.Id), err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *attempt) id(name string) string {
	if op := a.journal.Operations[name]; op != nil {
		return op.ID
	}
	return ""
}

func (a *attempt) result() Result {
	p := a.verified.preparation
	r := Receipt{PreparationSHA256: a.verified.digest, Principal: a.id("user"), Group: a.id("group"), PolicyID: a.id("policy"), MembershipID: a.id("membership"), PublicKeyFingerprint: a.id("key"), Cleaned: a.journal.Cleaned}
	if r.Group != "" {
		r.PolicyStatements = confinement.RequiredStatements(p.scope(r.Group))
	}
	return Result{receipt: r}
}

func validID(name, id string) bool {
	if name == "key" {
		return validFingerprint(id)
	}
	kind := map[string]string{"user": "user", "group": "group", "policy": "policy", "membership": "groupmembership"}[name]
	return kind != "" && identifier.MatchString(id) && strings.HasPrefix(id, "ocid1."+kind+".")
}

func value(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (a *attempt) wait(ctx context.Context, name string) error {
	for {
		if err := a.producer.check(ctx, a.verified, false); err != nil {
			return err
		}
		exists, _, err := a.observe(ctx, name)
		if err == nil && !exists {
			err = errPending
		}
		if !errors.Is(err, errPending) {
			return err
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// observe returns exact-target existence and ETag. Names/markers are additional
// checks on the recorded create result, never a way to discover/adopt identity.
func (a *attempt) observe(ctx context.Context, name string) (bool, string, error) {
	p := a.verified.preparation
	id := a.id(name)
	if !validID(name, id) {
		return false, "", errors.New("missing exact created identity")
	}
	var etag string
	var err error
	var active bool
	switch name {
	case "user":
		var r identity.GetUserResponse
		r, err = a.client.GetUser(ociclient.RequestContext(ctx), identity.GetUserRequest{UserId: new(id)})
		etag = value(r.Etag)
		if err == nil {
			if value(r.Id) != id || id == p.IssuerPrincipal || value(r.CompartmentId) != p.Tenancy || value(r.Name) != p.PrincipalName || value(r.Description) != a.description() {
				return true, "", errors.New("created user observation differs from exact request")
			}
			active = r.LifecycleState == identity.UserLifecycleStateActive
		}
	case "group":
		var r identity.GetGroupResponse
		r, err = a.client.GetGroup(ociclient.RequestContext(ctx), identity.GetGroupRequest{GroupId: new(id)})
		etag = value(r.Etag)
		if err == nil {
			if value(r.Id) != id || value(r.CompartmentId) != p.Tenancy || value(r.Name) != p.GroupName || value(r.Description) != a.description() {
				return true, "", errors.New("created group observation differs from exact request")
			}
			active = r.LifecycleState == identity.GroupLifecycleStateActive
		}
	case "policy":
		var r identity.GetPolicyResponse
		r, err = a.client.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(id)})
		etag = value(r.Etag)
		if err == nil {
			if value(r.Id) != id || value(r.CompartmentId) != p.Tenancy || value(r.Name) != p.PolicyName || value(r.Description) != a.description() || !slices.Equal(r.Statements, confinement.RequiredStatements(p.scope(a.id("group")))) {
				return true, "", errors.New("created policy observation differs from exact canonical request")
			}
			active = r.LifecycleState == identity.PolicyLifecycleStateActive
		}
	case "key":
		var r identity.ListApiKeysResponse
		r, err = a.client.ListApiKeys(ociclient.RequestContext(ctx), identity.ListApiKeysRequest{UserId: new(a.id("user"))})
		if err == nil {
			found := false
			for _, key := range r.Items {
				if value(key.Fingerprint) != id {
					continue
				}
				if found || id != p.PublicKeyFingerprint || value(key.UserId) != a.id("user") || value(key.KeyValue) != p.PublicKeyPEM {
					return true, "", errors.New("created API key observation differs from exact signed identity")
				}
				found = true
				active = key.LifecycleState == identity.ApiKeyLifecycleStateActive
			}
			if !found {
				return false, "", nil
			}
		}
	case "membership":
		var r identity.GetUserGroupMembershipResponse
		r, err = a.client.GetUserGroupMembership(ociclient.RequestContext(ctx), identity.GetUserGroupMembershipRequest{UserGroupMembershipId: new(id)})
		etag = value(r.Etag)
		if err == nil {
			if value(r.Id) != id || value(r.UserId) != a.id("user") || value(r.GroupId) != a.id("group") || value(r.CompartmentId) != p.Tenancy {
				return true, "", errors.New("created membership observation differs from exact user and group")
			}
			active = r.LifecycleState == identity.UserGroupMembershipLifecycleStateActive
		}
	}
	if isNotFound(err) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	if !active {
		return true, etag, errPending
	}
	return true, etag, nil
}

func isNotFound(err error) bool {
	service, ok := common.IsServiceError(err)
	return ok && service.GetHTTPStatusCode() == http.StatusNotFound && service.GetCode() == "NotAuthorizedOrNotFound"
}

// Cleanup revokes only exact journaled resources, then positively observes their
// absence. Ambiguous expired creates remain explicit recovery errors.
func (p *Producer) Cleanup(ctx context.Context, v VerifiedPreparation, workdir string) (Result, error) {
	a, err := p.attempt(ctx, v, workdir, true)
	if err != nil {
		return Result{}, err
	}
	defer a.store.close()
	if a.journal.Cleaned {
		if err := a.removePrivate(); err != nil {
			return a.result(), err
		}
		return a.result(), nil
	}
	// Resolve only existing pending create intents while their original authority
	// remains current. Never replay an expired create merely to learn its OCID.
	var unresolved error
	if !a.journal.Cleaning {
		if err := a.prepare(ctx, true); err != nil {
			unresolved = fmt.Errorf("pending principal recovery: %w", err)
		}
		a.journal.Cleaning = true
		if err := a.store.save(a.journal); err != nil {
			return a.result(), err
		}
	}
	for _, name := range []string{"policy", "key", "membership", "user", "group"} {
		op := a.journal.Operations[name]
		if op == nil || op.Deleted {
			continue
		}
		if op.ID == "" {
			if name == "key" && a.id("user") != "" {
				// The fingerprint is fixed cryptographically before upload, unlike OCIDs.
				op.ID = v.preparation.PublicKeyFingerprint
				if err := a.store.save(a.journal); err != nil {
					return a.result(), err
				}
			} else {
				unresolved = errors.Join(unresolved, fmt.Errorf("pending %s create has no exact cleanup identity; retain recovery evidence", name))
				continue
			}
		}
		if err := a.revoke(ctx, name, op); err != nil {
			unresolved = errors.Join(unresolved, err)
		}
	}
	if unresolved != nil {
		return a.result(), unresolved
	}
	a.journal.Cleaned = true
	if err := a.store.save(a.journal); err != nil {
		return a.result(), err
	}
	if err := a.removePrivate(); err != nil {
		return a.result(), err
	}
	return a.result(), nil
}

func (a *attempt) removePrivate() error {
	err := a.store.root.Remove("private.pem")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return a.store.sync()
}

func (a *attempt) revoke(ctx context.Context, name string, op *operation) error {
	if err := a.producer.check(ctx, a.verified, true); err != nil {
		return err
	}
	exists, etag, err := a.observe(ctx, name)
	if err != nil && !errors.Is(err, errPending) {
		return err
	}
	if !op.DeleteIntent {
		request := struct{ Operation, ID, User, ETag string }{name, op.ID, "", etag}
		if name == "key" {
			request.User = a.id("user")
		}
		wire, err := json.Marshal(request, json.Deterministic(true))
		if err != nil {
			return err
		}
		op.DeleteRequest = wire
		op.DeleteSHA256 = hash(wire)
		op.DeleteRequestID = hash([]byte(a.verified.digest + "/delete/" + name + "/" + op.DeleteSHA256))[:32]
		op.DeleteFirstAttempt = a.producer.now()
		op.DeleteIntent = true
		if err := a.store.save(a.journal); err != nil {
			return err
		}
	}
	if exists {
		var request struct{ Operation, ID, User, ETag string }
		if err := json.Unmarshal(op.DeleteRequest, &request); err != nil {
			return err
		}
		if request.Operation != name || request.ID != op.ID || request.ETag != etag || name == "key" && request.User != a.id("user") {
			return errors.New("principal delete request changed after durable intent")
		}
		if err := a.authenticate(ctx); err != nil {
			return err
		}
		requestID := op.DeleteRequestID
		switch name {
		case "policy":
			_, err = a.client.DeletePolicy(ociclient.RequestContext(ctx), identity.DeletePolicyRequest{PolicyId: new(op.ID), IfMatch: nonempty(etag), OpcRequestId: new(requestID)})
		case "key":
			_, err = a.client.DeleteApiKey(ociclient.RequestContext(ctx), identity.DeleteApiKeyRequest{UserId: new(a.id("user")), Fingerprint: new(op.ID), OpcRequestId: new(requestID)})
		case "membership":
			_, err = a.client.RemoveUserFromGroup(ociclient.RequestContext(ctx), identity.RemoveUserFromGroupRequest{UserGroupMembershipId: new(op.ID), IfMatch: nonempty(etag), OpcRequestId: new(requestID)})
		case "user":
			_, err = a.client.DeleteUser(ociclient.RequestContext(ctx), identity.DeleteUserRequest{UserId: new(op.ID), IfMatch: nonempty(etag), OpcRequestId: new(requestID)})
		case "group":
			_, err = a.client.DeleteGroup(ociclient.RequestContext(ctx), identity.DeleteGroupRequest{GroupId: new(op.ID), IfMatch: nonempty(etag), OpcRequestId: new(requestID)})
		}
		if err != nil && !isNotFound(err) {
			return err
		}
		for {
			if err := a.producer.check(ctx, a.verified, true); err != nil {
				return err
			}
			exists, _, err = a.observe(ctx, name)
			if err != nil && !errors.Is(err, errPending) {
				return err
			}
			if !exists {
				break
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	op.Deleted = true
	return a.store.save(a.journal)
}

func nonempty(value string) *string {
	if value == "" {
		return nil
	}
	return new(value)
}
