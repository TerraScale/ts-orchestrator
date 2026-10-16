package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// SourcePolicyRecord permanently reserves an exact object for its original
// instance. Renewing the signed grant never transfers that reservation.
type SourcePolicyRecord struct {
	Namespace               string                       `json:"namespace"`
	Bucket                  string                       `json:"bucket"`
	Object                  string                       `json:"object"`
	InstallationID          string                       `json:"installationId"`
	InstanceID              string                       `json:"instanceId"`
	GrantDigest             string                       `json:"grantDigest"`
	TemplateDigest          string                       `json:"templateDigest"`
	GrantGeneration         uint64                       `json:"grantGeneration"`
	PolicyID                string                       `json:"policyId,omitempty"`
	Request                 identity.CreatePolicyDetails `json:"request"`
	RequestDigest           string                       `json:"requestDigest"`
	RetryToken              string                       `json:"retryToken"`
	BucketCompartment       string                       `json:"bucketCompartment"`
	Escrow                  bootstrap.StartupVaultTarget `json:"escrow"`
	SecretName              string                       `json:"secretName"`
	ProtectionEstablishedAt time.Time                    `json:"protectionEstablishedAt,omitzero"`
	FirstAttemptAt          time.Time                    `json:"firstAttemptAt"`
}

// SourceFounder can only be constructed from current sealed local OCI proof
// and the shared protected home IAM lease.
type SourceFounder struct {
	authority *HomeIAMAuthority
	resolver  FoundationResolver
	iam       identity.IdentityClient
	cell      string
}

func NewSourceFounder(ctx context.Context, resolver FoundationResolver, authority *HomeIAMAuthority) (*SourceFounder, error) {
	if authority == nil || resolver.Footprint == nil || resolver.Store == nil {
		return nil, bootstrapstart.ErrSourceFounder
	}
	if err := authority.Guard(ctx, 0); err != nil {
		return nil, err
	}
	entry, ok := catalog.CellForOCIRegion(authority.factory.Region())
	if !ok {
		return nil, bootstrapstart.ErrSourceFounder
	}
	home, err := authority.factory.HomeRegion(ctx, authority.proof.TenancyID())
	if err != nil {
		return nil, err
	}
	factory, err := authority.factory.ForRegion(home)
	if err != nil {
		return nil, err
	}
	iam, err := factory.Identity()
	if err != nil {
		return nil, err
	}
	actor := &SourceFounder{authority: authority, resolver: resolver, iam: iam, cell: entry.Cell}
	if err := actor.Guard(ctx); err != nil {
		return nil, err
	}
	return actor, nil
}

func (actor *SourceFounder) Founder() bootstrapstart.VerifiedSourceFounder {
	if actor == nil || actor.authority == nil {
		return bootstrapstart.VerifiedSourceFounder{}
	}
	return actor.authority.proof
}
func (actor *SourceFounder) SourceStorageDomain() bootstrap.StorageDomain {
	if actor == nil || actor.authority == nil {
		return bootstrap.StorageDomain{}
	}
	return actor.authority.domain
}
func (actor *SourceFounder) InstanceID() string     { return actor.Founder().InstanceID() }
func (actor *SourceFounder) GrantDigest() string    { return actor.Founder().GrantDigest() }
func (actor *SourceFounder) TemplateDigest() string { return actor.Founder().TemplateDigest() }
func (actor *SourceFounder) Guard(ctx context.Context) error {
	if actor == nil || actor.authority == nil {
		return bootstrapstart.ErrSourceFounder
	}
	if err := actor.authority.Guard(ctx, 0); err != nil {
		return err
	}
	grant, err := actor.resolver.BootstrapMaterial(ctx, actor.cell)
	if err != nil {
		return err
	}
	if digestSource(grant.FoundationGrantWire()) != actor.GrantDigest() || !grant.IsVerified() || grant.InstallationID() != actor.Founder().InstallationID() || grant.Generation() != actor.Founder().Generation() || grant.StorageDomain() != actor.authority.domain {
		return bootstrapstart.ErrSourceFounder
	}
	_, err = actor.resolver.Resolve(ctx, actor.cell)
	return err
}

func (actor *SourceFounder) AuthorizeSourceObject(ctx context.Context, key string) error {
	if err := actor.Guard(ctx); err != nil {
		return err
	}
	scope := digestSource([]byte(actor.Founder().InstallationID() + "\x00" + strings.ToLower(actor.cell)))
	if key != actor.authority.domain.Prefix+"/bootstrap/v2/material-source/"+scope+".json" {
		return bootstrapstart.ErrSourceFounder
	}
	return actor.authorize(ctx, key, "ts-bootstrap-source-"+scope[:32], nil)
}

func (actor *SourceFounder) AuthorizeLinkObject(ctx context.Context, recipient bootstrap.LinkRecipient, key string) error {
	if err := actor.Guard(ctx); err != nil {
		return err
	}
	verify := func(ctx context.Context) error {
		if actor.cell != "GRU" || recipient.VerifyCurrent(ctx, time.Now().UTC()) != nil || recipient.GrantDigest() != actor.GrantDigest() ||
			recipient.InstallationID() != actor.Founder().InstallationID() || recipient.Generation() != actor.Founder().Generation() || recipient.StorageDomain() != actor.authority.domain || key != recipient.LinkObjectKey() {
			return bootstrapstart.ErrSourceFounder
		}
		return nil
	}
	if err := verify(ctx); err != nil {
		return err
	}
	scope := strings.TrimSuffix(strings.TrimPrefix(key, actor.authority.domain.Prefix+"/bootstrap/v2/material-source/spoke-link-"), ".json")
	if !sourceDigest(scope) {
		return bootstrapstart.ErrSourceFounder
	}
	return actor.authorize(ctx, key, "ts-bootstrap-source-link-"+scope[:32], verify)
}

func digestSource(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }
func sourceDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}
func sourcePolicyKey(namespace, bucket, object string) string {
	wire, _ := json.Marshal([]string{namespace, bucket, object}, json.Deterministic(true))
	return digestSource(wire)
}

func (actor *SourceFounder) authorize(ctx context.Context, key, secret string, extra func(context.Context) error) error {
	ctx, release, err := actor.authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	guard := func(ctx context.Context) error {
		if err := actor.Guard(ctx); err != nil {
			return err
		}
		if extra != nil {
			return extra(ctx)
		}
		return nil
	}
	ctx = ociclient.WithAuthority(ctx, guard)
	if err := guard(ctx); err != nil {
		return err
	}
	record, etag, err := actor.resolver.Store.Load(ctx, actor.cell)
	if err != nil {
		return err
	}
	// Resolve again under the lease before reserving any source object.
	current, err := actor.resolver.Resolve(ctx, actor.cell)
	if err != nil || current.OperationID != record.OperationID || current.Generation != record.Generation || current.Stage != record.Stage {
		return errors.Join(ErrFoundationFenced, err)
	}
	grant, err := actor.resolver.BootstrapMaterial(ctx, actor.cell)
	if err != nil {
		return err
	}
	escrow := grant.EscrowTarget()
	target := vaultsecret.Target{CompartmentID: escrow.CompartmentOCID, VaultID: escrow.VaultOCID, KeyID: escrow.KMSKeyOCID}
	if target.CompartmentID != actor.authority.bucketCompartment {
		return errors.New("source escrow and registration bucket are outside the same signed home compartment")
	}
	if err := actor.verifyControllerExclusions(ctx); err != nil {
		return err
	}
	statements, err := ociregion.BootstrapSourceStatements(actor.InstanceID(), secret, target)
	if err != nil {
		return err
	}
	domain := actor.authority.domain
	condition := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s', target.bucket.name='%s', target.object.name='%s'", actor.InstanceID(), domain.HeadBucket, key)
	statements = append(statements, fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {%s, any {request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE', request.permission='OBJECT_READ'}}", actor.authority.bucketCompartment, condition))
	mapKey := sourcePolicyKey(domain.Namespace, domain.HeadBucket, key)
	details := identity.CreatePolicyDetails{CompartmentId: new(target.CompartmentID), Name: new("ts-bootstrap-source-" + mapKey[:32]), Description: new("Exact founder source escrow and registration"), Statements: statements}
	requestWire, err := json.Marshal(details, json.Deterministic(true))
	if err != nil {
		return err
	}
	pending, exists := record.SourcePolicyIDs[mapKey]
	observedID, err := actor.findPolicy(ctx, details)
	if err != nil {
		return err
	}
	if !exists && observedID != "" {
		return errors.New("same-name source policy has no authenticated pending create")
	}

	if exists {
		if pending.Namespace != domain.Namespace || pending.Bucket != domain.HeadBucket || pending.Object != key || pending.InstanceID != actor.InstanceID() || pending.InstallationID != actor.Founder().InstallationID() || pending.RequestDigest != digestSource(requestWire) {
			return bootstrapstart.ErrSourceFounder
		}
	} else {
		if err := actor.requireSourceAbsent(ctx, key); err != nil {
			return err
		}
		// Fixed reservations preserve recipient history; exhaustion needs an explicit new authorization.
		if len(record.SourcePolicyIDs) >= 64 {
			return errors.New("source policy journal is full")
		}
		pending = SourcePolicyRecord{BucketCompartment: actor.authority.bucketCompartment, Escrow: bootstrap.StartupVaultTarget{CompartmentOCID: target.CompartmentID, VaultOCID: target.VaultID, KMSKeyOCID: target.KeyID}, SecretName: secret, Namespace: domain.Namespace, Bucket: domain.HeadBucket, Object: key, InstallationID: actor.Founder().InstallationID(), InstanceID: actor.InstanceID(), GrantDigest: actor.GrantDigest(), TemplateDigest: actor.TemplateDigest(), GrantGeneration: actor.Founder().Generation(), Request: details, RequestDigest: digestSource(requestWire), FirstAttemptAt: time.Now().UTC()}
		pending.RetryToken = digestSource([]byte(mapKey + "\x00" + pending.InstanceID + "\x00" + pending.GrantDigest + "\x00" + pending.RequestDigest))
		record.SourcePolicyIDs = maps.Clone(record.SourcePolicyIDs)
		if record.SourcePolicyIDs == nil {
			record.SourcePolicyIDs = map[string]SourcePolicyRecord{}
		}
		record.SourcePolicyIDs[mapKey] = pending
		if err := guard(ctx); err != nil {
			return err
		}
		etag, err = actor.resolver.Store.CompareAndSwap(ctx, record, etag)
		if err != nil {
			return err
		}
	}
	if pending.PolicyID != "" {
		if observedID != "" && observedID != pending.PolicyID {
			return errors.New("source policy name resolves to another identity")
		}
		return actor.verifyPolicy(ctx, pending)
	}
	if err := actor.requireSourceAbsent(ctx, key); err != nil {
		return err
	}
	if time.Since(pending.FirstAttemptAt) >= 23*time.Hour || pending.FirstAttemptAt.After(time.Now().UTC()) {
		return errors.New("source policy pending create is outside its safe retry window")
	}
	if err := guard(ctx); err != nil {
		return err
	}
	noRetry := common.NoRetryPolicy()
	response, err := actor.iam.CreatePolicy(ociclient.RequestContext(ctx), identity.CreatePolicyRequest{CreatePolicyDetails: pending.Request, OpcRetryToken: new(pending.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
	if err != nil {
		return err
	}
	if response.Id == nil || !validAuxiliaryID("controller_usage_policy", *response.Id, "") {
		return errors.New("source IAM create omitted its exact policy identity")
	}
	if observedID != "" && *response.Id != observedID {
		return errors.New("source create replay differs from observed exact policy")
	}
	pending.PolicyID = *response.Id
	if err := actor.verifyPolicy(ctx, pending); err != nil {
		return err
	}
	if err := actor.requireSourceAbsent(ctx, key); err != nil {
		return err
	}
	pending.ProtectionEstablishedAt = time.Now().UTC()
	// The original conditional record prevents stale reconciliation owners from
	// replacing a reservation or accepting an unrelated same-name policy.
	record.SourcePolicyIDs[mapKey] = pending
	if err := guard(ctx); err != nil {
		return err
	}
	_, err = actor.resolver.Store.CompareAndSwap(ctx, record, etag)
	return err
}

func (actor *SourceFounder) verifyPolicy(ctx context.Context, pending SourcePolicyRecord) error {
	response, err := actor.iam.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(pending.PolicyID)})
	if err != nil {
		return err
	}
	if response.Id == nil || *response.Id != pending.PolicyID || response.Name == nil || pending.Request.Name == nil || *response.Name != *pending.Request.Name || response.CompartmentId == nil || pending.Request.CompartmentId == nil || *response.CompartmentId != *pending.Request.CompartmentId || response.LifecycleState != identity.PolicyLifecycleStateActive || !slices.Equal(response.Statements, pending.Request.Statements) {
		return errors.New("source IAM policy differs from its exact recorded request")
	}
	return nil
}

var sourceObjectPattern = regexp.MustCompile(`^(?:[a-zA-Z0-9][a-zA-Z0-9/_.-]*/)?bootstrap/v2/material-source/(?:spoke-link-)?[a-f0-9]{64}\.json$`)
var sourceInstancePattern = regexp.MustCompile(`^ocid1\.instance\.oc1\.[a-z0-9-]+\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
var sourceCompartmentPattern = regexp.MustCompile(`^ocid1\.compartment\.oc1\.\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
var sourceStoragePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$`)

func (pending SourcePolicyRecord) validate(key string) error {
	if !sourceDigest(key) || sourcePolicyKey(pending.Namespace, pending.Bucket, pending.Object) != key ||
		!sourceStoragePattern.MatchString(pending.Namespace) || !sourceStoragePattern.MatchString(pending.Bucket) || !sourceObjectPattern.MatchString(pending.Object) || strings.Contains(pending.Object, "//") || strings.Contains(pending.Object, "/../") || strings.Contains(pending.Object, "/./") || len(pending.Object) > 1024 ||
		!sourceInstancePattern.MatchString(pending.InstanceID) || len(pending.InstanceID) > 512 || pending.InstallationID == "" || len(pending.InstallationID) > 128 ||
		!sourceDigest(pending.GrantDigest) || !sourceDigest(pending.TemplateDigest) || !sourceDigest(pending.RequestDigest) || !sourceDigest(pending.RetryToken) || pending.GrantGeneration == 0 || pending.FirstAttemptAt.IsZero() ||
		pending.PolicyID != "" && (!validAuxiliaryID("controller_usage_policy", pending.PolicyID, "") || pending.ProtectionEstablishedAt.Before(pending.FirstAttemptAt)) || pending.PolicyID == "" && !pending.ProtectionEstablishedAt.IsZero() {
		return errors.New("source policy reservation has invalid scope")
	}
	statements, err := ociregion.BootstrapSourceStatements(pending.InstanceID, pending.SecretName, vaultsecret.Target{CompartmentID: pending.Escrow.CompartmentOCID, VaultID: pending.Escrow.VaultOCID, KeyID: pending.Escrow.KMSKeyOCID})
	if err != nil || !sourceCompartmentPattern.MatchString(pending.BucketCompartment) {
		return errors.New("source policy reservation has invalid provider target")
	}
	_, name, _ := strings.CutLast(pending.Object, "/")
	scope := strings.TrimSuffix(name, ".json")
	link := strings.HasPrefix(scope, "spoke-link-")
	scope = strings.TrimPrefix(scope, "spoke-link-")
	secret := "ts-bootstrap-source-"
	if link {
		secret += "link-"
	}
	secret += scope[:32]
	if pending.SecretName != secret {
		return errors.New("source policy secret differs from its exact object")
	}
	condition := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s', target.bucket.name='%s', target.object.name='%s'", pending.InstanceID, pending.Bucket, pending.Object)
	statements = append(statements, fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {%s, any {request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE', request.permission='OBJECT_READ'}}", pending.BucketCompartment, condition))
	expected := identity.CreatePolicyDetails{CompartmentId: new(pending.Escrow.CompartmentOCID), Name: new("ts-bootstrap-source-" + key[:32]), Description: new("Exact founder source escrow and registration"), Statements: statements}
	expectedWire, err := json.Marshal(expected, json.Deterministic(true))
	if err != nil {
		return err
	}
	actualWire, err := json.Marshal(pending.Request, json.Deterministic(true))
	if err != nil || string(expectedWire) != string(actualWire) || digestSource(actualWire) != pending.RequestDigest || pending.RetryToken != digestSource([]byte(key+"\x00"+pending.InstanceID+"\x00"+pending.GrantDigest+"\x00"+pending.RequestDigest)) {
		return errors.New("source policy reservation changed its canonical request")
	}
	return nil
}

func (actor *SourceFounder) findPolicy(ctx context.Context, details identity.CreatePolicyDetails) (string, error) {
	id := ""
	page := ""
	for {
		response, err := actor.iam.ListPolicies(ociclient.RequestContext(ctx), identity.ListPoliciesRequest{CompartmentId: details.CompartmentId, Name: details.Name, Page: optionalSourceString(page)})
		if err != nil {
			return "", err
		}
		for _, policy := range response.Items {
			if policy.Name == nil || *policy.Name != *details.Name {
				continue
			}
			if policy.Id == nil || !validAuxiliaryID("controller_usage_policy", *policy.Id, "") || id != "" {
				return "", errors.New("source policy discovery is ambiguous")
			}
			id = *policy.Id
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return id, nil
		}
		if *response.OpcNextPage == page {
			return "", errors.New("source policy discovery repeated its page")
		}
		page = *response.OpcNextPage
	}
}
func optionalSourceString(value string) *string {
	if value == "" {
		return nil
	}
	return new(value)
}

func (actor *SourceFounder) verifyControllerExclusions(ctx context.Context) error {
	footprint, err := actor.resolver.Footprint.AuthorizedRegions(ctx)
	if err != nil {
		return err
	}
	for _, intent := range footprint.Regions {
		cell, _ := intent.Plan["cell"].(string)
		record, _, err := actor.resolver.Store.Load(ctx, cell)
		if errors.Is(err, ErrFoundationMissing) {
			continue
		}
		if err != nil {
			return err
		}
		id := record.ResourceIDs["controller_policy"]
		if id == "" {
			continue
		}
		ids := ociregion.Object{}
		for k, v := range record.ResourceIDs {
			ids[k] = v
		}
		prefix, _ := intent.Plan["bootstrap_object_prefix"].(string)
		expected, err := ociregion.RequiredControllerStatements(intent.Plan, ids, prefix)
		if err != nil {
			return err
		}
		identityPlan, ok := intent.Plan["identity"].(map[string]any)
		if !ok {
			return ErrFoundationFenced
		}
		name, _ := identityPlan["controller_policy_name"].(string)
		response, err := actor.iam.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(id)})
		if err != nil {
			return err
		}
		if response.Id == nil || *response.Id != id || response.Name == nil || *response.Name != name || response.CompartmentId == nil || *response.CompartmentId != footprint.ParentCompartmentID || response.LifecycleState != identity.PolicyLifecycleStateActive || !slices.Equal(response.Statements, expected) {
			return errors.New("actual controller policy differs from source-excluding reviewed scope")
		}
	}
	return nil
}

func (actor *SourceFounder) requireSourceAbsent(ctx context.Context, key string) error {
	domain := actor.authority.domain
	response, err := actor.authority.objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(key)})
	if response.Content != nil {
		response.Content.Close()
	}
	if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("source object predates its exact-principal protection journal; refusing adoption")
}
