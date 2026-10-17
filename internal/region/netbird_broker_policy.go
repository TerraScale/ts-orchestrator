package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// NetBirdBrokerPolicyRecord retains public IAM history, including dispatches
// whose outcomes are unknown. It contains no credential or signing material.
type NetBirdBrokerPolicyRecord struct {
	Cell               string                       `json:"cell"`
	InstallationID     string                       `json:"installationId"`
	GrantSHA256        string                       `json:"grantSha256"`
	SourceSHA256       string                       `json:"sourceSha256"`
	ActorInstanceID    string                       `json:"actorInstanceId"`
	OperationID        string                       `json:"operationId"`
	Epoch              uint64                       `json:"epoch"`
	IntentDigest       string                       `json:"intentDigest"`
	InstanceID         string                       `json:"instanceId"`
	PrivateIP          string                       `json:"privateIp"`
	StoreGeneration    string                       `json:"storeGeneration"`
	ManagerVaultTarget vaultsecret.Target           `json:"managerVaultTarget"`
	VaultTarget        vaultsecret.Target           `json:"vaultTarget"`
	SecretName         string                       `json:"secretName"`
	SecretID           string                       `json:"secretId"`
	Request            identity.CreatePolicyDetails `json:"request"`
	RequestDigest      string                       `json:"requestDigest"`
	RetryToken         string                       `json:"retryToken"`
	FirstAttemptAt     time.Time                    `json:"firstAttemptAt"`
	ExpiresAt          time.Time                    `json:"expiresAt"`
	Dispatches         uint8                        `json:"dispatches"`
	LastDispatchedAt   time.Time                    `json:"lastDispatchedAt,omitzero"`
	Uncertain          bool                         `json:"uncertain"`
	PolicyID           string                       `json:"policyId,omitempty"`
}

func netBirdBrokerPolicyKey(instance, secret string) string {
	return digestSource([]byte("netbird-broker\x00" + instance + "\x00" + secret))
}

func netBirdBrokerPolicyRequest(record NetBirdBrokerPolicyRecord) identity.CreatePolicyDetails {
	key := netBirdBrokerPolicyKey(record.InstanceID, record.SecretID)
	return identity.CreatePolicyDetails{CompartmentId: new(record.VaultTarget.CompartmentID), Name: new("ts-netbird-broker-read-" + key[:32]),
		Description: new("Exact dedicated NetBird manager reads one regional broker secret"),
		Statements:  []string{fmt.Sprintf("Allow any-user to read secret-bundles in compartment id %s where all {request.principal.type='instance', request.principal.id='%s', target.secret.id='%s', request.permission='SECRET_BUNDLE_READ'}", record.VaultTarget.CompartmentID, record.InstanceID, record.SecretID)}}
}

func (record NetBirdBrokerPolicyRecord) validate(key, cell string) error {
	entry, ok := catalog.Lookup(cell)
	address, addressErr := netip.ParseAddr(record.PrivateIP)
	if !ok || !slices.Contains([]string{"GRU", "SFO", "FRA"}, cell) || record.Cell != cell || key != netBirdBrokerPolicyKey(record.InstanceID, record.SecretID) || !entityid.Valid(record.InstallationID) ||
		!entityid.Valid(record.OperationID) || record.Epoch == 0 || !sourceDigest(record.IntentDigest) || !sourceDigest(record.GrantSHA256) || !sourceDigest(record.SourceSHA256) ||
		len(record.ActorInstanceID) > 512 || len(record.InstanceID) > 512 || len(record.SecretID) > 512 || len(record.PolicyID) > 512 ||
		!sourceInstancePattern.MatchString(record.ActorInstanceID) || !strings.HasPrefix(record.ActorInstanceID, "ocid1.instance.oc1."+entry.OCIRegion+".") ||
		!sourceInstancePattern.MatchString(record.InstanceID) || !strings.HasPrefix(record.InstanceID, "ocid1.instance.oc1."+foundationHomeRegion+".") ||
		record.SecretName != strings.ToLower(cell)+"-1-netbird-broker" || !workerSecretPattern.MatchString(record.SecretID) || !strings.HasPrefix(record.SecretID, "ocid1.vaultsecret.oc1."+entry.OCIRegion+".") ||
		validateNetBirdBrokerVault(record.VaultTarget, entry.OCIRegion) != nil || validateNetBirdBrokerVault(record.ManagerVaultTarget, foundationHomeRegion) != nil ||
		addressErr != nil || !address.Is4() || !address.IsPrivate() || address.String() != record.PrivateIP || record.StoreGeneration != entityid.Derive("netbird-foundation-store", record.InstallationID)+":1" ||
		record.FirstAttemptAt.IsZero() || !record.FirstAttemptAt.Before(record.ExpiresAt) || record.Dispatches > 16 ||
		record.Dispatches == 0 && (!record.LastDispatchedAt.IsZero() || record.Uncertain || record.PolicyID != "") ||
		record.Dispatches != 0 && (record.LastDispatchedAt.Before(record.FirstAttemptAt) || !record.LastDispatchedAt.Before(record.ExpiresAt)) ||
		record.PolicyID != "" && (!validAuxiliaryID("controller_usage_policy", record.PolicyID, "") || record.Uncertain) ||
		record.Dispatches != 0 && record.PolicyID == "" && !record.Uncertain {
		return errors.New("NetBird broker IAM history has invalid original scope or dispatch state")
	}
	expected, err := json.Marshal(netBirdBrokerPolicyRequest(record), json.Deterministic(true))
	if err != nil {
		return err
	}
	actual, err := json.Marshal(record.Request, json.Deterministic(true))
	if err != nil || string(expected) != string(actual) || record.RequestDigest != digestSource(actual) ||
		record.RetryToken != digestSource([]byte(record.OperationID+"\x00"+key+"\x00"+record.RequestDigest)) {
		return errors.New("NetBird broker IAM history changed its immutable request or retry token")
	}
	return nil
}

func validateNetBirdBrokerVault(target vaultsecret.Target, region string) error {
	if len(target.CompartmentID) > 512 || len(target.VaultID) > 512 || len(target.KeyID) > 512 {
		return errors.New("NetBird broker Vault target exceeds its fixed identity bound")
	}
	return (bootstrapmaterial.VaultTarget{CompartmentOCID: target.CompartmentID, VaultOCID: target.VaultID, KMSKeyOCID: target.KeyID}).Validate(region)
}

// EnsureNetBirdBrokerReader derives the fixed secret from the actual regional
// source. The installed original writer supplies the existing HOME IAM lease.
func (authority *HomeIAMAuthority) EnsureNetBirdBrokerReader(ctx context.Context, source bootstrap.VerifiedRegionalSource, recipient VerifiedNetBirdManagerRecipient) error {
	if authority == nil || authority.factory == nil || !source.IsVerified() || !recipient.IsVerified() {
		return errors.New("NetBird broker read policy requires current sealed source and recipient")
	}
	entry, ok := catalog.CellForOCIRegion(authority.factory.Region())
	if !ok || !slices.Contains([]string{"GRU", "SFO", "FRA"}, entry.Cell) || source.Manifest().OCIRegion != entry.OCIRegion || string(source.Manifest().Cell) != entry.Cell ||
		source.Template().InstallationID() != authority.installationID || source.Template().GrantDigest() != authority.grantDigest ||
		recipient.InstallationID() != authority.installationID || recipient.GrantDigest() != authority.grantDigest {
		return errors.New("NetBird broker read policy differs from the original regional source")
	}
	expires := source.ExpiresAt()
	if recipient.ExpiresAt().Before(expires) {
		expires = recipient.ExpiresAt()
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	ctx, cancelAuthority := context.WithDeadline(ctx, expires)
	defer cancelAuthority()
	var original *FoundationRecord
	var secretID string
	guard := func(ctx context.Context) error {
		if err := authority.VerifyFoundationWriter(ctx); err != nil {
			return err
		}
		if err := authority.Guard(ctx, 0); err != nil {
			return err
		}
		if err := source.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
			return err
		}
		if err := recipient.Check(ctx); err != nil {
			return err
		}
		if original != nil {
			latest, _, err := authority.resolver.Store.Load(ctx, entry.Cell)
			if err != nil {
				return err
			}
			if latest.Stage != "reconciled" || latest.OperationID != original.OperationID || latest.Epoch != original.Epoch || latest.IntentDigest != original.IntentDigest ||
				latest.ResourceIDs["control_compartment"] != original.ResourceIDs["control_compartment"] || latest.ResourceIDs["vault"] != original.ResourceIDs["vault"] || latest.ResourceIDs["key"] != original.ResourceIDs["key"] {
				return ErrFoundationFenced
			}
			if secretID != "" {
				target, err := latest.VaultTarget()
				if err != nil {
					return err
				}
				current, err := netBirdBrokerSecret(ctx, authority.factory, target, strings.ToLower(entry.Cell)+"-1-netbird-broker")
				if err != nil || current != secretID {
					return errors.Join(errors.New("NetBird broker original secret metadata changed"), err)
				}
			}
		}
		if err := ociclient.LimitAdmission(ctx, source.ExpiresAt()); err != nil {
			return err
		}
		return ociclient.LimitAdmission(ctx, recipient.ExpiresAt())
	}
	if err := guard(ctx); err != nil {
		return err
	}
	ctx, release, err := authority.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	lease, ok := ctx.Value(homeIAMLeaseKey{}).(*homeIAMLease)
	if !ok || lease.authority != authority {
		return ErrFoundationFenced
	}
	lease.mu.Lock()
	leaseExpiry := lease.record.ExpiresAt
	lease.mu.Unlock()
	if leaseExpiry.Before(expires) {
		expires = leaseExpiry
	}
	ctx, cancelLease := context.WithDeadline(ctx, expires)
	defer cancelLease()
	ctx = ociclient.WithAuthority(ctx, guard)
	record, err := authority.resolver.Resolve(ctx, entry.Cell)
	if err != nil {
		return err
	}
	original = &record
	target, err := record.VaultTarget()
	if err != nil {
		return err
	}
	bound := source.Template().VaultTarget()
	if target != (vaultsecret.Target{CompartmentID: bound.CompartmentOCID, VaultID: bound.VaultOCID, KeyID: bound.KMSKeyOCID}) {
		return errors.New("NetBird broker regional Vault differs from the signed source")
	}
	if target.CompartmentID != authority.bucketCompartment {
		return errors.New("NetBird broker policy container is outside the original writer policy authority")
	}
	name := strings.ToLower(entry.Cell) + "-1-netbird-broker"
	secret, err := netBirdBrokerSecret(ctx, authority.factory, target, name)
	if err != nil {
		return err
	}
	secretID = secret
	key := netBirdBrokerPolicyKey(recipient.InstanceID(), secret)
	homeRegion, err := authority.factory.HomeRegion(ctx, authority.tenancyID)
	if err != nil {
		return err
	}
	home, err := authority.factory.ForRegion(homeRegion)
	if err != nil {
		return err
	}
	iam, err := home.Identity()
	if err != nil {
		return err
	}
	observedID, err := findNetBirdBrokerPolicy(ctx, &iam, netBirdBrokerPolicyRequest(NetBirdBrokerPolicyRecord{InstanceID: recipient.InstanceID(), SecretID: secret, VaultTarget: target}))
	if err != nil {
		return err
	}
	pending, exists := record.NetBirdBrokerPolicies[key]
	if !exists {
		if observedID != "" {
			return errors.New("NetBird broker policy has no original authenticated reservation")
		}
		for _, historical := range record.NetBirdBrokerPolicies {
			if historical.SecretName == name && historical.VaultTarget == target {
				return errors.New("NetBird broker secret or recipient changed; preserve the original IAM history")
			}
		}
		pending = NetBirdBrokerPolicyRecord{Cell: entry.Cell, InstallationID: authority.installationID, GrantSHA256: authority.grantDigest,
			SourceSHA256: digestSource(source.Inventory()), ActorInstanceID: authority.instanceID, OperationID: record.OperationID, Epoch: record.Epoch,
			IntentDigest: record.IntentDigest, InstanceID: recipient.InstanceID(), PrivateIP: recipient.PrivateIP(), StoreGeneration: recipient.StoreGeneration(),
			ManagerVaultTarget: recipient.VaultTarget(), VaultTarget: target, SecretName: name, SecretID: secret, FirstAttemptAt: time.Now().UTC(), ExpiresAt: expires}
		pending.Request = netBirdBrokerPolicyRequest(pending)
		wire, err := json.Marshal(pending.Request, json.Deterministic(true))
		if err != nil {
			return err
		}
		pending.RequestDigest = digestSource(wire)
		pending.RetryToken = digestSource([]byte(pending.OperationID + "\x00" + key + "\x00" + pending.RequestDigest))
		if err := authority.commitNetBirdBrokerPolicy(ctx, key, nil, pending, guard); err != nil {
			return err
		}
	}
	if pending.validate(key, entry.Cell) != nil || pending.InstallationID != authority.installationID || pending.GrantSHA256 != authority.grantDigest ||
		pending.SourceSHA256 != digestSource(source.Inventory()) || pending.ActorInstanceID != authority.instanceID || pending.OperationID != record.OperationID ||
		pending.Epoch != record.Epoch || pending.IntentDigest != record.IntentDigest || pending.InstanceID != recipient.InstanceID() || pending.PrivateIP != recipient.PrivateIP() ||
		pending.StoreGeneration != recipient.StoreGeneration() || pending.ManagerVaultTarget != recipient.VaultTarget() || pending.VaultTarget != target || pending.SecretID != secret ||
		!time.Now().Before(pending.ExpiresAt) || pending.ExpiresAt.After(source.ExpiresAt()) || pending.ExpiresAt.After(recipient.ExpiresAt()) {
		return errors.New("NetBird broker IAM original reservation is no longer authorized")
	}
	ctx, cancel := context.WithDeadline(ctx, pending.ExpiresAt)
	defer cancel()
	if pending.PolicyID != "" {
		if observedID != "" && observedID != pending.PolicyID {
			return errors.New("NetBird broker policy name resolves to another identity")
		}
		if err := verifyNetBirdBrokerPolicy(ctx, &iam, pending); err != nil {
			return err
		}
		return guard(ctx)
	}
	if pending.Dispatches >= 16 || time.Since(pending.FirstAttemptAt) >= 23*time.Hour || pending.FirstAttemptAt.After(time.Now()) {
		return errors.New("NetBird broker IAM original dispatch window is exhausted")
	}
	// Checkpoint uncertainty before dispatch; a retry keeps the same body/token.
	next := pending
	next.Dispatches++
	next.LastDispatchedAt, next.Uncertain = time.Now().UTC(), true
	if err := authority.commitNetBirdBrokerPolicy(ctx, key, &pending, next, guard); err != nil {
		return err
	}
	pending = next
	if err := guard(ctx); err != nil {
		return err
	}
	noRetry := common.NoRetryPolicy()
	response, err := iam.CreatePolicy(ociclient.RequestContext(ctx), identity.CreatePolicyRequest{CreatePolicyDetails: pending.Request, OpcRetryToken: new(pending.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
	if err != nil {
		return err
	}
	if response.Id == nil || !validAuxiliaryID("controller_usage_policy", *response.Id, "") {
		return errors.New("NetBird broker IAM response omitted the original policy identity")
	}
	if observedID != "" && *response.Id != observedID {
		return errors.New("NetBird broker original retry resolved to another policy")
	}
	next = pending
	next.PolicyID, next.Uncertain = *response.Id, false
	if err := verifyNetBirdBrokerPolicy(ctx, &iam, next); err != nil {
		return err
	}
	return authority.commitNetBirdBrokerPolicy(ctx, key, &pending, next, guard)
}

func (authority *HomeIAMAuthority) commitNetBirdBrokerPolicy(ctx context.Context, key string, previous *NetBirdBrokerPolicyRecord, next NetBirdBrokerPolicyRecord, guard func(context.Context) error) error {
	if err := guard(ctx); err != nil {
		return err
	}
	latest, etag, err := authority.resolver.Store.Load(ctx, next.Cell)
	if err != nil {
		return err
	}
	if latest.Cell != next.Cell || latest.Stage != "reconciled" || latest.OperationID != next.OperationID || latest.Epoch != next.Epoch || latest.IntentDigest != next.IntentDigest ||
		next.validate(key, next.Cell) != nil || !time.Now().Before(next.ExpiresAt) {
		return ErrFoundationFenced
	}
	current, exists := latest.NetBirdBrokerPolicies[key]
	if previous == nil {
		if exists || len(latest.NetBirdBrokerPolicies) >= 3 {
			return errors.New("NetBird broker IAM reservation already exists or its journal is full")
		}
		for _, historical := range latest.NetBirdBrokerPolicies {
			if historical.SecretName == next.SecretName && historical.VaultTarget == next.VaultTarget {
				return errors.New("NetBird broker IAM recipient cannot replace retained history")
			}
		}
	} else {
		actual, err := json.Marshal(current, json.Deterministic(true))
		expected, expectedErr := json.Marshal(previous, json.Deterministic(true))
		if !exists || err != nil || expectedErr != nil || string(actual) != string(expected) {
			return ErrFoundationFenced
		}
	}
	latest.NetBirdBrokerPolicies = maps.Clone(latest.NetBirdBrokerPolicies)
	if latest.NetBirdBrokerPolicies == nil {
		latest.NetBirdBrokerPolicies = map[string]NetBirdBrokerPolicyRecord{}
	}
	latest.NetBirdBrokerPolicies[key], latest.UpdatedAt = next, time.Now().UTC()
	if err := guard(ctx); err != nil {
		return err
	}
	_, err = authority.resolver.Store.CompareAndSwap(ctx, latest, etag)
	return err
}

func verifyNetBirdBrokerPolicy(ctx context.Context, client *identity.IdentityClient, pending NetBirdBrokerPolicyRecord) error {
	response, err := client.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(pending.PolicyID)})
	if err != nil {
		return err
	}
	if response.Id == nil || *response.Id != pending.PolicyID || response.Name == nil || *response.Name != *pending.Request.Name ||
		response.CompartmentId == nil || *response.CompartmentId != pending.VaultTarget.CompartmentID || response.LifecycleState != identity.PolicyLifecycleStateActive ||
		!slices.Equal(response.Statements, pending.Request.Statements) {
		return errors.New("NetBird broker IAM policy differs from its original exact secret-read request")
	}
	return nil
}

func findNetBirdBrokerPolicy(ctx context.Context, client *identity.IdentityClient, request identity.CreatePolicyDetails) (string, error) {
	id, page := "", ""
	for range 32 {
		response, err := client.ListPolicies(ociclient.RequestContext(ctx), identity.ListPoliciesRequest{CompartmentId: request.CompartmentId, Name: request.Name, Page: optionalSourceString(page)})
		if err != nil {
			return "", err
		}
		for _, policy := range response.Items {
			if policy.Name == nil || *policy.Name != *request.Name {
				continue
			}
			if policy.Id == nil || !validAuxiliaryID("controller_usage_policy", *policy.Id, "") || id != "" {
				return "", errors.New("NetBird broker policy discovery is ambiguous")
			}
			id = *policy.Id
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return id, nil
		}
		if *response.OpcNextPage == page {
			return "", errors.New("NetBird broker policy discovery repeated its page")
		}
		page = *response.OpcNextPage
	}
	return "", errors.New("NetBird broker policy discovery exceeded its fixed page bound")
}

func netBirdBrokerSecret(ctx context.Context, factory *ociclient.Factory, target vaultsecret.Target, name string) (string, error) {
	client, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return "", err
	}
	client.SetRegion(factory.Region())
	factory.Configure(&client.BaseClient, ociclient.ServiceVault)
	response, err := client.ListSecrets(ociclient.RequestContext(ctx), ocivault.ListSecretsRequest{CompartmentId: new(target.CompartmentID), VaultId: new(target.VaultID), Name: new(name)})
	if err != nil {
		return "", err
	}
	if len(response.Items) != 1 || response.OpcNextPage != nil && *response.OpcNextPage != "" {
		return "", errors.New("fixed NetBird broker secret is absent or ambiguous")
	}
	item := response.Items[0]
	if item.Id == nil || !workerSecretPattern.MatchString(*item.Id) || item.SecretName == nil || *item.SecretName != name ||
		item.CompartmentId == nil || *item.CompartmentId != target.CompartmentID || item.VaultId == nil || *item.VaultId != target.VaultID || item.LifecycleState != ocivault.SecretSummaryLifecycleStateActive {
		return "", errors.New("NetBird broker secret differs from its exact regional Vault target")
	}
	secret, err := client.GetSecret(ociclient.RequestContext(ctx), ocivault.GetSecretRequest{SecretId: item.Id})
	if err != nil {
		return "", err
	}
	if secret.Id == nil || *secret.Id != *item.Id || secret.SecretName == nil || *secret.SecretName != name || secret.CompartmentId == nil ||
		*secret.CompartmentId != target.CompartmentID || secret.VaultId == nil || *secret.VaultId != target.VaultID || secret.KeyId == nil || *secret.KeyId != target.KeyID || secret.LifecycleState != ocivault.SecretLifecycleStateActive {
		return "", errors.New("NetBird broker secret metadata changed before IAM admission")
	}
	return *secret.Id, nil
}

// Every whole-record writer retains original broker IAM history. A sibling
// update cannot turn an unknown or completed effect into a fresh reservation.
func (record FoundationRecord) retainNetBirdBrokerPolicies(next FoundationRecord) error {
	denied := errors.New("NetBird broker original IAM request, deadline or outcome cannot be removed or rewritten")
	for key, original := range record.NetBirdBrokerPolicies {
		current, ok := next.NetBirdBrokerPolicies[key]
		if !ok {
			return denied
		}
		before, after := original, current
		before.Dispatches, after.Dispatches = 0, 0
		before.LastDispatchedAt, after.LastDispatchedAt = time.Time{}, time.Time{}
		before.Uncertain, after.Uncertain = false, false
		before.PolicyID, after.PolicyID = "", ""
		a, err := json.Marshal(before, json.Deterministic(true))
		b, nextErr := json.Marshal(after, json.Deterministic(true))
		if err != nil || nextErr != nil || string(a) != string(b) || current.Dispatches < original.Dispatches || current.Dispatches > original.Dispatches+1 {
			return denied
		}
		if original.PolicyID != "" {
			if current.PolicyID != original.PolicyID || current.Dispatches != original.Dispatches || !current.LastDispatchedAt.Equal(original.LastDispatchedAt) || current.Uncertain {
				return denied
			}
		} else if current.Dispatches == original.Dispatches {
			if !current.LastDispatchedAt.Equal(original.LastDispatchedAt) || current.Uncertain != original.Uncertain && (!original.Uncertain || current.Uncertain || current.PolicyID == "") || current.PolicyID != "" && (!original.Uncertain || current.Uncertain) {
				return denied
			}
		} else if !current.Uncertain || current.PolicyID != "" || current.LastDispatchedAt.Before(original.LastDispatchedAt) {
			return denied
		}
	}
	return nil
}
