package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

const netBirdWriterPurpose = "netbird-broker-reader-policy-create-v1"

// NetBirdBrokerPolicyWriterIntent is a root-signed exact capability for an
// existing original writer. It never changes that writer's original policy.
type NetBirdBrokerPolicyWriterIntent struct {
	Purpose                     string `json:"purpose"`
	OriginalWriterGrantSHA256   string `json:"originalWriterGrantSha256"`
	OriginalWriterOperationID   string `json:"originalWriterOperationId"`
	OriginalWriterRequestSHA256 string `json:"originalWriterRequestSha256"`
	OriginalWriterInstanceID    string `json:"originalWriterInstanceId"`
	PolicyCompartmentID         string `json:"policyCompartmentId"`
}

func (intent NetBirdBrokerPolicyWriterIntent) validate(cell string) error {
	entry, ok := catalog.Lookup(cell)
	if !ok || (cell != "GRU" && cell != "SFO" && cell != "FRA") || intent.Purpose != netBirdWriterPurpose ||
		!sourceDigest(intent.OriginalWriterGrantSHA256) || !entityid.Valid(intent.OriginalWriterOperationID) || !sourceDigest(intent.OriginalWriterRequestSHA256) ||
		len(intent.OriginalWriterInstanceID) > 512 || !sourceInstancePattern.MatchString(intent.OriginalWriterInstanceID) ||
		!strings.HasPrefix(intent.OriginalWriterInstanceID, "ocid1.instance.oc1."+entry.OCIRegion+".") || len(intent.PolicyCompartmentID) > 512 || !sourceCompartmentPattern.MatchString(intent.PolicyCompartmentID) {
		return errors.New("NetBird broker writer capability lacks exact original writer, purpose or compartment")
	}
	return nil
}

func (intent NetBirdBrokerPolicyWriterIntent) matches(writer *FoundationWriterRecord) bool {
	return writer != nil && intent.validate(writer.Cell) == nil && writer.GrantSHA256 == intent.OriginalWriterGrantSHA256 && writer.OperationID == intent.OriginalWriterOperationID &&
		writer.RequestDigest == intent.OriginalWriterRequestSHA256 && writer.InstanceID == intent.OriginalWriterInstanceID
}

// BrokerPolicyAuthorityRecord is one retained extension operation. Its dispatch
// deadline does not renew, and its positive receipt never replaces Policy.
type BrokerPolicyAuthorityRecord struct {
	Intent              NetBirdBrokerPolicyWriterIntent `json:"intent"`
	AuthorizationSHA256 string                          `json:"authorizationSha256"`
	OperationID         string                          `json:"operationId"`
	Epoch               uint64                          `json:"epoch"`
	IntentDigest        string                          `json:"intentDigest"`
	Request             identity.CreatePolicyDetails    `json:"request"`
	RequestDigest       string                          `json:"requestDigest"`
	RetryToken          string                          `json:"retryToken"`
	FirstAttemptAt      time.Time                       `json:"firstAttemptAt"`
	ExpiresAt           time.Time                       `json:"expiresAt"`
	Dispatches          uint8                           `json:"dispatches"`
	LastDispatchedAt    time.Time                       `json:"lastDispatchedAt,omitzero"`
	Uncertain           bool                            `json:"uncertain"`
	PolicyID            string                          `json:"policyId,omitempty"`
}

func netBirdWriterPolicy(intent NetBirdBrokerPolicyWriterIntent) identity.CreatePolicyDetails {
	key := digestSource([]byte(intent.OriginalWriterInstanceID + "\x00" + intent.PolicyCompartmentID))
	return identity.CreatePolicyDetails{CompartmentId: new(intent.PolicyCompartmentID), Name: new("ts-netbird-broker-issuer-" + key[:32]), Description: new("Original own-cell writer installs exact NetBird broker reader policies"),
		Statements: []string{fmt.Sprintf("Allow any-user to manage policies in compartment id %s where all {request.principal.type='instance', request.principal.id='%s', any {request.permission='POLICY_INSPECT', request.permission='POLICY_READ', request.permission='POLICY_CREATE'}}", intent.PolicyCompartmentID, intent.OriginalWriterInstanceID)}}
}

func (record BrokerPolicyAuthorityRecord) validate(writer *FoundationWriterRecord) error {
	if !record.Intent.matches(writer) || !sourceDigest(record.AuthorizationSHA256) || !entityid.Valid(record.OperationID) || record.Epoch == 0 || !sourceDigest(record.IntentDigest) ||
		record.FirstAttemptAt.IsZero() || !record.FirstAttemptAt.Before(record.ExpiresAt) || record.Dispatches > 16 || len(record.PolicyID) > 512 ||
		record.Dispatches == 0 && (!record.LastDispatchedAt.IsZero() || record.Uncertain || record.PolicyID != "") ||
		record.Dispatches != 0 && (record.LastDispatchedAt.Before(record.FirstAttemptAt) || !record.LastDispatchedAt.Before(record.ExpiresAt)) ||
		record.PolicyID != "" && (!validAuxiliaryID("controller_usage_policy", record.PolicyID, "") || record.Uncertain) || record.Dispatches != 0 && record.PolicyID == "" && !record.Uncertain {
		return errors.New("NetBird broker writer checkpoint changed its original authority or dispatch state")
	}
	expected, err := foundationWriterPolicyBody(netBirdWriterPolicy(record.Intent))
	actual, actualErr := foundationWriterPolicyBody(record.Request)
	if err != nil || actualErr != nil || string(expected) != string(actual) || record.RequestDigest != digestSource(actual) ||
		record.RetryToken != digestSource([]byte(record.OperationID+"\x00"+record.AuthorizationSHA256+"\x00"+record.RequestDigest)) {
		return errors.New("NetBird broker writer checkpoint changed its canonical original request or token")
	}
	return nil
}

// readNetBirdWriterCapability binds the signed clause to the protected original
// writer and independent SDK verification of the exact own-cell control role.
func readNetBirdWriterCapability(ctx context.Context, resolver FoundationResolver, cell string) (NetBirdBrokerPolicyWriterIntent, FoundationRecord, string, time.Time, error) {
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok || reader == nil || resolver.Store == nil {
		return NetBirdBrokerPolicyWriterIntent{}, FoundationRecord{}, "", time.Time{}, ErrFoundationFenced
	}
	ctx, cancel := context.WithDeadline(ctx, reader.expires)
	defer cancel()
	footprint, expires, err := reader.authorizedRegions(ctx)
	if err != nil {
		return NetBirdBrokerPolicyWriterIntent{}, FoundationRecord{}, "", time.Time{}, err
	}
	var capability *NetBirdBrokerPolicyWriterIntent
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] == cell {
			capability = intent.NetBirdBrokerPolicyWriter
		}
	}
	if capability == nil || capability.validate(cell) != nil {
		return NetBirdBrokerPolicyWriterIntent{}, FoundationRecord{}, "", time.Time{}, errors.New("signed foundation lacks the required exact NetBird broker writer capability")
	}
	ctx, cancelSigned := context.WithDeadline(ctx, expires)
	defer cancelSigned()
	record, err := resolver.Resolve(ctx, cell)
	if err != nil {
		return NetBirdBrokerPolicyWriterIntent{}, FoundationRecord{}, "", time.Time{}, err
	}
	if !capability.matches(record.FoundationWriter) || record.FoundationWriter.Policy == nil || record.FoundationWriter.Policy.PolicyID == "" || record.FoundationWriter.Policy.VerifiedAt.IsZero() {
		return NetBirdBrokerPolicyWriterIntent{}, FoundationRecord{}, "", time.Time{}, ErrFoundationFenced
	}
	bindings, err := resolver.ResourceBindingsFor(ctx, cell, "control_compartment")
	if err != nil {
		return NetBirdBrokerPolicyWriterIntent{}, FoundationRecord{}, "", time.Time{}, err
	}
	reference, _ := FoundationResourceReference(cell, "control_compartment")
	control, err := bindings.Resolve(reference)
	if err != nil || control != capability.PolicyCompartmentID || control != record.ResourceIDs["control_compartment"] {
		return NetBirdBrokerPolicyWriterIntent{}, FoundationRecord{}, "", time.Time{}, errors.Join(ErrFoundationFenced, err)
	}
	if err := bindings.Revalidate(ctx); err != nil {
		return NetBirdBrokerPolicyWriterIntent{}, FoundationRecord{}, "", time.Time{}, err
	}
	latest, err := checkNetBirdWriterCapability(ctx, resolver, cell, *capability, record, footprint.GrantSHA256, expires)
	if err != nil {
		return NetBirdBrokerPolicyWriterIntent{}, FoundationRecord{}, "", time.Time{}, err
	}
	return *capability, latest, footprint.GrantSHA256, expires, nil
}

// Recheck after SDK waits without repeating them or renewing the signed scope.
func checkNetBirdWriterCapability(ctx context.Context, resolver FoundationResolver, cell string, intent NetBirdBrokerPolicyWriterIntent, original FoundationRecord, authorization string, expires time.Time) (FoundationRecord, error) {
	reader, ok := resolver.Footprint.(*SignedFootprint)
	if !ok || reader == nil || original.FoundationWriter == nil || resolver.Store == nil {
		return FoundationRecord{}, ErrFoundationFenced
	}
	footprint, currentExpiry, err := reader.authorizedRegions(ctx)
	if err != nil || footprint.GrantSHA256 != authorization || !currentExpiry.Equal(expires) {
		return FoundationRecord{}, errors.Join(ErrFoundationFenced, err)
	}
	var found bool
	for _, region := range footprint.Regions {
		if region.Plan["cell"] == cell && region.NetBirdBrokerPolicyWriter != nil && *region.NetBirdBrokerPolicyWriter == intent {
			found = true
		}
	}
	latest, _, err := resolver.Store.Load(ctx, cell)
	if err != nil || !found || latest.Stage != "reconciled" || latest.OperationID != original.OperationID || latest.Epoch != original.Epoch || latest.IntentDigest != original.IntentDigest ||
		latest.Generation != original.Generation || latest.TenancyID != original.TenancyID || latest.ParentCompartmentID != original.ParentCompartmentID || latest.SharedCompartmentID != original.SharedCompartmentID ||
		latest.ResourceIDs["control_compartment"] != intent.PolicyCompartmentID || !intent.matches(latest.FoundationWriter) {
		return FoundationRecord{}, errors.Join(ErrFoundationFenced, err)
	}
	before, after := *original.FoundationWriter, *latest.FoundationWriter
	before.BrokerPolicyAuthority, after.BrokerPolicyAuthority = nil, nil
	a, err := json.Marshal(before, json.Deterministic(true))
	b, nextErr := json.Marshal(after, json.Deterministic(true))
	if err != nil || nextErr != nil || string(a) != string(b) || ctx.Err() != nil || !time.Now().Before(expires) {
		return FoundationRecord{}, errors.Join(ErrFoundationFenced, ctx.Err(), err, nextErr)
	}
	return latest, nil
}

func verifyNetBirdWriterPolicy(ctx context.Context, client *identity.IdentityClient, request identity.CreatePolicyDetails, policyID string) error {
	response, err := client.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(policyID)})
	if err != nil {
		return err
	}
	if response.Id == nil || *response.Id != policyID || response.Name == nil || request.Name == nil || *response.Name != *request.Name || response.CompartmentId == nil || request.CompartmentId == nil || *response.CompartmentId != *request.CompartmentId || response.LifecycleState != identity.PolicyLifecycleStateActive || !slices.Equal(response.Statements, request.Statements) {
		return errors.New("NetBird broker writer actual policy differs from its exact original request")
	}
	return nil
}

// InstallNetBirdBrokerPolicyWriter uses only the existing authenticated operator
// and the current root-signed grant. The writer cannot install its own extension.
func InstallNetBirdBrokerPolicyWriter(ctx context.Context, factory *ociclient.Factory, genesis trust.Keyring, bundle RetainedFoundation, cell string) error {
	authority, resolver, err := newOperatorHomeIAMAuthority(ctx, factory, genesis, bundle)
	if err != nil {
		return err
	}
	intent, original, authorization, expires, err := readNetBirdWriterCapability(ctx, resolver, cell)
	if err != nil {
		return err
	}
	if authority.operator == nil {
		return ErrFoundationFenced
	}
	signedExpiry := expires
	if authority.operator.deadline.Before(expires) {
		expires = authority.operator.deadline
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
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
	iam, err := authority.factory.Identity()
	if err != nil {
		return err
	}
	committed := original.FoundationWriter.BrokerPolicyAuthority
	guard := func(ctx context.Context) error {
		if err := authority.Guard(ctx, 0); err != nil {
			return err
		}
		current, record, grant, deadline, err := readNetBirdWriterCapability(ctx, resolver, cell)
		if err != nil {
			return err
		}
		if current != intent || grant != authorization || deadline.Before(expires) || record.OperationID != original.OperationID || record.Epoch != original.Epoch || record.IntentDigest != original.IntentDigest {
			return ErrFoundationFenced
		}
		if err := verifyNetBirdWriterPolicy(ctx, &iam, original.FoundationWriter.Policy.Request, original.FoundationWriter.Policy.PolicyID); err != nil {
			return err
		}
		latest, err := checkNetBirdWriterCapability(ctx, resolver, cell, intent, original, authorization, signedExpiry)
		if err != nil {
			return err
		}
		actual, err := json.Marshal(latest.FoundationWriter.BrokerPolicyAuthority, json.Deterministic(true))
		expected, expectedErr := json.Marshal(committed, json.Deterministic(true))
		if err != nil || expectedErr != nil || string(actual) != string(expected) {
			return ErrFoundationFenced
		}
		return ociclient.LimitAdmission(ctx, expires)
	}
	ctx = ociclient.WithAuthority(ctx, guard)
	if err := guard(ctx); err != nil {
		return err
	}
	request := netBirdWriterPolicy(intent)
	found, err := findNetBirdBrokerPolicy(ctx, &iam, request)
	if err != nil {
		return err
	}
	pending := original.FoundationWriter.BrokerPolicyAuthority
	if pending == nil {
		if found != "" {
			return errors.New("NetBird broker writer policy lacks its original protected reservation")
		}
		wire, err := foundationWriterPolicyBody(request)
		if err != nil {
			return err
		}
		pending = &BrokerPolicyAuthorityRecord{Intent: intent, AuthorizationSHA256: authorization, OperationID: original.OperationID, Epoch: original.Epoch, IntentDigest: original.IntentDigest,
			Request: request, RequestDigest: digestSource(wire), FirstAttemptAt: time.Now().UTC(), ExpiresAt: expires}
		pending.RetryToken = digestSource([]byte(pending.OperationID + "\x00" + authorization + "\x00" + pending.RequestDigest))
		if err := commitNetBirdWriterAuthority(ctx, resolver, cell, original, nil, *pending, guard); err != nil {
			return err
		}
		committed = pending
	}
	if pending.validate(original.FoundationWriter) != nil || pending.Intent != intent || pending.AuthorizationSHA256 != authorization || pending.OperationID != original.OperationID || pending.Epoch != original.Epoch || pending.IntentDigest != original.IntentDigest {
		return ErrFoundationFenced
	}
	if pending.PolicyID != "" {
		if found != pending.PolicyID {
			return ErrFoundationFenced
		}
		if err := verifyNetBirdWriterPolicy(ctx, &iam, pending.Request, pending.PolicyID); err != nil {
			return err
		}
		return guard(ctx)
	}
	if !time.Now().Before(pending.ExpiresAt) || pending.Dispatches >= 16 || time.Since(pending.FirstAttemptAt) >= 23*time.Hour || pending.FirstAttemptAt.After(time.Now()) {
		return errors.New("NetBird broker writer original dispatch window exhausted")
	}
	ctx, cancelDispatch := context.WithDeadline(ctx, pending.ExpiresAt)
	defer cancelDispatch()
	next := *pending
	next.Dispatches++
	next.LastDispatchedAt, next.Uncertain = time.Now().UTC(), true
	if err := commitNetBirdWriterAuthority(ctx, resolver, cell, original, pending, next, guard); err != nil {
		return err
	}
	pending = &next
	committed = pending
	if err := guard(ctx); err != nil {
		return err
	}
	noRetry := common.NoRetryPolicy()
	response, err := iam.CreatePolicy(ociclient.RequestContext(ctx), identity.CreatePolicyRequest{CreatePolicyDetails: pending.Request, OpcRetryToken: new(pending.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
	if err != nil {
		return err
	}
	if response.Id == nil || !validAuxiliaryID("controller_usage_policy", *response.Id, "") || found != "" && found != *response.Id {
		return ErrFoundationFenced
	}
	completed := *pending
	completed.PolicyID, completed.Uncertain = *response.Id, false
	if err := verifyNetBirdWriterPolicy(ctx, &iam, completed.Request, completed.PolicyID); err != nil {
		return err
	}
	return commitNetBirdWriterAuthority(ctx, resolver, cell, original, pending, completed, guard)
}

func commitNetBirdWriterAuthority(ctx context.Context, resolver FoundationResolver, cell string, original FoundationRecord, previous *BrokerPolicyAuthorityRecord, next BrokerPolicyAuthorityRecord, guard func(context.Context) error) error {
	if err := guard(ctx); err != nil {
		return err
	}
	latest, etag, err := resolver.Store.Load(ctx, cell)
	if err != nil {
		return err
	}
	if latest.OperationID != original.OperationID || latest.Epoch != original.Epoch || latest.IntentDigest != original.IntentDigest || !next.Intent.matches(latest.FoundationWriter) || next.validate(latest.FoundationWriter) != nil || !time.Now().Before(next.ExpiresAt) {
		return ErrFoundationFenced
	}
	actual, err := json.Marshal(latest.FoundationWriter.BrokerPolicyAuthority, json.Deterministic(true))
	expected, expectedErr := json.Marshal(previous, json.Deterministic(true))
	if err != nil || expectedErr != nil || string(actual) != string(expected) {
		return ErrFoundationFenced
	}
	writer := *latest.FoundationWriter
	writer.BrokerPolicyAuthority = &next
	latest.FoundationWriter, latest.UpdatedAt = &writer, time.Now().UTC()
	if err := guard(ctx); err != nil {
		return err
	}
	_, err = resolver.Store.CompareAndSwap(ctx, latest, etag)
	return err
}

func (authority *HomeIAMAuthority) verifyNetBirdBrokerPolicyWriter(ctx context.Context) error {
	entry, ok := catalog.CellForOCIRegion(authority.factory.Region())
	if !ok {
		return ErrFoundationFenced
	}
	intent, record, authorization, expires, err := readNetBirdWriterCapability(ctx, authority.resolver, entry.Cell)
	if err != nil {
		return err
	}
	pending := record.FoundationWriter.BrokerPolicyAuthority
	if intent.OriginalWriterInstanceID != authority.instanceID || pending == nil || pending.validate(record.FoundationWriter) != nil || pending.Intent != intent || pending.AuthorizationSHA256 != authorization ||
		pending.OperationID != record.OperationID || pending.Epoch != record.Epoch || pending.IntentDigest != record.IntentDigest || pending.PolicyID == "" {
		return ErrFoundationFenced
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	home, err := authority.factory.ForRegion(foundationHomeRegion)
	if err != nil {
		return err
	}
	iam, err := home.Identity()
	if err != nil {
		return err
	}
	if err := verifyNetBirdWriterPolicy(ctx, &iam, pending.Request, pending.PolicyID); err != nil {
		return err
	}
	latest, err := checkNetBirdWriterCapability(ctx, authority.resolver, entry.Cell, intent, record, authorization, expires)
	if err != nil {
		return err
	}
	a, err := json.Marshal(pending, json.Deterministic(true))
	b, currentErr := json.Marshal(latest.FoundationWriter.BrokerPolicyAuthority, json.Deterministic(true))
	if err != nil || currentErr != nil || string(a) != string(b) {
		return ErrFoundationFenced
	}
	return ociclient.LimitAdmission(ctx, expires)
}

func (record FoundationRecord) retainNetBirdWriterAuthority(next FoundationRecord) error {
	if (record.FoundationWriter == nil || record.FoundationWriter.BrokerPolicyAuthority == nil) && (next.FoundationWriter == nil || next.FoundationWriter.BrokerPolicyAuthority == nil) {
		return nil
	}
	if record.FoundationWriter == nil || next.FoundationWriter == nil || next.FoundationWriter.BrokerPolicyAuthority == nil {
		return ErrFoundationFenced
	}
	oldWriter, nextWriter := *record.FoundationWriter, *next.FoundationWriter
	oldWriter.BrokerPolicyAuthority, nextWriter.BrokerPolicyAuthority = nil, nil
	writer, err := json.Marshal(oldWriter, json.Deterministic(true))
	nextBytes, nextErr := json.Marshal(nextWriter, json.Deterministic(true))
	if err != nil || nextErr != nil || string(writer) != string(nextBytes) {
		return ErrFoundationFenced
	}
	original := record.FoundationWriter.BrokerPolicyAuthority
	current := next.FoundationWriter.BrokerPolicyAuthority
	if current.validate(next.FoundationWriter) != nil {
		return ErrFoundationFenced
	}
	if original == nil {
		if current.Dispatches != 0 || current.OperationID != next.OperationID || current.Epoch != next.Epoch || current.IntentDigest != next.IntentDigest {
			return ErrFoundationFenced
		}
		return nil
	}
	before, after := *original, *current
	before.Dispatches, after.Dispatches = 0, 0
	before.LastDispatchedAt, after.LastDispatchedAt = time.Time{}, time.Time{}
	before.Uncertain, after.Uncertain = false, false
	before.PolicyID, after.PolicyID = "", ""
	a, err := json.Marshal(before, json.Deterministic(true))
	b, nextErr := json.Marshal(after, json.Deterministic(true))
	if err != nil || nextErr != nil || string(a) != string(b) || current.Dispatches < original.Dispatches || current.Dispatches > original.Dispatches+1 {
		return ErrFoundationFenced
	}
	if original.PolicyID != "" {
		if current.PolicyID != original.PolicyID || current.Dispatches != original.Dispatches || !current.LastDispatchedAt.Equal(original.LastDispatchedAt) || current.Uncertain {
			return ErrFoundationFenced
		}
	} else if current.Dispatches == original.Dispatches {
		if !current.LastDispatchedAt.Equal(original.LastDispatchedAt) || current.Uncertain != original.Uncertain && (!original.Uncertain || current.Uncertain || current.PolicyID == "") || current.PolicyID != "" && (!original.Uncertain || current.Uncertain) {
			return ErrFoundationFenced
		}
	} else if !current.Uncertain || current.PolicyID != "" || current.LastDispatchedAt.Before(original.LastDispatchedAt) {
		return ErrFoundationFenced
	}
	return nil
}
