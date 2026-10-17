package region

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

const ocirAuthorityLimit = 32 << 10

func matchesOCIRAuthorityPolicy(details identity.CreatePolicyDetails, observed identity.Policy) bool {
	return observed.CompartmentId != nil && details.CompartmentId != nil && *observed.CompartmentId == *details.CompartmentId && observed.Name != nil && details.Name != nil && *observed.Name == *details.Name && observed.Description != nil && details.Description != nil && *observed.Description == *details.Description && slices.Equal(observed.Statements, details.Statements) && observed.VersionDate == nil && len(observed.FreeformTags) == 0 && len(observed.DefinedTags) == 0
}

// OCIRAuthorityRecord is one finite OPERATOR-installed capability for the
// original writer. It conveys no object-writer or capacity authority.
type OCIRAuthorityRecord struct {
	FoundationOperation string                `json:"foundationOperation"`
	Epoch               uint64                `json:"epoch"`
	WriterSHA256        string                `json:"writerSha256"`
	ScopeSHA256         string                `json:"scopeSha256"`
	Scope               []OCIRIssuerIntent    `json:"scope"`
	FirstAttemptAt      time.Time             `json:"firstAttemptAt"`
	DispatchExpiresAt   time.Time             `json:"dispatchExpiresAt"`
	AuthorityExpiresAt  time.Time             `json:"authorityExpiresAt"`
	Policies            []OCIRAuthorityPolicy `json:"policies"`
}

type OCIRAuthorityPolicy struct {
	Request       identity.CreatePolicyDetails `json:"request"`
	RequestDigest string                       `json:"requestDigest"`
	RetryToken    string                       `json:"retryToken"`
	Dispatches    []OCIRAuthorityDispatch      `json:"dispatches"`
	PolicyID      string                       `json:"policyId,omitempty"`
	VerifiedAt    time.Time                    `json:"verifiedAt,omitzero"`
}

type OCIRAuthorityDispatch struct {
	OCIRIssuerDispatch
	ObservedID string `json:"observedId,omitempty"`
}

func ocirWriterDigest(writer FoundationWriterRecord) (string, error) {
	wire, err := json.Marshal(foundationWriterOriginal(writer), json.Deterministic(true))
	return digestSource(wire), err
}

func ocirAuthorityScopeDigest(scope []OCIRIssuerIntent) (string, error) {
	wire, err := json.Marshal(scope, json.Deterministic(true))
	return digestSource(wire), err
}

func ocirAuthorityPolicies(writer FoundationWriterRecord, reservation OCIRAuthorityRecord) ([]OCIRAuthorityPolicy, error) {
	entry, ok := catalog.Lookup(writer.Cell)
	if !ok || !sourceInstancePattern.MatchString(writer.InstanceID) || len(reservation.Scope) == 0 || len(reservation.Scope) > 64 || reservation.AuthorityExpiresAt.IsZero() {
		return nil, ErrFoundationFenced
	}
	groups := map[string][]string{}
	previous := ""
	for _, intent := range reservation.Scope {
		key := intent.RepositoryCompartmentID + "\x00" + intent.RepositoryName
		if validateOCIRIssuerIdentity(intent) != nil || intent.OCIRegion != entry.OCIRegion || !sourceCompartmentPattern.MatchString(intent.RepositoryCompartmentID) || key <= previous {
			return nil, ErrFoundationFenced
		}
		previous = key
		groups[intent.RepositoryCompartmentID] = append(groups[intent.RepositoryCompartmentID], intent.RepositoryName)
	}
	if len(groups) > 2 {
		return nil, ErrFoundationFenced
	}
	compartments := make([]string, 0, len(groups))
	for compartment := range groups {
		compartments = append(compartments, compartment)
	}
	slices.Sort(compartments)
	policies := make([]OCIRAuthorityPolicy, 0, len(compartments))
	for _, compartment := range compartments {
		names := make([]string, 0, len(groups[compartment]))
		for _, name := range groups[compartment] {
			names = append(names, "target.repo.name='"+name+"'")
		}
		condition := names[0]
		if len(names) > 1 {
			condition = "any {" + strings.Join(names, ", ") + "}"
		}
		// CREATE/name applicability remains unqualified. A missing variable denies;
		// never remove this condition to obtain compartment-wide CREATE authority.
		statement := fmt.Sprintf("Allow any-user to manage repos in compartment id %s where all {request.principal.type='instance', request.principal.id='%s', request.region='%s', request.utc-timestamp before '%s', %s, any {all {request.operation='CreateContainerRepository', request.permission='REPOSITORY_CREATE'}, all {request.operation='GetContainerRepository', request.permission='REPOSITORY_READ'}, all {request.operation='UpdateContainerRepository', request.permission='REPOSITORY_MANAGE'}}}", compartment, writer.InstanceID, entry.OCIRegionKey, reservation.AuthorityExpiresAt.UTC().Format(time.RFC3339Nano), condition)
		name := "ts-ocir-writer-" + digestSource([]byte(writer.InstallationID + "\x00" + writer.Cell + "\x00" + compartment + "\x00" + reservation.ScopeSHA256))[:32]
		details := identity.CreatePolicyDetails{CompartmentId: new(compartment), Name: new(name), Description: new("Original writer finite signed OCIR repository lifecycle"), Statements: []string{statement}, FreeformTags: map[string]string{}, DefinedTags: map[string]map[string]any{}}
		wire, err := foundationWriterPolicyBody(details)
		if err != nil {
			return nil, err
		}
		digest := digestSource(wire)
		policies = append(policies, OCIRAuthorityPolicy{Request: details, RequestDigest: digest, RetryToken: digestSource([]byte(reservation.WriterSHA256 + "\x00" + reservation.ScopeSHA256 + "\x00" + digest)), Dispatches: []OCIRAuthorityDispatch{}})
	}
	return policies, nil
}

func (reservation OCIRAuthorityRecord) validate(writer FoundationWriterRecord) error {
	writerDigest, err := ocirWriterDigest(writer)
	scopeDigest, scopeErr := ocirAuthorityScopeDigest(reservation.Scope)
	if err != nil || scopeErr != nil || !entityid.Valid(reservation.FoundationOperation) || reservation.Epoch == 0 || writer.InstanceID == "" || writer.Policy == nil || writer.Policy.PolicyID == "" || writer.Policy.VerifiedAt.IsZero() || reservation.WriterSHA256 != writerDigest || reservation.ScopeSHA256 != scopeDigest || reservation.FirstAttemptAt.Before(writer.Policy.VerifiedAt) || !reservation.FirstAttemptAt.Before(reservation.DispatchExpiresAt) || reservation.DispatchExpiresAt.After(reservation.FirstAttemptAt.Add(bootstrapRetryLifetime)) || reservation.DispatchExpiresAt.After(reservation.AuthorityExpiresAt) {
		return errors.New("OCIR authority differs from its immutable original writer or lifetime")
	}
	expected, err := ocirAuthorityPolicies(writer, reservation)
	if err != nil || len(expected) != len(reservation.Policies) {
		return ErrFoundationFenced
	}
	for index, policy := range reservation.Policies {
		wire, err := foundationWriterPolicyBody(policy.Request)
		want, wantErr := foundationWriterPolicyBody(expected[index].Request)
		if err != nil || wantErr != nil || string(wire) != string(want) || policy.RequestDigest != expected[index].RequestDigest || policy.RetryToken != expected[index].RetryToken || len(policy.Dispatches) > 16 || policy.PolicyID == "" && !policy.VerifiedAt.IsZero() || policy.PolicyID != "" && (!validAuxiliaryID("controller_usage_policy", policy.PolicyID, "") || policy.VerifiedAt.Before(reservation.FirstAttemptAt) || !policy.VerifiedAt.Before(reservation.DispatchExpiresAt)) {
			return errors.New("OCIR authority policy differs from its exact original SDK request")
		}
		positiveID := ""
		for _, dispatch := range policy.Dispatches {
			if dispatch.StartedAt.Before(reservation.FirstAttemptAt) || !dispatch.StartedAt.Before(reservation.DispatchExpiresAt) || !dispatch.FinishedAt.IsZero() && dispatch.FinishedAt.Before(dispatch.StartedAt) || dispatch.Status != 0 && (!dispatch.Sent || dispatch.Status < 100 || dispatch.Status > 599 || dispatch.FinishedAt.IsZero()) || dispatch.FinishedAt.IsZero() && (dispatch.Sent || dispatch.ObservedID != "") || dispatch.ObservedID != "" && (!dispatch.Sent || dispatch.Status != 200 && dispatch.Status != 201 || !validAuxiliaryID("controller_usage_policy", dispatch.ObservedID, "")) {
				return errors.New("OCIR authority dispatch history is invalid")
			}
			if dispatch.ObservedID != "" {
				if positiveID != "" && dispatch.ObservedID != positiveID || policy.PolicyID != "" && (dispatch.ObservedID != policy.PolicyID || policy.VerifiedAt.Before(dispatch.FinishedAt)) {
					return ErrFoundationFenced
				}
				positiveID = dispatch.ObservedID
			}
		}
		if policy.PolicyID != "" && positiveID == "" {
			return errors.New("OCIR policy lacks a positive original create dispatch")
		}
	}
	wire, err := json.Marshal(reservation, json.Deterministic(true))
	if err != nil || len(wire) > ocirAuthorityLimit {
		return errors.New("OCIR authority exceeds its finite protected reservation")
	}
	return nil
}

func (record FoundationRecord) retainOCIRAuthority(next FoundationRecord) error {
	if record.FoundationWriter == nil || record.FoundationWriter.OCIRAuthority == nil {
		return nil
	}
	if !sameFoundationWriterOriginal(record.FoundationWriter, next.FoundationWriter) || next.FoundationWriter.OCIRAuthority == nil {
		return ErrFoundationFenced
	}
	before, after := *record.FoundationWriter.OCIRAuthority, *next.FoundationWriter.OCIRAuthority
	oldPolicies, newPolicies := before.Policies, after.Policies
	before.Policies, after.Policies = nil, nil
	if !reflect.DeepEqual(before, after) || len(oldPolicies) != len(newPolicies) {
		return ErrFoundationFenced
	}
	for index, old := range oldPolicies {
		current := newPolicies[index]
		oldDispatches, currentDispatches := old.Dispatches, current.Dispatches
		if old.PolicyID != "" && (old.PolicyID != current.PolicyID || !old.VerifiedAt.Equal(current.VerifiedAt)) || len(currentDispatches) < len(oldDispatches) {
			return ErrFoundationFenced
		}
		old.Dispatches, current.Dispatches = nil, nil
		old.PolicyID, current.PolicyID = "", ""
		old.VerifiedAt, current.VerifiedAt = time.Time{}, time.Time{}
		if !reflect.DeepEqual(old, current) {
			return ErrFoundationFenced
		}
		for dispatchIndex, dispatch := range oldDispatches {
			observed := currentDispatches[dispatchIndex]
			if !dispatch.StartedAt.Equal(observed.StartedAt) || !dispatch.FinishedAt.IsZero() && dispatch != observed {
				return ErrFoundationFenced
			}
		}
	}
	return nil
}
