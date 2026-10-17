package bootstrapstart

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
)

func (proof *ControllerHostRecipient) ExpiresAt() time.Time { return proof.validUntil }

// VerifyActivationTopology requires all three execution grants in the same
// current root-signed spec; a host-reported domain never supplies a grant.
func (proof *ControllerHostRecipient) VerifyActivationTopology(ctx context.Context) (map[string]bootstrap.ControllerFailureDomain, error) {
	if !proof.Valid(time.Now()) {
		return nil, ErrAdmission
	}
	_, authority, err := proof.current(ctx)
	if err != nil {
		return nil, err
	}
	inputs, err := proof.sources.trust.loadTrustInputs(proof.issuer)
	if err != nil {
		return nil, err
	}
	signed, err := cellspec.VerifyHistorical(proof.spec, inputs.Roots.Current, cellspec.Identity{
		DeploymentID: authority.identity.DeploymentID, Cell: strings.ToLower(authority.identity.Cell), Environment: authority.identity.Environment})
	if err != nil || !signed.RootSigned {
		return nil, ErrAdmission
	}
	domains := make(map[string]bootstrap.ControllerFailureDomain, 3)
	for _, grant := range signed.Spec.HostGrants {
		if !slices.Contains(grant.Roles, "ts-auth") {
			continue
		}
		domain, ok := authority.ControllerFailureDomain(grant.Controller)
		if !ok || domains[grant.Controller] != (bootstrap.ControllerFailureDomain{}) ||
			slices.Contains(grant.Roles, "function-worker") || slices.Contains(grant.Roles, "terrabase") {
			return nil, errors.New("controller activation requires three distinct controller TSAuth grants")
		}
		domains[grant.Controller] = domain
	}
	if len(domains) != 3 || !proof.Valid(time.Now()) {
		return nil, errors.New("controller activation requires all three canonical TSAuth grants")
	}
	return domains, nil
}

// ReadSlotRecipient derives the host locator and address from the retained
// signed grant, then repeats protected completion and live OCI verification.
func (proof *ControllerHostRecipient) ReadSlotRecipient(ctx context.Context, slot, instanceID string) (*ControllerHostRecipient, error) {
	if !proof.Valid(time.Now()) {
		return nil, ErrAdmission
	}
	_, authority, err := proof.current(ctx)
	if err != nil {
		return nil, err
	}
	inputs, err := proof.sources.trust.loadTrustInputs(proof.issuer)
	if err != nil {
		return nil, err
	}
	signed, err := cellspec.VerifyHistorical(proof.spec, inputs.Roots.Current, cellspec.Identity{
		DeploymentID: authority.identity.DeploymentID, Cell: strings.ToLower(authority.identity.Cell), Environment: authority.identity.Environment})
	if err != nil || !signed.RootSigned {
		return nil, ErrAdmission
	}
	for _, grant := range signed.Spec.HostGrants {
		if grant.Controller == slot && slices.Contains(grant.Roles, "ts-auth") {
			current, err := readControllerHostRecipient(ctx, proof.reader, proof.issuer, proof.spec, grant.Node, instanceID, grant.PrivateIP, proof.sources)
			if err != nil {
				return nil, err
			}
			// A sibling read cannot extend the original activation observation.
			current.validUntil = minTime(current.validUntil, proof.validUntil)
			if !proof.Valid(time.Now()) || !current.Valid(time.Now()) {
				return nil, ErrAdmission
			}
			return current, nil
		}
	}
	return nil, ErrAdmission
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
