package manager

import (
	"context"
	"errors"
	"net/url"
	"slices"
)

// RestrictBaseline removes only the pinned upstream genesis grant before ingress
// or enrollment opens. Changed or ambiguous defaults require explicit recovery.
func RestrictBaseline(ctx context.Context, api *API) error {
	if api == nil || api.beforeWrite == nil {
		return errors.New("NetBird baseline requires dedicated manager authority")
	}
	var groups []apiGroup
	if err := api.do(ctx, "GET", "/groups", nil, &groups); err != nil {
		return err
	}
	all := ""
	for _, group := range groups {
		if group.Name != "All" {
			continue
		}
		if all != "" || group.ID == "" || group.Issued != "api" {
			return errors.New("NetBird upstream All group is ambiguous or altered")
		}
		all = group.ID
	}
	if all == "" {
		return errors.New("NetBird upstream All group is absent")
	}
	var policies []apiPolicy
	if err := api.do(ctx, "GET", "/policies", nil, &policies); err != nil {
		return err
	}
	var defaults []apiPolicy
	for _, policy := range policies {
		if policy.Name == "Default" {
			defaults = append(defaults, policy)
		}
	}
	if len(defaults) == 0 {
		return nil
	}
	const description = "This is a default rule that allows connections between all the resources"
	if len(defaults) != 1 {
		return errors.New("NetBird upstream default policy is ambiguous")
	}
	policy := defaults[0]
	if policy.ID == "" || policy.Description != description || !policy.Enabled || len(policy.SourcePostureChecks) != 0 || len(policy.Rules) != 1 {
		return errors.New("NetBird upstream default policy was altered")
	}
	rule := policy.Rules[0]
	if rule.ID != policy.ID || rule.Name != "Default" || rule.Description != description || !rule.Enabled || !rule.Bidirectional || rule.Action != "accept" || rule.Protocol != "all" ||
		len(rule.Ports) != 0 || len(rule.PortRanges) != 0 || !slices.Equal(minimumIDs(rule.Sources), []string{all}) || !slices.Equal(minimumIDs(rule.Destinations), []string{all}) ||
		rule.SourceResource != nil || rule.DestinationResource != nil || len(rule.AuthorizedGroups) != 0 {
		return errors.New("NetBird upstream default rule was altered")
	}
	if err := api.do(ctx, "DELETE", "/policies/"+url.PathEscape(policy.ID), nil, nil); err != nil {
		return err
	}
	// A lost response is recovered by the next locked pass; never infer deletion from a successful status alone.
	var remaining []apiPolicy
	if err := api.do(ctx, "GET", "/policies", nil, &remaining); err != nil {
		return err
	}
	if slices.ContainsFunc(remaining, func(p apiPolicy) bool { return p.ID == policy.ID || p.Name == "Default" }) {
		return errors.New("NetBird upstream default policy deletion was not observed")
	}
	return nil
}
