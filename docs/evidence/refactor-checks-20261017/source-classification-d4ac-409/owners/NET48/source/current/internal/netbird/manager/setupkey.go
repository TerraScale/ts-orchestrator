package manager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
)

// CreateServerSetupKey plans the servers' setup key: reusable, never
// expiring, unlimited and auto-assigning only the servers group, so every
// revision and autoscaled host of the cell enrolls with it. On apply it
// writes the key value to out; the value is never printed or logged. An
// unrevoked key of the same name (a rotation) is reported, not revoked.
func CreateServerSetupKey(ctx context.Context, api *API, d Desired, out io.Writer, apply bool) (Report, error) {
	var err error
	d, err = d.withServerGroups([]string{d.ServersGroup})
	if err != nil {
		return Report{}, err
	}
	if err := d.Validate(); err != nil {
		return Report{}, err
	}
	var groups []apiGroup
	if err := api.do(ctx, "GET", "/groups", nil, &groups); err != nil {
		return Report{}, err
	}
	spec := d.Groups[slices.IndexFunc(d.Groups, func(group GroupSpec) bool { return group.Name == d.ServersGroup })]
	current, err := matchName(groups, func(group apiGroup) string { return group.Name }, spec.Name, spec.RenamedFrom, "group")
	if err != nil {
		return Report{}, err
	}
	p := &plan{refs: refs{groups: map[string]string{}}}
	if current == nil {
		if err := p.planGroups(api, Desired{Groups: []GroupSpec{spec}}, groups); err != nil {
			return Report{}, err
		}
	} else {
		if current.ID == "" || current.Issued != "api" {
			return Report{}, fmt.Errorf("NetBird regional servers group %s has no API-owned identity", spec.Name)
		}
		p.refs.groups[spec.Name] = current.ID
	}
	var keys []apiSetupKey
	if err := api.do(ctx, "GET", "/setup-keys", nil, &keys); err != nil {
		return Report{}, err
	}
	for _, key := range keys {
		if key.Name == d.SetupKeyName && !key.Revoked {
			p.warn("setup key %s (%s) is still valid; revoke it once Vault holds the new key", key.Name, key.ID)
		}
	}
	p.add(Change{"create", "setup-key", d.SetupKeyName, "reusable, never expires, auto-group " + d.ServersGroup},
		func(ctx context.Context, r *refs) error {
			servers, err := r.group(d.ServersGroup)
			if err != nil {
				return err
			}
			var response struct {
				ID  string `json:"id"`
				Key string `json:"key"`
			}
			if err := api.do(ctx, "POST", "/setup-keys", setupKeyRequest{Name: d.SetupKeyName, Type: "reusable",
				AutoGroups: []string{servers}}, &response); err != nil {
				return err
			}
			if response.Key == "" {
				return fmt.Errorf("manager returned no value for setup key %s (%s); revoke it", d.SetupKeyName, response.ID)
			}
			if _, err := io.WriteString(out, response.Key+"\n"); err != nil {
				return errors.Join(fmt.Errorf("setup key %s (%s) was created but not saved; revoke it", d.SetupKeyName, response.ID), err)
			}
			return nil
		})
	return p.run(ctx, apply, nil)
}
