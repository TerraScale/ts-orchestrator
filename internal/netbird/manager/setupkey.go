package manager

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// CreateServerSetupKey plans the servers' setup key: reusable, never
// expiring, unlimited and auto-assigning only the servers group, so every
// revision and autoscaled host of the cell enrolls with it. On apply it
// writes the key value to out; the value is never printed or logged. An
// unrevoked key of the same name (a rotation) is reported, not revoked.
func CreateServerSetupKey(ctx context.Context, api *API, d Desired, out io.Writer, apply bool) (Report, error) {
	if err := d.Validate(); err != nil {
		return Report{}, err
	}
	servers, err := serversGroupID(ctx, api, d)
	if err != nil {
		return Report{}, err
	}
	var keys []apiSetupKey
	if err := api.do(ctx, "GET", "/setup-keys", nil, &keys); err != nil {
		return Report{}, err
	}
	p := &plan{}
	for _, key := range keys {
		if key.Name == d.SetupKeyName && !key.Revoked {
			p.warn("setup key %s (%s) is still valid; revoke it once Vault holds the new key", key.Name, key.ID)
		}
	}
	p.add(Change{"create", "setup-key", d.SetupKeyName, "reusable, never expires, auto-group " + d.ServersGroup},
		func(ctx context.Context, _ *refs) error {
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
