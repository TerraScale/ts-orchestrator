package regionhost

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/oracle/oci-go-sdk/v65/identity"
)

func ReconcileVaultPolicy(ctx context.Context, client *identity.IdentityClient, compartment, name string, want []string) (string, string, error) {
	listed, err := client.ListPolicies(ctx, identity.ListPoliciesRequest{CompartmentId: &compartment, Name: &name})
	if err != nil {
		return "", "", err
	}
	if len(listed.Items) == 0 {
		created, err := client.CreatePolicy(ctx, identity.CreatePolicyRequest{CreatePolicyDetails: identity.CreatePolicyDetails{CompartmentId: &compartment, Name: &name, Description: new("Host Vault grants"), Statements: want}})
		if err != nil {
			return "", "", err
		}
		if created.Id == nil {
			return "", "", errors.New("created Vault policy has no id")
		}
		return *created.Id, "created", nil
	}
	if len(listed.Items) != 1 {
		return "", "", errors.New("managed Vault policy inventory is ambiguous")
	}
	current, err := client.GetPolicy(ctx, identity.GetPolicyRequest{PolicyId: listed.Items[0].Id})
	if err != nil {
		return "", "", err
	}
	if len(current.Statements) == 0 || current.Id == nil || current.Name == nil || *current.Name != name || current.CompartmentId == nil || *current.CompartmentId != compartment || current.LifecycleState != identity.PolicyLifecycleStateActive {
		return "", "", errors.New("managed Vault policy inventory is incomplete or inactive")
	}
	same := slices.Equal(slices.Sorted(slices.Values(current.Statements)), slices.Sorted(slices.Values(want)))
	narrowing := false
	for _, statement := range current.Statements {
		if !slices.Contains(want, statement) {
			same = false
			narrowing = true
		}
	}
	if same {
		return *current.Id, "unchanged", nil
	}
	if narrowing {
		retainedName := name + "-transition"
		policies, err := client.ListPolicies(ctx, identity.ListPoliciesRequest{CompartmentId: &compartment, Name: &retainedName})
		if err != nil {
			return "", "", err
		}
		if len(policies.Items) != 1 {
			return "", "", fmt.Errorf("refuse to narrow managed Vault policy: retain its current statements in separate policy %s first", retainedName)
		}
		retained, err := client.GetPolicy(ctx, identity.GetPolicyRequest{PolicyId: policies.Items[0].Id})
		if err != nil {
			return "", "", err
		}
		if retained.Id == nil || current.Id == nil || *retained.Id == *current.Id || retained.Name == nil || *retained.Name != retainedName || retained.CompartmentId == nil || *retained.CompartmentId != compartment || retained.LifecycleState != identity.PolicyLifecycleStateActive {
			return "", "", errors.New("retained Vault policy must be separate, active and in the same compartment")
		}
		for _, statement := range current.Statements {
			if !slices.Contains(retained.Statements, statement) {
				return "", "", errors.New("retained Vault policy does not preserve every current managed statement")
			}
		}
	}
	if current.Etag == nil || *current.Etag == "" {
		return "", "", errors.New("managed Vault policy has no concurrency token")
	}
	_, err = client.UpdatePolicy(ctx, identity.UpdatePolicyRequest{PolicyId: current.Id, IfMatch: current.Etag, UpdatePolicyDetails: identity.UpdatePolicyDetails{Statements: want}})
	if err != nil {
		return "", "", err
	}
	return *current.Id, "updated", nil
}
