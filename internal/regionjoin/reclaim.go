package regionjoin

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func reclaim(ctx context.Context, vault vault, region, hostname, instanceID string, current vaultsecret.Current) (Material, error) {
	material, err := decode(region, current.Value())
	if err != nil || current.CreatedAt.IsZero() {
		return material, err
	}
	if _, joinable := ReachableManager(ctx, material); joinable {
		return material, nil
	}
	definition, err := fleet.Embedded().Region(region)
	if err != nil {
		return Material{}, err
	}
	factory, err := ociclient.InstancePrincipalContext(ctx, definition.OCIRegion)
	if err != nil {
		return Material{}, err
	}
	client, err := factory.Compute()
	if err != nil {
		return Material{}, err
	}
	var candidates []core.Instance
	var page *string
	for {
		listed, err := client.ListInstances(ctx, core.ListInstancesRequest{CompartmentId: common.String(definition.CompartmentID), Page: page})
		if err != nil {
			return Material{}, fmt.Errorf("read region incarnation: %w", err)
		}
		for _, instance := range listed.Items {
			if instance.LifecycleState == core.InstanceLifecycleStateTerminated {
				continue
			}
			if instance.TimeCreated == nil || !instance.TimeCreated.After(current.CreatedAt) {
				return material, nil
			}
			if instance.Id != nil && (ociresource.Ownership{Owner: fleet.Owner}).Owns(definition.Key("instance", "node"), ociresource.Tags{Freeform: instance.FreeformTags}) {
				candidates = append(candidates, instance)
			}
		}
		if listed.OpcNextPage == nil || *listed.OpcNextPage == "" {
			break
		}
		page = listed.OpcNextPage
	}
	slices.SortFunc(candidates, func(a, b core.Instance) int {
		if order := a.TimeCreated.Compare(b.TimeCreated.Time); order != 0 {
			return order
		}
		return strings.Compare(*a.Id, *b.Id)
	})
	if len(candidates) == 0 || *candidates[0].Id != instanceID {
		return Material{}, fmt.Errorf("waiting for the oldest document node to reclaim %s", SecretName(region))
	}
	material = Material{Founder: hostname, FounderInstance: instanceID}
	value, err := json.Marshal(material)
	if err != nil {
		return Material{}, err
	}
	_, err = vaultsecret.Publish(ctx, vault.factory, vaultsecret.Ref{Vault: vault.target.VaultID, Name: SecretName(region)}, current.ID, current.Version, value)
	return material, err
}
