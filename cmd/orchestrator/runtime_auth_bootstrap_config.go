package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"

	"google.golang.org/protobuf/encoding/protojson"
	"terrascale.tech/orchestrator/src/orchestrator/authbootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// LoadProductionAuthBootstrap admits explicit auth-domain genesis intent before
// any authority lease is acquired. It contains no tokens or user rows.
func LoadProductionAuthBootstrap(path string) (productionAuthBootstrapConfig, error) {
	if path == "" {
		return productionAuthBootstrapConfig{}, authbootstrap.ErrInvalid
	}
	data, err := bootstrapcredentials.ReadFile(path, false, 256<<10)
	if err != nil {
		return productionAuthBootstrapConfig{}, err
	}
	return parseProductionAuthBootstrapConfig(data)
}
func parseProductionAuthBootstrapConfig(data []byte) (productionAuthBootstrapConfig, error) {
	var file struct {
		Version int `json:"version"`
		Targets []struct {
			ServerIdentity string `json:"server_identity"`
			Principal      string `json:"principal"`
		} `json:"targets"`
		Grants []jsontext.Value `json:"grants"`
	}
	if len(data) > 256<<10 || json.Unmarshal(data, &file, json.RejectUnknownMembers(true)) != nil || file.Version != 1 || len(file.Targets) == 0 || len(file.Targets) > 128 || len(file.Grants) == 0 || len(file.Grants) > 32 {
		return productionAuthBootstrapConfig{}, authbootstrap.ErrInvalid
	}
	result := productionAuthBootstrapConfig{}
	targets := map[string]string{}
	for _, target := range file.Targets {
		if _, _, err := authbootstrap.HostSubjects(target.ServerIdentity); err != nil {
			return result, err
		}
		if _, _, err := authbootstrap.HostSubjects(target.Principal); err != nil {
			return result, err
		}
		if _, exists := targets[target.ServerIdentity]; exists {
			return result, authbootstrap.ErrConflict
		}
		targets[target.ServerIdentity] = target.Principal
		result.Targets = append(result.Targets, productionPlacementTarget{ServerIdentity: target.ServerIdentity, Principal: target.Principal})
	}
	groups := map[string]bool{}
	scopes := map[string]bool{}
	for _, raw := range file.Grants {
		grant := new(pb.AuthGroupBootstrapGrant)
		if (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, grant) != nil {
			return result, authbootstrap.ErrInvalid
		}
		canonical, err := authbootstrap.CanonicalGrant(grant, true)
		if err != nil || canonical.AuthorityRevision != 0 {
			return result, authbootstrap.ErrInvalid
		}
		key := canonical.Environment + "/" + canonical.Cluster + "/" + canonical.Tenant + "/" + canonical.Project + "/" + canonical.Database
		if groups[canonical.GroupId] || scopes[key] {
			return result, authbootstrap.ErrConflict
		}
		groups[canonical.GroupId] = true
		scopes[key] = true
		for _, voter := range canonical.Voters {
			if _, ok := targets[voter.SpiffeUri]; !ok {
				return result, authbootstrap.ErrInvalid
			}
		}
		result.Grants = append(result.Grants, canonical)
	}
	return result, nil
}
