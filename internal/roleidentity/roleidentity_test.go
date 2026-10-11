package roleidentity_test

import (
	"slices"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/roleidentity"
)

func TestRoleScopePublishesObservationsInOwnCell(t *testing.T) {
	if !slices.Contains(roleidentity.Scope("key").Template.Pub.Allow, "ts.orch.v1.{{tag(cell)}}.obs.{{tag(obs)}}") {
		t.Fatal("role scope does not let members publish their cell's observation leaves")
	}
}

func TestRoleObservationsAreNotControllerLeaves(t *testing.T) {
	for role, grant := range roleidentity.Grants {
		for _, leaf := range grant.Observations {
			if leaf == "region" || leaf == "decisions" || strings.ContainsAny(leaf, ">*.") {
				t.Fatalf("%s: observation leaf %q is not a member leaf", role, leaf)
			}
		}
	}
}

func TestRoleGrantBucketsStartWithTheirRole(t *testing.T) {
	for role, grant := range roleidentity.Grants {
		prefix := strings.ReplaceAll(role, "-", "_") + "_"
		if !strings.HasSuffix(grant.EnvPrefix, "_") || len(grant.Buckets) == 0 {
			t.Fatalf("%s: env prefix %q or no buckets", role, grant.EnvPrefix)
		}
		for _, bucket := range grant.Buckets {
			if !strings.HasPrefix(bucket.Name, prefix) || strings.ToLower(bucket.Name) != bucket.Name {
				t.Fatalf("%s: bucket %q must be lowercase and start with %q", role, bucket.Name, prefix)
			}
		}
	}
}
