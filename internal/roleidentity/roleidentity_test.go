package roleidentity_test

import (
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/roleidentity"
)

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
