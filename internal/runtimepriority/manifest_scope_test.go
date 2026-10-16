package runtimepriority

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopeSeparatesAdmissionTokensAndEntityIDs(t *testing.T) {
	const id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	const token = "abcdef0123456789abcdef0123456789"
	for _, tc := range []struct {
		name, field, value string
		valid              bool
	}{
		{"valid", "cluster_id", token, true},
		{"cluster ULID", "cluster_id", id, false},
		{"zero cluster", "cluster_id", strings.Repeat("0", 32), false},
		{"uppercase incarnation", "incarnation", strings.ToUpper(token), false},
		{"incarnation ULID", "incarnation", id, false},
		{"zero incarnation", "incarnation", strings.Repeat("0", 32), false},
		{"tenant token", "tenant_id", token, false},
		{"database token", "database_id", token, false},
		{"lowercase member", "member_id", strings.ToLower(id), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest, _, err := LoadJSON("../../tests/runtime_priority/example-dry-run.json", 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			scope := sub(sub(sub(manifest, "managed_member"), "source"), "scope")
			scope["cluster_id"], scope["incarnation"] = token, token
			scope["tenant_id"], scope["database_id"], scope["member_id"] = id, id, id
			peer := sub(sub(sub(manifest, "managed_member"), "peer"), "scope")
			for _, key := range []string{"cluster_id", "tenant_id", "database_id"} {
				peer[key] = scope[key]
			}
			scope[tc.field] = tc.value
			if tc.valid {
				peer[tc.field] = tc.value
			}
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, Canonical(manifest), 0600); err != nil {
				t.Fatal(err)
			}
			output, err := runtimeCLI(t, "pressure", "dry-run", "--manifest", path)
			if !tc.valid && !strings.Contains(string(output), "source.scope."+tc.field) {
				t.Fatalf("scope rejected for the wrong reason: %s", output)
			}
			if (err == nil) != tc.valid {
				t.Fatalf("valid = %v, error = %v: %s", tc.valid, err, output)
			}
		})
	}
}
