package runtimepriority

import (
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
			scope := Object{"cluster_id": token, "incarnation": token, "tenant_id": id, "database_id": id, "member_id": id, "shard_id": int64(1)}
			scope[tc.field] = tc.value
			err := func() (err error) {
				defer recoverError(&err)
				validateScope(scope, "test.scope")
				return
			}()
			if (err == nil) != tc.valid {
				t.Fatalf("valid = %v, error = %v", tc.valid, err)
			}
		})
	}
}
