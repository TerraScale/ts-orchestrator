package managedmaterial

import (
	"encoding/json/v2"
	"strconv"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func validateCredentialRegistry(spec InitialSpec, wire []byte) error {
	var registry apiKeyRegistry
	if err := json.Unmarshal(wire, &registry, json.RejectUnknownMembers(true)); err != nil ||
		registry.Version != 1 || len(registry.Keys) == 0 || len(registry.Keys) > 128 {
		return ErrMaterialConflict
	}
	seen := make(map[string]bool, len(registry.Keys))
	for _, key := range registry.Keys {
		if !entityid.Valid(key.ID) || seen[key.ID] || !lowerHexDigest(key.VerifierSHA256) ||
			key.Tenant != spec.Scope.TenantID || key.Database != spec.Scope.DatabaseID ||
			key.Shard != strconv.FormatUint(spec.Scope.ShardID, 10) ||
			len(key.Permissions) != 2 || key.Permissions[0] != "read" || key.Permissions[1] != "write" ||
			!slicesEqual(key.Collections, initialCollectionIDs(spec.Catalogs)) ||
			!slicesEqual(key.TableIDs, initialSQLTableIDs(spec.SQLTables)) {
			return ErrMaterialConflict
		}
		seen[key.ID] = true
	}
	return nil
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
