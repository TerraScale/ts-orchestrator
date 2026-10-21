package ociregion

import "github.com/TerraScale/ts-orchestrator/internal/bootstrap"

// FoundationBucketKey selects the signed home ledger key; other bucket roles
// retain the plan key. The caller supplies only independently verified storage.
func FoundationBucketKey(plan, ids Object, role string, home bootstrap.StorageDomain) (string, error) {
	return capture(func() string {
		key := text(ids["key"])
		if home == (bootstrap.StorageDomain{}) {
			return key
		}
		names := obj(plan["foundation_buckets"])
		if home.Validate() != nil || plan["cell"] != "GRU" || plan["region"] != "sa-saopaulo-1" ||
			names["ledger"] != home.LedgerBucket || names["head"] != home.HeadBucket || key != home.HeadKMSKeyOCID {
			fail("signed home storage differs from the GRU foundation plan")
		}
		requireOCID(home.LedgerKMSKeyOCID, "key", "sa-saopaulo-1")
		requireOCID(home.HeadKMSKeyOCID, "key", "sa-saopaulo-1")
		if role == "ledger" {
			return home.LedgerKMSKeyOCID
		}
		return key
	})
}

// RequiredStorageControllerStatements includes the exact signed home ledger
// key when it differs from the plan's head/material key.
func RequiredStorageControllerStatements(plan, ids Object, prefix string, home bootstrap.StorageDomain) ([]string, error) {
	ledger, err := FoundationBucketKey(plan, ids, "ledger", home)
	if err != nil {
		return nil, err
	}
	return capture(func() []string { return controllerStatements(plan, ids, prefix, ledger) })
}

// ObjectStorageKeyStatements grants the regional service only the distinct
// keys used by the plan and its independently verified home storage domain.
func ObjectStorageKeyStatements(plan, ids Object, home bootstrap.StorageDomain) ([]string, error) {
	ledger, err := FoundationBucketKey(plan, ids, "ledger", home)
	if err != nil {
		return nil, err
	}
	return capture(func() []string {
		statements := []string{ObjectStorageKeyStatement(plan, ids)}
		if ledger != text(ids["key"]) {
			statements = append(statements, ObjectStorageKeyStatement(plan, Object{"key": ledger}))
		}
		return statements
	})
}
