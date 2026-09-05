package candidatesync

import (
	"encoding/hex"
	"errors"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
)

// VerifyScopedReceipt attributes the receipt using the key in the verified
// owner scope, then requires every regional object in its original order.
// Restore hashes are signed evidence references, not independent verification
// of the bytes or a claim that the candidate remains healthy now.
func VerifyScopedReceipt(scope preliminarytransfer.VerifiedScope, region string, raw []byte, observedAt time.Time) (Receipt, error) {
	if err := scope.Check(); err != nil {
		return Receipt{}, err
	}
	return verifyScopedReceipt(scope, region, raw, observedAt)
}

// The caller must have checked scope immediately before using this helper.
func verifyScopedReceipt(scope preliminarytransfer.VerifiedScope, region string, raw []byte, observedAt time.Time) (Receipt, error) {
	bad := errors.New("candidatesync: receipt differs from exact preliminary scope")
	var candidate preliminarytransfer.Candidate
	for _, c := range scope.Scope.Candidates {
		if c.Region == region {
			candidate = c
		}
	}
	if candidate.NodeID == "" || observedAt.IsZero() {
		return Receipt{}, bad
	}
	r, err := VerifyReceipt([]byte(candidate.ReceiptPublicKeyPEM), raw)
	if err != nil {
		return Receipt{}, err
	}
	epoch, err := scope.CaptureEpoch()
	if err != nil {
		return Receipt{}, err
	}
	captured, err := scope.CaptureTime()
	if err != nil {
		return Receipt{}, err
	}
	if r.ScopeSHA256 != scope.Digest || r.NodeID != candidate.NodeID || r.Region != region || r.PreparationGrantSHA256 != scope.Scope.PreparationGrantSHA256 || r.BootstrapGrantSHA256 != candidate.BootstrapGrantSHA256 || r.ManifestSHA256 != candidate.ManifestSHA256 || r.SourceReceiptSHA256 != scope.Scope.ReceiptSHA256 || r.CaptureEpoch != epoch || r.CreatedAt.Before(captured) || r.CreatedAt.After(observedAt) {
		return Receipt{}, bad
	}
	index := 0
	for _, object := range scope.Scope.Objects {
		if object.Region != region {
			continue
		}
		if index >= len(r.Objects) || r.Objects[index].Object != object || !receiptDigest(r.Objects[index].RestoreSHA256) {
			return Receipt{}, bad
		}
		index++
	}
	if index == 0 || index != len(r.Objects) {
		return Receipt{}, bad
	}
	return r, nil
}

func receiptDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}
