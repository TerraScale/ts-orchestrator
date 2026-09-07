package restoredrill

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
)

const nativeReceiptDomain = "terrascale/native-recovery-receipt/v1\x00"

var ErrNativeReceipt = errors.New("restore drill: native receipt is invalid or does not match the restore")
var nativeReceiptULID = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
var nativeReceiptRegion = regexp.MustCompile(`^[A-Za-z0-9-]{1,32}$`)
var nativeChecksumPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// NativeReceiptBinding consists of facts admitted before restore. Placement is
// ordered and must come from that admission, never from the receipt itself.
type NativeReceiptBinding struct {
	TenantID            string   `json:"tenant_id"`
	ProjectID           string   `json:"project_id"`
	SourceDatabaseID    string   `json:"source_database_id"`
	TargetDatabaseID    string   `json:"target_database_id"`
	SourceJournalCut    uint64   `json:"source_journal_cut"`
	CapturedAtMillis    uint64   `json:"captured_at_millis"`
	SourceChecksum      string   `json:"source_checksum"`
	SourceRowCount      uint64   `json:"source_row_count"`
	RestoreEpoch        uint64   `json:"restore_epoch"`
	IdempotencyKey      string   `json:"idempotency_key"`
	OperationID         string   `json:"operation_id"`
	RecoveryPointID     string   `json:"recovery_point_id"`
	RecoveryPointDigest string   `json:"recovery_point_digest"`
	TargetIncarnation   string   `json:"target_incarnation"`
	Placement           []string `json:"placement"`
}

// VerifiedNativeReceipt contains only signature-verified, request-bound facts.
// Completion time is produced by the engine; target statistics must equal the
// independently expected source statistics at the captured journal cut.
type VerifiedNativeReceipt struct {
	SchemaVersion uint64 `json:"schema_version"`
	NativeReceiptBinding
	TargetChecksum    string `json:"target_checksum"`
	TargetRowCount    uint64 `json:"target_row_count"`
	CompletedAtMillis uint64 `json:"completed_at_millis"`
}

func (r VerifiedNativeReceipt) Stats() RestoreStats {
	return RestoreStats{Checksum: r.TargetChecksum, RowCount: int64(r.TargetRowCount)}
}

type NativeReceiptVerifier struct {
	keyID string
	key   ed25519.PublicKey
}

func NewNativeReceiptVerifier(keyID string, key ed25519.PublicKey) (*NativeReceiptVerifier, error) {
	if !nativeReceiptToken(keyID) || len(keyID) > 128 || len(key) != ed25519.PublicKeySize {
		return nil, ErrNativeReceipt
	}
	return &NativeReceiptVerifier{keyID: keyID, key: slices.Clone(key)}, nil
}

func nativeReceiptToken(s string) bool {
	if s == "" || len(s) > 256 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func nativeRequiredJSON(raw []byte, names []string) error {
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != len(names) {
		return ErrNativeReceipt
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrNativeReceipt
		}
	}
	return nil
}

func (v *NativeReceiptVerifier) Verify(raw []byte, expected NativeReceiptBinding) (VerifiedNativeReceipt, error) {
	if v == nil || len(v.key) != ed25519.PublicKeySize || len(raw) == 0 || len(raw) > 16<<10 {
		return VerifiedNativeReceipt{}, ErrNativeReceipt
	}
	if err := nativeRequiredJSON(raw, []string{"key_id", "payload_base64", "signature_base64"}); err != nil {
		return VerifiedNativeReceipt{}, err
	}
	var envelope struct {
		KeyID     string `json:"key_id"`
		Payload   string `json:"payload_base64"`
		Signature string `json:"signature_base64"`
	}
	if err := json.Unmarshal(raw, &envelope, json.RejectUnknownMembers(true)); err != nil || envelope.KeyID != v.keyID {
		return VerifiedNativeReceipt{}, ErrNativeReceipt
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return VerifiedNativeReceipt{}, ErrNativeReceipt
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != envelope.Signature || !ed25519.Verify(v.key, append([]byte(nativeReceiptDomain), payload...), signature) {
		return VerifiedNativeReceipt{}, ErrNativeReceipt
	}
	if err := nativeRequiredJSON(payload, []string{"schema_version", "tenant_id", "project_id", "source_database_id", "target_database_id", "source_journal_cut", "captured_at_millis", "source_checksum", "source_row_count", "target_checksum", "target_row_count", "restore_epoch", "idempotency_key", "operation_id", "recovery_point_id", "placement", "completed_at_millis", "recovery_point_digest", "target_incarnation"}); err != nil {
		return VerifiedNativeReceipt{}, err
	}
	var receipt VerifiedNativeReceipt
	if err := json.Unmarshal(payload, &receipt, json.RejectUnknownMembers(true)); err != nil {
		return VerifiedNativeReceipt{}, ErrNativeReceipt
	}
	if receipt.SchemaVersion != 1 || !nativeChecksumPattern.MatchString(receipt.RecoveryPointDigest) || receipt.TargetIncarnation != receipt.TargetDatabaseID || receipt.SourceJournalCut > math.MaxInt64 || receipt.SourceRowCount > math.MaxInt64 || receipt.TargetRowCount != receipt.SourceRowCount || !nativeChecksumPattern.MatchString(receipt.SourceChecksum) || receipt.TargetChecksum != receipt.SourceChecksum || receipt.RestoreEpoch == 0 || receipt.CapturedAtMillis == 0 || receipt.CompletedAtMillis < receipt.CapturedAtMillis || receipt.CompletedAtMillis > uint64(time.Now().Add(5*time.Second).UnixMilli()) || receipt.SourceDatabaseID == receipt.TargetDatabaseID || len(receipt.Placement) == 0 || len(receipt.Placement) > 20 {
		return VerifiedNativeReceipt{}, ErrNativeReceipt
	}
	for _, id := range []string{receipt.TenantID, receipt.ProjectID, receipt.SourceDatabaseID, receipt.TargetDatabaseID} {
		if !nativeReceiptULID.MatchString(id) {
			return VerifiedNativeReceipt{}, ErrNativeReceipt
		}
	}
	for _, token := range []string{receipt.IdempotencyKey, receipt.OperationID, receipt.RecoveryPointID} {
		if !nativeReceiptToken(token) {
			return VerifiedNativeReceipt{}, ErrNativeReceipt
		}
	}
	seen := make(map[string]bool, len(receipt.Placement))
	for _, region := range receipt.Placement {
		if !nativeReceiptRegion.MatchString(region) || seen[region] {
			return VerifiedNativeReceipt{}, ErrNativeReceipt
		}
		seen[region] = true
	}
	actual := receipt.NativeReceiptBinding
	if actual.RecoveryPointDigest != expected.RecoveryPointDigest || actual.TargetIncarnation != expected.TargetIncarnation || actual.TenantID != expected.TenantID || actual.ProjectID != expected.ProjectID || actual.SourceDatabaseID != expected.SourceDatabaseID || actual.TargetDatabaseID != expected.TargetDatabaseID || actual.SourceJournalCut != expected.SourceJournalCut || actual.CapturedAtMillis != expected.CapturedAtMillis || actual.SourceChecksum != expected.SourceChecksum || actual.SourceRowCount != expected.SourceRowCount || actual.RestoreEpoch != expected.RestoreEpoch || actual.IdempotencyKey != expected.IdempotencyKey || actual.OperationID != expected.OperationID || actual.RecoveryPointID != expected.RecoveryPointID || !slices.Equal(actual.Placement, expected.Placement) {
		return VerifiedNativeReceipt{}, ErrNativeReceipt
	}
	return receipt, nil
}
