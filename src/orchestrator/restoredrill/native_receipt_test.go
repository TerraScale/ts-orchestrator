package restoredrill

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
)

// Hand-authored wire JSON deliberately uses whitespace and non-struct field
// order. Verification must authenticate these exact bytes, never reserialize.
const nativeReceiptTestPayload = `{
 "completed_at_millis":1700000001000,
 "schema_version":1,"tenant_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV",
 "project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAW",
 "source_database_id":"01ARZ3NDEKTSV4RRFFQ69G5FAX",
 "target_database_id":"01ARZ3NDEKTSV4RRFFQ69G5FAY",
 "source_journal_cut":42,"captured_at_millis":1700000000000,
 "source_checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "source_row_count":7,
 "target_checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "target_row_count":7,"restore_epoch":8,"idempotency_key":"restore/8",
 "operation_id":"operation-1","recovery_point_id":"recovery-1","placement":["GRU","VCP"]}`

func nativeReceiptExpected() NativeReceiptBinding {
	return NativeReceiptBinding{TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", SourceDatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", TargetDatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAY", SourceJournalCut: 42, CapturedAtMillis: 1700000000000, SourceChecksum: strings.Repeat("a", 64), SourceRowCount: 7, RestoreEpoch: 8, IdempotencyKey: "restore/8", OperationID: "operation-1", RecoveryPointID: "recovery-1", Placement: []string{"GRU", "VCP"}}
}
func nativeTestEnvelope(t *testing.T, key ed25519.PrivateKey, payload, domain string) []byte {
	t.Helper()
	signature := ed25519.Sign(key, append([]byte(domain), []byte(payload)...))
	raw, err := json.Marshal(map[string]string{"key_id": "receipt-key", "payload_base64": base64.StdEncoding.EncodeToString([]byte(payload)), "signature_base64": base64.StdEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNativeReceiptVerifiesExactBytesAndPinsCopiedKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewNativeReceiptVerifier("receipt-key", public)
	if err != nil {
		t.Fatal(err)
	}
	clear(public)
	raw := nativeTestEnvelope(t, private, nativeReceiptTestPayload, "terrascale/native-recovery-receipt/v1\x00")
	expected := nativeReceiptExpected()
	receipt, err := verifier.Verify(raw, expected)
	if err != nil {
		t.Fatal(err)
	}
	expected.Placement[0] = "changed"
	if receipt.Placement[0] != "GRU" || receipt.Stats().RowCount != 7 || receipt.Stats().Checksum != strings.Repeat("a", 64) || receipt.CompletedAtMillis != 1700000001000 {
		t.Fatal("incorrect or aliased receipt facts")
	}
}

func TestNativeReceiptRejectsRequestRebinding(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier, _ := NewNativeReceiptVerifier("receipt-key", public)
	raw := nativeTestEnvelope(t, private, nativeReceiptTestPayload, "terrascale/native-recovery-receipt/v1\x00")
	for _, tc := range []struct {
		name   string
		change func(*NativeReceiptBinding)
	}{
		{"tenant", func(b *NativeReceiptBinding) { b.TenantID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ" }},
		{"project", func(b *NativeReceiptBinding) { b.ProjectID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ" }},
		{"source", func(b *NativeReceiptBinding) { b.SourceDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ" }},
		{"target", func(b *NativeReceiptBinding) { b.TargetDatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ" }},
		{"cut", func(b *NativeReceiptBinding) { b.SourceJournalCut++ }},
		{"capture", func(b *NativeReceiptBinding) { b.CapturedAtMillis++ }},
		{"checksum", func(b *NativeReceiptBinding) { b.SourceChecksum = strings.Repeat("b", 64) }},
		{"count", func(b *NativeReceiptBinding) { b.SourceRowCount++ }},
		{"epoch", func(b *NativeReceiptBinding) { b.RestoreEpoch++ }},
		{"operation", func(b *NativeReceiptBinding) { b.OperationID = "other" }},
		{"idempotency", func(b *NativeReceiptBinding) { b.IdempotencyKey = "other" }},
		{"recovery", func(b *NativeReceiptBinding) { b.RecoveryPointID = "other" }},
		{"placement order", func(b *NativeReceiptBinding) { b.Placement = []string{"VCP", "GRU"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected := nativeReceiptExpected()
			tc.change(&expected)
			if _, err := verifier.Verify(raw, expected); !errors.Is(err, ErrNativeReceipt) {
				t.Fatalf("binding accepted: %v", err)
			}
		})
	}
}

func TestNativeReceiptRejectsAuthenticatedInvalidFacts(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier, _ := NewNativeReceiptVerifier("receipt-key", public)
	for _, tc := range []struct{ name, old, new string }{
		{"duplicate", `"schema_version":1`, `"schema_version":1,"schema_version":1`},
		{"unknown", `"schema_version":1`, `"schema_version":1,"extra":true`},
		{"missing", `"schema_version":1,`, ``},
		{"null", `"source_row_count":7`, `"source_row_count":null`},
		{"overflow", `"source_row_count":7`, `"source_row_count":9223372036854775808`},
		{"cut overflow", `"source_journal_cut":42`, `"source_journal_cut":9223372036854775808`},
		{"stats mismatch", `"target_row_count":7`, `"target_row_count":8`},
		{"checksum mismatch", `"target_checksum":"a`, `"target_checksum":"b`},
		{"completion before capture", `1700000001000`, `1699999999999`},
		{"completion future", `1700000001000`, `9223372036854775807`},
		{"duplicate placement", `["GRU","VCP"]`, `["GRU","GRU"]`},
		{"invalid placement", `["GRU","VCP"]`, `["GRU","bad/region"]`},
		{"zero epoch", `"restore_epoch":8`, `"restore_epoch":0`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := strings.Replace(nativeReceiptTestPayload, tc.old, tc.new, 1)
			raw := nativeTestEnvelope(t, private, payload, "terrascale/native-recovery-receipt/v1\x00")
			if _, err := verifier.Verify(raw, nativeReceiptExpected()); !errors.Is(err, ErrNativeReceipt) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

func TestNativeReceiptRejectsEnvelopeAndSignatureTampering(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier, _ := NewNativeReceiptVerifier("receipt-key", public)
	raw := nativeTestEnvelope(t, private, nativeReceiptTestPayload, "terrascale/native-recovery-receipt/v1\x00")
	var envelope map[string]string
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]string){
		func(e map[string]string) { e["key_id"] = "another-key" },
		func(e map[string]string) { e["signature_base64"] = base64.StdEncoding.EncodeToString(make([]byte, 64)) },
		func(e map[string]string) {
			e["payload_base64"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(nativeReceiptTestPayload, `"restore_epoch":8`, `"restore_epoch":9`, 1)))
		},
		func(e map[string]string) { e["payload_base64"] += "\n" },
		func(e map[string]string) { delete(e, "signature_base64") },
		func(e map[string]string) { e["extra"] = "yes" },
	} {
		var changed map[string]string
		if err := json.Unmarshal(raw, &changed); err != nil {
			t.Fatal(err)
		}
		change(changed)
		wire, _ := json.Marshal(changed)
		if _, err := verifier.Verify(wire, nativeReceiptExpected()); !errors.Is(err, ErrNativeReceipt) {
			t.Fatal("tampered envelope accepted")
		}
	}
	wrongDomain := nativeTestEnvelope(t, private, nativeReceiptTestPayload, "terrascale/native-recovery-receipt/v1")
	if _, err := verifier.Verify(wrongDomain, nativeReceiptExpected()); err == nil {
		t.Fatal("missing NUL domain accepted")
	}
	if _, err := verifier.Verify([]byte(strings.Repeat(" ", 16<<10+1)), nativeReceiptExpected()); err == nil {
		t.Fatal("oversized envelope accepted")
	}
}
