package memberstatus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testIdentity() Identity {
	return Identity{
		Process: Process{PID: 1234, StartNonce: strings.Repeat("a", 32)},
		Scope: Scope{
			ClusterID: strings.Repeat("b", 32), TenantID: "018f0000-0000-7000-8000-000000000001",
			DatabaseID: "018f0000-0000-7000-8000-000000000002", ShardID: 1,
			MemberID: "018f0000-0000-7000-8000-000000000003", Incarnation: strings.Repeat("c", 32),
		},
		Authority: Authority{
			Epoch: 7, ConfigurationID: strings.Repeat("d", 64),
			CertificateSHA256: strings.Repeat("e", 64), TLSLeafSHA256: strings.Repeat("f", 64),
		},
	}
}

func testRecord() DrainRecord {
	identity := testIdentity()
	return DrainRecord{
		Request: DrainRequest{
			SchemaVersion: 1, OperationID: strings.Repeat("1", 32), Nonce: strings.Repeat("2", 32), Expected: identity,
		},
		Survivor:       Survivor{MemberID: "018f0000-0000-7000-8000-000000000004", Incarnation: strings.Repeat("3", 32)},
		SourceSequence: 12,
	}
}

func testReceiptJSON() string {
	return `{"schema_version":1,"operation_id":"` + strings.Repeat("1", 32) +
		`","request_nonce":"` + strings.Repeat("2", 32) +
		`","requested_process":{"pid":1234,"start_nonce":"` + strings.Repeat("a", 32) +
		`"},"drained_process":{"pid":2345,"start_nonce":"` + strings.Repeat("4", 32) +
		`"},"scope":{"cluster_id":"` + strings.Repeat("b", 32) +
		`","tenant_id":"018f0000-0000-7000-8000-000000000001","database_id":"018f0000-0000-7000-8000-000000000002","shard_id":1,"member_id":"018f0000-0000-7000-8000-000000000003","incarnation":"` + strings.Repeat("c", 32) +
		`"},"authority":{"epoch":7,"configuration_id":"` + strings.Repeat("d", 64) +
		`","certificate_sha256":"` + strings.Repeat("e", 64) +
		`","tls_leaf_sha256":"` + strings.Repeat("f", 64) +
		`"},"local_source_origin":{"member_id":"018f0000-0000-7000-8000-000000000003","incarnation":"` + strings.Repeat("c", 32) +
		`"},"local_source_durable_sequence":12,"archived_source_sequence":12,"object_root_sha256":"` + strings.Repeat("5", 64) +
		`","peer":{"origin":{"member_id":"018f0000-0000-7000-8000-000000000004","incarnation":"` + strings.Repeat("3", 32) +
		`"},"durable_sequence":12,"applied_sequence":12,"local_inbox_durable_sequence":9,"local_inbox_applied_sequence":9},"replication_quiesced":true}`
}

func testEnvelope(receipt, digest string) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":1,"nonce":"%s","process":{"pid":2345,"start_nonce":"%s"},"operation_id":"%s","state":"complete","receipt_sha256":"%s","receipt":%s}`,
		strings.Repeat("6", 32), strings.Repeat("4", 32), strings.Repeat("1", 32), digest, receipt))
}

func TestDrainReceiptBindsOriginalRequestAndCurrentResponder(t *testing.T) {
	record := testRecord()
	receipt := testReceiptJSON()
	sum := sha256.Sum256([]byte(receipt))
	status := Status{Process: Process{PID: 2345, StartNonce: strings.Repeat("4", 32)}}
	envelope, err := validateDrainEnvelope(testEnvelope(receipt, hex.EncodeToString(sum[:])), http.StatusOK,
		strings.Repeat("6", 32), status, record)
	if err != nil || envelope.Receipt == nil || envelope.Receipt.RequestedProcess != record.Request.Expected.Process {
		t.Fatalf("valid restarted drain receipt: %+v, %v", envelope, err)
	}
	if _, err := validateDrainEnvelope(testEnvelope(receipt, strings.Repeat("0", 64)), http.StatusOK,
		strings.Repeat("6", 32), status, record); err == nil {
		t.Fatal("accepted altered receipt digest")
	}
	foreign := strings.Replace(receipt, `"applied_sequence":12`, `"applied_sequence":11`, 1)
	foreignSum := sha256.Sum256([]byte(foreign))
	if _, err := validateDrainEnvelope(testEnvelope(foreign, hex.EncodeToString(foreignSum[:])), http.StatusOK,
		strings.Repeat("6", 32), status, record); err == nil {
		t.Fatal("accepted survivor below the requested source frontier")
	}
	advanced := strings.Replace(receipt, `"local_source_durable_sequence":12,"archived_source_sequence":12`,
		`"local_source_durable_sequence":15,"archived_source_sequence":15`, 1)
	advanced = strings.Replace(advanced, `"durable_sequence":12,"applied_sequence":12`,
		`"durable_sequence":15,"applied_sequence":15`, 1)
	advancedSum := sha256.Sum256([]byte(advanced))
	advancedEnvelope, err := validateDrainEnvelope(testEnvelope(advanced, hex.EncodeToString(advancedSum[:])),
		http.StatusOK, strings.Repeat("6", 32), status, record)
	if err != nil {
		t.Fatalf("final source frontier above pre-drain proof was rejected: %v", err)
	}
	if err := VerifyReportedDrain(advancedEnvelope, record.Request.OperationID, record.Request.Expected,
		record.Survivor, record.SourceSequence); err != nil {
		t.Fatalf("published final receipt was rejected: %v", err)
	}
	if err := VerifyReportedDrain(advancedEnvelope, record.Request.OperationID, record.Request.Expected,
		record.Survivor, 16); err == nil {
		t.Fatal("accepted final receipt below required source frontier")
	}
}

func TestFileStoreRetainsExactDrainIntent(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "member-drain.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	record := testRecord()
	if err := store.Create(record); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := reopened.Load()
	if err != nil || !found || got != record {
		t.Fatalf("durable intent = %+v, found %v, err %v", got, found, err)
	}
	if err := reopened.Create(record); err != nil {
		t.Fatalf("exact replay rejected: %v", err)
	}
	changed := record
	changed.Request.Nonce = strings.Repeat("9", 32)
	if err := reopened.Create(changed); err != ErrOperationConflict {
		t.Fatalf("changed nonce error = %v", err)
	}
}

func TestRequiredFieldsRejectMissingFalseAndDuplicate(t *testing.T) {
	var status Status
	if err := decodeRequired([]byte(`{"schema_version":2,"schema_version":2}`), &status, "schema_version"); err == nil {
		t.Fatal("duplicate JSON member accepted")
	}
	if err := decodeRequired([]byte(`{"schema_version":2}`), &status, "receiver_only"); err == nil {
		t.Fatal("missing false field accepted")
	}
}
