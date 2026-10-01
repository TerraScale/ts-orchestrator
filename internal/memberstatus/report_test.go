package memberstatus

import (
	"strings"
	"testing"
)

func TestServingProofReceivedPrefixesAreOrderedWhenPresent(t *testing.T) {
	identity := testIdentity()
	survivor := testRecord().Survivor
	proofJSON := func(replication string) []byte {
		return []byte(`{"schema_version":1,"nonce":"` + strings.Repeat("7", 32) +
			`","process":{"pid":1234,"start_nonce":"` + strings.Repeat("a", 32) +
			`"},"scope":{"cluster_id":"` + strings.Repeat("b", 32) +
			`","tenant_id":"018f0000-0000-7000-8000-000000000001","database_id":"018f0000-0000-7000-8000-000000000002","shard_id":1,"member_id":"018f0000-0000-7000-8000-000000000003","incarnation":"` + strings.Repeat("c", 32) +
			`"},"authority":{"epoch":7,"configuration_id":"` + strings.Repeat("d", 64) +
			`","certificate_sha256":"` + strings.Repeat("e", 64) +
			`","tls_leaf_sha256":"` + strings.Repeat("f", 64) +
			`"},"serving":true,"listeners":{"client":true,"replication":true},"object":{"root_sha256":"` + strings.Repeat("5", 64) +
			`","target_sha256":"` + strings.Repeat("6", 64) +
			`","native_commit_seq_at_recovery":30,"inbox_archive_sha256_at_recovery":"` + strings.Repeat("8", 64) +
			`","local_source_sequence":12,"remote_inbox_durable_sequence":9,"remote_applied_sequence":9},"replication":{"local_source_sequence":12,"peer_member_id":"018f0000-0000-7000-8000-000000000004","peer_incarnation":"` + strings.Repeat("3", 32) +
			`","current_authenticated":true,` + replication + `}}`)
	}
	for _, tc := range []struct {
		name, replication string
		serving           bool
	}{
		{"received prefixes", `"peer_received_sequence":12,"peer_durable_sequence":12,"peer_applied_sequence":12,"local_inbox_received_sequence":10,"local_inbox_durable_sequence":9,"local_inbox_applied_sequence":9`, true},
		{"release without received prefixes", `"peer_durable_sequence":12,"peer_applied_sequence":12,"local_inbox_durable_sequence":9,"local_inbox_applied_sequence":9`, true},
		{"peer received behind durable", `"peer_received_sequence":11,"peer_durable_sequence":12,"peer_applied_sequence":12,"local_inbox_received_sequence":9,"local_inbox_durable_sequence":9,"local_inbox_applied_sequence":9`, false},
		{"inbox received behind durable", `"peer_received_sequence":12,"peer_durable_sequence":12,"peer_applied_sequence":12,"local_inbox_received_sequence":8,"local_inbox_durable_sequence":9,"local_inbox_applied_sequence":9`, false},
	} {
		var proof ServingProof
		if err := decodeRequired(proofJSON(tc.replication), &proof, servingPaths...); err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		err := VerifyReportedServing(proof, identity, survivor)
		if tc.serving && err != nil || !tc.serving && err != ErrNotServing {
			t.Fatalf("%s: serving verification = %v", tc.name, err)
		}
	}
	var proof ServingProof
	if err := decodeRequired(proofJSON(`"peer_durable_sequence":12,"peer_applied_sequence":12,"local_inbox_durable_sequence":9,"local_inbox_applied_sequence":9,"peer_forwarded_sequence":12`), &proof, servingPaths...); err == nil {
		t.Fatal("unknown replication field accepted")
	}
}
