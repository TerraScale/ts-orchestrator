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
			`","process":{"pid":1234,"start_nonce":"` + "000000000000c41e716df070e27a2bf2" +
			`"},"scope":{"cluster_id":"` + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
			`","tenant_id":"01HW000000E008000000000001","database_id":"01HW000000E008000000000002","shard_id":1,"member_id":"01HW000000E008000000000003","incarnation":"` + "cccccccccccccccccccccccccccccccc" +
			`"},"authority":{"epoch":7,"configuration_id":"` + strings.Repeat("d", 64) +
			`","certificate_sha256":"` + strings.Repeat("e", 64) +
			`","tls_leaf_sha256":"` + strings.Repeat("f", 64) +
			`"},"serving":true,"listeners":{"client":true,"replication":true},"object":{"root_sha256":"` + strings.Repeat("5", 64) +
			`","target_sha256":"` + strings.Repeat("6", 64) +
			`","native_commit_seq_at_recovery":30,"inbox_archive_sha256_at_recovery":"` + strings.Repeat("8", 64) +
			`","local_source_sequence":12,"remote_inbox_durable_sequence":9,"remote_applied_sequence":9},"replication":{"local_source_sequence":12,"peer_member_id":"01HW000000E008000000000004","peer_incarnation":"` + "33333333333333333333333333333333" +
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
		{"only the peer received prefix", `"peer_received_sequence":12,"peer_durable_sequence":12,"peer_applied_sequence":12,"local_inbox_durable_sequence":9,"local_inbox_applied_sequence":9`, false},
		{"only the inbox received prefix", `"peer_durable_sequence":12,"peer_applied_sequence":12,"local_inbox_received_sequence":9,"local_inbox_durable_sequence":9,"local_inbox_applied_sequence":9`, false},
	} {
		proof, err := decodeServingProof(proofJSON(tc.replication))
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		err = VerifyReportedServing(proof, identity, survivor)
		if tc.serving && err != nil || !tc.serving && err != ErrNotServing {
			t.Fatalf("%s: serving verification = %v", tc.name, err)
		}
	}
	for name, replication := range map[string]string{
		"unknown replication field": `"peer_durable_sequence":12,"peer_applied_sequence":12,"local_inbox_durable_sequence":9,"local_inbox_applied_sequence":9,"peer_forwarded_sequence":12`,
		"null received prefixes":    `"peer_received_sequence":null,"peer_durable_sequence":12,"peer_applied_sequence":12,"local_inbox_received_sequence":null,"local_inbox_durable_sequence":9,"local_inbox_applied_sequence":9`,
	} {
		if _, err := decodeServingProof(proofJSON(replication)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
