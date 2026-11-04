package app

import (
	"encoding/json/v2"
	"os"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

func TestBackupStatusReplyExposesCompleteEvidenceOnlyAfterRelease(t *testing.T) {
	data, err := os.ReadFile("../../testdata/backup-complete-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PublishedHead struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"published_head"`
		CompleteRelease struct {
			EnvelopeJSON string `json:"envelope_json"`
		} `json:"complete_release"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	record := authority.BackupOperationRecord{
		DatabaseID: "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8",
		OperationID:        "3QEXVQEXVQEXVQEXVQEXVQEXVQ",
		PublicationReceipt: []byte(fixture.PublishedHead.EnvelopeJSON),
		CompleteRelease:    []byte(fixture.CompleteRelease.EnvelopeJSON),
	}
	for _, state := range []string{"held"} {
		t.Run(state, func(t *testing.T) {
			record.State = state
			reply := backupStatusReplyFor(record, 42)
			if reply.PublicationReceipt != "" || reply.CompleteRelease != "" {
				t.Fatalf("%s status exposed committed publication evidence before release", state)
			}
		})
	}
	for _, state := range []string{"complete"} {
		t.Run(state, func(t *testing.T) {
			record.State = state
			reply := backupStatusReplyFor(record, 42)
			if reply.PublicationReceipt != fixture.PublishedHead.EnvelopeJSON ||
				reply.CompleteRelease != fixture.CompleteRelease.EnvelopeJSON {
				t.Fatalf("%s status did not preserve exact committed proof bytes", state)
			}
		})
	}
}
