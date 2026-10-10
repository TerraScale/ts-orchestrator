package oci

import (
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"testing"
)

// VolumeBackupProviderForTest lets external tests exercise the SDK and runner together.
func VolumeBackupProviderForTest(config RegionConfig, dispatcher common.HTTPRequestDispatcher, journal *KVJournal) VolumeBackupProvider {
	base := common.BaseClient{Host: "https://sdk.test.invalid", BasePath: "20160918",
		UserAgent: "oci-backup-test", Signer: observeSDKSigner{}, HTTPClient: dispatcher}
	return &sdkProvider{config: config, storage: core.BlockstorageClient{BaseClient: base}, terminations: journal}
}

func VolumeBackupJournalForTest(t *testing.T) *KVJournal {
	t.Helper()
	journal, err := NewKVJournal(testJournalBucket(t))
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func ReopenVolumeBackupJournalForTest(t *testing.T, journal *KVJournal) *KVJournal {
	t.Helper()
	reopened, err := NewKVJournal(journal.kv)
	if err != nil {
		t.Fatal(err)
	}
	return reopened
}
