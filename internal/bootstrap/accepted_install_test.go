package bootstrap

import (
	"errors"
	"testing"
)

func TestPublishAcceptedInstallIsWriteOnceAndReadable(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := BootstrapScope{DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: "GRU", Slot: "controller-a"}
	marker := []byte(`{"slot":"controller-a"}`)
	if _, err := fixture.ledger.ReadAcceptedInstall(t.Context(), scope); !errors.Is(err, ErrRecordMissing) {
		t.Fatalf("unpublished marker read = %v, want missing", err)
	}
	for range 2 {
		if err := fixture.ledger.PublishAcceptedInstall(t.Context(), scope, marker); err != nil {
			t.Fatalf("publish accepted-install marker: %v", err)
		}
	}
	read, err := fixture.ledger.ReadAcceptedInstall(t.Context(), scope)
	if err != nil || string(read) != string(marker) {
		t.Fatalf("published marker read = %q, %v", read, err)
	}
	if err := fixture.ledger.PublishAcceptedInstall(t.Context(), scope, []byte(`{"slot":"0000000000V4MRM46HP1SNGDYW"}`)); !errors.Is(err, ErrRecordAuthorization) {
		t.Fatalf("a different marker replaced the published one: %v", err)
	}
}
