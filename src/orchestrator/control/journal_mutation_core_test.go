package control

import (
	"strings"
	"testing"

	journalcore "terrascale.tech/orchestrator/src/orchestrator/journal"
)

func TestJournalMutationCoreCompatibilityFacade(t *testing.T) {
	proof := NatsOperationJournalMutationAuthorityProof{
		Cell: "gru", CallerIdentity: "controller-a", Action: "create",
		Key: "operation." + strings.Repeat("a", 64), Lease: "lease", Nonce: "nonce",
		Signature: "signature",
	}
	if got, want := NatsOperationJournalMutationRequestDigestCreate(proof),
		journalcore.NatsOperationJournalMutationRequestDigestCreate(proof); got != want {
		t.Fatalf("facade digest = %q, want %q", got, want)
	}
	if !natsOperationJournalIsValid(proof.Key, "value") {
		t.Fatal("facade rejected a valid mutation")
	}
	if natsOperationJournalIsValid(proof.Key, string([]byte{0xff})) {
		t.Fatal("facade accepted invalid UTF-8")
	}
	if nonce := randomNatsNonce(); len(nonce) != 32 {
		t.Fatalf("nonce length = %d, want 32", len(nonce))
	}
}
