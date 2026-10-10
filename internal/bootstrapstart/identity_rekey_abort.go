package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"os"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
)

// ReadStagedIdentityRekeyEvidence verifies expired proofs only at their exact
// accepted time. It grants no current mutation or predecessor replacement.
func ReadStagedIdentityRekeyEvidence(expectedSHA256 string) (IdentityRekeyJournal, VerifiedIdentityRekey, error) {
	return NewMarkerStore().stagedIdentityRekeyEvidence(expectedSHA256, bakedStore{
		directory: BakedDirectory, chainFile: RootChainFile, ownerUID: 0, ownerGID: 0,
	})
}

func (store MarkerStore) stagedIdentityRekeyEvidence(expectedSHA256 string, baked bakedStore) (IdentityRekeyJournal, VerifiedIdentityRekey, error) {
	if !markerDigestRE.MatchString(expectedSHA256) {
		return IdentityRekeyJournal{}, VerifiedIdentityRekey{}, ErrIdentityRekeyJournal
	}
	journal, err := store.readIdentityRekeyJournal()
	if err != nil {
		return journal, VerifiedIdentityRekey{}, err
	}
	wire, err := encodeIdentityRekeyJournal(journal)
	if err != nil || digest(wire) != expectedSHA256 {
		return journal, VerifiedIdentityRekey{}, ErrIdentityRekeyJournal
	}
	accepted, err := DecodeAcceptedIdentity(journal.AcceptedWire)
	if err != nil {
		return journal, VerifiedIdentityRekey{}, err
	}
	inputs, err := baked.loadTrustInputs(accepted)
	if err != nil {
		return journal, VerifiedIdentityRekey{}, err
	}
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, true)
	return journal, verified, err
}

// AbortIdentityRekeyJournal archives a permanently fenced, unaffected attempt.
// The caller holds the release lock and observes the original live invocation.
func (store MarkerStore) AbortIdentityRekeyJournal(ctx context.Context, expectedSHA256 string,
	js jetstream.JetStream, observe IdentityObservation,
) error {
	return store.abortIdentityRekeyJournal(ctx, expectedSHA256, js, observe, bakedStore{
		directory: BakedDirectory, chainFile: RootChainFile, ownerUID: 0, ownerGID: 0,
	})
}

func (store MarkerStore) abortIdentityRekeyJournal(ctx context.Context, expectedSHA256 string, js jetstream.JetStream, observe IdentityObservation, baked bakedStore) error {
	if uint32(os.Geteuid()) != store.ownerUID || store.ownerUID == 0 && os.Getegid() != 0 {
		return ErrIdentityRekeyJournal
	}
	journal, verified, err := store.stagedIdentityRekeyEvidence(expectedSHA256, baked)
	if err != nil {
		return err
	}
	envelope, err := verified.ResetEnvelope()
	if err != nil {
		return err
	}
	if err := authority.VerifyIdentityResetUncommittable(ctx, js, envelope, verified.AcceptedRoots(),
		verified.ResetTarget(), verified.Accepted().AcceptedAt); err != nil {
		return err
	}
	if err := VerifyIdentityRekeyStagingLocalIdentity(verified, observe); err != nil {
		return err
	}
	dir, err := store.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	previous, err := store.readIdentityBytes(dir, markerName)
	if err != nil || digest(previous) != journal.PreviousAcceptanceSHA256 {
		return errors.Join(ErrAcceptancePredecessor, err)
	}
	current, err := store.readIdentityRekeyJournal()
	if err != nil {
		return err
	}
	wire, err := encodeIdentityRekeyJournal(current)
	if err != nil || digest(wire) != expectedSHA256 {
		return ErrIdentityRekeyJournal
	}
	if err := VerifyIdentityRekeyStagingLocalIdentity(verified, observe); err != nil {
		return err
	}
	previous, err = store.readIdentityBytes(dir, markerName)
	if err != nil || digest(previous) != journal.PreviousAcceptanceSHA256 || bytes.Equal(previous, journal.AcceptedWire) {
		return errors.Join(ErrAcceptancePredecessor, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	archive := "identity-rekey.aborted." + expectedSHA256 + ".json"
	if err := unix.Renameat2(dir, identityRekeyJournalName, dir, archive, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return unix.Fsync(dir)
}
