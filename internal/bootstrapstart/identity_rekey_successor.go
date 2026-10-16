package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
)

// PrepareIdentityRekeySuccessor retains completed acceptance evidence before a
// different current-root proposal occupies the staging journal. The caller holds
// the release lock; no shared record or accepted identity is changed.
func (store MarkerStore) PrepareIdentityRekeySuccessor(ctx context.Context, proposal IdentityRekeyJournal, js jetstream.JetStream, now time.Time) error {
	return store.prepareIdentityRekeySuccessor(ctx, proposal, js, now, bakedStore{
		directory: BakedDirectory, chainFile: RootChainFile, ownerUID: 0, ownerGID: 0,
	})
}

func (store MarkerStore) prepareIdentityRekeySuccessor(ctx context.Context, proposal IdentityRekeyJournal, js jetstream.JetStream, now time.Time, baked bakedStore) error {
	if uint32(os.Geteuid()) != store.ownerUID || store.ownerUID == 0 && os.Getegid() != 0 {
		return ErrIdentityRekeyJournal
	}
	verified, _, err := verifyIdentityRekeyInstall(store, baked, proposal, now, false)
	if err != nil {
		return err
	}
	if existing, err := store.readIdentityRekeyJournal(); err == nil {
		wire, err := encodeIdentityRekeyJournal(existing)
		if err != nil {
			return err
		}
		if bytes.Equal(wire, verified.Wire()) {
			return ctx.Err()
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	accepted, err := store.ReadIdentity()
	if err != nil {
		// The first cutover's opaque predecessor is not a successor acceptance.
		if existing, readErr := store.readIdentityRekeyJournal(); errors.Is(readErr, os.ErrNotExist) {
			return nil
		} else if readErr == nil && bytes.Equal(existing.AcceptedWire, proposal.AcceptedWire) {
			return nil
		}
		return err
	}
	if accepted.Origin != identityrekey.AcceptanceOriginRekey {
		return nil
	}
	wire, err := EncodeAcceptedIdentity(accepted)
	if err != nil || digest(wire) != proposal.PreviousAcceptanceSHA256 {
		return errors.Join(ErrAcceptancePredecessor, err)
	}
	target, err := DecodeAcceptedIdentity(proposal.AcceptedWire)
	if err != nil || target.OperationID == accepted.OperationID {
		return errors.Join(ErrIdentityRekeyJournal, err)
	}
	inputs, err := baked.loadTrustInputs(accepted)
	if err != nil {
		return err
	}
	if err := store.verifyIdentityRekeyCompletion(ctx, accepted, inputs, js); err != nil {
		return err
	}
	retained, err := store.verifiedIdentityRekey(accepted, inputs)
	if err != nil {
		return err
	}
	dir, err := store.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	actual, err := store.readIdentityBytes(dir, markerName)
	if err != nil || !bytes.Equal(actual, wire) {
		return errors.Join(ErrAcceptancePredecessor, err)
	}
	existing, err := store.readIdentityRekeyJournal()
	if errors.Is(err, os.ErrNotExist) {
		return nil // Exact archived acceptance was independently verified above.
	}
	if err != nil {
		return err
	}
	existingWire, err := encodeIdentityRekeyJournal(existing)
	if err != nil || !bytes.Equal(existingWire, retained.Wire()) {
		return ErrIdentityRekeyJournal
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, _, err := verifyIdentityRekeyInstall(store, baked, proposal, time.Now().Round(0).UTC(), false); err != nil {
		return err
	}
	if err := unix.Renameat2(dir, identityRekeyJournalName, dir, identityRekeyAcceptedJournalName(wire), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return unix.Fsync(dir)
}
