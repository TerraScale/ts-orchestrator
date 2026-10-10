package bootstrapstart

import (
	"bytes"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const initialExportName = "initial-accepted-export.json"

func (store MarkerStore) readInitialExport() (AcceptedIdentity, error) {
	dir, err := store.openDirectory()
	if err != nil {
		return AcceptedIdentity{}, err
	}
	defer unix.Close(dir)
	wire, err := store.readIdentityBytes(dir, initialExportName)
	if err != nil {
		return AcceptedIdentity{}, err
	}
	return DecodeAcceptedIdentity(wire)
}

func (store MarkerStore) stageInitialExport(accepted AcceptedIdentity, observe IdentityObservation) error {
	err := store.publishIdentityAt(accepted, "", observe, initialExportName)
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	prior, err := store.readInitialExport()
	if err != nil {
		return err
	}
	return sameInitialExport(prior, accepted)
}

func sameInitialExport(left, right AcceptedIdentity) error {
	a, err := EncodeAcceptedIdentity(left)
	if err != nil {
		return err
	}
	b, err := EncodeAcceptedIdentity(right)
	if err != nil || !bytes.Equal(a, b) {
		return ErrAcceptedIdentity
	}
	return nil
}

func (store MarkerStore) clearInitialExport() error {
	dir, err := store.openDirectory()
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if err := unix.Unlinkat(dir, initialExportName, 0); err != nil {
		return err
	}
	return unix.Fsync(dir)
}
