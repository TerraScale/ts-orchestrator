package natscell

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// ObserveIdentityRekeyInstallation measures an existing store against a node ID
// independently read from its serving process. Ordinary admission requires pins.
func ObserveIdentityRekeyInstallation(cfg Config, observedRaftNodeID string) (InstallationIdentity, error) {
	if cfg.Embedded == nil || !validNodeID(observedRaftNodeID) {
		return InstallationIdentity{}, ErrStoreIdentity
	}
	if err := cfg.validate(); err != nil {
		return InstallationIdentity{}, err
	}
	dir, err := openInstallationDirectory(cfg.Embedded.StoreDir, false)
	if err != nil {
		return InstallationIdentity{}, err
	}
	defer unix.Close(dir)
	return observeIdentityRekeyInstallation(cfg, dir, observedRaftNodeID)
}

func observeIdentityRekeyInstallation(cfg Config, dir int, observedRaftNodeID string) (InstallationIdentity, error) {
	wire, err := readInstallationFileAt(dir, nodeIdentityFile, 4096)
	if errors.Is(err, os.ErrNotExist) {
		wire, err = json.Marshal(nodeIdentity{Version: 1, Cell: cfg.Cell, Instance: cfg.Instance, NodeID: observedRaftNodeID})
	}
	if err != nil {
		return InstallationIdentity{}, err
	}
	identity, err := observeInstallationIdentity(cfg, dir, wire)
	if err != nil {
		return InstallationIdentity{}, err
	}
	if identity.RaftNodeID != observedRaftNodeID {
		return InstallationIdentity{}, ErrStoreIdentity
	}
	return identity, nil
}

// PinIdentityRekeyInstallation only publishes the missing node pin. The root
// installer must verify its durable checkpoint and stopped service first.
func PinIdentityRekeyInstallation(cfg Config, expected InstallationIdentity, serviceUID, serviceGID uint32) error {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return ErrStoreIdentity
	}
	return pinIdentityRekeyInstallation(cfg, expected, serviceUID, serviceGID)
}

func pinIdentityRekeyInstallation(cfg Config, expected InstallationIdentity, serviceUID, serviceGID uint32) error {
	if cfg.Embedded == nil || serviceUID == 0 || serviceGID == 0 || !validNodeID(expected.RaftNodeID) {
		return ErrStoreIdentity
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	dir, err := openInstallationDirectory(cfg.Embedded.StoreDir, false)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	observed, err := observeIdentityRekeyInstallation(cfg, dir, expected.RaftNodeID)
	if err != nil {
		return err
	}
	if observed != expected {
		return ErrStoreIdentity
	}
	file, recorded, err := openInstallationFileAt(dir, nodeIdentityFile, 4096)
	if err == nil {
		defer file.Close()
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &stat); err != nil || stat.Uid != serviceUID || stat.Gid != serviceGID {
			return ErrStoreIdentity
		}
		if installationDigest(recorded) != expected.NodeIdentitySHA256 {
			return ErrStoreIdentity
		}
		return unix.Fsync(dir)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	wire, err := json.Marshal(nodeIdentity{Version: 1, Cell: cfg.Cell, Instance: cfg.Instance, NodeID: expected.RaftNodeID})
	if err != nil {
		return err
	}
	if installationDigest(wire) != expected.NodeIdentitySHA256 {
		return ErrStoreIdentity
	}
	file, err = publishInstallationPinOwned(dir, nodeIdentityFile, wire, serviceUID, serviceGID)
	if err != nil {
		return err
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil || stat.Uid != serviceUID || stat.Gid != serviceGID {
		return ErrStoreIdentity
	}
	current, err := readInstallationDescriptor(dir, file, 4096)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, wire) {
		return ErrStoreIdentity
	}
	actual, err := observeInstalledIdentity(cfg, dir)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrStoreIdentity
	}
	return unix.Fsync(dir)
}
