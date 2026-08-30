// Port of src/TerraScale.Orchestrator/Messaging/NatsCredentialFile.cs.
package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/nkeys"
)

// messagingGroupAny and messagingOtherAny mirror the C#
// UnixFileMode.Group*/Other* masks used by every owner-private file check in
// the Messaging area.
const (
	messagingGroupAny = 0o070
	messagingOtherAny = 0o007
)

// messagingUnixFileMode mirrors File.GetUnixFileMode for the Linux-only NATS
// credential paths. A non-Linux platform fails closed (the C# threw
// PlatformNotSupportedException).
func messagingUnixFileMode(path string) (uint32, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	return messagingUnixMode(info), nil
}

// messagingUnixMode mirrors the C# File.GetUnixFileMode (permission bits
// only, as os.FileMode.Perm()).
func messagingUnixMode(info os.FileInfo) uint32 { return uint32(info.Mode().Perm()) }

// NatsCredentialFile mirrors the C# static class: resolution of a bounded,
// owner-private NKey seed file plus the public-key helpers derived from the
// seed.
var NatsCredentialFile natsCredentialFile

type natsCredentialFile struct{}

// Resolve mirrors NatsCredentialFile.Resolve: it returns the absolute path of a
// bounded existing owner-private NKey seed file whose first non-blank line is a
// valid NKey seed.
func (natsCredentialFile) Resolve(value string, optionName string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}

	path, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("%s must identify a bounded existing NKey seed file.", optionName)
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() < 1 || info.Size() > 4096 {
		return "", fmt.Errorf("%s must identify a bounded existing NKey seed file.", optionName)
	}

	mode, err := messagingUnixFileMode(path)
	if err != nil {
		return "", fmt.Errorf("%s must be private to the current user.", optionName)
	}

	if mode&(messagingGroupAny|messagingOtherAny) != 0 {
		return "", fmt.Errorf("%s must be private to the current user.", optionName)
	}

	if _, err := nkeysPublicKeyFromSeedFile(path); err != nil {
		return "", fmt.Errorf("%s does not contain a valid NKey seed.", optionName)
	}

	return path, nil
}

// SameIdentity mirrors NatsCredentialFile.SameIdentity.
func (natsCredentialFile) SameIdentity(first, second string) (bool, error) {
	firstKey, err := nkeysPublicKeyFromSeedFile(first)
	if err != nil {
		return false, err
	}

	secondKey, err := nkeysPublicKeyFromSeedFile(second)
	if err != nil {
		return false, err
	}

	return firstKey == secondKey, nil
}

// PublicKey mirrors NatsCredentialFile.PublicKey.
func (natsCredentialFile) PublicKey(path string) (string, error) {
	return nkeysPublicKeyFromSeedFile(path)
}

// nkeysPublicKeyFromSeedFile reads the first non-blank line of the file and
// returns the public key encoded by that NKey seed.
func nkeysPublicKeyFromSeedFile(path string) (string, error) {
	seed, err := nkeySeed(path)
	if err != nil {
		return "", err
	}

	pair, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return "", err
	}

	return pair.PublicKey()
}

// nkeySeed mirrors the private Seed helper: the first non-whitespace line.
func nkeySeed(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("NKey seed file is empty.")
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			return strings.TrimSpace(line), nil
		}
	}

	return "", errors.New("NKey seed file is empty.")
}
