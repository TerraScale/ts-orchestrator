package messaging

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/nkeys"
)

// MessagingGroupAny and MessagingOtherAny are the group/other permission masks
// used by every owner-private file check.
const (
	MessagingGroupAny = 0o070
	MessagingOtherAny = 0o007
)

// MessagingUnixFileMode returns the Unix permission bits for the Linux-only
// NATS credential paths. A non-Linux platform fails closed.
func MessagingUnixFileMode(path string) (uint32, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	return messagingUnixMode(info), nil
}

// messagingRejectSymlinkPath rejects symlinks in every path component. NATS
// credentials are private identity material, so following a link here would
// make the identity depend on mutable filesystem state outside the configured
// path.
func messagingRejectSymlinkPath(path string) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	remainder := strings.TrimPrefix(clean, volume)
	if remainder == "" {
		return nil
	}
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(remainder, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("path contains a symbolic link")
		}
	}
	return nil
}

// messagingUnixMode returns the permission bits of info (as
// os.FileMode.Perm()).
func messagingUnixMode(info os.FileInfo) uint32 { return uint32(info.Mode().Perm()) }

// NatsCredentialFile resolves a bounded, owner-private NKey seed file plus
// the public-key helpers derived from the seed.
var NatsCredentialFile natsCredentialFile

type natsCredentialFile struct{}

// Resolve returns the absolute path of a bounded existing owner-private NKey
// seed file whose first non-blank line is a valid NKey seed.
func (natsCredentialFile) Resolve(value string, optionName string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}

	path, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("%s must identify a bounded existing NKey seed file.", optionName)
	}
	if err := messagingRejectSymlinkPath(path); err != nil {
		return "", fmt.Errorf("%s must not contain symbolic links.", optionName)
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() < 1 || info.Size() > 4096 {
		return "", fmt.Errorf("%s must identify a bounded existing NKey seed file.", optionName)
	}

	mode, err := MessagingUnixFileMode(path)
	if err != nil {
		return "", fmt.Errorf("%s must be private to the current user.", optionName)
	}

	if mode&(MessagingGroupAny|MessagingOtherAny) != 0 {
		return "", fmt.Errorf("%s must be private to the current user.", optionName)
	}

	if _, err := nkeysPublicKeyFromSeedFile(path); err != nil {
		return "", fmt.Errorf("%s does not contain a valid NKey seed.", optionName)
	}

	return path, nil
}

// SameIdentity reports whether two seed files encode the same NKey identity.
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

// PublicKey returns the public key encoded by the seed file.
func (natsCredentialFile) PublicKey(path string) (string, error) {
	return nkeysPublicKeyFromSeedFile(path)
}

// nkeysPublicKeyFromSeedFile reads the first non-blank line of the file and
// returns the public key encoded by that NKey seed.
func nkeysPublicKeyFromSeedFile(path string) (string, error) {
	seed, err := NkeySeed(path)
	if err != nil {
		return "", err
	}

	pair, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return "", err
	}

	return pair.PublicKey()
}

// NkeySeed returns the first non-whitespace line of the file.
func NkeySeed(path string) (string, error) {
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
