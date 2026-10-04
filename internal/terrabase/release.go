package terrabase

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Repository is the source of every TerraBase release.
const Repository = "https://git.terrascale.tech/TerraScale/terrabase"

// Release assets are terrabase-linux-<arch> and terrabase-linux-<arch>.sha256,
// attached to the prerelease ci-<commit>-run-<run> of each main push and to
// the release v<version> of each version tag.
var assetRE = regexp.MustCompile(`^terrabase-linux-(?:amd64|arm64)$`)

// maxBinaryBytes matches the controller's artifact admission limit.
const maxBinaryBytes = 512 << 20

// VerifyRelease checks a downloaded release executable against its
// published .sha256 asset and returns the digest to pin. The checksum file
// must hold exactly one sha256sum line naming the executable's asset.
func VerifyRelease(binaryPath, checksumPath string) (string, error) {
	name := filepath.Base(binaryPath)
	if !assetRE.MatchString(name) {
		return "", fmt.Errorf("release executable %q is not terrabase-linux-amd64 or terrabase-linux-arm64", name)
	}
	checksum, err := os.ReadFile(checksumPath)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(checksum))
	if len(fields) != 2 || bytes.Count(checksum, []byte("\n")) > 1 || strings.TrimPrefix(fields[1], "*") != name ||
		len(fields[0]) != 64 || strings.ToLower(fields[0]) != fields[0] {
		return "", fmt.Errorf("%s is not one sha256sum line for %s", checksumPath, name)
	}
	if _, err := hex.DecodeString(fields[0]); err != nil {
		return "", fmt.Errorf("%s is not one sha256sum line for %s", checksumPath, name)
	}
	file, err := os.Open(binaryPath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(file, magic); err != nil || !bytes.Equal(magic, []byte("\x7fELF")) {
		return "", fmt.Errorf("%s is not an ELF executable", binaryPath)
	}
	hash := sha256.New()
	hash.Write(magic)
	size, err := io.Copy(hash, io.LimitReader(file, maxBinaryBytes))
	if err != nil {
		return "", err
	}
	if size+4 > maxBinaryBytes {
		return "", errors.New("release executable exceeds the artifact admission limit")
	}
	if digest := hex.EncodeToString(hash.Sum(nil)); digest != fields[0] {
		return "", fmt.Errorf("%s has SHA-256 %s, its release checksum says %s", name, digest, fields[0])
	}
	return fields[0], nil
}
