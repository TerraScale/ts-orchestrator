package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// ReceiptPolicy verifies a release receipt for this node. Per-source
// receipts use the existing root-delegated release path. Update receipts
// signed automatically under a scoped binary update delegation use the same
// mandatory scope and current-root verification.
type ReceiptPolicy struct {
	Roots        trust.Keyring
	Environment  string
	Cell         string
	Architecture string
}

// Verify returns the verified binary receipt for receiptWire.
func (policy ReceiptPolicy) Verify(receiptWire, delegationWire []byte, now time.Time) (release.VerifiedBinary, error) {
	if len(policy.Roots) == 0 {
		return release.VerifiedBinary{}, fmt.Errorf("%w: no release trust roots", ErrInvalid)
	}
	envelope, err := trust.DecodeEnvelope(receiptWire)
	if err != nil {
		return release.VerifiedBinary{}, err
	}
	var verified release.VerifiedBinary
	switch envelope.Scope.Domain {
	case release.BinaryDomain:
		verified, err = release.VerifyBinaryCurrent(receiptWire, delegationWire, policy.Roots,
			release.BinaryExpectation{Environment: policy.Environment}, now)
	case release.UpdateReceiptDomain:
		verified, err = release.VerifyBinaryUpdateCurrent(receiptWire, delegationWire, policy.Roots,
			release.UpdateExpectation{Environment: policy.Environment, Cell: policy.Cell, Architecture: policy.Architecture}, now)
	default:
		return release.VerifiedBinary{}, fmt.Errorf("%w: receipt domain %q", ErrInvalid, envelope.Scope.Domain)
	}
	if err != nil {
		return release.VerifiedBinary{}, err
	}
	if !verified.IsVerified() || verified.Receipt().GOARCH != policy.Architecture {
		return release.VerifiedBinary{}, fmt.Errorf("%w: receipt architecture differs from this node", release.ErrExpectationMismatch)
	}
	return verified, nil
}

// Verifier is the receipt check Stage applies before any byte is kept.
type Verifier interface {
	Verify(receiptWire, delegationWire []byte, now time.Time) (release.VerifiedBinary, error)
}

// Stage verifies the receipt, copies the binary from source while hashing
// it, requires the exact signed size and digest, and installs it read-only
// under releases/<sha256>. It is idempotent for an already staged release.
// The caller holds Layout.Lock.
func Stage(layout Layout, source io.Reader, receiptWire, delegationWire []byte, verifier Verifier, now time.Time) (string, error) {
	if source == nil || verifier == nil {
		return "", fmt.Errorf("%w: stage source and verifier are required", ErrInvalid)
	}
	verified, err := verifier.Verify(receiptWire, delegationWire, now)
	if err != nil {
		return "", fmt.Errorf("verify release receipt: %w", err)
	}
	receipt := verified.Receipt()
	if knownBad, err := layout.KnownBad(); err != nil {
		return "", err
	} else if knownBad[receipt.SHA256] {
		return "", ErrKnownBad
	}
	if err := layout.ensureDirs(); err != nil {
		return "", err
	}
	if _, err := os.Lstat(layout.ReleaseDir(receipt.SHA256)); err == nil {
		if err := layout.VerifyRelease(receipt.SHA256); err != nil {
			return "", err
		}
		return receipt.SHA256, nil
	}
	if err := layout.install(source, receipt.SHA256, receipt.Bytes, map[string][]byte{
		receiptFile: receiptWire, delegationFile: delegationWire,
	}); err != nil {
		return "", err
	}
	return receipt.SHA256, nil
}

// ReleaseReceipt returns the signed receipt and delegation a staged release
// was verified with, once the release's ownership and bytes verify. The
// baked release has neither, so it fails.
func (layout Layout) ReleaseReceipt(digest string) (receiptWire, delegationWire []byte, err error) {
	if err := layout.VerifyRelease(digest); err != nil {
		return nil, nil, err
	}
	wires := make([][]byte, 2)
	for index, name := range []string{receiptFile, delegationFile} {
		path := filepath.Join(layout.ReleaseDir(digest), name)
		if err := layout.checkOwned(path, false); err != nil {
			return nil, nil, err
		}
		if wires[index], err = readBounded(path, trust.MaxEnvelopeBytes); err != nil {
			return nil, nil, err
		}
	}
	return wires[0], wires[1], nil
}

// Seed installs the image-baked binary as a release and points current at
// it when no current link exists. The baked binary is trusted as part of
// the signed image; it carries a marker instead of a receipt.
func Seed(layout Layout, bakedBinary string) (string, error) {
	if err := layout.ensureDirs(); err != nil {
		return "", err
	}
	current, err := layout.Current()
	if err != nil || current != "" {
		return current, err
	}
	file, err := os.Open(bakedBinary)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxBinaryBytes {
		return "", fmt.Errorf("%w: baked binary", ErrInvalid)
	}
	digest, _, err := hashFile(bakedBinary)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(layout.ReleaseDir(digest)); errors.Is(err, os.ErrNotExist) {
		if err := layout.install(file, digest, info.Size(), map[string][]byte{bakedMarkerFile: []byte(bakedBinary + "\n")}); err != nil {
			return "", err
		}
	}
	if err := layout.VerifyRelease(digest); err != nil {
		return "", err
	}
	return digest, layout.flipCurrent(digest)
}

// install writes the binary and metadata into a temporary directory and
// renames it into place, so a release directory is never partially present.
func (layout Layout) install(source io.Reader, digest string, size int64, metadata map[string][]byte) error {
	if !digestRE.MatchString(digest) || size <= 0 || size > MaxBinaryBytes {
		return fmt.Errorf("%w: release identity", ErrInvalid)
	}
	temporary, err := os.MkdirTemp(layout.releasesPath(), ".staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o755); err != nil {
		return err
	}
	binary, err := os.OpenFile(filepath.Join(temporary, BinaryName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o500)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(binary, hash), io.LimitReader(source, size+1))
	if copyErr == nil {
		copyErr = binary.Chmod(0o555)
	}
	if copyErr == nil {
		copyErr = binary.Sync()
	}
	if closeErr := binary.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return copyErr
	}
	if written != size || hex.EncodeToString(hash.Sum(nil)) != digest {
		return fmt.Errorf("%w: staged binary differs from its signed size or digest", ErrInvalid)
	}
	for name, data := range metadata {
		if err := writeSyncedFile(filepath.Join(temporary, name), data, 0o444); err != nil {
			return err
		}
	}
	if err := syncDir(temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, layout.ReleaseDir(digest)); err != nil {
		return err
	}
	if err := syncDir(layout.releasesPath()); err != nil {
		return err
	}
	return layout.VerifyRelease(digest)
}

// writeSyncedFile creates path with data and syncs it before the caller
// syncs and renames the directory, so a crash never keeps a release whose
// metadata files are empty or truncated.
func writeSyncedFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}
