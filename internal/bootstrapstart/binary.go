package bootstrapstart

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

var ErrRunningBinaryMismatch = errors.New("running orchestrator binary differs from signed image receipt")

// RunningBinary is measured from the executable inode of this process.
type RunningBinary struct {
	SHA256       string
	Bytes        int64
	Architecture string
}

func VerifyCurrentRunningBinary(image release.VerifiedImage) (RunningBinary, error) {
	if !image.IsVerified() {
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	return verifyBinaryFile("/proc/self/exe", image.Receipt())
}

// Historical release proof is usable only for exact restart identity checks;
// its result is never an authorization to fetch new secrets or mutate cloud.
func VerifyHistoricalRunningBinary(image release.HistoricalImage) (RunningBinary, error) {
	if !image.IsVerified() {
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	return verifyBinaryFile("/proc/self/exe", image.Receipt())
}

// verifySelfUpdatedBinary accepts the executable at path when it is the
// current release of the root-owned self-update layout, that release is not
// known bad on this node, and a binary-update receipt names it for the
// expected environment, cell and architecture. Restart admission tries it
// only when the executable is not the image receipt binary.
//
// The receipt is checked historically, like the image receipt: Stage
// accepted it as current before root kept a byte, so an expired delegation
// never stops a staged release from restarting. Revocation is the known-bad
// list a rollback writes.
func verifySelfUpdatedBinary(path string, layout selfupdate.Layout, roots trust.Keyring,
	expected release.UpdateExpectation,
) (RunningBinary, error) {
	current, err := layout.Current()
	if err != nil {
		return RunningBinary{}, fmt.Errorf("%w: self-update current release: %w", ErrRunningBinaryMismatch, err)
	}
	if current == "" {
		return RunningBinary{}, fmt.Errorf("%w: no self-update current release", ErrRunningBinaryMismatch)
	}
	knownBad, err := layout.KnownBad()
	if err != nil {
		return RunningBinary{}, fmt.Errorf("%w: self-update known-bad releases: %w", ErrRunningBinaryMismatch, err)
	}
	if knownBad[current] {
		return RunningBinary{}, fmt.Errorf("%w: %w", ErrRunningBinaryMismatch, selfupdate.ErrKnownBad)
	}
	receiptWire, delegationWire, err := layout.ReleaseReceipt(current)
	if err != nil {
		return RunningBinary{}, fmt.Errorf("%w: self-update current release: %w", ErrRunningBinaryMismatch, err)
	}
	verified, err := release.VerifyBinaryUpdateHistorical(receiptWire, delegationWire, roots, expected)
	if err != nil {
		return RunningBinary{}, fmt.Errorf("%w: self-update binary update receipt: %w", ErrRunningBinaryMismatch, err)
	}
	receipt := verified.Receipt()
	if receipt.SHA256 != current {
		return RunningBinary{}, fmt.Errorf("%w: binary update receipt names another release", ErrRunningBinaryMismatch)
	}
	return verifyBinaryFile(path, release.ImageReceipt{BinaryBytes: receipt.Bytes, BinarySHA256: receipt.SHA256,
		Architecture: receipt.GOARCH})
}

func verifyBinaryFile(path string, receipt release.ImageReceipt) (RunningBinary, error) {
	file, err := os.Open(path)
	if err != nil {
		return RunningBinary{}, fmt.Errorf("open running binary: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > release.MaxArtifactBytes ||
		info.Size() != receipt.BinaryBytes {
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	parsed, err := elf.NewFile(file)
	if err != nil || parsed.Class != elf.ELFCLASS64 || parsed.Data != elf.ELFDATA2LSB {
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	architecture := ""
	switch parsed.Machine {
	case elf.EM_X86_64:
		architecture = "amd64"
	case elf.EM_AARCH64:
		architecture = "arm64"
	default:
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	if architecture != receipt.Architecture {
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	hash := sha256.New()
	read := io.NewSectionReader(file, 0, info.Size())
	count, err := io.Copy(hash, read)
	if err != nil || count != info.Size() {
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if digest != receipt.BinarySHA256 {
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	return RunningBinary{SHA256: digest, Bytes: count, Architecture: architecture}, nil
}
