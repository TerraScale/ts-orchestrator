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
