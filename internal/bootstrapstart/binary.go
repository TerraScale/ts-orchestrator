package bootstrapstart

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/identityrekey"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

var ErrRunningBinaryMismatch = errors.New("running orchestrator binary differs from verified release pin")

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

// VerifyAcceptedRunningBinary measures the accepted executable baseline.
func VerifyAcceptedRunningBinary(pin identityrekey.BinaryPin) (RunningBinary, error) {
	return verifyAcceptedBinaryFile("/proc/self/exe", pin)
}

func verifyAcceptedBinaryFile(path string, pin identityrekey.BinaryPin) (RunningBinary, error) {
	return verifyBinaryFile(path, release.ImageReceipt{BinarySHA256: pin.SHA256, BinaryBytes: pin.Size, Architecture: pin.Architecture})
}

// verifySelfUpdatedBinary accepts the executable at path when it is the
// current release of the root-owned self-update layout, that release is not
// known bad on this node, and its receipt names it for the expected scope
// and architecture. Restart admission tries it
// only when the executable differs from the accepted binary baseline.
//
// The receipt is checked historically: Stage accepted it as current before
// root kept a byte, so an expired delegation
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
	envelope, err := trust.DecodeEnvelope(receiptWire)
	if err != nil {
		return RunningBinary{}, errors.Join(ErrRunningBinaryMismatch, err)
	}
	var verified release.HistoricalBinary
	switch envelope.Scope.Domain {
	case release.BinaryDomain:
		verified, err = release.VerifyBinaryHistorical(receiptWire, delegationWire, roots, release.BinaryExpectation{Environment: expected.Environment})
	case release.UpdateReceiptDomain:
		verified, err = release.VerifyBinaryUpdateHistorical(receiptWire, delegationWire, roots, expected)
	default:
		return RunningBinary{}, errors.Join(ErrRunningBinaryMismatch, trust.ErrScopeMismatch)
	}
	if err != nil {
		return RunningBinary{}, fmt.Errorf("%w: self-update binary update receipt: %w", ErrRunningBinaryMismatch, err)
	}
	receipt := verified.Receipt()
	if !verified.IsVerified() || receipt.SHA256 != current || receipt.GOARCH != expected.Architecture {
		return RunningBinary{}, fmt.Errorf("%w: binary update receipt names another release", ErrRunningBinaryMismatch)
	}
	return verifyBinaryFile(path, release.ImageReceipt{BinaryBytes: receipt.Bytes, BinarySHA256: receipt.SHA256,
		Architecture: receipt.GOARCH})
}

// verifyRecoveryPredecessor never authorizes a runtime start or target confirmation.
func verifyRecoveryPredecessor(path string, layout selfupdate.Layout, roots trust.Keyring, accepted AcceptedIdentity) (RunningBinary, error) {
	activation, pending, err := layout.Pending()
	if errors.Is(err, selfupdate.ErrUnreadableActivation) {
		activation, err = layout.RecoveryActivation()
		pending = err == nil
	}
	if err != nil {
		return RunningBinary{}, errors.Join(ErrRunningBinaryMismatch, err)
	}
	if !pending {
		intents, err := layout.PendingRestores()
		if err != nil {
			return RunningBinary{}, errors.Join(ErrRunningBinaryMismatch, err)
		}
		for _, intent := range intents {
			if intent.Unit == selfupdate.ControllerUnit {
				return verifyRecoveryRelease(path, layout, intent.Target, roots, accepted)
			}
		}
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	if activation.Unit != selfupdate.ControllerUnit {
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	current, err := layout.Current()
	if err != nil || current != activation.Target {
		return RunningBinary{}, errors.Join(ErrRunningBinaryMismatch, err)
	}
	bad, err := layout.KnownBad()
	if err != nil || bad[activation.Previous] {
		return RunningBinary{}, errors.Join(ErrRunningBinaryMismatch, err)
	}
	return verifyRecoveryRelease(path, layout, activation.Previous, roots, accepted)
}

func verifyRecoveryRelease(path string, layout selfupdate.Layout, digest string, roots trust.Keyring, accepted AcceptedIdentity) (RunningBinary, error) {
	if err := layout.VerifyRelease(digest); err != nil {
		return RunningBinary{}, err
	}
	if digest == accepted.Binary.SHA256 {
		return verifyAcceptedBinaryFile(path, accepted.Binary)
	}
	receiptWire, delegationWire, err := layout.ReleaseReceipt(digest)
	if err != nil {
		return RunningBinary{}, err
	}
	envelope, err := trust.DecodeEnvelope(receiptWire)
	if err != nil {
		return RunningBinary{}, err
	}
	var verified release.HistoricalBinary
	switch envelope.Scope.Domain {
	case release.BinaryDomain:
		verified, err = release.VerifyBinaryHistorical(receiptWire, delegationWire, roots, release.BinaryExpectation{Environment: accepted.Environment})
	case release.UpdateReceiptDomain:
		verified, err = release.VerifyBinaryUpdateHistorical(receiptWire, delegationWire, roots, release.UpdateExpectation{Environment: accepted.Environment, Cell: accepted.Cell, Architecture: accepted.Binary.Architecture})
	default:
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	if err != nil {
		return RunningBinary{}, err
	}
	receipt := verified.Receipt()
	if !verified.IsVerified() || receipt.SHA256 != digest || receipt.GOARCH != accepted.Binary.Architecture {
		return RunningBinary{}, ErrRunningBinaryMismatch
	}
	return verifyBinaryFile(path, release.ImageReceipt{BinaryBytes: receipt.Bytes, BinarySHA256: receipt.SHA256, Architecture: receipt.GOARCH})
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
