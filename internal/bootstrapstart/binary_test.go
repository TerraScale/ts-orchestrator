package bootstrapstart

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/release"
)

func TestRunningBinaryPinsInstalledExecutable(t *testing.T) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	receipt := release.ImageReceipt{
		BinaryBytes: info.Size(), BinarySHA256: hex.EncodeToString(hash.Sum(nil)), Architecture: runtime.GOARCH,
	}
	measured, err := verifyBinaryFile("/proc/self/exe", receipt)
	if err != nil || measured.SHA256 != receipt.BinarySHA256 {
		t.Fatalf("exact installed binary: %+v, %v", measured, err)
	}
	receipt.BinarySHA256 = strings.Repeat("0", 64)
	if _, err := verifyBinaryFile("/proc/self/exe", receipt); !errors.Is(err, ErrRunningBinaryMismatch) {
		t.Fatalf("changed digest = %v, want binary mismatch", err)
	}
	receipt.Architecture = "different"
	if _, err := verifyBinaryFile("/proc/self/exe", receipt); !errors.Is(err, ErrRunningBinaryMismatch) {
		t.Fatalf("changed architecture = %v, want binary mismatch", err)
	}
}
