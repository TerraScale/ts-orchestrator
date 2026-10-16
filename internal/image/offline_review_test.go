package image

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

func TestImageBuildRejectsUnpinnedNetBirdBeforeGuestEffects(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	artifact := make([]byte, 64)
	copy(artifact, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(artifact[16:], 3)
	binary.LittleEndian.PutUint16(artifact[18:], 183)
	binary.LittleEndian.PutUint32(artifact[20:], 1)
	binary.LittleEndian.PutUint16(artifact[52:], 64)
	path := filepath.Join(t.TempDir(), "netbird")
	if err := os.WriteFile(path, artifact, 0755); err != nil {
		t.Fatal(err)
	}
	digest, err := client.SHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	options := OfflineOptions{
		Base: "base", KernelRelease: "6.8.0", Binary: "binary", Qualification: "qualification",
		SourceRevision: strings.Repeat("a", 40), NativeVerifier: "verifier", NativeSHA256: strings.Repeat("a", 64),
		NetBirdBinary: path, NetBirdSHA256: digest, ReleaseTool: "release", Timesyncd: "timesync",
		Out: "image", KernelOut: "kernel", BootstrapRoots: []string{"root"},
	}
	if err := OfflineBuild(t.Context(), repo, options, io.Discard); err == nil || !strings.Contains(err.Error(), "supplied NetBird SHA-256 differs from the image pin") {
		t.Fatalf("independently supplied binary/digest reached image tools: %v", err)
	}
	if err := GuestBuild(t.Context(), repo, GuestBuildOptions{NetBirdBinary: path}, io.Discard); err == nil || !strings.Contains(err.Error(), "NetBird binary bytes differ from the pinned SHA-256") {
		t.Fatalf("guest build accepted bytes outside its baked fallback pin: %v", err)
	}
}
