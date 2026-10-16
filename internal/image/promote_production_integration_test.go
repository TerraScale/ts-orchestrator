package image

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
)

// The external verifier rejects the proof through its real process boundary;
// neither a new promotion nor a completed-import resume may reach OCI afterward.
func TestPromotionRejectsProductionProofBeforeOCI(t *testing.T) {
	for _, resume := range []bool{false, true} {
		t.Run(fmt.Sprintf("resume=%t", resume), func(t *testing.T) {
			root := t.TempDir()
			input, assets, tools := filepath.Join(root, "input"), filepath.Join(root, "assets"), filepath.Join(root, "tools")
			for _, directory := range []string{input, assets, tools} {
				if err := os.Mkdir(directory, 0755); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path, content string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(content), mode); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(tools, "gh"), `#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --pattern) asset=$2; shift 2 ;;
    --output) destination=$2; shift 2 ;;
    *) shift ;;
  esac
done
exec cp "$PROMOTION_ASSETS/$asset" "$destination"
`, 0755)
			write(filepath.Join(tools, "virt-cat"), "#!/bin/sh\nprintf 'fixture virt-cat\\n'\n", 0755)
			verifier := filepath.Join(tools, "release-tool")
			write(verifier, `#!/bin/sh
printf '%s\n' "$*" >> "$PROMOTION_COMMAND_LOG"
case "$1 $2" in
  'release verify-binary') exit 0 ;;
  'release verify-image-production') printf 'independent final-image proof rejected\n' >&2; exit 42 ;;
  *) exit 43 ;;
esac
`, 0755)
			commandLog := filepath.Join(root, "commands")
			t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("PROMOTION_ASSETS", assets)
			t.Setenv("PROMOTION_COMMAND_LOG", commandLog)
			write(filepath.Join(assets, "qualification.json"), "{}", 0644)
			write(filepath.Join(assets, "terrascale-orchestrator-linux-arm64"), "binary", 0644)
			write(filepath.Join(assets, "base-image.qcow2"), "base", 0644)
			write(filepath.Join(input, "terrascale-gru-arm64.qcow2"), "final image with pinned runtime", 0644)
			write(filepath.Join(input, "guest-kernel"), "kernel", 0644)
			digest := func(path string) string {
				t.Helper()
				value, err := fileHash(path)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			manifest := imageManifest{Schema: "terrascale.image.qualification.v2", SourceRevision: strings.Repeat("a", 40), SourceTree: strings.Repeat("b", 40)}
			manifest.Inputs.Manifest.Region = "GRU"
			manifest.Inputs.Manifest.Base.ChecksumName = "noble-server-cloudimg-arm64.img"
			manifest.Inputs.Manifest.Base.ReleaseTag = "pinned-base"
			manifest.Inputs.Manifest.Base.Assets.Base.SHA256 = digest(filepath.Join(assets, "base-image.qcow2"))
			manifest.Candidate.Tag = "ci-" + manifest.SourceRevision + "-run-1"
			manifest.Candidate.QualificationSHA256 = digest(filepath.Join(assets, "qualification.json"))
			manifest.Candidate.BinarySHA256 = digest(filepath.Join(assets, "terrascale-orchestrator-linux-arm64"))
			manifest.Image.SHA256 = digest(filepath.Join(input, "terrascale-gru-arm64.qcow2"))
			manifest.Kernel.SHA256 = digest(filepath.Join(input, "guest-kernel"))
			wire, err := canonical(manifest)
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(input, "image-qualification.json"), string(wire), 0644)
			var sums strings.Builder
			for _, name := range []string{"terrascale-gru-arm64.qcow2", "guest-kernel", "image-qualification.json"} {
				fmt.Fprintf(&sums, "%s  %s\n", digest(filepath.Join(input, name)), name)
			}
			write(filepath.Join(input, "SHA256SUMS"), sums.String(), 0644)
			out := filepath.Join(root, "promotion")
			if resume {
				if err := os.Mkdir(out, 0755); err != nil {
					t.Fatal(err)
				}
				state, err := canonical(promotionState{Schema: promotionStateV1, ImageDir: input, ImageSHA256: manifest.Image.SHA256})
				if err != nil {
					t.Fatal(err)
				}
				write(filepath.Join(out, promotionStateFile), string(state), 0644)
				imported, err := canonical(map[string]any{"schema": "terrascale.oci.image-import.v1", "image_id": "ocid1.image.fixture",
					"qcow2_sha256": manifest.Image.SHA256, "compartment_id": "compartment", "object": "namespace/bucket/image.qcow2", "display_name": "fixture"})
				if err != nil {
					t.Fatal(err)
				}
				write(filepath.Join(out, "oci-import.json"), string(imported), 0644)
			}
			trust := filepath.Join(root, "trust")
			write(trust, "fixture trust", 0644)
			providerCalls := 0
			err = Promote(t.Context(), root, PromotionOptions{ImageDir: input, Out: out, Environment: "canary",
				Delegation: trust, RootKey: trust, BinaryReceipt: trust, ReleaseTool: verifier, Resume: resume,
				CompartmentID: "compartment", Namespace: "namespace", Bucket: "bucket", DisplayName: "fixture",
				ProductionEvidenceDir: filepath.Join(root, "independent-proof"),
				Importer: func(string) (imageimport.Importer, error) {
					providerCalls++
					return imageimport.Importer{}, fmt.Errorf("OCI must not be reached")
				}}, new(bytes.Buffer))
			if err == nil || !strings.Contains(err.Error(), "final image production qualification") || providerCalls != 0 {
				t.Fatalf("proof rejection must precede OCI: err=%v providerCalls=%d", err, providerCalls)
			}
			commands, err := os.ReadFile(commandLog)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(commands), "release verify-image-production --image-file "+filepath.Join(out, "image", "terrascale-gru-arm64.qcow2")) {
				t.Fatalf("final image bytes were not sent to the independent verifier: %s", commands)
			}
		})
	}
}
