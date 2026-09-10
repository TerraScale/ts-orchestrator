//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
)

// The inherited executable is a measured local fixture for all three roles.
// It is never launched as a guest component or represented as a product build.
func commandMaterialArtifacts(t *testing.T) (string, []vmimage.GuestArtifact) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := elf.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var architecture vmimage.Architecture
	switch file.Machine {
	case elf.EM_X86_64:
		architecture = vmimage.AMD64
	case elf.EM_AARCH64:
		architecture = vmimage.ARM64
	default:
		t.Fatalf("unsupported fixture ELF architecture: %v", file.Machine)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	var artifacts []vmimage.GuestArtifact
	for _, component := range []string{"ts-node", "orchestrator", "terrabase"} {
		artifacts = append(artifacts, vmimage.GuestArtifact{
			Component: component, Architecture: architecture, Version: "local-command-fixture",
			Source: "https://releases.terrascale.tech/releases/" + component + "/local-command-fixture/" + component,
			SHA256: hex.EncodeToString(digest[:]), Size: int64(len(data)), Mode: 0755,
		})
	}
	t.Logf("measured inherited fixture: architecture=%s bytes=%d sha256=%s", architecture, len(data), hex.EncodeToString(digest[:]))
	return executable, artifacts
}

func TestLocalQualificationMaterialCommandRoundTrip(t *testing.T) {
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(t.TempDir(), "vm-qualify-material")
	build := exec.CommandContext(t.Context(), "go", "build", "-p=1", "-tags=sandboxvm", "-o", command, "./cmd/vm-qualify-material")
	build.Dir = repo
	build.Env = append(os.Environ(), "GOMAXPROCS=2")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build real material command: %v\n%s", err, output)
	}
	executable, artifacts := commandMaterialArtifacts(t)
	intent := localPublicMaterialIntent(t, artifacts)
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, input []byte) (string, []byte, error) {
		t.Helper()
		private := t.TempDir()
		inputPath := filepath.Join(private, "intent.json")
		if err := os.WriteFile(inputPath, input, 0600); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(private, "material")
		cmd := exec.CommandContext(t.Context(), command, "-out", root, "-input", inputPath,
			"-ts-node", executable, "-orchestrator", executable, "-terrabase", executable)
		output, err := cmd.CombinedOutput()
		return root, output, err
	}
	t.Run("public_intent_signed_loader", func(t *testing.T) {
		root, output, err := run(t, raw)
		if err != nil {
			t.Fatalf("real command rejected public intent: %v\n%s", err, output)
		}
		plan, err := vmnet.Plan(intent.NetworkConfig)
		if err != nil {
			t.Fatal(err)
		}
		admission, err := loadLocalMaterial(t, root, LocalQualificationMaterialInput{
			Network: plan, Architecture: intent.Architecture, Artifacts: artifacts,
		})
		if err != nil {
			t.Fatalf("private signed loader rejected command output: %v", err)
		}
		defer admission.Clear()
		if len(admission.memberships) != 6 || len(admission.authorityReaders) != 6 || len(admission.candidatePlan.Candidates) != 2 {
			t.Fatal("command output omitted expected launch-host or candidate inventory")
		}
		retained, err := retainQualificationRunIdentity(filepath.Join(root, "state"), intent.NetworkConfig)
		if err != nil || retained.NetworkRunID != plan.RunID || retained.StackRunID == "" {
			t.Fatalf("command retained run identity cannot reopen: %+v, %v", retained, err)
		}
		issuer, err := vmqualbootstrap.NewPersistentIssuer(filepath.Join(root, "state", "qualification-admission-"+plan.RunID), plan.RunID)
		if err != nil {
			t.Fatal(err)
		}
		defer issuer.Close()
		grant, err := issuer.Grant("gru-member-1", admission.candidatePlan.Candidates[0].Manifest)
		if err != nil || !bytes.Equal(grant.PublicKeyPEM, admission.ownerPublic) {
			t.Fatalf("command signing owner did not survive reopen: %v", err)
		}
		t.Log("real command -> public constructor -> material generator -> private signed loader verified; retained signing owner reopened")
	})
	for _, field := range []string{"controlPayload", "unknownIntent"} {
		t.Run("reject_"+field, func(t *testing.T) {
			var extended map[string]jsontext.Value
			if err := json.Unmarshal(raw, &extended); err != nil {
				t.Fatal(err)
			}
			extended[field] = jsontext.Value(`{}`)
			invalid, err := json.Marshal(extended)
			if err != nil {
				t.Fatal(err)
			}
			root, output, err := run(t, invalid)
			if err == nil || !strings.Contains(string(output), "unknown") || !strings.Contains(string(output), field) {
				t.Fatalf("strict command envelope did not reject %s: %v, %s", field, err, output)
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatalf("rejected %s created output: %v", field, err)
			}
		})
	}
}
