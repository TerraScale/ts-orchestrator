package ci_test

import (
	"encoding/json/v2"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func workflowText(t *testing.T, path string) string {
	t.Helper()
	return string(script.Read(t, filepath.Join(script.Root(t), path)))
}

func requireText(t *testing.T, text, fragment string) {
	t.Helper()
	if !strings.Contains(text, fragment) {
		t.Errorf("missing %q", fragment)
	}
}

func forbidText(t *testing.T, text, fragment string) {
	t.Helper()
	if strings.Contains(text, fragment) {
		t.Errorf("unexpected %q", fragment)
	}
}

func matches(text, pattern string) []string {
	var result []string
	for _, match := range regexp.MustCompile(pattern).FindAllStringSubmatch(text, -1) {
		result = append(result, match[1])
	}
	return result
}

func TestWorkflowContracts(t *testing.T) {
	ci := workflowText(t, ".forgejo/workflows/ci.yml")
	image := workflowText(t, ".forgejo/workflows/image.yml")
	t.Run("docs_skip_and_ci_dispatches_images", func(t *testing.T) {
		_, rest, ok := strings.Cut(ci, "    paths-ignore:\n")
		if !ok {
			t.Fatal("missing paths-ignore")
		}
		var patterns []string
		for line := range strings.SplitSeq(rest, "\n") {
			match := regexp.MustCompile(`^      - '([^']+)'$`).FindStringSubmatch(line)
			if match == nil {
				break
			}
			patterns = append(patterns, match[1])
		}
		if !reflect.DeepEqual(patterns, []string{"docs/**", "**/*.md"}) {
			t.Fatalf("paths-ignore: %v", patterns)
		}
		forbidText(t, image, "  push:")
		steps := matches(ci, `(?m)^      - name: (.+)$`)
		if len(steps) == 0 || steps[len(steps)-1] != "Start the image build for this revision" {
			t.Fatalf("last step: %v", steps)
		}
		_, last, _ := strings.CutLast(ci, "- name:")
		requireText(t, last, "run: bash scripts/ci/dispatch-image.sh")
		requireText(t, last, "continue-on-error: true")
		requireText(t, workflowText(t, "scripts/ci/dispatch-image.sh"), `trigger:"ci"`)
		requireText(t, image, "inputs.trigger == 'ci'")
		requireText(t, image, "  cancel-in-progress: false\n")
		requireText(t, image, "bash scripts/ci/image-superseded.sh")
	})
	t.Run("release_admission_job", func(t *testing.T) {
		const name = "verify/go + artifact/linux-amd64-arm64"
		if got := matches(ci, `(?m)^    name: (.+)$`); !reflect.DeepEqual(got, []string{name}) {
			t.Fatalf("jobs: %v", got)
		}
		for _, path := range []string{"scripts/ci/publish-qualification.sh", "deploy/image/build-image.sh"} {
			requireText(t, workflowText(t, path), name)
		}
	})
	t.Run("image_provenance_job", func(t *testing.T) {
		const name = "build/qualified-gru-arm64-image"
		if got := matches(image, `(?m)^    name: (.+)$`); !reflect.DeepEqual(got, []string{name}) {
			t.Fatalf("jobs: %v", got)
		}
		requireText(t, workflowText(t, "deploy/image/build-image.sh"), "image_job='"+name+"'")
	})
	t.Run("image_waits_for_ci", func(t *testing.T) {
		requireText(t, image, "--wait-for-ci")
		_, dispatch, ok := strings.Cut(image, "workflow_dispatch:")
		if !ok {
			t.Fatal("missing workflow dispatch")
		}
		dispatch, _, _ = strings.Cut(dispatch, "concurrency:")
		if got := matches(dispatch, `(?m)^      ([a-z_]+):$`); !reflect.DeepEqual(got, []string{"source_revision", "trigger"}) {
			t.Fatalf("inputs: %v", got)
		}
	})
	t.Run("image_inputs", func(t *testing.T) {
		root := script.Root(t)
		r := script.Run(t, root, nil, "python3", filepath.Join(root, "deploy/image/image-inputs.py"), "check")
		if r.Code != 0 {
			t.Fatal(r.Stderr)
		}
		var manifest struct {
			TrustRoots []struct {
				SHA256 string `json:"sha256"`
			} `json:"trust_roots"`
		}
		if err := json.Unmarshal(script.Read(t, filepath.Join(root, "deploy/image/image-inputs.json")), &manifest); err != nil {
			t.Fatal(err)
		}
		if len(manifest.TrustRoots) == 0 || manifest.TrustRoots[0].SHA256 != "bbdab8425dac0382d641cdf9de7c5a6685f0355a63f6b1131c64241873d418bc" {
			t.Fatal("trust root digest changed")
		}
	})
}
