package ci_test

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	imagecli "git.terrascale.tech/TerraScale/ts-orchestrator/internal/image"
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
		// The image job starts with the checks and waits for them to pass.
		steps := matches(ci, `(?m)^      - name: (.+)$`)
		if len(steps) < 2 || steps[1] != "Start the image build for this revision" {
			t.Fatalf("second step: %v", steps)
		}
		_, dispatchStep, _ := strings.Cut(ci, "- name: Start the image build for this revision")
		dispatchStep, _, _ = strings.Cut(dispatchStep, "- name:")
		requireText(t, dispatchStep, "run: bash scripts/ci/dispatch-image.sh")
		requireText(t, dispatchStep, "continue-on-error: true")
		requireText(t, workflowText(t, "scripts/ci/dispatch-image.sh"), `source_ci_run_id:$run_id, source_ci_run_number:$run_number, trigger:"ci"`)
		requireText(t, image, "inputs.trigger == 'ci'")
		requireText(t, image, "  cancel-in-progress: false\n")
		requireText(t, image, `bash scripts/ci/image-superseded.sh "${SOURCE_SHA}" "${SOURCE_CI_RUN_ID}" "${SOURCE_CI_RUN_NUMBER}" 6000`)
		if tools, gate := strings.Index(image, "deploy/image/tools.sh true"), strings.Index(image, "scripts/ci/image-superseded.sh"); tools < 0 || tools > gate {
			t.Error("image tools are not prepared before the CI gate")
		}
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
		if got := matches(dispatch, `(?m)^      ([a-z_]+):$`); !reflect.DeepEqual(got, []string{"source_revision", "source_ci_run_id", "source_ci_run_number", "trigger"}) {
			t.Fatalf("inputs: %v", got)
		}
	})
	t.Run("image_inputs", func(t *testing.T) {
		root := script.Root(t)
		var stdout, stderr bytes.Buffer
		if code := imagecli.Run(t.Context(), root, []string{"inputs", "check"}, &stdout, &stderr); code != 0 {
			t.Fatal(stderr.String())
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

func TestImageGateWaitsForDispatchingRun(t *testing.T) {
	t.Run("zero-budget-is-invalid", func(t *testing.T) {
		result := script.Run(t, script.Root(t), nil, "bash", "scripts/ci/image-superseded.sh", strings.Repeat("a", 40), "42", "7", "0")
		if result.Code != 2 || !strings.Contains(result.Stderr, "usage:") {
			t.Fatalf("zero budget: %+v", result)
		}
	})
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		mode, status, output string
		code                 int
	}{
		{"normal", "success", "skip=false\n", 0},
		{"transient", "success", "skip=false\n", 0},
		{"null", "success", "skip=false\n", 0},
		{"malformed", "success", "skip=false\n", 0},
		{"supersession-transient", "success", "skip=false\n", 0},
		{"newer", "success", "skip=true\n", 0},
		{"normal", "failure", "skip=true\n", 0},
		{"normal", "cancelled", "skip=true\n", 0},
		{"normal", "blocked", "", 1},
		{"normal", "skipped", "", 1},
		{"wrong-id", "success", "", 1},
		{"persistent", "success", "", 1},
	} {
		t.Run(test.mode+"/"+test.status, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			script.Write(t, filepath.Join(bin, "curl"), script.Read(t, filepath.Join(script.Root(t), "tests/ci/testdata/image-gate/curl")), 0o755)
			script.Write(t, filepath.Join(bin, "sleep"), []byte("#!/usr/bin/env bash\nif [[ $MOCK_MODE == wrong-id || $MOCK_MODE == persistent ]]; then exec \"$MOCK_REAL_SLEEP\" \"$@\"; fi\n"), 0o755)
			output := filepath.Join(root, "output")
			script.Write(t, output, nil, 0o600)
			token := filepath.Join(root, "token")
			script.Write(t, token, []byte("fixture-token"), 0o600)
			budget := "10"
			if test.mode == "wrong-id" || test.mode == "persistent" {
				budget = "1"
			}
			env := map[string]string{
				"PATH":      bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"MOCK_ROOT": root, "MOCK_MODE": test.mode, "MOCK_STATUS": test.status, "MOCK_REAL_SLEEP": sleepPath,
				"MOCK_SOURCE": strings.Repeat("a", 40), "FORGEJO_READ_TOKEN_FILE": token,
				"FORGEJO_SERVER_URL": "https://forgejo.invalid", "GITHUB_OUTPUT": output,
			}
			result := script.Run(t, script.Root(t), env, "bash", "scripts/ci/image-superseded.sh", env["MOCK_SOURCE"], "42", "7", budget)
			if result.Code != test.code || string(script.Read(t, output)) != test.output {
				t.Fatalf("exit=%d output=%q stdout=%s stderr=%s", result.Code, script.Read(t, output), result.Stdout, result.Stderr)
			}
			if test.code == 1 && !strings.Contains(result.Stderr, "dispatch image.yml manually") {
				t.Fatal("missing visible repair: " + result.Stderr)
			}
			if !strings.Contains(string(script.Read(t, filepath.Join(root, "requests"))), "run_number=7") {
				t.Fatal("dispatching run number was not requested")
			}
		})
	}
}

func TestImageDispatchPinsRun(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	script.Write(t, filepath.Join(bin, "curl"), script.Read(t, filepath.Join(script.Root(t), "tests/ci/testdata/image-gate/curl")), 0o755)
	env := map[string]string{
		"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH"), "MOCK_ROOT": root,
		"FORGEJO_TOKEN": "fixture-token", "FORGEJO_SERVER_URL": "https://forgejo.invalid",
		"GITHUB_SHA": strings.Repeat("a", 40), "GITHUB_RUN_ID": "42", "GITHUB_RUN_NUMBER": "7", "GITHUB_REF": "refs/heads/main",
	}
	result := script.Run(t, script.Root(t), env, "bash", "scripts/ci/dispatch-image.sh")
	if result.Code != 0 {
		t.Fatalf("dispatch: %s %s", result.Stdout, result.Stderr)
	}
	var payload struct {
		Ref    string            `json:"ref"`
		Inputs map[string]string `json:"inputs"`
	}
	if err := json.Unmarshal(script.Read(t, filepath.Join(root, "payload")), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Ref != "main" || payload.Inputs["source_revision"] != env["GITHUB_SHA"] || payload.Inputs["source_ci_run_id"] != "42" || payload.Inputs["source_ci_run_number"] != "7" || payload.Inputs["trigger"] != "ci" {
		t.Fatalf("dispatch payload: %+v", payload)
	}
}
