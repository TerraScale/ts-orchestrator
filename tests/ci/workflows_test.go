package ci_test

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	imagecli "github.com/TerraScale/ts-orchestrator/internal/image"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
)

func workflowText(t *testing.T, path string) string {
	t.Helper()
	return string(script.Read(t, filepath.Join(script.Root(t), path)))
}

// runCI runs a CI script from the repository root. The scripts these tests
// run read no repository file outside scripts/ci (their fakes come from
// each test's temporary directory), so only that tree is tracked.
func runCI(t *testing.T, env map[string]string, name string, args ...string) script.Result {
	t.Helper()
	script.Track(t, "scripts/ci")
	return script.Exec(t, script.Root(t), env, name, args...)
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
	ci := workflowText(t, ".github/workflows/ci.yml")
	image := workflowText(t, ".github/workflows/image.yml")
	t.Run("every_main_change_dispatches_delivery", func(t *testing.T) {
		forbidText(t, ci, "paths-ignore:")
		forbidText(t, ci, "TS_AUTO_DEPLOY_")
		forbidText(t, image, "  push:")
		// The image job starts once the release is retained, so it never
		// holds a builder slot while the checks run.
		steps := matches(ci, `(?m)^      - name: (.+)$`)
		if len(steps) < 4 || steps[len(steps)-1] != "Start the fleet deployment for this revision" ||
			steps[len(steps)-2] != "Start the image build for this revision" ||
			steps[len(steps)-3] != "Record the qualified main build for the deployment-lag guard" ||
			steps[len(steps)-4] != "Retain verified binaries and qualification manifest" {
			t.Fatalf("image and deploy dispatches must follow the retained release: %v", steps)
		}
		_, dispatchStep, _ := strings.Cut(ci, "- name: Start the image build for this revision")
		dispatchStep, _, _ = strings.Cut(dispatchStep, "- name:")
		requireText(t, dispatchStep, "run: bash scripts/ci/dispatch-image.sh\n")
		requireText(t, dispatchStep, "continue-on-error: true")
		_, deployStep, _ := strings.Cut(ci, "- name: Start the fleet deployment for this revision")
		requireText(t, deployStep, "run: bash scripts/ci/dispatch-image.sh deploy.yml\n")
		forbidText(t, deployStep, "continue-on-error:")
		requireText(t, deployStep, "if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}")
		// The weekly run rebuilds the image but never redeploys.
		requireText(t, ci, "  schedule:\n    - cron: ")
		requireText(t, workflowText(t, "scripts/ci/dispatch-image.sh"), `-f "inputs[source_ci_run_id]=$GITHUB_RUN_ID" -f "inputs[source_ci_run_number]=$GITHUB_RUN_NUMBER"`)
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
		// The gate waits for the dispatching run once; the build does not poll again.
		forbidText(t, image, "--wait-for-ci")
		steps := matches(image, `(?m)^      - name: (.+)$`)
		gate := slices.Index(steps, "Wait for ci.yml and skip a failed or overtaken revision")
		qualify := slices.Index(steps, "Qualify the revision against real infrastructure")
		build := slices.Index(steps, "Build the image from the qualified candidate")
		if gate < 0 || qualify != gate+1 || build != qualify+1 {
			t.Fatalf("qualification must run between the CI gate and the build: %v", steps)
		}
		_, qualifyStep, _ := strings.Cut(image, "- name: Qualify the revision against real infrastructure")
		qualifyStep, _, _ = strings.Cut(qualifyStep, "- name:")
		requireText(t, qualifyStep, "if: ${{ steps.gate.outputs.skip != 'true' }}")
		forbidText(t, qualifyStep, "vars.TS_QUALIFICATION_SUITES")
		requireText(t, qualifyStep, "TS_QUALIFICATION_SUITES: terrabase-walkthrough terrabase-successor native-validator rendered-sfo-enrollment terrabase-binary terrabase-release ts-auth-terrabase")
		requireText(t, qualifyStep, "TS_TEST_TIER: qualification\n")
		requireText(t, qualifyStep, "run: bash scripts/ci/qualify-image.sh")
		_, dispatch, ok := strings.Cut(image, "workflow_dispatch:")
		if !ok {
			t.Fatal("missing workflow dispatch")
		}
		dispatch, _, _ = strings.Cut(dispatch, "concurrency:")
		if got := matches(dispatch, `(?m)^      ([a-z_]+):$`); !reflect.DeepEqual(got, []string{"source_revision", "source_ci_run_id", "source_ci_run_number", "trigger"}) {
			t.Fatalf("inputs: %v", got)
		}
	})
	t.Run("deploy_waits_for_ci_without_an_opt_in", func(t *testing.T) {
		deploy := workflowText(t, ".github/workflows/deploy.yml")
		forbidText(t, deploy, "  push:")
		if got := matches(deploy, `(?m)^    name: (.+)$`); !reflect.DeepEqual(got, []string{"deploy/every-region"}) {
			t.Fatalf("jobs: %v", got)
		}
		requireText(t, deploy, "    if: ${{ github.ref == 'refs/heads/main' }}\n")
		forbidText(t, deploy, "TS_AUTO_DEPLOY_")
		// Queued, never cancelled: CI never abandons a region mid-rollout.
		requireText(t, deploy, "  group: ts-orchestrator-deploy\n  cancel-in-progress: false\n")
		_, dispatch, _ := strings.Cut(deploy, "workflow_dispatch:")
		dispatch, _, _ = strings.Cut(dispatch, "concurrency:")
		if got := matches(dispatch, `(?m)^      ([a-z_]+):$`); !reflect.DeepEqual(got, []string{"source_revision", "source_ci_run_id", "source_ci_run_number", "trigger"}) {
			t.Fatalf("inputs: %v", got)
		}
		_, deployJob, _ := strings.Cut(deploy, "\n  deploy:\n")
		steps := matches(deployJob, `(?m)^      - name: (.+)$`)
		gate := slices.Index(steps, "Wait for ci.yml and skip a failed or overtaken revision")
		admit := slices.Index(steps, "Verify retained production admission before deployment credentials")
		retain := slices.Index(steps, "Retain regional production admission results")
		roll := slices.Index(steps, "Sign and deploy admitted regions concurrently")
		if gate < 0 || admit != gate+1 || retain != admit+1 || roll != retain+1 || roll != len(steps)-1 {
			t.Fatalf("production admission and retained results must follow CI before rollout: %v", steps)
		}
		// Scripts of the revision run with secrets only once it is on main,
		// and the signer is never built from the shared Go caches.
		if verify := slices.Index(steps, "Verify the source revision and Go toolchain"); verify < 1 || verify >= gate {
			t.Fatalf("the source must be verified right after checkout: %v", steps)
		}
		_, verifyStep, _ := strings.Cut(deploy, "- name: Verify the source revision and Go toolchain")
		verifyStep, _, _ = strings.Cut(verifyStep, "- name:")
		requireText(t, verifyStep, `git merge-base --is-ancestor "${SOURCE_SHA}" refs/remotes/origin/main`)
		forbidText(t, deploy, "/cache/go")
		_, gateStep, _ := strings.Cut(deploy, "- name: Wait for ci.yml and skip a failed or overtaken revision")
		gateStep, _, _ = strings.Cut(gateStep, "- name:")
		requireText(t, gateStep, "if: ${{ inputs.trigger == 'ci' }}")
		requireText(t, gateStep, "GATE_WORKFLOW: deploy.yml\n")
		requireText(t, gateStep, `bash scripts/ci/image-superseded.sh "${SOURCE_SHA}" "${SOURCE_CI_RUN_ID}" "${SOURCE_CI_RUN_NUMBER}" 300`)
		_, admitStep, _ := strings.Cut(deploy, "- name: Verify retained production admission before deployment credentials")
		admitStep, _, _ = strings.Cut(admitStep, "- name:")
		requireText(t, admitStep, "if: ${{ steps.gate.outputs.skip != 'true' }}")
		requireText(t, admitStep, "run: bash scripts/ci/deploy-fleet.sh qualify\n")
		forbidText(t, admitStep, "continue-on-error:")
		_, retainStep, _ := strings.Cut(deploy, "- name: Retain regional production admission results")
		retainStep, _, _ = strings.Cut(retainStep, "- name:")
		requireText(t, retainStep, "if: always()")
		requireText(t, retainStep, "production-admission.jsonl")
		beforeRoll, rollStep, _ := strings.Cut(deploy, "- name: Sign and deploy admitted regions concurrently")
		for _, credential := range []string{"TS_OBJECT_NAMESPACE", "TS_RELEASE_VAULT_ID", "TS_RELEASE_LEAF_SECRET",
			"TS_DEPLOY_OCI_USER", "TS_DEPLOY_OCI_TENANCY", "TS_DEPLOY_OCI_FINGERPRINT", "TS_DEPLOY_OCI_KEY"} {
			forbidText(t, beforeRoll, credential+":")
		}
		requireText(t, rollStep, "if: ${{ steps.gate.outputs.skip != 'true' }}")
		requireText(t, rollStep, "run: bash scripts/ci/deploy-fleet.sh deploy\n")
		forbidText(t, rollStep, "continue-on-error:")
		// The OCI key reaches only the rollout step, and the leaf key never
		// reaches the job: ts-orch reads it from OCI Vault.
		if strings.Count(deploy, "secrets.TS_DEPLOY_OCI_KEY") != 1 || !strings.Contains(rollStep, "secrets.TS_DEPLOY_OCI_KEY") {
			t.Error("the OCI key must be passed to the rollout step only")
		}
		wrapper := workflowText(t, "scripts/ci/deploy-fleet.sh")
		forbidText(t, wrapper, "TS_AUTO_DEPLOY_")
		for _, flag := range []string{"--environment", "--arch"} {
			forbidText(t, wrapper, flag)
		}
		requireText(t, wrapper, "tag=ci-$SOURCE_SHA-run-$SOURCE_CI_RUN_ID")
		requireText(t, wrapper, "--pattern qualification.json")
		requireText(t, wrapper, "for architecture in amd64 arm64; do")
		requireText(t, wrapper, "asset=terrascale-orchestrator-linux-$architecture")
		requireText(t, wrapper, `--pattern "$asset"`)
		requireText(t, wrapper, `mapfile -t cells < <(jq -er 'select(.state == "qualified") | .cell' "$work/production-admission.jsonl")`)
		requireText(t, wrapper, `arguments+=(--cell "$cell")`)
		requireText(t, wrapper, `dist/ts-orch release verify-production --dir "$work/release" --root-key "$root_key" "${arguments[@]}"`)
		requireText(t, wrapper, `--source-checkout . --namespace "$TS_OBJECT_NAMESPACE" --poll 5s "${arguments[@]}"`)
		requireText(t, wrapper, "dist/ts-orch release deploy ")
		requireText(t, wrapper, `--signing-key-secret "$TS_RELEASE_LEAF_SECRET" --vault-id "$TS_RELEASE_VAULT_ID"`)
		forbidText(t, wrapper, "--signing-key \"")
	})
	t.Run("test_tiers", func(t *testing.T) {
		requireText(t, ci, "      TS_TEST_TIER: ${{ github.event_name == 'pull_request' && 'pr' || 'full' }}\n")
		requireText(t, ci, "      TS_RACE_IDLE_JOBS: '5'\n")
		forbidText(t, ci, "prepare-fj-admission.sh")
		for _, text := range []string{ci, image, workflowText(t, ".github/workflows/deploy.yml")} {
			requireText(t, text, "runs-on: ubuntu-24.04")
			requireText(t, text, "go-version: '1.27.1'")
			forbidText(t, text, "container:")
			forbidText(t, text, "FORGEJO_")
			forbidText(t, text, "/cache/")
			if !regexp.MustCompile(`uses: actions/checkout@[0-9a-f]{40}`).MatchString(text) {
				t.Error("checkout action must be pinned to a commit")
			}
		}
		makefile := workflowText(t, "Makefile")
		requireText(t, makefile, "$(if $(filter pr,$(TS_TEST_TIER)),,fixturetest-check)")
		requireText(t, makefile, "$(GO) vet -tags fixturetest ./...")
		requireText(t, makefile, "GO=\"$(GO)\" bash scripts/ci/racetest/race-test.sh")
	})
	t.Run("cacheable_checkout_and_lint", func(t *testing.T) {
		// Content-derived times must be in place before any test runs, or
		// every test that reads a repository file misses the test cache.
		steps := matches(ci, `(?m)^      - name: (.+)$`)
		stamp := slices.Index(steps, "Stamp tracked files with content-derived times")
		verify := slices.Index(steps, "Check, test and build static binaries in parallel")
		if stamp < 0 || verify != stamp+1 || slices.Index(steps, "Verify the source revision and Go toolchain") > stamp {
			t.Fatalf("the checkout must be stamped right before the checks: %v", steps)
		}
		requireText(t, ci, "run: go run ./scripts/ci/stablemtime\n")
		forbidText(t, ci, "--tmpfs")
		makefile := workflowText(t, "Makefile")
		_, ciVerify, _ := strings.Cut(makefile, "\nci-verify:\n")
		ciVerify, _, _ = strings.Cut(ciVerify, "\n\n")
		requireText(t, ciVerify, " shellcheck ")
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
		if len(manifest.TrustRoots) == 0 || manifest.TrustRoots[0].SHA256 != "548426817b9ab219720d4a934703b7dfbd5b63633533a9340ec4e19c2fb65e5e" {
			t.Fatal("trust root digest changed")
		}
	})
}

func TestImageGateWaitsForDispatchingRun(t *testing.T) {
	t.Run("zero-budget-is-invalid", func(t *testing.T) {
		result := runCI(t, nil, "bash", "scripts/ci/image-superseded.sh", strings.Repeat("a", 40), "42", "7", "0")
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
		{"normal", "action_required", "", 1},
		{"normal", "skipped", "", 1},
		{"wrong-id", "success", "", 1},
		{"persistent", "success", "", 1},
	} {
		t.Run(test.mode+"/"+test.status, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			script.Write(t, filepath.Join(bin, "gh"), script.Read(t, filepath.Join(script.Root(t), "tests/ci/testdata/image-gate/curl")), 0o755)
			script.Write(t, filepath.Join(bin, "sleep"), []byte("#!/usr/bin/env bash\nif [[ $MOCK_MODE == wrong-id || $MOCK_MODE == persistent ]]; then exec \"$MOCK_REAL_SLEEP\" \"$@\"; fi\n"), 0o755)
			output := filepath.Join(root, "output")
			script.Write(t, output, nil, 0o600)
			budget := "10"
			if test.mode == "wrong-id" || test.mode == "persistent" {
				// Leave enough time to reach the transport even on a contended host.
				budget = "5"
			}
			env := map[string]string{
				"PATH":      bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"MOCK_ROOT": root, "MOCK_MODE": test.mode, "MOCK_STATUS": test.status, "MOCK_REAL_SLEEP": sleepPath,
				"MOCK_SOURCE": strings.Repeat("a", 40), "GH_TOKEN": "fixture-token",
				"GITHUB_OUTPUT": output,
			}
			// The fleet deployment shares the gate; its repair names deploy.yml.
			workflow := "image.yml"
			if test.status == "action_required" {
				workflow = "deploy.yml"
				env["GATE_WORKFLOW"] = workflow
			}
			result := runCI(t, env, "bash", "scripts/ci/image-superseded.sh", env["MOCK_SOURCE"], "42", "7", budget)
			if result.Code != test.code || string(script.Read(t, output)) != test.output {
				t.Fatalf("exit=%d output=%q stdout=%s stderr=%s", result.Code, script.Read(t, output), result.Stdout, result.Stderr)
			}
			if test.code == 1 && !strings.Contains(result.Stderr, "dispatch "+workflow+" manually") {
				t.Fatal("missing visible repair: " + result.Stderr)
			}
			if !strings.Contains(string(script.Read(t, filepath.Join(root, "requests"))), "repos/TerraScale/ts-orchestrator/actions/runs/42") {
				t.Fatal("dispatching run ID was not requested")
			}
		})
	}
}

func TestImageDispatchPinsRun(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	script.Write(t, filepath.Join(bin, "gh"), script.Read(t, filepath.Join(script.Root(t), "tests/ci/testdata/image-gate/curl")), 0o755)
	env := map[string]string{
		"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH"), "MOCK_ROOT": root,
		"GH_TOKEN":   "fixture-token",
		"GITHUB_SHA": strings.Repeat("a", 40), "GITHUB_RUN_ID": "42", "GITHUB_RUN_NUMBER": "7", "GITHUB_REF": "refs/heads/main",
	}
	result := runCI(t, env, "bash", "scripts/ci/dispatch-image.sh")
	if result.Code != 0 || !strings.HasSuffix(string(script.Read(t, filepath.Join(root, "url"))), "/actions/workflows/image.yml/dispatches") {
		t.Fatalf("dispatch: %s %s", result.Stdout, result.Stderr)
	}
	if result := runCI(t, env, "bash", "scripts/ci/dispatch-image.sh", "deploy.yml"); result.Code != 0 ||
		!strings.HasSuffix(string(script.Read(t, filepath.Join(root, "url"))), "/actions/workflows/deploy.yml/dispatches") {
		t.Fatalf("deploy dispatch: %s %s", result.Stdout, result.Stderr)
	}
	if result := runCI(t, env, "bash", "scripts/ci/dispatch-image.sh", "ci.yml"); result.Code != 2 {
		t.Fatalf("dispatched an unknown workflow: %+v", result)
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

// TestImageDispatchOnlyForChangedInputs builds an image only when an image
// input differs from the newest image release's source, and weekly; any
// doubt (no release, an unreadable API) builds.
func TestImageDispatchOnlyForChangedInputs(t *testing.T) {
	base := strings.Repeat("b", 40)
	releases := fmt.Sprintf(`[{"tag_name":"ci-%s-run-9"},{"tag_name":"image-%s-run-8-attempt-1"},{"tag_name":"image-%s-run-1-attempt-1"}]`,
		strings.Repeat("c", 40), base, strings.Repeat("d", 40))
	for _, tc := range []struct {
		name, workflow, event, releases, diff string
		dispatched, consulted                 bool
	}{
		{"unchanged", "image.yml", "push", releases, "0", false, true},
		{"changed", "image.yml", "push", releases, "1", true, true},
		{"comparison failed", "image.yml", "push", releases, "128", true, true},
		// The gate script exits 1 on its own failure; only 3 means unchanged.
		{"gate failed", "image.yml", "push", releases, "crash", true, false},
		{"no image release", "image.yml", "push", `[{"tag_name":"ci-x"}]`, "0", true, false},
		{"unreadable releases", "image.yml", "push", "fail", "0", true, false},
		{"weekly", "image.yml", "schedule", releases, "0", true, false},
		{"deploy", "deploy.yml", "push", releases, "0", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			script.Write(t, filepath.Join(bin, "gh"), []byte(`#!/usr/bin/env bash
[[ $1 == api && $GH_HOST == github.com ]] || exit 2
if [[ $* == *dispatches* ]]; then printf '%s' "$4" > "$MOCK_ROOT/url"; exit 0; fi
[[ $MOCK_RELEASES != fail ]] || exit 22
printf '%s' "$MOCK_RELEASES"
`), 0o755)
			if tc.diff == "crash" {
				script.Write(t, filepath.Join(bin, "base64"), []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755)
			}
			script.Write(t, filepath.Join(bin, "git"), []byte(`#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_ROOT/git"
case $1 in
	fetch) exit 0 ;;
	diff) [[ $* == *--quiet* ]] && exit "$MOCK_DIFF"; echo deploy/image/image-inputs.json ;;
esac
`), 0o755)
			env := map[string]string{
				"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH"), "MOCK_ROOT": root,
				"MOCK_RELEASES": tc.releases, "MOCK_DIFF": tc.diff, "GITHUB_EVENT_NAME": tc.event,
				"GH_TOKEN":   "fixture-token",
				"GITHUB_SHA": strings.Repeat("a", 40), "GITHUB_RUN_ID": "42", "GITHUB_RUN_NUMBER": "7", "GITHUB_REF": "refs/heads/main",
			}
			result := runCI(t, env, "bash", "scripts/ci/dispatch-image.sh", tc.workflow)
			if result.Code != 0 {
				t.Fatalf("dispatch: %s %s", result.Stdout, result.Stderr)
			}
			url, _ := os.ReadFile(filepath.Join(root, "url"))
			if dispatched := strings.HasSuffix(string(url), "/"+tc.workflow+"/dispatches"); dispatched != tc.dispatched {
				t.Fatalf("dispatched = %v, want %v: %s %s", dispatched, tc.dispatched, result.Stdout, result.Stderr)
			}
			calls, _ := os.ReadFile(filepath.Join(root, "git"))
			if consulted := strings.Contains(string(calls), "fetch --quiet --no-tags --depth=1 origin "+base); consulted != tc.consulted {
				t.Fatalf("compared with the newest image's source = %v, want %v: %s", consulted, tc.consulted, calls)
			}
			if tc.consulted && !strings.Contains(string(calls), "-- deploy/image deploy/systemd deploy/udev internal/image") {
				t.Fatalf("image inputs not compared: %s", calls)
			}
		})
	}
}

func TestQualifyImageRequiresEverySuiteToPass(t *testing.T) {
	// The fake toolchain records the tier it ran under and prints what
	// MOCK_RESULT asks for, as `go test -v` would.
	fake := func(t *testing.T) (string, string) {
		root := t.TempDir()
		record := filepath.Join(root, "record")
		goTool := filepath.Join(root, "go")
		script.Write(t, goTool, []byte(`#!/usr/bin/env bash
printf '%s %s\n' "$TS_TEST_TIER" "$*" >> "$MOCK_RECORD"
case $MOCK_RESULT in
	pass) printf -- '=== RUN   TestX\n--- PASS: TestX (0.00s)\nPASS\n' ;;
	skip) printf -- '=== RUN   TestX\n--- SKIP: TestX (0.00s)\nPASS\n' ;;
	none) printf -- 'testing: warning: no tests to run\nPASS\n' ;;
	fail) printf -- '--- FAIL: TestX (0.00s)\nFAIL\n'; exit 1 ;;
esac
`), 0o755)
		return goTool, record
	}
	for _, tc := range []struct {
		name, suites, result, message string
		code                          int
	}{
		{"pass", "terrabase-walkthrough terrabase-successor", "pass", "qualification suite terrabase-successor passed", 0},
		// A multi-line repository variable keeps every line's suites.
		{"multi_line", "terrabase-walkthrough\nterrabase-successor\nnative-validator", "pass", "qualification suite native-validator passed", 0},
		{"skip", "terrabase-walkthrough", "skip", "skipped a test; its fixture is incomplete", 1},
		{"no_test", "native-validator", "none", "ran no test", 1},
		{"fail", "rendered-sfo-enrollment", "fail", "qualification suite rendered-sfo-enrollment failed", 1},
		{"backup_bridge_is_not_a_suite", "terrabase-backup", "pass", "unknown qualification suite: terrabase-backup", 2},
		{"unknown", "terrabase-walkthrough firecracker", "pass", "unknown qualification suite: firecracker", 2},
		{"none", " ", "pass", "names no qualification suite", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			goTool, record := fake(t)
			env := map[string]string{"GO": goTool, "MOCK_RECORD": record, "MOCK_RESULT": tc.result, "TS_QUALIFICATION_SUITES": tc.suites, "TS_TEST_TIER": "full"}
			result := runCI(t, env, "bash", "scripts/ci/qualify-image.sh")
			if result.Code != tc.code || !strings.Contains(result.Stdout+result.Stderr, tc.message) {
				t.Fatalf("exit=%d stdout=%s stderr=%s", result.Code, result.Stdout, result.Stderr)
			}
			if tc.code == 2 {
				if _, err := os.Stat(record); !os.IsNotExist(err) {
					t.Fatal("invalid suites invoked Go")
				}
				return
			}
			lines := strings.Split(strings.TrimSpace(string(script.Read(t, record))), "\n")
			if len(lines) != len(strings.Fields(tc.suites)) {
				t.Fatalf("ran %d suites for %q", len(lines), tc.suites)
			}
			for _, line := range lines {
				if !strings.HasPrefix(line, "qualification test -count=1 -v -timeout=") {
					t.Fatalf("suite did not run as a fresh qualification-tier test: %q", line)
				}
				var seconds int
				if _, err := fmt.Sscanf(strings.Fields(line)[4], "-timeout=%ds", &seconds); err != nil || seconds <= 0 || seconds > 600 {
					t.Fatalf("suite timeout is not drawn from the shared budget: %q", line)
				}
			}
		})
	}
}

// Every suite draws its -timeout from one shared budget, so qualification
// cannot outgrow the image job's timeout; a spent budget fails the gate.
func TestQualifyImageSharesOneBudget(t *testing.T) {
	root := t.TempDir()
	goTool := filepath.Join(root, "go")
	script.Write(t, goTool, []byte(`#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_RECORD"
sleep 2
printf -- '=== RUN   TestX\n--- PASS: TestX (0.00s)\nPASS\n'
`), 0o755)
	record := filepath.Join(root, "record")
	env := map[string]string{"GO": goTool, "MOCK_RECORD": record, "TS_QUALIFICATION_SUITES": "terrabase-walkthrough terrabase-successor",
		"TS_QUALIFICATION_BUDGET_SECONDS": "1"} // Retired input cannot override the fixed budget.
	result := runCI(t, env, "bash", "scripts/ci/qualify-image.sh")
	if result.Code != 0 {
		t.Fatalf("exit=%d stdout=%s stderr=%s", result.Code, result.Stdout, result.Stderr)
	}
	lines := strings.Split(strings.TrimSpace(string(script.Read(t, record))), "\n")
	if len(lines) != 2 {
		t.Fatalf("recorded runs: %q", lines)
	}
	var first, second int
	fmt.Sscanf(strings.Fields(lines[0])[3], "-timeout=%ds", &first)
	fmt.Sscanf(strings.Fields(lines[1])[3], "-timeout=%ds", &second)
	if first > 600 || first < 590 || second >= first || second < 580 {
		t.Fatalf("timeouts do not share the fixed budget: %d then %d", first, second)
	}
}

func TestQualifyImageDeadlineIncludesCompilation(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	wallTimeout, err := exec.LookPath("timeout")
	if err != nil {
		t.Fatal(err)
	}
	// Shorten the process-boundary clock, without adding a production timing override.
	script.Write(t, filepath.Join(bin, "timeout"), []byte("#!/usr/bin/env bash\n"+
		"[[ $1 == --kill-after=5s && $2 =~ ^[0-9]+s$ ]] || exit 2\nshift 2\nexec "+wallTimeout+" --kill-after=0.1s 0.1s \"$@\"\n"), 0o755)
	goTool := filepath.Join(bin, "go")
	script.Write(t, goTool, []byte("#!/usr/bin/env bash\nsleep 2\nprintf -- '--- PASS: TestX (0.00s)\\nPASS\\n'\n"), 0o755)
	result := runCI(t, map[string]string{"GO": goTool, "PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TS_QUALIFICATION_SUITES": "terrabase-walkthrough"}, "bash", "scripts/ci/qualify-image.sh")
	if result.Code != 1 || !strings.Contains(result.Stdout+result.Stderr, "qualification suite terrabase-walkthrough failed") {
		t.Fatalf("compilation escaped the deadline: exit=%d stdout=%s stderr=%s", result.Code, result.Stdout, result.Stderr)
	}
}
