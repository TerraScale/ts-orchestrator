package ci_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
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

// Only the release-push job, after a publishing main push, can mint the
// GitHub OIDC token that is the release push credential (W20 M7).
func TestReleasePushJob(t *testing.T) {
	ci := workflowText(t, ".github/workflows/ci.yml")
	build, push, found := strings.Cut(ci, "\n  release-push:\n")
	if !found {
		t.Fatal("ci.yml has no release-push job")
	}
	if strings.Count(ci, "id-token: write") != 1 || !strings.Contains(push, "    permissions:\n      contents: read\n      id-token: write\n") {
		t.Fatal("id-token: write must be granted to the release-push job only, with contents: read")
	}
	requireText(t, build, "    outputs:\n      publication: ${{ steps.inputs.outputs.publication }}\n")
	// Main qualifies its own Fast area before publishing; scheduled Slow
	// cannot hold a release on the push path.
	requireText(t, push, "    needs: [build]\n")
	_, buildJob, _ := strings.Cut(build, "\n  build:\n")
	forbidText(t, buildJob, "    needs: [race]\n")
	requireText(t, buildJob, "Verify exact-commit dev-host Fast evidence")
	requireText(t, buildJob, "if: steps.fast-proof.outputs.verified != 'true'")
	qualify := strings.Index(buildJob, "Qualify this revision with Fast tests")
	publication := strings.Index(buildJob, "Build and verify this revision's static release binaries")
	if qualify < 0 || publication <= qualify {
		t.Fatal("Fast qualification must precede release publication")
	}
	forbidText(t, ci, "\n  race:\n")
	slow := workflowText(t, ".github/workflows/slow.yml")
	requireText(t, slow, "\n  schedule:\n")
	forbidText(t, slow, "\n  push:\n")
	forbidText(t, buildJob, "dispatch-image.sh")
	requireText(t, push, "    if: ${{ always() && needs.build.result == 'success' && github.event_name == 'push' && github.ref == 'refs/heads/main' && needs.build.outputs.publication == 'required' }}\n")
	if steps := matches(push, `(?m)^      - name: (.+)$`); !reflect.DeepEqual(steps, []string{
		"Check out the region list", "Download this run's release binaries", "Push the release to every region"}) {
		t.Fatalf("release-push steps: %v", steps)
	}
	requireText(t, push, "sparse-checkout: deploy/m1/regions.json")
	requireText(t, push, "persist-credentials: false")
	requireText(t, push, `gh release download "ci-${GITHUB_SHA}-run-${GITHUB_RUN_ID}"`)
	requireText(t, push, "--pattern terrascale-orchestrator-linux-amd64 --pattern terrascale-orchestrator-linux-arm64")
	requireText(t, push, `release push --sha "${GITHUB_SHA}" --dir dist`)
	requireText(t, push, `>> "${GITHUB_STEP_SUMMARY}"`)
	forbidText(t, push, "continue-on-error:")
	forbidText(t, push, "secrets.")
}

// A documentation-only push reuses its newest code ancestor's dev-host Fast
// evidence, and the Fast execution clock excludes compilation.
func TestFastQualificationBudget(t *testing.T) {
	ci := workflowText(t, ".github/workflows/ci.yml")
	_, buildJob, _ := strings.Cut(ci, "\n  build:\n")
	buildJob, _, _ = strings.Cut(buildJob, "\n  release-push:\n")
	compile := strings.Index(buildJob, "- name: Compile Fast test binaries\n")
	qualify := strings.Index(buildJob, "- name: Qualify this revision with Fast tests\n")
	if compile < 0 || qualify <= compile {
		t.Fatal("Fast compilation must be a separate step before Fast execution")
	}
	requireText(t, buildJob[qualify:], "        timeout-minutes: 5\n        run: make test-fast GO=go\n")

	_, fn, _ := strings.Cut(buildJob, "docs_only() {\n")
	fn, _, found := strings.Cut(fn, "\n          }\n")
	if !found {
		t.Fatal("missing docs_only function")
	}
	repo := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("commit", "-q", "--allow-empty", "-m", "base")
	for _, c := range []struct {
		path string
		docs bool
	}{
		{"docs/runbook.md", true}, {"README.md", true}, {".cos/lanes.md", true},
		{"internal/app/AGENTS.md", true}, {"docs/diagram.svg", true},
		{"main.go", false}, {"scripts/notes.md", false}, {"tests/fixture.md", false},
		{"docs/config.json", false}, {".github/workflows/ci.yml", false},
	} {
		file := filepath.Join(repo, c.path)
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(c.path), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", "-A")
		git("commit", "-q", "-m", c.path)
		cmd := exec.Command("bash", "-c", "docs_only() {\n"+fn+"\n}\ndocs_only HEAD")
		cmd.Dir = repo
		if err := cmd.Run(); (err == nil) != c.docs {
			t.Errorf("%s: docs-only=%v, want %v", c.path, err == nil, c.docs)
		}
	}
}
