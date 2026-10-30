package ci_test

import (
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

func TestRequiredCheckIdentity(t *testing.T) {
	ci := workflowText(t, ".github/workflows/ci.yml")
	_, change, found := strings.Cut(ci, "\n  change:\n")
	if !found {
		t.Fatal("missing PR verification job")
	}
	change, _, _ = strings.Cut(change, "\n  build:\n")
	requireText(t, change, "    if: ${{ github.event_name == 'pull_request' }}\n")
	requireText(t, change, "    name: ${{ github.event_name == 'pull_request' && 'test' || 'verify/change' }}\n")
	requireText(t, change, "      - uses: ./.github/actions/verify\n        if: ${{ steps.changes.outputs.checks == 'true' }}")
	forbidText(t, change, "continue-on-error:")
	requireText(t, change, "      GOMAXPROCS: '1'\n")
	requireText(t, change, "cpus=$(getconf _NPROCESSORS_ONLN)")
	requireText(t, change, `echo "TS_RACE_JOBS=$cpus" >> "$GITHUB_ENV"`)
	forbidText(t, change, "TS_RACE_JOBS: '2'")
	requireText(t, change, "      TS_RACE_IDLE_JOBS: '1'\n")
	_, aggregate, found := strings.Cut(ci, "\n  test:\n")
	if !found {
		t.Fatal("missing non-PR aggregate job")
	}
	aggregate, _, _ = strings.Cut(aggregate, "\n  flaky-report:\n")
	requireText(t, aggregate, "    if: ${{ always() }}\n")
	requireText(t, aggregate, "    needs: [change, build]\n")
	requireText(t, aggregate, `test "$CHANGE" = success`)
	requireText(t, aggregate, `test "$BUILD" = success`)
	forbidText(t, aggregate, "needs.race")
	forbidText(t, aggregate, "continue-on-error:")
}
