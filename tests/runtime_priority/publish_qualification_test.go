package runtimepriority_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func TestD15PublisherReadback(t *testing.T) {
	for _, tc := range []struct {
		name, permanent, httpFailure, attempts, events string
		success                                        bool
	}{
		{"transient_wrong_attachment", "no", "no", "2\n", "release-created\nqualification-created\n", true},
		{"persistent_wrong_attachment", "yes", "no", "6\n", "release-created\n", false},
		{"http_failure", "no", "yes", "6\n", "release-created\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			repo := script.Root(t)
			for _, path := range []string{"scripts/ci/publish-qualification.sh", "tests/runtime_priority/qualify.py"} {
				script.Write(t, filepath.Join(root, path), script.Read(t, filepath.Join(repo, path)), 0o644)
			}
			script.Write(t, filepath.Join(root, "go.mod"), []byte("module fixture\n"), 0o644)
			script.Write(t, filepath.Join(root, "go.sum"), []byte("fixture\n"), 0o644)
			for _, arch := range []string{"amd64", "arm64"} {
				script.Write(t, filepath.Join(root, "dist/terrascale-orchestrator-linux-"+arch), []byte("fixture "+arch+"\n"), 0o644)
			}
			for _, name := range []string{"git", "go", "sleep", "fj"} {
				script.Write(t, filepath.Join(root, "bin", name), script.Read(t, filepath.Join(repo, "tests/runtime_priority/testdata/publisher", name)), 0o755)
			}
			r := script.Run(t, root, map[string]string{
				"PATH":          filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
				"GITHUB_RUN_ID": "123", "GITHUB_RUN_NUMBER": "7", "GITHUB_SHA": strings.Repeat("a", 40), "FIXTURE_TREE": strings.Repeat("b", 40),
				"FORGEJO_TOKEN": "fixture-write-token", "FORGEJO_READ_TOKEN": "fixture-read-token", "FORGEJO_SERVER_URL": "https://fixture.invalid",
				"FAKE_FJ_STATE": root, "FAKE_FJ_EVENTS": filepath.Join(root, "events"), "FAKE_FJ_PERMANENT": tc.permanent, "FAKE_FJ_HTTP_FAILURE": tc.httpFailure, "FAKE_REPO": root,
			}, "bash", filepath.Join(root, "scripts/ci/publish-qualification.sh"))
			if (r.Code == 0) != tc.success {
				t.Fatalf("exit %d: %s\n%s", r.Code, r.Stdout, r.Stderr)
			}
			for _, secret := range []string{"fixture-write-token", "fixture-read-token"} {
				if strings.Contains(r.Stdout+r.Stderr, secret) {
					t.Fatal("credential leaked")
				}
			}
			if got := string(script.Read(t, filepath.Join(root, "terrascale-d15-qualify.py.count"))); got != tc.attempts {
				t.Errorf("attempts %q want %q", got, tc.attempts)
			}
			if got := string(script.Read(t, filepath.Join(root, "events"))); got != tc.events {
				t.Errorf("events %q want %q", got, tc.events)
			}
			if strings.Contains(r.Stdout, "TS_D15_PROBE_PUBLICATION_V1") != tc.success {
				t.Fatal("completion marker inconsistent with successful readback")
			}
			if tc.success {
				if got := string(script.Read(t, filepath.Join(root, "terrascale-d15-probe.json.count"))); got != "1\n" {
					t.Errorf("descriptor attempts: %q", got)
				}
			} else if !strings.Contains(r.Stderr, "never matched") {
				t.Fatal(r.Stderr)
			}
		})
	}
}
