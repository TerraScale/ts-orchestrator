package runtimepriority_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
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
			for _, path := range []string{"scripts/ci/publish-qualification.sh"} {
				script.Write(t, filepath.Join(root, path), script.Read(t, filepath.Join(repo, path)), 0o644)
			}
			script.Write(t, filepath.Join(root, "go.mod"), []byte("module fixture\n"), 0o644)
			script.Write(t, filepath.Join(root, "go.sum"), []byte("fixture\n"), 0o644)
			for _, arch := range []string{"amd64", "arm64"} {
				script.Write(t, filepath.Join(root, "dist/terrascale-orchestrator-linux-"+arch), []byte("fixture "+arch+"\n"), 0o644)
			}
			for _, name := range []string{"git", "go", "sleep"} {
				script.Write(t, filepath.Join(root, "bin", name), script.Read(t, filepath.Join(repo, "tests/runtime_priority/testdata/publisher", name)), 0o755)
			}
			script.Write(t, filepath.Join(root, "bin", "gh"), []byte(`#!/usr/bin/env bash
set -euo pipefail
[[ $GH_HOST == github.com && $GH_TOKEN == fixture-token ]] || exit 5
[[ $1 == release ]] || exit 4
case $2 in
  create)
    [[ $4 == --repo && $5 == TerraScale/ts-orchestrator ]] || exit 4
    printf 'release-created\n' >> "$FAKE_GH_EVENTS" ;;
  download)
    [[ $4 == --repo && $5 == TerraScale/ts-orchestrator && $6 == --pattern && $8 == --output ]] || exit 4
    name=$7
    output=$9
    [[ ! -e $output ]] || exit 3
    count_file="$FAKE_GH_STATE/$name.count"
    count=0
    [[ ! -f $count_file ]] || count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s\n' "$count" > "$count_file"
    [[ $FAKE_GH_HTTP_FAILURE != yes ]] || exit 22
    if [[ $FAKE_GH_PERMANENT == yes || ( $name == terrascale-d15-qualify && $count == 1 ) ]]; then
      printf 'transient wrong attachment body\n' > "$output"
    else
      cp -- "$FAKE_REPO/dist/$name" "$output"
    fi ;;
  upload)
    [[ $4 == dist/qualification.json && $5 == --repo && $6 == TerraScale/ts-orchestrator ]] || exit 4
    printf 'qualification-created\n' >> "$FAKE_GH_EVENTS" ;;
  *) exit 4 ;;
esac
`), 0o755)

			r := script.Exec(t, root, map[string]string{
				"PATH":          filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
				"GITHUB_RUN_ID": "123", "GITHUB_RUN_NUMBER": "7", "GITHUB_SHA": strings.Repeat("a", 40), "FIXTURE_TREE": strings.Repeat("b", 40),
				"GH_TOKEN":      "fixture-token",
				"FAKE_GH_STATE": root, "FAKE_GH_EVENTS": filepath.Join(root, "events"), "FAKE_GH_PERMANENT": tc.permanent, "FAKE_GH_HTTP_FAILURE": tc.httpFailure, "FAKE_REPO": root,
			}, "bash", filepath.Join(root, "scripts/ci/publish-qualification.sh"))
			if (r.Code == 0) != tc.success {
				t.Fatalf("exit %d: %s\n%s", r.Code, r.Stdout, r.Stderr)
			}
			for _, secret := range []string{"fixture-token"} {
				if strings.Contains(r.Stdout+r.Stderr, secret) {
					t.Fatal("credential leaked")
				}
			}
			if got := string(script.Read(t, filepath.Join(root, "terrascale-d15-qualify.count"))); got != tc.attempts {
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
