package cicontract_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const deployRevision = "5c6c68d95eb2dcbf0a9b1f57afd53a120ac1af3c"

type deployConfiguration struct {
	Repository string    `json:"repository"`
	Profiles   []profile `json:"prProfiles"`
}

type profile struct {
	Name     string    `json:"name"`
	Commands []command `json:"commands"`
}

type command struct {
	Command   string   `json:"command"`
	Arguments []string `json:"arguments"`
}

func TestPushWorkflowPinsToolsAndKeepsThemOutsideSource(t *testing.T) {
	workflow := readRepositoryFile(t, ".forgejo", "workflows", "ci.yml")

	requireContains(t, workflow,
		"  push:\n    branches: [develop, main]",
		"  contents: read",
		"TS_DEPLOY_REVISION: \""+deployRevision+"\"",
		"fetch --no-tags --depth=1",
		"\"${TS_DEPLOY_REVISION}\"",
		"GOBIN: ${{ runner.temp }}/terrascale-deploy/bin",
		"case \"${GOBIN}\" in /*)",
		"path: ${{ runner.temp }}/terrascale-deploy/bin",
		"--require-clean-source",
		"--output \"${RUNNER_TEMP}/orchestrator-plan.json\"",
		"Contents: Read on only",
	)
	for _, forbidden := range []string{"pull_request:", "GOBIN=.", ".tools", "container:", " docker "} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("workflow contains forbidden text %q", forbidden)
		}
	}

	secretPattern := regexp.MustCompile(`secrets\.([A-Za-z0-9_]+)`)
	for _, match := range secretPattern.FindAllStringSubmatch(workflow, -1) {
		if match[1] != "TS_DEPLOY_READ_TOKEN" {
			t.Fatalf("workflow grants an unexpected secret: %s", match[1])
		}
	}

	usesPattern := regexp.MustCompile(`(?m)^\s*- uses: \S+@([0-9a-f]{40})\s*$`)
	usesLines := regexp.MustCompile(`(?m)^\s*- uses: .+$`).FindAllString(workflow, -1)
	if len(usesLines) == 0 {
		t.Fatal("workflow contains no actions")
	}
	if pinned := usesPattern.FindAllString(workflow, -1); len(pinned) != len(usesLines) {
		t.Fatalf("every action must use a full commit pin: pinned=%d actions=%d", len(pinned), len(usesLines))
	}
}

func TestDeployProfilesCoverTheFullGoAndArtifactContracts(t *testing.T) {
	data := readRepositoryFile(t, ".terrascale", "deploy.json")
	var configuration deployConfiguration
	if err := json.Unmarshal([]byte(data), &configuration); err != nil {
		t.Fatalf("decode deploy configuration: %v", err)
	}
	if configuration.Repository != "TerraScale.Orchestrator" {
		t.Fatalf("unexpected repository %q", configuration.Repository)
	}

	byName := make(map[string]profile, len(configuration.Profiles))
	for _, entry := range configuration.Profiles {
		if _, exists := byName[entry.Name]; exists {
			t.Fatalf("duplicate profile %q", entry.Name)
		}
		byName[entry.Name] = entry
	}
	if names := sortedKeys(byName); !slices.Equal(names, []string{"artifact", "build", "static", "test"}) {
		t.Fatalf("unexpected profiles: %v", names)
	}

	assertCommand(t, byName["static"].Commands, 0, "bash", "-c", `test -z "$(gofmt -l .)"`)
	assertCommand(t, byName["static"].Commands, 1, "go", "vet", "./...")
	assertCommand(t, byName["build"].Commands, 0, "go", "build", "./...")
	assertCommand(t, byName["test"].Commands, 0, "go", "test", "./...")
	assertCommand(t, byName["test"].Commands, 1, "go", "test", "-race", "./...")

	artifact := byName["artifact"].Commands
	assertCommand(t, artifact, 0, "podman", "build", "--file", ".terrascale/ci.Dockerfile", "--target", "ci-artifact", "--output", "type=local,dest=artifacts/orchestrator", ".")
	if len(artifact) != 2 || artifact[1].Command != "bash" || len(artifact[1].Arguments) != 2 {
		t.Fatalf("artifact validation command is missing: %#v", artifact)
	}
	for _, path := range expectedArtifactFiles() {
		requireContains(t, artifact[1].Arguments[1], path)
	}
}

func TestArtifactBuildPinsGoAndIncludesTsNodeForBothArchitectures(t *testing.T) {
	dockerfile := readRepositoryFile(t, ".terrascale", "ci.Dockerfile")
	requireContains(t, dockerfile,
		"FROM docker.io/library/golang@sha256:eef6a67266eeed3c86dd47fd01b32faa8bf0229eb83eb3d4d466e80391bd3820 AS source",
		"GOARCH=amd64 go build -trimpath -o /out/linux-x64/terrascale-orchestrator ./cmd/orchestrator",
		"GOARCH=amd64 go build -trimpath -o /out/linux-x64/ts-node ./cmd/ts-node",
		"GOARCH=arm64 go build -trimpath -o /out/linux-arm64/terrascale-orchestrator ./cmd/orchestrator",
		"GOARCH=arm64 go build -trimpath -o /out/linux-arm64/ts-node ./cmd/ts-node",
		"/candidate/linux-x64/seccomp/terrascale-default-v1.json",
		"/candidate/linux-arm64/seccomp/terrascale-default-v1.json",
	)
}

func assertCommand(t *testing.T, commands []command, index int, executable string, arguments ...string) {
	t.Helper()
	if index >= len(commands) {
		t.Fatalf("command %d is missing", index)
	}
	actual := commands[index]
	if actual.Command != executable || !slices.Equal(actual.Arguments, arguments) {
		t.Fatalf("command %d = %#v, want %s %v", index, actual, executable, arguments)
	}
}

func expectedArtifactFiles() []string {
	return []string{
		"linux-arm64/orchestrator-tooling",
		"linux-arm64/seccomp/terrascale-default-v1.json",
		"linux-arm64/terrascale-orchestrator",
		"linux-arm64/ts-node",
		"linux-x64/orchestrator-tooling",
		"linux-x64/seccomp/terrascale-default-v1.json",
		"linux-x64/terrascale-orchestrator",
		"linux-x64/ts-node",
	}
}

func readRepositoryFile(t *testing.T, elements ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, elements...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func requireContains(t *testing.T, value string, snippets ...string) {
	t.Helper()
	for _, snippet := range snippets {
		if !strings.Contains(value, snippet) {
			t.Fatalf("missing required text %q", snippet)
		}
	}
}

func sortedKeys(values map[string]profile) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
