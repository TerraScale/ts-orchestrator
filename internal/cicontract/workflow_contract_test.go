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

func TestPushWorkflowHasFailClosedDeployBootstrap(t *testing.T) {
	workflow := readRepositoryFile(t, ".forgejo", "workflows", "ci.yml")
	requireContains(t, workflow,
		"  push:\n    branches: [develop, main]",
		"  contents: read",
		"TS_DEPLOY_REVISION: \"PENDING_DEP1_GREEN_COMMIT\"",
		"TS_DEPLOY_EXPECTED_TREE: \"PENDING_DEP1_GREEN_TREE\"",
		"TERRASCALE_DEPLOY_REPOSITORY_READ_TOKEN",
		"GIT_CONFIG_GLOBAL=\"${git_config_global}\"",
		"GIT_ASKPASS=\"${askpass}\"",
		"chmod 600 \"${git_config_global}\"",
		"chmod 600 \"${askpass}\"",
		"trap cleanup EXIT",
		"fetch --no-tags --depth=1",
		"rev-parse HEAD^{tree}",
		"go build -trimpath -o \"${GOBIN}/terrascale-deploy\" ./cmd/terrascale-deploy",
		"--require-clean-source",
	)
	for _, forbidden := range []string{
		"pull_request:",
		"TS_DEPLOY_READ_TOKEN",
		"e7718c8",
		"container:",
		"GOBIN=.tools",
		".tools/",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("workflow contains forbidden text %q", forbidden)
		}
	}

	secrets := regexp.MustCompile(`secrets\.([A-Za-z0-9_]+)`).FindAllStringSubmatch(workflow, -1)
	for _, match := range secrets {
		if match[1] != "TERRASCALE_DEPLOY_REPOSITORY_READ_TOKEN" {
			t.Fatalf("workflow grants an unexpected secret: %s", match[1])
		}
	}
	if len(secrets) != 2 {
		t.Fatalf("expected token only in the require and fetch steps, found %d references", len(secrets))
	}

	usesLines := []string{}
	for _, line := range strings.Split(workflow, "\n") {
		if strings.Contains(line, "- uses:") {
			usesLines = append(usesLines, line)
		}
	}
	for _, line := range usesLines {
		at := strings.LastIndex(line, "@")
		if at < 0 || len(strings.TrimSpace(line[at+1:])) != 40 || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(strings.TrimSpace(line[at+1:])) {
			t.Fatalf("every action must use a full commit pin: %q", line)
		}
	}
}

func TestDeployProfilesCoverTheFullGoAndArtifactContracts(t *testing.T) {
	data := readRepositoryFile(t, ".terrascale", "deploy.json")
	var configuration deployConfiguration
	if err := json.Unmarshal([]byte(data), &configuration); err != nil {
		t.Fatalf("decode deploy configuration: %v", err)
	}
	if configuration.Repository != "TerraScale/TerraScale.Orchestrator" {
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
	assertCommand(t, byName["artifact"].Commands, 0, "bash", ".terrascale/build-artifacts.sh", "artifacts/orchestrator")
}

func TestArtifactScriptContainsBothArchitecturesAndRequiredFiles(t *testing.T) {
	script := readRepositoryFile(t, ".terrascale", "build-artifacts.sh")
	requireContains(t, script,
		"GOOS=linux GOARCH=\"$goarch\" go build -trimpath -o \"$output/$directory/terrascale-orchestrator\" ./cmd/orchestrator",
		"GOOS=linux GOARCH=\"$goarch\" go build -trimpath -o \"$output/$directory/ts-node\" ./cmd/ts-node",
		"GOOS=linux GOARCH=\"$goarch\" go build -trimpath -o \"$output/$directory/orchestrator-tooling\" ./tools/orchestrator-tooling",
		"build_architecture amd64 linux-x64",
		"build_architecture arm64 linux-arm64",
		"seccomp/terrascale-default-v1.json",
		"artifact file set mismatch",
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
