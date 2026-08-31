package cicontract_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

type deployConfiguration struct {
	Repository string    `json:"repository"`
	Profiles   []profile `json:"prProfiles"`
}

type profile struct {
	Name           string    `json:"name"`
	ResourceWeight string    `json:"resourceWeight"`
	Commands       []command `json:"commands"`
}

type command struct {
	Command   string   `json:"command"`
	Arguments []string `json:"arguments"`
}

func TestPushWorkflowHasFailClosedDeployBootstrap(t *testing.T) {
	workflow := readRepositoryFile(t, ".forgejo", "workflows", "ci.yml")
	if err := validatePushOnlyWorkflow(workflow); err != nil {
		t.Fatalf("validate workflow triggers: %v", err)
	}
	requireContains(t, workflow,
		"  contents: read",
		"TS_DEPLOY_REVISION: \"PENDING_DEP1_GREEN_COMMIT\"",
		"TS_DEPLOY_EXPECTED_TREE: \"PENDING_DEP1_GREEN_TREE\"",
		"TERRASCALE_DEPLOY_REPOSITORY_READ_TOKEN",
		"GIT_CONFIG_GLOBAL=\"${git_config_global}\"",
		"GIT_ASKPASS=\"${askpass}\"",
		"chmod 600 \"${git_config_global}\"",
		"chmod 700 \"${askpass}\"",
		"trap cleanup EXIT",
		"fetch --no-tags --depth=1",
		"rev-parse HEAD^{tree}",
		"go build -trimpath -o \"${GOBIN}/terrascale-deploy\" ./cmd/terrascale-deploy",
		"--require-clean-source",
		"needs: [bootstrap, plan, static, build, test]",
		"name: orchestrator-linux-amd64-arm64",
		"path: artifacts/orchestrator",
	)
	for _, forbidden := range []string{
		"TS_DEPLOY_READ_TOKEN",
		"bf9703f",
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

	for _, line := range strings.Split(workflow, "\n") {
		if !strings.Contains(line, "- uses:") {
			continue
		}
		at := strings.LastIndex(line, "@")
		pin := strings.TrimSpace(line[at+1:])
		if at < 0 || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(pin) {
			t.Fatalf("every action must use a full commit pin: %q", line)
		}
	}
}

func TestWorkflowTriggerValidation(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name     string
		workflow string
	}{
		{
			name: "block",
			workflow: `on:
  push:
    branches:
      - develop
      - main
`,
		},
		{
			name:     "quoted inline and comments",
			workflow: "# pull_request: must not be a trigger\n\"on\": {\"push\": {\"branches\": [\"main\", \"develop\"]}}\nnote: 'pull_request_target: is scalar text'\n",
		},
	}
	for _, test := range valid {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validatePushOnlyWorkflow(test.workflow); err != nil {
				t.Fatalf("valid workflow rejected: %v", err)
			}
		})
	}

	invalid := []struct {
		name     string
		workflow string
	}{
		{
			name:     "pull request block",
			workflow: "on:\n  push: {branches: [develop, main]}\n  pull_request: {}\n",
		},
		{
			name:     "quoted pull request",
			workflow: "on:\n  push: {branches: [develop, main]}\n  'pull_request': {}\n",
		},
		{
			name:     "spaced pull request",
			workflow: "on:\n  push: {branches: [develop, main]}\n  pull_request : {}\n",
		},
		{
			name:     "inline pull request",
			workflow: "on: {push: {branches: [develop, main]}, pull_request: {}}\n",
		},
		{
			name:     "pull request target",
			workflow: "on: {push: {branches: [develop, main]}, pull_request_target: {}}\n",
		},
		{
			name:     "quoted pull request target",
			workflow: "on: {push: {branches: [develop, main]}, \"pull_request_target\": {}}\n",
		},
		{
			name:     "spaced pull request target",
			workflow: "on:\n  push: {branches: [develop, main]}\n  pull_request_target : {}\n",
		},
		{
			name:     "event scalar",
			workflow: "on: 'push: {branches: [develop, main]}'\n",
		},
		{
			name:     "missing main branch",
			workflow: "on: {push: {branches: [develop]}}\n",
		},
		{
			name:     "extra branch",
			workflow: "on: {push: {branches: [develop, main, release]}}\n",
		},
		{
			name:     "wildcard branch scalar",
			workflow: "on: {push: {branches: '*'}}\n",
		},
	}
	for _, test := range invalid {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validatePushOnlyWorkflow(test.workflow); err == nil {
				t.Fatal("invalid workflow accepted")
			}
		})
	}
}

func validatePushOnlyWorkflow(workflow string) error {
	decoder := yaml.NewDecoder(strings.NewReader(workflow))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("workflow must contain exactly one YAML document")
		}
		return fmt.Errorf("decode trailing YAML: %w", err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return errors.New("workflow root must be one YAML document")
	}

	root, err := yamlStringMap(document.Content[0], "workflow root")
	if err != nil {
		return err
	}
	eventsNode, ok := root["on"]
	if !ok {
		return errors.New("workflow is missing the on mapping")
	}
	events, err := yamlStringMap(eventsNode, "on")
	if err != nil {
		return err
	}
	if len(events) != 1 {
		return fmt.Errorf("on must contain only push, found %v", sortedNodeKeys(events))
	}
	pushNode, ok := events["push"]
	if !ok {
		return errors.New("on must contain push")
	}
	push, err := yamlStringMap(pushNode, "on.push")
	if err != nil {
		return err
	}
	if len(push) != 1 {
		return fmt.Errorf("on.push must contain only branches, found %v", sortedNodeKeys(push))
	}
	branchesNode, ok := push["branches"]
	if !ok {
		return errors.New("on.push is missing branches")
	}
	if branchesNode.Kind != yaml.SequenceNode {
		return errors.New("on.push.branches must be a sequence")
	}
	branches := make([]string, 0, len(branchesNode.Content))
	for _, branch := range branchesNode.Content {
		if branch.Kind != yaml.ScalarNode || branch.Tag != "!!str" {
			return errors.New("every on.push.branches entry must be a string")
		}
		branches = append(branches, branch.Value)
	}
	slices.Sort(branches)
	if !slices.Equal(branches, []string{"develop", "main"}) {
		return fmt.Errorf("on.push.branches must be exactly develop and main, found %v", branches)
	}
	return nil
}

func yamlStringMap(node *yaml.Node, path string) (map[string]*yaml.Node, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s must be a mapping", path)
	}
	entries := make(map[string]*yaml.Node, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return nil, fmt.Errorf("%s contains a non-string key", path)
		}
		if _, exists := entries[key.Value]; exists {
			return nil, fmt.Errorf("%s contains duplicate key %q", path, key.Value)
		}
		entries[key.Value] = node.Content[index+1]
	}
	return entries, nil
}

func sortedNodeKeys(values map[string]*yaml.Node) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func TestDeployBootstrapAskpassAuthenticatesAndCleansUp(t *testing.T) {
	workflow := readRepositoryFile(t, ".forgejo", "workflows", "ci.yml")
	askpassBody := extractAskpassBody(t, workflow)
	tempDir := t.TempDir()
	harnessPath := filepath.Join(tempDir, "askpass-harness.sh")
	harness := `#!/usr/bin/env bash
set -euo pipefail
umask 077
git_config_global="${RUNNER_TEMP}/terrascale-deploy-gitconfig"
askpass="${RUNNER_TEMP}/terrascale-deploy-askpass"
cleanup() {
  rm -f -- "${git_config_global}" "${askpass}"
}
trap cleanup EXIT
: >"${git_config_global}"
chmod 600 "${git_config_global}"
cat >"${askpass}" <<'EOF'
` + askpassBody + `
EOF
chmod 700 "${askpass}"
test -x "${askpass}"
printf 'protocol=https\nhost=example.invalid\n\n' |
  GIT_CONFIG_GLOBAL="${git_config_global}" GIT_CONFIG_NOSYSTEM=1 GIT_ASKPASS="${askpass}" GIT_TERMINAL_PROMPT=0 \
  git -c credential.helper= credential fill
`
	if err := os.WriteFile(harnessPath, []byte(harness), 0o700); err != nil {
		t.Fatalf("write askpass harness: %v", err)
	}
	const token = "x8-regression-token-do-not-log"
	command := exec.Command(harnessPath)
	command.Dir = tempDir
	command.Env = append(os.Environ(),
		"RUNNER_TEMP="+tempDir,
		"TERRASCALE_DEPLOY_REPOSITORY_READ_TOKEN="+token,
		"HOME="+tempDir,
	)
	var stderr strings.Builder
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("askpass authentication harness failed: %v", err)
	}
	outputText := string(output)
	if !strings.Contains(outputText, "username=x-access-token") || !strings.Contains(outputText, "password="+token) {
		t.Fatal("git did not receive the expected username and password from the executable askpass helper")
	}
	if strings.Contains(stderr.String(), token) {
		t.Fatal("askpass token was written to stderr")
	}
	for _, path := range []string{
		filepath.Join(tempDir, "terrascale-deploy-gitconfig"),
		filepath.Join(tempDir, "terrascale-deploy-askpass"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("credential bootstrap temporary file was not cleaned up: %s (%v)", path, err)
		}
	}
	err = filepath.WalkDir(tempDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), token) {
			t.Fatalf("askpass token persisted in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect askpass temporary files: %v", err)
	}
}

func extractAskpassBody(t *testing.T, workflow string) string {
	t.Helper()
	return extractHeredocBody(t, workflow, "          cat >\"${askpass}\" <<'EOF'\n")
}

func extractHeredocBody(t *testing.T, workflow, startMarker string) string {
	t.Helper()
	const endMarker = "\n          EOF"
	start := strings.Index(workflow, startMarker)
	if start < 0 {
		t.Fatal("workflow askpass heredoc is missing")
	}
	start += len(startMarker)
	end := strings.Index(workflow[start:], endMarker)
	if end < 0 {
		t.Fatal("workflow askpass heredoc terminator is missing")
	}
	indentedBody := workflow[start : start+end]
	const indent = "          "
	lines := strings.Split(indentedBody, "\n")
	for index, line := range lines {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, indent) {
			t.Fatalf("askpass heredoc line %d has unexpected indentation", index+1)
		}
		lines[index] = strings.TrimPrefix(line, indent)
	}
	return strings.Join(lines, "\n")
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
	if byName["static"].ResourceWeight != "light" || byName["build"].ResourceWeight != "medium" ||
		byName["test"].ResourceWeight != "heavy" || byName["artifact"].ResourceWeight != "heavy" {
		t.Fatal("profile resource weights changed")
	}

	assertCommandCount(t, byName["static"], 2)
	assertCommand(t, byName["static"].Commands, 0, "bash", "-c", `test -z "$(gofmt -l .)"`)
	assertCommand(t, byName["static"].Commands, 1, "go", "vet", "./...")
	assertCommandCount(t, byName["build"], 1)
	assertCommand(t, byName["build"].Commands, 0, "go", "build", "./...")
	assertCommandCount(t, byName["test"], 2)
	assertCommand(t, byName["test"].Commands, 0, "go", "test", "./...")
	assertCommand(t, byName["test"].Commands, 1, "go", "test", "-race", "./...")
	assertCommandCount(t, byName["artifact"], 1)
	assertCommand(t, byName["artifact"].Commands, 0, "bash", ".terrascale/build-artifacts.sh", "artifacts/orchestrator")
}

func TestArtifactScriptContract(t *testing.T) {
	scriptPath := repositoryPath(".terrascale", "build-artifacts.sh")
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatalf("stat artifact script: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("artifact script is not executable")
	}

	script := readRepositoryFile(t, ".terrascale", "build-artifacts.sh")
	requireContains(t, script,
		"refusing symlinked artifact output component",
		"GOOS=linux GOARCH=\"$goarch\" go build -trimpath -o \"$output/$directory/terrascale-orchestrator\" ./cmd/orchestrator",
		"GOOS=linux GOARCH=\"$goarch\" go build -trimpath -o \"$output/$directory/ts-node\" ./cmd/ts-node",
		"GOOS=linux GOARCH=\"$goarch\" go build -trimpath -o \"$output/$directory/orchestrator-tooling\" ./tools/orchestrator-tooling",
		"build_architecture amd64 linux-x64",
		"build_architecture arm64 linux-arm64",
		"seccomp/terrascale-default-v1.json",
		"artifact file set mismatch",
	)
}

func TestArtifactScriptRejectsUnsafeOutputPaths(t *testing.T) {
	repositoryRoot, err := filepath.Abs(repositoryPath())
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	script := filepath.Join(repositoryRoot, ".terrascale", "build-artifacts.sh")
	for _, output := range []string{
		"",
		"artifacts/",
		"artifacts/../escape",
		"artifacts/./escape",
		"artifacts//escape",
		"artifacts/orchestrator/../../escape",
		"/tmp/escape",
	} {
		output := output
		t.Run(output, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, script, output)
			command.Dir = repositoryRoot
			runErr := command.Run()
			if runErr == nil {
				t.Fatalf("artifact builder accepted unsafe output %q", output)
			}
			if ctx.Err() != nil {
				t.Fatalf("artifact builder did not reject %q promptly: %v", output, ctx.Err())
			}
			exitError, ok := runErr.(*exec.ExitError)
			if !ok || exitError.ExitCode() != 2 {
				t.Fatalf("artifact builder rejected %q with %v, want exit code 2", output, runErr)
			}
		})
	}
}

func TestRetiredCIDefinitionsAreAbsent(t *testing.T) {
	for _, elements := range [][]string{{".terrascale", "ci-v2.json"}, {".terrascale", "ci.Dockerfile"}} {
		path := repositoryPath(elements...)
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("retired CI definition still exists at %s: %v", path, err)
		}
	}
}

func assertCommandCount(t *testing.T, profile profile, want int) {
	t.Helper()
	if len(profile.Commands) != want {
		t.Fatalf("profile %q has %d commands, want %d", profile.Name, len(profile.Commands), want)
	}
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

func repositoryPath(elements ...string) string {
	return filepath.Join(append([]string{"..", ".."}, elements...)...)
}

func readRepositoryFile(t *testing.T, elements ...string) string {
	t.Helper()
	path := repositoryPath(elements...)
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
