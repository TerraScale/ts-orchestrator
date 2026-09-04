// The evidence record a lab requires before it may start, plus its validator.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// PreDeploymentEvidence is the evidence document; the JSON tags emit
// camelCase keys, as written by development-attest.
type PreDeploymentEvidence struct {
	SchemaVersion       int                               `json:"schemaVersion"`
	Result              string                            `json:"result"`
	SourceCommit        string                            `json:"sourceCommit"`
	BinarySha256        string                            `json:"binarySha256"`
	AuthorizedProfile   string                            `json:"authorizedProfile"`
	ExpiresAt           time.Time                         `json:"expiresAt"`
	ResourcePolicy      *PreDeploymentResourcePolicy      `json:"resourcePolicy"`
	TestInventory       []PreDeploymentTestModule         `json:"testInventory"`
	ProcessObservations []PreDeploymentProcessObservation `json:"processObservations"`
}

// PreDeploymentResourcePolicy is the resource policy the evidence declares.
type PreDeploymentResourcePolicy struct {
	AggregateMemoryLimitBytes  int64 `json:"aggregateMemoryLimitBytes"`
	ExecutionMemoryLimitBytes  int64 `json:"executionMemoryLimitBytes"`
	ReservedHeadroomBytes      int64 `json:"reservedHeadroomBytes"`
	MaximumParallelTestModules int   `json:"maximumParallelTestModules"`
	MaximumParallelTests       int   `json:"maximumParallelTests"`
	MaximumValidationProcesses int   `json:"maximumValidationProcesses"`
}

// PreDeploymentTestModule is one module's test inventory entry.
type PreDeploymentTestModule struct {
	Module               string `json:"module"`
	Tests                int    `json:"tests"`
	MaximumParallelTests int    `json:"maximumParallelTests"`
}

// PreDeploymentProcessObservation is one observed validation process.
type PreDeploymentProcessObservation struct {
	Name                 string `json:"name"`
	ProcessId            int    `json:"processId"`
	PeakMemoryBytes      int64  `json:"peakMemoryBytes"`
	PeakProcessCount     int    `json:"peakProcessCount"`
	DurationMilliseconds int64  `json:"durationMilliseconds"`
}

// RequirePreDeploymentEvidence verifies the evidence authorizes this lab
// profile on the exact source commit and binary.
func RequirePreDeploymentEvidence(ctx context.Context, evidenceFile string, workspaceRoot string, profile string) error {
	if strings.TrimSpace(evidenceFile) == "" {
		return errors.New("Lab startup requires --evidence with valid exact-tree pre-deployment evidence.")
	}
	if info, err := os.Stat(evidenceFile); err != nil || info.IsDir() {
		return errors.New("Lab startup requires --evidence with valid exact-tree pre-deployment evidence.")
	}

	content, err := os.ReadFile(evidenceFile)
	if err != nil {
		return err
	}
	var evidence *PreDeploymentEvidence
	if err := json.Unmarshal(content, &evidence); err != nil {
		return err
	}
	if evidence == nil {
		return errors.New("Pre-deployment evidence is empty.")
	}
	if evidence.SchemaVersion != 2 ||
		evidence.Result != "pass" ||
		evidence.AuthorizedProfile != profile ||
		!time.Now().Before(evidence.ExpiresAt) ||
		!evidence.HasBoundedValidationEvidence() {
		return errors.New("Pre-deployment evidence does not authorize this lab profile.")
	}

	repository := filepath.Join(workspaceRoot, "TerraScale.Orchestrator")
	commit, err := readPreDeploymentGit(ctx, repository, []string{"rev-parse", "HEAD"})
	if err != nil {
		return err
	}
	status, err := readPreDeploymentGit(ctx, repository, []string{"status", "--porcelain", "--untracked-files=all"})
	if err != nil {
		return err
	}
	if strings.TrimSpace(status) != "" {
		return errors.New("Pre-deployment evidence cannot authorize a dirty Orchestrator worktree.")
	}
	if strings.TrimSpace(commit) != evidence.SourceCommit {
		return errors.New("Pre-deployment evidence was produced for another source commit.")
	}

	executable, err := os.Executable()
	if err != nil {
		return errors.New("The current Orchestrator executable path is unavailable.")
	}
	// The hashed artifact is the executable itself.
	artifactFile, err := os.Open(executable)
	if err != nil {
		return err
	}
	defer artifactFile.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, artifactFile); err != nil {
		return err
	}
	if hex.EncodeToString(digest.Sum(nil)) != evidence.BinarySha256 {
		return errors.New("Pre-deployment evidence was produced for another binary.")
	}
	return nil
}

// HasBoundedValidationEvidence reports whether the evidence declares the
// bounded validation policy and its observations.
func (evidence *PreDeploymentEvidence) HasBoundedValidationEvidence() bool {
	const aggregateLimit = int64(24) * 1024 * 1024 * 1024
	const executionLimit = int64(20) * 1024 * 1024 * 1024
	const processLimit = 512
	policy := evidence.ResourcePolicy
	if policy == nil ||
		policy.AggregateMemoryLimitBytes != aggregateLimit ||
		policy.ExecutionMemoryLimitBytes != executionLimit ||
		policy.ReservedHeadroomBytes != aggregateLimit-executionLimit ||
		policy.MaximumParallelTestModules != 1 ||
		policy.MaximumParallelTests != 4 ||
		policy.MaximumValidationProcesses != processLimit ||
		len(evidence.TestInventory) != 5 ||
		len(evidence.ProcessObservations) != 8 {
		return false
	}
	modules := map[string]bool{}
	for _, item := range evidence.TestInventory {
		if item.Tests <= 0 || item.MaximumParallelTests != 4 {
			return false
		}
		modules[item.Module] = true
	}
	if len(modules) != 5 {
		return false
	}
	for _, item := range evidence.ProcessObservations {
		if item.ProcessId <= 0 ||
			item.PeakMemoryBytes <= 0 || item.PeakMemoryBytes > executionLimit ||
			item.PeakProcessCount <= 0 || item.PeakProcessCount > processLimit ||
			item.DurationMilliseconds < 0 {
			return false
		}
	}
	observed := map[string]bool{}
	for _, item := range evidence.ProcessObservations {
		observed[item.Name] = true
	}
	if len(observed) != 8 ||
		!observed["solution-restore"] ||
		!observed["solution-build"] ||
		!observed["orchestrator-policy-tooling-tests"] {
		return false
	}
	for module := range modules {
		if !observed[module] {
			return false
		}
	}
	return true
}

func readPreDeploymentGit(ctx context.Context, workingDirectory string, arguments []string) (string, error) {
	command := exec.Command("git", arguments...)
	command.Dir = workingDirectory
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			var exitError *exec.ExitError
			if errors.As(err, &exitError) {
				return "", fmt.Errorf("Git evidence check failed: %s", stderr.String())
			}
			return "", err
		}
		return stdout.String(), nil
	case <-ctx.Done():
		// Terminate the whole child tree before rethrowing, so a cancelled
		// evidence check never leaves a git child process behind.
		killProcessTree(command.Process.Pid)
		<-done
		return "", ctx.Err()
	}
}
