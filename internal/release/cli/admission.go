package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/githubapi"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

const (
	maxGitHubRunDetailBytes = 64 << 10
	maxGitHubLogsBytes      = 32 << 20
)

type githubRunDetail struct {
	RunID     int64             `json:"run_id"`
	RunNumber int64             `json:"run_number"`
	HeadSHA   string            `json:"head_sha"`
	Workflow  string            `json:"workflow"`
	Status    string            `json:"status"`
	Jobs      []githubJobDetail `json:"jobs"`
}

type githubJobDetail struct {
	ID      int64  `json:"id"`
	RunID   int64  `json:"run_id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Attempt int64  `json:"attempt"`
}

func readQualification(path string) (release.Qualification, string, error) {
	wire, err := readBoundedRegular(path, release.MaxQualificationBytes)
	if err != nil {
		return release.Qualification{}, "", err
	}
	return release.DecodeQualification(wire)
}

// verifyGitHubQualification checks the GitHub run and its exact job logs. The
// result binds the successful check to the full source SHA and API run ID.
// The job's immutable log marker binds the exact retained manifest bytes.
func (c command) verifyGitHubQualification(qualification release.Qualification, qualificationSHA256 string) error {
	ctx, cancel := context.WithTimeout(c.ctx, time.Minute)
	defer cancel()
	output, err := githubapi.RunDetail(qualification.Repository, qualification.Verification.RunID,
		func(args ...string) ([]byte, error) { return exec.CommandContext(ctx, "gh", args...).Output() })
	if err != nil {
		return fmt.Errorf("query exact GitHub run: %w", err)
	}
	if len(output) == 0 || len(output) > maxGitHubRunDetailBytes {
		return errors.New("GitHub run detail is empty or exceeds size limit")
	}
	job, err := matchGitHubRunDetail(output, qualification)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "gh", "api", "--hostname", "github.com", "repos/"+qualification.Repository+"/actions/jobs/"+strconv.FormatInt(job.ID, 10)+"/logs")
	logs, err := command.Output()
	if err != nil {
		return fmt.Errorf("query exact GitHub job logs: %w", err)
	}
	if len(logs) == 0 || len(logs) > maxGitHubLogsBytes {
		return errors.New("GitHub job logs are empty or exceed size limit")
	}
	return matchGitHubQualificationLog(logs, qualification, qualificationSHA256)
}

func matchGitHubRunDetail(output []byte, qualification release.Qualification) (githubJobDetail, error) {
	var detail githubRunDetail
	if err := protocol.DecodeStrict(output, &detail, maxGitHubRunDetailBytes); err != nil {
		return githubJobDetail{}, fmt.Errorf("decode GitHub run detail: %w", err)
	}
	if detail.RunID != qualification.Verification.RunID ||
		detail.RunNumber != qualification.Verification.RunNumber ||
		detail.HeadSHA != qualification.SourceRevision ||
		detail.Workflow != qualification.Verification.Workflow || detail.Status != "success" {
		return githubJobDetail{}, errors.New("GitHub run ID, number, full source, workflow, or status differs from qualification")
	}
	var job githubJobDetail
	matched := false
	for _, candidate := range detail.Jobs {
		if candidate.Name != qualification.Verification.Job {
			continue
		}
		if matched {
			return githubJobDetail{}, errors.New("GitHub verification run has duplicate required jobs")
		}
		job, matched = candidate, true
	}
	if job.ID <= 0 || job.RunID != detail.RunID || job.Name != qualification.Verification.Job ||
		job.Status != "success" || job.Attempt <= 0 {
		return githubJobDetail{}, errors.New("required GitHub job has no successful result bound to the run")
	}
	return job, nil
}

func matchGitHubQualificationLog(logs []byte, qualification release.Qualification, qualificationSHA256 string) error {
	marker := fmt.Sprintf("TS_RELEASE_QUALIFICATION_V1 source_sha=%s run_id=%d run_number=%d manifest_sha256=%s",
		qualification.SourceRevision, qualification.Verification.RunID,
		qualification.Verification.RunNumber, qualificationSHA256)
	count := 0
	for line := range strings.SplitSeq(string(logs), "\n") {
		stamp, payload, ok := strings.Cut(strings.TrimSuffix(line, "\r"), " ")
		if !ok || payload != marker {
			continue
		}
		if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
			return fmt.Errorf("GitHub qualification marker has invalid log timestamp: %w", err)
		}
		count++
	}
	if count != 1 {
		return errors.New("GitHub verification log must contain one exact retained qualification digest")
	}
	return nil
}

// runDetail exposes the same attempt-pinned proof to image and release scripts.
func (c command) runDetail(args []string) error {
	flags := flag.NewFlagSet("run-detail", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	repository := flags.String("repository", "", "GitHub owner/repository")
	runID := flags.Int64("run-id", 0, "GitHub Actions run ID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("run-detail accepts only --repository and --run-id")
	}
	ctx, cancel := context.WithTimeout(c.ctx, time.Minute)
	defer cancel()
	data, err := githubapi.RunDetail(*repository, *runID, func(args ...string) ([]byte, error) { return exec.CommandContext(ctx, "gh", args...).Output() })
	if err != nil {
		return err
	}
	_, err = c.output.Write(append(data, '\n'))
	return err
}
