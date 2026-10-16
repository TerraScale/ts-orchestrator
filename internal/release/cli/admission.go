package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

const (
	maxForgejoRunDetailBytes = 64 << 10
	maxForgejoLogsBytes      = 32 << 20
)

type forgejoRunDetail struct {
	RunID     int64              `json:"run_id"`
	RunNumber int64              `json:"run_number"`
	HeadSHA   string             `json:"head_sha"`
	Workflow  string             `json:"workflow"`
	Status    string             `json:"status"`
	Jobs      []forgejoJobDetail `json:"jobs"`
}

type forgejoJobDetail struct {
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

// verifyForgejoQualification uses the pinned fj run-detail extension. The
// result binds the successful check to the full source SHA and API run ID.
// The job's immutable log marker binds the exact retained manifest bytes.
func (c command) verifyForgejoQualification(qualification release.Qualification, qualificationSHA256 string) error {
	ctx, cancel := context.WithTimeout(c.ctx, time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "fj", "actions", "run-detail",
		strconv.FormatInt(qualification.Verification.RunNumber, 10), "-r", qualification.Repository)
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("query exact Forgejo run with fj: %w", err)
	}
	if len(output) == 0 || len(output) > maxForgejoRunDetailBytes {
		return errors.New("Forgejo run detail is empty or exceeds size limit")
	}
	job, err := matchForgejoRunDetail(output, qualification)
	if err != nil {
		return err
	}
	command = exec.CommandContext(ctx, "fj", "actions", "job-logs",
		strconv.FormatInt(job.ID, 10), "-r", qualification.Repository)
	logs, err := command.Output()
	if err != nil {
		return fmt.Errorf("query exact Forgejo job logs with fj: %w", err)
	}
	if len(logs) == 0 || len(logs) > maxForgejoLogsBytes {
		return errors.New("Forgejo job logs are empty or exceed size limit")
	}
	return matchForgejoQualificationLog(logs, qualification, qualificationSHA256)
}

func matchForgejoRunDetail(output []byte, qualification release.Qualification) (forgejoJobDetail, error) {
	var detail forgejoRunDetail
	if err := protocol.DecodeStrict(output, &detail, maxForgejoRunDetailBytes); err != nil {
		return forgejoJobDetail{}, fmt.Errorf("decode Forgejo run detail: %w", err)
	}
	if detail.RunID != qualification.Verification.RunID ||
		detail.RunNumber != qualification.Verification.RunNumber ||
		detail.HeadSHA != qualification.SourceRevision ||
		detail.Workflow != qualification.Verification.Workflow || detail.Status != "success" {
		return forgejoJobDetail{}, errors.New("Forgejo run ID, number, full source, workflow, or status differs from qualification")
	}
	var job forgejoJobDetail
	matched := false
	for _, candidate := range detail.Jobs {
		if candidate.Name != qualification.Verification.Job {
			continue
		}
		if matched {
			return forgejoJobDetail{}, errors.New("Forgejo verification run has duplicate required jobs")
		}
		job, matched = candidate, true
	}
	if job.ID <= 0 || job.RunID != detail.RunID || job.Name != qualification.Verification.Job ||
		job.Status != "success" || job.Attempt <= 0 {
		return forgejoJobDetail{}, errors.New("required Forgejo job has no successful result bound to the run")
	}
	return job, nil
}

func matchForgejoQualificationLog(logs []byte, qualification release.Qualification, qualificationSHA256 string) error {
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
			return fmt.Errorf("Forgejo qualification marker has invalid log timestamp: %w", err)
		}
		count++
	}
	if count != 1 {
		return errors.New("Forgejo verification log must contain one exact retained qualification digest")
	}
	return nil
}
