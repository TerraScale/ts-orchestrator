package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	staged "git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

const (
	terrabaseForgejoRepo = "TerraScale/TerraBase"
	terrabaseSourceRepo  = "https://git.terrascale.tech/TerraScale/TerraBase"
	cdActiveFile         = "cd-active.json"
	cdBlockedFile        = "cd-blocked.json"
	cdTransientFile      = "cd-transient.json"
)

// cdRetryPolicy bounds how a sync run treats transient rollout failures:
// retry the pinned candidate with backoff inside the run, keep the pin
// across runs, and block for review only once failures have persisted for
// BlockAfter, so a pair is never left mixed-version silently.
type cdRetryPolicy struct {
	Backoff    staged.Backoff
	BlockAfter time.Duration
	sleep      func(context.Context, time.Duration) error
}

var defaultCDRetryPolicy = cdRetryPolicy{
	Backoff:    staged.Backoff{Initial: 30 * time.Second, Max: 5 * time.Minute, Attempts: 4},
	BlockAfter: 6 * time.Hour,
}

// cdTransientRecord is the first transient failure of the pinned candidate.
type cdTransientRecord struct {
	Candidate terrabaseCDCandidate `json:"candidate"`
	FirstAt   time.Time            `json:"first_at"`
	Reason    string               `json:"reason"`
}

var cdTagPattern = regexp.MustCompile(`^ci-([0-9a-f]{40})-run-([1-9][0-9]*)$`)
var cdReceiptPattern = regexp.MustCompile(`^cd-complete-[0-9]{20}\.json$`)
var errCDNotAncestor = errors.New("source is not an ancestor")

type terrabaseCDCandidate struct {
	Generation          uint64 `json:"generation"`
	Tag                 string `json:"tag"`
	Commit              string `json:"commit"`
	RunID               uint64 `json:"run_id"`
	QualificationSHA256 string `json:"qualification_sha256"`
	BinarySHA256        string `json:"binary_sha256"`
	SourceSHA256        string `json:"source_sha256"`
}

// Each invocation performs one bounded scan/rollout. Scheduling and Bastion
// forwarding belong to the operator host, never to the controller or CI.
func runTerraBaseSync(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("operator terrabase-sync", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := flags.String("config", "", "operator role configuration")
	statePath := flags.String("state", "", "existing owner-only deployment state")
	checkout := flags.String("source-checkout", "", "full TerraBase checkout with the reviewed origin")
	actor := flags.String("compatibility-actor", "", "trusted compatibility signer actor")
	key := flags.String("compatibility-key", "", "owner-only compatibility signer key")
	wait := flags.Duration("wait", defaultUpdateSeatWait, "outcome wait per seat")
	soak := flags.Duration("soak", staged.DefaultSoak, "how long a promoted seat must keep serving before the next seat (0 disables)")
	assumeCompatible := flags.Bool("assume-compatibility", false, "certify releases without a compatibility declaration as compatible (unverified)")
	retries := flags.Int("transient-retries", defaultCDRetryPolicy.Backoff.Attempts, "in-run retries of a transient rollout failure")
	blockAfter := flags.Duration("transient-block-after", defaultCDRetryPolicy.BlockAfter, "block for review once transient failures persist this long")
	timeout := flags.Duration("timeout", time.Hour, "total scan/rollout deadline")
	var forwards operatorForwardFlags
	flags.Var(&forwards, "nats-forward", "PRIVATE_IP:4222=LOOPBACK_IP:PORT (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *config == "" || *statePath == "" || !filepath.IsAbs(*checkout) ||
		*actor == "" || *key == "" || *wait <= 0 || *timeout <= 0 || *soak < 0 || *retries < 0 || *blockAfter <= 0 {
		return errors.New("terrabase-sync requires --config, --state, --source-checkout, --compatibility-actor, --compatibility-key and positive deadlines")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	update := func(files terrabaseReleaseFiles) error {
		updateArgs := []string{"terrabase-update", "--config", *config, "--state", *statePath,
			"--qualification", files.Qualification, "--binary", files.Binary, "--source-digest", files.SourceDigest,
			"--compatibility-actor", *actor, "--compatibility-key", *key, "--wait", wait.String(), "--soak", soak.String()}
		if *assumeCompatible {
			updateArgs = append(updateArgs, "--assume-compatibility")
		}
		for original, destination := range forwards {
			updateArgs = append(updateArgs, "--nats-forward", original+"="+destination)
		}
		return runOperator(ctx, updateArgs, output)
	}
	policy := defaultCDRetryPolicy
	policy.Backoff.Attempts, policy.BlockAfter = *retries, *blockAfter
	return syncTerraBaseWithPolicy(ctx, *statePath, *checkout, cdCommand, update, output, policy)
}

type cdRunCommand func(context.Context, string, ...string) ([]byte, error)

// Bound subprocess output too: a broken CLI or huge job log cannot exhaust
// the operator. Private credentials stay in fj's profile, never arguments.
type cdCommandOutput struct{ buffer bytes.Buffer }

func (out *cdCommandOutput) Write(data []byte) (int, error) {
	if out.buffer.Len()+len(data) > 8<<20 {
		return 0, errors.New("continuous delivery command output exceeds 8 MiB")
	}
	return out.buffer.Write(data)
}

func cdCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.WaitDelay = time.Second
	var output cdCommandOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if exit, ok := errors.AsType[*exec.ExitError](err); ok && name == "git" &&
			len(args) > 2 && args[2] == "merge-base" && exit.ExitCode() == 1 {
			return nil, errCDNotAncestor
		}
		return nil, fmt.Errorf("%s continuous delivery command failed: %w", name, err)
	}
	return output.buffer.Bytes(), nil
}

func syncTerraBase(ctx context.Context, statePath, checkout string, run cdRunCommand,
	update func(terrabaseReleaseFiles) error, output io.Writer,
) error {
	return syncTerraBaseWithPolicy(ctx, statePath, checkout, run, update, output, defaultCDRetryPolicy)
}

func syncTerraBaseWithPolicy(ctx context.Context, statePath, checkout string, run cdRunCommand,
	update func(terrabaseReleaseFiles) error, output io.Writer, policy cdRetryPolicy,
) error {
	state, err := openDeployState(statePath)
	if err != nil {
		return err
	}
	// Lock the deployment, not a candidate: an overlapping timer must not
	// choose another release while the first is between its two seats.
	fd, err := syscall.Open(filepath.Join(statePath, "cd.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	lock := os.NewFile(uintptr(fd), "cd.lock")
	defer lock.Close()
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another TerraBase sync holds this deployment: %w", err)
	}
	var blocked struct {
		Candidate terrabaseCDCandidate `json:"candidate"`
		Reason    string               `json:"reason"`
	}
	if exists, err := state.readJSON(cdBlockedFile, &blocked); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("automatic rollout stopped for %s; review %s before resuming", blocked.Candidate.Tag, cdBlockedFile)
	}
	baseline, generation, err := cdBaseline(state)
	if err != nil {
		return err
	}
	var candidate terrabaseCDCandidate
	active, err := state.readJSON(cdActiveFile, &candidate)
	if err != nil {
		return err
	}
	if active && candidate.Generation == generation {
		// Completion was synced before a crash removing the active pin.
		var completed terrabaseCDCandidate
		_, err := state.readJSON(cdReceiptName(generation), &completed)
		if err != nil || completed != candidate {
			return errors.New("active release differs from its completion receipt")
		}
		return os.Remove(filepath.Join(statePath, cdActiveFile))
	}
	origin, err := run(ctx, "git", "-C", checkout, "remote", "get-url", "origin")
	if err != nil {
		return err
	}
	if url := strings.TrimSpace(string(origin)); !strings.EqualFold(url, terrabaseSourceRepo+".git") &&
		!strings.EqualFold(url, "ssh://git@git.terrascale.tech/TerraScale/TerraBase.git") &&
		!strings.EqualFold(url, "git@git.terrascale.tech:TerraScale/TerraBase.git") {
		return errors.New("TerraBase checkout origin differs from the reviewed repository")
	}
	if _, err := run(ctx, "git", "-C", checkout, "fetch", "origin", "main:refs/remotes/origin/main"); err != nil {
		return err
	}
	if _, err := run(ctx, "git", "-C", checkout, "merge-base", "--is-ancestor", baseline, "refs/remotes/origin/main"); err != nil {
		return fmt.Errorf("deployed TerraBase source is outside current main: %w", err)
	}
	if !active {
		candidate, err = discoverTerraBase(ctx, checkout, baseline, run)
		if err != nil {
			return err
		}
		if candidate.Tag == "" {
			return printJSON(output, terrabaseDeployStep{Step: "sync", Status: "current", Detail: baseline})
		}
		candidate.Generation = generation + 1
	}
	if candidate.Generation != generation+1 || !cdTagPattern.MatchString(candidate.Tag) ||
		candidate.Tag != fmt.Sprintf("ci-%s-run-%d", candidate.Commit, candidate.RunID) {
		return errors.New("invalid active continuous delivery pin")
	}
	if err := cdCheckAncestry(ctx, checkout, baseline, candidate.Commit, run); err != nil {
		return err
	}
	directory, err := os.MkdirTemp(statePath, ".cd-release-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	files := terrabaseReleaseFiles{Qualification: filepath.Join(directory, "qualification.json"),
		Binary: filepath.Join(directory, terrabaseServerArtifact), SourceDigest: filepath.Join(directory, "source-digest.json")}
	download := func(path string) error {
		if _, err := run(ctx, "fj", "release", "asset", "download", "-H", "https://git.terrascale.tech",
			"-r", terrabaseForgejoRepo, candidate.Tag, filepath.Base(path), "-o", path); err != nil {
			return fmt.Errorf("download %s for %s: %w", filepath.Base(path), candidate.Tag, err)
		}
		return nil
	}
	// Check publication readiness before downloading the much larger server.
	for _, path := range []string{files.Qualification, files.SourceDigest} {
		if err := download(path); err != nil {
			return err
		}
	}
	if err := cdVerifyPublication(ctx, files.Qualification, candidate, run); err != nil {
		return err
	}
	if err := download(files.Binary); err != nil {
		return err
	}
	release, err := loadTerraBaseRelease(files)
	if err != nil {
		return err
	}
	if release.Source.Repository != terrabaseSourceRepo || release.Source.Commit != candidate.Commit || release.CIRunID != candidate.RunID {
		return errors.New("TerraBase release does not match its selected repository, commit and run")
	}
	verified := candidate
	verified.QualificationSHA256, verified.BinarySHA256, verified.SourceSHA256 = release.QualificationSHA256, release.Digest, release.Source.TreeDigest
	if active && verified != candidate {
		return errors.New("published TerraBase assets changed after the rollout was pinned")
	}
	candidate = verified
	if _, err := state.ensureJSON(cdActiveFile, candidate); err != nil {
		return err
	}
	if err := updateWithRetries(ctx, policy, func() error { return update(files) }, output); err != nil {
		// An explicit interruption resumes the same pin next invocation. An
		// expired --timeout is a transient failure of this run: it counts
		// toward --transient-block-after, or a timeout shorter than the
		// rollout would keep a mixed-version deployment from ever escalating.
		timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
		if ctx.Err() != nil && !timedOut {
			return err
		}
		reason := err.Error()
		if timedOut {
			reason = "sync deadline expired: " + reason
		}
		if timedOut || staged.IsTransient(err) {
			// Keep the pin and resume it next run; escalate only once the
			// failure has outlived the bound.
			first, persistErr := cdTransientSince(state, candidate, reason)
			if persistErr != nil || time.Since(first) < policy.BlockAfter {
				return errors.Join(err, persistErr)
			}
			reason = fmt.Sprintf("transient failures persisted since %s: %s", first.Format(time.RFC3339), reason)
		}
		blocked.Candidate, blocked.Reason = candidate, reason
		_, persistErr := state.ensureJSON(cdBlockedFile, blocked)
		if persistErr == nil {
			// The stop marker carries the reason. Once a reviewer removes it,
			// a later transient failure starts a fresh window instead of
			// blocking again at once on this stale first failure.
			if removeErr := os.Remove(filepath.Join(statePath, cdTransientFile)); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				persistErr = removeErr
			}
		}
		return errors.Join(err, persistErr)
	}
	if err := os.Remove(filepath.Join(statePath, cdTransientFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := state.ensureJSON(cdReceiptName(candidate.Generation), candidate); err != nil {
		return err
	}
	return os.Remove(filepath.Join(statePath, cdActiveFile))
}

// updateWithRetries reruns a transiently failed update of the same pinned
// candidate with bounded backoff. Reruns resume from the controller's
// durable seat state, so a retry never repeats a completed seat.
func updateWithRetries(ctx context.Context, policy cdRetryPolicy, update func() error, output io.Writer) error {
	sleep := policy.sleep
	if sleep == nil {
		sleep = sleepContext
	}
	for attempt := 1; ; attempt++ {
		err := update()
		if err == nil || ctx.Err() != nil || !staged.IsTransient(err) {
			return err
		}
		delay, retry := policy.Backoff.Delay(attempt)
		if !retry {
			return err
		}
		if printErr := printJSON(output, terrabaseDeployStep{Step: "sync", Status: "retrying",
			Detail: fmt.Sprintf("attempt %d after %s: %v", attempt+1, delay, err)}); printErr != nil {
			return errors.Join(err, printErr)
		}
		if sleepErr := sleep(ctx, delay); sleepErr != nil {
			return errors.Join(err, sleepErr)
		}
	}
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// cdTransientSince returns when the pinned candidate first failed
// transiently, recording now on its first failure. A record for another
// candidate is replaced.
func cdTransientSince(state deployState, candidate terrabaseCDCandidate, reason string) (time.Time, error) {
	var record cdTransientRecord
	exists, err := state.readJSON(cdTransientFile, &record)
	if err != nil {
		return time.Time{}, err
	}
	if exists && record.Candidate == candidate {
		return record.FirstAt, nil
	}
	if exists {
		if err := os.Remove(filepath.Join(state.directory, cdTransientFile)); err != nil {
			return time.Time{}, err
		}
	}
	record = cdTransientRecord{Candidate: candidate, FirstAt: time.Now().UTC(), Reason: reason}
	if _, err := state.readOrCreateJSON(cdTransientFile, record); err != nil {
		return time.Time{}, err
	}
	return record.FirstAt, nil
}

func cdReceiptName(generation uint64) string {
	return fmt.Sprintf("cd-complete-%020d.json", generation)
}

func cdBaseline(state deployState) (string, uint64, error) {
	var initial delivery.ArtifactRecord
	if exists, err := state.readJSON(deployArtifactFile, &initial); err != nil {
		return "", 0, err
	} else if !exists {
		return "", 0, errors.New("continuous delivery requires the existing deployment artifact record")
	}
	if initial.Source.Repository != terrabaseSourceRepo || !gitCommitPattern.MatchString(initial.Source.Commit) {
		return "", 0, errors.New("deployment artifact is not from the reviewed TerraBase repository")
	}
	entries, err := os.ReadDir(state.directory)
	if err != nil {
		return "", 0, err
	}
	baseline, generation := initial.Source.Commit, uint64(0)
	for _, entry := range entries { // ReadDir sorts immutable receipt names.
		if !cdReceiptPattern.MatchString(entry.Name()) {
			continue
		}
		var completed terrabaseCDCandidate
		if _, err := state.readJSON(entry.Name(), &completed); err != nil {
			return "", 0, err
		}
		if completed.Generation != generation+1 || entry.Name() != cdReceiptName(completed.Generation) ||
			!gitCommitPattern.MatchString(completed.Commit) {
			return "", 0, errors.New("continuous delivery completion receipts are not a contiguous sequence")
		}
		baseline, generation = completed.Commit, completed.Generation
	}
	return baseline, generation, nil
}

func discoverTerraBase(ctx context.Context, checkout, baseline string, run cdRunCommand) (terrabaseCDCandidate, error) {
	listing, err := run(ctx, "fj", "release", "list", "-H", "https://git.terrascale.tech", "-r", terrabaseForgejoRepo, "--include-prerelease")
	if err != nil {
		return terrabaseCDCandidate{}, err
	}
	var selected terrabaseCDCandidate
	// fj wraps names in Unicode isolation marks even in minimal style. Parse
	// complete ci tag tokens only, never descriptions or shell commands.
	listingText := strings.NewReplacer("\u2068", "", "\u2069", "").Replace(string(listing))
	for line := range strings.SplitSeq(listingText, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		match := cdTagPattern.FindStringSubmatch(fields[0])
		if match == nil || match[1] == baseline {
			continue
		}
		runID, err := strconv.ParseUint(match[2], 10, 64)
		if err != nil {
			return selected, err
		}
		candidate := terrabaseCDCandidate{Tag: match[0], Commit: match[1], RunID: runID}
		if err := cdCheckAncestry(ctx, checkout, baseline, candidate.Commit, run); err != nil {
			// A rerun of old source, a side branch, or an unfetched release
			// cannot become an automatic downgrade.
			if errors.Is(err, errCDNotAncestor) {
				continue
			}
			return selected, err
		}
		if selected.Tag != "" {
			if selected.Commit == candidate.Commit && selected.RunID >= candidate.RunID {
				continue
			}
			if _, err := run(ctx, "git", "-C", checkout, "merge-base", "--is-ancestor", selected.Commit, candidate.Commit); err != nil {
				if errors.Is(err, errCDNotAncestor) {
					continue
				}
				return selected, err
			}
		}
		selected = candidate
	}
	return selected, nil
}

func cdCheckAncestry(ctx context.Context, checkout, baseline, candidate string, run cdRunCommand) error {
	for _, pair := range [][2]string{{baseline, candidate}, {candidate, "refs/remotes/origin/main"}} {
		if _, err := run(ctx, "git", "-C", checkout, "merge-base", "--is-ancestor", pair[0], pair[1]); err != nil {
			return fmt.Errorf("TerraBase source is outside the current main lineage: %w", err)
		}
	}
	return nil
}

func cdVerifyPublication(ctx context.Context, path string, candidate terrabaseCDCandidate, run cdRunCommand) error {
	wire, err := readBoundedConfigFile(path)
	if err != nil {
		return err
	}
	var qualification struct {
		Repository   string `json:"repository"`
		Verification struct {
			Workflow  string `json:"workflow"`
			Job       string `json:"job"`
			RunNumber uint64 `json:"run_number"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(wire, &qualification); err != nil {
		return err
	}
	if qualification.Repository != "TerraScale/TerraBase" || qualification.Verification.Workflow != "fast.yml" ||
		qualification.Verification.Job != "fast" || qualification.Verification.RunNumber == 0 {
		return errors.New("automatic TerraBase delivery requires a Fast-qualified publication")
	}
	detailWire, err := run(ctx, "fj", "actions", "run-detail", strconv.FormatUint(qualification.Verification.RunNumber, 10),
		"-H", "https://git.terrascale.tech", "-r", terrabaseForgejoRepo)
	if err != nil {
		return err
	}
	var detail struct {
		RunID     uint64 `json:"run_id"`
		RunNumber uint64 `json:"run_number"`
		HeadSHA   string `json:"head_sha"`
		Workflow  string `json:"workflow"`
		Status    string `json:"status"`
		Jobs      []struct {
			ID     uint64 `json:"id"`
			RunID  uint64 `json:"run_id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(detailWire, &detail); err != nil {
		return err
	}
	if detail.RunID != candidate.RunID || detail.RunNumber != qualification.Verification.RunNumber ||
		detail.HeadSHA != candidate.Commit || detail.Workflow != "fast.yml" || detail.Status != "success" {
		return errors.New("TerraBase publication run differs from its qualification or is not successful")
	}
	fast, publish, publishID := 0, 0, uint64(0)
	for _, job := range detail.Jobs {
		if job.RunID == candidate.RunID && job.Status == "success" && job.ID != 0 {
			switch job.Name {
			case "fast":
				fast++
			case "publish":
				publish++
				publishID = job.ID
			}
		}
	}
	if fast != 1 || publish != 1 {
		return errors.New("TerraBase publication lacks exactly one successful Fast and publish job")
	}
	logs, err := run(ctx, "fj", "actions", "job-logs", strconv.FormatUint(publishID, 10), "-H", "https://git.terrascale.tech", "-r", terrabaseForgejoRepo)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(wire)
	marker := fmt.Sprintf("TS_TERRABASE_QUALIFICATION_V2 source_sha=%s run_id=%d run_number=%d manifest_sha256=%x",
		candidate.Commit, candidate.RunID, detail.RunNumber, sum)
	if strings.Count(string(logs), marker) != 1 {
		return errors.New("TerraBase publish log does not bind the exact qualification bytes")
	}
	return nil
}
