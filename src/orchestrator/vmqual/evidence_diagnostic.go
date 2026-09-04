package vmqual

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

const maximumFailureDiagnosticExcerptBytes = 4096

// FailureDiagnostic is a structured, bounded observation of one VM's
// Firecracker console and metrics artifacts. It is collected before cleanup
// removes the journaled paths; it is not synthesized from an error string.
type FailureDiagnostic struct {
	VMID       string                    `json:"vmId"`
	Region     vmnet.RegionCode          `json:"region"`
	CapturedAt time.Time                 `json:"capturedAt"`
	Console    FailureDiagnosticArtifact `json:"console"`
	Metrics    FailureDiagnosticArtifact `json:"metrics"`
}

// FailureDiagnosticArtifact records the observed source state as well as a
// short tail. SHA256 covers all source bytes, whose producer-side size is
// independently bounded by sandboxvm.DiagnosticLimitBytes.
type FailureDiagnosticArtifact struct {
	Path          string `json:"path"`
	Present       bool   `json:"present"`
	SourceBytes   int64  `json:"sourceBytes"`
	CapturedBytes int    `json:"capturedBytes"`
	Truncated     bool   `json:"truncated"`
	SHA256        string `json:"sha256,omitempty"`
	Tail          string `json:"tail,omitempty"`
	Observation   string `json:"observation,omitempty"`
}

type failureDiagnosticTarget struct {
	id      string
	region  vmnet.RegionCode
	root    string
	console string
	metrics string
}

// CollectFailureDiagnostics reads only exact VM paths from the durable cleanup
// journal. One structured record is returned for every planned VM even when a
// failed launch never created its diagnostic files.
func (s *Stack) CollectFailureDiagnostics(ctx context.Context) ([]FailureDiagnostic, error) {
	if s == nil {
		return nil, errors.New("vmqual: diagnostic stack is nil")
	}
	if ctx == nil {
		return nil, errors.New("vmqual: diagnostic context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	targets := s.failureDiagnosticTargets()
	if len(targets) == 0 {
		return nil, errors.New("vmqual: cleanup journal contains no diagnostic targets")
	}
	report := make([]FailureDiagnostic, 0, len(targets))
	var captureErrs []error
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return report, errors.Join(errors.Join(captureErrs...), err)
		}
		captured := FailureDiagnostic{VMID: target.id, Region: target.region, CapturedAt: time.Now().UTC()}
		captured.Console, _ = captureFailureDiagnosticArtifact(target.root, target.console)
		captured.Metrics, _ = captureFailureDiagnosticArtifact(target.root, target.metrics)
		if captured.Console.Observation != "" {
			captureErrs = append(captureErrs, fmt.Errorf("vmqual: observe %s console: %s", target.id, captured.Console.Observation))
		}
		if captured.Metrics.Observation != "" {
			captureErrs = append(captureErrs, fmt.Errorf("vmqual: observe %s metrics: %s", target.id, captured.Metrics.Observation))
		}
		report = append(report, captured)
	}
	return report, errors.Join(captureErrs...)
}

func (s *Stack) failureDiagnosticTargets() []failureDiagnosticTarget {
	s.journalMu.Lock()
	defer s.journalMu.Unlock()
	if s.journal == nil {
		return nil
	}
	targets := make([]failureDiagnosticTarget, 0, len(s.journal.VMs))
	for _, resource := range s.journal.VMs {
		if resource.ID == "" {
			continue
		}
		targets = append(targets, failureDiagnosticTarget{
			id:      resource.ID,
			region:  vmnet.RegionCode(resource.Region),
			root:    resource.StateDir,
			console: resource.LogPath,
			metrics: resource.MetricsPath,
		})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].id < targets[j].id })
	return targets
}

func captureFailureDiagnosticArtifact(root, path string) (FailureDiagnosticArtifact, error) {
	artifact := FailureDiagnosticArtifact{Path: path}
	if path == "" {
		artifact.Observation = "path was not planned"
		return artifact, errors.New(artifact.Observation)
	}
	file, info, err := openFailureDiagnosticAt(root, path)
	if errors.Is(err, os.ErrNotExist) {
		artifact.Observation = "file was not created"
		return artifact, nil
	}
	if err != nil {
		artifact.Observation = boundedDiagnosticObservation(err)
		return artifact, err
	}
	defer file.Close()
	artifact.Present = true
	artifact.SourceBytes = info.Size()
	if info.Size() > sandboxvm.DiagnosticLimitBytes {
		err := fmt.Errorf("diagnostic exceeds producer limit: %d > %d", info.Size(), sandboxvm.DiagnosticLimitBytes)
		artifact.Observation = boundedDiagnosticObservation(err)
		return artifact, err
	}

	digest := sha256.New()
	hashed, err := io.Copy(digest, io.LimitReader(file, info.Size()))
	if err != nil {
		artifact.Observation = boundedDiagnosticObservation(err)
		return artifact, err
	}
	if hashed != info.Size() {
		err := errors.New("diagnostic source shrank while reading")
		artifact.Observation = boundedDiagnosticObservation(err)
		return artifact, err
	}
	artifact.SHA256 = hex.EncodeToString(digest.Sum(nil))

	start := info.Size() - maximumFailureDiagnosticExcerptBytes
	if start < 0 {
		start = 0
	}
	length := info.Size() - start
	tail := make([]byte, int(length))
	read, err := file.ReadAt(tail, start)
	if err != nil && !errors.Is(err, io.EOF) {
		artifact.Observation = boundedDiagnosticObservation(err)
		return artifact, err
	}
	tail = tail[:read]
	artifact.Tail = boundedValidUTF8(tail, maximumFailureDiagnosticExcerptBytes)
	artifact.CapturedBytes = len([]byte(artifact.Tail))
	artifact.Truncated = start > 0 || info.Size() == sandboxvm.DiagnosticLimitBytes
	return artifact, nil
}

func safeFailureDiagnosticInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if info.Mode().Perm() != 0600 || info.Size() < 0 || info.Size() > sandboxvm.DiagnosticLimitBytes {
		return false
	}
	return true
}

func boundedValidUTF8(payload []byte, maximum int) string {
	if maximum <= 0 || len(payload) == 0 {
		return ""
	}
	text := strings.ToValidUTF8(string(payload), "\uFFFD")
	if len(text) <= maximum {
		return text
	}
	text = text[:maximum]
	for len(text) > 0 && !utf8.ValidString(text) {
		text = text[:len(text)-1]
	}
	return text
}

func boundedDiagnosticObservation(err error) string {
	if err == nil {
		return ""
	}
	const maximum = 256
	observation := err.Error()
	if len(observation) <= maximum {
		return observation
	}
	return observation[:maximum-len("...[truncated]")] + "...[truncated]"
}
