package mesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func (a swarmApplier) Bake(ctx context.Context, spec swarmruntime.ServiceSpec, ready swarmruntime.ServiceRollout) (rollout.BakeVerdict, error) {
	var logs []*bakeLog
	var initial error
	if spec.Name == "terrabase" {
		for _, task := range ready.Tasks {
			for _, stream := range []string{"stdout", "stderr"} {
				log := &bakeLog{path: swarmruntime.RuntimeLogFile(a.state, task.TaskID, stream)}
				initial = errors.Join(initial, log.check())
				logs = append(logs, log)
			}
		}
	}
	transport := &http.Transport{MaxResponseHeaderBytes: 8 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return rollout.RunBake(ctx, func(ctx context.Context) (map[string]string, error) {
		checks := map[string]string{}
		if initial != nil {
			checks["terrabase-logs"] = initial.Error()
			return checks, initial
		}
		control, close, err := a.control()
		if err != nil {
			checks["candidate"] = "control-unavailable"
			return checks, errors.New("bake candidate control unavailable")
		}
		defer close()
		current, err := swarmruntime.ProbeServiceSpecExact(ctx, control, spec)
		if failure := candidateUnready(spec.Name, err); failure != nil {
			checks["candidate"] = failure.Status
			return checks, failure
		}
		if err != nil || !bakeSameTasks(ready.Tasks, current.Tasks) {
			checks["candidate"] = "changed-or-not-ready"
			return checks, errors.New("bake candidate changed or is not ready")
		}
		checks["candidate"] = "ok"
		for _, log := range logs {
			if err := log.check(); err != nil {
				checks["terrabase-logs"] = err.Error()
				return checks, err
			}
		}
		if len(logs) != 0 {
			checks["terrabase-logs"] = "ok"
			waits := 0
			for _, log := range logs {
				waits += log.waits
			}
			if waits != 0 {
				checks["terrabase-writer-waits"] = strconv.Itoa(waits) + " under " + strconv.FormatFloat(severeWriterWait, 'f', -1, 64) + " s"
			}
		}
		if !judgesDependencies(spec.Name) {
			return checks, nil
		}
		local, err := localDependencies(ctx, control, spec.Name)
		if err != nil {
			checks["dependencies"] = "control-unavailable"
			return checks, errors.New("bake dependency placement unavailable")
		}
		return checks, bakeDependencies(ctx, client, checks, a.region, local)
	})
}

// candidateUnready is a running candidate whose application readiness failed.
// The dashboard's readiness includes ts-auth, so a briefly unready candidate
// recovers within the same window as a dependency; anything else about the
// candidate (replaced, superseded, absent) stays fatal.
func candidateUnready(service string, err error) *rollout.DependencyFailure {
	var notReady *swarmruntime.TaskReadinessError
	if !errors.As(err, &notReady) {
		return nil
	}
	return &rollout.DependencyFailure{Service: service, Status: notReady.Status}
}

// judgesDependencies is true for what ts-auth and ts-dashboard readiness
// depends on. Only these bakes judge that readiness: no other service can
// change it, and a concurrent ts-auth, dashboard or TerraBase rollout in gru
// must not fail whoami or app-canary in sjc and fra.
func judgesDependencies(service string) bool {
	return slices.Contains([]string{"terrabase", "ts-auth", "ts-dashboard"}, service)
}

// localDependencies are the ts-auth and ts-dashboard services this region
// runs, other than service: readiness served from another region cannot
// judge this candidate (gru's restarts failed sjc and fra TerraBase bakes),
// and the candidate's own readiness is its task readiness.
func localDependencies(ctx context.Context, control api.ControlClient, service string) ([]string, error) {
	dependencies := []string{"ts-auth", "ts-dashboard"}
	listed, err := control.ListServices(ctx, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: dependencies}})
	if err != nil {
		return nil, err
	}
	var local []string
	for _, listed := range listed.Services {
		if name := listed.Spec.Annotations.Name; name != service && slices.Contains(dependencies, name) {
			local = append(local, name)
		}
	}
	slices.Sort(local)
	return slices.Compact(local), nil
}

func bakeDependencies(ctx context.Context, client *http.Client, checks map[string]string, region string, services []string) error {
	var failures error
	for _, service := range services {
		checks[service] = bakeDependency(ctx, client, region, service)
		if checks[service] != "ok" && !strings.HasPrefix(checks[service], "served by ") {
			failures = errors.Join(failures, &rollout.DependencyFailure{Service: service, Status: checks[service]})
		}
	}
	return failures
}

func bakeSameTasks(before, now []swarmruntime.ServiceTaskEvidence) bool {
	ids := func(tasks []swarmruntime.ServiceTaskEvidence) []string {
		result := make([]string, 0, len(tasks))
		for _, task := range tasks {
			if task.TaskID == "" {
				return nil
			}
			result = append(result, task.TaskID)
		}
		slices.Sort(result)
		return result
	}
	a, b := ids(before), ids(now)
	return len(a) != 0 && len(slices.Compact(slices.Clone(a))) == len(a) && slices.Equal(a, b)
}

// bakeDependency is "served by <region>" when another region answered: its
// readiness cannot judge this region's candidate.
func bakeDependency(ctx context.Context, client *http.Client, region, service string) string {
	endpoint := "https://auth.terrascale.tech/readyz"
	if service == "ts-dashboard" {
		endpoint = "https://dash.terrascale.tech/readyz"
	} else if service != "ts-auth" {
		return "unsupported-service"
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	response, err := client.Do(request)
	if err != nil {
		return "request-failed"
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	var status struct {
		Status       string
		Region       string
		Dependencies map[string]string
	}
	parsed := err == nil && len(body) <= 16<<10 && json.Unmarshal(body, &status) == nil
	if parsed && status.Region != "" && status.Region != region {
		return "served by " + status.Region
	}
	if response.StatusCode != http.StatusOK {
		return "HTTP " + strconv.Itoa(response.StatusCode)
	}
	if !parsed {
		return "invalid-readiness-body"
	}
	if service == "ts-auth" && status.Status == "ready" || service == "ts-dashboard" && status.Status == "ok" && status.Dependencies["ts-auth"] == "ok" && status.Dependencies["terrabase"] == "ok" {
		return "ok"
	}
	return "dependency-unavailable-or-missing"
}

type bakeLog struct {
	path   string
	info   os.FileInfo
	offset int64
	sum    [32]byte
	// waits counts tolerated writer waits (under severeWriterWait).
	waits int
}

// severeWriterWait is the writer wait that fails a TerraBase bake. TerraBase
// logs every wait from 5 s. On gru the serving release already waited
// 5.1-5.7 s every 5-10 minutes, and each swap's catch-up added a burst of
// 5.0-6.2 s waits (2026-10-27), so failing on any wait failed every gru roll
// whatever the candidate did. Shorter waits are counted in the verdict.
const severeWriterWait = 10.0

// Keep only offsets and a checkpoint hash; never retain or report log contents.
func (l *bakeLog) check() error {
	f, err := os.Open(l.path)
	if err != nil {
		return errors.New("bake TerraBase logs unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("bake TerraBase logs unreadable")
	}
	first := l.info == nil
	if first {
		l.info, l.offset = info, info.Size()
	}
	if !os.SameFile(l.info, info) || info.Size() < l.offset || info.Size()-l.offset > 1<<20 {
		return errors.New("bake TerraBase log coverage lost")
	}
	checkpoint, err := io.ReadAll(io.NewSectionReader(f, max(0, l.offset-64), min(64, l.offset)))
	if err != nil || int64(len(checkpoint)) != min(64, l.offset) || !first && sha256.Sum256(checkpoint) != l.sum {
		return errors.New("bake TerraBase log coverage lost")
	}
	data, err := io.ReadAll(io.NewSectionReader(f, l.offset, info.Size()-l.offset))
	if err != nil || int64(len(data)) != info.Size()-l.offset {
		return errors.New("bake TerraBase logs unreadable")
	}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		var record struct {
			Msg    string // Production JSON uses "msg"; decoding is case insensitive.
			Waited *float64
		}
		message := string(line)
		if json.Unmarshal(line, &record) == nil {
			message = record.Msg
		}
		if strings.Contains(message, "catalog anchor could not be") {
			return errors.New("bake TerraBase catalog anchor failure")
		}
		if strings.HasPrefix(message, "Waited ") && strings.Contains(message, " s for a database's writer ") {
			if waited, ok := writerWait(message, record.Waited); !ok || waited >= severeWriterWait {
				return errors.New("bake TerraBase writer wait regression")
			}
			l.waits++
		}
	}
	l.offset += int64(bytes.LastIndexByte(data, '\n') + 1)
	checkpoint, err = io.ReadAll(io.NewSectionReader(f, max(0, l.offset-64), min(64, l.offset)))
	l.sum = sha256.Sum256(checkpoint)
	if err != nil || int64(len(checkpoint)) != min(64, l.offset) {
		return errors.New("bake TerraBase logs unreadable")
	}
	return nil
}

// writerWait reads the seconds of a writer wait record: the structured
// Waited field, or the number a rendered message starts with.
func writerWait(message string, field *float64) (float64, bool) {
	if field != nil {
		return *field, true
	}
	value, _, _ := strings.Cut(strings.TrimPrefix(message, "Waited "), " ")
	waited, err := strconv.ParseFloat(value, 64)
	return waited, err == nil
}
