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
		if err != nil || !bakeSameTasks(ready.Tasks, current.Tasks) {
			checks["candidate"] = "changed-or-not-ready"
			return checks, errors.New("bake candidate changed or is not ready")
		}
		checks["candidate"] = "ok"
		for _, service := range []string{"ts-auth", "ts-dashboard"} {
			checks[service] = bakeDependency(ctx, client, service)
			if checks[service] != "ok" {
				return checks, errors.New("bake " + service + " readiness: " + checks[service])
			}
		}
		for _, log := range logs {
			if err := log.check(); err != nil {
				checks["terrabase-logs"] = err.Error()
				return checks, err
			}
		}
		if len(logs) != 0 {
			checks["terrabase-logs"] = "ok"
		}
		return checks, nil
	})
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

func bakeDependency(ctx context.Context, client *http.Client, service string) string {
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
	if response.StatusCode != http.StatusOK {
		return "HTTP " + strconv.Itoa(response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	var status struct {
		Status       string
		Dependencies map[string]string
	}
	if err != nil || len(body) > 16<<10 || json.Unmarshal(body, &status) != nil {
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
}

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
		var record struct{ Msg string } // Production JSON uses "msg"; decoding is case insensitive.
		message := string(line)
		if json.Unmarshal(line, &record) == nil {
			message = record.Msg
		}
		if strings.Contains(message, "catalog anchor could not be") {
			return errors.New("bake TerraBase catalog anchor failure")
		}
		if strings.HasPrefix(message, "Waited ") && strings.Contains(message, " s for a database's writer ") {
			return errors.New("bake TerraBase writer wait regression")
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
