package host

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/logs"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	// logLineLimit bounds one journal line; a longer one is counted, not parsed.
	logLineLimit  = 1 << 20
	logMinBackoff = time.Second
	logMaxBackoff = time.Minute
)

// publishLogs follows the node's orchestrator and NetBird journal and publishes
// one window per minute until ctx ends. A failing journalctl is retried with
// backoff, and the agent's other work never waits for it.
func (a *Agent) publishLogs(ctx context.Context) {
	command, tick, publish := a.logsCommand, a.logsTick, a.logsPublish
	if command == nil {
		command = startJournal
	}
	if publish == nil {
		publish = a.cfg.Conn.Publish
	}
	if tick == nil {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		tick = ticker.C
	}
	windows := &logWindows{
		counter: logs.NewCounter(a.cfg.Cell, a.cfg.Node),
		subject: protocol.AgentObservation(a.cfg.Cell, a.cfg.NATSUserPublicKey, "logs"),
		minute:  a.wallTime().Truncate(time.Minute),
		publish: publish,
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick:
				ctx := observability.StartTrace(ctx)
				windows.roll(ctx, a.wallTime())
			}
		}
	}()
	retry := logRetry{wait: logMinBackoff}
	for {
		ctx := observability.StartTrace(ctx)
		started := time.Now()
		err := a.followLogs(ctx, command, windows, &retry)
		if ctx.Err() != nil {
			return
		}
		wait := retry.failed(ctx, err, time.Since(started))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// followLogs runs journalctl until it fails or ctx ends, counting its lines.
func (a *Agent) followLogs(ctx context.Context, command func(context.Context) (io.ReadCloser, error), windows *logWindows, retry *logRetry) error {
	journal, err := command(ctx)
	if err != nil {
		return err
	}
	if retry.failure != "" {
		slog.InfoContext(ctx, "journal follow running again", "component", "logs")
		retry.failure = ""
	}
	readErr := readLogLines(journal, func(line []byte, oversized bool) {
		windows.observe(ctx, a.wallTime(), line, oversized)
	})
	waitErr := journal.Close()
	switch {
	case readErr != io.EOF:
		return readErr
	case waitErr != nil:
		return waitErr
	}
	return errors.New("journalctl exited")
}

// startJournal follows the orchestrator's and NetBird's records from now on.
func startJournal(ctx context.Context) (io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, "journalctl", "--follow", "--since=now", "--output=json",
		"--output-fields=_SYSTEMD_UNIT,_COMM,_PID,MESSAGE,PRIORITY", "-u", "terrascale*", "-u", "netbird*")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return journalProcess{stdout, cmd}, nil
}

// journalProcess reads journalctl's output; Close waits for the process to exit.
type journalProcess struct {
	io.ReadCloser
	cmd *exec.Cmd
}

func (p journalProcess) Close() error {
	return p.cmd.Wait()
}

// readLogLines calls line for each line of r. A line over logLineLimit is
// reported as oversized, and its remainder is skipped.
func readLogLines(r io.Reader, line func(text []byte, oversized bool)) error {
	reader := bufio.NewReaderSize(r, logLineLimit)
	for {
		text, err := reader.ReadSlice('\n')
		oversized := errors.Is(err, bufio.ErrBufferFull)
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = reader.ReadSlice('\n')
		}
		if len(text) > 0 || oversized {
			line(text, oversized)
		}
		if err != nil {
			return err
		}
	}
}

// logRetry paces journalctl restarts: a failure waits 1 s, doubling up to 1 min.
type logRetry struct {
	wait time.Duration
	// failure is the last failure's error; empty while journalctl runs.
	failure string
}

// failed logs one failure and returns how long to wait before the next start.
// A run that lasted a minute was healthy, so its failure starts the backoff over.
func (r *logRetry) failed(ctx context.Context, err error, ran time.Duration) time.Duration {
	if ran >= logMaxBackoff {
		r.wait = logMinBackoff
	}
	msg := err.Error()
	if r.failure == "" || msg != r.failure {
		slog.WarnContext(ctx, "journal follow failed; retrying", "component", "logs", "error", msg, "wait", r.wait)
	} else {
		slog.DebugContext(ctx, "journal follow failed again", "component", "logs", "error", msg)
	}
	r.failure = msg
	wait := r.wait
	r.wait = min(2*r.wait, logMaxBackoff)
	return wait
}

// logWindows counts the journal's records and publishes each minute's window
// once the minute has ended.
type logWindows struct {
	mu      sync.Mutex
	counter *logs.Counter
	parser  logs.Parser
	subject string
	minute  time.Time
	publish func(subject string, data []byte) error
}

// observe counts one journal line that arrived at now.
func (w *logWindows) observe(ctx context.Context, now time.Time, line []byte, oversized bool) {
	w.roll(ctx, now)
	w.mu.Lock()
	defer w.mu.Unlock()
	if oversized {
		w.counter.Add(logs.Record{Service: "ts-orchestrator", Level: logs.LevelWarn, Component: "logs", Message: "oversized journal line"})
		return
	}
	if e, ok := logs.DecodeJournal(line); ok {
		if r, ok := w.parser.Parse(e); ok {
			w.counter.Add(r)
		}
	}
}

// roll publishes the window of every minute before now's, empty minutes included,
// so a silent node still reports.
func (w *logWindows) roll(ctx context.Context, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for end := now.Truncate(time.Minute); w.minute.Before(end); w.minute = w.minute.Add(time.Minute) {
		w.send(ctx, w.counter.Flush(w.minute))
	}
}

func (w *logWindows) send(ctx context.Context, window logs.Window) {
	data, err := json.Marshal(window)
	if err != nil {
		slog.WarnContext(ctx, "journal window not encoded", "component", "logs", "error", err)
		return
	}
	if err := w.publish(w.subject, data); err != nil {
		slog.WarnContext(ctx, "journal window not published", "component", "logs", "error", err)
	}
}
