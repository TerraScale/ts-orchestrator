package releasepush

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	preflightTimeout = 70 * time.Second
	replyBudget      = 110 * time.Second
	outputWait       = time.Second
	textBusyWait     = 5 * time.Second
	textBusyStep     = 20 * time.Millisecond
	maxOutputBytes   = 4 << 10
	truncatedNote    = " [truncated]"
)

type preflightError struct {
	error
	ran bool
}

func preflight(ctx context.Context, candidate string, deadline time.Time) error {
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	busySince := time.Now()
	for {
		if ctx.Err() != nil {
			return &preflightError{fmt.Errorf("no time left for the candidate preflight: %w", ctx.Err()), false}
		}
		err := runPreflight(ctx, candidate)
		if !errors.Is(err, syscall.ETXTBSY) {
			if err != nil {
				return &preflightError{err, true}
			}
			return nil
		}
		if time.Since(busySince) >= textBusyWait {
			return &preflightError{fmt.Errorf("candidate still open for writing by another process after %s: %w", textBusyWait, err), false}
		}
		select {
		case <-ctx.Done():
			return &preflightError{ctx.Err(), false}
		case <-time.After(textBusyStep):
		}
	}
}

func runPreflight(ctx context.Context, binary string) error {
	ctx, cancel := context.WithTimeout(ctx, preflightTimeout)
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("release preflight: %w", err)
	}
	defer reader.Close()
	command := exec.CommandContext(ctx, binary, "release", "preflight")
	command.WaitDelay = time.Second
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.Stdout, command.Stderr = writer, writer
	err = command.Start()
	writer.Close()
	if err != nil {
		return fmt.Errorf("release preflight: %w", err)
	}
	output := &boundedOutput{}
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(output, reader)
		close(copied)
	}()
	waitErr := command.Wait()
	killErr := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	if errors.Is(killErr, syscall.ESRCH) {
		killErr = nil
	}
	drained := time.NewTimer(outputWait)
	defer drained.Stop()
	select {
	case <-copied:
	case <-drained.C:
		reader.Close()
		<-copied
	}
	if waitErr != nil {
		return errors.New(scrub(fmt.Sprintf("release preflight: %v: %s", errors.Join(ctx.Err(), waitErr, killErr), output.text())))
	}
	if killErr != nil {
		return fmt.Errorf("release preflight: stop its process group: %w", killErr)
	}
	return nil
}

type boundedOutput struct {
	data      []byte
	truncated bool
}

func (w *boundedOutput) Write(data []byte) (int, error) {
	n := min(len(data), maxOutputBytes-len(w.data))
	w.data = append(w.data, data[:n]...)
	w.truncated = w.truncated || n < len(data)
	return len(data), nil
}

func (w *boundedOutput) text() string {
	text := string(w.data)
	if w.truncated {
		text += truncatedNote
	}
	return text
}

func scrub(text string) string {
	text = strings.Map(func(r rune) rune {
		if r == '\n' {
			return ' '
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(text, ""))
	if len(text) <= maxOutputBytes {
		return text
	}
	text = text[:maxOutputBytes-len(truncatedNote)]
	for !utf8.ValidString(text) {
		text = text[:len(text)-1]
	}
	return text + truncatedNote
}
