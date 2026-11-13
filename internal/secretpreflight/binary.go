package secretpreflight

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

func Check(ctx context.Context, binary string) error {
	ctx, cancel := context.WithTimeout(ctx, 70*time.Second)
	defer cancel()
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
	output := &boundedOutput{}
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		return fmt.Errorf("release preflight: %w", err)
	}
	if err := command.Wait(); err != nil {
		return errors.New(Scrub(fmt.Sprintf("release preflight: %v: %s", errors.Join(ctx.Err(), err), output.text())))
	}
	return nil
}

const MaxOutputBytes = 4 << 10

const truncatedNote = " [truncated]"

type boundedOutput struct {
	data      []byte
	truncated bool
}

func (w *boundedOutput) Write(data []byte) (int, error) {
	n := min(len(data), MaxOutputBytes-len(w.data))
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

func Scrub(text string) string {
	text = strings.Map(func(r rune) rune {
		if r == '\n' {
			return ' '
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(text, ""))
	if len(text) <= MaxOutputBytes {
		return text
	}
	text = text[:MaxOutputBytes-len(truncatedNote)]
	for !utf8.ValidString(text) {
		text = text[:len(text)-1]
	}
	return text + truncatedNote
}
