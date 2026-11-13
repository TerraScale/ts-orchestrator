package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type process struct {
	cmd     *exec.Cmd
	mu      sync.Mutex
	lines   []string
	changed chan struct{}
	done    chan struct{}
}

func launch(ctx context.Context, name string, env []string, args ...string) (*process, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), env...)
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = writer, writer
	log, err := os.OpenFile(name+".log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		reader.Close()
		writer.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		reader.Close()
		writer.Close()
		log.Close()
		return nil, err
	}
	writer.Close()
	p := &process{cmd: cmd, changed: make(chan struct{}, 1), done: make(chan struct{})}
	go func() {
		defer reader.Close()
		defer log.Close()
		scan := bufio.NewScanner(io.TeeReader(reader, log))
		for scan.Scan() {
			p.mu.Lock()
			p.lines = append(p.lines, scan.Text())
			p.mu.Unlock()
			select {
			case p.changed <- struct{}{}:
			default:
			}
		}
		_ = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

func (p *process) stop() {
	_ = p.cmd.Process.Signal(syscall.SIGCONT)
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-p.done:
	case <-timer.C:
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

func (p *process) wait(ctx context.Context, pattern string, count int) error {
	for {
		p.mu.Lock()
		found := 0
		for _, line := range p.lines {
			if strings.Contains(line, pattern) {
				found++
			}
		}
		p.mu.Unlock()
		if found >= count {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %q (%d): %w", pattern, count, ctx.Err())
		case <-p.done:
			return fmt.Errorf("process exited waiting for %q", pattern)
		case <-p.changed:
		}
	}
}

func command(args ...string) error {
	output, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", args[0], err, output)
	}
	return nil
}
