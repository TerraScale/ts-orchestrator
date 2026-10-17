package swarmruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"syscall"
)

// SourceChildRegistrar transfers an actual launched child to the root broker.
// The concrete registrar must verify its process witness; these arguments are not authority.
type SourceChildRegistrar interface {
	RegisterSourceChild(ctx context.Context, pid int, command string, query []byte) (release func(), err error)
}

type sourceChildRegistrarKey struct{}

// WithSourceChildRegistrar carries the root broker's concrete child registry.
func WithSourceChildRegistrar(ctx context.Context, registrar SourceChildRegistrar) context.Context {
	return context.WithValue(ctx, sourceChildRegistrarKey{}, registrar)
}

func runSourceChild(ctx context.Context, sourceCommand string, query []byte, uid, gid uint32, output io.Writer) error {
	registrar, ok := ctx.Value(sourceChildRegistrarKey{}).(SourceChildRegistrar)
	if !ok || registrar == nil {
		return errors.New("source child requires root broker registration")
	}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(childCtx, "/proc/self/exe", sourceCommand)
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	command.Stdout = output
	input, err := command.StdinPipe()
	if err != nil {
		return err
	}
	defer input.Close()
	if err := command.Start(); err != nil {
		return err
	}
	var release func()
	waited := false
	defer func() {
		if !waited {
			cancel()
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		if release != nil {
			release()
		}
	}()
	release, err = registrar.RegisterSourceChild(childCtx, command.Process.Pid, sourceCommand, bytes.Clone(query))
	if err != nil {
		return err
	}
	if release == nil {
		return errors.New("source child registration did not retain its lease")
	}
	if err := childCtx.Err(); err != nil {
		return err
	}
	// Keep stdin withheld until the root broker has captured the actual child.
	if _, err := input.Write(query); err != nil {
		return err
	}
	if err := input.Close(); err != nil {
		return err
	}
	err = command.Wait()
	waited = true
	return err
}
