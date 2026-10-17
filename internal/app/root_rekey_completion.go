package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"golang.org/x/sys/unix"
)

const rootRekeyCompletionCommand = "identity-rekey-completion-check"

// This lifetime belongs to the separate root cleanup CLI, never the main broker.
type rootRekeyCompletionScope struct {
	original                        context.Context
	parent                          *rootoci.ProcessWitness
	child                           *rootoci.ProcessWitness
	accepted                        bootstrapstart.AcceptedIdentity
	acceptedWire, journalWire, boot []byte
	current                         string
}

type rootRekeyCompletionInput struct {
	Deadline       time.Time `json:"deadline"`
	Parent         string    `json:"parent"`
	Child          string    `json:"child"`
	AcceptedSHA256 string    `json:"accepted_sha256"`
	JournalSHA256  string    `json:"journal_sha256"`
	BootSHA256     string    `json:"boot_sha256"`
	Current        string    `json:"current"`
}

func captureRootRekeyCompletionScope(ctx context.Context, pid int) (*rootRekeyCompletionScope, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || os.Getegid() != 0 {
		return nil, rootoci.ErrUnauthorized
	}
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) || deadline.After(time.Now().Add(15*time.Second)) {
		return nil, rootoci.ErrUnauthorized
	}
	parent, err := rootoci.CaptureProcess(pid)
	if err != nil {
		return nil, err
	}
	scope := &rootRekeyCompletionScope{original: ctx, parent: parent}
	success := false
	defer func() {
		if !success {
			_ = parent.Close()
		}
	}()
	if err := verifyRootRekeyCleanupParent(parent); err != nil {
		return nil, err
	}
	scope.accepted, err = bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return nil, err
	}
	scope.acceptedWire, err = bootstrapstart.EncodeAcceptedIdentity(scope.accepted)
	if err != nil {
		return nil, err
	}
	journal, err := bootstrapstart.ReadIdentityRekeyJournal(scope.accepted)
	if err != nil {
		return nil, err
	}
	scope.journalWire = journal.Wire()
	scope.current, err = selfupdate.NewLayout(selfupdate.DefaultRoot).Current()
	if err != nil || scope.current == "" {
		return nil, rootoci.ErrUnauthorized
	}
	scope.boot, err = os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(bytes.TrimSpace(scope.boot)) != 36 {
		return nil, rootoci.ErrUnauthorized
	}
	if err := scope.guard(ctx); err != nil {
		return nil, err
	}
	success = true
	return scope, nil
}

func (scope *rootRekeyCompletionScope) guard(ctx context.Context) error {
	if scope == nil || scope.original == nil || scope.original.Err() != nil || ctx == nil || ctx.Err() != nil ||
		os.Geteuid() != 0 || os.Getegid() != 0 || scope.parent == nil || scope.parent.Verify() != nil ||
		scope.parent.Peer().UID != 0 || scope.parent.Peer().GID != 0 {
		return rootoci.ErrUnauthorized
	}
	deadline, finite := scope.original.Deadline()
	if !finite || !time.Now().Before(deadline) {
		return rootoci.ErrUnauthorized
	}
	if scope.child != nil && scope.child.Verify() != nil {
		return rootoci.ErrUnauthorized
	}
	if err := verifyRootRekeyCleanupParent(scope.parent); err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || !bytes.Equal(boot, scope.boot) {
		return rootoci.ErrUnauthorized
	}
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return err
	}
	wire, err := bootstrapstart.EncodeAcceptedIdentity(accepted)
	if err != nil || !bytes.Equal(wire, scope.acceptedWire) {
		return rootoci.ErrUnauthorized
	}
	journal, err := bootstrapstart.ReadIdentityRekeyJournal(accepted)
	if err != nil || !bytes.Equal(journal.Wire(), scope.journalWire) {
		return rootoci.ErrUnauthorized
	}
	current, err := selfupdate.NewLayout(selfupdate.DefaultRoot).Current()
	if err != nil || current != scope.current {
		return rootoci.ErrUnauthorized
	}
	inputs, err := bootstrapstart.LoadTrustInputs(accepted)
	if err != nil {
		return err
	}
	if err := bootstrapstart.VerifyIdentityRekeyCompletionProcessBinary(ctx, scope.parent.Peer().PID, accepted,
		selfupdate.NewLayout(selfupdate.DefaultRoot), inputs.Roots.Historical); err != nil {
		return err
	}
	if scope.original.Err() != nil || ctx.Err() != nil ||
		!time.Now().Before(deadline) || scope.parent.Verify() != nil {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func verifyRootRekeyCleanupParent(parent *rootoci.ProcessWitness) error {
	if parent == nil || parent.Verify() != nil || parent.Peer().UID != 0 || parent.Peer().GID != 0 {
		return rootoci.ErrUnauthorized
	}
	command, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", parent.Peer().PID))
	parts := bytes.Split(command, []byte{0})
	if err != nil || len(parts) != 4 || string(parts[1]) != "identity-rekey" || string(parts[2]) != "cleanup" || parent.Verify() != nil {
		return rootoci.ErrUnauthorized
	}
	return nil
}

// Open every ancestor without following links, then hash the inode passed to exec.
func openRootRekeyCompletionBinary(ctx context.Context, current string) (*os.File, error) {
	layout := selfupdate.NewLayout(selfupdate.DefaultRoot)
	if ctx == nil || ctx.Err() != nil || layout.VerifyRelease(current) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	directory, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(filepath.Dir(layout.BinaryPath(current)), "/"), "/") {
		next, err := unix.Openat(directory, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(directory)
		if err != nil {
			return nil, err
		}
		directory = next
		var stat unix.Stat_t
		if unix.Fstat(directory, &stat) != nil || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o022 != 0 {
			unix.Close(directory)
			return nil, rootoci.ErrUnauthorized
		}
	}
	defer unix.Close(directory)
	fd, err := unix.Openat(directory, selfupdate.BinaryName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), selfupdate.BinaryName)
	fail := func() (*os.File, error) { _ = file.Close(); return nil, rootoci.ErrUnauthorized }
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Gid != 0 ||
		before.Nlink != 1 || before.Mode&0o6022 != 0 || before.Mode&0o111 == 0 || before.Size <= 0 || before.Size > selfupdate.MaxBinaryBytes {
		return fail()
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, selfupdate.MaxBinaryBytes+1))
	if err != nil || count != before.Size || hex.EncodeToString(hash.Sum(nil)) != current || unix.Fstat(fd, &after) != nil || ctx.Err() != nil {
		return fail()
	}
	before.Atim, after.Atim = unix.Timespec{}, unix.Timespec{}
	if before != after {
		return fail()
	}
	return file, nil
}

func checkRootRekeySharedCompletion(original context.Context) error {
	if original == nil || original.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(original, 15*time.Second)
	defer cancel()
	scope, err := captureRootRekeyCompletionScope(ctx, os.Getpid())
	if err != nil {
		return err
	}
	defer scope.parent.Close()
	binary, err := openRootRekeyCompletionBinary(ctx, scope.current)
	if err != nil {
		return err
	}
	defer binary.Close()
	command := exec.CommandContext(ctx, "/proc/self/fd/3", rootRekeyCompletionCommand)
	command.ExtraFiles = []*os.File{binary}
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.Stdout, command.Stderr = io.Discard, os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	input, err := command.StdinPipe()
	if err != nil {
		return err
	}
	defer input.Close()
	if err := scope.guard(ctx); err != nil {
		return err
	}
	if err := original.Err(); err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	witness, err := rootoci.CaptureProcess(command.Process.Pid)
	if err != nil {
		cancel()
		_ = command.Wait()
		return err
	}
	defer witness.Close() // Release only after the actual child's Wait.
	childInfo, childErr := os.Stat(witness.ExecutablePath())
	targetInfo, targetErr := binary.Stat()
	var pinned unix.Stat_t
	if witness.Peer().UID != 0 || witness.Peer().GID != 0 || witness.ParentPID() != os.Getpid() ||
		witness.Cgroup() != scope.parent.Cgroup() || childErr != nil || targetErr != nil || !os.SameFile(childInfo, targetInfo) ||
		unix.Fstat(int(binary.Fd()), &pinned) != nil || witness.Verify() != nil || scope.guard(ctx) != nil || original.Err() != nil {
		cancel()
		_ = command.Wait()
		return rootoci.ErrUnauthorized
	}
	deadline, _ := ctx.Deadline()
	wire, err := protocol.EncodeJSON(rootRekeyCompletionInput{Deadline: deadline, Parent: scope.parent.Binding(), Child: witness.Binding(), Current: scope.current,
		AcceptedSHA256: controllerSHA256(scope.acceptedWire), JournalSHA256: controllerSHA256(scope.journalWire), BootSHA256: controllerSHA256(scope.boot)})
	if err == nil {
		err = scope.guard(ctx)
	}
	if err == nil {
		err = original.Err()
	}
	if err == nil {
		err = witness.Verify()
	}
	if err == nil {
		_, err = input.Write(wire)
	}
	closeErr := input.Close()
	if err != nil || closeErr != nil {
		cancel()
		_ = command.Wait()
		return errors.Join(err, closeErr)
	}
	err = command.Wait()
	var final unix.Stat_t
	if unix.Fstat(int(binary.Fd()), &final) != nil {
		return rootoci.ErrUnauthorized
	}
	pinned.Atim, final.Atim = unix.Timespec{}, unix.Timespec{}
	currentInfo, currentErr := os.Stat(selfupdate.NewLayout(selfupdate.DefaultRoot).BinaryPath(scope.current))
	if pinned != final || currentErr != nil || !os.SameFile(targetInfo, currentInfo) {
		return rootoci.ErrUnauthorized
	}
	if sourceErr := scope.guard(ctx); sourceErr != nil {
		return sourceErr
	}
	if sourceErr := original.Err(); sourceErr != nil {
		return sourceErr
	}
	return err
}

func runRootRekeyCompletionChild(original context.Context, args []string) error {
	if len(args) != 0 || original == nil || original.Err() != nil || os.Geteuid() != 0 || os.Getegid() != 0 {
		return rootoci.ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(original, 15*time.Second)
	defer cancel()
	scope, err := captureRootRekeyCompletionScope(ctx, os.Getppid())
	if err != nil {
		return err
	}
	defer scope.parent.Close()
	self, err := rootoci.CaptureProcess(os.Getpid())
	if err != nil {
		return err
	}
	defer self.Close()
	scope.child = self
	if self.ParentPID() != scope.parent.Peer().PID || self.Cgroup() != scope.parent.Cgroup() {
		return rootoci.ErrUnauthorized
	}
	command, err := os.ReadFile("/proc/self/cmdline")
	if err != nil || !bytes.Equal(command, []byte("/proc/self/fd/3\x00"+rootRekeyCompletionCommand+"\x00")) {
		return rootoci.ErrUnauthorized
	}
	stop := context.AfterFunc(ctx, func() { _ = os.Stdin.Close() })
	wire, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	stop()
	if err != nil || len(wire) == 0 || len(wire) > 4096 || scope.guard(ctx) != nil || original.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	var input rootRekeyCompletionInput
	if protocol.DecodeStrict(wire, &input, 4096) != nil || input.Parent != scope.parent.Binding() || input.Child != self.Binding() ||
		input.Current != scope.current || input.AcceptedSHA256 != controllerSHA256(scope.acceptedWire) ||
		input.JournalSHA256 != controllerSHA256(scope.journalWire) || input.BootSHA256 != controllerSHA256(scope.boot) || !time.Now().Before(input.Deadline) || input.Deadline.After(time.Now().Add(15*time.Second)) {
		return rootoci.ErrUnauthorized
	}
	ctx, stopDeadline := context.WithDeadline(ctx, input.Deadline)
	defer stopDeadline()
	// The parent's earlier finite deadline remains the original source ceiling.
	scope.original = ctx
	target, err := openRootRekeyCompletionBinary(ctx, scope.current)
	if err != nil {
		return err
	}
	defer target.Close()
	inherited := os.NewFile(3, "rekey-completion-executable")
	defer inherited.Close()
	inheritedInfo, inheritedErr := inherited.Stat()
	actual, err := os.Stat(self.ExecutablePath())
	expected, expectedErr := target.Stat()
	if err != nil || expectedErr != nil || inheritedErr != nil || !os.SameFile(inheritedInfo, expected) || !os.SameFile(actual, expected) || self.Verify() != nil || scope.guard(ctx) != nil {
		return rootoci.ErrUnauthorized
	}
	cfg, err := LoadConfig(controllerSidecarPath(controllerConfigFilename))
	if err != nil {
		return err
	}
	if err := checkControllerIdentityRekeyCompletion(ctx, cfg, scope); err != nil {
		return err
	}
	if self.Verify() != nil || original.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	return scope.guard(ctx)
}
