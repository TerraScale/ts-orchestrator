//go:build fixturetest

package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

type installedManagerProcess struct {
	command *exec.Cmd
	input   io.WriteCloser
	parent  *rootoci.ProcessWitness
	witness *rootoci.ProcessWitness
	done    chan struct{}
	waitErr error
	stop    sync.Once
}

func newInstalledManagerProcess(t *testing.T, ctx context.Context, installed *installedControllerFixture) *installedManagerProcess {
	t.Helper()
	requireInstalledControllerNamespace(t)
	if ctx == nil || ctx.Err() != nil || installed == nil || installed.Bootstrap == nil {
		t.Fatal("installed manager process requires original live installation")
	}
	parent, err := rootoci.CaptureProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	child := &installedManagerProcess{parent: parent, done: make(chan struct{})}
	command := exec.CommandContext(ctx, installed.Executable, installedManagerProcessCommand)
	command.Env = []string{"PATH=/usr/bin:/bin", "GOMAXPROCS=2"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: installed.ServiceUID, Gid: installed.ServiceGID, Groups: []uint32{},
	}}
	command.WaitDelay = time.Second
	command.Stderr = os.Stderr
	child.command = command
	child.input, err = command.StdinPipe()
	if err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = child.input.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		_ = child.input.Close()
		_ = output.Close()
		_ = parent.Close()
		t.Fatal(err)
	}
	go func() { child.waitErr = command.Wait(); close(child.done) }()
	t.Cleanup(child.close)
	ready := bufio.NewReaderSize(output, 16)
	if wire, err := ready.ReadString('\n'); err != nil || wire != "ready\n" {
		t.Fatal("installed manager child did not finish exec", err)
	}
	child.witness, err = rootoci.CaptureProcess(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if child.witness.Peer().UID != installed.ServiceUID || child.witness.Peer().GID != installed.ServiceGID ||
		child.verify(ctx, child.witness) != nil {
		t.Fatal("installed manager child differs from its actual supervisor and account")
	}
	return child
}

func (child *installedManagerProcess) verify(ctx context.Context, witness *rootoci.ProcessWitness) error {
	if ctx == nil || ctx.Err() != nil || child == nil || child.parent == nil || child.witness == nil || witness == nil ||
		child.parent.Verify() != nil || child.witness.Verify() != nil || witness.Verify() != nil ||
		witness.Peer() != child.witness.Peer() || witness.Binding() != child.witness.Binding() ||
		witness.ParentPID() != child.parent.Peer().PID || witness.ParentPID() != os.Getpid() ||
		witness.Cgroup() != child.parent.Cgroup() || witness.KernelStart() != child.witness.KernelStart() {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func (child *installedManagerProcess) close() {
	child.stop.Do(func() {
		_, _ = fmt.Fprintln(child.input, "stop")
		_ = child.input.Close()
		select {
		case <-child.done:
		case <-time.After(time.Second):
			_ = child.command.Process.Kill()
			<-child.done
		}
		if child.witness != nil {
			_ = child.witness.Close()
		}
		_ = child.parent.Close()
	})
}

func TestInstalledManagerProcessRetainsMeasuredWitness(t *testing.T) {
	if runInstalledControllerNamespace(t) {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	installed := newInstalledControllerFixture(t)
	child := newInstalledManagerProcess(t, ctx, installed)
	brokers := startInstalledControllerBrokers(t, ctx, installed)
	for _, broker := range brokers {
		observation, err := broker.ObserveCluster()
		if err != nil || !observation.Running || observation.MetaSize != 3 || len(observation.Routes) != 2 || observation.MetaLeader == "" {
			t.Fatal("original generated material did not form its actual three-broker cluster", err)
		}
	}
	ownhost := &managedRuntimeHost{reader: installed.Bootstrap.Reader, accepted: installed.Bootstrap.Accepted.Clone()}
	layout := selfupdate.NewLayout(selfUpdateRoot(installed.Config.Controller.SelfUpdateRoot))
	authority, err := newRootOCIAuthority(ctx, installed.Bootstrap.Accepted, ownhost, layout, installed.ServiceUID, installed.ServiceGID)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	process := authority.process(child.witness, "")
	process.supervisor = child
	authority.main = process
	if _, err := authority.readVerifiedBinary(ctx, child.witness); err != nil {
		t.Fatal("actual child executable differs from the signed installed measure", err)
	}
	if current, err := authority.currentProcess(ctx, child.witness.Peer()); err != nil || current != process {
		t.Fatal("retained real child was not revalidated through its sealed supervisor", err)
	}
	candidate := entityid.Derive("controller-runtime", child.witness.Binding())
	if candidate == "" || candidate == entityid.Derive("controller-runtime", child.parent.Binding()) {
		t.Fatal("candidate was not derived from the actual child")
	}
	child.close()
	if child.waitErr != nil || child.verify(ctx, child.witness) == nil || authority.verifyProcess(ctx, process) == nil {
		t.Fatal("exited child retained process authority", child.waitErr)
	}
}
