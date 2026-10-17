//go:build fixturetest

package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
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
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	fixture := newInstalledControllerHostFixture(t, ctx)
	installed, child := fixture.installed, fixture.process
	for _, broker := range fixture.brokers {
		observation, err := broker.ObserveCluster()
		if err != nil || !observation.Running || observation.MetaSize != 3 || len(observation.Routes) != 2 || observation.MetaLeader == "" {
			t.Fatal("original generated material did not form its actual three-broker cluster", err)
		}
	}
	// This launches the unchanged service child; it cannot use a supplied
	// registration snapshot, guard or successful Call.
	binding, err := swarmruntime.ReadControllerHostBinding(ctx, fixture.sdk.Reader(), installed.Bootstrap.Accepted,
		fixture.agent, fixture.transport.Request, fixture.transport.Response)
	if err != nil || binding == nil || binding.ControllerSlot() != installed.Bootstrap.Accepted.Slot {
		t.Fatal("actual installed Gate, child SDK and current registration did not admit the ownhost", err)
	}
	statuses, err := fixture.hosts.ListHosts(ctx)
	if err != nil || len(statuses) != 1 || !time.Now().Before(statuses[0].SessionExpiresAt) || binding.VerifyRegistration(ctx, statuses[0].Registration) != nil {
		t.Fatal("actual current ownhost session differs from its installed binding", err)
	}
	checkSDKProtocolDenials(t, ctx, fixture)
	ownhost := &managedRuntimeHost{reader: fixture.sdk.Reader(), accepted: installed.Bootstrap.Accepted.Clone()}
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
	if fixture.control.Current().CandidateID != candidate {
		t.Fatal("regional authority was not derived from the original child witness")
	}
	acquired, err := bootstrapstart.AcquireControllerSDKAcquisitionFixture(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	child.close()
	if child.waitErr != nil || child.verify(ctx, child.witness) == nil || authority.verifyProcess(ctx, process) == nil {
		t.Fatal("exited child retained process authority", child.waitErr)
	}
	cancel()
	if _, err := fixture.sdk.Observer().ObserveInstance(t.Context(), installed.Bootstrap.Accepted.InstanceOCID); err == nil {
		t.Fatal("retained parent SDK accepted cancellation of its original root runtime")
	}
	if _, err := acquired.Observer().ObserveInstance(t.Context(), installed.Bootstrap.Accepted.InstanceOCID); err == nil {
		t.Fatal("reacquired SDK read survived original root server cancellation")
	}
}

func checkSDKProtocolDenials(t *testing.T, ctx context.Context, fixture *installedControllerHostFixture) {
	t.Helper()
	sourceCtx, stopSource := context.WithCancel(ctx)
	acquired, err := bootstrapstart.AcquireControllerSDKAcquisitionFixture(sourceCtx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquired.Observer().ObserveInstance(ctx, fixture.installed.Bootstrap.Accepted.InstanceOCID); err != nil {
		t.Fatal("actual signed SDK instance read failed", err)
	}
	stopSource()
	if _, err := acquired.Observer().ObserveInstance(ctx, fixture.installed.Bootstrap.Accepted.InstanceOCID); err == nil {
		t.Fatal("retained SDK accepted a fresh call after its acquisition lifetime ended")
	}
	if _, err := fixture.sdk.Observer().ObserveInstance(ctx, "ocid1.instance.oc1.sa-saopaulo-1.outsideinstalledsource"); err == nil {
		t.Fatal("signed SDK read escaped the original instance scope")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fixture.sdk.Storage().Host+"/20160918/instances/"+fixture.installed.Bootstrap.Accepted.InstanceOCID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "invalid signature")
	response, err := fixture.sdk.Storage().HTTPClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned SDK request returned %d, want 401", response.StatusCode)
	}
}

func TestInstalledControllerHostRejectsSDKDescriptorDrift(t *testing.T) {
	if runInstalledControllerNamespace(t) {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	fixture := newInstalledControllerHostFixture(t, ctx)
	read := func() error {
		_, err := swarmruntime.ReadControllerHostBinding(ctx, fixture.sdk.Reader(), fixture.installed.Bootstrap.Accepted,
			fixture.agent, fixture.transport.Request, fixture.transport.Response)
		return err
	}
	if err := read(); err != nil {
		t.Fatal("original installed host source was not admitted", err)
	}
	const sourcePath = "/run/ts-installed-controller-sdk/source.json"
	wire, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	// Even identical signed bytes at a replaced inode revoke retained clients.
	if err := os.Rename(sourcePath, sourcePath+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, wire, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := read(); err == nil {
		t.Fatal("descriptor replacement preserved the original installed host source")
	}
	if _, err := fixture.sdk.Observer().ObserveInstance(ctx, fixture.installed.Bootstrap.Accepted.InstanceOCID); err == nil {
		t.Fatal("retained SDK ignored its original descriptor inode")
	}
	wire[len(wire)/2] ^= 1
	if err := os.WriteFile(sourcePath, wire, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapstart.AcquireControllerSDKAcquisitionFixture(ctx); err == nil {
		t.Fatal("tampered signed acquisition source was admitted")
	}
}
