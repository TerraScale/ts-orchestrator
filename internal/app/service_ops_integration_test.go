package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

var containerdSocket = flag.String("containerd-socket", "", "disposable containerd fixture socket")

// noSecretMaterial attests a verified empty secret profile for every task.
type noSecretMaterial struct{}

func (noSecretMaterial) CurrentContainerMaterial(_ context.Context, binding swarmruntime.ContainerTaskBinding) (swarmruntime.ContainerMaterial, error) {
	return swarmruntime.ContainerMaterial{Binding: binding, ExpiresAt: time.Now().Add(time.Hour), User: "65532:65532"}, nil
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The operator commands run against a real single-host node and containerd.
func TestContainerdSingleHostOperatorCommands(t *testing.T) {
	if *containerdSocket == "" {
		t.Skip("runs in the containerd workflow, which passes -containerd-socket")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	state := t.TempDir()
	executor, err := swarmruntime.NewExecutor(*containerdSocket, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = executor.Close() })
	if err := executor.BindContainerMaterial(swarmruntime.Admission{Role: "manager", Region: "local", HostID: "single-host", InstanceID: "single-host"}, noSecretMaterial{}); err != nil {
		t.Fatal(err)
	}
	node, err := swarmruntime.StartSingleHost(ctx, state, executor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_ = node.Stop(stop)
	})
	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := runServiceCLI(ctx, args, &out, state)
		return out.String(), err
	}
	waitFor := func(what string, check func() bool) {
		t.Helper()
		for !check() {
			select {
			case <-ctx.Done():
				out, err := run("ps", "opsproof")
				t.Fatalf("timed out waiting for %s; ps:\n%s%v", what, out, err)
			case <-time.After(time.Second):
			}
		}
	}

	follow, stopFollow := context.WithCancel(ctx)
	defer stopFollow()
	streamed := &lockedBuffer{}
	followed := make(chan error, 1)
	go func() { followed <- runEventsCLI(follow, []string{"-f"}, streamed, state) }()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	image := map[string]string{
		"amd64": "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764",
		"arm64": "docker.io/library/alpine@sha256:2e1a7aa4cbc4e9e5222bb4c24a839aa1a6170ea5492d644777ce7b178824e44f",
	}[runtime.GOARCH]
	spec := fmt.Sprintf(`{"name":"opsproof","image":%q,"args":["/bin/sh","-c","echo hello from opsproof; echo warn from opsproof >&2; exec sleep 600"],"port":%d,"replicas":1,"secrets":{"OPS_TOKEN_FILE":{"vault":"ocid1.vault.oc1.sa-saopaulo-1.aa.bb","name":"gru-1-opsproof-token"}}}`, image, port)
	path := filepath.Join(t.TempDir(), "opsproof.json")
	if err := os.WriteFile(path, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run("apply", "-f", path); err != nil {
		t.Fatalf("apply: %s%v", out, err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		client, conn, err := swarmruntime.DialSingleHost(state)
		if err != nil {
			return
		}
		defer conn.Close()
		tasks, err := client.ListTasks(cleanup, &api.ListTasksRequest{})
		if err != nil {
			return
		}
		_ = runServiceCLI(cleanup, []string{"rm", "opsproof"}, &bytes.Buffer{}, state)
		// Remove containers before the node stops, or their shims outlive the test.
		for _, task := range tasks.Tasks {
			if c, err := executor.Controller(task); err == nil {
				_ = c.Remove(cleanup)
			}
		}
	})

	waitFor("a running task", func() bool {
		out, err := run("ps", "opsproof")
		lines := strings.Split(out, "\n")
		// TASK NODE STATE DESIRED ...: DESIRED is "running" from the start and NODE is blank until assigned.
		return err == nil && len(lines) > 1 && len(strings.Fields(lines[1])) > 3 && strings.Fields(lines[1])[1] == "single-host" && strings.Fields(lines[1])[2] == "running"
	})
	out, err := run("ps", "opsproof")
	if err != nil || !strings.HasPrefix(out, "TASK ") || !strings.Contains(out, "single-host") {
		t.Fatalf("ps: %s%v", out, err)
	}
	waitFor("container logs", func() bool {
		out, err := run("logs", "opsproof")
		return err == nil && strings.Contains(out, "hello from opsproof\n") && strings.Contains(out, "warn from opsproof\n")
	})

	out, err = run("inspect", "opsproof")
	var inspection swarmruntime.ServiceInspection
	if err != nil || json.Unmarshal([]byte(out), &inspection) != nil {
		t.Fatalf("inspect: %s%v", out, err)
	}
	if _, digest, _ := strings.Cut(image, "@"); inspection.ImageDigest != digest || inspection.Spec.Secrets["OPS_TOKEN_FILE"].Name != "gru-1-opsproof-token" || inspection.Spec.Port != uint32(port) {
		t.Fatalf("inspect: %s", out)
	}

	var recent bytes.Buffer
	if err := runEventsCLI(ctx, nil, &recent, state); err != nil || !strings.Contains(recent.String(), "service opsproof updated version") || !strings.Contains(recent.String(), "task opsproof.1 ") {
		t.Fatalf("events: %s%v", recent.String(), err)
	}
	waitFor("streamed running event", func() bool { return strings.Contains(streamed.String(), " running") })
	stopFollow()
	if err := <-followed; err != nil {
		t.Fatalf("events -f: %v\n%s", err, streamed.String())
	}
	if !strings.Contains(streamed.String(), "service opsproof created") {
		t.Fatalf("events -f:\n%s", streamed.String())
	}
	if out, err := run("ps", "missing"); err == nil || !strings.Contains(err.Error(), "service ls") {
		t.Fatalf("ps missing: %s%v", out, err)
	}
	t.Logf("events:\n%s\nevents -f:\n%s", recent.String(), streamed.String())
}
