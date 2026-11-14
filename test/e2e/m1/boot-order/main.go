package main

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/fsnotify/fsnotify"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetLevel(logrus.WarnLevel)
	if len(os.Args) == 3 && os.Args[1] == "--runtime-logger" {
		swarmruntime.RunRuntimeLogger(os.Args[2])
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var err error
	switch os.Args[1] {
	case "agent":
		err = agent(ctx, os.Args[2])
	case "workload":
		err = workload(ctx)
	case "lane":
		if len(os.Args) != 4 || os.Args[3] != "management" && os.Args[3] != "peer" {
			err = errors.New("lane needs a management or peer host")
		} else {
			err = lane(ctx, os.Args[2], os.Args[3] == "management")
		}
	default:
		err = errors.New("unknown journey operation")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func workload(ctx context.Context) error {
	view := "management"
	if os.Getenv("ROLE") != "peer" {
		if os.Getenv("TS_PEERS_FILE") != "" {
			return errors.New("independent task received a peers environment variable")
		}
		if _, err := os.Stat(swarmruntime.PeersFile); !errors.Is(err, os.ErrNotExist) {
			return errors.New("independent task received a peers file")
		}
	}
	if os.Getenv("ROLE") == "peer" {
		data, err := os.ReadFile(os.Getenv("TS_PEERS_FILE"))
		if err != nil {
			return err
		}
		view = string(data)
		address, err := mesh.NetBirdAddress()
		if err != nil {
			return err
		}
		if view != "boot-host gru "+address+"\n" {
			return fmt.Errorf("started with wrong peers: %q", view)
		}
	}
	server := &http.Server{Addr: "127.0.0.1:" + os.Getenv("LISTEN_PORT"), ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, view) })}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type bootLog struct {
	slog.Handler
}

func (h bootLog) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == "mesh peers file track failed" {
		record.Attrs(func(attr slog.Attr) bool {
			if attr.Key == "error" && strings.Contains(attr.Value.String(), "own NetBird address") {
				fmt.Println("mesh-track-missing")
			}
			return true
		})
	}
	return h.Handler.Handle(ctx, record)
}

func agent(ctx context.Context, state string) error {
	slog.SetDefault(slog.New(bootLog{slog.NewTextHandler(os.Stderr, nil)}))
	executor, err := swarmruntime.NewExecutor(filepath.Join(filepath.Dir(state), "containerd.sock"), state)
	if err != nil {
		return err
	}
	defer executor.Close()
	node, err := swarmruntime.StartSingleHost(ctx, state, executor, swarmruntime.SingleHostAddress, swarmruntime.SingleHostAddress, swarmruntime.FounderAdmission())
	if err != nil {
		return err
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = node.Stop(stop)
	}()
	fmt.Println("ready")
	started := make(chan *mesh.Node, 1)
	failure := make(chan error, 1)
	go func() {
		input := bufio.NewScanner(os.Stdin)
		if !input.Scan() {
			return
		}
		ca, err := mesh.DeriveCA([]byte(strings.Repeat("a", 32)))
		if err != nil {
			failure <- err
			return
		}
		meshNode, err := mesh.Start(ctx, state, "gru", "boot-host", ca, strings.Repeat("b", 64), mesh.Cluster{})
		if err != nil {
			failure <- err
			return
		}
		fmt.Println("mesh-ready")
		started <- meshNode
		meshNode.Run(ctx)
	}()
	select {
	case <-ctx.Done():
	case err := <-failure:
		return err
	case meshNode := <-started:
		defer func() {
			if ctx.Err() != nil {
				meshNode.ForceClose()
				return
			}
			_ = meshNode.Close()
		}()
		<-ctx.Done()
	}
	return nil
}

func command(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func address(value string) error {
	if err := command("ip", "link", "add", "wt0", "type", "dummy"); err != nil {
		return err
	}
	if err := command("ip", "addr", "add", value+"/32", "dev", "wt0"); err != nil {
		return err
	}
	return command("ip", "link", "set", "wt0", "up")
}

func awaitFile(ctx context.Context, file string) error {
	watch, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watch.Close()
	if err := watch.Add(filepath.Dir(file)); err != nil {
		return err
	}
	for {
		if _, err := os.Stat(file); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-watch.Errors:
			return err
		case <-watch.Events:
		}
	}
}

type process struct {
	cmd     *exec.Cmd
	output  *bufio.Scanner
	input   io.WriteCloser
	events  api.Watch_WatchClient
	control api.ControlClient
	close   func() error
	initial []*api.Task
	runtime *containerd.Client
	ctx     context.Context
}

func startAgent(ctx context.Context, state, executable string) (*process, error) {
	cmd := exec.Command(executable, "agent", state)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &process{cmd: cmd, input: input, ctx: ctx}
	p.output = bufio.NewScanner(output)
	if !p.output.Scan() || p.output.Text() != "ready" {
		p.stop()
		return nil, errors.New("agent did not become ready")
	}
	client, conn, err := swarmruntime.DialSingleHost(state)
	if err != nil {
		p.stop()
		return nil, err
	}
	p.control, p.close = client, conn.Close
	p.events, err = api.NewWatchClient(conn).Watch(ctx, &api.WatchRequest{Entries: []*api.WatchRequest_WatchEntry{{Kind: "task", Action: api.WatchActionKindCreate | api.WatchActionKindUpdate}}})
	if err != nil {
		p.stop()
		return nil, err
	}
	_, err = p.events.Recv()
	if err != nil {
		p.stop()
		return nil, err
	}
	tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{})
	if err != nil {
		p.stop()
		return nil, err
	}
	p.initial = tasks.Tasks
	p.runtime, err = containerd.New(filepath.Join(filepath.Dir(state), "containerd.sock"), containerd.WithDefaultNamespace("terrascale"))
	if err != nil {
		p.stop()
		return nil, err
	}
	return p, nil
}

func (p *process) mesh(state string, missing bool) (*nats.Conn, error) {
	fmt.Fprintln(p.input, "mesh")
	for _, want := range []string{"mesh-ready", "mesh-track-missing"} {
		if want == "mesh-track-missing" && !missing {
			break
		}
		for {
			if !p.output.Scan() {
				return nil, fmt.Errorf("agent stopped before %s", want)
			}
			if p.output.Text() == want {
				break
			}
		}
	}
	return mesh.Connect(state)
}

func (p *process) stop() {
	if p.runtime != nil {
		_ = p.runtime.Close()
	}
	if p.close != nil {
		_ = p.close()
	}
	_ = p.input.Close()
	_ = p.cmd.Process.Signal(os.Interrupt)
	_ = p.cmd.Wait()
}

func (p *process) until(check func(*api.Task) (bool, error)) error {
	services, err := p.control.ListServices(p.ctx, &api.ListServicesRequest{})
	if err != nil {
		return err
	}
	generations := map[string]string{}
	for _, service := range services.Services {
		generations[service.ID] = service.Spec.Annotations.Labels[swarmruntime.LabelGeneration]
	}
	for {
		tasks := p.initial
		p.initial = nil
		if len(tasks) == 0 {
			message, err := p.events.Recv()
			if err != nil {
				return err
			}
			for _, event := range message.Events {
				if task := event.Object.GetTask(); task != nil {
					tasks = append(tasks, task)
				}
			}
		}
		for _, task := range tasks {
			if generation, exists := generations[task.ServiceID]; exists && task.ServiceAnnotations.Labels[swarmruntime.LabelGeneration] != generation {
				continue
			}
			if task.Status.State == api.TaskStateRunning {
				ctr, err := p.runtime.LoadContainer(p.ctx, "ts-"+task.ID)
				if errdefs.IsNotFound(err) {
					continue
				}
				if err != nil {
					return err
				}
				live, err := ctr.Task(p.ctx, nil)
				if errdefs.IsNotFound(err) {
					continue
				}
				if err != nil {
					return err
				}
				status, err := live.Status(p.ctx)
				if err != nil {
					return err
				}
				if status.Status != containerd.Running {
					continue
				}
			}
			if done, err := check(task); done || err != nil {
				return err
			}
		}
	}
}

func running(ctx context.Context, p *process, management bool) error {
	want := map[string]bool{"boot-peer": false, "boot-default": false, "boot-empty": false}
	if management {
		want["netbird-server"] = false
	}
	return p.until(func(task *api.Task) (bool, error) {
		name := task.ServiceAnnotations.Labels[swarmruntime.LabelServiceSpec]
		if task.Status.State == api.TaskStateRejected && name == "netbird-server" && task.ServiceAnnotations.Labels[swarmruntime.LabelDependencies] == "[]" {
			return false, fmt.Errorf("management rejected without mesh: %s", task.Status.Err)
		}
		if task.Status.State == api.TaskStateRunning {
			want[name] = true
		}
		for _, ready := range want {
			if !ready {
				return false, nil
			}
		}
		return true, nil
	})
}

func desired(state, image string, management bool) error {
	entries := map[string]any{}
	for _, role := range []string{"management", "peer", "default", "empty"} {
		port := 18085
		if role != "management" {
			port = 18086
		}
		if role == "default" {
			port = 18087
		}
		if role == "empty" {
			port = 18088
		}
		workloadRole := role
		if role == "default" {
			workloadRole = "peer"
		}
		spec := map[string]any{"name": "boot-" + role, "image": image, "replicas": 1, "port": port, "readyPath": "/", "regions": []string{"gru"},
			"env": map[string]string{"ROLE": workloadRole, "LISTEN_PORT": fmt.Sprint(port)}}
		if role == "peer" {
			spec["dependencies"] = []string{"peers"}
		}
		if role == "empty" {
			spec["dependencies"] = []string{}
		}
		name := "boot-" + role
		if role == "management" {
			name = "netbird-server"
			if !management {
				spec["regions"] = []string{"sjc"}
			}
			spec["name"] = name
			spec["env"].(map[string]string)["TS_ORCH_NETBIRD_CONFIG_SHA256"] = "existing-config"
		}
		entries[name] = map[string]any{"generation": 1, "spec": spec}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(state, "mesh"), 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(state, "mesh", "desired.json"), data, 0600)
}

func lane(ctx context.Context, root string, management bool) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	log, err := os.Create(filepath.Join(root, "containerd-output"))
	if err != nil {
		return err
	}
	defer log.Close()
	socket := filepath.Join(root, "containerd.sock")
	if err := os.MkdirAll("/run/containerd", 0755); err != nil {
		return err
	}
	if err := os.Symlink(socket, "/run/containerd/containerd.sock"); err != nil {
		return err
	}
	daemon := exec.Command("containerd", "--root", filepath.Join(root, "content"), "--state", filepath.Join(root, "runtime"), "--address", socket)
	daemon.Stdout, daemon.Stderr = log, log
	if err := daemon.Start(); err != nil {
		return err
	}
	defer func() { _ = daemon.Process.Signal(syscall.SIGTERM); _ = daemon.Wait() }()
	if err := awaitFile(ctx, socket); err != nil {
		return err
	}
	client, err := containerd.New(socket, containerd.WithDefaultNamespace("terrascale"))
	if err != nil {
		return err
	}
	defer client.Close()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := stopTasks(namespaces.WithNamespace(cleanup, "terrascale"), client); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	ctx = namespaces.WithNamespace(ctx, "terrascale")
	ref, err := image(ctx, client)
	if err != nil {
		return err
	}
	return scenario(ctx, root, executable, ref, client, management)
}

func scenario(ctx context.Context, root, executable, ref string, client *containerd.Client, management bool) error {
	state := filepath.Join(root, fmt.Sprint(management))
	defer command("ip", "link", "del", "wt0")
	if err := desired(state, ref, management); err != nil {
		return err
	}
	p, err := startAgent(ctx, state, executable)
	if err != nil {
		return err
	}
	defer func() {
		if p != nil {
			p.stop()
		}
	}()
	if management {
		entry, err := stored(state, "netbird-server")
		if err != nil {
			return err
		}
		old := *entry.Spec
		old.Name, old.Region, old.Node = "old-manager", "gru", "boot-host"
		spec, err := old.SwarmSpec()
		if err != nil {
			return err
		}
		spec.Annotations.Name = "netbird-server"
		spec.Annotations.Labels[swarmruntime.LabelServiceSpec] = "netbird-server"
		if _, err := p.control.CreateService(ctx, &api.CreateServiceRequest{Spec: spec}); err != nil {
			return err
		}
		if err := independent(p, true); err != nil {
			return err
		}
		tasks, err := p.control.ListTasks(ctx, &api.ListTasksRequest{})
		if err != nil {
			return err
		}
		oldTask := false
		for _, task := range tasks.Tasks {
			container, err := swarmruntime.DecodeContainer(task)
			if err != nil {
				return err
			}
			if slices.Contains(container.Env, "TS_PEERS_FILE="+swarmruntime.PeersFile) && task.ServiceAnnotations.Labels[swarmruntime.LabelDependencies] == "" {
				oldTask = true
			}
		}
		if !oldTask {
			return errors.New("seed did not retain an old task with the peers environment")
		}
		p.stop()
		p = nil
		if err := stopTasks(ctx, client); err != nil {
			return err
		}
		if err := os.RemoveAll("/run/ts-orch"); err != nil {
			return err
		}
		p, err = startAgent(ctx, state, executable)
		if err != nil {
			return err
		}
		if err := independent(p, true); err != nil {
			return err
		}
		fmt.Println("boot-order: old stored declaration and old task recovered management without a peers file or operator action")
	}
	conn, err := p.mesh(state, true)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := independent(p, management); err != nil {
		return err
	}
	if err := address("100.100.0.1"); err != nil {
		return err
	}
	if err := running(ctx, p, management); err != nil {
		return err
	}
	if management {
		if err := upgrade(ctx, p, conn, state); err != nil {
			return err
		}
	}
	if err := stripNewer(ctx, p, conn, state); err != nil {
		return err
	}
	before, err := taskPIDs(ctx, client)
	if err != nil {
		return err
	}
	expectedTasks := 3
	if management {
		expectedTasks++
	}
	if len(before) != expectedTasks {
		return fmt.Errorf("expected %d live tasks, got %v", expectedTasks, before)
	}
	p.stop()
	p, err = startAgent(ctx, state, executable)
	if err != nil {
		return err
	}
	if err := samePIDs(ctx, client, before); err != nil {
		return err
	}
	conn.Close()
	conn, err = p.mesh(state, false)
	if err != nil {
		return err
	}
	defer conn.Close()
	entry, err := stored(state, "boot-default")
	if err != nil {
		return err
	}
	if err := reconcileDeclaration(ctx, conn, entry); err != nil {
		return err
	}
	if err := samePIDs(ctx, client, before); err != nil {
		return err
	}
	fmt.Printf("boot-order: management=%t agent restart kept task PIDs before and after mesh reconciliation\n", management)
	p.stop()
	p = nil
	if err := stopTasks(ctx, client); err != nil {
		return err
	}
	if err := os.RemoveAll("/run/ts-orch"); err != nil {
		return err
	}
	if err := command("ip", "link", "del", "wt0"); err != nil {
		return err
	}
	p, err = startAgent(ctx, state, executable)
	if err != nil {
		return err
	}
	if err := independent(p, management); err != nil {
		return err
	}
	if management {
		fmt.Println("boot-order: second cold boot recovered management after an older node stripped the field at a higher generation")
	}
	if err := address("100.100.0.2"); err != nil {
		return err
	}
	dir := "/run/ts-orch/peers/boot-peer"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for _, bad := range []struct{ data, failure string }{
		{"", "peers generation is empty"},
		{"malformed\n", "peers generation has an invalid identity"},
		{"boot-host gru 100.100.0.1\n", "peers generation has a stale local address"},
		{"boot-host sjc 100.100.0.2\n", "peers generation has a stale local address or region"},
	} {
		if err := os.WriteFile(filepath.Join(dir, "peers"), []byte(bad.data), 0644); err != nil {
			return err
		}
		if err := p.until(func(task *api.Task) (bool, error) {
			name := task.ServiceAnnotations.Labels[swarmruntime.LabelServiceSpec]
			if (name == "boot-peer" || name == "boot-default") && task.Status.State == api.TaskStateRunning {
				return false, fmt.Errorf("dependent task started with invalid generation %q", bad.data)
			}
			return name == "boot-peer" && task.Status.State == api.TaskStateRejected && strings.Contains(task.Status.Err, bad.failure), nil
		}); err != nil {
			return err
		}
		fmt.Printf("boot-order: refused peers generation %q\n", bad.data)
	}
	if err := command("ip", "link", "del", "wt0"); err != nil {
		return err
	}
	coldConn, err := p.mesh(state, true)
	if err != nil {
		return err
	}
	defer coldConn.Close()
	if err := address("100.100.0.2"); err != nil {
		return err
	}
	if err := running(ctx, p, management); err != nil {
		return err
	}
	cold := "boot-host gru 100.100.0.2\n"
	for _, port := range []string{"18086", "18087"} {
		response, err := http.Get("http://127.0.0.1:" + port + "/")
		if err != nil {
			return err
		}
		data, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(data) != cold {
			return fmt.Errorf("peer response %q: %w", data, err)
		}
	}
	fmt.Printf("boot-order: management=%t recovered with %q; explicit and default peers dependencies held\n", management, cold)
	p.stop()
	p = nil
	return stopTasks(ctx, client)
}

func independent(p *process, management bool) error {
	return p.until(func(task *api.Task) (bool, error) {
		name := task.ServiceAnnotations.Labels[swarmruntime.LabelServiceSpec]
		if (name == "boot-peer" || name == "boot-default") && task.Status.State == api.TaskStateRunning {
			return false, errors.New("dependent task started before the mesh interface")
		}
		want := "boot-empty"
		if management {
			want = "netbird-server"
		}
		if name == want && task.Status.State == api.TaskStateRejected {
			return false, fmt.Errorf("independent task rejected: %s", task.Status.Err)
		}
		return name == want && task.Status.State == api.TaskStateRunning, nil
	})
}

func samePIDs(ctx context.Context, client *containerd.Client, before map[string]uint32) error {
	after, err := taskPIDs(ctx, client)
	if err != nil {
		return err
	}
	if !maps.Equal(before, after) {
		return fmt.Errorf("agent restart replaced running tasks: %v -> %v", before, after)
	}
	return nil
}

func taskPIDs(ctx context.Context, client *containerd.Client) (map[string]uint32, error) {
	containers, err := client.Containers(ctx)
	if err != nil {
		return nil, err
	}
	pids := map[string]uint32{}
	for _, ctr := range containers {
		task, err := ctr.Task(ctx, nil)
		if errdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		status, err := task.Status(ctx)
		if err != nil {
			return nil, err
		}
		if status.Status == containerd.Running {
			pids[ctr.ID()] = task.Pid()
		}
	}
	return pids, nil
}

func stopTasks(ctx context.Context, client *containerd.Client) error {
	containers, err := client.Containers(ctx)
	if err != nil {
		return err
	}
	for _, ctr := range containers {
		task, err := ctr.Task(ctx, nil)
		if errdefs.IsNotFound(err) {
			if err := ctr.Delete(ctx, containerd.WithSnapshotCleanup); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		exit, err := task.Wait(ctx)
		if err != nil {
			return err
		}
		status, err := task.Status(ctx)
		if err != nil {
			return err
		}
		if status.Status != containerd.Stopped {
			if err := task.Kill(ctx, syscall.SIGKILL, containerd.WithKillAll); err != nil {
				return err
			}
		}
		<-exit
		if _, err := task.Delete(ctx); err != nil {
			return err
		}
		if err := ctr.Delete(ctx, containerd.WithSnapshotCleanup); err != nil {
			return err
		}
	}
	return nil
}
