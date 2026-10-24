package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/gogo/protobuf/types"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc/grpclog"
)

// operatorFixes maps error text the M1 hosts produced to the operator's next step.
var operatorFixes = []struct{ match, fix string }{
	{"swarm-root-ca.crt: permission denied", "run it as root: sudo ts-orch ..."},
	{"swarm-root-ca.crt: no such file", "no single-host node was ever started with this state: sudo systemctl start ts-orch"},
	{"control.sock: connect: connection refused", "ts-orch single-host is not running: sudo systemctl status ts-orch; sudo journalctl -u ts-orch -n 50"},
	{"control.sock: connect: no such file", "ts-orch single-host is not running: sudo systemctl status ts-orch; sudo journalctl -u ts-orch -n 50"},
	{"signed container material is pending", "the host delivers no secrets for this task: check each ref in `ts-orch service inspect <svc>` .spec.secrets exists in OCI Vault and this host runs a ts-orch release with Vault secret delivery, then re-apply"},
	{"disk capacity or retained storage is unavailable", "the task reserves 10 GiB of disk: free space with `df -h /var/lib/containerd /var/lib/ts-orch` and `sudo ctr -n terrascale images prune --all`"},
	{"no suitable node", "the host lacks CPU, memory, disk or the port for this task: check `ts-orch service ls` and remove or shrink another service"},
	{"load admitted container image", "pulling the image failed: check the host reaches the registry and the digest exists: sudo ctr -n terrascale images pull <image>"},
	{"architecture-specific child manifest", "pin the linux/" + runtime.GOARCH + " child manifest digest, not the multi-arch index digest: docker buildx imagetools inspect <image>"},
	{"architecture does not match host", "the pinned image is for another CPU: pin its linux/" + runtime.GOARCH + " child manifest digest"},
	{"image target differs from pinned digest", "a cached image has another digest: sudo ctr -n terrascale images rm <image>, then re-apply"},
	{"address already in use", "another process holds the service port: sudo ss -ltnp | grep <port>"},
	{"bind mount", "check the mount source is a directory under /var/lib/ts-data and the image contains the target directory"},
	{"container image requires a sha256 digest", "pin the image by digest: <registry>/<repo>@sha256:<digest>"},
	{"rolled back to", "the previous spec is serving again; fix the new image or spec, check ts-orch service logs <svc>, then re-apply"},
	{"not ready within", "the new task never answered its readyPath with 200: check ts-orch service logs <svc> or raise readyTimeoutSeconds"},
	{"OOM-killed", "the container used more memory than its limit: raise memoryMiB in the service spec, then re-apply"},
	{"exited with status", "the container exited: ts-orch service logs <svc>"},
	{"task: non-zero exit", "the container exited: ts-orch service logs <svc>"},
}

// operatorFix returns the next step for a known failure, or "".
func operatorFix(message string) string {
	for _, known := range operatorFixes {
		if strings.Contains(message, known.match) {
			return known.fix
		}
	}
	return ""
}

// explain appends the operator's next step to a known failure.
func explain(err error) error {
	if err == nil {
		return nil
	}
	if fix := operatorFix(err.Error()); fix != "" {
		return fmt.Errorf("%w. Fix: %s", err, fix)
	}
	return err
}

// RunEventsCLI prints recent task and service state changes, or streams them with -f.
func RunEventsCLI(ctx context.Context, args []string, output io.Writer) error {
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(io.Discard, io.Discard, io.Discard))
	return explain(runEventsCLI(ctx, args, output, singleHostState))
}

func runEventsCLI(ctx context.Context, args []string, output io.Writer, state string) error {
	follow := slices.Equal(args, []string{"-f"})
	if !follow && len(args) != 0 {
		_, err := io.WriteString(output, "usage: ts-orch events [-f]\n")
		return errors.Join(err, errors.New("unknown events arguments"))
	}
	client, conn, err := swarmruntime.DialSingleHost(state)
	if err != nil {
		return err
	}
	defer conn.Close()
	if follow {
		return followEvents(ctx, api.NewWatchClient(conn), output)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return recentEvents(ctx, client, output)
}

type event struct {
	at   time.Time
	line string
}

func taskEvent(task *api.Task) event {
	line := fmt.Sprintf("task %s.%d %s %s", task.ServiceAnnotations.Name, task.Slot, task.ID, strings.ToLower(task.Status.State.String()))
	if task.Status.Err != "" {
		line += fmt.Sprintf(" error=%q", task.Status.Err)
		if fix := operatorFix(task.Status.Err); fix != "" {
			line += fmt.Sprintf(" fix=%q", fix)
		}
	}
	return event{swarmruntime.TaskTime(task), line}
}

func serviceEvent(action string, service *api.Service) event {
	at, _ := types.TimestampFromProto(service.Meta.UpdatedAt)
	if action == "removed" {
		at = time.Now()
	}
	line := fmt.Sprintf("service %s %s version %d", service.Spec.Annotations.Name, action, service.Meta.Version.Index)
	if status := service.UpdateStatus; status != nil {
		line += fmt.Sprintf(" update=%s", strings.ToLower(status.State.String()))
		if status.Message != "" {
			line += fmt.Sprintf(" message=%q", status.Message)
		}
	}
	return event{at, line}
}

func writeEvent(output io.Writer, e event) error {
	_, err := fmt.Fprintf(output, "%s %s\n", e.at.UTC().Format(time.RFC3339), e.line)
	return err
}

// recentEvents replays the latest state of every retained task and service, oldest first.
func recentEvents(ctx context.Context, client api.ControlClient, output io.Writer) error {
	services, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return err
	}
	tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{})
	if err != nil {
		return err
	}
	var events []event
	for _, service := range services.Services {
		events = append(events, serviceEvent("updated", service))
	}
	for _, task := range tasks.Tasks {
		events = append(events, taskEvent(task))
	}
	slices.SortStableFunc(events, func(a, b event) int { return a.at.Compare(b.at) })
	for _, e := range events[max(0, len(events)-100):] {
		if err := writeEvent(output, e); err != nil {
			return err
		}
	}
	return nil
}

// followEvents streams service changes and task state transitions from the manager's watch API.
func followEvents(ctx context.Context, watch api.WatchClient, output io.Writer) error {
	stream, err := startEventWatch(ctx, watch)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	return streamEvents(ctx, stream, output)
}

func startEventWatch(ctx context.Context, watch api.WatchClient) (api.Watch_WatchClient, error) {
	actions := api.WatchActionKindCreate | api.WatchActionKindUpdate | api.WatchActionKindRemove
	stream, err := watch.Watch(ctx, &api.WatchRequest{Entries: []*api.WatchRequest_WatchEntry{{Kind: "task", Action: actions}, {Kind: "service", Action: actions}}})
	if err != nil {
		return nil, err
	}
	// The first empty message confirms the manager has registered the watch.
	if _, err := stream.Recv(); err != nil {
		return nil, err
	}
	return stream, nil
}

func streamEvents(ctx context.Context, stream api.Watch_WatchClient, output io.Writer) error {
	states := map[string]api.TaskState{}
	for {
		message, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		for _, change := range message.Events {
			var e event
			switch object := change.Object.GetObject().(type) {
			case *api.Object_Task:
				task := object.Task
				// Status heartbeats repeat the state; print transitions only.
				if state, seen := states[task.ID]; change.Action != api.WatchActionKindRemove && seen && state == task.Status.State {
					continue
				}
				states[task.ID] = task.Status.State
				if change.Action == api.WatchActionKindRemove {
					delete(states, task.ID)
					continue
				}
				e = taskEvent(task)
			case *api.Object_Service:
				action := map[api.WatchActionKind]string{api.WatchActionKindCreate: "created", api.WatchActionKindUpdate: "updated", api.WatchActionKindRemove: "removed"}[change.Action]
				e = serviceEvent(action, object.Service)
			default:
				continue
			}
			if err := writeEvent(output, e); err != nil {
				return err
			}
		}
	}
}

// runServiceOps serves `service ps|logs|inspect`.
func runServiceOps(ctx context.Context, args []string, output io.Writer, state string) error {
	command, rest := args[0], args[1:]
	follow := command == "logs" && slices.Contains(rest, "-f")
	previous := command == "logs" && slices.Contains(rest, "--previous")
	if follow && previous {
		return errors.New("service logs --previous is a snapshot; use -f for the current task")
	}
	rest = slices.DeleteFunc(slices.Clone(rest), func(arg string) bool {
		return follow && arg == "-f" || previous && arg == "--previous"
	})
	if len(rest) != 1 || strings.HasPrefix(rest[0], "-") {
		_, err := io.WriteString(output, serviceCLIUsage)
		return errors.Join(err, fmt.Errorf("service %s needs one service name", command))
	}
	client, conn, err := swarmruntime.DialSingleHost(state)
	if err != nil {
		return err
	}
	defer conn.Close()
	lookup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	service, err := swarmruntime.ServiceByName(lookup, client, rest[0])
	if err != nil {
		return err
	}
	switch command {
	case "inspect":
		inspection, err := swarmruntime.InspectService(service)
		if err != nil {
			return err
		}
		if err := json.MarshalWrite(output, inspection); err != nil {
			return err
		}
		_, err = fmt.Fprintln(output)
		return err
	case "ps":
		rows, err := swarmruntime.ServiceTasks(lookup, client, service)
		if err != nil {
			return err
		}
		return writeTaskRows(output, rows, time.Now())
	default:
		rows, err := swarmruntime.ServiceTasks(lookup, client, service)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return fmt.Errorf("service %q has no tasks yet; check `ts-orch service ps %s`", rest[0], rest[0])
		}
		if previous {
			return writePreviousTaskLogs(ctx, output, state, rows)
		}
		// shortcut: follow replacement tasks when restarts during -f need it.
		return writeTaskLogs(ctx, output, state, rows[0], follow)
	}
}

// SwarmKit retains exited task containers and their bounded logs until its
// task-history reaper removes them. Read the most recently stopped local task
// with output, including when newer rejected tasks never reached the logger.
func writePreviousTaskLogs(ctx context.Context, output io.Writer, state string, rows []swarmruntime.TaskRow) error {
	for _, row := range rows {
		if !row.Terminal {
			continue
		}
		for _, stream := range []string{"stdout", "stderr"} {
			_, err := os.Stat(swarmruntime.RuntimeLogFile(state, row.ID, stream))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(output, "== task %s node=%s slot=%d state=%s stopped=%s ==\n",
				row.ID, row.Node, row.Slot, strings.ToLower(row.State), row.Since.UTC().Format(time.RFC3339)); err != nil {
				return err
			}
			return writeTaskLogs(ctx, output, state, row, false)
		}
	}
	return errors.New("no retained previous task logs on this host; check `ts-orch service ps` for task nodes and history")
}

func writeTaskRows(output io.Writer, rows []swarmruntime.TaskRow, now time.Time) error {
	table := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "TASK\tNODE\tSTATE\tDESIRED\tSINCE\tRESTARTS\tEXIT\tERROR")
	for _, row := range rows {
		exit := "-"
		if row.Exit >= 0 {
			exit = strconv.Itoa(int(row.Exit))
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s ago\t%d\t%s\t%s\n", row.ID, row.Node, strings.ToLower(row.State), strings.ToLower(row.Desired), now.Sub(row.Since).Round(time.Second), row.Restarts, exit, row.Error)
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if len(rows) != 0 && rows[0].Error != "" {
		if fix := operatorFix(rows[0].Error); fix != "" {
			_, err := fmt.Fprintf(output, "Fix: %s\n", fix)
			return err
		}
	}
	return nil
}

// writeTaskLogs copies the task's stdout then stderr; with follow it polls both for appended output.
func writeTaskLogs(ctx context.Context, output io.Writer, state string, task swarmruntime.TaskRow, follow bool) error {
	offsets := map[string]int64{}
	found := false
	for {
		for _, stream := range []string{"stdout", "stderr"} {
			file, err := os.Open(swarmruntime.RuntimeLogFile(state, task.ID, stream))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			found = true
			info, err := file.Stat()
			if err == nil && info.Size() < offsets[stream] {
				offsets[stream] = 0 // The logger truncated a full segment.
			}
			if err == nil {
				_, err = file.Seek(offsets[stream], io.SeekStart)
			}
			var n int64
			if err == nil {
				n, err = io.Copy(output, file)
			}
			offsets[stream] += n
			if err := errors.Join(err, file.Close()); err != nil {
				return err
			}
		}
		if !found && !follow {
			return fmt.Errorf("task %s (%s) has no container logs yet; check `ts-orch service ps`", task.ID, strings.ToLower(task.State))
		}
		if !follow {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(500 * time.Millisecond):
		}
	}
}
