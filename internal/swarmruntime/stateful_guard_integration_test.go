package swarmruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	"golang.org/x/sys/unix"
)

type statefulGuardFixture struct {
	Socket, Logs, ContainerID string
	Guard                     StatefulRuntimeGuard
}

// statefulGuardAgentFixture exits after creating the real task. Its logger is
// owned by containerd's shim and must enforce the cache after this process exits.
func statefulGuardAgentFixture(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var fixture statefulGuardFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(runtimeContext(context.Background()), 30*time.Second)
	defer cancel()
	client, err := containerd.New(fixture.Socket, containerd.WithDefaultNamespace(runtimeNamespace))
	if err != nil {
		return err
	}
	defer client.Close()
	image, err := client.GetImage(ctx, integrationImage)
	if err != nil {
		return fmt.Errorf("cached integration image required: %w", err)
	}
	container, err := client.NewContainer(ctx, fixture.ContainerID,
		containerd.WithSnapshotter("native"), containerd.WithImage(image), containerd.WithNewSnapshot(fixture.ContainerID, image),
		containerd.WithRuntime("io.containerd.runc.v2", nil),
		containerd.WithContainerLabels(map[string]string{"terrascale.spec": fixture.Guard.TaskSHA256, "terrascale.task-binding": fixture.Guard.TaskSHA256,
			"terrascale.task": strings.TrimPrefix(fixture.ContainerID, "ts-"), "terrascale.service": "statefulguard"}),
		containerd.WithNewSpec(oci.WithImageConfig(image), oci.WithProcessArgs("/bin/sleep", "60"), oci.WithUIDGID(65532, 65532),
			oci.WithCgroup("/terrascale/"+fixture.ContainerID), oci.WithRootFSReadonly(), oci.WithNoNewPrivileges, oci.WithCapabilities(nil)))
	if err != nil {
		return err
	}
	argument, err := json.Marshal(runtimeLoggerInvocation{Root: fixture.Logs, Guard: runtimeCredentialGuard{Socket: fixture.Socket, TaskID: fixture.ContainerID, Fingerprint: fixture.Guard.TaskSHA256, State: &fixture.Guard}})
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	uri, err := cio.LogURIGenerator("binary-v2", executable, map[string]string{"--runtime-logger": string(argument)})
	if err != nil {
		return err
	}
	task, err := container.NewTask(ctx, cio.LogURI(uri))
	if err != nil {
		return err
	}
	for {
		labels, err := container.Labels(ctx)
		if err != nil {
			return err
		}
		if labels[runtimeGuardPIDLabel] == fmt.Sprintf("%s:%d", fixture.Guard.TaskSHA256, task.Pid()) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := task.Start(ctx); err != nil {
		return err
	}
	fmt.Println(task.Pid())
	return nil
}

func writeStatefulGuardFixture(t *testing.T, guard StatefulRuntimeGuard, private ed25519.PrivateKey, revision uint64, deadline time.Time) {
	t.Helper()
	now := time.Now().UTC()
	payload := executionwire.WorkerGrantPayload{Identity: guard.Identity, TaskID: guard.EffectID, ServiceID: "statefulguard",
		TaskSHA256: guard.TaskSHA256, EffectID: guard.EffectID, Nonce: strings.Repeat("a", 32), Epoch: guard.Epoch, LeaderEpoch: guard.Epoch, Revision: revision, IssuedAt: now, Deadline: deadline, Phase: "held"}
	material, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	nonce := strings.Repeat("b", 32)
	response, err := json.Marshal(struct {
		Nonce     string         `json:"nonce"`
		Node      string         `json:"node"`
		SessionID string         `json:"session_id"`
		Epoch     uint64         `json:"epoch"`
		Operation string         `json:"operation"`
		Payload   jsontext.Value `json:"payload"`
	}{nonce, guard.Identity.HostNode, guard.Identity.HostSessionID, guard.HostEpoch, "runtime-effect", material})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := protocol.SignEnvelope(response, protocol.EnvelopeScope{Region: guard.Identity.Cell, Kind: "host.response.runtime-effect", Actor: "controller", OperationID: entityid.Derive("host-request", nonce), Epoch: guard.HostEpoch}, now, now.Add(10*time.Second), private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	temporary := guard.CachePath + ".tmp"
	if err := os.WriteFile(temporary, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, guard.CachePath); err != nil {
		t.Fatal(err)
	}
}

func TestContainerdStatefulGuardSurvivesAgentExit(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	if *integrationSocket == "" {
		t.Fatal("provide -containerd-socket for a disposable real runtime")
	}
	if os.Geteuid() != 0 {
		t.Fatal("actual protected root cache/runtime fixture requires root")
	}
	for _, scenario := range []string{"expiry", "renewal", "forged", "rollback", "missing", "guardian-death"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(runtimeContext(t.Context()), 35*time.Second)
			defer cancel()
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			hash := fmt.Sprintf("%064x", time.Now().UnixNano())
			identity := executionwire.WorkerIdentity{Cell: "gru", HostNode: "guardhost", NodeID: "guardnode", InstanceID: "ocid1.instance.guard", HostSessionID: entityid.Derive("guard-session", hash), RegistrationGeneration: 1}
			payload := executionwire.WorkerGrantPayload{Identity: identity, TaskID: entityid.Derive("guard-effect", hash), ServiceID: "statefulguard", TaskSHA256: hash, EffectID: entityid.Derive("guard-effect", hash), Epoch: 1}
			admission, err := executionwire.WorkerAdmissionSHA256(payload)
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().UTC().Add(10 * time.Second)
			guard := StatefulRuntimeGuard{CachePath: filepath.Join(root, hash+".json"), Identity: identity, ControllerPublicKey: public, TaskSHA256: hash, AdmissionSHA256: admission, EffectID: payload.EffectID, Epoch: 1, HostEpoch: 7, Revision: 2, Deadline: deadline}
			writeStatefulGuardFixture(t, guard, private, 2, deadline)
			fixture := statefulGuardFixture{Socket: *integrationSocket, Logs: filepath.Join(root, "logs"), ContainerID: "ts-" + payload.TaskID, Guard: guard}
			data, err := json.Marshal(fixture)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "fixture.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			client, err := containerd.New(*integrationSocket, containerd.WithDefaultNamespace(runtimeNamespace))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(runtimeContext(context.Background()), 10*time.Second)
				defer stop()
				container, err := client.LoadContainer(cleanup, fixture.ContainerID)
				if err != nil {
					return
				}
				if task, err := container.Task(cleanup, nil); err == nil {
					_ = task.Kill(cleanup, unix.SIGKILL, containerd.WithKillAll)
					_, _ = task.Delete(cleanup, containerd.WithProcessKill)
				}
				_ = container.Delete(cleanup, containerd.WithSnapshotCleanup)
			})
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			output, err := exec.CommandContext(ctx, executable, "stateful-guard-agent-fixture", path).CombinedOutput()
			if err != nil {
				t.Fatalf("fixture process: %v: %s", err, output)
			}
			container, err := client.LoadContainer(ctx, fixture.ContainerID)
			if err != nil {
				t.Fatal(err)
			}
			task, err := container.Task(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			status, err := task.Status(ctx)
			if err != nil || status.Status != containerd.Running {
				t.Fatalf("agent exit lost running process: %s %v", status.Status, err)
			}
			wait, err := task.Wait(ctx)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "guardian-death":
				killStatefulFixtureLogger(t, guard)
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(time.Until(deadline) + 200*time.Millisecond):
				}
				status, err := task.Status(ctx)
				if err != nil || status.Status != containerd.Running {
					t.Fatalf("guardian death limitation changed: %s %v", status.Status, err)
				}
				events, err := os.ReadFile(filepath.Join("/sys/fs/cgroup/terrascale", fixture.ContainerID, "cgroup.events"))
				if err != nil || !strings.Contains("\n"+string(events), "\npopulated 1\n") {
					t.Fatalf("live writer lost independently observed populated cgroup: %v", err)
				}
				t.Log("killed guardian leaves a live writer; deadline alone cannot satisfy stopped-process settlement")
				return
			case "renewal":
				deadline = deadline.Add(3 * time.Second)
				writeStatefulGuardFixture(t, guard, private, 3, deadline)
			case "forged":
				_, forged, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				writeStatefulGuardFixture(t, guard, forged, 3, deadline)
				deadline = time.Now().Add(2 * time.Second)
			case "rollback":
				writeStatefulGuardFixture(t, guard, private, 1, deadline)
				deadline = time.Now().Add(2 * time.Second)
			case "missing":
				if err := os.Remove(guard.CachePath); err != nil {
					t.Fatal(err)
				}
				deadline = time.Now().Add(2 * time.Second)
			}
			select {
			case result := <-wait:
				if _, _, err := result.Result(); err != nil {
					t.Fatal(err)
				}
				if time.Now().After(deadline.Add(2 * time.Second)) {
					t.Fatal("guardian exceeded signed deadline")
				}
				if (scenario == "expiry" || scenario == "renewal") && time.Now().Before(deadline.Add(-200*time.Millisecond)) {
					t.Fatal("guardian stopped before latest signed deadline")
				}
			case <-time.After(time.Until(deadline) + 2*time.Second):
				t.Fatal("process survived expired or invalid signed lease")
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

// This locates only this scenario's shim logger, then pins and rechecks the
// exact command before killing it; no unrelated runtime process is signalled.
func killStatefulFixtureLogger(t *testing.T, guard StatefulRuntimeGuard) {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 2 {
			continue
		}
		path := filepath.Join("/proc", entry.Name(), "cmdline")
		command, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		arguments := bytes.Split(bytes.TrimSuffix(command, []byte{0}), []byte{0})
		if len(arguments) != 3 || string(arguments[1]) != "--runtime-logger" {
			continue
		}
		var invocation runtimeLoggerInvocation
		if json.Unmarshal(arguments[2], &invocation) != nil || invocation.Guard.State == nil || invocation.Guard.State.CachePath != guard.CachePath || invocation.Guard.Fingerprint != guard.TaskSHA256 {
			continue
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			t.Fatal(err)
		}
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, command) {
			_ = unix.Close(fd)
			t.Fatal("shim logger identity changed before kill")
		}
		err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		_ = unix.Close(fd)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("exact shim logger process was not found")
}
